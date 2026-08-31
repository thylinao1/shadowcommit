import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { captureEffects, resolveLimits, snapshotStats, MAX_EFFECT_BYTES } from "./capture.js";
import type { EffectRecord } from "./policy-types.js";

/**
 * An install is not a large write.
 *
 * Measured against a real provider on the demo's own prompt ("create a TypeScript hello-world CLI,
 * add a test, run it"): the model ran `npm install`, `node_modules/typescript/lib/typescript.js`
 * arrived at 9,112,572 bytes, and the whole turn was destroyed under `effect-too-large` while the
 * model reported success. Four days of mock runs could not produce that, because no mock ever
 * installed anything.
 *
 * A dependency-tree CREATE is now exempt from the byte cap and captured normally. That is not a new
 * concession: `blast-radius`, `dependency-tree`, `scan-targets`, `multi-file-delete` and
 * `dependency-change` already carve the class out, and no content rule reads a byte of it at ANY
 * size, so the cap was never the control on that path. Everything else over the cap is recorded by
 * size alone, never read, never hashed, and held for a person.
 *
 * The exemption is CREATES only, and that line is load-bearing rather than tidy. An install is a
 * create; tampering with an installed file is a modify. Exempting modifies would also resurrect the
 * defect commit 7e66363 fixed: the seal signs an over-cap file `<statSignature>:oversize` because
 * it never hashed it, so hashing it here would produce a signature that can never match, and every
 * untouched over-cap file in the tree would read as changed on every turn.
 *
 * The whole axis is swept rather than the one point the defect was found at: both sides of the
 * boundary, both kinds, both path classes, both mechanisms.
 */

interface Bed {
  root: string;
  real: string;
  shadow: string;
  upper: string;
}

async function bed(mechanism: "overlay" | "copy"): Promise<Bed> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "install-cap-"));
  const real = path.join(root, "ws");
  const shadow = path.join(root, "shadow");
  const upper = path.join(shadow, mechanism === "overlay" ? "upper" : "merged");
  await fs.mkdir(real, { recursive: true });
  await fs.mkdir(upper, { recursive: true });
  return { root, real, shadow, upper };
}

/**
 * A file of an exact size without writing that many bytes. `truncate` makes it sparse, so a 9 MB
 * case costs a stat rather than 9 MB of disk, and the first byte is written so two files of one
 * size still differ in content.
 */
async function place(dir: string, rel: string, size: number, marker: number): Promise<void> {
  await fs.mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
  const handle = await fs.open(path.join(dir, rel), "w");
  try {
    await handle.truncate(size);
    if (size > 0) await handle.write(Buffer.alloc(1, marker), 0, 1, 0);
  } finally {
    await handle.close();
  }
}

const DEPENDENCY = "node_modules/typescript/lib/typescript.js";
const ORDINARY = "dist/bundle.js";

/** The cap is lowered so the boundary can be swept in bytes rather than in megabytes. */
const CAP = 4096;
const limits = resolveLimits({ maxEffectBytes: CAP });

const UNDER = [0, 1, CAP - 1, CAP];
const OVER = [CAP + 1, CAP * 2, CAP * 16];

async function capture(b: Bed, mechanism: "overlay" | "copy", sealed: Awaited<ReturnType<typeof snapshotStats>>) {
  return captureEffects({
    shadowDir: b.shadow,
    real: b.real,
    mechanism,
    sealed,
    realInodes: (await snapshotStats(b.real)).inodes,
    limits,
  });
}

const found = (effects: EffectRecord[], rel: string): EffectRecord | undefined =>
  effects.find((effect) => effect.path === rel);

/** Sets up one case and returns the capture result, for whichever mechanism and kind. */
async function runCase(
  mechanism: "overlay" | "copy",
  kind: "create" | "modify",
  rel: string,
  size: number,
) {
  const b = await bed(mechanism);
  try {
    if (kind === "modify") {
      // the file existed before the turn, in the real workspace and therefore in the sealed copy
      await place(b.real, rel, size, 1);
      if (mechanism === "copy") await place(b.upper, rel, size, 1);
    }
    const sealed =
      mechanism === "copy"
        ? await snapshotStats(b.upper, { hash: true, maxHashBytes: limits.maxEffectBytes })
        : await snapshotStats(path.join(b.root, "nothing-here"));

    // the turn's action: a new file, or a different one at a path that already existed
    await place(b.upper, rel, size, 2);

    return await capture(b, mechanism, sealed);
  } finally {
    await fs.rm(b.root, { recursive: true, force: true });
  }
}

for (const mechanism of ["copy", "overlay"] as const) {
  describe(`under ${mechanism}, a dependency-tree CREATE is captured at every size`, () => {
    for (const size of [...UNDER, ...OVER]) {
      it(`captures ${size} bytes at ${DEPENDENCY}, hashed and not refused`, async () => {
        const result = await runCase(mechanism, "create", DEPENDENCY, size);
        const effect = found(result.effects, DEPENDENCY);
        expect(effect?.kind).toBe("create");
        expect(effect?.bytes).toBe(size);
        // hashed, because tamperedEffects, the commit-time re-check and alreadyApplied all need a
        // sha256 for the class we are now letting through
        expect(typeof effect?.sha256).toBe("string");
        // and not marked, because nothing about it was refused
        expect(effect?.oversize).toBeUndefined();
        expect(result.oversize).toEqual([]);
      });
    }

    it("keeps an oversize install out of the turn's byte total", async () => {
      // otherwise the per-effect exemption is defeated by the per-turn cap on the next real project
      const under = await runCase(mechanism, "create", DEPENDENCY, CAP);
      const over = await runCase(mechanism, "create", DEPENDENCY, CAP * 16);
      expect(under.totalBytes).toBe(CAP);
      expect(over.totalBytes).toBe(0);
    });
  });

  describe(`under ${mechanism}, a dependency-tree MODIFY is still capped`, () => {
    for (const size of UNDER) {
      it(`captures ${size} bytes at ${DEPENDENCY}, hashed`, async () => {
        const result = await runCase(mechanism, "modify", DEPENDENCY, size);
        const effect = found(result.effects, DEPENDENCY);
        expect(effect?.oversize).toBeUndefined();
        expect(typeof effect?.sha256).toBe("string");
        expect(result.oversize).toEqual([]);
      });
    }

    for (const size of OVER) {
      it(`records ${size} bytes at ${DEPENDENCY} without reading it`, async () => {
        const result = await runCase(mechanism, "modify", DEPENDENCY, size);
        const effect = found(result.effects, DEPENDENCY);
        expect(effect?.kind).toBe("modify");
        expect(effect?.oversize).toBe(true);
        expect(effect?.sha256).toBeUndefined();
        expect(result.oversize.map((o) => o.path)).toEqual([DEPENDENCY]);
        expect(result.totalBytes).toBe(0);
      });
    }
  });

  for (const kind of ["create", "modify"] as const) {
    describe(`under ${mechanism}, an ordinary path over the cap is recorded, not refused, on a ${kind}`, () => {
      for (const size of UNDER) {
        it(`captures ${size} bytes at ${ORDINARY}`, async () => {
          const result = await runCase(mechanism, kind, ORDINARY, size);
          const effect = found(result.effects, ORDINARY);
          expect(effect?.oversize).toBeUndefined();
          expect(typeof effect?.sha256).toBe("string");
          expect(result.oversize).toEqual([]);
        });
      }

      for (const size of OVER) {
        it(`records ${size} bytes at ${ORDINARY} by size alone`, async () => {
          const result = await runCase(mechanism, kind, ORDINARY, size);
          const effect = found(result.effects, ORDINARY);
          // present in the effect set, which is what makes it settleable by a person, and carrying
          // exactly what a stat can say: path, kind, mode, size
          expect(effect?.kind).toBe(kind);
          expect(effect?.bytes).toBe(size);
          expect(typeof effect?.mode).toBe("number");
          expect(effect?.oversize).toBe(true);
          // never read, so never hashed: this is the whole a39 property
          expect(effect?.sha256).toBeUndefined();
          // and still named on its own line, so the journal keeps saying which files went unread
          expect(result.oversize).toEqual([{ path: ORDINARY, bytes: size }]);
        });
      }
    });
  }
}

/**
 * The two sizes the real run and this repository's own tree actually produce, at the shipped cap
 * rather than a lowered one, because a threshold proven only against a test constant is a threshold
 * nobody checked against the number in production.
 */
describe("the sizes the real run produced, at the shipped cap", () => {
  const TYPESCRIPT_JS = 9_112_572;
  const ESBUILD_BINARY = 10_573_778;

  for (const [name, size] of [
    ["typescript.js", TYPESCRIPT_JS],
    ["the esbuild binary", ESBUILD_BINARY],
  ] as const) {
    it(`installs ${name} at ${size} bytes instead of destroying the turn`, async () => {
      const b = await bed("copy");
      try {
        const sealed = await snapshotStats(b.upper, { hash: true, maxHashBytes: MAX_EFFECT_BYTES });
        await place(b.upper, DEPENDENCY, size, 2);
        const result = await captureEffects({
          shadowDir: b.shadow,
          real: b.real,
          mechanism: "copy",
          sealed,
          realInodes: (await snapshotStats(b.real)).inodes,
          limits: resolveLimits(),
        });
        expect(size).toBeGreaterThan(MAX_EFFECT_BYTES);
        expect(result.oversize).toEqual([]);
        expect(found(result.effects, DEPENDENCY)?.bytes).toBe(size);
      } finally {
        await fs.rm(b.root, { recursive: true, force: true });
      }
    });
  }

  it("still records, and still does not read, the same size at an ordinary path", async () => {
    const b = await bed("copy");
    try {
      const sealed = await snapshotStats(b.upper, { hash: true, maxHashBytes: MAX_EFFECT_BYTES });
      await place(b.upper, ORDINARY, TYPESCRIPT_JS, 2);
      const result = await captureEffects({
        shadowDir: b.shadow,
        real: b.real,
        mechanism: "copy",
        sealed,
        realInodes: (await snapshotStats(b.real)).inodes,
        limits: resolveLimits(),
      });
      expect(found(result.effects, ORDINARY)?.oversize).toBe(true);
      expect(found(result.effects, ORDINARY)?.sha256).toBeUndefined();
      expect(result.oversize).toEqual([{ path: ORDINARY, bytes: TYPESCRIPT_JS }]);
    } finally {
      await fs.rm(b.root, { recursive: true, force: true });
    }
  });
});

/**
 * The exemption is by CLASS, not by spelling, and the class table puts `protected` ahead of
 * `dependency-tree`. A protected asset that happens to sit under a vendored path does not buy the
 * exemption by living there.
 */
describe("a path under a dependency tree that is not classified as one stays capped", () => {
  for (const rel of ["node_modules/pkg/.env", "vendor/app/.env.local"]) {
    it(`records ${rel} rather than installing it`, async () => {
      const b = await bed("copy");
      try {
        const sealed = await snapshotStats(b.upper, { hash: true, maxHashBytes: limits.maxEffectBytes });
        await place(b.upper, rel, CAP * 4, 2);
        const result = await capture(b, "copy", sealed);
        expect(found(result.effects, rel)?.oversize).toBe(true);
        expect(result.oversize.map((o) => o.path)).toEqual([rel]);
      } finally {
        await fs.rm(b.root, { recursive: true, force: true });
      }
    });
  }
});

import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { safeResolve, safeWriteTarget } from "./safe-path.js";

/**
 * Property fuzzing of the settlement path: whatever name an agent chooses, nothing is created,
 * written or deleted outside the workspace root.
 *
 * CONTAINMENT IS THE FIRST PROPERTY OF THE SUITE ITSELF, not just of the code under test. A fuzzer
 * that generates hostile path names and then writes them with a bare `fs.writeFile` is a program
 * for damaging the machine it runs on. So every mutation here goes through `w.*`, which refuses any
 * path outside the roots this file allocated, and one test reads this file's own source to prove no
 * bare mutation slipped in. A guard nobody checks is a claim, not a feature.
 *
 * No fast-check. The case space here is enumerable and every case has a name, so a failure already
 * reports a minimal named case and there is nothing for a shrinker to do. That also keeps the suite
 * from adding a dependency to the submission. Randomness comes from a seeded PRNG, so a failing run
 * reprints the seed and replays exactly.
 */

const SEED = Number(process.env.FUZZ_SEED ?? 0x5EA1ED);
const CASES = Number(process.env.FUZZ_CASES ?? 120);

/** xorshift32: tiny, deterministic, and its seed fits in the failure message. */
function rng(seed: number): () => number {
  let x = seed || 1;
  return () => {
    x ^= x << 13; x >>>= 0;
    x ^= x >> 17;
    x ^= x << 5; x >>>= 0;
    return x / 0x1_0000_0000;
  };
}

// ---------------------------------------------------------------------------
// containment: one allocator, one mutation gate, and a test that reads this file
// ---------------------------------------------------------------------------

const ROOTS: string[] = [];
let repoRoot = "";

async function newRoot(tag: string): Promise<string> {
  // realpath at creation, so a /tmp that is itself a symlink cannot defeat the comparison later
  const base = await fs.realpath(os.tmpdir());
  const dir = await fs.mkdtemp(path.join(base, tag));
  const real = await fs.realpath(dir);
  ROOTS.push(real);
  return real;
}

/**
 * Resolve the deepest ancestor that exists and require the result to sit inside a root this suite
 * created. The walk is written out here rather than calling `safe-path`, deliberately: a bug in the
 * code under test must not be able to disarm the guard that protects the machine from the test.
 */
async function assertInsideRoots(p: string): Promise<void> {
  let probe = path.resolve(p);
  let suffix = "";
  for (;;) {
    const real = await fs.realpath(probe).catch(() => null);
    if (real) { probe = suffix ? path.join(real, suffix) : real; break; }
    const parent = path.dirname(probe);
    if (parent === probe) { probe = path.resolve(p); break; }
    suffix = suffix ? path.join(path.basename(probe), suffix) : path.basename(probe);
    probe = parent;
  }
  const inside = ROOTS.some((r) => {
    const rel = path.relative(r, probe);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  });
  if (!inside) throw new Error(`fuzz guard: refused to touch ${p} (outside every allocated root)`);
}

/** The only mutation surface in this file. */
const w = {
  async writeFile(p: string, body: string | Uint8Array) { await assertInsideRoots(p); await fs.writeFile(p, body); },
  async mkdir(p: string) { await assertInsideRoots(p); await fs.mkdir(p, { recursive: true }); },
  async symlink(target: string, p: string) { await assertInsideRoots(p); await fs.symlink(target, p); },
  async link(existing: string, p: string) { await assertInsideRoots(p); await fs.link(existing, p); },
  async chmod(p: string, mode: number) { await assertInsideRoots(p); await fs.chmod(p, mode); },
  async rm(p: string) {
    await assertInsideRoots(p);
    // the kill condition, in the test harness too: never delete through a mount
    if (process.platform === "linux") {
      const info = await fs.readFile("/proc/self/mountinfo", "utf8").catch(() => null);
      if (info === null) throw new Error("fuzz guard: mountinfo unreadable, refusing a recursive delete");
      const real = await fs.realpath(p).catch(() => path.resolve(p));
      for (const line of info.split("\n")) {
        const mp = line.split(" ")[4];
        if (mp && (mp === real || mp.startsWith(real + path.sep))) {
          throw new Error(`fuzz guard: ${mp} is mounted under ${p}, refusing to delete through it`);
        }
      }
    }
    await fs.rm(p, { recursive: true, force: true });
  },
};

// ---------------------------------------------------------------------------
// the generated case space: named, finite, hostile
// ---------------------------------------------------------------------------

/** Names an agent might choose. Every one of these is a real class, not random bytes. */
const NAMES: Array<{ name: string; s: string }> = [
  { name: "plain", s: "notes.txt" },
  { name: "leading-dash", s: "-rf" },
  { name: "double-dash", s: "--force" },
  { name: "dot", s: "." },
  { name: "dotdot", s: ".." },
  { name: "triple-dot", s: "..." },
  { name: "hidden", s: ".hidden" },
  { name: "semicolon", s: "a;b" },
  { name: "pipe", s: "a|b" },
  { name: "ampersand", s: "a&b" },
  { name: "dollar", s: "a$b" },
  { name: "backtick", s: "a`b`" },
  { name: "glob", s: "a*?[]" },
  { name: "quote", s: "a'\"b" },
  { name: "backslash", s: "a\\b" },
  { name: "space", s: "a b" },
  { name: "tab", s: "a\tb" },
  { name: "newline", s: "a\nb" },
  { name: "cr", s: "a\rb" },
  { name: "ansi-escape", s: "a\u001b[2Jb" },
  { name: "del", s: "a\u007fb" },
  { name: "rtl-override", s: "a\u202eb" },
  { name: "zero-width", s: "a\u200bb" },
  { name: "cyrillic-homoglyph", s: "\u0430dmin" },
  { name: "nfc", s: "caf\u00e9" },
  { name: "nfd", s: "cafe\u0301" },
  { name: "upper-twin", s: "CAFE" },
  { name: "lower-twin", s: "cafe" },
  { name: "long-255", s: "x".repeat(255) },
];

/** Path strings an effect record might carry. Separate space from names, on purpose. */
const CHOSEN: Array<{ name: string; s: string }> = [
  { name: "escape-1", s: "../CANARY.txt" },
  { name: "escape-8", s: "../".repeat(8) + "CANARY.txt" },
  { name: "escape-40", s: "../".repeat(40) + "CANARY.txt" },
  { name: "absolute", s: "/etc/passwd" },
  { name: "abs-canary", s: "__CANARY_ABS__" },
  { name: "windows-abs", s: "C:\\Windows\\system32" },
  { name: "unc", s: "\\\\server\\share" },
  { name: "tilde", s: "~/.ssh/authorized_keys" },
  { name: "double-slash", s: "sub//x" },
  { name: "dot-segment", s: "sub/./x" },
  { name: "mixed-updown", s: "sub/../../x" },
  { name: "empty", s: "" },
  { name: "only-dot", s: "." },
  { name: "only-dotdot", s: ".." },
  { name: "trailing-slash", s: "sub/" },
  { name: "nul-ish", s: "a\u0000b" },
  { name: "deep-40", s: Array.from({ length: 40 }, (_, i) => `d${i}`).join("/") + "/leaf" },
  { name: "through-symlink", s: "link/leaf.txt" },
  { name: "through-dirlink", s: "dirlink/leaf.txt" },
  { name: "in-tree", s: "sub/ok.txt" },
];

interface Canary { map: Map<string, string>; absFile: string }

/** A fingerprint of everything outside the workspace that a bug could plausibly reach. */
async function snapshot(dir: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const walk = async (d: string, prefix: string): Promise<void> => {
    const entries = await fs.readdir(d, { withFileTypes: true }).catch(() => []);
    for (const e of entries) {
      const full = path.join(d, e.name);
      const rel = prefix ? `${prefix}/${e.name}` : e.name;
      const st = await fs.lstat(full).catch(() => null);
      if (!st) continue;
      const kind = st.isSymbolicLink() ? "link" : st.isDirectory() ? "dir" : "file";
      let digest = "";
      if (kind === "file") {
        const body = await fs.readFile(full).catch(() => Buffer.alloc(0));
        digest = crypto.createHash("sha256").update(body).digest("hex").slice(0, 16);
      } else if (kind === "link") {
        digest = await fs.readlink(full).catch(() => "");
      }
      out.set(rel, `${kind}:${st.size}:${(st.mode & 0o777).toString(8)}:${st.nlink}:${digest}`);
      if (kind === "dir") await walk(full, rel);
    }
  };
  await walk(dir, "");
  return out;
}

let CANARY_BYTES = "";

/** root/ws is the workspace; root/outside is everything the settlement path must never reach. */
async function buildCase(root: string, rand: () => number): Promise<{ ws: string; canary: Canary }> {
  const ws = path.join(root, "ws");
  const outside = path.join(root, "outside");
  await w.mkdir(path.join(ws, "sub"));
  await w.mkdir(outside);

  CANARY_BYTES = `SECRET-${crypto.randomUUID()}`;
  const absFile = path.join(outside, "SECRET.txt");
  await w.writeFile(absFile, CANARY_BYTES);
  await w.writeFile(path.join(outside, "other.txt"), "do not touch\n");
  await w.mkdir(path.join(outside, "nested"));
  await w.writeFile(path.join(outside, "nested", "deep.txt"), "also do not touch\n");
  await w.writeFile(path.join(root, "CANARY.txt"), CANARY_BYTES);

  await w.writeFile(path.join(ws, "keep.txt"), "keep\n");
  await w.writeFile(path.join(ws, "sub", "ok.txt"), "ok\n");

  // the hostile shapes the settlement path has historically been broken by
  await w.symlink(absFile, path.join(ws, "link"));               // leaf symlink out
  await w.symlink(outside, path.join(ws, "dirlink"));            // directory symlink out
  await w.symlink(path.join(ws, "keep.txt"), path.join(ws, "inlink")); // benign, must survive
  await w.link(absFile, path.join(ws, "hard.txt")).catch(() => undefined); // hardlink out
  await w.symlink(path.join(ws, "loop"), path.join(ws, "loop")).catch(() => undefined);

  // a few generated names, chosen by the seeded rng so a failure replays
  const n = 3 + Math.floor(rand() * 4);
  for (let i = 0; i < n; i++) {
    const pick = NAMES[Math.floor(rand() * NAMES.length)]!;
    const safeLeaf = pick.s.replace(/\//g, "_").slice(0, 200) || "_empty";
    await w.writeFile(path.join(ws, safeLeaf), `body-${i}\n`).catch(() => undefined);
  }

  const canaryMap = await snapshot(outside);
  canaryMap.set("__ROOT_CANARY__", (await snapshot(root)).get("CANARY.txt") ?? "missing");
  return { ws, canary: { map: canaryMap, absFile } };
}

// ---------------------------------------------------------------------------

let srcMtimes = new Map<string, string>();

beforeAll(async () => {
  repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  // refuse to run if TMPDIR was pointed inside the checkout
  const tmp = await fs.realpath(os.tmpdir());
  const rel = path.relative(repoRoot, tmp);
  expect(rel.startsWith("..") || path.isAbsolute(rel)).toBe(true);
  srcMtimes = await snapshot(path.dirname(fileURLToPath(import.meta.url)));
});

afterEach(async () => {
  while (ROOTS.length) {
    const r = ROOTS[ROOTS.length - 1]!;
    await w.rm(r).catch(() => undefined);
    ROOTS.pop();
  }
});

afterAll(async () => {
  // the worst case a fuzzer can produce is an escape into the checkout itself
  const after = await snapshot(path.dirname(fileURLToPath(import.meta.url)));
  const changed = [...after].filter(([k, v]) => srcMtimes.has(k) && srcMtimes.get(k) !== v).map(([k]) => k);
  expect(changed).toEqual([]);
});

describe.skipIf(process.platform === "win32")("the fuzzer cannot damage the machine it runs on", () => {
  it("has no bare filesystem mutation outside the guarded wrapper", async () => {
    const src = await fs.readFile(fileURLToPath(import.meta.url), "utf8");
    // everything after the wrapper definition must go through w.*
    const body = src.slice(src.indexOf("// the generated case space"));
    // Assembled rather than written out, because a literal here would appear in the very file this
    // scan reads and the test would match itself. The first version of this check did exactly that.
    const mutators = ["writeFile", "mkdir", "symlink", "link", "chmod", "rm"];
    for (const m of mutators) {
      const banned = "fs." + m + "(";
      expect(body.includes(banned), `bare ${banned} found outside the guard`).toBe(false);
    }
  });

  it("refuses a path outside every allocated root", async () => {
    const root = await newRoot("fuzz-guard-");
    await expect(w.writeFile(path.join(root, "..", "escaped.txt"), "x")).rejects.toThrow(/fuzz guard/);
    await expect(w.writeFile("/tmp/definitely-not-ours.txt", "x")).rejects.toThrow(/fuzz guard/);
  });
});

describe.skipIf(process.platform === "win32")("settlement path, property fuzzed", () => {
  it(`resolves ${CASES} generated cases without ever leaving the workspace (seed ${SEED.toString(16)})`, async () => {
    const rand = rng(SEED);
    for (let i = 0; i < CASES; i++) {
      const root = await newRoot("fuzz-settle-");
      const { ws, canary } = await buildCase(root, rand);
      const chosen = CHOSEN[i % CHOSEN.length]!;
      const target = chosen.s === "__CANARY_ABS__" ? canary.absFile : chosen.s;
      const label = `case ${i} name=${chosen.name} seed=${SEED.toString(16)}`;

      const resolved = await safeResolve(ws, target).catch(() => ({ ok: false, abs: "", reason: "threw" }));
      const writeTo = await safeWriteTarget(ws, target).catch(() => ({ ok: false, abs: "", reason: "threw" }));

      for (const r of [resolved, writeTo]) {
        if (!r.ok) continue;
        // O2: if the resolver said yes, prove it independently of the resolver
        const realWs = await fs.realpath(ws);
        const rel = path.relative(realWs, r.abs);
        expect(rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel)), `${label}: ${r.abs} escaped`).toBe(true);
        // every component from the root down must be a real directory, never a link
        const parts = rel.split(path.sep).filter(Boolean);
        let cur = realWs;
        for (let k = 0; k < parts.length - 1; k++) {
          cur = path.join(cur, parts[k]!);
          const st = await fs.lstat(cur).catch(() => null);
          if (st) expect(st.isSymbolicLink(), `${label}: component ${parts[k]} is a symlink`).toBe(false);
        }
      }

      // O1: nothing outside the workspace changed, by full map comparison so a create and a
      // delete both fail rather than only a modification
      const after = await snapshot(path.join(root, "outside"));
      after.set("__ROOT_CANARY__", (await snapshot(root)).get("CANARY.txt") ?? "missing");
      expect(after, `${label}: something outside the workspace changed`).toEqual(canary.map);

      await w.rm(root);
      ROOTS.pop();
    }
  }, 120_000);

  it("never dereferences a link that leaves the workspace", async () => {
    const rand = rng(SEED ^ 0x9e3779b9);
    for (let i = 0; i < 24; i++) {
      const root = await newRoot("fuzz-deref-");
      const { ws, canary } = await buildCase(root, rand);
      const canaryAbs = canary.absFile;
      // Symlinks: the resolver must not follow one out of the workspace at all, for read or write.
      for (const p of ["link", "dirlink/SECRET.txt"]) {
        const r = await safeResolve(ws, p).catch(() => ({ ok: false, abs: "", reason: "threw" }));
        if (!r.ok) continue;
        const body = await fs.readFile(r.abs, "utf8").catch(() => "");
        expect(body.includes(CANARY_BYTES), `case ${i}: ${p} read the canary through a symlink`).toBe(false);
      }

      // A hardlink is a different animal and the right invariant is narrower. It is a real entry
      // inside the workspace sharing an inode with a file outside it, so there is no outside PATH to
      // refuse and realpath containment cannot see it. Reading it is not the danger: at seal time
      // `cp -a` writes a separate copy into the shadow, so the shipped flow never hands the agent
      // the shared inode. Writing through it on the trusted side IS the danger, because that reaches
      // the outside file's bytes, and safe-path.ts:99 defuses exactly that by unlinking any nlink>1
      // destination first. That is the property worth pinning.
      const hard = path.join(ws, "hard.txt");
      const before = await fs.readFile(canaryAbs, "utf8").catch(() => "");
      if (before.includes(CANARY_BYTES)) {
        const target = await safeWriteTarget(ws, "hard.txt");
        if (target.ok) {
          await w.writeFile(target.abs, "clobbered by the fuzzer\n");
          const after = await fs.readFile(canaryAbs, "utf8").catch(() => "");
          expect(after, `case ${i}: writing hard.txt reached the file outside the workspace`).toBe(before);
        }
        expect((await fs.lstat(hard).catch(() => null)) !== null).toBe(true);
      }
      await w.rm(root);
      ROOTS.pop();
    }
  }, 60_000);

  it("refuses every parent reference and every absolute path, in any spelling", async () => {
    const root = await newRoot("fuzz-escape-");
    const { ws, canary } = await buildCase(root, rng(SEED));
    const escapes = CHOSEN.filter((c) => /escape|absolute|windows-abs|unc|tilde|only-dotdot|mixed-updown/.test(c.name));
    for (const c of escapes) {
      const target = c.s === "__CANARY_ABS__" ? canary.absFile : c.s;
      const r = await safeResolve(ws, target).catch(() => ({ ok: false, abs: "", reason: "threw" }));
      if (r.ok) {
        const rel = path.relative(await fs.realpath(ws), r.abs);
        expect(rel.startsWith("..") || path.isAbsolute(rel), `${c.name} resolved outside`).toBe(false);
      }
    }
    await w.rm(root);
    ROOTS.pop();
  }, 30_000);
});

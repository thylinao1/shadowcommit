import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { captureEffects, defaultLimits, snapshotStats } from "./capture.js";
import { basicContext } from "./policy-types.js";
import { defaultPolicy } from "./shadow-policy.js";
import {
  ARM_BACKDATE_MS,
  armReadWitness,
  collectReadWitness,
  probeAtimeSupport,
  rearmReadWitness,
  summariseReadWitness,
} from "./read-witness.js";

const execFileAsync = promisify(execFile);

/**
 * The gap: an effect set is not a description of what a turn did, because a read leaves no effect.
 *
 * Every test here builds a real workspace, seals it the way the runner seals it (`cp -a`), runs a
 * real command against the sealed copy in a separate process, and then asks two questions of the
 * same turn: what does capture say, and what does the witness say. The first says nothing, on
 * purpose, because that is the defect. The second is the contribution.
 */

let root: string;
let real: string;
let merged: string;

const OLD = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

async function writeAged(rel: string, body: string | Buffer): Promise<void> {
  const full = path.join(real, rel);
  await fs.mkdir(path.dirname(full), { recursive: true });
  await fs.writeFile(full, body);
  await fs.utimes(full, OLD, OLD);
}

/**
 * Seals the workspace the way the transactional runner does: arm, then snapshot, then re-arm.
 *
 * The arm is in two passes with the snapshot between them. Pass one writes, so it goes before the
 * snapshot and the snapshot records the times it chose, which is why nothing needs reconciling
 * afterwards. Pass two goes after, because the snapshot hashes every file and a hash is a read that
 * spends every arm; re-arming there makes the window the witness measures exactly the turn.
 */
async function seal() {
  await fs.mkdir(merged, { recursive: true });
  await execFileAsync("cp", ["-a", real + "/.", merged]);
  const realInodes = (await snapshotStats(real)).inodes;
  const baseline = await armReadWitness(merged);
  const sealed = await snapshotStats(merged, { hash: true, maxHashBytes: defaultLimits.maxEffectBytes });
  await rearmReadWitness(baseline);
  return { baseline, realInodes, sealed };
}

async function capture(sealedState: Awaited<ReturnType<typeof seal>>) {
  return captureEffects({
    shadowDir: root,
    real,
    mechanism: "copy",
    sealed: sealedState.sealed,
    realInodes: sealedState.realInodes,
    limits: defaultLimits,
  });
}

/**
 * Writes a file whose modification time carries sub-millisecond precision, which is what any file a
 * build just wrote carries. `utimes` cannot express it, so this is the shape the two-pass arm exists
 * for, and the loop makes the test say so on purpose rather than by luck.
 */
async function writeSubMillisecond(rel: string, body: string): Promise<void> {
  const full = path.join(real, rel);
  for (let attempt = 0; attempt < 200; attempt += 1) {
    await fs.writeFile(full, body);
    const stat = await fs.lstat(full);
    if (stat.mtimeMs % 1 !== 0) return;
  }
  throw new Error("this host records whole-millisecond modification times only");
}

/** Runs a command inside the sealed copy, as a turn would. */
const turn = (script: string) => execFileAsync("sh", ["-c", script], { cwd: merged });

beforeEach(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "read-witness-"));
  real = path.join(root, "real");
  merged = path.join(root, "merged");
  await fs.mkdir(real, { recursive: true });
});

afterEach(async () => {
  await fs.rm(root, { recursive: true, force: true });
});

describe("the gap this module exists for", () => {
  it("a turn that reads every secret and writes nothing produces an empty effect set that commits", async () => {
    await writeAged(".env", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n");
    await writeAged("secrets/prod.key", "-----BEGIN PRIVATE KEY-----\nabc\n");
    await writeAged("customers.jsonl", '{"email":"a@b.c"}\n');
    await writeAged("src/index.ts", "export const a = 1;\n");

    const sealed = await seal();
    await turn("cat .env secrets/prod.key customers.jsonl > /dev/null");

    // the witness is read off the copy BEFORE capture, because capture hashes and a hash is a read
    const witness = await collectReadWitness(sealed.baseline);
    const captured = await capture(sealed);
    const verdict = await defaultPolicy(captured.effects, basicContext(async () => ""));

    // this is the defect, stated as an assertion so it cannot quietly stop being true
    expect(captured.effects).toEqual([]);
    expect(verdict).toMatchObject({ decision: "commit", rule: "none" });

    // and this is what the witness adds to the same turn
    expect(witness.supported).toBe(true);
    const readPaths = witness.observations.filter((o) => o.kind === "read").map((o) => o.path).sort();
    expect(readPaths).toEqual([".env", "customers.jsonl", "secrets/prod.key"]);
    expect(witness.protectedReads).toBe(3);
    expect(readPaths).not.toContain("src/index.ts");
  });

  it("names the protected asset first in a bounded summary, past forty files that sort ahead of it", async () => {
    // the protected path sorts LAST here, so only the ranking can put it in a summary of three
    await writeAged("config/secrets/prod.key", "KEY\n");
    for (let i = 0; i < 40; i += 1) await writeAged(`aaa/mod${i}.ts`, `export const n = ${i};\n`);

    const sealed = await seal();
    await turn("grep -rl . . > /dev/null 2>&1 || true");
    const witness = await collectReadWitness(sealed.baseline);

    expect(witness.reads).toBeGreaterThan(3);
    const summary = summariseReadWitness(witness, 3);
    expect(summary.paths[0]).toBe("config/secrets/prod.key");
    expect(summary.protectedReads).toBe(1);
    expect(summary.pathsTruncated).toBeGreaterThan(0);
  });
});

describe("the mechanism the witness does not cover, stated as a test rather than a claim", () => {
  it("under the overlay mechanism the effect set cannot express a read at all", async () => {
    // overlayfs copies a file up when it is WRITTEN, never when it is read, so `upper` is empty
    // after a turn that only read. Capture under overlay walks `upper` and nothing else, so there
    // is no arrangement of a read that produces an effect on that path.
    await writeAged(".env", "TOKEN=abc\n");
    await writeAged("src/index.ts", "export const a = 1;\n");
    const upper = path.join(root, "upper");
    await fs.mkdir(upper, { recursive: true });
    const realInodes = (await snapshotStats(real)).inodes;

    const captured = await captureEffects({
      shadowDir: root,
      real,
      mechanism: "overlay",
      sealed: { signatures: new Map(), inodes: new Map() },
      realInodes,
      limits: defaultLimits,
    });

    expect(await fs.readdir(upper)).toEqual([]);
    expect(captured.effects).toEqual([]);
    // and the copy mechanism, which is the one this host takes, is where the witness lives
    expect(process.platform === "linux" || process.platform === "darwin").toBe(true);
  });
});

describe("the arm is what makes a read observable", () => {
  it("arming puts atime behind mtime, and the unarmed case is a property of the host, not a fact", async () => {
    // MEASURED on both platforms rather than assumed, because they disagree in OPPOSITE directions
    // and an earlier version of this test asserted one of them as universal:
    //
    //   Linux, relatime   updates atime when atime < mtime, OR atime < ctime, OR the atime is more
    //                     than a day old. `cp -a` preserves atime and mtime but cannot preserve
    //                     ctime, so a copy's ctime is always now, and an AGED fixture satisfies two
    //                     of the three conditions. Its first read is always recorded.
    //   macOS, APFS       updates when atime < mtime and ignores the ctime and 24-hour clauses. The
    //                     same aged fixture is NOT recorded, and a freshly copied one IS.
    //
    // So the old assertion, that an unarmed read of an aged copy leaves no trace, passed here and
    // failed on every Linux runner by exactly the seven-day backdate. Widening a tolerance could
    // never have fixed it: the premise was wrong, not the precision. And there is no fixture age
    // that makes the unarmed claim true on both, so this test does not make it.
    //
    // What IS true on both is the condition the production arm is built on, `atime < mtime`, which
    // is the one clause every filesystem in this family honours. That is the load-bearing property,
    // and the read being seen afterwards is the thing the witness actually promises.
    await writeAged(".env", "TOKEN=abc\n");
    const sealed = await seal();
    const entry = sealed.baseline.entries.get(".env");
    const stat = await fs.lstat(path.join(merged, ".env"), { bigint: true });

    expect(entry).toBeDefined();
    expect(entry!.atimeNs).toBeLessThan(stat.mtimeNs);

    await turn("cat .env > /dev/null");
    expect((await collectReadWitness(sealed.baseline)).reads).toBe(1);
  });

  it("arming pushes access time behind modification time by more than a relatime day", async () => {
    await writeAged(".env", "TOKEN=abc\n");
    const sealed = await seal();
    const entry = sealed.baseline.entries.get(".env");
    const stat = await fs.lstat(path.join(merged, ".env"), { bigint: true });
    expect(entry).toBeDefined();
    expect(Number(stat.mtimeNs - entry!.atimeNs) / 1e6).toBeCloseTo(ARM_BACKDATE_MS, -1);
    expect(ARM_BACKDATE_MS).toBeGreaterThan(24 * 60 * 60 * 1000);
  });
});

describe("the axis: what moves the bit and what does not", () => {
  const readers: ReadonlyArray<readonly [string, string]> = [
    ["cat", "cat target > /dev/null"],
    ["head -c 1", "head -c 1 target > /dev/null"],
    ["grep", "grep -q zzz target || true"],
    ["dd one byte", "dd if=target of=/dev/null bs=1 count=1 2>/dev/null"],
    ["awk", "awk 'NR==1' target > /dev/null"],
  ];

  // WHAT THIS MECHANISM DOES NOT SEE, stated here rather than in a commit message, because the
  // limits of a detector belong next to its tests where a reviewer finds them.
  //
  //   O_NOATIME readers      invisible. A process with CAP_FOWNER or owning the file may open with
  //                          O_NOATIME, and the kernel then records no access at all. GNU tar does
  //                          this; bsdtar does not, so `tar cf - target` used to sit in the list
  //                          above and passed on macOS while failing on every Linux runner. It was
  //                          not an atime-policy failure, it was one reader implementation, and its
  //                          fixture ended `2>&1 || true`, so a tar that was missing or erroring
  //                          was indistinguishable from a tar that read the file.
  //   mmap without read()    a mapping that faults pages in does not reliably update atime.
  //   noatime mounts         nothing is visible; the probe reports atime-frozen and no read count
  //                          is quoted, which is the case covered below.
  //
  // An atime witness is corroborating evidence, not proof of absence. A turn that reads a file
  // without leaving a trace is possible, and the product must never claim otherwise.

  for (const [name, script] of readers) {
    it(`sees a read by ${name}`, async () => {
      await writeAged("target", "TOKEN=abc\n");
      const sealed = await seal();
      await turn(script);
      const witness = await collectReadWitness(sealed.baseline);
      expect(witness.observations.map((o) => o.path)).toContain("target");
    });
  }

  const sizes: ReadonlyArray<readonly [string, number]> = [
    ["empty", 0],
    ["one byte", 1],
    ["4 KiB", 4096],
    ["1 MiB", 1024 * 1024],
    ["9 MiB, past the per-effect cap", 9 * 1024 * 1024],
  ];
  for (const [name, bytes] of sizes) {
    it(`sees a read of a ${name} file`, async () => {
      await writeAged("target", Buffer.alloc(bytes, 0x41));
      const sealed = await seal();
      await turn("head -c 1 target > /dev/null");
      const witness = await collectReadWitness(sealed.baseline);
      expect(witness.observations.map((o) => o.path)).toContain("target");
    });
  }

  it("does not fire on a file nobody opened", async () => {
    await writeAged("a.ts", "1\n");
    await writeAged("b.ts", "2\n");
    const sealed = await seal();
    await turn("cat a.ts > /dev/null");
    const witness = await collectReadWitness(sealed.baseline);
    expect(witness.observations.map((o) => o.path)).toEqual(["a.ts"]);
  });

  it("does not fire on a stat, and does not fire on an open with no read", async () => {
    await writeAged("target", "TOKEN=abc\n");
    const sealed = await seal();
    await turn("ls -l target > /dev/null; : < /dev/null");
    const handle = await fs.open(path.join(merged, "target"), "r");
    await handle.close();
    const witness = await collectReadWitness(sealed.baseline);
    expect(witness.observations).toEqual([]);
  });

  it("hands a written file to capture instead of claiming it as a read", async () => {
    await writeAged("target", "one\n");
    const sealed = await seal();
    await turn("echo two >> target");
    const witness = await collectReadWitness(sealed.baseline);
    const captured = await capture(sealed);
    expect(witness.observations).toEqual([]);
    expect(witness.changed).toBe(1);
    expect(captured.effects.map((e) => e.path)).toEqual(["target"]);
  });

  it("sees a read performed through a symlink, on the target", async () => {
    await writeAged("secrets/prod.key", "KEY\n");
    await fs.symlink("secrets/prod.key", path.join(real, "link"));
    const sealed = await seal();
    await turn("cat link > /dev/null");
    const witness = await collectReadWitness(sealed.baseline);
    expect(witness.observations.map((o) => o.path)).toEqual(["secrets/prod.key"]);
    expect(witness.protectedReads).toBe(1);
  });
});

describe("the evasion, and the bit that closes it", () => {
  it("catches a turn that reads a secret and puts the access time back", async () => {
    await writeAged(".env", "TOKEN=abc\n");
    const sealed = await seal();
    const armed = sealed.baseline.entries.get(".env")!;

    // What an agent that knows about this module does, in the shell it already has: keep a
    // timestamp-preserving copy, read the file, then put both times back from it. `cp -p` and
    // `touch -r` carry nanoseconds, so the restore is exact and needs no privilege.
    const keep = path.join(root, "keep");
    await turn(`cp -p .env ${JSON.stringify(keep)}; cat .env > /dev/null; touch -r ${JSON.stringify(keep)} .env`);

    const after = await fs.lstat(path.join(merged, ".env"), { bigint: true });
    expect(after.atimeNs).toBe(armed.atimeNs); // the restore succeeded, exactly
    expect(after.ctimeNs).not.toBe(armed.ctimeNs); // and could not avoid moving ctime

    const witness = await collectReadWitness(sealed.baseline);
    expect(witness.observations).toEqual([
      { path: ".env", canonicalPath: ".env", kind: "timestamp-tampered", protectedAsset: true },
    ]);
    expect(witness.tampered).toBe(1);
  });

  it("does not call an ordinary read tampering", async () => {
    await writeAged(".env", "TOKEN=abc\n");
    const sealed = await seal();
    await turn("cat .env > /dev/null");
    const witness = await collectReadWitness(sealed.baseline);
    expect(witness.tampered).toBe(0);
    expect(witness.reads).toBe(1);
  });
});

describe("the control that stops this from becoming a fake that cannot fail", () => {
  it("reports an unsupported host as unsupported rather than as a turn that read nothing", async () => {
    await writeAged(".env", "TOKEN=abc\n");
    const sealed = await seal();
    await turn("cat .env > /dev/null");

    // the shape a noatime mount produces: the probe fails, so nothing is armed
    const frozen = { ...sealed.baseline, supported: false, reason: "atime-frozen" };
    const witness = await collectReadWitness(frozen);

    expect(witness.supported).toBe(false);
    expect(witness.reason).toBe("atime-frozen");
    expect(witness.selectivity).toBeNull();
    // and the honest version of the same turn, on a host that can see it
    expect((await collectReadWitness(sealed.baseline)).reads).toBe(1);
  });

  it("probes the directory it was given, not the platform, and leaves nothing behind", async () => {
    const support = await probeAtimeSupport(root);
    expect(support).toEqual({ supported: true, reason: "armed" });
    expect(await fs.readdir(root)).not.toContainEqual(expect.stringContaining("read-witness-probe"));
  });

  it("says atime-frozen when a read does not move the access time, the noatime answer", async () => {
    const frozen = await probeAtimeSupport(root, async () => undefined);
    expect(frozen).toEqual({ supported: false, reason: "atime-frozen" });
    // and nothing is armed on a host that answers that way, so no read count can be quoted from it
    const baseline = await armReadWitness(path.join(root, "nowhere-at-all"));
    expect(baseline.supported).toBe(false);
    expect(baseline.entries.size).toBe(0);
  });

  it("says probe-failed when it cannot write into the directory at all", async () => {
    const locked = path.join(root, "locked-root");
    await fs.mkdir(locked, { recursive: true });
    await fs.chmod(locked, 0o500);
    const result = await probeAtimeSupport(locked);
    await fs.chmod(locked, 0o700);
    expect(result).toEqual({ supported: false, reason: "probe-failed" });
  });

  it("names a file it could not arm, and a directory it could not list, as blind spots", async () => {
    await writeAged("a.ts", "1\n");
    await fs.mkdir(merged, { recursive: true });
    await execFileAsync("cp", ["-a", real + "/.", merged]);
    // listable, not traversable: readdir names the child and every stat of it is refused
    await fs.mkdir(path.join(merged, "listable"), { recursive: true });
    await fs.writeFile(path.join(merged, "listable", "b.ts"), "2\n");
    // not listable at all: the whole subtree is invisible to the walk
    await fs.mkdir(path.join(merged, "sealed-off", "deep"), { recursive: true });
    await fs.writeFile(path.join(merged, "sealed-off", "deep", "c.ts"), "3\n");
    await fs.chmod(path.join(merged, "listable"), 0o600);
    await fs.chmod(path.join(merged, "sealed-off"), 0o000);

    const baseline = await armReadWitness(merged);
    await fs.chmod(path.join(merged, "listable"), 0o700);
    await fs.chmod(path.join(merged, "sealed-off"), 0o700);

    expect(baseline.entries.has("a.ts")).toBe(true);
    expect(baseline.unarmed).toContain("listable/b.ts");
    expect(baseline.unwalked).toContain("sealed-off");
    expect((await collectReadWitness(baseline)).blindSpots).toBe(2);
  });
});

describe("the ordering the wiring has to get right", () => {
  /**
   * The OLD order, kept as the control: snapshot first, then a single arm, nothing after.
   *
   * This is what the two-pass arm replaced. The arm perturbs the very stats the snapshot just
   * recorded, so a turn that does nothing hands capture the whole workspace. It is here to show the
   * problem is real rather than assumed, which is the only reason the ordering above is worth its
   * cost.
   */
  async function sealArmingAfterTheSnapshot() {
    await fs.mkdir(merged, { recursive: true });
    await execFileAsync("cp", ["-a", real + "/.", merged]);
    const realInodes = (await snapshotStats(real)).inodes;
    const sealed = await snapshotStats(merged, { hash: true, maxHashBytes: defaultLimits.maxEffectBytes });
    const baseline = await armReadWitness(merged);
    return { baseline, realInodes, sealed };
  }

  it("arming before the sealed snapshot and re-arming after it leaves capture with nothing to report", async () => {
    await writeSubMillisecond("fresh.ts", "1\n");
    await writeAged("aged.ts", "2\n");
    const sealed = await seal();
    const captured = await capture(sealed);
    // the arm did move it: a sub-millisecond time cannot survive a `utimes`, which is the whole
    // reason the ordering matters
    expect(sealed.sealed.signatures.get("fresh.ts")).not.toBe(undefined);
    expect(captured.effects).toEqual([]);
  });

  it("arming AFTER the snapshot, the order this replaced, makes a turn that did nothing look like a rewrite", async () => {
    await writeSubMillisecond("fresh.ts", "1\n");
    const stale = await sealArmingAfterTheSnapshot();
    const captured = await captureEffects({
      shadowDir: root,
      real,
      mechanism: "copy",
      sealed: stale.sealed,
      realInodes: stale.realInodes,
      limits: defaultLimits,
    });
    expect(captured.effects.map((e) => e.path)).toContain("fresh.ts");
  });

  /**
   * THE INVARIANT THE WHOLE FIX RESTS ON, asserted rather than left to the verdict tests.
   *
   * `utimes` stores whole microseconds and `Date` carries whole milliseconds, and for about half of
   * all millisecond values the conversion loses a microsecond. A seal holding such a value can be
   * matched by no `Date`-based restore, so the same turn committed or discarded depending on which
   * millisecond its fixture happened to be written in. Pass one refuses to leave a file on a value
   * it cannot reproduce, and this is that promise stated directly: every armed file's recorded time
   * survives a round trip through `new Date`, so no verdict downstream can depend on which file it
   * was.
   */
  it("leaves every armed file on a time a Date reproduces exactly, which is what makes a verdict repeatable", async () => {
    await writeSubMillisecond("fresh.ts", "1\n");
    await writeSubMillisecond("also-fresh.ts", "2\n");
    await writeAged("aged.ts", "3\n");
    const sealed = await seal();
    expect(sealed.baseline.entries.size).toBe(3);
    for (const rel of sealed.baseline.entries.keys()) {
      const full = path.join(merged, rel);
      const before = await fs.lstat(full);
      await fs.utimes(full, new Date(before.atimeMs), new Date(before.mtimeMs));
      const after = await fs.lstat(full);
      expect(after.mtimeMs).toBe(before.mtimeMs);
      expect(after.atimeMs).toBe(before.atimeMs);
    }
  });

  it("the seal still compares content, so a real edit behind a restored stat is still caught", async () => {
    await writeSubMillisecond("fresh.ts", "1\n");
    const sealed = await seal();
    // restore the stat the seal recorded while changing the bytes, the CAP02 shape
    const before = await fs.lstat(path.join(merged, "fresh.ts"));
    await fs.writeFile(path.join(merged, "fresh.ts"), "9\n");
    await fs.utimes(path.join(merged, "fresh.ts"), before.atime, before.mtime);
    const captured = await capture(sealed);
    expect(captured.effects.map((e) => e.path)).toEqual(["fresh.ts"]);
  });

  /**
   * The claim the second pass exists to answer, measured on both sides of it.
   *
   * A single arm placed before the snapshot is not enough: the snapshot hashes every file, spends
   * every arm, and the witness reports the platform's own work as the turn's. That half is the
   * reason the docstring used to say the arm had to go last. The other half is that it is fixable,
   * because a second pass can put the access times back without moving a modification time.
   */
  it("a single arm before the sealed snapshot reports the seal's own hashing as the turn's reads", async () => {
    await writeAged(".env", "TOKEN=abc\n");
    await writeAged("src/index.ts", "export const a = 1;\n");
    await fs.mkdir(merged, { recursive: true });
    await execFileAsync("cp", ["-a", real + "/.", merged]);
    const early = await armReadWitness(merged);
    await snapshotStats(merged, { hash: true, maxHashBytes: defaultLimits.maxEffectBytes });
    // the turn runs and reads nothing at all
    const witness = await collectReadWitness(early);
    expect(witness.observations.map((o) => o.path).sort()).toEqual([".env", "src/index.ts"]);
  });

  it("re-arming after the sealed snapshot puts them back, and the same turn reads nothing", async () => {
    await writeAged(".env", "TOKEN=abc\n");
    await writeAged("src/index.ts", "export const a = 1;\n");
    const sealed = await seal();
    // the turn runs and reads nothing at all
    const witness = await collectReadWitness(sealed.baseline);
    expect(witness.observations).toEqual([]);
    expect(witness.armed).toBe(2);
    expect(witness.changed).toBe(0);
  });

  it("collecting after capture reports the trusted server's own hashing as the turn's reads", async () => {
    await writeAged(".env", "TOKEN=abc\n");
    await writeAged("src/index.ts", "export const a = 1;\n");
    const sealed = await seal();
    // the turn reads nothing at all
    await capture(sealed);
    const late = await collectReadWitness(sealed.baseline);
    expect(late.observations.map((o) => o.path).sort()).toEqual([".env", "src/index.ts"]);
  });
});

describe("selectivity, the number that separates a sweep from a theft", () => {
  it("separates a targeted read from a whole-tree scan that swept the same file up", async () => {
    await writeAged(".env", "TOKEN=abc\n");
    for (let i = 0; i < 60; i += 1) await writeAged(`src/mod${i}.ts`, `export const n = ${i};\n`);

    const targeted = await seal();
    await turn("cat .env > /dev/null");
    const theft = await collectReadWitness(targeted.baseline);
    await fs.rm(merged, { recursive: true, force: true });

    const sweeping = await seal();
    await turn("grep -rl zzz . > /dev/null 2>&1 || true");
    const sweep = await collectReadWitness(sweeping.baseline);

    expect(theft.protectedReads).toBe(1);
    expect(sweep.protectedReads).toBe(1);
    // the protected-read bit cannot tell them apart; selectivity can
    expect(theft.selectivity!).toBeLessThan(0.05);
    expect(sweep.selectivity!).toBeGreaterThan(0.9);
  });
});

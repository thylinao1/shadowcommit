import crypto from "node:crypto";
import type { Stats } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { canonicalPath, statSignature } from "./capture.js";
import { compareByCodeUnit } from "./stable-order.js";
import { isProtectedPath } from "./effect-classifier.js";

/**
 * A read is not an effect, and that is the hole in the middle of the design.
 *
 * `EffectKind` is create, modify, delete, symlink, outbound. A turn that opens every credential in
 * the sealed view and writes nothing produces an EMPTY effect set, so the policy is handed nothing,
 * every rule abstains, and the turn commits under rule `none`. The transaction can roll a write
 * back. It cannot roll a read back, because what the turn learned has already left through the
 * model channel, which the broker allowlists.
 *
 * This module is the smallest honest thing that can be said about that hole. It does not make a
 * read into an effect and it does not decide a turn. It records, on the trusted side, which files
 * in the sealed view were opened, using the one signal the platform can observe without a kernel
 * hook: the access time on the sealed copy.
 *
 * ## The mechanism, and why it needs arming
 *
 * Filesystems do not update `atime` on every read. Linux mounts `relatime` by default and APFS
 * behaves the same way: the access time is written only when it is already older than the
 * modification time, or older than a day. A freshly sealed copy has `atime == mtime` (`cp -a`
 * preserves both), so the first read of every file would go unrecorded.
 *
 * So the seal ARMS the copy: every regular file gets its access time pushed back behind its
 * modification time. The next read then writes a new access time, whatever process performs it and
 * whatever syscall it uses. Measured on this host: `cat`, `grep`, `head -c 1`, `dd`, a Python
 * `mmap`, and `read(2)` of a single byte all move it; `open` without a read, and `lstat`, do not.
 *
 * ## The arm is TWO passes, and the sealed snapshot goes between them
 *
 * The seal's own work is reads. `cp -a` reads every byte, link neutralisation reads every link, and
 * the sealed snapshot hashes every regular file in the copy. A single arm placed before any of that
 * reports the trusted server's own hashing as the turn's reads, on every file, on every turn, and
 * `read-witness.test.ts` holds that case so the claim stays measured rather than asserted.
 *
 * The arm therefore runs in two passes with the snapshot between them:
 *
 * 1. `armReadWitness` sets each file's times. It is free to CHOOSE what it writes, because nothing
 *    has recorded a signature yet, and that freedom is what the whole design turns on.
 * 2. The caller takes the sealed snapshot, which hashes every file and so moves every access time.
 * 3. `rearmReadWitness` pushes the access times back behind the modification times again, WITHOUT
 *    moving a modification time, and records what each file reads as. The window the witness
 *    measures is therefore exactly the turn, and the snapshot recorded the same signature the
 *    second pass leaves behind, so there is nothing to reconcile afterwards.
 *
 * ## Why pass one chooses the time instead of preserving it
 *
 * `utimes` takes a `Date`, whose time value is a whole number of milliseconds, and the platform
 * stores whole MICROSECONDS. Measured on this host over 3,000 consecutive millisecond values, a
 * requested whole millisecond is stored exactly 1,512 times and stored 1 microsecond short 1,488
 * times, decided by the value and not by timing. So for about half of all modification times, a
 * file armed to `M` reads back as `M - 0.000001`, `statSignature` carries that fraction, and the
 * next `new Date(mtimeMs)` anyone writes truncates it to `M - 1` and lands a full millisecond away.
 * That amplification is what made a verdict differ run to run on identical input.
 *
 * Pass one closes it by refusing to leave a file on a time it cannot reproduce. It writes a
 * candidate, reads it back, and keeps it only when BOTH clocks survive the round trip; otherwise it
 * steps the candidate down a millisecond and tries again, and falls back to the whole second below,
 * which is exact for every value because dividing a whole number of seconds' worth of milliseconds
 * by 1000 is exact in binary floating point. Measured over 400 files: 213 settled on the first
 * candidate, 119 on the second, 68 on the third, and the fallback was never reached. Every file in
 * the sealed copy therefore carries a modification time that a `Date` round trips exactly, which is
 * what makes pass two able to restore an access time without disturbing a signature, and what makes
 * an honest restore by the turn reproduce the armed value every time instead of half the time.
 *
 * ## The evasion, and the second bit that closes it
 *
 * A turn that knows it is being watched can `stat` a file, read it, and put the access time back
 * with `utimes`. Restoring it exactly is possible, because the armed value is readable.
 *
 * `ctime` is not. No syscall sets it; the kernel moves it whenever the inode changes, and calling
 * `utimes` is a change to the inode. So a file whose `ctime` advanced while its size, modification
 * time and mode are all identical to the armed values is a file whose timestamps were rewritten by
 * hand, and that is reported as `timestamp-tampered` rather than passed over. A plain read does not
 * move `ctime`, so the two bits do not collide.
 *
 * ## What this cannot do, stated here rather than found later
 *
 * - It is one bit per file per turn, not a count and not an order. After the first read the access
 *   time is newer than the modification time, so `relatime` stops recording.
 * - It needs a filesystem that keeps access times. `probeAtimeSupport` measures that against the
 *   real directory instead of assuming it, and an unsupported host reports `supported: false`
 *   rather than an empty read list, because "no reads" and "cannot see reads" are different
 *   answers and only one of them is evidence.
 * - It sees the sealed copy. Under the overlay mechanism an unmodified file is read through the
 *   lower layer, which is the real workspace, so arming would write access times into the real
 *   tree. That is a different decision and this module does not take it: `armReadWitness` is for a
 *   directory the platform owns.
 * - A file the arm could not touch is counted in `unarmed`, not skipped quietly. Coverage is a
 *   number the caller can read.
 */

/** Access time is pushed this far behind the modification time. Past `relatime`'s day, on purpose. */
export const ARM_BACKDATE_MS = 25 * 60 * 60 * 1000;

/**
 * How many millisecond values below a file's own time the arm will try before falling back.
 *
 * Each candidate is stored exactly or not, decided by the value, at roughly even odds. Four is
 * therefore about a 1-in-16 chance of reaching the fallback, and the fallback is exact by
 * construction, so this bounds the work rather than the correctness. Measured over 400 files: 213
 * settled on the first candidate, 119 on the second, 68 on the third, none on the fourth.
 */
export const ARM_CANDIDATE_STEPS = 4;

/** Cap on the observations carried in a compact summary record. */
export const MAX_SUMMARY_PATHS = 64;

export interface ReadWitnessEntry {
  /** access time in nanoseconds immediately after arming */
  atimeNs: bigint;
  /** change time in nanoseconds immediately after arming; the arm itself moved it */
  ctimeNs: bigint;
  /** `size:mtimeMs:mode`, the same spelling capture seals with */
  signature: string;
}

export interface ReadWitnessBaseline {
  root: string;
  supported: boolean;
  /** slug: `armed`, `atime-frozen`, `probe-failed`, or `unreadable-root` */
  reason: string;
  armedAt: string;
  entries: Map<string, ReadWitnessEntry>;
  /** regular files the arm could not set times on; each is a blind spot */
  unarmed: string[];
  /**
   * Directories the walk could not list, whose whole subtree is therefore unwatched.
   *
   * A directory the process may read but not traverse (mode 0600) lists its children and refuses
   * every stat of one; a directory it may not read at all (mode 0000) refuses the listing. Both
   * used to end in a `catch` that returned, so the arm reported full coverage over a tree it had
   * never seen. A blind spot that is counted is a limit; a blind spot that is not is a lie.
   */
  unwalked: string[];
  armMs: number;
}

export type ReadWitnessKind = "read" | "timestamp-tampered";

export interface ReadObservation {
  path: string;
  canonicalPath: string;
  kind: ReadWitnessKind;
  /** true when the path is a protected asset under the platform defaults plus the caller's set */
  protectedAsset: boolean;
}

export interface ReadWitnessReport {
  supported: boolean;
  reason: string;
  /** regular files that carried a live arm when the turn started */
  armed: number;
  observations: ReadObservation[];
  reads: number;
  tampered: number;
  protectedReads: number;
  /**
   * Files whose seal signature moved during the turn. They are capture's business, not this
   * module's, and they are counted rather than reported so a caller can see the whole tree
   * accounted for.
   */
  changed: number;
  /** armed files that no longer exist; also capture's business */
  vanished: number;
  /**
   * Files the arm could not set times on plus directories it could not list. Coverage is
   * `armed / (armed + blindSpots)` and a caller that quotes a read count without this number is
   * quoting a fraction of a tree as if it were the tree.
   */
  blindSpots: number;
  /**
   * reads divided by armed files, or null when nothing was armed.
   *
   * The discriminator that survives contact with a real workspace. A turn that opened four files
   * and one of them was `.env` is not the same event as a turn that ran `grep -r` over nine
   * hundred files and swept `.env` up with them, and the raw protected-read bit cannot tell them
   * apart. This can.
   */
  selectivity: number | null;
  collectMs: number;
}

/**
 * Does this filesystem record reads at all?
 *
 * Measured against `dir` itself, because the answer belongs to the mount and not to the platform:
 * the same server sees it one way on an ext4 volume and another on one mounted `noatime`. The
 * probe writes one file, arms it, reads it, and removes it.
 */
export async function probeAtimeSupport(
  dir: string,
  /**
   * How the probe reads its own file. The default is the real thing. A caller passing a reader that
   * does not read is standing in for a mount that does not record one, which is the only way to
   * exercise the `atime-frozen` answer on a host that is not mounted that way.
   */
  read: (absolute: string) => Promise<unknown> = (absolute) => fs.readFile(absolute),
): Promise<{ supported: boolean; reason: string }> {
  const probe = path.join(dir, `.read-witness-probe-${crypto.randomBytes(8).toString("hex")}`);
  try {
    await fs.writeFile(probe, "probe\n");
  } catch {
    return { supported: false, reason: "probe-failed" };
  }
  try {
    const armed = await armOne(probe);
    if (!armed) return { supported: false, reason: "probe-failed" };
    await read(probe);
    const after = await fs.lstat(probe, { bigint: true });
    return after.atimeNs !== armed.entry.atimeNs
      ? { supported: true, reason: "armed" }
      : { supported: false, reason: "atime-frozen" };
  } catch {
    return { supported: false, reason: "probe-failed" };
  } finally {
    await fs.rm(probe, { force: true }).catch(() => undefined);
  }
}

/**
 * The seal signature of one path, in the ONE representation the rest of the platform uses.
 *
 * A `bigint` stat truncates `mtimeMs` to whole milliseconds and a plain stat does not, so the two
 * disagree on any file whose modification time carries a fraction. Capture compares against the
 * plain one, so every signature this module computes or compares is taken from a plain stat, and
 * the `bigint` stat is used for nothing but the nanosecond clocks.
 */
async function signatureOf(absolute: string): Promise<string | null> {
  const stat = await fs.lstat(absolute).catch(() => null);
  return stat ? statSignature(stat) : null;
}

/**
 * Writes both clocks for one file and reports whether the platform stored what it was asked for.
 *
 * `Date` carries a whole number of milliseconds and the platform stores whole microseconds, and the
 * conversion between them loses a microsecond for about half of all millisecond values. So the
 * answer is not assumed from the call succeeding: the file is stat-ed back, and the caller is told
 * whether BOTH clocks survived. Both, because the seal signature carries the modification time and
 * the tamper bit is read off the access time, so a value that round trips on one clock and not the
 * other still makes a verdict depend on which file it was.
 */
async function writeArmTimes(
  absolute: string,
  mtimeMs: number,
): Promise<{ stat: Stats; exact: boolean } | null> {
  try {
    await fs.utimes(absolute, new Date(mtimeMs - ARM_BACKDATE_MS), new Date(mtimeMs));
  } catch {
    return null;
  }
  const stat = await fs.lstat(absolute).catch(() => null);
  if (!stat) return null;
  return { stat, exact: stat.mtimeMs === mtimeMs && stat.atimeMs === mtimeMs - ARM_BACKDATE_MS };
}

/**
 * Pushes one file's access time behind its modification time and returns what it now reads as.
 *
 * It also CHOOSES the modification time, which is the part that matters. Preserving the file's own
 * time is impossible to do exactly: a file the clock just wrote carries nanoseconds and the arm can
 * only express milliseconds. Landing on an arbitrary nearby value is worse than it sounds, because
 * about half of them are stored a microsecond short, and a `Date` cannot express the value that
 * comes back. Everything downstream then writes a timestamp a full millisecond away from the one
 * the seal recorded, and whether a turn commits depends on which millisecond its fixture happened
 * to be written in.
 *
 * So the arm walks DOWN from the file's own millisecond until it finds one the platform stores
 * exactly, and settles there. Down rather than up, so a file in the sealed copy is never stamped
 * newer than the file it was copied from. The last resort is the whole second below, which is exact
 * for every value: a whole number of seconds' worth of milliseconds divided by 1000 is an integer
 * small enough to be represented exactly, so the conversion has no fraction to lose. Measured over
 * 400 files it was never needed, and over 4,000 whole-second values it was exact 4,000 times.
 */
async function armOne(absolute: string): Promise<{ before: string; entry: ReadWitnessEntry } | null> {
  const before = await fs.lstat(absolute).catch(() => null);
  if (!before || !before.isFile()) return null;
  const base = Math.floor(before.mtimeMs);
  let settled: Stats | null = null;
  for (let step = 0; step < ARM_CANDIDATE_STEPS && settled === null; step += 1) {
    const written = await writeArmTimes(absolute, base - step);
    if (written === null) return null;
    if (written.exact) settled = written.stat;
  }
  if (settled === null) {
    const wholeSecond = Math.floor(base / 1000) * 1000;
    const written = await writeArmTimes(absolute, wholeSecond);
    // A file left on a time the platform will not reproduce is a file whose verdict would depend on
    // its timestamp, so it is reported as unarmed rather than watched on a value that drifts.
    if (written === null || !written.exact) return null;
    settled = written.stat;
  }
  const clocks = await fs.lstat(absolute, { bigint: true }).catch(() => null);
  if (!clocks) return null;
  return {
    before: statSignature(before),
    entry: { atimeNs: clocks.atimeNs, ctimeNs: clocks.ctimeNs, signature: statSignature(settled) },
  };
}

export interface ArmOptions {
  /** workspace-relative paths for which the walk does not descend or arm */
  skip?: (relPath: string) => boolean;
  /**
   * Where the support probe writes its one temporary file. Defaults to `root`, and must name a
   * directory on the same filesystem as `root`, because the question the probe answers belongs to
   * the mount.
   *
   * It became load-bearing the moment this was wired. `root` is the sealed view, and capture walks
   * the sealed view to build the effect set the turn is judged on. The probe removes its file in a
   * `finally`, so the normal case is clean, but a removal that failed would leave a file the turn
   * never wrote inside the set of things the turn is answerable for, and the platform would have
   * invented an effect. The runner therefore points this at the shadow directory that CONTAINS the
   * sealed copy: same mount, same answer, nothing left where capture looks.
   */
  probeDir?: string;
  /**
   * How the support probe reads its own file, handed to `probeAtimeSupport`.
   *
   * The default is the real read. A caller passing a reader that does not read is standing in for
   * a MOUNT that does not record one, which is the only way to exercise the `atime-frozen` answer
   * on a host that is not mounted that way. What it replaces is one syscall on one throwaway file:
   * the walk, the arm, the collection and the journal fields all run for real underneath it.
   */
  probeRead?: (absolute: string) => Promise<unknown>;
}

/**
 * Arms every regular file under `root` and records what each one reads as afterwards.
 *
 * Call it on the sealed copy as the last thing the seal does that WRITES, immediately BEFORE the
 * sealed snapshot, and call `rearmReadWitness` immediately after that snapshot. This pass performs
 * one `lstat`, one to four `utimes` and the same number of `lstat` calls per file, and opens
 * nothing, so its cost does not depend on how large the files are.
 *
 * On its own this pass is not a witness. The snapshot that follows it reads every file and spends
 * every arm, which is why the second pass exists; a caller that skips it gets a witness reporting
 * the platform's own hashing as the turn's reads, and `read-witness.test.ts` holds that case.
 *
 * Directories and symlinks are deliberately left alone. A directory's access time moves on any
 * `ls`, which says nothing about whether a secret was opened, and a symlink's own access time did
 * not move on `readlink` when it was measured, so arming one would promise a signal that is not
 * there. Reading THROUGH a link moves the target's access time, and the target is armed.
 */
export async function armReadWitness(root: string, opts: ArmOptions = {}): Promise<ReadWitnessBaseline> {
  const started = Date.now();
  const entries = new Map<string, ReadWitnessEntry>();
  const unarmed: string[] = [];
  const unwalked: string[] = [];
  const probeDir = opts.probeDir ?? root;
  const support =
    opts.probeRead === undefined
      ? await probeAtimeSupport(probeDir)
      : await probeAtimeSupport(probeDir, opts.probeRead);

  const walk = async (dir: string, prefix: string): Promise<void> => {
    let dirents;
    try {
      dirents = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      unwalked.push(prefix);
      return;
    }
    for (const entry of dirents) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (opts.skip?.(rel)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full, rel);
        continue;
      }
      if (!entry.isFile()) continue;
      const armed = await armOne(full);
      if (!armed) {
        unarmed.push(rel);
        continue;
      }
      entries.set(rel, armed.entry);
    }
  };

  if (support.supported) await walk(root, "");

  return {
    root,
    supported: support.supported,
    reason: support.reason,
    armedAt: new Date().toISOString(),
    entries,
    unarmed,
    unwalked,
    armMs: Date.now() - started,
  };
}

/**
 * The second arm pass: puts the access times back after the sealed snapshot spent them.
 *
 * Call it immediately after the snapshot and before the agent runs. The snapshot hashes every
 * regular file in the copy, and a hash is a read, so by the time it returns every access time the
 * first pass set has been overwritten and the witness would see the platform's own work instead of
 * the turn's. This walks the files the first pass armed and pushes each access time back behind its
 * modification time again, so the window the witness measures starts here.
 *
 * It does NOT move a modification time, and that is the property the whole ordering rests on. The
 * first pass left every file on a time the platform stores exactly, so writing that same time back
 * is a no-op on the value the snapshot recorded a moment ago. That is checked rather than trusted:
 * a file whose signature came back different is dropped from the watched set and counted as a blind
 * spot, because a file whose recorded signature no longer matches the copy is one capture will
 * report as modified, and claiming to watch it would hide that behind a read count.
 *
 * Returns the number of files it re-armed.
 */
export async function rearmReadWitness(baseline: ReadWitnessBaseline): Promise<number> {
  if (!baseline.supported) return 0;
  let rearmed = 0;
  for (const [rel, previous] of [...baseline.entries]) {
    const absolute = path.join(baseline.root, rel);
    const before = await fs.lstat(absolute).catch(() => null);
    if (before === null) {
      // Gone between the two passes. It is capture's business now, not a file this can watch.
      baseline.entries.delete(rel);
      continue;
    }
    const expected = statSignature(before);
    const written = await writeArmTimes(absolute, before.mtimeMs);
    const clocks =
      written === null ? null : await fs.lstat(absolute, { bigint: true }).catch(() => null);
    if (written === null || clocks === null || statSignature(written.stat) !== expected) {
      baseline.entries.delete(rel);
      baseline.unarmed.push(rel);
      continue;
    }
    baseline.entries.set(rel, {
      atimeNs: clocks.atimeNs,
      ctimeNs: clocks.ctimeNs,
      signature: expected,
    });
    rearmed += 1;
  }
  baseline.armedAt = new Date().toISOString();
  return rearmed;
}

export interface CollectOptions {
  /** added to the platform's own protected patterns, the same union the classifier takes */
  protectedPaths?: readonly RegExp[];
}

/**
 * Reads the arm back off the sealed copy after the turn.
 *
 * Must run BEFORE effect capture. Capture hashes every regular file in the copy, and a hash is a
 * read, so a witness collected afterwards reports the trusted server's own work as the turn's.
 * That is the one ordering mistake that turns this module into a signal generator, and the test
 * beside it holds the line.
 */
export async function collectReadWitness(
  baseline: ReadWitnessBaseline,
  opts: CollectOptions = {},
): Promise<ReadWitnessReport> {
  const started = Date.now();
  const extra = opts.protectedPaths ?? [];
  const observations: ReadObservation[] = [];
  let changed = 0;
  let vanished = 0;

  if (!baseline.supported) {
    return {
      supported: false,
      reason: baseline.reason,
      armed: 0,
      observations: [],
      reads: 0,
      tampered: 0,
      protectedReads: 0,
      changed: 0,
      vanished: 0,
      blindSpots: baseline.unarmed.length + baseline.unwalked.length,
      selectivity: null,
      collectMs: Date.now() - started,
    };
  }

  for (const [rel, armed] of baseline.entries) {
    const absolute = path.join(baseline.root, rel);
    const now = await fs.lstat(absolute, { bigint: true }).catch(() => null);
    const signature = now ? await signatureOf(absolute) : null;
    if (!now || signature === null) {
      vanished += 1;
      continue;
    }
    if (signature !== armed.signature) {
      // The turn wrote to it, so capture already has it as a create or a modify and the policy
      // already judges it. Counting it here and claiming it twice would inflate both.
      changed += 1;
      continue;
    }
    const canonical = canonicalPath(rel);
    const kind: ReadWitnessKind | null =
      now.atimeNs !== armed.atimeNs
        ? "read"
        : now.ctimeNs !== armed.ctimeNs
          ? "timestamp-tampered"
          : null;
    if (kind === null) continue;
    observations.push({
      path: rel,
      canonicalPath: canonical,
      kind,
      protectedAsset: isProtectedPath(canonical, extra),
    });
  }

  const reads = observations.filter((o) => o.kind === "read").length;
  const tampered = observations.length - reads;
  return {
    supported: true,
    reason: baseline.reason,
    armed: baseline.entries.size,
    observations,
    reads,
    tampered,
    protectedReads: observations.filter((o) => o.protectedAsset).length,
    changed,
    vanished,
    blindSpots: baseline.unarmed.length + baseline.unwalked.length,
    selectivity: baseline.entries.size === 0 ? null : reads / baseline.entries.size,
    collectMs: Date.now() - started,
  };
}

export interface ReadWitnessRecord {
  supported: boolean;
  reason: string;
  armed: number;
  reads: number;
  tampered: number;
  protectedReads: number;
  blindSpots: number;
  selectivity: number | null;
  /** protected observations first, then tampering, bounded */
  paths: string[];
  pathsTruncated: number;
}

/**
 * The compact form for a journal line or a containment record.
 *
 * Protected observations and tampering come first, because a bound that drops them in favour of
 * the four hundred source files a build happened to open would hide the only part anybody reads.
 */
export function summariseReadWitness(
  report: ReadWitnessReport,
  max: number = MAX_SUMMARY_PATHS,
): ReadWitnessRecord {
  const rank = (o: ReadObservation): number =>
    o.protectedAsset ? 0 : o.kind === "timestamp-tampered" ? 1 : 2;
  // Code units, not `localeCompare`, and here it decides more than an order. The sort is followed by
  // a `slice(0, max)`, so the comparator chooses WHICH observations survive truncation, and the
  // survivors are spread into a journal record at transactional-runner.ts:406. A hash-chained record
  // whose contents depend on the host's locale is the exact failure `stable-order.ts` exists to
  // remove: two machines running the same turn over the same files would keep different paths and
  // chain different hashes. `rank` still comes first, so protected and tampered observations are
  // never displaced by ordinary reads.
  const ordered = [...report.observations].sort(
    (a, b) => rank(a) - rank(b) || compareByCodeUnit(a.path, b.path),
  );
  const kept = ordered.slice(0, Math.max(0, max));
  return {
    supported: report.supported,
    reason: report.reason,
    armed: report.armed,
    reads: report.reads,
    tampered: report.tampered,
    protectedReads: report.protectedReads,
    blindSpots: report.blindSpots,
    selectivity: report.selectivity,
    paths: kept.map((o) => (o.kind === "read" ? o.path : `${o.path} (${o.kind})`)),
    pathsTruncated: Math.max(0, ordered.length - kept.length),
  };
}

/* ------------------------------------------------------------------------------------------------
 * The wiring. Three things the product does with a witness, and the one thing it must not do.
 *
 * What follows is what the runner calls: build a witness that failed into the same shape as one
 * that worked, read the arm back without letting the reading throw a turn, put the record on the
 * journal line, and put it on the context the policy is handed. There is deliberately no rule here
 * and no verdict: this module records, and something else decides.
 *
 * The decision now exists and lives in `rules/read-exposure.ts`, which is the only consumer of
 * `readWitnessOf` in the whole registry. It is kept out of this file on purpose, because the raw
 * protected-read bit is 35.4% false positive on the measured benign set and 10.4% behind the
 * selectivity gate, against a human-ask rate already at 24.1% of benign turns. A signal at that
 * rate is not a control until something narrows it, the narrowing is a cost decision with its own
 * measurement, and a module that both produces evidence and rules on it gives nobody a place to
 * change one without the other. What is wired here is still the observation and nothing else.
 * ---------------------------------------------------------------------------------------------- */

/** How many observed paths a journal line carries. Protected and tampered first; see summarise. */
export const JOURNAL_READ_PATHS = 20;

/**
 * A baseline for a witness that could not be established, in the same shape as one that was.
 *
 * The alternative is a `null` witness, and `null` already means something else here: it is what the
 * overlay mechanism produces, where the sealed view is not a directory the platform owns and arming
 * it would write access times into the user's real repository. A failed arm reported as `null`
 * would read on the journal line exactly like an overlay turn, which is the silent degradation this
 * repository keeps being bitten by. It gets its own reason instead, and everything downstream
 * treats it the way it treats a mount that does not record reads: no read count is quoted at all.
 */
export function failedReadWitness(root: string, reason: string): ReadWitnessBaseline {
  return {
    root,
    supported: false,
    reason,
    armedAt: new Date().toISOString(),
    entries: new Map(),
    unarmed: [],
    unwalked: [],
    armMs: 0,
  };
}

/**
 * The collection the runner performs, one turn, immediately BEFORE effect capture.
 *
 * Two things it adds over `collectReadWitness`. A null baseline stays null, because a turn under a
 * mechanism this cannot watch has no witness rather than an empty one. And a collection that throws
 * becomes `collect-failed` rather than an exception, because an observation that cannot decide
 * anything must not be able to fail a turn: the turn's own writes are still captured, still judged
 * and still settled, and the journal says the witness was not read.
 */
export async function collectTurnReadWitness(
  baseline: ReadWitnessBaseline | null,
  opts: CollectOptions = {},
): Promise<ReadWitnessReport | null> {
  if (baseline === null) return null;
  try {
    return await collectReadWitness(baseline, opts);
  } catch {
    return collectReadWitness(failedReadWitness(baseline.root, "collect-failed"), opts);
  }
}

/**
 * The fields a turn's journal line carries about what the turn read.
 *
 * Three states, and the difference between them is the whole point of the function.
 *
 * `null` is no witness: the overlay mechanism, where the sealed view is the user's own tree. The
 * line says `readWitness: "none"`, the same way a turn with nothing sealing the network says
 * `confinement: "none"`, and it quotes no count.
 *
 * An unsupported witness is a witness that could not see: a mount that does not move access times
 * reports `atime-frozen`, a probe that could not write reports `probe-failed`, and the two failure
 * shapes above report themselves. The line names the reason and quotes NO READ COUNT. Measured on
 * the NUS cluster, atime moved for zero of seven readers and zero fixture shapes on nfs4 relatime,
 * so a cluster home or any network share reaches this branch for real, and a zero printed there
 * would be a turn that read nothing according to a platform that cannot see reads.
 *
 * A supported witness quotes the counts and the paths. `reads` sits beside the effect count so the
 * one line an operator reads about a turn says what it wrote AND what it opened, and `readsArmed`
 * and `readsBlind` sit beside it so the count is readable as a fraction of a tree rather than as a
 * fact about a whole one.
 */
export function readWitnessJournalFields(
  report: ReadWitnessReport | null,
  max: number = JOURNAL_READ_PATHS,
): Record<string, unknown> {
  if (report === null) return { readWitness: "none" };
  // `reason` is "armed" exactly when the witness is supported, so the slug is taken from the report
  // rather than written out twice and left to drift.
  if (!report.supported) return { readWitness: report.reason };
  const record = summariseReadWitness(report, max);
  return {
    readWitness: record.reason,
    reads: record.reads,
    protectedReads: record.protectedReads,
    readsTampered: record.tampered,
    readsArmed: record.armed,
    readsBlind: record.blindSpots,
    ...(record.selectivity === null ? {} : { readSelectivity: Number(record.selectivity.toFixed(4)) }),
    ...(record.paths.length === 0 ? {} : { readPaths: record.paths }),
    ...(record.pathsTruncated === 0 ? {} : { readPathsTruncated: record.pathsTruncated }),
  };
}

/**
 * What a policy is handed about the turn's reads.
 *
 * It is a separate field rather than an effect, and that is the design. A read is not a write, and
 * putting a read into the effect array would put a record in front of every rule in the registry,
 * all of which were written about writes: `protected-asset-write` would fire on a file the turn only
 * opened, and the product would start DISCARDING turns on a signal whose false positive rate nobody
 * has priced. As a context field it reaches exactly one rule, `rules/read-exposure.ts`, which can
 * only ask a person.
 */
export interface ReadWitnessCarrier {
  /**
   * The turn's reads, or `null` when this turn produced no witness at all.
   *
   * Null and `supported: false` are DIFFERENT answers and a rule that treats them alike is wrong in
   * both directions. Null is "this mechanism was not watched". `supported: false` is "this mount
   * cannot show reads". Neither is "this turn read nothing"; only a supported record with
   * `reads: 0` says that.
   */
  readWitness: ReadWitnessRecord | null;
}

/**
 * Puts the record on the context, without mutating the context that was passed in.
 *
 * The field is added structurally rather than by editing `PolicyContext` in `policy-types.ts`,
 * which is a shared contract this lane does not own. `readWitnessOf` is the typed way to read it
 * back, so a rule that wants it never reaches for `any`.
 */
export function attachReadWitness<T extends object>(
  context: T,
  record: ReadWitnessRecord | null,
): T & ReadWitnessCarrier {
  return { ...context, readWitness: record };
}

/**
 * Reads the witness back off a context, returning null when there is none.
 *
 * A caller that quotes `reads` without first asking whether the record is null and whether it is
 * supported is quoting a number that may mean "not watched" or "cannot see". The three states are
 * kept distinguishable all the way to here on purpose.
 */
export function readWitnessOf(context: unknown): ReadWitnessRecord | null {
  if (typeof context !== "object" || context === null) return null;
  const carried = (context as Partial<ReadWitnessCarrier>).readWitness;
  return carried === undefined || carried === null ? null : carried;
}

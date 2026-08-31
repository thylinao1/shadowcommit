import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { EffectRecord } from "./policy-types.js";
import { classifyPath, isDependencyTree } from "./effect-classifier.js";

/**
 * Capture: turning the difference between the sealed copy and the real workspace into the typed
 * effect set the policy judges.
 *
 * Three properties this module is responsible for, each of which a red-team round broke:
 *
 * 1. **Nothing is read before its size is known.** `lstat` first, always. A turn that writes an
 *    8 GB file must cost the trusted server process a stat, not 8 GB of resident memory
 *    (attack a39). Every read here is bounded and every hash is streamed.
 * 2. **Change detection is by content, not by stat.** A file whose bytes changed while its
 *    size, mtime and mode were restored to the sealed values is still an effect (attack CAP02),
 *    so the copy-path seal signature carries a sha256.
 * 3. **Identity does not depend on spelling.** Every effect carries a canonical path (NFC then
 *    case fold) and, for a path that already existed, the real side's dev:ino, so a protected
 *    asset stays protected under a case variant or a Unicode variant (attack ev02).
 */

/**
 * The most work the trusted process will do for one effect: an effect over this is never read and
 * never hashed. It is still recorded, by path, kind, mode and size alone, marked `oversize` so no
 * content rule may read it, and it holds the turn for a person rather than destroying it. The bound
 * on what the JUDGE may ingest is `MAX_SCAN_BYTES`, not this one; every read in the policy is
 * bounded by that and every hash here is streamed, which is what defeats attack a39.
 *
 * A dependency-tree CREATE is exempt. Those bytes came from a package manager, not from the agent,
 * no content rule reads them at any size (`rules/scan-targets.ts`), and four other rules already
 * carve the class out. The exemption is creates only: an install is a create, tampering is a modify,
 * which is the line `rules/dependency-tree.ts` already draws.
 */
export const MAX_EFFECT_BYTES = 8 * 1024 * 1024;
/**
 * The same question for the turn as a whole, over the bytes the turn itself wrote. Dependency-tree
 * creates do not count against it, for the reason above, and a turn over it is held rather than
 * discarded: a total is an accounting fact about the platform's budget, not a judgement about what
 * the turn did.
 */
export const MAX_TURN_BYTES = 256 * 1024 * 1024;
/** The most any content-scanning read hands to the policy. */
export const MAX_SCAN_BYTES = 1024 * 1024;
/** Read granularity for streamed hashing, so memory is constant in file size. */
const CHUNK_BYTES = 64 * 1024;

export interface CaptureLimits {
  maxEffectBytes: number;
  maxTurnBytes: number;
  maxScanBytes: number;
}

export const defaultLimits: CaptureLimits = {
  maxEffectBytes: MAX_EFFECT_BYTES,
  maxTurnBytes: MAX_TURN_BYTES,
  maxScanBytes: MAX_SCAN_BYTES,
};

export function resolveLimits(overrides: Partial<CaptureLimits> = {}): CaptureLimits {
  return { ...defaultLimits, ...overrides };
}

/**
 * One spelling for one file. NFC first so a decomposed accent and a composed accent agree, then a
 * case fold, then NFC again because lowercasing can leave a decomposed form behind.
 */
export function canonicalPath(relPath: string): string {
  return relPath.normalize("NFC").toLowerCase().normalize("NFC");
}

/** sha256 of a file, read in fixed chunks so a large file costs one buffer, not its own size. */
/**
 * The stat signature, in one place. Three sites used to spell it out by hand and the third had
 * drifted: the seal signed a socket as `size:mtime:mode` and the capture compared it against
 * `size:mtime:mode:unreadable`, so every socket read as modified on every copy-sealed turn.
 */
export function statSignature(stat: { size: number; mtimeMs: number; mode: number }): string {
  return `${stat.size}:${stat.mtimeMs}:${stat.mode}`;
}

/**
 * A file's identity, exactly, as `dev:ino`.
 *
 * This is the key behind "identity, not spelling": it is what `policy-context` turns into
 * `protectedInodes` and what `effect.realIno` carries, so that a protected asset reached under
 * another name is still recognised as that asset.
 *
 * It reads the stat a SECOND time with `{bigint: true}` rather than reusing the caller's, and that
 * is deliberate on both counts.
 *
 * Bigint, because a plain `lstat` returns `ino` as a double and a 64 bit file id does not fit in
 * one. MEASURED on this NTFS host: of 400 files, 132 had ids above 2^53 whose keys were stored
 * lossily, and over 6,000 files there were 12 rounded keys claimed by two or more DISTINCT files,
 * one of them by three. Two different files sharing one identity key is the exact failure this key
 * exists to prevent, and a benign file colliding with a protected one gets its turn discarded.
 * macOS and Linux hand out small inodes, so this cannot appear on those hosts.
 *
 * A second read rather than making the caller's stat bigint, because `statSignature` takes numbers
 * and is compared ACROSS the seal and commit boundary. A bigint stat truncates `mtimeMs` to whole
 * milliseconds, so converting it back would produce a different signature string on one side of that
 * comparison than the other, and change detection would break in a way no test here would catch.
 * The second read is CONDITIONAL, so the cost lands only where the precision is actually at risk.
 * MEASURED over 5,000 files: an unconditional second stat took snapshotStats from 214ms to 413ms,
 * and gating it on the id exceeding 2^53 returns every small-inode host to the original cost while
 * still recording the exact identity on a host whose ids are large.
 */
export async function identityKey(
  absolute: string,
  known?: { dev: number; ino: number },
): Promise<string> {
  // The fast path, and the one every macOS and Linux host takes. Inodes there are small integers,
  // a double holds them exactly, and the caller has already paid for this stat. Only a value at or
  // past the point where a double stops being able to represent every integer can have been
  // rounded, so only that case pays for a second read.
  if (known && Math.abs(known.ino) < Number.MAX_SAFE_INTEGER && Math.abs(known.dev) < Number.MAX_SAFE_INTEGER) {
    return `${known.dev}:${known.ino}`;
  }
  const exact = await fs.lstat(absolute, { bigint: true }).catch(() => null);
  if (exact) return `${exact.dev}:${exact.ino}`;
  // A file that vanished between the two reads has no identity to record. Falling back to the lossy
  // form would put a key in the map that claims to be exact, so this does not do that either.
  //
  // What it must NOT do is return a constant. This returned "" and the empty string is not inert:
  // it flows into `realInodes`, then into `protectedInodes` at policy-context.ts, which adds it with
  // no filter, and then into protected-identity.ts, which matches on equality. Two files that both
  // vanished during a seal therefore shared one identity key, and a benign one colliding with a
  // protected one had its turn discarded as if it were that protected asset. That is precisely the
  // failure this whole function exists to prevent, reproduced by its own error path.
  //
  // A path-derived value cannot collide with another path and cannot collide with a real `dev:ino`.
  // It also keeps `realInodes.has(rel)` true, which matters because capture.ts uses that map for
  // EXISTENCE as well as identity (`const existed = realInodes.has(rel)`), so omitting the entry
  // would break change detection rather than fix anything.
  return `unknown:${absolute}`;
}

/** A regular file has bytes. Everything else is identified by its stat and is never opened. */
export function hasBytes(stat: { isFile(): boolean }): boolean {
  return stat.isFile();
}

export async function hashFile(absolute: string): Promise<string | null> {
  let handle;
  try {
    handle = await fs.open(absolute, "r");
  } catch {
    return null;
  }
  try {
    const digest = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(CHUNK_BYTES);
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, CHUNK_BYTES, null);
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
    }
    return digest.digest("hex");
  } catch {
    return null;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/** Reads at most `max` bytes as UTF-8. The cap is the point: a policy never sees an unbounded body. */
export async function readBounded(absolute: string, max: number): Promise<string | null> {
  // The type is checked BEFORE the open. open() on a fifo blocks until a writer shows up, so a
  // read that checks afterwards has already hung. A fifo, a socket or a device has no body to
  // bound, and a policy asking for one gets the same answer as for a file it cannot read.
  const kind = await fs.lstat(absolute).catch(() => null);
  if (!kind || !hasBytes(kind)) return null;
  let handle;
  try {
    handle = await fs.open(absolute, "r");
  } catch {
    return null;
  }
  try {
    const stat = await handle.stat();
    const size = Math.min(Number(stat.size), max);
    if (size <= 0) return "";
    const buffer = Buffer.allocUnsafe(size);
    const { bytesRead } = await handle.read(buffer, 0, size, 0);
    return buffer.subarray(0, bytesRead).toString("utf8");
  } catch {
    return null;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

export interface Snapshot {
  /** path -> "size:mtimeMs:mode", plus ":sha256" when the snapshot was taken with hashing */
  signatures: Map<string, string>;
  /** path -> "dev:ino", the identity of the file rather than the name it was reached by */
  inodes: Map<string, string>;
}

export function emptySnapshot(): Snapshot {
  return { signatures: new Map(), inodes: new Map() };
}

/**
 * Walks a tree recording, per file, a change signature and an inode identity.
 *
 * Called twice per turn with different jobs. On the real workspace it is stat-only, because it is
 * the baseline a conflict check compares against and stats are what keeps that cheap on a large
 * repo. On the sealed copy it hashes, because that is the signature capture compares against and a
 * stat signature can be forged back to its sealed value (CAP02). `cp -a` has already read every
 * byte by then, so the hash is a cost the copy path is paying anyway.
 */
export async function snapshotStats(
  root: string,
  opts: { hash?: boolean; maxHashBytes?: number } = {},
): Promise<Snapshot> {
  const out = emptySnapshot();
  const maxHashBytes = opts.maxHashBytes ?? MAX_EFFECT_BYTES;
  const walk = async (dir: string, prefix: string): Promise<void> => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full, rel);
        continue;
      }
      const stat = await fs.lstat(full).catch(() => null);
      if (!stat) continue;
      out.inodes.set(rel, await identityKey(full, stat));
      // mode is part of the signature: a chmod-only change is a real change to what can run
      let signature = statSignature(stat);
      if (opts.hash && entry.isFile()) {
        // a file past the cap is never read, here or anywhere else; it is marked instead
        signature += stat.size > maxHashBytes ? ":oversize" : `:${(await hashFile(full)) ?? "unreadable"}`;
      }
      out.signatures.set(rel, signature);
    }
  };
  await walk(root, "");
  return out;
}

/** The stat-only signature of one live path, for comparing against a baseline. */
export async function liveSignature(absolute: string): Promise<string | null> {
  const stat = await fs.lstat(absolute).catch(() => null);
  return stat ? statSignature(stat) : null;
}

export interface OversizeEffect {
  path: string;
  bytes: number;
}

export interface CaptureResult {
  effects: EffectRecord[];
  /** effects refused before any read because one file was over the per-effect cap */
  oversize: OversizeEffect[];
  /** total bytes across the captured effects, for the per-turn cap */
  totalBytes: number;
}

export interface CaptureInput {
  shadowDir: string;
  real: string;
  mechanism: "overlay" | "copy";
  /** signatures of the sealed copy, hashed; empty under overlay where `upper` is the effect set */
  sealed: Snapshot;
  /** inode identity of the real workspace at seal, for realIno and for existence */
  realInodes: Map<string, string>;
  limits: CaptureLimits;
}

/**
 * Builds the effect set. Under overlay the `upper` layer already is the set of changes; under the
 * copy fallback a file counts only if its sealed signature no longer holds, and deletions need a
 * second walk of the real workspace because an absence is not an entry in the copy.
 */
export async function captureEffects(input: CaptureInput): Promise<CaptureResult> {
  const { shadowDir, real, mechanism, sealed, realInodes, limits } = input;
  const upper = path.join(shadowDir, mechanism === "overlay" ? "upper" : "merged");
  const effects: EffectRecord[] = [];
  const oversize: OversizeEffect[] = [];
  let totalBytes = 0;

  const walk = async (dir: string, prefix: string): Promise<void> => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name);

      if (entry.isSymbolicLink()) {
        // Only a symlink this turn created or changed is an effect. A link that was already in the
        // workspace is part of the baseline; treating it as an effect blocked all benign work in
        // any workspace that happened to contain one.
        const before = await fs.readlink(path.join(real, rel)).catch(() => null);
        const target = (await fs.readlink(full).catch(() => null)) ?? "";
        if (before !== null && before === target) continue;
        // A symlink must never be dereferenced by the trusted half. Following it would copy the
        // CONTENT of whatever it points at into the real workspace, which turns a one-line agent
        // action into arbitrary file read as the server user.
        const resolved = path.resolve(path.dirname(path.join(real, rel)), target);
        effects.push({
          path: rel,
          kind: "symlink",
          target,
          escapes: !within(real, resolved),
          canonicalPath: canonicalPath(rel),
          ...(realInodes.has(rel) ? { realIno: realInodes.get(rel)! } : {}),
        });
        continue;
      }

      if (entry.isDirectory()) {
        await walk(full, rel);
        continue;
      }

      // an overlayfs whiteout is a 0/0 character device: the file was deleted
      if (entry.isCharacterDevice()) {
        effects.push(...(await expandDelete(real, rel, realInodes)));
        continue;
      }

      // SIZE BEFORE BYTES. Everything below this line would otherwise read the file, and a turn
      // that writes a file larger than memory must not be able to take the server down with it.
      const stat = await fs.lstat(full).catch(() => null);
      if (!stat) continue;
      if (stat.size > limits.maxEffectBytes) {
        // A file the turn never touched must not fail the turn. This check used to run before the
        // unchanged-since-seal comparison below, so one 9 MiB baseline file in the workspace made
        // EVERY turn discard under effect-too-large, terminally, including a turn whose only action
        // wrote seven bytes elsewhere. Any real repository with a build artifact, a dataset or a
        // large pack file was unusable from its first turn.
        //
        // The comparison costs no strength, because it is the one the SEAL itself made: an oversize
        // file is never read here and snapshotStats does not read one either, it records
        // `<statSignature>:oversize`. Matching that is the same evidence, not weaker evidence. The
        // size check still runs ahead of everything that reads bytes, which is what it is for.
        if (mechanism === "copy" && sealed.signatures.get(rel) === `${statSignature(stat)}:oversize`) {
          continue;
        }

        const existedOversize = realInodes.has(rel);

        // An install is not a large write, it is upstream's bytes arriving. A CREATE under
        // node_modules, vendor, .venv or site-packages is exempt from the byte cap and captured
        // normally, because no content rule reads that class at any size (rules/scan-targets.ts)
        // and four other rules already carve it out; the cap was the only thing standing between a
        // 9 MB dependency create and a commit, and nothing at all stands between a 9 KB one and a
        // commit, so the cap was never the control on this path. Measured: `npm install typescript`
        // ships a 9,112,572-byte typescript.js, which killed the whole turn.
        //
        // Creates only, and that is load-bearing rather than tidy. An oversize MODIFY must stay on
        // the capped branch below, because the seal never hashed it either and signed it
        // `<statSignature>:oversize`. Hashing it here would produce `stat:<realhash>`, which can
        // never equal the sealed string, so every untouched over-cap file in the tree would read as
        // changed on every turn. That is exactly the defect 7e66363 fixed, wearing a review verdict
        // instead of a discard.
        if (!existedOversize && isDependencyTree(classifyPath(rel))) {
          const installedSha = await hashFile(full);
          effects.push({
            path: rel,
            kind: "create",
            mode: stat.mode & 0o777,
            bytes: stat.size,
            canonicalPath: canonicalPath(rel),
            ...(installedSha ? { sha256: installedSha } : {}),
          });
          continue;
        }

        // Everything else over the cap is RECORDED rather than refused. The bytes are still never
        // read and still never hashed, which is the whole a39 property: a 100 GB blob costs this
        // process an lstat and a journal line. What changes is that "I cannot read this" stops
        // being a verdict. The record carries the path, kind, mode and size, `oversize` keeps every
        // content rule off it, and blast-radius turns the declared size into a hold, so a person
        // settles it instead of the work being destroyed with no override.
        effects.push({
          path: rel,
          kind: existedOversize ? "modify" : "create",
          mode: stat.mode & 0o777,
          bytes: stat.size,
          canonicalPath: canonicalPath(rel),
          oversize: true,
          ...(existedOversize ? { realIno: realInodes.get(rel)! } : {}),
        });
        // still reported on its own line, so the journal keeps naming which files were not read
        oversize.push({ path: rel, bytes: stat.size });
        continue;
      }

      // A socket, a fifo or a device is never opened. It has no bytes to hash, and open() on a fifo
      // blocks until a writer appears, which made `mkfifo` inside the sealed view a way to stop a
      // turn from ever settling: no privilege needed, and the capture sat in open() for as long as
      // the agent liked. Identity is the stat signature alone, the same shape the seal signed it
      // with. One that existed and is unchanged is nothing; one the turn made is reported as what
      // it is, with no bytes and no hash, and the commit decides what to do about it without
      // reading it either.
      if (!hasBytes(stat)) {
        if (mechanism === "copy" && sealed.signatures.get(rel) === statSignature(stat)) continue;
        const existed = realInodes.has(rel);
        effects.push({
          path: rel,
          kind: existed ? "modify" : "create",
          mode: stat.mode & 0o777,
          bytes: 0,
          canonicalPath: canonicalPath(rel),
          ...(existed ? { realIno: realInodes.get(rel)! } : {}),
        });
        continue;
      }

      let sha256: string | null = null;
      if (mechanism === "copy") {
        const sealedSignature = sealed.signatures.get(rel) ?? null;
        sha256 = await hashFile(full);
        const nowSignature = `${statSignature(stat)}:${sha256 ?? "unreadable"}`;
        // unchanged since the seal means this turn did not touch it, whatever the real workspace
        // has done in the meantime; the hash is what makes a restored stat insufficient
        if (sealedSignature !== null && nowSignature === sealedSignature) continue;
        if (sealedSignature === null && sha256 !== null && sha256 === (await hashFile(path.join(real, rel)))) {
          continue;
        }
      } else {
        sha256 = await hashFile(full);
      }

      const existed = realInodes.has(rel);
      totalBytes += stat.size;
      effects.push({
        path: rel,
        kind: existed ? "modify" : "create",
        mode: stat.mode & 0o777,
        bytes: stat.size,
        canonicalPath: canonicalPath(rel),
        ...(sha256 ? { sha256 } : {}),
        ...(existed ? { realIno: realInodes.get(rel)! } : {}),
      });
    }
  };

  await walk(upper, "");

  if (mechanism === "copy") {
    // Walking a copy shows what still exists. A deletion is an ABSENCE, so it is only visible by
    // walking the real workspace and asking what the copy no longer has. Under overlay this is
    // free (a whiteout is a real entry); under the copy fallback it is this extra pass.
    const seen = new Set(effects.map((effect) => effect.path));
    const walkReal = async (dir: string, prefix: string): Promise<void> => {
      let entries;
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
          await walkReal(path.join(dir, entry.name), rel);
          continue;
        }
        if (seen.has(rel)) continue;
        const stillThere = await fs
          .access(path.join(upper, rel))
          .then(() => true)
          .catch(() => false);
        if (stillThere) continue;
        effects.push({
          path: rel,
          kind: "delete",
          canonicalPath: canonicalPath(rel),
          ...(realInodes.has(rel) ? { realIno: realInodes.get(rel)! } : {}),
        });
      }
    };
    await walkReal(real, "");
  }

  return { effects, oversize, totalBytes };
}

/** a directory whiteout hides every file under it, so `rm -rf src` must not read as one delete */
export async function expandDelete(
  real: string,
  rel: string,
  realInodes: Map<string, string>,
): Promise<EffectRecord[]> {
  const one = (p: string): EffectRecord => ({
    path: p,
    kind: "delete",
    canonicalPath: canonicalPath(p),
    ...(realInodes.has(p) ? { realIno: realInodes.get(p)! } : {}),
  });
  const target = path.join(real, rel);
  const stat = await fs.stat(target).catch(() => null);
  if (!stat?.isDirectory()) return [one(rel)];
  const under: EffectRecord[] = [];
  const walk = async (dir: string, prefix: string): Promise<void> => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const child = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(path.join(dir, entry.name), child);
      else under.push(one(`${rel}/${child}`));
    }
  };
  await walk(target, "");
  return under.length ? under : [one(rel)];
}

/**
 * The identity of an effect set, over sorted `path:kind:sha256` triples.
 *
 * This is what an approval is bound to. Without it an operator approves a runId, and whatever the
 * held turn happens to contain at the moment of the click is what lands (attacks r18 and r07).
 */
export function effectSetHash(effects: EffectRecord[]): string {
  const lines = effects
    .map((effect) => `${effect.path}:${effect.kind}:${effect.sha256 ?? ""}`)
    .sort();
  return crypto.createHash("sha256").update(lines.join("\n")).digest("hex");
}

/**
 * True when a captured path is the shape capture produces: workspace-relative, no parent
 * reference, not absolute.
 *
 * Capture cannot produce anything else, so this is depth rather than the primary control. It
 * matters because the SOURCE side of a commit reads `shadowDir/<path>`, and only the destination
 * side goes through the path resolver: a record carrying `../../etc/passwd` would otherwise read a
 * file the turn never had and write it into the workspace under a name of its choosing.
 */
export function isSafeRelative(relPath: string): boolean {
  if (relPath.length === 0 || path.isAbsolute(relPath)) return false;
  const parts = relPath.split("/");
  return !parts.some((part) => part === ".." || part === "" || part === ".");
}

/** true when `candidate` is inside `base` after resolution, so `..` cannot walk out */
export function within(base: string, candidate: string): boolean {
  const rel = path.relative(path.resolve(base), path.resolve(candidate));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

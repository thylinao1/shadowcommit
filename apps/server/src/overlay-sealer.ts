import { execFile } from "node:child_process";
import crypto from "node:crypto";
import type { Stats } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * Host-side sealing for a transactional turn.
 *
 * The runner opens a turn by handing the agent a sealed view of the workspace. Copying the tree is
 * always correct and costs O(files); an overlay mount costs the same few milliseconds whether the
 * repository holds fifty files or thirty thousand, and its upper layer IS the effect set, so nothing
 * has to be diffed to find out what the turn did.
 *
 * The whole difficulty is the other end. Tearing a copy down is `rm -rf`. Tearing a mount down is
 * `umount` and then `rm -rf`, and if the umount silently failed the delete runs THROUGH the mount.
 * That is the one operation in this system that can destroy the real workspace, so every path here
 * is written so that a delete happens only after the absence of a mount has been proven, and a
 * failure to prove it quarantines rather than deletes.
 *
 * Two consequences shape the module:
 *
 *   1. `seal()` throws for exactly one class of failure and no other: it could not produce a
 *      COMPLETE sealed view. Every mechanism problem still resolves to "copy" with the reason
 *      recorded, because a turn must not be lost over a host that cannot mount an overlay.
 *
 *      A partial copy is a different animal. The effect capture reads the copy fallback by walking
 *      the real workspace and asking what the shadow no longer has, so a file `cp -a` could not
 *      read is indistinguishable from a file the agent deleted. One such file is below every
 *      multi-delete threshold, so it commits, and the commit step removes the real file that the
 *      turn never opened. There is no value `seal()` could return that makes that safe, so a copy
 *      that could not copy everything raises `SealFailedError` after recording `seal.failed` and
 *      removing the partial shadow through the same proven gate a normal teardown uses. A failed
 *      turn is recoverable; a manufactured deletion is not.
 *   2. `seal()` will not return "overlay" unless the caller states that a matching release hook is
 *      wired. The runner's own `release()` is private, swallows the umount failure, and deletes
 *      regardless. Handing that function a live mount leaks the mount and the shadow tree, which is
 *      the orphan-mount defect crash recovery already measured. Refusing the composition we cannot
 *      clean up after is the same rule as refusing the host we cannot unmount on.
 */

export type Mechanism = "overlay" | "copy";

/** at most this many missing paths are named in the error text and the journal record */
const MAX_NAMED_MISSING = 10;

/** a path the workspace has that the sealed copy does not, with what it was, so the record is actionable */
type CopyGap = { rel: string; kind: string };

/**
 * What an entry is, for the failure text. `cp` cannot reproduce a socket at all, so an operator
 * reading `tmp/app.sock (socket)` knows immediately that this is not a transient failure to retry.
 */
function describeEntry(s: Stats): string {
  if (s.isDirectory()) return "directory";
  if (s.isSocket()) return "socket";
  if (s.isFIFO()) return "fifo";
  if (s.isSymbolicLink()) return "symlink";
  if (s.isBlockDevice() || s.isCharacterDevice()) return "device";
  if (s.isFile()) return "file";
  return "unknown type";
}

/**
 * The seal could not produce a complete view of the workspace. Raised only from `seal()`, and only
 * when continuing would hand the effect capture a tree it cannot honestly diff.
 */
export class SealFailedError extends Error {
  readonly reason: string;
  /** workspace-relative paths the copy is missing or truncated, capped for the record */
  readonly missing: string[];

  constructor(reason: string, message: string, missing: string[] = []) {
    super(message);
    this.name = "SealFailedError";
    this.reason = reason;
    this.missing = missing;
  }
}

export interface HostRecord {
  platform: string;
  release: string;
  arch: string;
  uid: number;
  shadowRootFsType: string | null;
}

export interface Capability {
  mechanism: Mechanism;
  /** slug explaining the mechanism chosen, carried into the journal and the sidecar */
  reason: string;
  detail?: string | undefined;
  usesSudo: boolean;
  mountArgv: string[];
  umountArgv: string[];
  host: HostRecord;
  probedInMs: number;
}

export interface MountInfoEntry {
  mountPoint: string;
  fsType: string;
  source: string;
  /** the per-mount option list, field 6. Carries `ro` when the mount came up read-only. */
  options: string;
}

export interface MountProof {
  proven: boolean;
  reason: string;
  offenders: string[];
  corroboration: {
    devDiffersFromParent: boolean | null;
    findmntSaysMounted: boolean | null;
  };
}

export interface UnmountResult {
  ok: boolean;
  how: "already-unmounted" | "eager" | "lazy" | "refused";
  attempts: number;
  classification?: string | undefined;
  lastStderr?: string | undefined;
}

export interface ReleaseResult {
  removed: boolean;
  proof: MountProof;
  unmount: UnmountResult | null;
  quarantinedTo: string | null;
  error?: string | undefined;
}

export interface SealerOptions {
  /** every path this module creates, mounts or deletes lives under here and nowhere else */
  shadowRoot: string;
  /**
   * The runner must call a release that proves the absence of a mount before deleting. Until that
   * hook exists, "overlay" is never returned. Default false on purpose.
   */
  releaseHookWired?: boolean;
  /** force a mechanism; SHADOW_SEAL=copy|overlay does the same from the environment */
  force?: Mechanism;
  /**
   * A sudo-made mount whose writes land as root leaves an upper tree an unprivileged server cannot
   * remove, which turns every turn into a quarantine. Off unless the caller knows the uids match.
   */
  allowSudo?: boolean;
  /**
   * How long a quarantined shadow is kept before a sweep may reclaim it. A quarantine exists
   * because a delete could not be justified at the time, so the reclaim re-proves rather than
   * escalating: past the window it deletes only what it can still prove is unmounted, and keeps
   * and reports the rest. Zero means "as soon as the proof allows", which is what a test wants.
   */
  orphanRetentionMs?: number;
  /** structured events; the runner's journal writer in production, a collector in tests */
  emit?: (record: Record<string, unknown>) => void | Promise<void>;
}

/** a week is long enough for an operator to notice a quarantine and short enough to bound the disk */
const DEFAULT_ORPHAN_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

const LOW_CONTROL = /[\x00-\x1f\x7f]/;

/**
 * The kernel parses the option string by splitting on commas and colons, so a path containing one
 * changes the meaning of the mount rather than failing it. execFile already keeps a shell out of the
 * picture; this keeps the option parser out of it too.
 */
export function pathIsMountOptionSafe(p: string): boolean {
  return !(p.includes(",") || p.includes(":") || p.includes("\\") || LOW_CONTROL.test(p));
}

export function overlayOptionString(real: string, shadowDir: string): string {
  return (
    `lowerdir=${real},upperdir=${path.join(shadowDir, "upper")},` +
    `workdir=${path.join(shadowDir, "work")},` +
    // metacopy would copy up metadata without data, so contentOf reads "" and the commit step
    // truncates the real file. redirect_dir hides a directory rename behind an xattr nothing reads.
    // index and xino keep st_dev/st_ino honest for the hardlink defusal in safe-path.
    //
    // userxattr is deliberately ABSENT rather than set to off. It is a flag in this kernel, not a
    // key=value, so `userxattr=off` is rejected outright with "bad option" and the whole mount
    // fails closed to a copy. Leaving it unset already selects the trusted. namespace, which is
    // what effect capture was written against. Measured on Linux 6.6.87 by bisecting the options.
    `metacopy=off,redirect_dir=off,index=off,xino=off`
  );
}

export function overlayMountArgv(real: string, shadowDir: string, viaSudo: boolean): string[] {
  // the source name is cosmetic to the kernel and load-bearing in evidence: findmnt and mountinfo
  // both name the product rather than a generic "overlay"
  const base = [
    "mount", "-t", "overlay", "shadow-commit",
    "-o", overlayOptionString(real, shadowDir),
    path.join(shadowDir, "merged"),
  ];
  return viaSudo ? ["sudo", "-n", ...base] : base;
}

/** Resolve without following the leaf: a symlinked leaf must not canonicalise to its target. */
export async function canonicalNoFollow(p: string): Promise<string> {
  const parent = await fs.realpath(path.dirname(p)).catch(() => path.resolve(path.dirname(p)));
  return path.join(parent, path.basename(p));
}

/**
 * Every mount visible to this process, or null when the host offers no way to ask.
 *
 * Linux answers from /proc/self/mountinfo. macOS and the BSDs have no procfs, and the first version
 * of this stopped there: `readMountInfo` returned null, `proveNotMounted` could never succeed, and
 * `release()` quarantined every shadow it was asked to remove. On a host whose shipped path is a
 * full copy that meant one leaked workspace copy per turn, forever.
 *
 * So the proof is PORTED rather than dropped. `mount` prints the same facts in a different shape and
 * exists on every Unix, which keeps the guarantee, prove the absence of a mount before you delete,
 * true everywhere instead of true on Linux and abandoned elsewhere. Only when neither source can be
 * read does this return null, and only then is refusing to delete the correct answer rather than an
 * expensive one.
 */
export async function readMountInfo(): Promise<MountInfoEntry[] | null> {
  const raw = await fs.readFile("/proc/self/mountinfo", "utf8").catch(() => null);
  if (raw !== null) return parseMountInfo(raw);
  const r = await run(["mount"]);
  if (r.code !== 0) return null;
  return parseMountCommand(r.stdout);
}

/** mountinfo: field 5 is the mount point, field 6 the options, then " - " fstype source. */
export function parseMountInfo(raw: string): MountInfoEntry[] {
  const entries: MountInfoEntry[] = [];
  const OCTAL: Record<string, string> = { "040": " ", "011": "\t", "012": "\n", "134": "\\" };
  const unescape = (v: string) => v.replace(/\\(040|011|012|134)/g, (_m, c: string) => OCTAL[c] ?? _m);
  for (const line of raw.split("\n")) {
    if (!line) continue;
    const sep = line.indexOf(" - ");
    if (sep === -1) continue;
    const left = line.slice(0, sep).split(" ");
    const right = line.slice(sep + 3).split(" ");
    if (left.length < 6 || right.length < 2) continue;
    entries.push({
      mountPoint: unescape(left[4]!),
      options: left[5] ?? "",
      fsType: right[0]!,
      source: unescape(right[1]!),
    });
  }
  return entries;
}

/**
 * `mount` output, in the two shapes it actually comes in.
 *
 *   macOS, BSD   src on /mount/point (fstype, opt, opt)
 *   Linux        src on /mount/point type fstype (opt,opt)
 *
 * The Linux `type fstype` infix is the reason this is one function and not a copy of the macOS
 * reading: the first version matched only the macOS shape, so on Linux the mount point came back as
 * "/ type ext4" and the cross-check against procfs failed. That failure is why the cross-check
 * exists, and it is worth more than the parser it corrected.
 *
 * A mount point can contain " on " or " (", so the source is taken non-greedily up to the first
 * " on " and the options from the final parenthesised group. That is the only reading which survives
 * a path like "/Volumes/My Disk (backup)".
 */
export function parseMountCommand(stdout: string): MountInfoEntry[] {
  const entries: MountInfoEntry[] = [];
  for (const line of stdout.split("\n")) {
    const m = /^(.*?) on (.*?)(?: type ([^\s(]+))? \(([^)]*)\)$/.exec(line.trim());
    if (!m) continue;
    const opts = m[4]!.split(",").map((o) => o.trim()).filter(Boolean);
    entries.push({
      mountPoint: m[2]!,
      // normalised to the mountinfo spelling, so every caller reads one vocabulary
      options: opts.join(","),
      // Linux names the type in its own field; macOS leads the option list with it
      fsType: m[3] ?? opts[0] ?? "",
      source: m[1]!,
    });
  }
  return entries;
}

async function run(argv: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(argv[0]!, argv.slice(1));
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: typeof err.code === "number" ? err.code : 1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}

async function haveBinary(name: string): Promise<boolean> {
  return (await run(["sh", "-c", `command -v ${name}`])).code === 0;
}

export async function isMountPoint(dir: string): Promise<{ mounted: boolean; known: boolean }> {
  const entries = await readMountInfo();
  if (entries === null) return { mounted: false, known: false };
  const canonical = await canonicalNoFollow(dir);
  return { mounted: entries.some((e) => e.mountPoint === canonical), known: true };
}

/**
 * The gate in front of every delete.
 *
 * mountinfo is the decision and it covers the whole subtree, because a mount anywhere under the
 * directory is equally fatal to a recursive delete. Everything else can only veto: st_dev and a
 * findmnt call both miss a same-filesystem bind mount, so treating either as the test is exactly how
 * a bind mount gets deleted through. An unreadable mountinfo means safety is unprovable, and
 * unprovable is treated as mounted.
 */
export async function proveNotMounted(dir: string): Promise<MountProof> {
  const corroboration: MountProof["corroboration"] = { devDiffersFromParent: null, findmntSaysMounted: null };

  const leaf = await fs.lstat(dir).catch(() => null);
  if (leaf === null) {
    return { proven: true, reason: "absent", offenders: [], corroboration };
  }
  if (leaf.isSymbolicLink()) {
    return { proven: false, reason: "leaf-is-symlink", offenders: [], corroboration };
  }

  const entries = await readMountInfo();
  if (entries === null) {
    return { proven: false, reason: "mountinfo-unreadable", offenders: [], corroboration };
  }

  const canonical = await canonicalNoFollow(dir);
  const offenders = entries
    .filter((e) => e.mountPoint === canonical || e.mountPoint.startsWith(canonical + path.sep))
    .map((e) => e.mountPoint);

  const self = await fs.stat(dir).catch(() => null);
  const parent = await fs.stat(path.dirname(canonical)).catch(() => null);
  if (self && parent) corroboration.devDiffersFromParent = self.dev !== parent.dev;

  if (await haveBinary("findmnt")) {
    corroboration.findmntSaysMounted = (await run(["findmnt", "--mountpoint", canonical])).code === 0;
  }

  if (offenders.length > 0) return { proven: false, reason: "mountinfo-entry-present", offenders, corroboration };
  if (corroboration.findmntSaysMounted === true) {
    return { proven: false, reason: "findmnt-disagrees-with-mountinfo", offenders, corroboration };
  }
  if (corroboration.devDiffersFromParent === true) {
    return { proven: false, reason: "st_dev-differs-from-parent", offenders, corroboration };
  }
  return { proven: true, reason: "no-mount-at-or-under", offenders, corroboration };
}

function classifyUmount(stderr: string): string {
  const s = stderr.toLowerCase();
  if (s.includes("must be superuser") || s.includes("operation not permitted")) return "not-permitted";
  if (s.includes("busy")) return "busy";
  if (s.includes("not mounted") || s.includes("no mount point")) return "already-gone";
  return "unknown-failure";
}

/**
 * Every umount failure exits 32, so the exit code decides nothing. The stderr text picks the reason
 * slug; the decision is always the mountinfo re-check afterwards, so a different locale or a busybox
 * umount degrades to "re-prove and see" rather than to a wrong delete.
 */
export async function unmountWithProof(
  merged: string,
  umountArgv: string[],
  opts: { retries?: number } = {},
): Promise<UnmountResult> {
  const retries = opts.retries ?? 5;
  if ((await isMountPoint(merged)).mounted === false) {
    return { ok: true, how: "already-unmounted", attempts: 0 };
  }

  let classification = "unknown-failure";
  let lastStderr = "";
  let attempt = 0;
  let backoff = 40;

  for (attempt = 1; attempt <= retries; attempt++) {
    const r = await run([...umountArgv, merged]);
    if (r.code === 0 && (await isMountPoint(merged)).mounted === false) {
      return { ok: true, how: "eager", attempts: attempt };
    }
    classification = classifyUmount(r.stderr);
    lastStderr = (r.stderr.split("\n")[0] ?? "").trim();
    if (classification === "already-gone" && (await isMountPoint(merged)).mounted === false) {
      return { ok: true, how: "already-unmounted", attempts: attempt };
    }
    if (classification !== "busy") break;
    await new Promise((res) => setTimeout(res, backoff));
    backoff = Math.min(backoff * 2, 640);
  }

  // Lazy only after eager retries are exhausted on a busy mount. It detaches the path immediately
  // and lets the filesystem die when the last reference drops, after which `merged` is the ordinary
  // empty directory underneath. Never escalate the DELETE with sudo; that is what turns a leak into
  // destruction.
  if (classification === "busy") {
    const r = await run([...umountArgv, "-l", merged]);
    if (r.code === 0 && (await isMountPoint(merged)).mounted === false) {
      return { ok: true, how: "lazy", attempts: attempt };
    }
    lastStderr = (r.stderr.split("\n")[0] ?? "").trim() || lastStderr;
  }

  return { ok: false, how: "refused", attempts: attempt, classification, lastStderr };
}

export function createOverlaySealer(options: SealerOptions) {
  const shadowRoot = options.shadowRoot;
  const releaseHookWired = options.releaseHookWired ?? false;
  const allowSudo = options.allowSudo ?? process.env.SHADOW_SEAL_ALLOW_SUDO === "1";
  const emit = options.emit ?? (() => undefined);
  const orphanRetentionMs = options.orphanRetentionMs ?? DEFAULT_ORPHAN_RETENTION_MS;
  const forced = options.force ?? (process.env.SHADOW_SEAL as Mechanism | undefined);
  const live = new Set<string>();
  let cached: Capability | null = null;

  const hostRecord = async (): Promise<HostRecord> => {
    const entries = (await readMountInfo()) ?? [];
    const canonical = await canonicalNoFollow(shadowRoot).catch(() => shadowRoot);
    let best: MountInfoEntry | null = null;
    for (const e of entries) {
      if (canonical === e.mountPoint || canonical.startsWith(e.mountPoint === "/" ? "/" : e.mountPoint + path.sep)) {
        if (!best || e.mountPoint.length > best.mountPoint.length) best = e;
      }
    }
    return {
      platform: process.platform,
      release: os.release(),
      arch: process.arch,
      uid: typeof process.getuid === "function" ? process.getuid() : -1,
      shadowRootFsType: best?.fsType ?? null,
    };
  };

  const copyOnly = async (reason: string, detail?: string): Promise<Capability> => ({
    mechanism: "copy", reason, detail, usesSudo: false,
    mountArgv: [], umountArgv: ["umount"], host: await hostRecord(), probedInMs: 0,
  });

  /**
   * Runs once per process. Every step is a proof, and the unmount is demonstrated on a throwaway
   * tree BEFORE any real workspace is ever mounted, because a host where the mount works and the
   * unmount does not is the host this module exists to refuse.
   */
  async function capability(): Promise<Capability> {
    if (cached) return cached;
    const started = Date.now();
    const host = await hostRecord();

    const settle = (c: Capability) => {
      cached = { ...c, host, probedInMs: Date.now() - started };
      void emit({ kind: "seal.capability", mechanism: cached.mechanism, reason: cached.reason, detail: cached.detail, host });
      return cached;
    };

    if (forced === "copy") return settle(await copyOnly("forced-copy"));
    if (process.platform !== "linux") return settle(await copyOnly("not-linux"));
    if ((await readMountInfo()) === null) return settle(await copyOnly("no-mountinfo"));

    const probeRoot = path.join(shadowRoot, `.probe-${process.pid}-${crypto.randomBytes(4).toString("hex")}`);
    const merged = path.join(probeRoot, "merged");
    const upper = path.join(probeRoot, "upper");
    const lower = path.join(probeRoot, "lower");

    try {
      for (const d of ["lower", "upper", "work", "merged"]) {
        await fs.mkdir(path.join(probeRoot, d), { recursive: true });
      }
      await fs.writeFile(path.join(lower, "probe.txt"), "probe\n");

      if (!pathIsMountOptionSafe(probeRoot)) return settle(await copyOnly("unsafe-path"));

      const candidates: Array<{ argv: string[]; sudo: boolean }> = [
        { argv: overlayMountArgv(lower, probeRoot, false), sudo: false },
      ];
      if (allowSudo) candidates.push({ argv: overlayMountArgv(lower, probeRoot, true), sudo: true });

      let remembered = "mount-refused";
      let detail: string | undefined;

      for (const candidate of candidates) {
        const umountArgv = candidate.sudo ? ["sudo", "-n", "umount"] : ["umount"];
        const r = await run(candidate.argv);
        if (r.code !== 0) {
          const cls = classifyUmount(r.stderr);
          remembered = cls === "not-permitted" ? "no-privilege" : "mount-refused";
          detail = (r.stderr.split("\n")[0] ?? "").trim();
          continue;
        }

        const bail = async (reason: string): Promise<Capability> => {
          await unmountWithProof(merged, umountArgv);
          return settle(await copyOnly(reason));
        };

        // visible in THIS namespace: a mount made in a private user namespace is not
        if ((await isMountPoint(merged)).mounted !== true) return bail("mount-not-visible");
        if (!(await fs.readdir(merged).catch(() => [] as string[])).includes("probe.txt")) {
          return bail("mount-not-visible");
        }
        // A successful mount is not a usable mount. Measured on the demo Mac: an overlay whose
        // upperdir sits on virtiofs comes up READ-ONLY rather than refusing. It reports
        // ro,relatime,...,nouserxattr and the first write fails with EROFS. A probe that only
        // checked the mount exit code would arm there and then die on the first real turn.
        const mergedCanonical = await canonicalNoFollow(merged);
        const mergedEntry = ((await readMountInfo()) ?? []).find((e) => e.mountPoint === mergedCanonical);
        if (mergedEntry && /(^|,)ro(,|$)/.test(mergedEntry.options)) return bail("mount-read-only");

        // copy-up must produce real data in upper, not a metadata stub
        try {
          await fs.writeFile(path.join(merged, "created.txt"), "x\n");
        } catch (e) {
          const code = (e as NodeJS.ErrnoException).code;
          return bail(code === "EROFS" ? "mount-read-only" : "mount-not-writable");
        }
        const created = await fs.stat(path.join(upper, "created.txt")).catch(() => null);
        if (!created || created.size === 0) return bail("no-copy-up");
        // a delete must leave the 0/0 character device the effect capture reads as a whiteout
        await fs.rm(path.join(merged, "probe.txt"), { force: true });
        const wh = await fs.lstat(path.join(upper, "probe.txt")).catch(() => null);
        if (!wh || !wh.isCharacterDevice() || wh.rdev !== 0) return bail("no-whiteout");
        if (!(await fs.stat(path.join(lower, "probe.txt")).catch(() => null))) return bail("no-whiteout");

        // the unmount is demonstrated here, on a throwaway tree, and nowhere near a real workspace
        const u = await unmountWithProof(merged, umountArgv);
        if (!u.ok) return settle(await copyOnly("unmount-unproven"));
        if (!(await proveNotMounted(probeRoot)).proven) return settle(await copyOnly("unmount-unproven"));

        try {
          await fs.rm(probeRoot, { recursive: true, force: true });
        } catch {
          return settle(await copyOnly("cannot-clean-upper"));
        }

        return settle({
          mechanism: "overlay", reason: "overlay-proven", usesSudo: candidate.sudo,
          mountArgv: candidate.argv, umountArgv, host, probedInMs: 0,
        });
      }
      return settle(await copyOnly(remembered, detail));
    } catch (e) {
      return settle(await copyOnly("probe-threw", String((e as Error)?.message ?? e)));
    } finally {
      // never a bare rm: prove first, quarantine if the proof fails
      if ((await proveNotMounted(probeRoot)).proven) {
        await fs.rm(probeRoot, { recursive: true, force: true }).catch(() => undefined);
      }
    }
  }

  /**
   * Compares the sealed copy against the workspace it was made from, and reports the two kinds of
   * discrepancy SEPARATELY, because they do not have the same consequence.
   *
   *   `absent` is a non-directory path the workspace has and the shadow does not. This is the one
   *   that manufactures an effect out of nothing. `captureEffects` finds a deletion by walking the
   *   real workspace and asking what the shadow no longer holds, so absence in the shadow and
   *   deletion by the agent are the same observation, and one delete is under every multi-delete
   *   threshold. Never survivable, whatever `cp` had to say about it.
   *
   *   `short` is a regular file the shadow holds fewer bytes of. On its own this manufactures
   *   nothing: under the copy mechanism a file counts as modified only when its signature has
   *   changed SINCE the seal, so a file the turn never opened produces no effect however far the
   *   real workspace has moved underneath it. It matters for a different reason, that a read which
   *   died part way leaves the agent working against a truncated file, which is why the caller
   *   weighs it against whether `cp` reported trouble rather than failing on it alone.
   *
   * A directory that cannot be listed counts as absent. Nothing under it can be compared, so the
   * copy under it is unproven, and unproven is not the same as present.
   *
   * The type of a source entry comes from `lstat`, never from the dirent. `readdir` with
   * `withFileTypes` passes the directory entry's `d_type` through without stat'ing, and a
   * filesystem that does not fill it in reports UNKNOWN, which answers false to `isDirectory()` and
   * to `isFile()` alike. Deciding on that value skips the entry, and everything beneath it when it
   * was a directory, which is a hole in the check shaped exactly like the one it exists to catch.
   */
  async function compareCopy(real: string, merged: string): Promise<{ absent: CopyGap[]; short: string[] }> {
    const absent: CopyGap[] = [];
    const short: string[] = [];
    const walk = async (dir: string, prefix: string): Promise<void> => {
      let entries;
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        absent.push({ rel: prefix === "" ? "." : prefix, kind: "unreadable directory" });
        return;
      }
      for (const e of entries) {
        const rel = prefix ? `${prefix}/${e.name}` : e.name;
        const source = await fs.lstat(path.join(dir, e.name)).catch(() => null);
        // gone between the listing and the stat: it is not in the workspace now, so the capture's
        // walk of the workspace will not see it either, and the shadow is not missing anything
        if (!source) continue;
        const copied = await fs.lstat(path.join(merged, rel)).catch(() => null);
        if (!copied) {
          absent.push({ rel, kind: describeEntry(source) });
          continue;
        }
        if (source.isDirectory()) {
          await walk(path.join(dir, e.name), rel);
          continue;
        }
        // a shadow file LONGER than the source is the workspace shrinking under us, not a lost read
        if (source.isFile() && copied.isFile() && copied.size < source.size) short.push(rel);
      }
    };
    await walk(real, "");
    return { absent, short };
  }

  /**
   * `cp -a` plus link neutralisation, byte for byte what the runner's own fallback does, with the
   * result actually checked.
   *
   * The check does not run because `cp` complained. It runs every time, because the exit status is
   * not how you learn whether the copy is complete, in either direction:
   *
   *   - a non-zero exit does not mean incomplete. GNU `cp -a` exits non-zero when it cannot
   *     preserve ownership on a file it copied in full, and failing every turn on a workspace with
   *     mixed ownership would be a worse bug than the one this closes.
   *   - an exit of 0 does not mean complete. BSD `cp -a` cannot reproduce a unix socket, and says
   *     so on stderr while exiting 0: `cp: real/./app.sock is a socket (not copied).` A workspace
   *     with a dev server's socket in it seals "successfully" and the socket is missing from the
   *     shadow, which the capture then reads as the agent having deleted it.
   *
   * So completeness of the tree is the whole decision, and what `cp` said is evidence about one
   * narrower question: whether a file the shadow has fewer bytes of is a read that died (fatal) or
   * a file the workspace is still appending to (skew, recorded and survivable).
   */
  async function copySeal(real: string, merged: string): Promise<"copy"> {
    const runId = path.basename(path.dirname(merged));
    let complaint: string | null = null;
    try {
      const { stderr } = await execFileAsync("cp", ["-a", real + "/.", merged]);
      const said = String(stderr ?? "").trim();
      if (said !== "") complaint = said;
    } catch (e) {
      const stderr = String((e as { stderr?: string })?.stderr ?? "").trim();
      complaint = stderr || String((e as Error)?.message ?? e);
    }

    const { absent, short } = await compareCopy(real, merged);

    if (absent.length > 0) {
      const named = absent.slice(0, MAX_NAMED_MISSING).map((g) => `${g.rel} (${g.kind})`).join(", ");
      const rest = absent.length > MAX_NAMED_MISSING ? ` and ${absent.length - MAX_NAMED_MISSING} more` : "";
      throw new SealFailedError(
        "copy-incomplete",
        `the sealed copy is missing ${absent.length} path(s) the workspace has: ${named}${rest}. ` +
          `The shadow cannot be diffed against the workspace, because absence in the shadow is ` +
          `indistinguishable from deletion by the turn. ` +
          (complaint === null ? `cp exited 0 and reported nothing.` : `cp said: ${complaint}`),
        absent.map((g) => g.rel),
      );
    }

    if (short.length > 0 && complaint !== null) {
      const named = short.slice(0, MAX_NAMED_MISSING).join(", ");
      const rest = short.length > MAX_NAMED_MISSING ? ` and ${short.length - MAX_NAMED_MISSING} more` : "";
      throw new SealFailedError(
        "copy-truncated",
        `the sealed copy holds fewer bytes than the workspace for ${short.length} file(s): ` +
          `${named}${rest}, and cp reported trouble, so the read did not finish. An agent working ` +
          `against a truncated file writes a truncated file back. cp said: ${complaint}`,
        short,
      );
    }

    if (short.length > 0) {
      // the workspace moved under the copy: inherent to copying a live tree, so it is recorded
      // rather than fatal, and it cannot become an effect the turn did not ask for
      void emit({ kind: "seal.copy.degraded", runId, reason: "size-skew-during-copy", paths: short.slice(0, MAX_NAMED_MISSING) });
    } else if (complaint !== null) {
      // complete tree, unhappy cp: survivable, and still recorded
      void emit({ kind: "seal.copy.degraded", runId, reason: "cp-complained-tree-complete", error: complaint });
    }

    await neutraliseOutboundLinks(real, merged);
    return "copy";
  }

  const within = (base: string, candidate: string): boolean => {
    const rel = path.relative(base, candidate);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  };

  /**
   * A copy is not a jail: `cp -a` reproduces a symlink faithfully, so a link resolving outside the
   * workspace is a live hole through the sealed view. One that stays inside is kept; one that
   * escapes becomes a regular file holding a snapshot, so the turn reads what it could read before
   * and anything it writes is judged like every other effect.
   */
  async function neutraliseOutboundLinks(real: string, merged: string): Promise<string[]> {
    const neutralised: string[] = [];
    const walk = async (dir: string, prefix: string): Promise<void> => {
      let entries;
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        const full = path.join(dir, e.name);
        const rel = prefix ? `${prefix}/${e.name}` : e.name;
        if (e.isSymbolicLink()) {
          const target = await fs.readlink(full).catch(() => "");
          const resolvedInReal = path.resolve(path.dirname(path.join(real, rel)), target);
          if (within(real, resolvedInReal)) continue;
          const body = await fs.readFile(resolvedInReal).catch(() => Buffer.alloc(0));
          await fs.rm(full, { force: true });
          await fs.writeFile(full, body);
          neutralised.push(rel);
          continue;
        }
        if (e.isDirectory()) await walk(full, rel);
      }
    };
    await walk(merged, "");
    return neutralised;
  }

  async function writeSidecar(shadowDir: string, cap: Capability, mechanism: Mechanism, reason: string): Promise<void> {
    const body = JSON.stringify({
      runId: path.basename(shadowDir), mechanism, reason,
      host: cap.host, mountArgv: mechanism === "overlay" ? cap.mountArgv : [],
      optionString: mechanism === "overlay" ? overlayOptionString("<lower>", shadowDir) : null,
    });
    await fs.writeFile(path.join(shadowDir, "seal.json"), body, { mode: 0o600 }).catch(() => undefined);
  }

  /**
   * Throws `SealFailedError`, and only that, and only for one thing: the sealed view is not a
   * complete view of the workspace. Every other failure resolves to "copy" with the reason
   * recorded, because a turn must not be lost over a host that cannot mount an overlay.
   *
   * Callers have to handle that one throw. There is no return value that makes an incomplete seal
   * safe to run a turn against, for the reason set out in the module header: the capture reads a
   * path missing from the shadow as a deletion by the agent.
   */
  async function seal(real: string, shadowDir: string): Promise<Mechanism> {
    const merged = path.join(shadowDir, "merged");
    const runId = path.basename(shadowDir);

    const fallback = async (reason: string): Promise<Mechanism> => {
      void emit({ kind: "seal.fallback", runId, mechanism: "copy", reason });
      const cap = cached ?? (await copyOnly(reason));
      await copySeal(real, merged);
      await writeSidecar(shadowDir, cap, "copy", reason);
      return "copy";
    };

    try {
      const cap = await capability();
      if (cap.mechanism === "overlay" && !releaseHookWired) {
        // refusing the composition we cannot clean up after, for the same reason we refuse a host
        // whose unmount we cannot prove
        void emit({ kind: "seal.refused", runId, reason: "release-hook-not-wired" });
        return await fallback("release-hook-not-wired");
      }
      if (cap.mechanism !== "overlay") return await fallback(cap.reason);
      if (!pathIsMountOptionSafe(real) || !pathIsMountOptionSafe(shadowDir)) return await fallback("unsafe-path");
      if (!(await proveNotMounted(shadowDir)).proven) return await fallback("stale-mount-at-shadow-dir");

      const r = await run(overlayMountArgv(real, shadowDir, cap.usesSudo));
      if (r.code !== 0) return await fallback("mount-refused");
      if ((await isMountPoint(merged)).mounted !== true) {
        await unmountWithProof(merged, cap.umountArgv);
        return await fallback("mount-not-visible");
      }

      live.add(shadowDir);
      await writeSidecar(shadowDir, cap, "overlay", "overlay-proven");
      void emit({ kind: "seal.mounted", runId, mechanism: "overlay", fsType: "overlay" });
      return "overlay";
    } catch (e) {
      if (e instanceof SealFailedError) return await failSeal(runId, shadowDir, e);
      void emit({ kind: "seal.threw", runId, error: String((e as Error)?.message ?? e) });
      try {
        return await fallback("seal-threw");
      } catch (again) {
        // The old reading here was `return "copy"`. A fallback that threw copied nothing or copied
        // part of the tree, and calling that "copy" hands the capture an empty or partial shadow,
        // which is every file in the workspace read as a deletion. The wider version of the same
        // hole, reached by a shorter path.
        return await failSeal(
          runId,
          shadowDir,
          again instanceof SealFailedError
            ? again
            : new SealFailedError(
                "fallback-failed",
                `the copy fallback could not seal the workspace: ${String((again as Error)?.message ?? again)}`,
              ),
        );
      }
    }
  }

  /**
   * Records the failure and removes the partial shadow before raising. The removal goes through
   * `release`, not a bare `rm`, so it is the same prove-then-delete gate as a normal teardown: a
   * failed seal is not a reason to relax the one rule this module exists to keep.
   */
  async function failSeal(runId: string, shadowDir: string, error: SealFailedError): Promise<never> {
    void emit({
      kind: "seal.failed",
      runId,
      reason: error.reason,
      missing: error.missing.slice(0, MAX_NAMED_MISSING),
      error: error.message,
    });
    await release(shadowDir).catch(() => undefined);
    throw error;
  }

  async function quarantine(shadowDir: string, why: Record<string, unknown>): Promise<string | null> {
    const dest = path.join(shadowRoot, ".orphan", `${path.basename(shadowDir)}-${process.hrtime.bigint()}`);
    try {
      await fs.mkdir(path.join(shadowRoot, ".orphan"), { recursive: true });
      // a rename succeeds even when a live mount sits inside the directory, and the mount follows it
      await fs.rename(shadowDir, dest);
      await fs.writeFile(path.join(dest, "ORPHAN.json"), JSON.stringify(why), { mode: 0o600 }).catch(() => undefined);
      return dest;
    } catch {
      return null;
    }
  }

  /**
   * The replacement for the runner's private release. It deletes only after proving there is no
   * mount at or under the directory, and quarantines when it cannot prove it. The proof runs for the
   * copy mechanism too: the mechanism value reaching this function can be wrong, and an agent that
   * persuaded anything to mount inside the shadow tree must not turn a copy teardown into a delete
   * through a mount.
   */
  async function release(shadowDir: string, mechanismRaw?: string): Promise<ReleaseResult> {
    const merged = path.join(shadowDir, "merged");
    const sidecar = await fs
      .readFile(path.join(shadowDir, "seal.json"), "utf8")
      .then((t) => JSON.parse(t) as { mechanism?: string })
      .catch(() => null);
    // anything unrecognised is treated as overlay, because assuming "copy" is the assumption that
    // skips the unmount
    const mechanism: Mechanism = (sidecar?.mechanism ?? mechanismRaw) === "copy" ? "copy" : "overlay";

    const cap = cached ?? (await copyOnly("not-probed"));
    let unmount: UnmountResult | null = null;
    if (mechanism === "overlay") unmount = await unmountWithProof(merged, cap.umountArgv);

    const proof = await proveNotMounted(shadowDir);
    live.delete(shadowDir);

    if (!proof.proven) {
      const quarantinedTo = await quarantine(shadowDir, { reason: proof.reason, offenders: proof.offenders, unmount });
      void emit({ kind: "seal.release", runId: path.basename(shadowDir), removed: false, reason: proof.reason, offenders: proof.offenders, quarantinedTo });
      return { removed: false, proof, unmount, quarantinedTo };
    }

    try {
      await fs.rm(shadowDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 25 });
      void emit({ kind: "seal.release", runId: path.basename(shadowDir), removed: true, how: unmount?.how });
      return { removed: true, proof, unmount, quarantinedTo: null };
    } catch (e) {
      // an upper tree written as another uid cannot be removed as this identity. Escalating the
      // delete is the one move that turns a leak into destruction, so quarantine instead.
      const quarantinedTo = await quarantine(shadowDir, { reason: "rm-failed", error: String((e as Error)?.message ?? e) });
      void emit({ kind: "seal.release", runId: path.basename(shadowDir), removed: false, reason: "rm-failed", quarantinedTo });
      return { removed: false, proof, unmount, quarantinedTo, error: String((e as Error)?.message ?? e) };
    }
  }

  /**
   * The other end of `quarantine`. Without it a quarantined shadow, a full workspace copy on the
   * copy path and a live mount on the overlay path, stays on disk for ever and is never counted,
   * so an operator learns about the accumulation from a full volume.
   *
   * Reclaiming is not "delete the thing we refused to delete". Two conditions have to hold, and the
   * second is the same one a normal teardown must satisfy:
   *
   *   1. the quarantine is older than the retention window, so a human had a chance to look at it
   *   2. there is provably no mount at or under it, NOW, and the removal itself succeeds
   *
   * Anything that fails either test is kept and reported by name. Nothing here escalates
   * privileges, forces a delete or removes a path outside `<shadowRoot>/.orphan`.
   */
  async function reclaimOrphans(
    opts: { olderThanMs?: number } = {},
  ): Promise<{ reclaimed: string[]; retained: string[]; unmounted: string[] }> {
    const olderThanMs = opts.olderThanMs ?? orphanRetentionMs;
    const reclaimed: string[] = [];
    const retained: string[] = [];
    const unmounted: string[] = [];
    const orphanRoot = path.join(shadowRoot, ".orphan");
    const cap = cached ?? (await copyOnly("not-probed"));
    const orphanRootCanonical = await canonicalNoFollow(orphanRoot).catch(() => orphanRoot);

    for (const name of await fs.readdir(orphanRoot).catch(() => [] as string[])) {
      const dir = path.join(orphanRoot, name);
      const stat = await fs.lstat(dir).catch(() => null);
      // only directories, and never through a symlink: a link here would aim the delete elsewhere
      if (!stat || !stat.isDirectory()) continue;

      const ageMs = Date.now() - stat.mtimeMs;
      // a timestamp in the future is a clock that moved, not a quarantine that aged
      if (!(ageMs >= olderThanMs)) {
        retained.push(dir);
        continue;
      }

      const dirCanonical = await canonicalNoFollow(dir).catch(() => dir);
      if (!within(orphanRootCanonical, dirCanonical) || dirCanonical === orphanRootCanonical) {
        retained.push(dir);
        continue;
      }

      for (const entry of (await readMountInfo()) ?? []) {
        if (!entry.mountPoint.startsWith(dirCanonical + path.sep) && entry.mountPoint !== dirCanonical) continue;
        const u = await unmountWithProof(entry.mountPoint, cap.umountArgv);
        if (u.ok) unmounted.push(entry.mountPoint);
      }

      if (!(await proveNotMounted(dir)).proven) {
        retained.push(dir);
        continue;
      }
      try {
        await fs.rm(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 25 });
        reclaimed.push(dir);
      } catch {
        // still undeletable as this identity, which is why it was quarantined in the first place
        retained.push(dir);
      }
    }

    void emit({ kind: "seal.orphan.reclaim", reclaimed: reclaimed.length, retained: retained.length, unmounted: unmounted.length });
    return { reclaimed, retained, unmounted };
  }

  /**
   * Crash recovery leaves mounts behind. This finds every mount under the shadow root that no live
   * turn owns, unmounts it with proof, and releases the directory through the same gate as a normal
   * teardown. It never touches a path outside the shadow root.
   *
   * The quarantine is swept too, through `reclaimOrphans`, and whatever survives the sweep is
   * counted in the result and the event. An accumulation nobody can see is the half of this defect
   * that costs the most to discover.
   */
  async function sweepOrphans(
    liveRunIds?: Set<string>,
  ): Promise<{
    swept: string[];
    refused: string[];
    unmounted: string[];
    reclaimedOrphans: string[];
    retainedOrphans: string[];
  }> {
    const swept: string[] = [];
    const refused: string[] = [];
    const unmounted: string[] = [];
    const cap = cached ?? (await copyOnly("not-probed"));
    const rootCanonical = await canonicalNoFollow(shadowRoot).catch(() => shadowRoot);

    // When the caller names the live turns it is authoritative: that is the whole point of a
    // recovery sweep, where the in-process registry is exactly the thing that did not survive.
    // Only fall back to the registry when the caller says nothing.
    const isLive = (runId: string): boolean =>
      liveRunIds ? liveRunIds.has(runId) : live.has(path.join(shadowRoot, runId));

    for (const entry of (await readMountInfo()) ?? []) {
      if (!entry.mountPoint.startsWith(rootCanonical + path.sep)) continue;
      const runId = path.relative(rootCanonical, entry.mountPoint).split(path.sep)[0]!;
      if (isLive(runId)) continue;
      const u = await unmountWithProof(entry.mountPoint, cap.umountArgv);
      if (u.ok) unmounted.push(entry.mountPoint);
    }

    for (const name of await fs.readdir(shadowRoot).catch(() => [] as string[])) {
      if (name === ".orphan" || name.startsWith(".probe-")) continue;
      if (isLive(name)) continue;
      const dir = path.join(shadowRoot, name);
      const r = await release(dir);
      (r.removed ? swept : refused).push(dir);
    }

    const orphans = await reclaimOrphans();
    unmounted.push(...orphans.unmounted);

    void emit({
      kind: "seal.sweep",
      swept: swept.length,
      refused: refused.length,
      unmounted: unmounted.length,
      orphansReclaimed: orphans.reclaimed.length,
      orphansRetained: orphans.retained.length,
    });
    return {
      swept,
      refused,
      unmounted,
      reclaimedOrphans: orphans.reclaimed,
      retainedOrphans: orphans.retained,
    };
  }

  return { seal, release, sweepOrphans, reclaimOrphans, capability, neutraliseOutboundLinks };
}

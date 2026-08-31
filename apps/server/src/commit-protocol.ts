import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { hasBytes, hashFile, isSafeRelative, liveSignature } from "./capture.js";
import { sortByNameForDigest } from "./stable-order.js";
import { shadowFileOf } from "./policy-context.js";
import { safeResolve, safeWriteTarget } from "./safe-path.js";
import type { RunnerStore, PendingCommit } from "./runner-store.js";
import type { EffectRecord } from "./policy-types.js";

const execFileAsync = promisify(execFile);

/**
 * The commit half of the transaction: the only place anything the agent produced becomes real.
 *
 * The protocol is spike J's, and its shape is a deliberate retreat from a claim that was not
 * achievable. An "atomic single-rename commit" against a live bind-mounted workspace does not
 * exist, so instead exactly one operation has to be atomic, and it is a single journal append.
 * Everything after it is idempotent and replayable:
 *
 *   1. verify the bytes against the hashes captured with them, and stop here if they moved
 *   2. write the private record, then append `turn.committing`, the commit point
 *   3. apply the effects, re-checking the ground and the bytes under each individual write
 *   4. append `turn.committed`, and only then release the sealed copy
 *
 * A crash between 2 and 4 leaves a state the system knows how to finish, because the effects and
 * the copy they came from are both still there. `reconcile()` finishes it at the next start, and
 * finishing it twice does nothing the second time.
 */

/** How many effects a single journal record may name before it says how many it dropped. */
export const JOURNAL_EFFECT_LIMIT = 200;

export const nowIso = (): string => new Date().toISOString();

/**
 * The effect list as a journal record carries it.
 *
 * Discard and conflict used to journal no effect list at all, so the record of the one moment the
 * product exists for said only that something was stopped, never what. The bound is not
 * decoration: an install of a dependency tree is tens of thousands of effects, and an unbounded
 * list would append megabytes to a hash-chained file per turn.
 */
export function boundedEffects(effects: EffectRecord[]): Record<string, unknown> {
  return {
    effects: effects.slice(0, JOURNAL_EFFECT_LIMIT),
    ...(effects.length > JOURNAL_EFFECT_LIMIT
      ? { effectsTruncated: effects.length - JOURNAL_EFFECT_LIMIT }
      : {}),
  };
}

/**
 * The measurement of the REAL workspace, taken by the side that did the work.
 *
 * The product's headline claim is "the attack ran, and the real workspace is byte for byte what it
 * was before". Until this existed the only thing that asserted it was `scripts/demo-drive.mjs`,
 * which computes both digests itself, from outside, and compares them: a driver written the same way
 * could report "identical" over a product that had quietly written to the workspace, and nothing in
 * the system would disagree. So the server records its own measurement, on its own hash-chained
 * ledger, and the script becomes a second opinion instead of the only one. Four properties, each the
 * reason a cheaper version would be worthless:
 *
 * 1. **It walks the real path, never the sealed view.** Under overlay `merged` is a view whose lower
 *    layer IS the workspace, so digesting it measures the tree through the exact mechanism a seal
 *    escape defeats. Under copy, `neutraliseOutboundLinks` has already rewritten escaping links
 *    inside `merged`, so it is not byte-equal to the real tree even on an honest turn.
 * 2. **It is content, not stat.** `snapshotStats` is size, mtime and mode, and capture.ts:13 names
 *    the attack that defeats exactly that: bytes changed with the stat fields restored (CAP02).
 * 3. **It is not derived from the effect set.** If the seal leaked and the turn wrote straight to
 *    the real tree, that write is precisely what capture does not see. "Nothing changed" computed
 *    from an empty effect set proves only that the system agrees with itself.
 * 4. **A link is recorded, never followed.** A turn that plants `report.txt -> /etc/passwd` would
 *    otherwise get a file outside the workspace hashed under a path inside it, and a link to a fifo
 *    or a device would hang or throw. `lstat` only, and no `realpath` anywhere.
 */

/** The value a digest field carries when nothing was measured. Never a 64-hex string. */
export const NOT_MEASURED = "not-measured";

/**
 * Above this many entries the walk refuses instead of running.
 *
 * The cost is the filesystem, not the file count: 633 ms for 8,886 entries on APFS here, 16 s for
 * 30,000 on the bench's NTFS host, which is what the bound is for. It is an ENTRY count and counts
 * `.git` and `node_modules`, so an ordinary checked-out repository is over it and records a refusal
 * on every turn rather than a digest. That is the honest outcome and not a quiet one: the refusal is
 * written, the panel prints it, and the measurement is not behind an off-by-default flag, because a
 * claim measured only when a setting says so leaves a judge unable to tell a turn that was measured
 * and clean from a turn that was never measured at all.
 */
export const WORKSPACE_DIGEST_MAX_FILES = 20_000;

export interface WorkspaceDigest {
  /** sha256 over the tree, or null when the walk refused */
  digest: string | null;
  /** entries walked: files, directories, links and special entries alike */
  files: number;
  /**
   * Entries the walk could not read: a `readdir` refused, an `lstat` refused, bytes that would not
   * come back. Counted rather than swallowed, because a constant token for an unreadable subtree
   * returns an ordinary 64-hex digest that cannot move whatever is written under there, and anything
   * above this that says "byte for byte" has to know the number first.
   */
  unreadable: number;
  /** why there is no digest; absent when there is one */
  reason?: string;
}

/**
 * sha256 over one tree: every path, its type, its mode, and for a regular file its bytes.
 *
 * The layout is `immutable-oracle.ts`'s, with three corrections it needed to be usable here. Bytes
 * are streamed through `hashFile` rather than read whole, so an 8 GB file costs one 64 KiB buffer
 * (attack a39). A fifo, socket or device is recorded as `s` rather than thrown on, because a real
 * workspace can contain one and a measurement must never be able to fail a turn. And the order is
 * `sortByNameForDigest`, which is code units, because `localeCompare` gives the same tree a
 * different digest on a different host.
 *
 * The permission field is `mode & 0o7777`, not `& 0o777`: the three bits the shorter mask drops are
 * setuid, setgid and sticky, and under it a script going 0o755 to 0o4755 left the digest identical.
 * uid and gid are in the layout for the same reason, chown being a privilege change that moves no
 * bytes.
 */
export async function workspaceDigest(
  root: string,
  opts: { maxFiles?: number } = {},
): Promise<WorkspaceDigest> {
  const maxFiles = opts.maxFiles ?? WORKSPACE_DIGEST_MAX_FILES;
  const hash = createHash("sha256");
  let files = 0;
  let unreadable = 0;
  let overBudget = false;

  const walk = async (directory: string, prefix: string): Promise<void> => {
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      // The token below is a constant: everything under here is unmeasured and the digest cannot
      // move for any of it. So it is COUNTED, and the count travels to the sentence a person reads.
      hash.update(`u\0${prefix}\0`);
      unreadable += 1;
      return;
    }
    sortByNameForDigest(entries);
    for (const entry of entries) {
      if (overBudget) return;
      const absolute = path.join(directory, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      files += 1;
      if (files > maxFiles) {
        overBudget = true;
        return;
      }
      const stat = await fs.lstat(absolute).catch(() => null);
      if (!stat) {
        hash.update(`u\0${relative}\0`);
        unreadable += 1;
        continue;
      }
      if (stat.isSymbolicLink()) {
        // The target string, and only the string. Following it is how a link into /etc gets hashed
        // as if it were workspace content.
        const target = await fs.readlink(absolute).catch(() => null);
        hash.update(`l\0${relative}\0${target ?? ""}\0`);
        continue;
      }
      // setuid, setgid and sticky included, and the owner beside them; see the note above.
      const bits = `${stat.mode & 0o7777}\0${stat.uid}\0${stat.gid}`;
      if (stat.isDirectory()) {
        hash.update(`d\0${relative}\0${bits}\0`);
        await walk(absolute, relative);
        continue;
      }
      if (stat.isFile()) {
        const sha = await hashFile(absolute);
        if (sha === null) unreadable += 1;
        hash.update(`f\0${relative}\0${bits}\0${stat.size}\0${sha ?? "unreadable"}\0`);
        continue;
      }
      hash.update(`s\0${relative}\0${bits}\0`);
    }
  };

  const rootStat = await fs.stat(root).catch(() => null);
  if (!rootStat?.isDirectory()) return { digest: null, files: 0, unreadable: 1, reason: "workspace-unreadable" };
  await walk(root, "");
  if (overBudget) return { digest: null, files, unreadable, reason: "tree-over-budget" };
  // A root nothing can be listed under is not an empty workspace. Without this the walk hands back a
  // 64-hex digest over zero entries at both ends and the panel claims byte for byte, having opened
  // nothing at all.
  if (files === 0 && unreadable > 0) return { digest: null, files: 0, unreadable, reason: "workspace-unreadable" };
  return { digest: hash.digest("hex"), files, unreadable };
}

/**
 * One measurement as journal fields.
 *
 * `workspaceDigestBefore` / `workspaceDigestAfter` rather than anything shorter: `journal-format.ts`
 * reserves `hash`, `hmac`, `seq`, `prev`, `ts` and `principal`, and `writeOne` drops a caller field
 * with one of those names in silence.
 */
export function workspaceDigestFields(
  measured: WorkspaceDigest,
  when: "before" | "after",
): Record<string, unknown> {
  return {
    [when === "before" ? "workspaceDigestBefore" : "workspaceDigestAfter"]: measured.digest ?? NOT_MEASURED,
    [when === "before" ? "workspaceFilesBefore" : "workspaceFilesAfter"]: measured.files,
    // Always written, zero included: a record that omitted it would read like one written before
    // anyone counted, which is the gap this lane exists to close.
    [when === "before" ? "workspaceUnreadableBefore" : "workspaceUnreadableAfter"]: measured.unreadable,
    ...(measured.reason === undefined ? {} : { workspaceDigestReason: measured.reason }),
  };
}

/**
 * The closing measurement for a terminal record, including for the endings that have no workspace
 * path to measure. Those say so; they do not quietly omit the field, because a record that reads
 * the same whether the measurement happened or not is the defect this whole change exists to close.
 */
export async function closingWorkspaceFields(
  workspacePath: string | null,
  opts: { maxFiles?: number; unmeasuredReason?: string } = {},
): Promise<Record<string, unknown>> {
  if (workspacePath === null) {
    return workspaceDigestFields(
      { digest: null, files: 0, unreadable: 0, reason: opts.unmeasuredReason ?? "no-workspace-path" },
      "after",
    );
  }
  return workspaceDigestFields(await workspaceDigest(workspacePath, opts), "after");
}

export interface CommitDeps {
  emit(fields: Record<string, unknown>): Promise<void>;
  store: RunnerStore;
  journalPath: string;
  shadowRoot: string;
  workspaceRoot?: string | undefined;
  /** deterministic fault injection; see TransactionalRunnerOptions */
  afterEffectApplied?: ((state: { applied: string[]; total: number }) => Promise<void>) | undefined;
  /** the bound on the closing workspace measurement; see WORKSPACE_DIGEST_MAX_FILES */
  workspaceDigestMaxFiles?: number | undefined;
  /**
   * Settles the network and the memory half of the turn at the same moment the file half settles,
   * and returns the fields that describe what it did for the terminal record.
   *
   * It is called from inside the protocol rather than around it because the ordering is
   * load-bearing: a held outbound write may only be replayed once the files have actually landed,
   * and a commit that conflicts under its own apply loop must drop those writes rather than send
   * them. Sending is not reversible, so it has to be the last thing that happens, after every
   * check that can still turn a commit into a conflict.
   */
  settleConfinement?:
    | ((runId: string, decision: "commit" | "discard" | "conflict") => Promise<Record<string, unknown>>)
    | undefined;
  /**
   * Tears down one turn's sealed copy. Supplied by whoever created the seal, because only that
   * side knows what it built and how to prove it is gone.
   *
   * The default below is deliberately conservative: the one operation in this system that can
   * destroy the real workspace is a recursive delete of a directory that still has a mount under
   * it, so a delete only happens once the absence of a mount is established, and an unproven
   * teardown quarantines the directory instead. An overlay sealer that can prove more (by reading
   * the whole mount table rather than one exit code) replaces this by passing its own release.
   */
  release?: ((shadowDir: string, mechanism: "overlay" | "copy") => Promise<void>) | undefined;
}

export interface CommitOutcome {
  ok: boolean;
  rule: string;
  decision: "commit" | "conflict" | "discard";
}

export interface ApplyOutcome {
  applied: string[];
  conflictedAt?: string;
  tamperedAt?: string;
  /** a regular-file effect that passed every check and still could not be written */
  failedAt?: string;
  /** the errno-shaped reason the write failed, for the journal */
  failReason?: string;
}

export class CommitProtocol {
  constructor(private readonly deps: CommitDeps) {}

  /**
   * What the real workspace is at the moment this turn ends, for the terminal record.
   *
   * Taken before `release`, and that is the ordering that carries weight: under overlay `merged` is
   * a view of this same tree and tearing it down is not a no-op for the walk. It also follows the
   * confinement settle, but that settle moves the network and the agent's memory rather than
   * workspace bytes, so measuring on either side of THAT one would give the same answer.
   */
  private async closing(workspacePath: string | null, unmeasuredReason?: string): Promise<Record<string, unknown>> {
    return closingWorkspaceFields(workspacePath, {
      ...(this.deps.workspaceDigestMaxFiles === undefined
        ? {}
        : { maxFiles: this.deps.workspaceDigestMaxFiles }),
      ...(unmeasuredReason === undefined ? {} : { unmeasuredReason }),
    });
  }

  /** Runs the protocol above for one turn. */
  async commit(pending: PendingCommit): Promise<CommitOutcome> {
    const { runId, agentId } = pending;
    const tampered = await this.tamperedEffects(pending.shadowDir, pending.mechanism, pending.effects);
    if (tampered.length) {
      for (const changed of tampered.slice(0, JOURNAL_EFFECT_LIMIT)) {
        await this.deps.emit({ runId, agentId, kind: "effect.tampered", path: changed, at: nowIso() });
      }
      await this.discard(
        runId,
        agentId,
        pending.shadowDir,
        pending.mechanism,
        pending.effects,
        "effect-tampered",
        pending.workspacePath,
      );
      return { ok: false, rule: "effect-tampered", decision: "discard" };
    }

    await this.deps.store.putPending(pending);
    // the commit point is this single append; applying is idempotent and replayable from it
    await this.deps.emit({
      runId,
      agentId,
      kind: "turn.committing",
      ...boundedEffects(pending.effects),
      ...(pending.actor === undefined ? {} : { actor: pending.actor, viaApproval: true }),
      at: nowIso(),
    });

    const applied = await this.applyEffects(pending, { replay: false });
    if (applied.conflictedAt || applied.tamperedAt || applied.failedAt) {
      const rule = applied.tamperedAt
        ? "effect-tampered"
        : applied.failedAt
          ? "effect-write-failed"
          : "workspace-changed-during-commit";
      const settledConflict = await this.settle(runId, "conflict");
      await this.deps.emit({
        runId,
        agentId,
        kind: "turn.conflicted",
        rule,
        path: applied.conflictedAt ?? applied.tamperedAt ?? applied.failedAt,
        ...(applied.failReason ? { reason: applied.failReason.slice(0, 240) } : {}),
        applied: applied.applied.slice(0, JOURNAL_EFFECT_LIMIT),
        ...boundedEffects(pending.effects),
        ...settledConflict,
        // The one ending where bytes DID reach the workspace and the turn still did not commit, so
        // this digest is expected to differ. The record says which files landed; the digest is what
        // proves the list is the whole of it.
        ...(await this.closing(pending.workspacePath)),
        at: nowIso(),
      });
      await this.deps.store.removePending(runId);
      await this.release(pending.shadowDir, pending.mechanism);
      return { ok: false, rule, decision: "conflict" };
    }

    const settled = await this.settle(runId, "commit");
    await this.deps.emit({
      runId,
      agentId,
      kind: "turn.committed",
      applied: applied.applied.length,
      ...settled,
      // A commit is the one verdict where the workspace SHOULD have moved. Recorded here for the
      // same reason as on a discard: a commit that changed nothing is then as visible as a discard
      // that changed something.
      ...(await this.closing(pending.workspacePath)),
      at: nowIso(),
    });
    await this.deps.store.removePending(runId);
    await this.release(pending.shadowDir, pending.mechanism);
    return { ok: true, rule: "none", decision: "commit" };
  }

  /**
   * Writes one turn's effects into the real workspace.
   *
   * Every destination goes through the one audited resolver, is re-checked against the baseline
   * immediately before its own write rather than once for the whole batch (attack a44), and is
   * re-hashed immediately before its own write so the bytes that land are the bytes that were
   * judged. On replay the checks invert: an effect already present is skipped, which is what makes
   * running recovery twice change nothing.
   */
  async applyEffects(pending: PendingCommit, opts: { replay: boolean }): Promise<ApplyOutcome> {
    const real = pending.workspacePath;
    const baseline = new Map(Object.entries(pending.baseline));
    const applied: string[] = [];
    for (const effect of pending.effects) {
      // An outbound effect is a held network write, not a path. It is settled by the confinement
      // hook and must never reach the filesystem resolver, which would try to create a file named
      // `net:POST collector:9100/ingest`.
      if (effect.kind === "outbound") continue;
      if (!isSafeRelative(effect.path)) {
        await this.refuse(pending, effect.path, "the recorded path is not a workspace-relative path");
        continue;
      }
      if (opts.replay && (await this.alreadyApplied(real, effect))) {
        applied.push(effect.path);
        continue;
      }
      if (!opts.replay) {
        // Compared on the same path the baseline was taken from, before the resolver touches
        // anything, so an ordinary write to a hardlinked file is not mistaken for a conflict.
        const live = await liveSignature(path.join(real, effect.path));
        const opened = baseline.get(effect.path) ?? null;
        if (live !== opened) return { applied, conflictedAt: effect.path };
      }

      // every trusted-half path goes through one audited resolver: symlink components, hardlinks,
      // parent references and anything resolving outside the workspace are refused in one place
      const target =
        effect.kind === "delete" ? await safeResolve(real, effect.path) : await safeWriteTarget(real, effect.path);
      if (!target.ok) {
        await this.refuse(pending, effect.path, target.reason);
        continue;
      }
      const destination = target.abs;

      if (effect.kind === "delete") {
        const stat = await fs.lstat(destination).catch(() => null);
        if (stat?.isSymbolicLink()) {
          await fs.rm(destination, { force: true }); // drop the link, not its target
        } else {
          await fs.rm(destination, { force: true, recursive: true });
        }
      } else if (effect.kind === "symlink") {
        if (effect.escapes || !effect.target) {
          // Not applied on purpose, so it goes on the record like every other refusal in this loop
          // rather than vanishing. A bare continue here left no trace that the turn asked for a link
          // the commit declined to make.
          await this.refuse(
            pending,
            effect.path,
            effect.escapes ? "the link resolves outside the workspace" : "the link records no target",
          );
          continue;
        }
        // Both calls used to end in `.catch(() => undefined)` and execution fell through to
        // applied.push, so a link that was never created was reported as APPLIED. That is the same
        // hole as the swallowed copyFile below and a worse shape of it: the copy at least dropped the
        // effect from the applied set. A non-empty directory standing where the link goes reaches it
        // deterministically, because rm is called without recursive and then symlink fails EEXIST.
        const linkTarget = effect.target; // narrowed by the guard above; closures lose the narrowing
        const linkError = await fs
          .rm(destination, { force: true })
          .then(() => fs.symlink(linkTarget, destination))
          .then(() => null, (error: unknown) => (error instanceof Error ? error.message : String(error)));
        if (linkError !== null) {
          return { applied, failedAt: effect.path, failReason: linkError };
        }
      } else {
        const from = await this.sourceOf(pending, effect.path);
        // Checked before anything opens it. copyFile on a fifo blocks until a writer appears, and
        // on a socket it fails, which used to be swallowed two lines down: the effect was dropped
        // from `applied` and nothing recorded why. A commit carries bytes across, and these have
        // none, so the refusal goes on the record and the real workspace is not touched.
        const source = await fs.lstat(from).catch(() => null);
        if (!source || !hasBytes(source)) {
          await this.refuse(
            pending,
            effect.path,
            source ? "a socket, fifo or device is not carried across by a commit" : "the shadow no longer holds it",
          );
          continue;
        }
        if (effect.sha256 && (await hashFile(from)) !== effect.sha256) {
          return { applied, tamperedAt: effect.path };
        }
        const copyError = await fs
          .copyFile(from, destination)
          .then(() => null, (error: unknown) => (error instanceof Error ? error.message : String(error)));
        if (copyError !== null) {
          // A regular file the turn produced could not be written into the workspace. Every sibling
          // failure above aborts the commit: a tamper returns, a workspace that moved returns. A
          // bare `continue` here dropped the effect from `applied` and recorded nothing, and commit()
          // then ran on to turn.committed, removed the pending record and released the shadow, so the
          // write was lost with no trace and no way to replay it. It fails closed like the others:
          // the turn is reported as a conflict, named, and not as a clean commit. EISDIR (a directory
          // sits where a file was to be written), ENOSPC, EACCES and a source that vanished mid-commit
          // all reach here, and none of them is a thing to pass over in silence.
          return { applied, failedAt: effect.path, failReason: copyError };
        }
        if (typeof effect.mode === "number") await fs.chmod(destination, effect.mode).catch(() => undefined);
      }

      applied.push(effect.path);
      if (this.deps.afterEffectApplied) {
        await this.deps.afterEffectApplied({ applied: [...applied], total: pending.effects.length });
      }
    }
    return { applied };
  }

  /** effects whose shadow bytes no longer hash to what capture recorded */
  async tamperedEffects(
    shadowDir: string,
    mechanism: "overlay" | "copy",
    effects: EffectRecord[],
  ): Promise<string[]> {
    const changed: string[] = [];
    for (const effect of effects) {
      if (effect.kind === "outbound") continue;   // no file behind it to re-hash
      if (!isSafeRelative(effect.path)) {
        changed.push(effect.path);
        continue;
      }
      if (effect.kind === "delete" || effect.kind === "symlink" || !effect.sha256) continue;
      const from = await this.sourceOf({ shadowDir, mechanism }, effect.path);
      if ((await hashFile(from)) !== effect.sha256) changed.push(effect.path);
    }
    return changed;
  }

  /**
   * Finishes any commit that was interrupted, from the sealed copy still on disk.
   *
   * Run at construction, before the runner accepts any new work, and safe to run again: what is
   * already applied is recognised by its hash and skipped.
   */
  async reconcile(): Promise<{ replayed: string[]; unrecoverable: string[] }> {
    const replayed: string[] = [];
    const unrecoverable: string[] = [];
    const kinds = await this.journalKinds();
    const terminal = (runId: string): boolean => {
      const seen = kinds.get(runId);
      return (
        !!seen && (seen.has("turn.committed") || seen.has("turn.conflicted") || seen.has("turn.rejected"))
      );
    };

    for (const pending of await this.deps.store.listPending()) {
      if (terminal(pending.runId)) {
        await this.deps.store.removePending(pending.runId);
        continue;
      }
      const roots = await this.validPaths(pending.shadowDir, pending.workspacePath);
      if (!roots.ok) {
        await this.deps.emit({
          runId: pending.runId,
          agentId: pending.agentId,
          kind: "commit.unrecoverable",
          reason: roots.reason,
          // Deliberately not measured: this path just failed the root check, and a refused path is
          // not a path this process walks.
          ...(await this.closing(null, "workspace-path-refused")),
          at: nowIso(),
        });
        await this.deps.store.removePending(pending.runId);
        unrecoverable.push(pending.runId);
        continue;
      }
      const applied = await this.applyEffects(pending, { replay: true });
      const terminalFailure = applied.tamperedAt ?? applied.conflictedAt ?? applied.failedAt;
      if (terminalFailure !== undefined) {
        // Recovery reported turn.committed no matter what the replay did, so a tamper, a conflict or
        // a failed write during recovery all surfaced as a clean recovered commit. It fails closed
        // like the live path now: the turn is named a conflict, the pending record is cleared, and
        // it is tracked so the trailing unrecoverable scan does not double-report it.
        const rule = applied.tamperedAt
          ? "effect-tampered"
          : applied.failedAt
            ? "effect-write-failed"
            : "workspace-changed-during-commit";
        const settledConflict = await this.settle(pending.runId, "conflict");
        await this.deps.emit({
          runId: pending.runId,
          agentId: pending.agentId,
          kind: "turn.conflicted",
          recovered: true,
          rule,
          path: terminalFailure,
          ...(applied.failReason ? { reason: applied.failReason.slice(0, 240) } : {}),
          applied: applied.applied.length,
          ...settledConflict,
          ...(await this.closing(pending.workspacePath)),
          at: nowIso(),
        });
        await this.deps.store.removePending(pending.runId);
        await this.release(pending.shadowDir, pending.mechanism);
        unrecoverable.push(pending.runId);
        continue;
      }
      // Recovery used to finish the FILE half only. The memory promote and the broker's held
      // outbound writes live behind settle, which had exactly three call sites and none of them was
      // here, so a recovered turn emitted turn.committed while the agent's memory was never promoted
      // and the held writes were never replayed. README:169 claims a crash after the commit point is
      // finished idempotently at the next start, and that was true of files and of nothing else.
      //
      // Calling settle here is safe in both directions. When the process that held the turn is gone,
      // the live map is empty and settle returns confinementStateLost with the detail saying only
      // the file half happened, so the journal records an incomplete settle instead of claiming a
      // clean one. When state does survive, settle's own `state.settled` flag makes a second call a
      // no-op, so a replayed hold cannot be sent twice.
      const settled = await this.settle(pending.runId, "commit");
      await this.deps.emit({
        runId: pending.runId,
        agentId: pending.agentId,
        kind: "turn.committed",
        recovered: true,
        applied: applied.applied.length,
        ...settled,
        ...(await this.closing(pending.workspacePath)),
        at: nowIso(),
      });
      await this.deps.store.removePending(pending.runId);
      await this.release(pending.shadowDir, pending.mechanism);
      replayed.push(pending.runId);
    }

    // A commit point in the journal with no completion and no record left to finish it from is the
    // one outcome recovery cannot fix. It is named rather than passed over in silence.
    for (const [runId, seen] of kinds) {
      if (!seen.has("turn.committing") || terminal(runId)) continue;
      if (seen.has("commit.unrecoverable")) continue;
      if (replayed.includes(runId) || unrecoverable.includes(runId)) continue;
      if (await this.deps.store.getPending(runId)) continue;
      await this.deps.emit({
        runId,
        kind: "commit.unrecoverable",
        reason: "no retained effect record",
        // No record is left naming a workspace, so there is nothing to measure and this says so.
        // The one ending where the product cannot claim anything, and must not read as if it could.
        ...(await this.closing(null, "no-retained-effect-record")),
        at: nowIso(),
      });
      unrecoverable.push(runId);
    }
    return { replayed, unrecoverable };
  }

  /**
   * Refuses a record that points anywhere but the configured roots.
   *
   * The runner's own store writes these, so this is depth rather than the primary control, and it
   * is the check that turns "the store is private" from an assumption into something enforced.
   */
  async validPaths(shadowDir: string, workspacePath: string): Promise<{ ok: boolean; reason?: string }> {
    const under = async (root: string, absolute: string, label: string): Promise<string | null> => {
      const relative = path.relative(root, absolute);
      if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
        return `${label} is not under its configured root`;
      }
      const resolved = await safeResolve(root, relative);
      return resolved.ok ? null : `${label}: ${resolved.reason}`;
    };
    const shadowProblem = await under(this.deps.shadowRoot, shadowDir, "shadow directory");
    if (shadowProblem) return { ok: false, reason: shadowProblem };
    if (this.deps.workspaceRoot) {
      const workspaceProblem = await under(this.deps.workspaceRoot, workspacePath, "workspace");
      if (workspaceProblem) return { ok: false, reason: workspaceProblem };
    }
    return { ok: true };
  }

  /**
   * Drops a turn: the record says what was thrown away, then the sealed copy goes.
   *
   * `workspacePath` is required rather than optional, and that is the point of it: an optional
   * parameter is how a new discard path ends up writing a record with no measurement on it.
   */
  async discard(
    runId: string,
    agentId: string,
    shadowDir: string,
    mechanism: "overlay" | "copy",
    effects: EffectRecord[],
    rule: string,
    workspacePath: string,
  ): Promise<void> {
    const settled = await this.settle(runId, "discard");
    await this.deps.emit({
      runId,
      agentId,
      kind: "turn.discarded",
      rule,
      ...boundedEffects(effects),
      ...settled,
      // The claim the product is named for: the turn wrote into the sealed copy, the copy is about
      // to go, and this says what the real workspace is at that moment.
      ...(await this.closing(workspacePath)),
      at: nowIso(),
    });
    await this.release(shadowDir, mechanism);
  }

  /** The confinement settle, or nothing when the host wired none. Never throws into the protocol. */
  private async settle(
    runId: string,
    decision: "commit" | "discard" | "conflict",
  ): Promise<Record<string, unknown>> {
    if (!this.deps.settleConfinement) return {};
    return this.deps.settleConfinement(runId, decision);
  }

  async release(shadowDir: string, mechanism: "overlay" | "copy"): Promise<void> {
    if (this.deps.release) {
      await this.deps.release(shadowDir, mechanism);
      return;
    }
    if (mechanism === "copy") {
      await fs.rm(shadowDir, { recursive: true, force: true }).catch(() => undefined);
      return;
    }
    // An overlay teardown that deletes on an unproven unmount deletes THROUGH the mount, and the
    // lower layer is the real workspace. `umount` exits 32 for every failure, so its exit code
    // decides nothing; the mount table does.
    const merged = path.join(shadowDir, "merged");
    await execFileAsync("umount", [merged]).catch(() => undefined);
    if (await this.stillMounted(merged)) {
      await this.deps.emit({
        kind: "shadow.quarantined",
        shadowDir,
        reason: "a mount is still present under the shadow, so it was not deleted",
      });
      return;
    }
    await fs.rm(shadowDir, { recursive: true, force: true }).catch(() => undefined);
  }

  /**
   * True unless the absence of a mount at or under `dir` can be established from the mount table.
   * Unreadable means unprovable, and unprovable is treated as mounted, because the cost of being
   * wrong in the other direction is the real workspace.
   */
  private async stillMounted(dir: string): Promise<boolean> {
    let table: string;
    try {
      table = await fs.readFile("/proc/self/mountinfo", "utf8");
    } catch {
      // No mountinfo (macOS, and any host that hides it). Fall back to the mount command, and
      // treat a failure to read the table as mounted rather than as clean.
      const out = await execFileAsync("mount", []).then((r) => r.stdout).catch(() => null);
      if (out === null) return true;
      return out.split("\n").some((line) => this.lineTouches(line, dir));
    }
    const prefix = dir.endsWith(path.sep) ? dir : dir + path.sep;
    return table.split("\n").some((line) => {
      const point = line.split(" ")[4];
      return point !== undefined && (point === dir || point.startsWith(prefix));
    });
  }

  private lineTouches(line: string, dir: string): boolean {
    const prefix = dir.endsWith(path.sep) ? dir : dir + path.sep;
    const match = / on (.+?) \(/.exec(line);
    const point = match?.[1];
    return point !== undefined && (point === dir || point.startsWith(prefix));
  }

  // ---- internals ------------------------------------------------------------

  /** the sealed copy of one path: the upper layer under overlay, the merged tree under a copy */
  private async sourceOf(
    where: { shadowDir: string; mechanism: "overlay" | "copy" },
    relPath: string,
  ): Promise<string> {
    const source = shadowFileOf(where.shadowDir, where.mechanism, relPath);
    const alternate = path.join(where.shadowDir, "merged", relPath);
    return (await fs.access(source).then(() => true).catch(() => false)) ? source : alternate;
  }

  private async refuse(pending: PendingCommit, effectPath: string, reason?: string): Promise<void> {
    await this.deps.emit({
      runId: pending.runId,
      agentId: pending.agentId,
      kind: "effect.refused",
      path: effectPath,
      reason,
      at: nowIso(),
    });
  }

  /** true when the workspace already holds what this effect would produce */
  private async alreadyApplied(real: string, effect: EffectRecord): Promise<boolean> {
    const absolute = path.join(real, effect.path);
    if (effect.kind === "delete") {
      return !(await fs.access(absolute).then(() => true).catch(() => false));
    }
    if (effect.kind === "symlink") {
      const current = await fs.readlink(absolute).catch(() => null);
      return current !== null && current === effect.target;
    }
    if (!effect.sha256) return false;
    return (await hashFile(absolute)) === effect.sha256;
  }

  /** runId -> the record kinds the journal already holds for it */
  private async journalKinds(): Promise<Map<string, Set<string>>> {
    const text = await fs.readFile(this.deps.journalPath, "utf8").catch(() => "");
    const out = new Map<string, Set<string>>();
    for (const line of text.split("\n")) {
      if (!line) continue;
      let record: { runId?: unknown; kind?: unknown };
      try {
        record = JSON.parse(line) as { runId?: unknown; kind?: unknown };
      } catch {
        continue; // torn line, skipped
      }
      if (typeof record.runId !== "string" || typeof record.kind !== "string") continue;
      const seen = out.get(record.runId) ?? new Set<string>();
      seen.add(record.kind);
      out.set(record.runId, seen);
    }
    return out;
  }
}

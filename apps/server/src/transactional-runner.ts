import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import type { AgentRunner, Containment, RunnerRequest, RunnerResult } from "./types.js";
import {
  captureEffects,
  effectSetHash,
  emptySnapshot,
  liveSignature,
  resolveLimits,
  snapshotStats,
  within,
  type CaptureLimits,
  type Snapshot,
} from "./capture.js";
import {
  DEFAULT_PROTECTED_PATHS,
  DEFAULT_REGISTRY_ALLOWLIST,
  buildPolicyContext,
  probeCaseInsensitive,
  readDeclaredProtectedPaths,
} from "./policy-context.js";
import {
  armReadWitness,
  attachReadWitness,
  collectTurnReadWitness,
  failedReadWitness,
  readWitnessJournalFields,
  rearmReadWitness,
  summariseReadWitness,
  type ReadWitnessBaseline,
} from "./read-witness.js";
import { RunnerStore, type HeldTurn } from "./runner-store.js";
import { buildReviewViews, type ReviewView } from "./review-view.js";
import {
  CommitProtocol,
  JOURNAL_EFFECT_LIMIT,
  boundedEffects,
  closingWorkspaceFields,
  nowIso,
  workspaceDigest,
  workspaceDigestFields,
} from "./commit-protocol.js";
import type { EffectRecord, Policy, PolicyVerdict, PolicyContext } from "./policy-types.js";

const execFileAsync = promisify(execFile);

import { ZERO_HEAD, canonicalJson, sha256Hex } from "./journal-format.js";
import {
  Journal,
  JournalCompromisedError,
  verifyJournalAt,
  type CheckpointInfo,
  type JournalOptions,
} from "./journal.js";
export type { EffectRecord, Policy, PolicyVerdict, PolicyContext };
export type { Containment };
export type { ReviewEffectView, ReviewView } from "./review-view.js";

/**
 * The network half and the memory half of a turn, supplied by the host so the decorator stays one
 * file about one idea. Everything here is optional: with no confinement the decorator behaves
 * exactly as it did, and every turn is journaled `confinement: "none"` rather than quietly
 * appearing contained.
 */
export interface TurnConfinement {
  /** Before the turn: seal the network and the agent's memory. Returns what the runner is told. */
  open(input: {
    runId: string;
    request: RunnerRequest;
    shadowDir: string;
  }): Promise<{ request: RunnerRequest; note: Record<string, unknown> }>;
  /** After the turn and BEFORE the policy runs: the writes the broker deferred, as effects. */
  outboundEffects(runId: string): Promise<EffectRecord[]>;
  /** The one settle point: commit replays and promotes, every other verdict drops and restores. */
  settle(
    runId: string,
    decision: "commit" | "discard" | "review" | "conflict",
  ): Promise<{ note?: Record<string, unknown>; threadId?: string | null }>;
}

export interface JournalRecord {
  seq: number;
  runId: string;
  agentId: string;
  kind: string;
  prev: string;
  hash?: string;
  [k: string]: unknown;
}

/** Why a settle did or did not happen. The caller turns this into an HTTP answer. */
export type SettleCode =
  | "ok"
  | "settling"
  | "not-pending"
  | "chain-broken"
  | "invalid-record"
  | "hash-mismatch"
  | "tampered"
  | "policy-refused"
  | "conflict";

export interface SettleResult {
  ok: boolean;
  code: SettleCode;
  detail?: string | undefined;
}

export interface TransactionalRunnerOptions {
  shadowRoot: string;
  journalPath: string;
  policy: Policy;
  /** host-side sealing; falls back to a copy when the host cannot mount an overlay */
  seal?: (real: string, shadowDir: string) => Promise<"overlay" | "copy">;
  /** where the runner keeps its private held and pending records; defaults beside the journal */
  stateRoot?: string;
  /** every workspace lives under this; a held record naming anything else is refused */
  workspaceRoot?: string;
  /** the platform's own secrets, so a turn writing one out is recognisable */
  platformSecrets?: string[];
  registryAllowlist?: string[];
  limits?: Partial<CaptureLimits>;
  /**
   * Deterministic fault injection, called after each effect is applied.
   *
   * Two invariants are only testable with a hand on the clock. A crash-safe commit needs a stop at
   * a known effect, because the first attempt at that test raced a `sleep` against a kill, landed
   * before the commit point, and proved nothing. A per-effect conflict check needs a writer that
   * changes the workspace between two writes. Throwing here leaves exactly the state a `kill -9`
   * mid-commit leaves; writing here is the concurrent editor. Unset in the product.
   */
  afterEffectApplied?: (state: { applied: string[]; total: number }) => Promise<void>;
  /**
   * The bound on the workspace measurement, in entries. Defaults to WORKSPACE_DIGEST_MAX_FILES.
   *
   * It raises or lowers a threshold; it does not switch the measurement off. A host whose tree is
   * over the bound gets a recorded refusal on every turn, not a journal that reads the same whether
   * anything was measured or not.
   */
  workspaceDigestMaxFiles?: number;
  /** keys, checkpoint interval and anchors; the defaults are the shipping configuration */
  journal?: Omit<JournalOptions, "journalPath">;
  /** the sealed network and the sealed codex-home, when the host wired them */
  confinement?: TurnConfinement;
  /**
   * Tears down one turn's sealed copy, supplied by whoever created the seal.
   *
   * A sealer that mounts something must own the unmount, because the runner cannot prove a
   * teardown it did not perform. Without one the runner uses a conservative default that refuses
   * to delete a shadow while a mount is still present under it.
   */
  release?: (shadowDir: string, mechanism: "overlay" | "copy") => Promise<void>;
}

/**
 * Wraps ANY AgentRunner so every turn of every agent becomes a transaction.
 *
 * The wrapped runner is never told it is wrapped: it receives a workspacePath like always. That
 * path is a sealed view of the real workspace, so whatever the turn does lands nowhere until the
 * captured effect set clears policy. Commit applies the effects; discard drops them.
 *
 * This is the whole "for every agent, zero config" claim: composing it in the runner factory makes
 * every agent created through the stock CRUD flow transactional with no per-agent setup.
 *
 * This file owns the turn: seal, run, capture, judge, and the settle decision. The two halves with
 * a life of their own live beside it. `commit-protocol.ts` is everything that makes a change real,
 * including the recovery of one that was interrupted. `review-view.ts` is what a human is shown
 * before deciding. `capture.ts` and `policy-context.ts` are what the judge is given.
 */
export class TransactionalRunner implements AgentRunner {
  /**
   * The ledger. Sequence numbers, chaining, the keyed layer, checkpoints, anchoring and the boot
   * verification all live in Journal; this class only says what happened, never how it is recorded.
   */
  private readonly journal: Journal;
  /** links replaced at seal time; a write to one of these is an effect, not a passthrough */
  private neutralised = new Set<string>();
  private restored: Promise<void> | null = null;
  private pendingNote: Record<string, unknown> | null = null;
  /**
   * Turns whose settle is in flight. Entered synchronously, before the first await, so two callers
   * racing approve against reject on one turn cannot both find it pending (attack a40).
   */
  private readonly settling = new Set<string>();
  /** agents an operator asked to stop; checked after the runtime returns (attack a45) */
  private readonly cancelled = new Set<string>();
  private readonly store: RunnerStore;
  private readonly protocol: CommitProtocol;
  private readonly limits: CaptureLimits;
  private readonly reconciliation: Promise<void>;
  /**
   * The thread id the confinement restored, per run, waiting for withContainment to put it on the
   * result. A turn that did not commit reports the thread it STARTED from: without this the
   * agent's memory is rolled back on disk while the platform still points the next turn at the
   * conversation the rolled-back turn created.
   */
  private readonly settledThread = new Map<string, string | null>();
  /**
   * The ledger the operator signed for, as bytes, captured at the instant they signed it.
   *
   * Held in memory and never written down. An acknowledgement is already a per-process fact
   * (Journal.open re-enters compromised on every restart), so a file would give this a longer life
   * than the thing it qualifies, and it would be a file the runner obeys: whoever can rewrite the
   * ledger to erase a turn can rewrite a record of what the ledger used to be just as easily. A
   * value that only lives where the acknowledgement lives cannot be reached by editing the disk.
   */
  private acknowledgedLedger: { records: number; digest: string } | null = null;

  constructor(
    private readonly inner: AgentRunner,
    private readonly opts: TransactionalRunnerOptions,
  ) {
    // One writer per journal path per process, and a lock file against a second process. Two
    // writers on one ledger fork the chain, which is a48.
    this.journal = Journal.acquire({ journalPath: opts.journalPath, ...opts.journal });
    this.store = new RunnerStore(opts.stateRoot ?? path.dirname(opts.journalPath));
    this.limits = resolveLimits(opts.limits);
    this.protocol = new CommitProtocol({
      emit: (fields) => this.emit(fields),
      store: this.store,
      journalPath: opts.journalPath,
      shadowRoot: opts.shadowRoot,
      workspaceRoot: opts.workspaceRoot,
      afterEffectApplied: opts.afterEffectApplied,
      workspaceDigestMaxFiles: opts.workspaceDigestMaxFiles,
      settleConfinement: opts.confinement ? (runId, decision) => this.settleConfinement(runId, decision) : undefined,
      release: opts.release,
    });
    // A commit that was interrupted is finished before this runner accepts any new work.
    this.reconciliation = this.reconcile().then(
      () => undefined,
      () => undefined,
    );
  }

  async isAvailable(): Promise<boolean> {
    return this.inner.isAvailable();
  }

  /**
   * Stop is not only a signal to the runtime. A turn that wrote its damage quickly and then stalled
   * has already returned by the time the operator clicks, and forwarding the request to a process
   * that has exited is a no-op the operator reads as "I stopped it in time" (attack a45). So the
   * request is also recorded here, and run() refuses to judge or apply a turn that carries it.
   */
  async cancel(agentId: string): Promise<boolean> {
    this.cancelled.add(agentId);
    return this.inner.cancel(agentId);
  }

  /** Resolves once any interrupted commit found at construction has been replayed. */
  async ready(): Promise<void> {
    await this.reconciliation;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    await this.ready();
    // Refused BEFORE anything is built, not merely before anything is executed.
    //
    // emit() already refuses on a compromised ledger, so a turn was never executed unrecorded. But
    // the first record is written after the workspace is sealed and after the confinement is open,
    // and the throw from emit unwound neither, so every refused attempt left an overlay mount, a
    // broker container and a sealed codex home behind, once per attempt, with nothing on the
    // product path to sweep them. Whoever can break the ledger should not also get an unbounded
    // resource leak out of it, so the refusal happens here, where it costs a stat.
    await this.assertJournalUsable();
    this.cancelled.delete(request.agentId);
    // One turn, one identifier. The control plane's run id is adopted when there is one, so the
    // journal, the review queue, the timeline, the run history and the Playground all name the
    // same turn by the same string. A caller with no run of its own still gets a fresh id.
    const runId = request.runId ?? crypto.randomUUID();
    try {
      return await this.runTurn(runId, request);
    } finally {
      // settledThread is scratch space for ONE call: settleConfinement fills it and
      // withContainment consumes it. Every exit in between used to have to remember to clear it,
      // and the exit for a turn whose agent died did not, so a crashed turn left an entry behind
      // for the life of the process. The lifetime is the call, so it is enforced where the call
      // ends rather than at each of the ways out of it.
      this.settledThread.delete(runId);
    }
  }

  /** One turn, from the seal to the verdict. run() owns the identifier and the scratch it leaves. */
  private async runTurn(runId: string, request: RunnerRequest): Promise<RunnerResult> {
    const agentId = request.agentId;
    const shadowDir = path.join(this.opts.shadowRoot, runId);
    await fs.mkdir(path.join(shadowDir, "upper"), { recursive: true });
    await fs.mkdir(path.join(shadowDir, "work"), { recursive: true });
    const merged = path.join(shadowDir, "merged");
    await fs.mkdir(merged, { recursive: true });

    const { mechanism, confined, opened, sealed, readWitness } = await this.openTurn({ runId, agentId, request, shadowDir, merged });
    const baseline = opened.signatures;

    let result: RunnerResult;
    try {
      // the inner runner sees a normal workspace path and nothing else changes for it
      result = await this.inner.run(confined?.request ?? { ...request, workspacePath: merged });
    } catch (error) {
      await this.emit({ runId, agentId, kind: "turn.executed", exit: "failed", at: nowIso() });
      // a turn that crashed still made network calls; the held writes go with it
      await this.settleConfinement(runId, "discard");
      await this.protocol.release(shadowDir, mechanism);
      await this.emit({
        runId,
        agentId,
        kind: "turn.discarded",
        rule: "turn-failed",
        // A crashed or timed-out turn is the one ending with no effect list, because captureEffects
        // is never reached. Without this the record says only that something was stopped, and says
        // nothing whatever about the workspace it was stopped over.
        ...(await this.closingWorkspace(request.workspacePath)),
        at: nowIso(),
      });
      throw error;
    }
    // `exit` is the runtime process's own outcome and stays "ok" when codex exited cleanly, because
    // it did. What the record could not say before is what happened INSIDE the turn: codex stops
    // waiting for a command at ten seconds and reports it as `exit_code: 124, status: "failed"`,
    // then finishes the turn normally. A turn whose only command was killed therefore reached this
    // line reading exactly like a turn whose command succeeded, and the command's half-finished work
    // was captured and committed with nothing recording that it never finished.
    const commands = result.commands ?? [];
    const failedCommands = commands.filter((command) => command.failed);
    await this.emit({
      runId,
      agentId,
      kind: "turn.executed",
      exit: "ok",
      ...(result.commands === undefined
        ? {}
        : {
            commands: commands.length,
            commandsFailed: failedCommands.length,
            // Bounded, and the exit code is kept because 124 is the timeout and any other non-zero
            // is a command that ran and refused, which an operator reads differently.
            ...(failedCommands.length > 0
              ? {
                  failed: failedCommands.slice(0, JOURNAL_EFFECT_LIMIT).map((command) => ({
                    command: command.command.slice(0, 240),
                    exitCode: command.exitCode,
                    status: command.status,
                  })),
                }
              : {}),
          }),
      at: nowIso(),
    });

    // Read the arm back BEFORE capture, and not one line later. captureEffects hashes every
    // regular file in the sealed copy, and a hash is a read, so a witness collected after it
    // reports the platform's own work as the turn's, on every file in the workspace.
    const witness = await collectTurnReadWitness(readWitness, {
      // The real protected set, not a stand-in: the platform defaults plus whatever the workspace
      // declared, which is the same union buildPolicyContext hands the rules. The declaration is
      // read from the REAL workspace rather than the sealed copy, so a turn cannot widen or narrow
      // the set it is watched against by editing it.
      protectedPaths: [
        ...DEFAULT_PROTECTED_PATHS,
        ...(await readDeclaredProtectedPaths(request.workspacePath)),
      ],
    });
    const captured = await captureEffects({
      shadowDir,
      real: request.workspacePath,
      mechanism,
      sealed,
      realInodes: opened.inodes,
      limits: this.limits,
    });
    const effects = captured.effects;
    // The seal closed the holes it could see. This asserts the outcome instead of trusting the walk:
    // a link the SEALED VIEW still carries outward is a defect in the seal, and it is recorded
    // loudly rather than folded into the ordinary policy verdict. A link the agent created during
    // its own turn is a different thing and the policy judges it as `symlink` with `escapes` set.
    const stillEscaping = effects.filter((effect) => effect.kind === "symlink" && effect.escapes);
    if (stillEscaping.length) {
      await this.emit({
        runId,
        agentId,
        kind: "seal.escape.observed",
        count: stillEscaping.length,
        paths: stillEscaping.map((effect) => effect.path).slice(0, 20),
        at: nowIso(),
      });
    }
    // The writes the broker held join the same effect set, so files, memory and outbound writes are
    // one question for the policy rather than three, and one verdict rather than three.
    if (this.opts.confinement) effects.push(...(await this.opts.confinement.outboundEffects(runId)));
    await this.emit({
      runId,
      agentId,
      kind: "effects.captured",
      count: effects.length,
      bytes: captured.totalBytes,
      oversize: captured.oversize.length,
      // Beside the effect count, because the two answer one question. A turn that wrote nothing and
      // read the credentials has `count: 0` and always did; what it did not have was anything at
      // all on the line saying so. Absence is a value here: `readWitness: "none"` under a mechanism
      // that is not armed, the reason slug under a mount that cannot see reads, and in neither case
      // a read count, because "no reads" and "cannot see reads" are different answers.
      ...readWitnessJournalFields(witness),
      at: nowIso(),
    });

    // The operator pressed Stop. Whether the runtime was still alive to receive it or not, this
    // turn does not get judged and does not get applied.
    if (this.cancelled.delete(agentId)) {
      await this.protocol.discard(
        runId,
        agentId,
        shadowDir,
        mechanism,
        effects,
        "cancelled-by-operator",
        request.workspacePath,
      );
      return this.withContainment(result, this.containmentOf(runId, "discard", "cancelled-by-operator", effects));
    }

    // The caps are enforced in CAPTURE, before anything reads bytes, because the policy reads
    // content and content is exactly what a turn that wrote a file bigger than memory wants it to
    // read (attack a39). That has not changed: an over-cap file is still never read and never
    // hashed. What this block no longer does is decide the turn. It says WHICH FILES WERE NOT READ
    // and then gets out of the way, because "more bytes than the platform will read" is a fact
    // about the platform's budget, not a judgement about what the agent did, and spending a discard
    // on it spends the product's one unappealable outcome on an accounting event. Measured against
    // a real model on the demo's own prompt: `npm install` wrote a 9,112,572-byte typescript.js and
    // the whole turn was destroyed while the model reported success.
    //
    // The over-cap files reach the policy as records carrying a path, a kind, a mode and a size and
    // no content, marked so no content rule can read them, and `blast-radius` turns the declared
    // size into a REVIEW. The hold branch below keeps the sealed copy so a person can settle it.
    const capRule = captured.oversize.length
      ? "effect-too-large"
      : captured.totalBytes > this.limits.maxTurnBytes
        ? "turn-too-large"
        : null;
    if (capRule) {
      await this.emit({
        runId,
        agentId,
        kind: "effects.refused",
        rule: capRule,
        oversize: captured.oversize.slice(0, JOURNAL_EFFECT_LIMIT),
        totalBytes: captured.totalBytes,
        limit: capRule === "effect-too-large" ? this.limits.maxEffectBytes : this.limits.maxTurnBytes,
        at: nowIso(),
      });
    }

    // A judge that throws must not become a turn that commits, and must not leave the sealed copy
    // on disk with no record of what happened to it. The safe answer to "the policy failed" is the
    // same as the safe answer to everything else here: nothing reaches the workspace.
    let verdict: PolicyVerdict;
    try {
      const context = await buildPolicyContext({
        shadowDir,
        mechanism,
        workspacePath: request.workspacePath,
        journalPath: this.opts.journalPath,
        agentId,
        taskPrompt: request.prompt,
        limits: this.limits,
        platformSecrets: this.opts.platformSecrets ?? [],
        registryAllowlist: this.opts.registryAllowlist ?? DEFAULT_REGISTRY_ALLOWLIST,
        realInodes: opened.inodes,
      });
      verdict = await this.opts.policy(
        effects,
        // The witness rides on the context, and `protected-read-exposure` now reads it. It was
        // unread for a while on purpose, because the raw protected-read bit is 35.4% false positive
        // and making it decide anything was a cost decision. The rule that consumes it pays that
        // cost down with five preconditions rather than trusting the bit: a supported witness, at
        // least 20 armed files, a protected path, selectivity at or under 5%, and a turn that
        // either wrote nothing at all or made an outbound request. Measured on 80 real turns across
        // four workspaces: 32 of 32 read-only credential thefts held, against 4 added holds on 48
        // benign turns, all four of them `grep -h PORT .env`. It reads through readWitnessOf and
        // answers for the null and unsupported cases, which stay three distinct answers.
        attachReadWitness(context, witness === null ? null : summariseReadWitness(witness)),
      );
    } catch (error) {
      await this.emit({
        runId,
        agentId,
        kind: "policy.failed",
        detail: error instanceof Error ? error.message : String(error),
        at: nowIso(),
      });
      await this.protocol.discard(runId, agentId, shadowDir, mechanism, effects, "policy-failed", request.workspacePath);
      return this.withContainment(result, this.containmentOf(runId, "discard", "policy-failed", effects));
    }
    // A floor, never a decision: the caps can only make a `commit` into a hold, and can never turn a
    // discard or a review into anything weaker. It exists because `maxEffectBytes` and
    // `maxTurnBytes` are constructor options, while `blast-radius` compares against the shipped
    // constants it imports. Under the defaults the two agree and this never fires. Under a runner
    // configured with a LOWER cap they do not, and without this the runner would record a file it
    // deliberately never read and then let the policy commit it unjudged, which is the silent
    // fail-open version of the defect this change is fixing.
    if (capRule && verdict.decision === "commit") {
      verdict = {
        decision: "review",
        rule: capRule,
        hits: [
          ...(verdict.hits ?? []),
          {
            rule: capRule,
            decision: "review",
            detail: `over this runner's configured ${capRule === "effect-too-large" ? "per-effect" : "per-turn"} byte limit, so the bytes were never read`,
          },
        ],
      };
    }
    await this.emit({ runId, agentId, kind: "policy.decision", ...verdict, at: nowIso() });

    if (verdict.decision === "commit") {
      // Optimistic concurrency: refuse rather than silently overwrite. Without this, two turns that
      // opened against the same state both commit and the later one wins, losing the earlier turn's
      // work with no record that it happened.
      const conflicts = await this.conflictingPaths(request.workspacePath, baseline, effects);
      if (conflicts.length) {
        await this.emit({
          runId,
          agentId,
          kind: "turn.conflicted",
          rule: "workspace-changed-during-turn",
          paths: conflicts.slice(0, JOURNAL_EFFECT_LIMIT),
          ...boundedEffects(effects),
          // Somebody else moved the ground, so this digest is expected to differ from the one on
          // turn.begin, and what it says is that the difference is theirs: nothing of this turn was
          // applied. The conflict settle that follows moves the network and the agent's memory, not
          // workspace bytes, so measuring on either side of it gives the same answer.
          ...(await this.closingWorkspace(request.workspacePath)),
          at: nowIso(),
        });
        await this.settleConfinement(runId, "conflict");
        await this.protocol.release(shadowDir, mechanism);
        return this.withContainment(
          result,
          this.containmentOf(runId, "conflict", "workspace-changed-during-turn", effects),
        );
      }
      const outcome = await this.protocol.commit({
        runId,
        agentId,
        effects,
        workspacePath: request.workspacePath,
        shadowDir,
        mechanism,
        baseline: Object.fromEntries(baseline),
        startedAt: nowIso(),
      });
      return this.withContainment(
        result,
        this.containmentOf(runId, outcome.decision, outcome.decision === "commit" ? verdict.rule : outcome.rule, effects),
      );
    }

    if (verdict.decision === "review") {
      // HELD, not discarded. The effect set and the sealed copy are kept so a human can look at the
      // diff and approve or reject it later. Deleting the shadow here, as the first version did,
      // meant the operator this product is named for could never actually approve anything.
      const hash = effectSetHash(effects);
      const held: HeldTurn = {
        runId,
        agentId,
        rule: verdict.rule,
        hits: verdict.hits ?? [{ rule: verdict.rule, decision: "review" }],
        effects,
        effectSetHash: hash,
        workspacePath: request.workspacePath,
        shadowDir,
        mechanism,
        baseline: Object.fromEntries(baseline),
        heldAt: nowIso(),
        taskPrompt: request.prompt,
      };
      await this.store.putHeld(held);
      // The held payloads and the sealed codex-home stay where they are: a review is not a verdict
      // yet. What settle("review") does is tear down the live network and say what is waiting.
      const settledHeld = await this.settleConfinement(runId, "review");
      await this.emit({
        runId,
        agentId,
        kind: "turn.held",
        ...settledHeld,
        rule: verdict.rule,
        hits: held.hits,
        effectSetHash: hash,
        workspacePath: request.workspacePath,
        shadowDir,
        mechanism,
        ...boundedEffects(effects),
        // The claim under the review screen: the proposed changes are parked in the sealed copy and
        // NONE of them is in the workspace yet. It has to be written into this record at the moment
        // the record is written, never patched in later, because attestsHeldTurn re-hashes the whole
        // record at approve time.
        ...(await this.closingWorkspace(request.workspacePath)),
        at: nowIso(),
      });
      // deliberately NOT released: release() happens on approve or reject
      return this.withContainment(result, this.containmentOf(runId, "review", verdict.rule, effects));
    }

    await this.protocol.discard(runId, agentId, shadowDir, mechanism, effects, verdict.rule, request.workspacePath);
    return this.withContainment(result, this.containmentOf(runId, "discard", verdict.rule, effects));
  }

  /** Turns waiting on a human, newest first, read from the runner's own store and not the journal. */
  async pendingReviews(): Promise<HeldTurn[]> {
    const held = await this.store.listHeld();
    return held.sort((left, right) => right.heldAt.localeCompare(left.heldAt));
  }

  /** The same queue, rendered for a human: see `review-view.ts` for what that means and why. */
  async reviewQueue(): Promise<ReviewView[]> {
    return buildReviewViews(await this.pendingReviews());
  }

  /**
   * Applies a held turn's effect set after a human approved it.
   *
   * Six things have to be true before anything is written, and each one is here because an attack
   * showed what happens when it is not: the chain verifies, the ledger still holds the record of
   * THIS turn, the record comes from the runner's own store and points inside the configured roots,
   * the approval names the exact effect set the operator was shown, the bytes still hash to what
   * was captured, and the policy still says yes.
   */
  async approve(runId: string, actor: string, expectedEffectSetHash: string): Promise<SettleResult> {
    // entered synchronously: two settles for one turn must not both see it as pending
    if (this.settling.has(runId)) {
      return { ok: false, code: "settling", detail: "another decision on this turn is already in flight" };
    }
    this.settling.add(runId);
    try {
      await this.ready();
      const refuse = async (code: SettleCode, detail?: string): Promise<SettleResult> => {
        await this.emit({
          runId,
          kind: "settle.refused",
          action: "approve",
          reason: code,
          ...(detail === undefined ? {} : { detail }),
          actor,
          at: nowIso(),
        });
        return { ok: false, code, ...(detail === undefined ? {} : { detail }) };
      };

      const gate = await this.settleGate();
      if (!gate.ok) return this.refuseUnsettleable("approve", runId, actor, gate.detail);
      // Asked on the approve path only, and only here, for the reason in attestsHeldTurn().
      if (!(await this.attestsHeldTurn(runId))) {
        return this.refuseUnsettleable(
          "approve",
          runId,
          actor,
          `the ledger no longer holds the turn.held record for ${runId}, so nothing in it attests the turn being applied`,
        );
      }

      const held = await this.store.getHeld(runId);
      if (!held) return { ok: false, code: "not-pending" };

      const roots = await this.protocol.validPaths(held.shadowDir, held.workspacePath);
      if (!roots.ok) return refuse("invalid-record", roots.reason);

      if (expectedEffectSetHash !== held.effectSetHash) {
        return refuse("hash-mismatch", "the approval names a different set of changes than the held turn");
      }

      const tampered = await this.protocol.tamperedEffects(held.shadowDir, held.mechanism, held.effects);
      if (tampered.length) {
        for (const changed of tampered.slice(0, JOURNAL_EFFECT_LIMIT)) {
          await this.emit({ runId, agentId: held.agentId, kind: "effect.tampered", path: changed, at: nowIso() });
        }
        return refuse("tampered", tampered[0]);
      }

      // Judged again, on the held set, at the moment it would land. A verdict taken hours ago
      // against rules that have since changed is not a decision about what is about to happen.
      let verdict: PolicyVerdict;
      try {
        const context = await buildPolicyContext({
          shadowDir: held.shadowDir,
          mechanism: held.mechanism,
          workspacePath: held.workspacePath,
          journalPath: this.opts.journalPath,
          agentId: held.agentId,
          taskPrompt: held.taskPrompt,
          limits: this.limits,
          platformSecrets: this.opts.platformSecrets ?? [],
          registryAllowlist: this.opts.registryAllowlist ?? DEFAULT_REGISTRY_ALLOWLIST,
          realInodes: (await snapshotStats(held.workspacePath)).inodes,
        });
        verdict = await this.opts.policy(held.effects, context);
      } catch (error) {
        return refuse("policy-refused", error instanceof Error ? error.message : String(error));
      }
      await this.emit({ runId, agentId: held.agentId, kind: "policy.decision", ...verdict, atApproval: true, at: nowIso() });
      const discarding =
        verdict.decision === "discard" || (verdict.hits ?? []).some((hit) => hit.decision === "discard");
      if (discarding) return refuse("policy-refused", verdict.rule);

      // A review can sit for hours, so the ground is even more likely to have moved than for an
      // immediate commit. Approving a stale diff would overwrite whatever happened in between.
      const conflicts = await this.conflictingPaths(
        held.workspacePath,
        new Map(Object.entries(held.baseline)),
        held.effects,
      );
      if (conflicts.length) {
        await this.emit({
          runId,
          agentId: held.agentId,
          kind: "turn.conflicted",
          rule: "workspace-changed-during-review",
          paths: conflicts.slice(0, JOURNAL_EFFECT_LIMIT),
          ...boundedEffects(held.effects),
          actor,
          ...(await this.closingWorkspace(held.workspacePath)),
          at: nowIso(),
        });
        return { ok: false, code: "conflict", detail: conflicts[0] };
      }

      await this.emit({
        runId,
        agentId: held.agentId,
        kind: "turn.approved",
        actor,
        effectSetHash: held.effectSetHash,
        at: nowIso(),
      });
      await this.store.removeHeld(runId);
      const outcome = await this.protocol.commit({
        runId,
        agentId: held.agentId,
        effects: held.effects,
        workspacePath: held.workspacePath,
        shadowDir: held.shadowDir,
        mechanism: held.mechanism,
        baseline: held.baseline,
        startedAt: nowIso(),
        actor,
      });
      if (!outcome.ok) {
        return { ok: false, code: outcome.decision === "conflict" ? "conflict" : "tampered", detail: outcome.rule };
      }
      return { ok: true, code: "ok" };
    } finally {
      this.settling.delete(runId);
      // The settle wrote a restored thread id for a run() call that returned long ago and will
      // never come back for it. Nobody reads it and nothing else deletes it, so without this the
      // map grows by one entry for every turn an operator ever settles.
      this.settledThread.delete(runId);
    }
  }

  /** Drops a held turn's effect set. Nothing reaches the workspace. */
  async reject(runId: string, actor: string): Promise<SettleResult> {
    if (this.settling.has(runId)) {
      return { ok: false, code: "settling", detail: "another decision on this turn is already in flight" };
    }
    this.settling.add(runId);
    try {
      await this.ready();
      const gate = await this.settleGate();
      if (!gate.ok) return this.refuseUnsettleable("reject", runId, actor, gate.detail);
      const held = await this.store.getHeld(runId);
      if (!held) return { ok: false, code: "not-pending" };
      const roots = await this.protocol.validPaths(held.shadowDir, held.workspacePath);
      if (!roots.ok) {
        await this.emit({ runId, kind: "settle.refused", action: "reject", reason: "invalid-record", actor, at: nowIso() });
        return { ok: false, code: "invalid-record", detail: roots.reason };
      }
      // The held network writes are dropped and the sealed codex-home is thrown away, the same as
      // any other non-commit verdict. Until integration wired this, a rejected turn left both
      // sitting on disk and the memory half of the rollback never happened.
      const settledReject = await this.settleConfinement(runId, "discard");
      await this.emit({
        runId,
        agentId: held.agentId,
        kind: "turn.rejected",
        ...settledReject,
        actor,
        effectSetHash: held.effectSetHash,
        ...boundedEffects(held.effects),
        ...(await this.closingWorkspace(held.workspacePath)),
        at: nowIso(),
      });
      await this.store.removeHeld(runId);
      await this.protocol.release(held.shadowDir, held.mechanism);
      return { ok: true, code: "ok" };
    } finally {
      this.settling.delete(runId);
      this.settledThread.delete(runId);
    }
  }

  /**
   * Finishes any commit that was interrupted, from the sealed copy still on disk. Runs at
   * construction and is safe to run again; the protocol itself is in `commit-protocol.ts`.
   */
  async reconcile(): Promise<{ replayed: string[]; unrecoverable: string[] }> {
    return this.protocol.reconcile();
  }

  // ---- helpers -------------------------------------------------------------

  /** The bound this host put on the workspace measurement, or the shipped default. */
  private workspaceDigestOpts(): { maxFiles?: number } {
    return this.opts.workspaceDigestMaxFiles === undefined
      ? {}
      : { maxFiles: this.opts.workspaceDigestMaxFiles };
  }

  /**
   * What the real workspace is at the moment a turn ends here, for a terminal record this file
   * writes rather than one the commit protocol writes.
   *
   * Every ending gets one. The ending that needs it most is the one that carries the least
   * otherwise: a turn whose agent crashed or timed out never reaches capture, so its record names
   * no effects at all. That is exactly the turn where nobody knows what happened, and the only turn
   * where the answer cannot come from the effect set.
   */
  private async closingWorkspace(workspacePath: string): Promise<Record<string, unknown>> {
    return closingWorkspaceFields(workspacePath, this.workspaceDigestOpts());
  }

  private containmentOf(
    runId: string,
    decision: Containment["decision"],
    rule: string,
    effects: EffectRecord[],
  ): Containment {
    const paths = effects.slice(0, JOURNAL_EFFECT_LIMIT).map((effect) => effect.path);
    return {
      runId,
      decision,
      rule,
      effects: effects.length,
      paths,
      ...(effects.length > paths.length ? { pathsTruncated: effects.length - paths.length } : {}),
    };
  }

  /**
   * Everything a turn needs before the agent is allowed to run: the sealed view with its outbound
   * links closed, the opening snapshot, the network and memory jail, and the opening record.
   *
   * It unwinds itself, which is the whole reason it is a method rather than a run of statements.
   * Anything that throws in here used to escape run() with the seal made and the confinement open
   * and neither torn down: one leaked overlay mount, one broker container and one sealed codex home
   * per attempt. The ledger refusing the opening record is the throw that actually happened, and
   * run() now refuses that case before this is reached, so what is left here is the belt: a sealer,
   * a probe, a jail or a checkpoint that fails still leaves nothing running.
   *
   * The one thing it will not do is delete a shadow whose seal threw halfway. A half-made overlay
   * may already be mounted, and `rm -rf` through a mount deletes the lower layer, which is the real
   * workspace. Teardown belongs to whoever made the seal, so when the seal itself failed the
   * directory is left for the sealer's own sweep rather than removed on a guess.
   */
  private async openTurn(input: {
    runId: string;
    agentId: string;
    request: RunnerRequest;
    shadowDir: string;
    merged: string;
  }): Promise<{
    mechanism: "overlay" | "copy";
    confined: { request: RunnerRequest; note: Record<string, unknown> } | undefined;
    opened: Snapshot;
    sealed: Snapshot;
    /** the armed sealed copy, or null under a mechanism this platform does not arm */
    readWitness: ReadWitnessBaseline | null;
  }> {
    const { runId, agentId, request, shadowDir, merged } = input;
    let mechanism: "overlay" | "copy" | null = null;
    let sealAttempted = false;
    let confinementOpened = false;
    try {
      // Asked before anything is copied or snapshotted, so the probe can never be mistaken for
      // something the turn did.
      await probeCaseInsensitive(request.workspacePath);

      sealAttempted = true;
      mechanism = this.opts.seal
        ? await this.opts.seal(request.workspacePath, shadowDir)
        : await this.copyFallback(request.workspacePath, merged);

      // Neutralisation belongs to the SEAL, not to one branch of it.
      //
      // A link resolving outside the workspace is a hole THROUGH the sealed view: the turn writes
      // through it and changes a real file at execution time, before any policy sees an effect. This
      // lived inside copyFallback, so it protected the copy and nothing else. A sealer returning
      // "overlay" skipped it entirely, and the overlay is the path the product now takes on Linux, so
      // the defence was missing exactly where the mechanism is fastest.
      //
      // Here it is unconditional, which makes it the contract rather than a property of one branch:
      // whatever sealed the workspace, no link inside the sealed view points out of it by the time the
      // agent runs. It is idempotent, so the copy path finding nothing on a second walk is the
      // expected cost of having one owner instead of two.
      await this.neutraliseOutboundLinks(request.workspacePath, merged);
      // What the workspace looked like when this turn opened. Stat-only, so it stays cheap on a large
      // repo, and it is what lets the commit step notice that somebody else moved the ground. The
      // inode half is what lets a protected asset stay protected under a different spelling.
      const opened = await snapshotStats(request.workspacePath);
      // And what it IS, by content, which the stat snapshot above deliberately is not.
      //
      // The ordering is the whole reason this value is worth anything. It is taken before the
      // confinement opens and before the inner runner is allowed to execute, and it goes onto
      // `turn.begin`, which is hmac'd, chained, folded into the Merkle leaves and eventually into
      // the signed checkpoint and the external anchor. A before-digest committed to an append-only
      // anchored ledger before the agent runs cannot be back-dated to match whatever the tree
      // turned out to be. One computed at the end, or held in memory and written at the end, can be
      // and would be worth nothing.
      //
      // It is also taken after probeCaseInsensitive. That probe compares inodes under an existing
      // name wherever it can and only falls back to creating and removing a file, in an EMPTY
      // workspace, so the ordering is load-bearing in exactly one case: a fallback probe whose
      // cleanup failed. Ordering it this way costs nothing and covers that case.
      const measuredOpen = await workspaceDigest(request.workspacePath, this.workspaceDigestOpts());
      // Seal the network and the agent's memory, and record what the turn is actually inside. A
      // platform that cannot say which of the three it sealed is a platform whose journal reads the
      // same whether the jail was there or not, so the absence is recorded as loudly as the presence.
      const confined = await this.opts.confinement?.open({
        runId,
        request: { ...request, workspacePath: merged },
        shadowDir,
      });
      confinementOpened = this.opts.confinement !== undefined;
      await this.emit({
        runId,
        agentId,
        kind: "turn.begin",
        mechanism,
        ...(confined?.note ?? { confinement: "none" }),
        ...workspaceDigestFields(measuredOpen, "before"),
        at: nowIso(),
      });
      // A read is not an effect, and a turn that opens every credential in the sealed view and
      // writes nothing therefore hands the policy an empty set: every rule abstains over nothing
      // and the turn commits under rule `none`. The witness is what makes that turn visible. It
      // records, on the trusted side, which files in the sealed copy were opened. It decides
      // nothing: no rule reads it, and the corpus replay behind read-witness-wiring.test.ts is the
      // evidence that no verdict moved when it was wired.
      //
      // The arm is TWO passes with the sealed snapshot BETWEEN them, and that ordering is the whole
      // mechanism.
      //
      // Pass one goes first because it WRITES. It sets every file in the copy to a modification
      // time the platform stores exactly, which it is free to do because nothing has recorded a
      // signature yet. The snapshot on the next line then records those times, so there is no shift
      // between the seal and the copy and nothing to reconcile afterwards. This is what replaced
      // reconcileSealedSignatures: the old order snapshotted first and patched the seal afterwards
      // with whatever the arm had left behind, which was a value `new Date()` could not reproduce
      // about half the time, so an identical turn committed or discarded depending on which
      // millisecond its files happened to be written in.
      //
      // Pass two goes last because the snapshot READS. It hashes every regular file, and a hash is
      // a read, so it spends every access time pass one set. Re-arming here, after the hashing and
      // immediately before the agent starts, makes the window the witness measures exactly the
      // turn. It moves no modification time, so the signatures the snapshot just took still stand.
      //
      // Under the overlay mechanism there is no witness at all rather than an empty one. There the
      // sealed view reads an unmodified file through the lower layer, which is the user's real
      // repository, so arming it would write access times into the user's own tree on every turn.
      // That is a different decision with a real cost and this is not the place it gets taken; the
      // journal records the absence as loudly as it records the presence.
      let readWitness =
        mechanism === "copy"
          ? await armReadWitness(merged, { probeDir: shadowDir }).catch(() =>
              // An observation that failed must not fail a turn, and must not report as an absent
              // mechanism either. It gets its own reason and quotes no read count.
              failedReadWitness(merged, "arm-failed"),
            )
          : null;
      const sealed =
        mechanism === "copy"
          ? await snapshotStats(merged, { hash: true, maxHashBytes: this.limits.maxEffectBytes })
          : emptySnapshot();
      if (readWitness !== null) {
        // A second pass that throws leaves every access time spent by the hashing above, so the
        // witness would report the platform's own reads as the turn's. That is worse than no
        // witness, and it is reported as its own failure rather than as a turn that read the tree.
        readWitness = await rearmReadWitness(readWitness)
          .then(() => readWitness)
          .catch(() => failedReadWitness(merged, "rearm-failed"));
      }
      return { mechanism, confined, opened, sealed, readWitness };
    } catch (error) {
      if (confinementOpened) {
        // best effort: the turn is already failing, and a settle that also throws must not replace
        // the reason the caller is about to be given
        await this.settleConfinement(runId, "discard").catch(() => undefined);
      }
      if (mechanism) await this.protocol.release(shadowDir, mechanism).catch(() => undefined);
      else if (!sealAttempted) await fs.rm(shadowDir, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }
  }

  private async copyFallback(real: string, merged: string): Promise<"copy"> {
    await execFileAsync("cp", ["-a", real + "/.", merged]);
    // Neutralisation used to live here. It happens for every mechanism at the seal site now, so the
    // property has one owner and cannot drift between the two branches.
    return "copy";
  }

  /**
   * A copy is not a jail. `cp -a` reproduces symlinks faithfully, so a link that resolves outside
   * the workspace is a live hole THROUGH the sealed view: the turn writes through it and changes a
   * real file at execution time, before any policy sees an effect. Capture-time and commit-time
   * rules cannot close that, because the write already happened.
   *
   * So the seal itself has to remove the hole. Every link in the copy is resolved: one that stays
   * inside the workspace is kept (a monorepo depends on those), and one that escapes is replaced by
   * a regular file holding a snapshot of the target's bytes. The turn can still read what it could
   * read before; anything it writes lands in the shadow and is judged like every other effect.
   */
  private async neutraliseOutboundLinks(real: string, merged: string): Promise<void> {
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
          if (within(real, resolvedInReal)) continue; // in-workspace link: harmless, keep it
          const body = await fs.readFile(resolvedInReal).catch(() => Buffer.alloc(0));
          await fs.rm(full, { force: true });
          await fs.writeFile(full, body);
          this.neutralised.add(rel);
          continue;
        }
        if (e.isDirectory()) await walk(full, rel);
      }
    };
    await walk(merged, "");
  }

  /**
   * Attaches the boundary's verdict to what the runner returns. Without it the caller reads the
   * agent's own "I completed the task and updated the files" on a turn that was discarded, held or
   * conflicted, which is the worst possible thing for a product about knowing what really happened.
   */
  private withContainment(result: RunnerResult, containment: Containment): RunnerResult {
    const suffix =
      containment.decision === "commit"
        ? ""
        : containment.decision === "review"
          ? `\n\n[held for review: ${containment.rule}. ${containment.effects} proposed change(s) are waiting for a human. Nothing has been applied.]`
          : containment.decision === "conflict"
            ? `\n\n[not applied: the workspace changed while this turn was running. Nothing has been applied.]`
            : containment.rule === "cancelled-by-operator"
              ? `\n\n[stopped by the operator. ${containment.effects} change(s) were discarded and nothing was applied.]`
              : `\n\n[blocked by policy: ${containment.rule}. ${containment.effects} change(s) were discarded and nothing was applied.]`;
    const restored = this.settledThread.get(containment.runId);
    this.settledThread.delete(containment.runId);
    const threadId = restored === undefined ? result.threadId : restored;
    return { ...result, threadId, output: result.output + suffix, containment };
  }

  /**
   * Settles the confinement once for a turn and keeps the thread id it restored.
   *
   * Returns the fields the terminal journal record should carry. When no confinement is wired this
   * is an empty object and nothing downstream can tell the difference, which is the point: the
   * decorator has to work on a host that sealed nothing.
   */
  private async settleConfinement(
    runId: string,
    decision: "commit" | "discard" | "review" | "conflict",
  ): Promise<Record<string, unknown>> {
    if (!this.opts.confinement) return {};
    const settled = await this.opts.confinement.settle(runId, decision);
    if (settled && "threadId" in settled) this.settledThread.set(runId, settled.threadId ?? null);
    return settled?.note ?? {};
  }

  /**
   * Whether a held turn may be settled against the ledger as it stands right now.
   *
   * What an acknowledgement means, decided here because the two halves of the product disagreed.
   *
   * `acknowledge()` deliberately never repairs anything: the break stays in the main chain forever
   * and the verifier keeps reporting it, which is the property that makes the ledger worth having.
   * So a settle path that re-verified all of history refused forever. Turns ran, because run() only
   * needs an appendable ledger, and nothing could ever be approved or rejected again: one forged
   * line permanently bricked settlement, and the review queue filled up with turns no operator
   * could clear.
   *
   * An acknowledgement means an operator, by name, took responsibility for THAT break, so it stops
   * blocking settlement. It does not mean verification stopped mattering, and it is a statement
   * about ONE ledger rather than about a kind of problem. Both halves are checked here.
   *
   * Asking only "is every problem the chain reports now one the operator already owns" is what the
   * first version of this gate did, and a subset passes that question. Truncating the file back to
   * the acknowledged break reports the acknowledged problems, byte for byte, because the records
   * that would have said otherwise are the records that were deleted. So the acknowledgement could
   * be spent on erasing the acknowledgement itself, along with the operator's journal.reopened
   * record and every record of the turn being settled.
   *
   * Verification cannot close that on its own, and no wording of the problem check can either. A
   * chain walk describes the records a file HOLDS, and a prefix of a hash chain is a hash chain, so
   * a record that is gone leaves nothing behind to report. Erasure is therefore answered by the two
   * things that remember what was here: the prefix the operator signed for, pinned when they signed
   * it, and the head this runner last wrote or adopted, which must still be in the file. It is the
   * same question the anchor layer already asks of an external witness (journal-verify.ts, "the
   * last anchored head is not in this journal"), asked of the writer's own memory.
   */
  private async settleGate(): Promise<{ ok: true } | { ok: false; detail: string }> {
    const status = await this.journalStatus();
    // The head is read BEFORE the file. An ordinary turn appending between the two reads only makes
    // the file longer, and a witness in a longer file is still findable; reading the file first
    // would let a concurrent turn look like an erasure and refuse an honest settle.
    const witness = status.head;
    const chain = await TransactionalRunner.verifyChain(this.opts.journalPath);
    const lines = await this.ledgerLines();

    const erased = this.erasure(witness, lines);
    if (erased !== null) return { ok: false, detail: erased };

    if (chain.ok) return { ok: true };
    const first = chain.problems[0] ?? "the journal did not verify";
    if (status.state !== "acknowledged") return { ok: false, detail: first };
    // Problem messages name the record they belong to, so they are unique per break; that is what
    // lets a set answer "is this one the operator already owns".
    const acknowledged = new Set(status.problems);
    const unowned = chain.problems.find((problem) => !acknowledged.has(problem));
    if (unowned !== undefined) return { ok: false, detail: unowned };
    return { ok: true };
  }

  /**
   * Which records were here and are not any more, named, or null when none are.
   *
   * Two questions, because the acknowledgement pins a prefix and turns keep running after it. The
   * pinned prefix answers for everything up to the signature, including the operator's own
   * acknowledgement record and the broken record itself, whose content is then also fixed rather
   * than merely its problem message. The head answers for everything appended since, where cutting
   * the tail is invisible to every other check in this file.
   */
  private erasure(witness: string, lines: string[]): string | null {
    const pinned = this.acknowledgedLedger;
    if (pinned) {
      if (lines.length < pinned.records) {
        return `the ledger holds ${lines.length} of the ${pinned.records} records the operator acknowledged, so records have been removed since`;
      }
      if (TransactionalRunner.ledgerDigest(lines.slice(0, pinned.records)) !== pinned.digest) {
        return "a record the operator acknowledged is no longer the record they acknowledged";
      }
    }
    if (witness === ZERO_HEAD) return null;   // nothing written and nothing adopted, so nothing lost
    for (const line of lines) {
      let record: Record<string, unknown>;
      try {
        record = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;                             // not a record, so not the record we wrote
      }
      if (record.hash !== witness) continue;
      // The hash field is a claim, not a proof: whoever cut the tail off can write a line that
      // names the head they removed. The line has to hash to it, which is the same computation the
      // verifier runs, and it is what makes this check stand up on its own rather than lean on the
      // problem list below.
      const { hash: _claimed, ...body } = record;
      if (sha256Hex(canonicalJson(body)) === witness) return null;
    }
    return `the ledger no longer holds the record this runner last wrote (${witness.slice(0, 12)}), so its tail was cut`;
  }

  /**
   * Whether the ledger still holds the record that says this turn was held.
   *
   * The two witnesses in `erasure()` both live in this process: the prefix pinned when the operator
   * acknowledged, and the head this runner last wrote. A held turn does not. It is written to the
   * store on disk and it is still waiting there after a restart, so erasing its records and then
   * waiting for one faces neither witness, and what is left verifies clean because a prefix of a
   * hash chain is a hash chain. The measured result was an approve returning ok on a turn the
   * ledger no longer mentioned, with the turn's bytes in the real workspace.
   *
   * The external anchor is the designed answer and it does catch this, but its local stand-in is a
   * file beside the ledger, so the hand that rewrote one rewrites the other and the check the
   * settle leans on evaporates. This asks the same question of something already in hand instead.
   * It is not a new trust boundary: approve() already reads this turn from the store and applies
   * the bytes the store names, so whoever can rewrite the store never needed the ledger at all.
   * All that is added is the requirement that the ledger STILL SAY the turn happened.
   *
   * The self-hash makes this look for a record rather than for a mention, so a bare line naming the
   * run does not answer for the record that went. What makes forging a real one hard is the keyed
   * hmac, which this cannot check without the key: the chain walk in settleGate() enforces that,
   * and it runs first. Erasure is this check's job, forgery is that one's.
   *
   * Approve only. A reject writes nothing anywhere and is the operator's way to clear a queue, and
   * settlement that can never complete is the defect round one existed to fix, so a turn whose
   * record was erased can still be dropped. It just cannot be applied.
   */
  private async attestsHeldTurn(runId: string): Promise<boolean> {
    for (const line of await this.ledgerLines()) {
      let record: Record<string, unknown>;
      try {
        record = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;
      }
      if (record.kind !== "turn.held" || record.runId !== runId) continue;
      const { hash, ...body } = record;
      if (typeof hash === "string" && sha256Hex(canonicalJson(body)) === hash) return true;
    }
    return false;
  }

  /** The ledger as lines, because what is missing from a file is not visible to a chain walk. */
  private async ledgerLines(): Promise<string[]> {
    const text = await fs.readFile(this.opts.journalPath, "utf8").catch(() => "");
    return text.split("\n").filter((line) => line.trim() !== "");
  }

  /** Bytes, not fields: a record whose content changed at all is a different record. */
  private static ledgerDigest(lines: string[]): string {
    const digest = crypto.createHash("sha256");
    for (const line of lines) digest.update(line).update("\n");
    return digest.digest("hex");
  }

  /**
   * The one refusal that cannot rely on the ledger, because the ledger is what is broken.
   *
   * The record is still attempted, since an acknowledged journal accepts it and that is the case an
   * operator most needs to see. A compromised one throws instead, and that throw is swallowed here
   * and nowhere else: it carries no information the caller is not already being given, the sidecar
   * already holds the compromise record, and letting it escape turned an honest "no" into a crash
   * on the operator's approve button.
   */
  private async refuseUnsettleable(
    action: "approve" | "reject",
    runId: string,
    actor: string,
    detail: string,
  ): Promise<SettleResult> {
    await this.emit({
      runId,
      kind: "settle.refused",
      action,
      reason: "chain-broken",
      detail,
      actor,
      at: nowIso(),
    }).catch((error: unknown) => {
      if (!(error instanceof JournalCompromisedError)) throw error;
    });
    return { ok: false, code: "chain-broken", detail };
  }

  /**
   * Walks the chain and reports every place it breaks, in order. A hash chain nobody verifies is a
   * claim rather than a feature. This now checks more than the plain chain: the keyed hmac on every
   * record, sequence continuity, the Ed25519 signature on every checkpoint against the published
   * key, each checkpoint's Merkle root against the records it covers, and whether the last anchored
   * head is still present. The messages keep their old wording so existing readers still parse them.
   */
  static async verifyChain(journalPath: string): Promise<{ ok: boolean; records: number; problems: string[] }> {
    const report = await verifyJournalAt(journalPath);
    return { ok: report.ok, records: report.records, problems: report.problems.map((p) => p.message) };
  }

  /** the paths this turn wants to touch that somebody else changed while it was running */
  private async conflictingPaths(
    real: string,
    baseline: Map<string, string>,
    effects: EffectRecord[],
  ): Promise<string[]> {
    const conflicts: string[] = [];
    for (const e of effects) {
      if (e.kind === "outbound") continue;   // not a path, so nothing on disk can conflict with it
      const now = await liveSignature(path.join(real, e.path));
      const then = baseline.get(e.path) ?? null;
      if (now !== then) conflicts.push(e.path);
    }
    return conflicts;
  }

  /**
   * Picks the chain back up from what is already on disk, and refuses to pick up a chain that does
   * not verify. The old version adopted the last line that merely parsed, so a well-formed forged
   * tail was silently believed and every later record chained onto the forgery (a46). Journal.open()
   * verifies from record one, compares the last external anchor, and on any break enters compromised
   * mode instead of adopting a head.
   */
  private async restoreChain(): Promise<void> {
    await this.journal.open();
  }

  /**
   * One line in the ledger. Everything that made this hard (serialising concurrent turns, surviving
   * a torn tail, keeping sequence numbers unique across a restart) now lives in Journal, along with
   * the parts that were missing: the keyed hmac, the principal, the periodic signed checkpoint and
   * the external anchor.
   *
   * It throws while the journal is compromised, which is what makes run() refuse turns: the first
   * thing a turn does is journal turn.begin, and it does that before the inner runner is called, so
   * a turn that cannot be recorded never executes (a46, a47).
   */
  private async emit(fields: Record<string, unknown>): Promise<void> {
    await this.restoreChain();
    await this.journal.append(fields);
  }

  /**
   * Throws when the ledger may not be extended. emit() already refuses, so a turn is never executed
   * unrecorded, but calling this as the first line of run() refuses before any shadow copy is made.
   */
  async assertJournalUsable(): Promise<void> {
    await this.journal.open();
    this.journal.assertUsable();
  }

  /** what the boundary can say about its own ledger, for the operator surface and the verifier */
  async journalStatus(): Promise<ReturnType<Journal["status"]>> {
    await this.journal.open().catch(() => undefined);
    return this.journal.status();
  }

  /**
   * An operator, by name, takes responsibility for a break so the platform can serve again. Nothing
   * is erased: the break stays in the chain and the verifier keeps reporting it.
   */
  async acknowledgeJournal(actor: string): Promise<boolean> {
    const acknowledged = await this.journal.acknowledge(actor);
    // Captured here and nowhere else, because this is the instant the operator's name refers to.
    // acknowledge() has already appended the journal.reopened record by the time it returns, so
    // the pinned prefix includes the acknowledgement itself and deleting it is a new break.
    if (acknowledged) {
      const lines = await this.ledgerLines();
      this.acknowledgedLedger = { records: lines.length, digest: TransactionalRunner.ledgerDigest(lines) };
    }
    return acknowledged;
  }

  /** Signs a checkpoint now, rather than waiting for the interval. Used at shutdown and in demos. */
  async checkpointJournal(reason = "manual"): Promise<CheckpointInfo | null> {
    return this.journal.checkpoint(reason);
  }

  /** Final checkpoint, drains anchoring, releases the lock. Safe to call more than once. */
  async closeJournal(): Promise<void> {
    await this.journal.close();
  }
}

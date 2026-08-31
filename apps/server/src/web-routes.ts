import fs from "node:fs/promises";
import path from "node:path";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import type { EffectKind, EffectRecord, RuleHit } from "./policy-types.js";
import { TransactionalRunner } from "./transactional-runner.js";
import { classifyPath, type ChangeClass } from "./change-class.js";

// Re-exported so the panel's own surface stays one import for its callers and its tests.
export { classifyPath };
export type { ChangeClass };

/**
 * The routes the browser panel needs, kept in their own module so the panel can be built and
 * tested without touching the runner, the policy or the review routes another lane owns.
 *
 * One surface lives here: `/api/agents/:id/journal`, the run timeline. It reads the hash-chained
 * journal and returns one entry per turn with the verdict the boundary recorded.
 *
 * The panel's review queue used to live here too, behind a temporary `/api/web/reviews` prefix,
 * because the two lanes were built in parallel. It does not any more. The queue is served by the
 * hardened `/api/reviews` routes: those verify the chain before they settle anything, re-run the
 * policy at approve time, bind the approval to the hash of the exact set the operator was shown,
 * and take the actor from the presented credential rather than a header the caller types. Two
 * routes to the same decision would have meant the weaker one was the one an attacker used.
 *
 * The timeline never carries a body. Only paths, kinds, classes and byte counts leave this module,
 * whitelisted field by field, because a history surface has no reason to render file contents and
 * a journal record is written by code that changes more often than this reader does.
 */

/** how many effect rows one timeline entry carries */
const EFFECTS_PER_TURN = 100;
const DEFAULT_TURNS = 50;
const MAX_TURNS = 200;
/** chain problems reported to the browser; the full list stays server side */
const MAX_CHAIN_PROBLEMS = 5;




export type TurnVerdict =
  | "committed"
  | "discarded"
  | "held"
  | "approved"
  | "rejected"
  | "conflicted"
  | "restored"
  /** the commit point was passed and no record survives to finish it: the workspace may be partly written */
  | "unrecoverable"
  | "running";

export interface TimelineEffect {
  path: string;
  kind: EffectKind;
  class: ChangeClass;
  bytes: number;
  target?: string;
  escapes?: boolean;
}

export interface TimelineTurn {
  runId: string;
  agentId: string;
  verdict: TurnVerdict;
  /** the rule behind a discard, a hold or a conflict; null when nothing decided against the turn */
  rule: string | null;
  /** who approved or rejected it */
  principal: string | null;
  seq: number;
  at: string | null;
  mechanism: string | null;
  effectCount: number;
  truncated: number;
  effects: TimelineEffect[];
  /** the paths a conflict named, whether it was found before the commit or under one of its writes */
  conflictPaths: string[];
  /** on a conflict that hit mid-apply, the files that were already written before it stopped */
  appliedPaths: string[];
  /**
   * The server's own measurement of the REAL workspace, sha256 over the tree, taken at turn open
   * and again at the moment the turn ended. Null when the record carries no digest: a turn from
   * before this was recorded, or a tree the walk refused, in which case `workspaceDigestReason`
   * says which. Never a value this module invents.
   */
  workspaceDigestBefore: string | null;
  workspaceDigestAfter: string | null;
  workspaceDigestReason: string | null;
  workspaceFilesBefore: number | null;
  workspaceFilesAfter: number | null;
  /**
   * How many of those entries the walk could not read at all. A digest over a tree with an
   * unreadable subtree in it is a partial measurement wearing the same 64 hex as a whole one, so
   * the count has to travel with it or the panel prints an unqualified byte-for-byte claim over a
   * region nothing opened.
   */
  workspaceUnreadableBefore: number | null;
  workspaceUnreadableAfter: number | null;
  /**
   * The OTHER bounded control, projected from the same records the filesystem half is read from.
   *
   * Track C asks for two controls and the journal has always carried both, but only the filesystem
   * half ever reached a screen: `turn.begin` records what the turn ran inside, and the record the
   * turn settled on records what the broker decided and what happened to the agent's memory. None
   * of it was read here, so a person could learn the network half existed only by being told.
   *
   * Every field is optional and every absence is projected as an absence, because
   * `confinement: "none"` is a REAL value: the Compose and ECS profiles run the host-process
   * runtime under SHADOW_ALLOW_UNCONFINED=1, and `transactional-runner.ts` writes
   * `...(confined?.note ?? { confinement: "none" })` onto every `turn.begin`. A missing field and
   * that word must never arrive at the panel as the same thing, so `beginRecorded` separates a turn
   * with no opening record from a turn whose opening record predates these fields, and both from a
   * turn that was journaled as not contained at all.
   */
  beginRecorded?: boolean;
  /** the mode word the record carries: "container+sealed-network", "container", or "none" */
  confinement?: string | null;
  /** the note's own reason, which the unconfined path writes and the container path does not */
  confinementReason?: string | null;
  /** the per-run network name, null under a container whose network was not sealed */
  network?: string | null;
  /** how many destinations the broker would allow; 0 is a real allowlist, null is no record of one */
  egressAllowlistSize?: number | null;
  /** "terminated-at-broker", or "direct" when the model channel was not terminated */
  modelChannel?: string | null;
  codexHomeFiles?: number | null;
  /** one count per broker decision kind, off the record the turn settled on */
  egress?: Record<string, number> | null;
  outboundDropped?: number | null;
  /**
   * DISJOINT counts, not a set and a subset: the sealer increments exactly one of the two per held
   * payload, so the number attempted is their sum.
   */
  outboundReplayed?: number | null;
  outboundFailed?: number | null;
  outboundHeldForReview?: number | null;
  /** the agent's memory: whether the rollback had to run, and whether it was verified unmoved */
  codexHomeRestored?: boolean | null;
  codexHomeVerifiedUnchanged?: boolean | null;
  /**
   * True marks the two fields above as bookkeeping rather than measurement: a rejected review
   * journals `{ restored: false, verifiedUnchanged: true, droppedAfterReview: true }` as a literal,
   * because the rollback already ran at the earlier review settle and this settle only drops the
   * sealed copy.
   */
  codexHomeDroppedAfterReview?: boolean | null;
  /** on a commit the memory is promoted instead of restored, and this is that diff's own count */
  codexHomeChanged?: number | null;
  /** a per-run network the settle could not remove, which outlives the turn that made it */
  networkLeaked?: string | null;
  /** the settle found no network or memory state for this run, so only the files half of it ran */
  confinementStateLost?: boolean;
  records: Array<{ seq: number; kind: string; hash: string }>;
}

export interface JournalResponse {
  agentId: string;
  turns: TimelineTurn[];
  /** turns that exist in the journal beyond the requested bound */
  more: number;
  chain: { ok: boolean; records: number; problems: string[] };
}

interface JournalLine {
  seq: number;
  runId?: string;
  agentId?: string;
  kind?: string;
  hash?: string;
  [k: string]: unknown;
}









function parseJournal(text: string): JournalLine[] {
  const out: JournalLine[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as JournalLine);
    } catch {
      /* a torn line from a crash mid-append: skipped, never fatal for a read-only view */
    }
  }
  return out;
}

/** run id -> every rule that fired on that turn, read from its `policy.decision` record */
async function hitsFromJournal(journalPath: string): Promise<Map<string, RuleHit[]>> {
  const text = await fs.readFile(journalPath, "utf8").catch(() => "");
  const out = new Map<string, RuleHit[]>();
  for (const line of parseJournal(text)) {
    if (line.kind !== "policy.decision" || typeof line.runId !== "string") continue;
    if (Array.isArray(line.hits)) out.set(line.runId, line.hits as RuleHit[]);
  }
  return out;
}

/**
 * What each record means about where the turn ENDED, read newest first.
 *
 * `turn.approved` and `turn.committing` are decisions, not outcomes: the commit protocol re-checks
 * the bytes and the ground under every individual write after both of them, so either can still be
 * followed by `turn.discarded` or `turn.conflicted`. They are listed here so they shadow the
 * `turn.held` that precedes them, and they resolve to "running" because at that point the journal
 * carries no record of anything having landed.
 */
const SETTLING: Record<string, TurnVerdict> = {
  "turn.committed": "committed",
  "turn.discarded": "discarded",
  "turn.held": "held",
  "turn.approved": "running",
  "turn.committing": "running",
  "turn.rejected": "rejected",
  "turn.conflicted": "conflicted",
  "turn.restored": "restored",
  "commit.unrecoverable": "unrecoverable",
};

function timelineEffects(records: JournalLine[]): { effects: TimelineEffect[]; count: number; truncated: number } {
  // A record's effect list is bounded: `boundedEffects` (commit-protocol.ts) names at most
  // JOURNAL_EFFECT_LIMIT paths and puts the remainder in `effectsTruncated`. The list length is
  // therefore a bound, never a count, and `effects.captured` carries what the turn really did.
  // Reading the list length as the count reported a turn that changed thousands of files as a turn
  // that changed 200, which is the audit surface under-stating the blast radius of a change.
  const carrier = [...records].reverse().find((r) => Array.isArray(r.effects));
  const captured = [...records].reverse().find((r) => r.kind === "effects.captured");
  const all = carrier ? (carrier.effects as EffectRecord[]) : [];
  const shown = all.slice(0, EFFECTS_PER_TURN);
  const droppedFromRecord = typeof carrier?.effectsTruncated === "number" ? carrier.effectsTruncated : 0;
  const capturedCount = typeof captured?.count === "number" ? captured.count : 0;
  // The larger of the two, so neither a bounded list nor a missing `effects.captured` can make the
  // panel report fewer changes than a record already accounts for.
  const count = Math.max(all.length + droppedFromRecord, capturedCount);
  return {
    effects: shown.map((e) => ({
      path: String(e.path),
      kind: e.kind,
      class: classifyPath(String(e.path), e.effectClass),
      bytes: typeof e.bytes === "number" ? e.bytes : 0,
      ...(e.target === undefined ? {} : { target: e.target }),
      ...(e.escapes === undefined ? {} : { escapes: e.escapes }),
    })),
    count,
    truncated: Math.max(0, count - shown.length),
  };
}

/**
 * A digest field, or null.
 *
 * A journal line is untyped, and the boundary writes the sentinel `"not-measured"` into the same
 * field when a walk refused, so this is the whitelist that keeps a non-digest out of a place the
 * panel prints digests. Anything that is not 64 lowercase hex is not a digest.
 */
function digestOf(value: unknown): string | null {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value) ? value : null;
}

const numberOf = (value: unknown): number | null => (typeof value === "number" ? value : null);

const stringOf = (value: unknown): string | null => (typeof value === "string" ? value : null);
const boolOf = (value: unknown): boolean | null => (typeof value === "boolean" ? value : null);

/** how many broker decision kinds one turn may report; the broker writes four and this is the belt */
const MAX_DECISION_KINDS = 12;

/**
 * The broker's decision counts, or null.
 *
 * `summariseDecisions` (broker.ts) writes one lowercase key per decision kind with a count under
 * it, so the shape is open: a kind added to the broker appears here without this reader changing.
 * What is closed is the VALUE. Anything that is not a finite number is dropped rather than printed,
 * and a record whose keys all fail that is reported as no summary at all rather than as a broker
 * that decided nothing, because those two are opposite claims.
 */
function decisionCountsOf(value: unknown): Record<string, number> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const entries = Object.entries(value as Record<string, unknown>);
  const out: Record<string, number> = {};
  for (const [kind, count] of entries.slice(0, MAX_DECISION_KINDS)) {
    if (typeof count === "number" && Number.isFinite(count)) out[kind] = count;
  }
  if (entries.length > 0 && Object.keys(out).length === 0) return null;
  return out;
}

/**
 * How many destinations the allowlist named.
 *
 * The list itself is not projected. A count is what a person reads in one line, and the panel has
 * no reason to render a host list it would only truncate. Null is the absence of a list; zero is a
 * list that allows nothing, and the two do not render alike.
 */
const allowlistSizeOf = (value: unknown): number | null => (Array.isArray(value) ? value.length : null);

/** The nested `codexHome` note, when the settling record carries one in either of its two shapes. */
function codexHomeOf(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** The paths a `turn.conflicted` record names, in either of the two shapes the boundary writes. */
function conflictPathsOf(conflict: JournalLine | undefined): string[] {
  if (Array.isArray(conflict?.paths)) return (conflict.paths as unknown[]).slice(0, 50).map(String);
  if (typeof conflict?.path === "string") return [conflict.path];
  return [];
}

/**
 * One ordered list of turns, newest first, each with the verdict the boundary recorded rather than
 * the sentence the agent wrote about itself.
 *
 * Records written after a hold settles (`turn.approved`, `turn.rejected`) carry no agent id, so the
 * run id is resolved to its agent from whichever record of the same turn does carry one.
 */
export function buildTimeline(lines: JournalLine[], agentId: string, limit: number): { turns: TimelineTurn[]; more: number } {
  const agentOf = new Map<string, string>();
  for (const line of lines) {
    if (typeof line.runId === "string" && typeof line.agentId === "string") agentOf.set(line.runId, line.agentId);
  }
  const byRun = new Map<string, JournalLine[]>();
  for (const line of lines) {
    if (typeof line.runId !== "string") continue;
    if (agentOf.get(line.runId) !== agentId) continue;
    const bucket = byRun.get(line.runId);
    if (bucket) bucket.push(line);
    else byRun.set(line.runId, [line]);
  }

  const turns: TimelineTurn[] = [];
  for (const [runId, records] of byRun) {
    const ordered = [...records].sort((a, b) => a.seq - b.seq);
    // The verdict is the record the turn ENDED on, never the first decision taken about it.
    //
    // Approving appends `turn.approved` and then runs the ordinary commit, which re-hashes the
    // bytes and re-checks the ground under every individual write. An approval can therefore be
    // followed by `turn.discarded` or `turn.conflicted`, and reading the approval as the verdict
    // reported a turn that was stopped as "Committed, approved by operator". An audit surface
    // saying something that did not happen is worse than one that shows nothing.
    //
    // The operator's name is a separate fact and is kept whatever the outcome: `principal` below
    // is read from whichever record carries an actor, so a discarded approval still names who
    // approved it.
    const settling = [...ordered].reverse().find((r) => typeof r.kind === "string" && r.kind in SETTLING);
    const settledVerdict: TurnVerdict = settling ? SETTLING[settling.kind as string]! : "running";
    // "approved" is the commit that a human asked for, so it needs BOTH records: the approval, and
    // the `turn.committed` that says the commit it authorised actually finished.
    const approvedByHuman = ordered.some((r) => r.kind === "turn.approved");
    const verdict: TurnVerdict = settledVerdict === "committed" && approvedByHuman ? "approved" : settledVerdict;
    const ruleRecord = [...ordered].reverse().find((r) => typeof r.rule === "string");
    const principalRecord = [...ordered].reverse().find((r) => typeof r.actor === "string");
    const begin = ordered.find((r) => r.kind === "turn.begin");
    const conflict = [...ordered].reverse().find((r) => r.kind === "turn.conflicted");
    // The before value comes from `turn.begin` and nowhere else, because that is the record that
    // was chained before the agent was allowed to execute. The after value comes from the last
    // record that carries one, which is the terminal record of the turn. A running turn has a
    // before and no after, and reads as exactly that.
    const closing = [...ordered].reverse().find((r) => r.workspaceDigestAfter !== undefined);
    const codexHome = codexHomeOf(settling?.codexHome);
    const { effects, count, truncated } = timelineEffects(ordered);
    const last = ordered[ordered.length - 1]!;
    turns.push({
      runId,
      agentId,
      verdict,
      rule: verdict === "committed" || verdict === "approved" ? null : ((ruleRecord?.rule as string) ?? null),
      principal: (principalRecord?.actor as string) ?? null,
      seq: last.seq,
      at: typeof last.at === "string" ? last.at : typeof last.ts === "string" ? last.ts : null,
      mechanism: typeof begin?.mechanism === "string" ? begin.mechanism : null,
      effectCount: count,
      truncated,
      effects,
      // Two shapes, because there are two moments a conflict is found. Before the commit the
      // runner names every stale path in `paths`; under one of the commit's own writes the
      // protocol stops at the first and names it in `path`, singular, alongside the files that had
      // already been written. Reading only the plural left the mid-apply conflict with no paths at
      // all, on the one conflict where something did land in the real workspace.
      conflictPaths: conflictPathsOf(conflict),
      appliedPaths: Array.isArray(conflict?.applied) ? (conflict.applied as string[]).slice(0, 50).map(String) : [],
      workspaceDigestBefore: digestOf(begin?.workspaceDigestBefore),
      workspaceDigestAfter: digestOf(closing?.workspaceDigestAfter),
      // The reason belongs to whichever measurement is missing, so the closing record's reason wins
      // and the opening one answers for a turn that has not ended yet.
      workspaceDigestReason:
        typeof closing?.workspaceDigestReason === "string"
          ? closing.workspaceDigestReason
          : typeof begin?.workspaceDigestReason === "string"
            ? begin.workspaceDigestReason
            : null,
      workspaceFilesBefore: numberOf(begin?.workspaceFilesBefore),
      workspaceFilesAfter: numberOf(closing?.workspaceFilesAfter),
      workspaceUnreadableBefore: numberOf(begin?.workspaceUnreadableBefore),
      workspaceUnreadableAfter: numberOf(closing?.workspaceUnreadableAfter),
      // The network half. The opening record says what the turn ran inside, and it is the record
      // chained before the agent was allowed to execute, so `confinement` and the four fields under
      // it are read from `begin` and from NOWHERE ELSE. Falling back to the settling record for any
      // of them would source the panel's containment claim from a record written after the agent
      // ran, which is the one record an agent that got out could have influenced. There is a test
      // that plants a confinement on the settle and requires this to stay null. What the broker decided and what happened to the agent's memory are settle
      // facts, so they are read from the record the turn ENDED on, the same one the verdict and
      // the closing digest come from. A running turn therefore has a confinement and no egress
      // summary, and reads as exactly that.
      beginRecorded: begin !== undefined,
      confinement: stringOf(begin?.confinement),
      confinementReason: stringOf(begin?.reason),
      network: stringOf(begin?.network),
      egressAllowlistSize: allowlistSizeOf(begin?.egressAllowlist),
      modelChannel: stringOf(begin?.modelChannel),
      codexHomeFiles: numberOf(begin?.codexHomeFiles),
      egress: decisionCountsOf(settling?.egress),
      outboundDropped: numberOf(settling?.outboundDropped),
      outboundReplayed: numberOf(settling?.outboundReplayed),
      outboundFailed: numberOf(settling?.outboundFailed),
      outboundHeldForReview: numberOf(settling?.outboundHeldForReview),
      codexHomeRestored: boolOf(codexHome?.restored),
      codexHomeVerifiedUnchanged: boolOf(codexHome?.verifiedUnchanged),
      // The field that says the two above are bookkeeping rather than evidence. `settleReviewed`
      // in runner-factory.ts writes `{ restored: false, verifiedUnchanged: true,
      // droppedAfterReview: true }` as a LITERAL on a rejected review, because the memory was
      // already rolled back at the earlier review settle and this settle only drops the sealed
      // copy. Projecting its two neighbours and stepping over it made a rejected review render
      // identically to a turn that was genuinely measured unchanged.
      codexHomeDroppedAfterReview: boolOf(codexHome?.droppedAfterReview),
      codexHomeChanged: numberOf(codexHome?.changed),
      networkLeaked: stringOf(settling?.networkLeaked),
      confinementStateLost: boolOf(settling?.confinementStateLost) === true,
      records: ordered.map((r) => ({
        seq: r.seq,
        kind: String(r.kind ?? "unknown"),
        hash: typeof r.hash === "string" ? r.hash.slice(0, 12) : "",
      })),
    });
  }
  turns.sort((a, b) => b.seq - a.seq);
  return { turns: turns.slice(0, limit), more: Math.max(0, turns.length - limit) };
}

const agentIdParams = z.object({ id: z.string().uuid() });
const journalQuery = z.object({
  limit: z.coerce.number().int().min(1).max(MAX_TURNS).optional(),
});



/**
 * Wires the browser panel's routes onto the app. One call from `app.ts`; nothing else in the kit
 * changes.
 */
export function registerWebRoutes(
  app: FastifyInstance,
  runner: TransactionalRunner | undefined,
  config: AppConfig,
): void {
  const journalPath = path.join(config.dataDirectory, "journal.jsonl");

  app.get("/api/agents/:id/journal", async (request): Promise<JournalResponse> => {
    const { id } = agentIdParams.parse(request.params);
    const { limit } = journalQuery.parse(request.query ?? {});
    const text = await fs.readFile(journalPath, "utf8").catch(() => "");
    const { turns, more } = buildTimeline(parseJournal(text), id, limit ?? DEFAULT_TURNS);
    const chain = await TransactionalRunner.verifyChain(journalPath);
    return {
      agentId: id,
      turns,
      more,
      chain: { ok: chain.ok, records: chain.records, problems: chain.problems.slice(0, MAX_CHAIN_PROBLEMS) },
    };
  });

}

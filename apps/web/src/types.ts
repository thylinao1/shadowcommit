export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  workspacePath: string;
  codexThreadId: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: {
    inputTokens?: number;
    cachedInputTokens?: number;
    outputTokens?: number;
  } | null;
  createdAt: string;
  /**
   * What the transactional boundary did with this run. Optional because the field is being moved
   * onto the runner result in another lane; the panel reads it when it is there and falls back to
   * the journal and then to the sentence the runner appended to the reply.
   */
  containment?: Containment;
}

export interface Containment {
  /**
   * The transaction id in the journal. It is the SAME identifier as the run id: the control plane
   * passes its run id into the transaction (agent-service.ts) and the transaction adopts it, so the
   * journal, the review queue, the timeline and the run history all name one turn by one string.
   */
  runId?: string;
  decision: "commit" | "discard" | "review" | "conflict";
  rule: string;
  effects: number;
}

export interface SystemInfo {
  arkConfigured: boolean;
  arkBaseUrl: string;
  arkModel: string | null;
  codexAvailable: boolean;
  codexSandboxMode: string;
  runtimeProvider: "local-process" | "container";
  containerEngine: string | null;
  runtime: string;
}

/**
 * The shapes the transactional boundary returns. They mirror `apps/server/src/web-routes.ts`;
 * the two workspaces do not share a tsconfig, so this is a deliberate copy rather than an import.
 */

export type EffectKind = "create" | "modify" | "delete" | "symlink" | "outbound";
export type ChangeClass = "protected" | "dependency" | "ci" | "config" | "source" | "other";

export interface RuleHit {
  rule: string;
  decision: "discard" | "review";
  path?: string;
  detail?: string;
}

/** One row of PROPOSED CHANGES: what the turn wants to do to one path. */
export interface ProposedChange {
  path: string;
  kind: EffectKind;
  class: ChangeClass;
  bytes: number;
  before: string | null;
  after: string | null;
  truncated: boolean;
  binary: boolean;
  target?: string;
  escapes?: boolean;
}

export interface Review {
  runId: string;
  agentId: string;
  rule: string;
  hits: RuleHit[];
  effectSetHash: string;
  effectCount: number;
  truncated: number;
  workspacePath: string;
  /** ISO timestamp the runner recorded when it held the turn */
  heldAt: string | null;
  effects: ProposedChange[];
}

export type TurnVerdict =
  | "committed"
  | "discarded"
  | "held"
  | "approved"
  | "rejected"
  | "conflicted"
  | "restored"
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
  rule: string | null;
  principal: string | null;
  seq: number;
  at: string | null;
  mechanism: string | null;
  effectCount: number;
  truncated: number;
  effects: TimelineEffect[];
  conflictPaths: string[];
  /** files a mid-apply conflict had already written; empty for every other verdict */
  appliedPaths: string[];
  /**
   * The server's own sha256 over the REAL workspace, at turn open and at the moment the turn
   * ended. Equal means the workspace is byte for byte what it was; different means it moved, which
   * is what a commit is supposed to do. Null when the journal carries no measurement, and then
   * `workspaceDigestReason` says why rather than leaving the panel to guess.
   */
  workspaceDigestBefore: string | null;
  workspaceDigestAfter: string | null;
  workspaceDigestReason: string | null;
  workspaceFilesBefore: number | null;
  workspaceFilesAfter: number | null;
  /**
   * Entries the walk could not read: an unlistable directory, a failed lstat, a file whose bytes
   * would not come back. Non-zero means the digest is a partial measurement, and the panel must not
   * say "byte for byte" over it however equal the two values are.
   */
  workspaceUnreadableBefore: number | null;
  workspaceUnreadableAfter: number | null;
  /**
   * The network half of the boundary, mirroring `apps/server/src/web-routes.ts`.
   *
   * A turn runs on a per-run internal network whose only route out is the broker, with the model
   * channel terminated there and the agent's own memory sealed the same way as the workspace. All
   * of it is journaled and none of it reached a screen before this.
   *
   * Every field is optional and every absence has to render as an absence. `confinement: "none"` is
   * a real journaled value, written on every turn of the host-process runtime under
   * SHADOW_ALLOW_UNCONFINED=1, and it is the one case the panel must not paint as contained.
   * `beginRecorded` is what separates it from a turn whose opening record predates these fields and
   * from a turn that has no opening record at all.
   */
  beginRecorded?: boolean;
  confinement?: string | null;
  confinementReason?: string | null;
  network?: string | null;
  /** a count, never the host list; 0 is an allowlist that allows nothing, null is no record of one */
  egressAllowlistSize?: number | null;
  modelChannel?: string | null;
  codexHomeFiles?: number | null;
  /** one count per broker decision kind, off the record the turn settled on */
  egress?: Record<string, number> | null;
  outboundDropped?: number | null;
  /**
   * DISJOINT counts, not a set and a subset. The sealer increments exactly one of the two per held
   * payload, so the number attempted is their sum. Rendering the failed count against the replayed
   * one said "2 of them failed" about 3 successes, and said "0 sent, 3 of them failed" about a
   * total failure to send.
   */
  outboundReplayed?: number | null;
  outboundFailed?: number | null;
  outboundHeldForReview?: number | null;
  codexHomeRestored?: boolean | null;
  codexHomeVerifiedUnchanged?: boolean | null;
  /**
   * True marks the two fields above as bookkeeping rather than measurement. A rejected review
   * journals `{ restored: false, verifiedUnchanged: true, droppedAfterReview: true }` as a literal,
   * because the rollback already ran at the earlier review settle and this settle only drops the
   * sealed copy. Without this field a rejected review reads as a turn that was verified unchanged.
   */
  codexHomeDroppedAfterReview?: boolean | null;
  codexHomeChanged?: number | null;
  networkLeaked?: string | null;
  confinementStateLost?: boolean;
  records: Array<{ seq: number; kind: string; hash: string }>;
}

export interface JournalResponse {
  agentId: string;
  turns: TimelineTurn[];
  more: number;
  chain: { ok: boolean; records: number; problems: string[] };
}

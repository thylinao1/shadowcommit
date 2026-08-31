import type { CommandExecution } from "./codex-runner.js";

export type AgentStatus = "ready" | "busy" | "stopped" | "error";
/**
 * "contained" is a run the runtime finished and the boundary did not apply: discarded by policy,
 * held for a human, or refused because the workspace moved. It is deliberately not "completed",
 * because a completed run means the work is in the workspace, and for these it is not.
 */
export type RunStatus =
  | "queued"
  | "running"
  | "completed"
  | "contained"
  | "failed"
  | "cancelled";
export type MessageRole = "user" | "assistant";

/**
 * What the transactional boundary did with a turn. This travels on the runner result so no caller
 * can read the agent's own "I completed the task" on a turn whose effects went nowhere.
 */
export interface Containment {
  runId: string;
  decision: "commit" | "discard" | "review" | "conflict";
  /** the rule that decided, or "none" */
  rule: string;
  /** how many effects the turn produced */
  effects: number;
  /** the paths those effects touched, bounded */
  paths: string[];
  /** how many paths were dropped from `paths` by that bound */
  pathsTruncated?: number;
}

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
  role: MessageRole;
  content: string;
  createdAt: string;
}

export interface RunUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
  /** the boundary's verdict, so a discarded turn is never stored as an ordinary completed run */
  containment: Containment | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface Database {
  version: 1;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface UpdateAgentInput {
  name?: string | undefined;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface RunnerResult {
  output: string;
  threadId: string | null;
  usage: RunUsage | null;
  /** present whenever the runner is wrapped in the transactional boundary */
  containment?: Containment;
  /**
   * Every shell command the turn ran, from the codex event stream. Absent on a runner that does not
   * report commands, which is why it is optional rather than an empty array by default: a runner
   * that cannot see commands and one whose turn ran none are different states and should not read
   * the same.
   *
   * It exists because a command codex killed at its ten second limit was invisible: the runner read
   * the agent's final message and the usage block and nothing else, so a turn whose command was
   * killed halfway produced the same result as one whose command succeeded. See
   * `test-fixtures/codex-events/README.md` for the captured streams and the swept boundary.
   */
  commands?: CommandExecution[];
}

/**
 * What the sealed network and the sealed codex-home give one turn. Set by the transactional
 * runner's confinement hook; the runner that receives it is the only thing that reads it, and a
 * runner that ignores it is journaled as `confinement: "none"` rather than silently unconfined.
 */
export interface RunnerConfinement {
  runId: string;
  /**
   * The per-run `--internal` docker network; the agent is on this one and nothing else. Null when
   * only the memory half is sealed, in which case the turn keeps the runtime's ordinary network
   * and the journal says `confinement: "container"` rather than "container+sealed-network".
   */
  networkName: string | null;
  /** HTTP_PROXY / HTTPS_PROXY for shell egress, terminated at the broker; null when unsealed */
  proxyUrl: string | null;
  noProxy: string | null;
  /** the one-turn credential the container gets in place of the real provider key */
  turnToken: string | null;
  /** the per-turn copy of the agent's codex-home, mounted in place of the real directory */
  codexHomePath: string;
}

export interface RunnerRequest {
  agentId: string;
  workspacePath: string;
  prompt: string;
  threadId: string | null;
  /**
   * The id the control plane already gave this turn.
   *
   * Without it the transaction mints its own, and one turn ends up with two identifiers: the run
   * history and the Playground know it by one, the journal, the review queue and the timeline know
   * it by the other, and nothing on the platform can be joined to anything else without knowing to
   * hop through `containment.runId` first. Optional so a caller that has no run of its own (a test,
   * a script) still gets a generated one.
   */
  runId?: string | undefined;
  confinement?: RunnerConfinement | undefined;
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}

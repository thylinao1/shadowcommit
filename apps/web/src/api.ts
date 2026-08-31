import type {
  Agent,
  AgentRun,
  JournalResponse,
  Message,
  Review,
  SystemInfo,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

/** The review surface. Hardened server side: chain verified, policy re-run, approval hash bound. */
const REVIEWS_BASE = "/api/reviews";

/**
 * Every mutating request carries a header no cross-site form can set.
 *
 * A body-less cross-origin POST is a CORS simple request: the browser sends it with no preflight,
 * and refusing the origin only hides the response, it does not stop the request from running. A
 * custom header forces a preflight the browser will not send cross-origin. The server requires it
 * on every POST, PUT, PATCH and DELETE under /api/, not only on the settle routes, so it belongs
 * in the one place every request goes through rather than on the calls that happened to need it
 * when the panel was written.
 */
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

let authToken = "";

export function setAuthToken(token: string): void {
  authToken = token.trim();
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const method = (options?.method ?? "GET").toUpperCase();
  const headers = {
    ...(options?.body ? { "Content-Type": "application/json" } : {}),
    ...(authToken ? { Authorization: "Bearer " + authToken } : {}),
    ...(MUTATING.has(method) ? { "x-shadow-commit": "1" } : {}),
    ...options?.headers,
  };
  const response = await fetch(url, {
    ...options,
    headers,
  });
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    throw new ApiError(data.error ?? "Request failed", response.status);
  }
  return data;
}

/**
 * The policy registry, as the server reports it.
 *
 * Read this shape carefully before rendering it: `notes.reportsFiredNotEvaluated` is the server
 * saying that it records which rules FIRED and does not record which rules it evaluated on a given
 * turn. So this list is what is registered NOW. Presenting it as a record of what ran on one
 * particular turn would be a claim about the server that the server did not make.
 */
export interface PolicyRuleView {
  id: string;
  position: number;
  decisions: string[];
  /** every id this rule reports a hit under; an entry ending in ":" is a prefix */
  hitIds: string[];
  summary: string;
}

export interface PolicyRegistryView {
  count: number;
  rules: PolicyRuleView[];
  notes: {
    noShortCircuit: boolean;
    reportsFiredNotEvaluated: boolean;
    /**
     * `stopsAtFirstFailure` is the scope `noShortCircuit` does not have. That flag is about the
     * registry loop; the authorization check ahead of it returns at the first question it fails,
     * so a turn both over budget and out of scope reports as over budget alone.
     */
    authorizationAhead: {
      hitIdPrefix: string;
      decisions: string[];
      stopsAtFirstFailure: boolean;
    };
    ruleErrorHitId: string;
  };
}

/**
 * One Agent's capability grant: which workspace paths its effects may touch, which destinations it
 * may reach, and how many effects one turn may propose.
 *
 * `source` is the field that keeps the panel honest. "stored" means an operator issued this grant.
 * "default" means nobody has, and the server synthesised the open one: every path, every
 * destination, no practical effect ceiling. A panel that draws the default the same way it draws a
 * narrow grant is telling the operator they are protected when they are not.
 *
 * Which is why the two shapes are separate types. Only the GET path carries `source`:
 * `effectiveCapabilityGrant` adds it, and the PUT and DELETE handlers return `store.issue(...)` and
 * `store.revoke(...)` straight through, neither of which sets it. Declaring it required on all
 * three was a type lie that the panel survived by luck, because `undefined === "default"` is false
 * and the stored branch is the fallthrough. Written the equally natural way round,
 * `grant.source !== "stored"`, the panel would have told an operator "No grant has been issued for
 * this Agent" one line after they issued one.
 */
export interface StoredCapabilityGrant {
  agentId: string;
  allowedPathGlobs: string[];
  allowedDestinations: string[];
  budget: number;
  revision: number;
  status: "active" | "revoked";
  issuedAt: string;
  issuedBy: string;
  revokedAt: string | null;
  revokedBy: string | null;
}

export interface CapabilityGrant extends StoredCapabilityGrant {
  source: "default" | "stored";
}

export interface CapabilityGrantInput {
  allowedPathGlobs: string[];
  allowedDestinations: string[];
  budget: number;
}

export const api = {
  auth: () => request<{ required: boolean }>("/api/auth"),
  system: () => request<SystemInfo>("/api/system"),
  listAgents: () => request<{ agents: Agent[] }>("/api/agents"),
  createAgent: (body: {
    name: string;
    description: string;
    instructions: string;
  }) =>
    request<{ agent: Agent }>("/api/agents", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAgent: (
    id: string,
    body: { name: string; description: string; instructions: string },
  ) =>
    request<{ agent: Agent }>("/api/agents/" + id, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAgent: (id: string) =>
    request<{ archivedWorkspace: string }>("/api/agents/" + id, {
      method: "DELETE",
    }),
  startAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/start", {
      method: "POST",
    }),
  stopAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/stop", {
      method: "POST",
    }),
  messages: (id: string) =>
    request<{ messages: Message[] }>("/api/agents/" + id + "/messages"),
  runs: (id: string) =>
    request<{ runs: AgentRun[] }>("/api/agents/" + id + "/runs"),
  sendMessage: (id: string, content: string) =>
    request<{ run: AgentRun; message: Message }>(
      "/api/agents/" + id + "/messages",
      {
        method: "POST",
        body: JSON.stringify({ content }),
      },
    ),
  run: (id: string) => request<{ run: AgentRun }>("/api/runs/" + id),

  /** Held turns waiting on a human, newest first, with their proposed changes. */
  reviews: () => request<{ reviews: Review[] }>(REVIEWS_BASE),

  /**
   * Settles a held turn. The hash is the effect set the panel actually rendered: if it moved while
   * the operator was reading it, the server refuses rather than applying something nobody saw.
   */
  approveReview: (runId: string, effectSetHash: string) =>
    request<{ runId: string; decision: string; actor: string }>(
      REVIEWS_BASE + "/" + runId + "/approve",
      {
        method: "POST",
        body: JSON.stringify({ effectSetHash }),
      },
    ),

  rejectReview: (runId: string) =>
    request<{ runId: string; decision: string; actor: string }>(
      REVIEWS_BASE + "/" + runId + "/reject",
      { method: "POST" },
    ),

  /**
   * The rule set the policy iterates, straight from the server's registry. Guarded like every
   * other control route, so a caller with no credential is refused rather than shown a list.
   */
  policyRules: () => request<PolicyRegistryView>("/api/policy/rules"),

  /** The grant in force for this Agent, including the open default when nobody has issued one. */
  capabilityGrant: (agentId: string) =>
    request<{ grant: CapabilityGrant }>("/api/agents/" + agentId + "/capability-grant"),

  /** Narrows or widens the grant. Every issue is a new revision, and the policy reads it live. */
  issueCapabilityGrant: (agentId: string, body: CapabilityGrantInput) =>
    request<{ grant: StoredCapabilityGrant }>("/api/agents/" + agentId + "/capability-grant", {
      method: "PUT",
      body: JSON.stringify(body),
    }),

  /**
   * Revokes it. From the next judgement onward every turn by this Agent is held, including a turn
   * that is running right now, because the grant is read when the turn is judged rather than when
   * it starts. It does not settle a turn already waiting in the review queue: that stays a person's
   * decision on the approve path.
   */
  revokeCapabilityGrant: (agentId: string) =>
    request<{ grant: StoredCapabilityGrant }>("/api/agents/" + agentId + "/capability-grant", {
      method: "DELETE",
    }),

  /** The run timeline: every turn of this agent with the verdict the boundary recorded. */
  journal: (agentId: string, limit = 50) =>
    request<JournalResponse>("/api/agents/" + agentId + "/journal?limit=" + limit),
};

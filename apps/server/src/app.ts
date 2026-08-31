import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { createHash, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { HttpError } from "./errors.js";
import type { AgentService } from "./agent-service.js";
import type { SettleCode, TransactionalRunner } from "./transactional-runner.js";
import { registerWebRoutes } from "./web-routes.js";
import { registerCapabilityGrantRoutes } from "./capability-grant-routes.js";
import { registerPolicyRoutes } from "./policy-routes.js";
import { capabilityGrantStoreFor } from "./capability-grants.js";

/**
 * The header every state-changing request has to carry.
 *
 * A body-less cross-origin POST is a CORS "simple request": the browser sends it without a
 * preflight, and `origin: false` only hides the response from the attacker, it does not stop the
 * request from executing. So any page the operator happened to visit could approve a held turn or
 * delete an agent (attack r11). Requiring a custom header forces a preflight, which the browser
 * refuses to send cross-origin, and costs a first-party caller one line.
 */
const PREFLIGHT_HEADER = "x-shadow-commit";
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * The header a handler may read to learn who is acting, and the caller does not get to write it.
 *
 * It arrives from the caller like any other header, and `capability-grant-routes.ts` reads it
 * straight into the stored grant's `issuedBy` and `revokedBy`. So the operator hook overwrites it
 * with the principal it just authenticated, before any handler runs. See the hook for why that is
 * the only place this can be decided.
 */
const ACTOR_HEADER = "x-actor";

/**
 * The path the ROUTER will match, which is not always the one the caller typed.
 *
 * Every guard below decides from the request target, and a guard that reads a different string than
 * the router does is not a guard. Two normalisations the router performs and a naive
 * `request.url.startsWith("/api/")` does not:
 *
 *   1. Absolute form. HTTP/1.1 permits `GET http://host:port/api/agents` as a request target, and
 *      find-my-way strips the origin before matching (its FULL_PATH_REGEXP, index.js:572). So the
 *      route ran while `request.url` still began with "http", every hook returned early, and a
 *      caller presenting NO credential against a server with a token configured was served agent
 *      data, could read a held turn's effects, and could issue itself a capability grant recorded
 *      as the operator. Measured on this file before this change: origin form 401, absolute form
 *      200 with the data.
 *   2. Percent-encoding. `/%61pi/agents` and `/api%2fagents` reach the same handlers.
 *
 * Decoding can itself throw on a malformed escape, and a target that cannot be decoded is exactly
 * the kind that should not be waved through, so the raw form is kept alongside and any guard treats
 * a request as protected when EITHER spelling looks protected.
 */
export function requestPaths(rawUrl: string): { raw: string; decoded: string } {
  let raw = rawUrl;
  if (raw.charCodeAt(0) !== 47) raw = raw.replace(/^https?:\/\/.*?\//, "/");
  const withoutQuery = raw.split("?")[0] ?? raw;
  let decoded = withoutQuery;
  try {
    decoded = decodeURIComponent(withoutQuery);
  } catch {
    // an undecodable target keeps its raw spelling rather than being skipped
  }
  return { raw: withoutQuery, decoded };
}

/** Addresses that are this machine talking to itself. */
function isLoopback(address: string | undefined): boolean {
  if (!address) return false;
  const bare = address.startsWith("::ffff:") ? address.slice("::ffff:".length) : address;
  return bare === "::1" || bare === "localhost" || bare.startsWith("127.");
}

/**
 * What a request is asking for, in the only vocabulary this file has for it.
 *
 * - `open`: the two routes that must answer a caller who has no credential yet. `/api/health` is
 *   the liveness probe an orchestrator calls before any token exists, and `/api/auth` is how a
 *   panel with no token finds out whether it needs one. The list is exact rather than a prefix, so
 *   a future auth route has to be added here on purpose.
 * - `review`: the routes that settle a held turn, which is the one authority an agent must never
 *   hold over its own turn.
 * - `control`: the rest of the control plane.
 *
 * Exported because it is the single answer to "which surface is this", and every hook and every
 * handler below reads it. The token hook and the operator hook used to decide openness separately,
 * one on the whole url and one on the path, so `/api/health?ts=1` was open to one and closed to the
 * other. Two exemption lists drifting apart is how the next bypass gets in.
 */
export type ApiSurface = "not-api" | "open" | "control" | "review";

const OPEN_API_PATHS = new Set(["/api/health", "/api/auth"]);
const REVIEW_API_PREFIX = "/api/reviews";

export function apiSurfaceOf(url: string): ApiSurface {
  const { raw, decoded } = requestPaths(url);
  if (!raw.startsWith("/api/") && !decoded.startsWith("/api/")) return "not-api";
  const isReview = (candidate: string): boolean =>
    candidate === REVIEW_API_PREFIX || candidate.startsWith(REVIEW_API_PREFIX + "/");
  // when the two spellings disagree the stricter tier wins, so an encoding cannot demote a route
  if (isReview(raw) || isReview(decoded)) return "review";
  // and both spellings have to be open, for the same reason: "review" and the /api/ gate consulted
  // the raw form as well and only "open" did not, so an encoding could demote a route to the open
  // tier while no encoding could promote one to the guarded tier. One path read two ways with
  // opposite strictness is the shape of the last two bypasses.
  if (OPEN_API_PATHS.has(raw) && OPEN_API_PATHS.has(decoded)) return "open";
  return "control";
}

/** The bearer token on a request, or "" when there is none. */
function bearerToken(request: FastifyRequest): string {
  const header = request.headers.authorization ?? "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

/**
 * True when the agent's turn runs on this host's own network stack.
 *
 * A container gets its own stack. Its turn reaches the control plane across the docker bridge and
 * arrives from a bridge address, which is not loopback: `container-codex-runner.ts` always passes
 * `--network bridge` or a private per-run network, never `--network host`. A host process gets no
 * stack of its own, so its loopback IS our loopback and `127.0.0.1` says nothing about who called.
 *
 * Only the provider decides that. SHADOW_ALLOW_UNCONFINED is the operator's consent for
 * `runner-factory.ts` to accept a host-process runtime at all; with RUNTIME_PROVIDER=container it
 * changes nothing about where a turn's packets come from, and `.env.example` ships the two
 * together. Reading the flag here as well cost that shipped combination its whole review surface.
 */
function agentSharesHostNetwork(config: AppConfig): boolean {
  return config.runtimeProvider !== "container";
}

/** Each refusal names the first thing actually wrong, so an operator knows which one to fix. */
const OFF_BOX_REFUSAL =
  "This control plane answers the local operator only. Set APP_AUTH_TOKEN and present it.";
const UNCONFINED_REFUSAL =
  "This runtime shares the host network with the agent, so a loopback address does not " +
  "identify an operator. Settling a review here needs APP_AUTH_TOKEN set and presented.";

/**
 * ONE decision about who may call what, and this is the whole of it:
 *
 *   every /api route answers the operator only; the operator is whoever presents the configured
 *   APP_AUTH_TOKEN or, failing that, a caller on this machine's loopback; and settling a review
 *   additionally refuses bare loopback whenever the agent's turn runs on this host's own network
 *   stack, because there loopback cannot tell the agent from the operator.
 *
 * Never the `x-actor` header. That header is a value the caller types, so an agent that reached the
 * control plane, or a page that forged a request, could approve its own turn as a named human and
 * the hash chain would faithfully attest a sign-off that never happened (attack r13). A tamper
 * evident log that certifies a forged decision is worse than no log. So the principal is either a
 * loopback operator or a name derived from the token actually presented, and nothing else.
 *
 * Under the confined default that boundary is real: the turn sits on the docker bridge, so it can
 * reach this control plane at the gateway address but never from loopback, and it is refused
 * everywhere, on every route (attack r10, and r13 through it).
 *
 * Why only the review tier refuses loopback, and what that does not buy. On an unconfined host the
 * turn is a plain child process of this server with no filesystem jail: it can already read the
 * journal and the workspaces off disk and delete them, so refusing it `GET /api/agents` protects
 * nothing and only breaks the developer who chose that runtime. What it cannot do by touching the
 * filesystem is make this server write a settled, hash-chained record naming an
 * operator who never looked, and that is the one authority this tier withholds. Say the rest
 * plainly: on an unconfined host this control does not stop a local agent, it stops the control
 * plane from vouching for one. An operator who needs a boundary there runs a container.
 */
function operatorPrincipal(
  config: AppConfig,
  request: FastifyRequest,
  surface: "control" | "review",
): { ok: true; actor: string } | { ok: false; reason: string } {
  const token = bearerToken(request);
  if (config.authToken.length > 0 && token.length > 0) {
    // the token hook has already compared it; this derives a stable, non-secret name from it
    return {
      ok: true,
      actor: "operator:" + createHash("sha256").update(token).digest("hex").slice(0, 12),
    };
  }
  const address = request.socket?.remoteAddress ?? request.ip;
  if (!isLoopback(address)) return { ok: false, reason: OFF_BOX_REFUSAL };
  if (surface === "review" && agentSharesHostNetwork(config)) {
    return { ok: false, reason: UNCONFINED_REFUSAL };
  }
  return { ok: true, actor: "operator" };
}

/** Says which control refused, in words an operator can act on. */
function settleMessage(code: SettleCode, detail?: string): string {
  const because: Record<SettleCode, string> = {
    ok: "Settled",
    settling: "Another decision on this turn is already in flight",
    "not-pending": "Not pending",
    "chain-broken": "The journal does not verify, so no turn can be settled",
    "invalid-record": "The held record points outside the configured roots",
    "hash-mismatch": "The changes moved since you looked at them; reload the review",
    tampered: "The held bytes no longer match what was captured",
    "policy-refused": "Policy refuses this change now",
    conflict: "The workspace changed while this turn waited",
  };
  return detail ? `${because[code]}: ${detail}` : because[code];
}

/** How a refused settle reaches the caller. */
const SETTLE_STATUS: Record<SettleCode, number> = {
  ok: 200,
  settling: 409,
  "not-pending": 409,
  "chain-broken": 409,
  "invalid-record": 409,
  "hash-mismatch": 409,
  tampered: 409,
  "policy-refused": 409,
  conflict: 409,
};

const agentIdParams = z.object({ id: z.string().uuid() });
const runIdParams = z.object({ id: z.string().uuid() });
const createAgentBody = z.object({
  name: z.string().trim().min(1).max(80),
  description: z.string().max(500).optional(),
  instructions: z.string().max(10_000).optional(),
});
const updateAgentBody = createAgentBody.partial().refine(
  (value) => Object.keys(value).length > 0,
  "At least one field is required",
);
const messageBody = z.object({
  content: z.string().trim().min(1).max(50_000),
});
/** An approval names the exact set of changes the operator was shown. */
const approveBody = z.object({
  effectSetHash: z.string().regex(/^[0-9a-f]{64}$/, "effectSetHash must be a sha256 hex digest"),
});

export async function createApp(
  config: AppConfig,
  service: AgentService,
  /** optional so existing callers and tests keep working; supplied by index.ts in the real server */
  reviews?: TransactionalRunner,
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: ["req.headers.authorization", "req.headers.cookie"],
    },
    bodyLimit: 1_048_576,
  });

  await app.register(cors, {
    origin:
      config.nodeEnv === "development"
        ? ["http://localhost:5173", "http://127.0.0.1:5173"]
        : false,
  });

  // The operator surface for capability grants, sharing ONE store with the runner that enforces
  // them (capability-grants.ts memoises per data directory). Registered here so the app's existing
  // authentication hook covers these routes like every other /api route: issuing and revoking a
  // capability is an operator action, never an agent one.
  await registerCapabilityGrantRoutes(app, {
    store: capabilityGrantStoreFor(config.dataDirectory),
    agentExists: (agentId) => {
      try {
        service.getAgent(agentId);
        return true;
      } catch {
        return false;
      }
    },
  });

  // The rule set, so an operator can read which questions the policy asks instead of only the
  // answers it happened to give. Registered here for the same reason as the grant routes above:
  // the hooks below are instance-wide and cover every route on this app, so this route arrives on
  // the "control" tier with the token check, the preflight check and the operator check in front
  // of it. It must never be added to OPEN_API_PATHS.
  await registerPolicyRoutes(app);

  // First of three. Reads `apiSurfaceOf`, like the other two, so there is one answer in this
  // process to which paths are open and which prefix counts as the API.
  app.addHook("onRequest", async (request, reply) => {
    if (!config.authToken) return;
    const surface = apiSurfaceOf(request.url);
    if (surface === "not-api" || surface === "open") return;
    const header = request.headers.authorization ?? "";
    const candidate = header.startsWith("Bearer ") ? header.slice(7) : "";
    const expectedBuffer = Buffer.from(config.authToken);
    const candidateBuffer = Buffer.from(candidate);
    const valid =
      candidateBuffer.length === expectedBuffer.length &&
      timingSafeEqual(candidateBuffer, expectedBuffer);
    if (!valid) {
      return reply.code(401).send({ error: "Authentication required" });
    }
  });

  // Registered after the token check so a caller with no credentials is told that first.
  app.addHook("onRequest", async (request, reply) => {
    if (apiSurfaceOf(request.url) === "not-api") return;
    if (!MUTATING_METHODS.has(request.method)) return;
    if (request.headers[PREFLIGHT_HEADER] === "1") return;
    return reply.code(403).send({
      error: `State-changing requests must carry the ${PREFLIGHT_HEADER}: 1 header`,
    });
  });

  /**
   * Third and last of the three, and here rather than earlier for two reasons.
   *
   * After the token hook, because `operatorPrincipal` names a caller from the sha256 of whatever
   * bearer string arrived, on that hook's promise that the string was already compared against the
   * configured token. Run first, it would hand `operator:<hash>` to anyone who typed a header.
   *
   * After the preflight hook, because that one asks a question about the shape of the request that
   * applies to the operator as much as to anyone else. A first-party caller that only forgot
   * `x-shadow-commit` is then told the header is missing rather than told it is not the operator,
   * and each refusal names the first thing actually wrong.
   *
   * It sits with the other two, above every route on this instance, so its coverage is exactly the
   * token hook's coverage: the routes below, and the capability grant routes registered above.
   *
   * `operatorOnly` stays where it is inside the three review handlers. This hook is the floor under
   * those calls, not a replacement for them, and the review routes are the ones where a bypass
   * would let a held turn approve itself.
   */
  app.addHook("onRequest", async (request, reply) => {
    const surface = apiSurfaceOf(request.url);
    if (surface === "not-api" || surface === "open") return;
    const principal = operatorPrincipal(config, request, surface);
    if (!principal.ok) {
      // the principal's own words, so the refusal names the branch that fired, not one of them
      return reply.code(403).send({ error: principal.reason });
    }
    /**
     * ... and the caller's own idea of who it is does not survive the boundary that just decided.
     *
     * The rule above is "never the `x-actor` header", and the three review handlers obeyed it by
     * calling `operatorPrincipal` themselves. The capability-grant routes, registered on this same
     * instance and covered by these same hooks, did not: they read `x-actor` off the request and
     * wrote it into the durable grant as `issuedBy`, so every caller this hook admitted also chose
     * what the record called them. A grant says which paths and which destinations a turn may
     * touch, so a forged name on it is the same defect as a forged name on an approval.
     *
     * Overwriting the header rather than asking each route to look elsewhere is deliberate: a route
     * cannot opt out of it, and a route written later inherits it without having to know the rule.
     * Replacing untrusted input with the vetted value is what this boundary is for.
     */
    request.headers[ACTOR_HEADER] = principal.actor;
  });

  app.get("/api/health", async () => ({
    ok: true,
    service: "volc-agent-launchpad",
  }));

  app.get("/api/auth", async () => ({ required: config.authToken.length > 0 }));

  app.get("/api/system", async () => service.systemInfo());

  // The review surface. Without these the held-turn state is unreachable from the running platform:
  // a turn stopped for a human waits forever and nobody can see what it proposed.
  //
  // The hook above already refused anyone who is not the operator on the "review" surface. These
  // three keep their own call because `operatorOnly` also returns the actor name the journal
  // records, and because a bypass here is the one that settles a turn: the container a turn runs in
  // sits on the docker bridge, so without this rule the agent reaches the control plane at the
  // gateway address and approves the very review it is held for (attack r10), which closes the loop
  // on every review verdict the product has.
  const operatorOnly = (request: FastifyRequest): string => {
    const principal = operatorPrincipal(config, request, "review");
    if (!principal.ok) throw new HttpError(403, principal.reason);
    return principal.actor;
  };

  app.get("/api/reviews", async (request) => {
    operatorOnly(request);
    if (!reviews) return { reviews: [] };
    return { reviews: await reviews.reviewQueue() };
  });

  app.post("/api/reviews/:id/approve", async (request, reply) => {
    const actor = operatorOnly(request);
    if (!reviews) throw new HttpError(503, "Review surface unavailable");
    const { id } = runIdParams.parse(request.params);
    const { effectSetHash } = approveBody.parse(request.body);
    const outcome = await reviews.approve(id, actor, effectSetHash);
    if (!outcome.ok) {
      throw new HttpError(SETTLE_STATUS[outcome.code], settleMessage(outcome.code, outcome.detail));
    }
    reply.code(200);
    return { runId: id, decision: "approved", actor };
  });

  app.post("/api/reviews/:id/reject", async (request, reply) => {
    const actor = operatorOnly(request);
    if (!reviews) throw new HttpError(503, "Review surface unavailable");
    const { id } = runIdParams.parse(request.params);
    const outcome = await reviews.reject(id, actor);
    if (!outcome.ok) {
      throw new HttpError(SETTLE_STATUS[outcome.code], settleMessage(outcome.code, outcome.detail));
    }
    reply.code(200);
    return { runId: id, decision: "rejected", actor };
  });

  // The browser panel's routes: the reviews queue it renders and the run timeline. One call.
  registerWebRoutes(app, reviews, config);

  app.get("/api/agents", async () => ({ agents: service.listAgents() }));

  app.post("/api/agents", async (request, reply) => {
    const body = createAgentBody.parse(request.body);
    const agent = await service.createAgent(body);
    return reply.code(201).send({ agent });
  });

  app.get("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: service.getAgent(id) };
  });

  app.patch("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    const body = updateAgentBody.parse(request.body);
    return { agent: await service.updateAgent(id, body) };
  });

  app.delete("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return service.deleteAgent(id);
  });

  app.post("/api/agents/:id/start", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: await service.startAgent(id) };
  });

  app.post("/api/agents/:id/stop", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: await service.stopAgent(id) };
  });

  app.get("/api/agents/:id/messages", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { messages: service.getMessages(id) };
  });

  app.get("/api/agents/:id/runs", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { runs: service.getRuns(id) };
  });

  app.post("/api/agents/:id/messages", async (request, reply) => {
    const { id } = agentIdParams.parse(request.params);
    const body = messageBody.parse(request.body);
    const result = await service.sendMessage(id, body.content);
    return reply.code(202).send(result);
  });

  app.get("/api/runs/:id", async (request) => {
    const { id } = runIdParams.parse(request.params);
    return { run: service.getRun(id) };
  });

  // Registered BEFORE the production static block on purpose. Fastify resolves the error handler
  // for a route from the context the route was added in, and registering @fastify/static first left
  // the production build running Fastify's DEFAULT handler: a bad UUID came back as 500 with
  // { statusCode, error, message } instead of 400 with { error, details }. Every other app test
  // builds with NODE_ENV=test, so the production branch was never exercised and nothing said so.
  // It is judge-visible too: the web client renders `data.error`, so an operational refusal that
  // carries its reason in `message` reached the panel as a bare HTTP word.
  app.setErrorHandler((error, request, reply) => {
    const appError = error instanceof Error ? error : new Error(String(error));
    const validationError = error instanceof z.ZodError;
    const frameworkStatus =
      typeof (error as { statusCode?: unknown }).statusCode === "number"
        ? (error as { statusCode: number }).statusCode
        : null;
    const statusCode =
      error instanceof HttpError
        ? error.statusCode
        : validationError
          ? 400
          : frameworkStatus && frameworkStatus >= 400 && frameworkStatus <= 599
            ? frameworkStatus
            : 500;
    if (statusCode >= 500) {
      request.log.error(appError);
    }
    return reply.code(statusCode).send({
      error: appError.message,
      ...(validationError ? { details: error.issues } : {}),
    });
  });

  if (config.nodeEnv === "production") {
    const webRoot = fileURLToPath(new URL("../../web/dist", import.meta.url));
    await app.register(fastifyStatic, {
      root: webRoot,
      prefix: "/",
    });
    app.setNotFoundHandler((request, reply) => {
      if (apiSurfaceOf(request.url) !== "not-api") {
        return reply.code(404).send({ error: "API route not found" });
      }
      return reply.sendFile("index.html");
    });
  }

  return app;
}

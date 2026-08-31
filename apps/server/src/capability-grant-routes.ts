import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  effectiveCapabilityGrant,
  type CapabilityGrantInput,
  type CapabilityGrantStore,
} from "./capability-grants.js";
import { HttpError } from "./errors.js";

const agentIdParams = z.object({ id: z.string().uuid() });
const grantBody = z
  .object({
    allowedPathGlobs: z.array(z.string().min(1).max(512)).min(1).max(128),
    allowedDestinations: z.array(z.string().min(1).max(512)).min(1).max(128),
    budget: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

export interface CapabilityGrantRouteOptions {
  store: CapabilityGrantStore;
  /** Bind grants to existing Agents without coupling the grant module to AgentService storage. */
  agentExists(agentId: string): boolean | Promise<boolean>;
}

function actorFrom(request: FastifyRequest): string {
  const actor = request.headers["x-actor"];
  return typeof actor === "string" ? actor : "operator";
}

async function requireAgent(
  options: CapabilityGrantRouteOptions,
  agentId: string,
): Promise<void> {
  if (!(await options.agentExists(agentId))) throw new HttpError(404, "Agent not found");
}

/**
 * Registers the operator surface. The parent app's existing API authentication hook protects these
 * routes when this function is called during app construction.
 */
export async function registerCapabilityGrantRoutes(
  app: FastifyInstance,
  options: CapabilityGrantRouteOptions,
): Promise<void> {
  app.get("/api/agents/:id/capability-grant", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    await requireAgent(options, id);
    return { grant: await effectiveCapabilityGrant(options.store, id) };
  });

  app.put("/api/agents/:id/capability-grant", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    await requireAgent(options, id);
    const input: CapabilityGrantInput = grantBody.parse(request.body);
    return { grant: await options.store.issue(id, input, actorFrom(request)) };
  });

  app.delete("/api/agents/:id/capability-grant", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    await requireAgent(options, id);
    return { grant: await options.store.revoke(id, actorFrom(request)) };
  });
}

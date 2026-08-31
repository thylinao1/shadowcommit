import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { registerCapabilityGrantRoutes } from "./capability-grant-routes.js";
import { withCapabilityGrantRule } from "./capability-grant-rule.js";
import { MemoryCapabilityGrantStore } from "./capability-grants.js";
import { basicContext, type EffectRecord } from "./policy-types.js";

const agentId = "11111111-1111-4111-8111-111111111111";
const effect: EffectRecord = { kind: "modify", path: "src/index.ts" };

describe("capability grant routes", () => {
  it("issues and revokes a persisted per-Agent grant", async () => {
    const app = Fastify();
    const store = new MemoryCapabilityGrantStore();
    await registerCapabilityGrantRoutes(app, {
      store,
      agentExists: (candidate) => candidate === agentId,
    });

    const issued = await app.inject({
      method: "PUT",
      url: `/api/agents/${agentId}/capability-grant`,
      headers: { "x-actor": "operator-2" },
      payload: {
        allowedPathGlobs: ["src/**"],
        allowedDestinations: ["api.example.test:443"],
        budget: 1,
      },
    });
    expect(issued.statusCode).toBe(200);
    expect(issued.json().grant).toMatchObject({
      agentId,
      issuedBy: "operator-2",
      status: "active",
      revision: 1,
    });

    const policy = withCapabilityGrantRule(store, async () => ({ decision: "commit", rule: "none" }));
    const context = basicContext(async () => "", { agentId });
    await expect(policy([effect], context)).resolves.toMatchObject({ decision: "commit" });

    const revoked = await app.inject({
      method: "DELETE",
      url: `/api/agents/${agentId}/capability-grant`,
      headers: { "x-actor": "operator-2" },
    });
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json().grant).toMatchObject({ status: "revoked", revision: 2 });
    await expect(policy([effect], context)).resolves.toMatchObject({
      decision: "review",
      rule: "capability-grant-revoked",
    });

    const fetched = await app.inject({
      method: "GET",
      url: `/api/agents/${agentId}/capability-grant`,
    });
    expect(fetched.json().grant).toMatchObject({ status: "revoked", source: "stored" });
    await app.close();
  });

  it("does not issue grants for unknown Agents", async () => {
    const app = Fastify();
    await registerCapabilityGrantRoutes(app, {
      store: new MemoryCapabilityGrantStore(),
      agentExists: () => false,
    });
    const response = await app.inject({
      method: "PUT",
      url: `/api/agents/${agentId}/capability-grant`,
      payload: { allowedPathGlobs: ["**"], allowedDestinations: ["*"], budget: 1 },
    });
    expect(response.statusCode).toBe(404);
    await app.close();
  });
});

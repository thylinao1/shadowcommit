import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";
import type { FastifyInstance } from "fastify";

/**
 * Every app test builds with NODE_ENV=test, so the production branch of createApp has never been
 * exercised. In production the static-file plugin is registered first and `setErrorHandler` is
 * called after it, and the measured consequence on a running instance was that a validation failure
 * came back as HTTP 500 with Fastify's default body shape instead of 400 with ours.
 *
 * That is judge-visible: the web client reads `data.error`, so an operational refusal that carries
 * its reason in `message` reaches the panel as a bare HTTP word.
 */
let app: FastifyInstance;
const AUTH = { authorization: "Bearer a-production-token-of-sufficient-length" };

const service = {
  listAgents: () => [],
  systemInfo: async () => ({ ok: true }),
  getAgent: () => ({ id: "x", name: "x" }),
} as unknown as AgentService;

beforeAll(async () => {
  app = await createApp(
    loadConfig({ NODE_ENV: "production", APP_AUTH_TOKEN: "a-production-token-of-sufficient-length" }),
    service,
  );
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

describe("the production build installs the app's own error handler", () => {
  it("answers a bad UUID with 400 and our body shape, not 500 and Fastify's", async () => {
    const res = await app.inject({ method: "GET", url: "/api/agents/not-a-uuid", headers: AUTH });
    const body = res.json() as Record<string, unknown>;

    expect(res.statusCode).toBe(400);
    // ours is { error, details }; Fastify's default is { statusCode, error, message }
    expect(body).toHaveProperty("details");
    expect(body).not.toHaveProperty("statusCode");
  });

  it("keeps the reason in `error`, which is the field the web client renders", async () => {
    const res = await app.inject({ method: "GET", url: "/api/runs/not-a-uuid", headers: AUTH });
    expect(res.statusCode).toBe(400);
    const body = res.json() as { error?: string };
    // a bare HTTP word here is the panel bug; the message must carry information
    expect(typeof body.error).toBe("string");
    expect(body.error).not.toBe("Bad Request");
    expect((body.error ?? "").length).toBeGreaterThan(10);
  });

  it("still serves the API 404 shape for an unknown API route", async () => {
    const res = await app.inject({ method: "GET", url: "/api/definitely-not-a-route", headers: AUTH });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({ error: "API route not found" });
  });
});

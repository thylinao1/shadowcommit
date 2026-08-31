import { afterAll, beforeAll, describe, expect, it } from "vitest";
import net from "node:net";
import { createApp, requestPaths } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";
import type { FastifyInstance } from "fastify";

/**
 * Every API guard decides from the request target, and the router does not match the string the
 * caller typed. It strips an absolute-form origin (find-my-way's FULL_PATH_REGEXP) and it decodes
 * percent-escapes. A guard reading `request.url.startsWith("/api/")` therefore saw "http://..." or
 * "/%61pi/..." , decided the request was not API, and returned early while the route still ran.
 *
 * Measured on this file before the fix, with APP_AUTH_TOKEN configured and NO credential presented:
 * the origin form answered 401 and the absolute form answered 200 with the agent list. The same
 * shape reached the journal route and the capability-grant route, where the stored grant recorded
 * `issuedBy: operator`.
 *
 * These tests drive a REAL listening server over a raw socket rather than `app.inject`, because the
 * injection path can normalise the target itself and would hide exactly this defect.
 */

const AGENT_ID = "11111111-1111-4111-8111-111111111111";

const service = {
  listAgents: () => [{ id: AGENT_ID, name: "cataloguer" }],
  systemInfo: async () => ({ ok: true }),
  getAgent: (id: string) => ({ id, name: "cataloguer" }),
} as unknown as AgentService;

let app: FastifyInstance;
let port = 0;

beforeAll(async () => {
  app = await createApp(
    loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
    service,
  );
  await app.listen({ host: "127.0.0.1", port: 0 });
  port = (app.server.address() as net.AddressInfo).port;
});

afterAll(async () => {
  await app.close();
});

/** One request, written to the socket verbatim, so the target reaches the server unmodified. */
function send(method: string, target: string, headers: string[] = []): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write(
        `${method} ${target} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n` +
          headers.map((h) => h + "\r\n").join("") +
          "Connection: close\r\n\r\n",
      );
    });
    let buffer = "";
    socket.on("data", (chunk) => (buffer += chunk.toString()));
    socket.on("end", () => resolve(buffer));
    socket.on("error", reject);
  });
}

const status = (response: string): number => Number(response.split(" ")[1]);

describe("the API guard reads the path the router will match", () => {
  it("refuses an unauthenticated request written in absolute form, the same as origin form", async () => {
    const origin = await send("GET", "/api/agents");
    const absolute = await send("GET", `http://127.0.0.1:${port}/api/agents`);

    expect(status(origin)).toBe(401);
    expect(status(absolute)).toBe(401);
    // the body check is the one that matters: a 401 that still shipped the data would pass on status
    expect(absolute).not.toContain("cataloguer");
  });

  it("refuses percent-encoded spellings of the same prefix", async () => {
    for (const target of ["/%61pi/agents", "/api%2fagents"]) {
      const response = await send("GET", target);
      expect(status(response), `${target} should not be served`).not.toBe(200);
      expect(response).not.toContain("cataloguer");
    }
  });

  it("still demands the preflight header on a state-changing request in absolute form", async () => {
    // with a valid credential, so the only thing standing between the caller and the mutation is
    // the preflight guard that the absolute form also used to skip
    const auth = "Authorization: Bearer a-strong-test-token";
    const response = await send("DELETE", `http://127.0.0.1:${port}/api/agents/${AGENT_ID}`, [auth]);
    expect(status(response)).toBe(403);
  });

  it("keeps the open routes open, in either spelling, so the fix is not an outage", async () => {
    for (const target of ["/api/health", `http://127.0.0.1:${port}/api/health`]) {
      const response = await send("GET", target);
      expect(status(response), `${target} must stay open`).toBe(200);
    }
  });
});

describe("requestPaths", () => {
  it("strips an absolute-form origin the way the router does", () => {
    expect(requestPaths("http://host:3000/api/agents").raw).toBe("/api/agents");
    expect(requestPaths("https://host/api/agents").raw).toBe("/api/agents");
  });

  it("drops the query string, so a guard cannot be fooled by what follows a question mark", () => {
    expect(requestPaths("/api/agents?x=/public").raw).toBe("/api/agents");
  });

  it("returns both spellings, and keeps the raw one when the escape cannot be decoded", () => {
    expect(requestPaths("/%61pi/agents").decoded).toBe("/api/agents");
    // "%zz" is not a valid escape: decodeURIComponent throws and the raw spelling must survive
    expect(requestPaths("/api/%zz").raw).toBe("/api/%zz");
    expect(requestPaths("/api/%zz").decoded).toBe("/api/%zz");
  });
});

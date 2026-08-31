import { afterAll, beforeAll, describe, expect, it } from "vitest";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { FastifyInstance } from "fastify";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

/**
 * The operator boundary, driven over a real socket instead of `app.inject`.
 *
 * Two reasons this file exists beside the injected tests. `inject` builds the request from a parsed
 * URL, so it cannot carry an absolute-form request target the way a socket can, and that form is
 * what walked past all three hooks before the classifier learned to strip the origin. And `inject`
 * takes `remoteAddress` as an argument, which proves the guard reads the field but not that the
 * field arrives the way the guard assumes.
 *
 * The off-box peer here is a Unix domain socket. Its peer has no address at all
 * (`request.socket.remoteAddress` is undefined, measured), which is the same "this is not our own
 * loopback" branch a caller at the docker bridge gateway takes, without the test depending on the
 * machine it runs on having a second network interface.
 *
 * Config is the default a developer runs: NO token configured, provider unset. That is the
 * configuration in which the whole boundary rests on the peer address, so it is the one worth
 * driving.
 */

const AGENT = "11111111-1111-4111-8111-111111111111";

const deleted: string[] = [];
const service = {
  listAgents: () => [{ id: AGENT, name: "cataloguer" }],
  getAgent: (id: string) => ({ id, name: "cataloguer" }),
  deleteAgent: async (id: string) => {
    deleted.push(id);
    return { archivedWorkspace: "/tmp/archived" };
  },
  systemInfo: async () => ({ platform: "test" }),
} as unknown as AgentService;

let dataDirectory = "";
let offBox: FastifyInstance;
let onBox: FastifyInstance;
let socketPath = "";
let loopbackPort = 0;

beforeAll(async () => {
  dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "off-box-"));
  socketPath = path.join(dataDirectory, "control.sock");
  const config = loadConfig({ NODE_ENV: "test", APP_DATA_DIR: dataDirectory });
  expect(config.authToken).toBe("");

  offBox = await createApp(config, service);
  await offBox.listen({ path: socketPath });

  onBox = await createApp(config, service);
  await onBox.listen({ host: "127.0.0.1", port: 0 });
  loopbackPort = (onBox.server.address() as net.AddressInfo).port;
});

afterAll(async () => {
  await offBox.close();
  await onBox.close();
  await fs.rm(dataDirectory, { recursive: true, force: true });
});

/** One request written to the socket verbatim, so the target reaches the server unmodified. */
function send(
  where: string | number,
  method: string,
  target: string,
  headers: string[] = [],
  body = "",
): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket =
      typeof where === "string" ? net.connect(where) : net.connect(where, "127.0.0.1");
    socket.on("connect", () => {
      socket.write(
        `${method} ${target} HTTP/1.1\r\nHost: control.invalid\r\n` +
          headers.map((h) => h + "\r\n").join("") +
          "Connection: close\r\n\r\n" +
          body,
      );
    });
    let buffer = "";
    socket.on("data", (chunk) => (buffer += chunk.toString()));
    socket.on("end", () => resolve(buffer));
    socket.on("error", reject);
  });
}

const status = (response: string): number => Number(response.split(" ")[1]);

describe("a caller that is not on this machine's loopback, over a real socket", () => {
  it("is refused in absolute form as well as origin form, with no credential configured", async () => {
    const origin = await send(socketPath, "GET", "/api/agents");
    const absolute = await send(socketPath, "GET", "http://control.invalid/api/agents");

    expect(status(origin)).toBe(403);
    expect(status(absolute)).toBe(403);
    // the body is the assertion that matters: a 403 that still shipped the list would pass on status
    expect(absolute).not.toContain("cataloguer");
    expect(absolute).toContain("answers the local operator only");
  });

  it("cannot read a held turn or the system surface by rewriting the target", async () => {
    for (const route of ["/api/reviews", "/api/system", `/api/runs/${AGENT}`]) {
      const response = await send(socketPath, "GET", `http://control.invalid${route}`);
      expect([route, status(response)]).toEqual([route, 403]);
    }
  });

  it("cannot delete an agent in absolute form, and the service is never reached", async () => {
    const response = await send(
      socketPath,
      "DELETE",
      `http://control.invalid/api/agents/${AGENT}`,
      ["x-shadow-commit: 1"],
    );
    expect(status(response)).toBe(403);
    expect(deleted).toEqual([]);
  });

  it("cannot issue itself a capability grant in absolute form", async () => {
    const payload = JSON.stringify({
      allowedPathGlobs: ["**"],
      allowedDestinations: ["*"],
      budget: 1000,
    });
    const response = await send(
      socketPath,
      "PUT",
      `http://control.invalid/api/agents/${AGENT}/capability-grant`,
      [
        "x-shadow-commit: 1",
        "x-actor: operator",
        "content-type: application/json",
        `Content-Length: ${Buffer.byteLength(payload)}`,
      ],
    );
    expect(status(response)).toBe(403);
  });

  it("still answers the liveness probe, in either spelling, so this is not an outage", async () => {
    for (const target of ["/api/health", "http://control.invalid/api/health"]) {
      const response = await send(socketPath, "GET", target);
      expect([target, status(response)]).toEqual([target, 200]);
    }
  });
});

describe("the operator on this machine's loopback is unaffected", () => {
  it("is served the control plane in both spellings of the target", async () => {
    const origin = await send(loopbackPort, "GET", "/api/agents");
    const absolute = await send(
      loopbackPort,
      "GET",
      `http://127.0.0.1:${loopbackPort}/api/agents`,
    );

    expect(status(origin)).toBe(200);
    expect(origin).toContain("cataloguer");
    expect(status(absolute)).toBe(200);
    expect(absolute).toContain("cataloguer");
  });

  it("still has its actor decided for it, even sending the header twice", async () => {
    // two headers of the same name reach a handler as one joined string or an array depending on
    // the header, and `actorFrom` in capability-grant-routes.ts only checks for a string. Neither
    // shape survives, because the hook replaces the value rather than inspecting it.
    const payload = JSON.stringify({
      allowedPathGlobs: ["src/**"],
      allowedDestinations: ["*"],
      budget: 3,
    });
    const response = await send(
      loopbackPort,
      "PUT",
      `/api/agents/${AGENT}/capability-grant`,
      [
        "x-shadow-commit: 1",
        "content-type: application/json",
        "x-actor: maksim@example.com",
        "x-actor: someone-else",
        `content-length: ${Buffer.byteLength(payload)}`,
      ],
      payload,
    );

    expect(status(response)).toBe(200);
    expect(response).toContain('"issuedBy":"operator"');
    expect(response).not.toContain("maksim@example.com");
    expect(response).not.toContain("someone-else");
  });
});

import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import type { AgentService } from "./agent-service.js";

/**
 * Everything under /api/ is an operator surface, and until this file existed only the three
 * /api/reviews routes said so. `operatorOnly` was called by hand inside those three handlers, so
 * agent CRUD and the run timeline answered whoever asked whenever no token was configured, which
 * is the default in development and in the tests.
 *
 * That default is not a hypothetical. A turn runs in a container on the docker bridge and can reach
 * the host control plane at the gateway address. From there it could delete the agents next to it
 * and read their journals, which carry the paths, kinds and byte counts of every change those
 * agents proposed. A boundary that holds a turn for review and then hands the same turn the delete
 * button on the reviewer is not a boundary.
 *
 * The negatives matter as much: the liveness probe and the token question have to answer a caller
 * who has no credential yet, and the panel in the operator's own browser has to keep working with
 * exactly the headers apps/web/src/api.ts sends and no others.
 */

const AGENT = "11111111-1111-4111-8111-111111111111";
const RUN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
/** the docker bridge gateway: what a turn's own container sees of the host control plane */
const OFF_BOX = "172.17.0.1";
/** the one header apps/web/src/api.ts adds to every POST, PUT, PATCH and DELETE */
const PANEL_MUTATION = { "x-shadow-commit": "1" } as const;
const FIXTURE_TOKEN = "FIXTURE-KEY-NOT-REAL-operator-token";

interface Bench {
  root: string;
  deleted: string[];
  app(env?: Record<string, string>): Promise<Awaited<ReturnType<typeof createApp>>>;
}

/** One data directory holding one held turn, so the timeline has something worth taking. */
async function bench(): Promise<Bench> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "operator-guard-"));
  const deleted: string[] = [];
  const service = {
    listAgents: () => [{ id: AGENT, name: "cataloguer" }],
    getAgent: (id: string) => ({ id, name: "cataloguer" }),
    deleteAgent: async (id: string) => {
      deleted.push(id);
      return { archivedWorkspace: path.join(root, "archived") };
    },
    systemInfo: async () => ({ platform: "test" }),
  } as unknown as AgentService;

  const lines = [
    { seq: 1, runId: RUN, agentId: AGENT, kind: "turn.begin", prev: "x", mechanism: "copy" },
    {
      seq: 2,
      runId: RUN,
      agentId: AGENT,
      kind: "turn.held",
      prev: "x",
      rule: "manifest-script-change",
      effects: [{ path: "deploy/credentials.env", kind: "modify", bytes: 12 }],
    },
  ];
  await fs.writeFile(
    path.join(root, "journal.jsonl"),
    lines.map((line) => JSON.stringify(line)).join("\n") + "\n",
  );

  return {
    root,
    deleted,
    async app(env = {}) {
      return createApp(loadConfig({ NODE_ENV: "test", APP_DATA_DIR: root, ...env }), service);
    },
  };
}

describe("every /api route answers the operator, not only the review routes", () => {
  it("refuses a delete from off the box when no token is configured", async () => {
    const b = await bench();
    const app = await b.app();

    const response = await app.inject({
      method: "DELETE",
      url: `/api/agents/${AGENT}`,
      headers: PANEL_MUTATION,
      remoteAddress: OFF_BOX,
    });

    expect(response.statusCode).toBe(403);
    // and the refusal happened before the service was asked, not after it archived the workspace
    expect(b.deleted).toEqual([]);

    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });

  it("refuses a journal read from off the box, and sends none of the timeline with the refusal", async () => {
    const b = await bench();
    const app = await b.app();

    const response = await app.inject({
      method: "GET",
      url: `/api/agents/${AGENT}/journal?limit=50`,
      remoteAddress: OFF_BOX,
    });

    expect(response.statusCode).toBe(403);
    expect(response.body).not.toContain("deploy/credentials.env");
    expect(response.body).not.toContain("manifest-script-change");

    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });

  it("refuses the rest of the agent surface from off the box too", async () => {
    const b = await bench();
    const app = await b.app();

    for (const call of [
      { method: "GET" as const, url: "/api/agents" },
      { method: "GET" as const, url: `/api/agents/${AGENT}` },
      { method: "GET" as const, url: "/api/system" },
      { method: "GET" as const, url: `/api/agents/${AGENT}/capability-grant` },
    ]) {
      const response = await app.inject({ ...call, remoteAddress: OFF_BOX });
      expect([call.url, response.statusCode]).toEqual([call.url, 403]);
      expect(response.body).not.toContain("cataloguer");
    }

    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });
});

describe("ordinary work still goes through", () => {
  it("leaves the liveness probe and the token question open to a caller with no credential", async () => {
    const b = await bench();
    const app = await b.app();

    const health = await app.inject({ method: "GET", url: "/api/health", remoteAddress: OFF_BOX });
    expect(health.statusCode).toBe(200);
    expect(health.json()).toMatchObject({ ok: true });

    // the panel asks this before it has a token, so it cannot be behind the token
    const auth = await app.inject({ method: "GET", url: "/api/auth", remoteAddress: OFF_BOX });
    expect(auth.statusCode).toBe(200);
    expect(auth.json()).toEqual({ required: false });

    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });

  it("lets the panel in the operator's own browser do its whole job with the headers it actually sends", async () => {
    const b = await bench();
    const app = await b.app();

    // GET: apps/web/src/api.ts sends no headers at all when no token is set
    const listed = await app.inject({ method: "GET", url: "/api/agents" });
    expect(listed.statusCode).toBe(200);
    expect(listed.json()).toEqual({ agents: [{ id: AGENT, name: "cataloguer" }] });

    const system = await app.inject({ method: "GET", url: "/api/system" });
    expect(system.statusCode).toBe(200);

    const timeline = await app.inject({ method: "GET", url: `/api/agents/${AGENT}/journal?limit=50` });
    expect(timeline.statusCode).toBe(200);
    expect(timeline.body).toContain("deploy/credentials.env");

    // and a mutation, which carries x-shadow-commit and nothing else
    const removed = await app.inject({
      method: "DELETE",
      url: `/api/agents/${AGENT}`,
      headers: PANEL_MUTATION,
    });
    expect(removed.statusCode).toBe(200);
    expect(b.deleted).toEqual([AGENT]);

    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });

  it("lets a remote operator work once a token is configured and presented", async () => {
    const b = await bench();
    const app = await b.app({ APP_AUTH_TOKEN: FIXTURE_TOKEN });

    const credentialled = {
      authorization: "Bearer " + FIXTURE_TOKEN,
    };

    const listed = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: credentialled,
      remoteAddress: OFF_BOX,
    });
    expect(listed.statusCode).toBe(200);

    const removed = await app.inject({
      method: "DELETE",
      url: `/api/agents/${AGENT}`,
      headers: { ...credentialled, ...PANEL_MUTATION },
      remoteAddress: OFF_BOX,
    });
    expect(removed.statusCode).toBe(200);
    expect(b.deleted).toEqual([AGENT]);

    // a wrong token is still refused, and by the token hook, so the caller is told to authenticate
    const forged = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Bearer FIXTURE-KEY-NOT-REAL-wrong" },
      remoteAddress: OFF_BOX,
    });
    expect(forged.statusCode).toBe(401);

    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });
});

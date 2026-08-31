import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { apiSurfaceOf, createApp, type ApiSurface } from "./app.js";
import { loadConfig } from "./config.js";
import { TransactionalRunner } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import type { AgentService } from "./agent-service.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/**
 * Round two on J6 and J7 together. Both lanes moved the same boundary, so this file states the
 * whole of it once and pins the four places the round-one fixes got it wrong.
 *
 * The rule, entire: every /api route answers the operator only, the operator is whoever presents
 * APP_AUTH_TOKEN or, failing that, a caller on this machine's loopback, and settling a review
 * additionally refuses bare loopback whenever the agent's turn runs on this host's own network
 * stack, because there loopback cannot tell the agent from the operator.
 */

const AGENT = "11111111-1111-4111-8111-111111111111";
/** the docker bridge gateway: what a confined turn sees of the host control plane */
const OFF_BOX = "172.17.0.1";
const PANEL_MUTATION = { "x-shadow-commit": "1" } as const;
const FIXTURE_TOKEN = "FIXTURE-KEY-NOT-REAL-operator-boundary";

/** the real unconfined deployment: a host process, which runner-factory accepts only with the flag */
const UNCONFINED = { RUNTIME_PROVIDER: "local-process", SHADOW_ALLOW_UNCONFINED: "1" } as const;
/** what .env.example actually ships: a container runtime with the flag also set */
const CONFINED_WITH_FLAG = { RUNTIME_PROVIDER: "container", SHADOW_ALLOW_UNCONFINED: "1" } as const;

interface Bench {
  root: string;
  deleted: string[];
  app(env?: Record<string, string>): Promise<Awaited<ReturnType<typeof createApp>>>;
}

async function bench(): Promise<Bench> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "operator-boundary-"));
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
    { seq: 1, runId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agentId: AGENT, kind: "turn.begin", prev: "x" },
    {
      seq: 2,
      runId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
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

const reviewService = {
  listAgents: () => [],
  systemInfo: async () => ({}),
} as unknown as AgentService;

const scriptRunner = (act: (ws: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

/** a turn whose change needs a human: a package manifest gaining an install hook */
async function heldTurn() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "operator-boundary-review-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await fs.writeFile(path.join(ws, "package.json"), '{"name":"x"}\n');
  const runner = new TransactionalRunner(
    scriptRunner(async (w) => {
      await fs.writeFile(path.join(w, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
    }),
    { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy },
  );
  await runner.run({ agentId: AGENT, workspacePath: ws, prompt: "p", threadId: null });
  return { runner, root, ws };
}

/** the ids the attack needs, read once under the confined default */
async function heldIds(runner: TransactionalRunner) {
  const reading = await createApp(loadConfig({ NODE_ENV: "test" }), reviewService, runner);
  const listed = await reading.inject({ method: "GET", url: "/api/reviews" });
  const [held] = (listed.json() as { reviews: { runId: string; effectSetHash: string }[] }).reviews;
  await reading.close();
  expect(held).toBeDefined();
  return held!;
}

describe("the guard reads the path the router will match, not the one the caller typed", () => {
  /** Fastify decodes before it routes, so all three of these reach the /api/agents handler. */
  const ENCODED_PREFIX = ["/%61pi/agents", "/a%70i/agents", "/ap%69/agents"];

  it("refuses a percent-encoded /api/ prefix from off the box", async () => {
    const b = await bench();
    const app = await b.app();
    for (const url of ENCODED_PREFIX) {
      const response = await app.inject({ method: "GET", url, remoteAddress: OFF_BOX });
      expect([url, response.statusCode]).toEqual([url, 403]);
      expect(response.body).not.toContain("cataloguer");
    }
    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });

  it("refuses an encoded-prefix delete, with no preflight header and no credential", async () => {
    const b = await bench();
    const app = await b.app();
    const response = await app.inject({
      method: "DELETE",
      url: `/%61pi/agents/${AGENT}`,
      remoteAddress: OFF_BOX,
    });
    expect(response.statusCode).toBe(403);
    expect(b.deleted).toEqual([]);
    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });

  it("refuses an encoded-prefix journal read, and sends none of the timeline with the refusal", async () => {
    const b = await bench();
    const app = await b.app();
    const response = await app.inject({
      method: "GET",
      url: `/%61pi/agents/${AGENT}/journal?limit=50`,
      remoteAddress: OFF_BOX,
    });
    expect(response.statusCode).toBe(403);
    expect(response.body).not.toContain("deploy/credentials.env");
    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });

  it("does not let an encoded prefix walk past a configured token either", async () => {
    const b = await bench();
    const app = await b.app({ APP_AUTH_TOKEN: FIXTURE_TOKEN });
    const response = await app.inject({
      method: "GET",
      url: "/%61pi/agents",
      remoteAddress: OFF_BOX,
    });
    expect(response.statusCode).toBe(401);
    expect(response.body).not.toContain("cataloguer");
    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });

});

describe("one classifier, so no two hooks can disagree about a path again", () => {
  it("puts every spelling of a path on the surface the router will send it to", () => {
    const cases: [string, ApiSurface][] = [
      ["/", "not-api"],
      ["/index.html", "not-api"],
      ["/apidocs", "not-api"],
      ["/api/agents", "control"],
      ["/api/agents?ts=1", "control"],
      ["/%61pi/agents", "control"],
      ["/a%70i/agents", "control"],
      ["/ap%69/agents", "control"],
      ["/api%2fagents", "control"],
      ["/api/health", "open"],
      ["/api/health?ts=1", "open"],
      ["/api/auth", "open"],
      ["/api/auth?ts=1", "open"],
      // a trailing slash is a different path, and the router has no route for it
      ["/api/health/", "control"],
      ["/api/reviews", "review"],
      ["/api/reviews?ts=1", "review"],
      ["/api/reviews/aaaa/approve", "review"],
      // the stricter tier wins when the two spellings disagree
      ["/api/%72eviews/aaaa/approve", "review"],
      ["/%61pi/reviews/aaaa/approve", "review"],
      // ... including at the open tier, which used to be decided from the decoded spelling alone,
      // so an encoding could demote a route into "open" while no encoding could promote one into
      // "control". One path, two readings, opposite strictness is how the last bypass got in.
      ["/api%2fhealth", "control"],
      ["/api%2fauth", "control"],
      ["/%61pi/health", "control"],
      // absolute form, which the router strips to the origin form before it matches (main's fix,
      // pinned here so the classifier and the live socket test cannot drift apart again)
      ["http://host:3000/api/agents", "control"],
      ["https://host/api/reviews/aaaa/approve", "review"],
      ["http://host:3000/api/health", "open"],
      ["http://host:3000/index.html", "not-api"],
    ];
    for (const [url, expected] of cases) {
      expect([url, apiSurfaceOf(url)]).toEqual([url, expected]);
    }
  });

  it("does not throw on an escape it cannot decode, and keeps it guarded", () => {
    expect(apiSurfaceOf("/api/agents%zz")).toBe("control");
    expect(apiSurfaceOf("/api/health%")).toBe("control");
    expect(apiSurfaceOf("/static/%zz.css")).toBe("not-api");
  });
});

describe("a container runtime keeps its review surface even with SHADOW_ALLOW_UNCONFINED set", () => {
  it("lets the loopback operator list and approve under the combination .env.example ships", async () => {
    const { runner, root, ws } = await heldTurn();
    const held = await heldIds(runner);
    const config = loadConfig({ NODE_ENV: "test", ...CONFINED_WITH_FLAG });
    expect(config.shadowAllowUnconfined).toBe(true);
    expect(config.runtimeProvider).toBe("container");

    const app = await createApp(config, reviewService, runner);
    const listed = await app.inject({ method: "GET", url: "/api/reviews" });
    expect(listed.statusCode).toBe(200);

    const approved = await app.inject({
      method: "POST",
      url: `/api/reviews/${held.runId}/approve`,
      headers: PANEL_MUTATION,
      payload: { effectSetHash: held.effectSetHash },
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json()).toMatchObject({ actor: "operator" });
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toContain("postinstall");

    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the unconfined developer path stays usable, and still cannot settle a turn", () => {
  it("answers the loopback developer on the control plane with no token configured", async () => {
    const b = await bench();
    const app = await b.app(UNCONFINED);

    for (const url of ["/api/agents", "/api/system", `/api/agents/${AGENT}/journal?limit=50`]) {
      const response = await app.inject({ method: "GET", url });
      expect([url, response.statusCode]).toEqual([url, 200]);
    }
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

  it("still refuses that same loopback caller the authority to settle a review", async () => {
    const { runner, root, ws } = await heldTurn();
    const held = await heldIds(runner);
    const app = await createApp(loadConfig({ NODE_ENV: "test", ...UNCONFINED }), reviewService, runner);

    const selfApproved = await app.inject({
      method: "POST",
      url: `/api/reviews/${held.runId}/approve`,
      headers: PANEL_MUTATION,
      payload: { effectSetHash: held.effectSetHash },
    });
    expect(selfApproved.statusCode).toBe(403);
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.not.toContain("postinstall");
    await expect(runner.pendingReviews()).resolves.toHaveLength(1);

    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("still refuses the whole control plane from off the box in that configuration", async () => {
    const b = await bench();
    const app = await b.app(UNCONFINED);
    const response = await app.inject({ method: "GET", url: "/api/agents", remoteAddress: OFF_BOX });
    expect(response.statusCode).toBe(403);
    expect(response.body).not.toContain("cataloguer");
    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });
});

describe("each refusal names the thing that is actually wrong", () => {
  it("tells an off-box caller it is off the box, and an unconfined one why loopback proves nothing", async () => {
    const b = await bench();
    const offBoxApp = await b.app();
    const offBox = await offBoxApp.inject({
      method: "GET",
      url: "/api/agents",
      remoteAddress: OFF_BOX,
    });
    const offBoxReason = (offBox.json() as { error: string }).error;
    expect(offBoxReason).toContain("answers the local operator only");
    await offBoxApp.close();

    const { runner, root } = await heldTurn();
    const unconfinedApp = await createApp(
      loadConfig({ NODE_ENV: "test", ...UNCONFINED }),
      reviewService,
      runner,
    );
    const unconfined = await unconfinedApp.inject({ method: "GET", url: "/api/reviews" });
    const unconfinedReason = (unconfined.json() as { error: string }).error;
    expect(unconfinedReason).toContain("shares the host network with the agent");
    expect(unconfinedReason).not.toEqual(offBoxReason);
    await unconfinedApp.close();

    await fs.rm(b.root, { recursive: true, force: true });
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the token hook and the operator hook agree on which paths are open", () => {
  it("keeps the liveness probe and the token question open with a query string attached", async () => {
    const b = await bench();
    const app = await b.app({ APP_AUTH_TOKEN: FIXTURE_TOKEN });

    for (const url of ["/api/health", "/api/health?ts=1", "/api/auth", "/api/auth?ts=1"]) {
      const response = await app.inject({ method: "GET", url, remoteAddress: OFF_BOX });
      expect([url, response.statusCode]).toEqual([url, 200]);
    }
    // and nothing else opens with one
    const guarded = await app.inject({ method: "GET", url: "/api/agents?ts=1", remoteAddress: OFF_BOX });
    expect(guarded.statusCode).toBe(401);

    await app.close();
    await fs.rm(b.root, { recursive: true, force: true });
  });
});

describe("what this boundary does not achieve is written down where an operator will read it", () => {
  it("says in SECURITY.md that an unconfined host process is beside the control plane, not behind it", async () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
    const text = await fs.readFile(path.join(repoRoot, "SECURITY.md"), "utf8");
    expect(text).toContain("SHADOW_ALLOW_UNCONFINED");
    expect(text).toContain("APP_AUTH_TOKEN");
    expect(text.toLowerCase()).toContain("no filesystem jail");
  });
});

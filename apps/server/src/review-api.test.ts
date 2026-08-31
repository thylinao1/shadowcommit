import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { TransactionalRunner } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import type { Policy } from "./policy-types.js";
import type { AgentService } from "./agent-service.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const service = { listAgents: () => [], systemInfo: async () => ({}) } as unknown as AgentService;

const scriptRunner = (act: (ws: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

/** every mutating call a first-party caller makes carries the forced-preflight header */
const OPERATOR = { "x-shadow-commit": "1" } as const;

interface ReviewedEffect {
  path: string;
  kind: string;
  effectClass: string;
  bytes: number;
  sha256: string;
  before: string | null;
  after: string | null;
}
interface ReviewedTurn {
  runId: string;
  rule: string;
  hits: Array<{ rule: string; decision: string }>;
  effectSetHash: string;
  effects: ReviewedEffect[];
  effectCount: number;
}

/** a turn whose change needs a human: a package manifest gaining an install hook */
async function heldTurn(policy: Policy = defaultPolicy) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "reviewapi-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await fs.writeFile(path.join(ws, "package.json"), '{"name":"x"}\n');
  const runner = new TransactionalRunner(
    scriptRunner(async (w) => {
      await fs.writeFile(path.join(w, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
    }),
    { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy },
  );
  await runner.run({ agentId: "11111111-1111-4111-8111-111111111111", workspacePath: ws, prompt: "p", threadId: null });
  return { runner, root, ws };
}

const journalOf = async (root: string): Promise<string> =>
  fs.readFile(path.join(root, "j.jsonl"), "utf8").catch(() => "");

describe("an operator can settle a held turn over HTTP", () => {
  it("shows what would land, then approves that exact set and the change lands", async () => {
    const { runner, root, ws } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);

    const listed = await app.inject({ method: "GET", url: "/api/reviews" });
    expect(listed.statusCode).toBe(200);
    const { reviews } = listed.json() as { reviews: ReviewedTurn[] };
    expect(reviews).toHaveLength(1);
    expect(reviews[0]!.rule).toBe("manifest-script-change");
    // a path list is not a review: the operator is shown the bytes on both sides
    expect(reviews[0]!.effects[0]!.after).toContain("postinstall");
    expect(reviews[0]!.effects[0]!.before).toContain('"name":"x"');
    expect(reviews[0]!.effects[0]!.bytes).toBeGreaterThan(0);
    expect(reviews[0]!.effects[0]!.kind).toBe("modify");
    expect(reviews[0]!.effects[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(reviews[0]!.effects[0]).toHaveProperty("effectClass");
    // every rule that fired, so a review-class hit cannot hide anything beside it. A hit also
    // carries the path it fired on and the detail that names why, which is what the panel renders
    // beside each proposed change; before lane A1's rule set landed a hit was the pair alone.
    expect(reviews[0]!.hits).toEqual([
      { rule: "manifest-script-change", decision: "review", path: "package.json", detail: "postinstall" },
    ]);
    expect(reviews[0]!.effectCount).toBe(1);
    expect(reviews[0]!.effectSetHash).toMatch(/^[0-9a-f]{64}$/);

    // nothing has been applied while it waits
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.not.toContain("postinstall");

    const approved = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/approve`,
      headers: OPERATOR,
      payload: { effectSetHash: reviews[0]!.effectSetHash },
    });
    expect(approved.statusCode).toBe(200);
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toContain("postinstall");

    const after = await app.inject({ method: "GET", url: "/api/reviews" });
    expect((after.json() as { reviews: unknown[] }).reviews).toHaveLength(0);
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("rejects a held turn and nothing reaches the workspace", async () => {
    const { runner, root, ws } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const { reviews } = (await app.inject({ method: "GET", url: "/api/reviews" })).json() as {
      reviews: ReviewedTurn[];
    };
    const rejected = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/reject`,
      headers: OPERATOR,
    });
    expect(rejected.statusCode).toBe(200);
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.not.toContain("postinstall");
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("refuses to approve something that is not pending", async () => {
    const { runner, root } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const missing = await app.inject({
      method: "POST",
      url: "/api/reviews/22222222-2222-4222-8222-222222222222/approve",
      headers: OPERATOR,
      payload: { effectSetHash: "0".repeat(64) },
    });
    expect(missing.statusCode).toBe(409);
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the review surface answers the operator, and only the operator", () => {
  it("r11: refuses a mutating request that carries no forced-preflight header", async () => {
    const { runner, root, ws } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const { reviews } = (await app.inject({ method: "GET", url: "/api/reviews" })).json() as {
      reviews: ReviewedTurn[];
    };
    // exactly the shape a cross-origin form post has: no custom header, so no preflight
    const forged = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/approve`,
      payload: { effectSetHash: reviews[0]!.effectSetHash },
    });
    expect(forged.statusCode).toBe(403);
    // and it is still waiting, unsettled
    await expect(runner.pendingReviews()).resolves.toHaveLength(1);
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.not.toContain("postinstall");
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r11: the same rule covers agent lifecycle routes, not only the review routes", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const deleted = await app.inject({
      method: "DELETE",
      url: "/api/agents/22222222-2222-4222-8222-222222222222",
    });
    expect(deleted.statusCode).toBe(403);
    await app.close();
  });

  it("r10: refuses a caller that is not on loopback when no token is configured", async () => {
    const { runner, root, ws } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const { reviews } = (await app.inject({ method: "GET", url: "/api/reviews" })).json() as {
      reviews: ReviewedTurn[];
    };
    // the docker bridge gateway: what the turn's own container sees of the host control plane
    const listed = await app.inject({
      method: "GET",
      url: "/api/reviews",
      remoteAddress: "172.17.0.1",
    });
    expect(listed.statusCode).toBe(403);
    const selfApproved = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/approve`,
      headers: OPERATOR,
      remoteAddress: "172.17.0.1",
      payload: { effectSetHash: reviews[0]!.effectSetHash },
    });
    expect(selfApproved.statusCode).toBe(403);
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.not.toContain("postinstall");
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r10: lets a remote caller through only with the configured token", async () => {
    const { runner, root, ws } = await heldTurn();
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      service,
      runner,
    );
    const listed = await app.inject({
      method: "GET",
      url: "/api/reviews",
      remoteAddress: "172.17.0.1",
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(listed.statusCode).toBe(200);
    const { reviews } = listed.json() as { reviews: ReviewedTurn[] };
    const approved = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/approve`,
      remoteAddress: "172.17.0.1",
      headers: { ...OPERATOR, authorization: "Bearer a-strong-test-token" },
      payload: { effectSetHash: reviews[0]!.effectSetHash },
    });
    expect(approved.statusCode).toBe(200);
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toContain("postinstall");
    // the principal is derived from the token that was presented, not from anything the caller typed
    expect(await journalOf(root)).toContain('"actor":"operator:');
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r13: records the authenticated principal and never the x-actor header", async () => {
    const { runner, root } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const { reviews } = (await app.inject({ method: "GET", url: "/api/reviews" })).json() as {
      reviews: ReviewedTurn[];
    };
    const approved = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/approve`,
      headers: { ...OPERATOR, "x-actor": "maksim" },
      payload: { effectSetHash: reviews[0]!.effectSetHash },
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json()).toMatchObject({ actor: "operator" });
    const journal = await journalOf(root);
    expect(journal).toContain('"actor":"operator"');
    expect(journal).not.toContain("maksim");
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("an approval names the exact changes the operator was shown", () => {
  it("r18: refuses an approval whose effect-set hash does not match", async () => {
    const { runner, root, ws } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const { reviews } = (await app.inject({ method: "GET", url: "/api/reviews" })).json() as {
      reviews: ReviewedTurn[];
    };
    const blind = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/approve`,
      headers: OPERATOR,
      payload: { effectSetHash: "a".repeat(64) },
    });
    expect(blind.statusCode).toBe(409);
    expect(blind.json()).toMatchObject({ error: expect.stringContaining("moved since you looked") });
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.not.toContain("postinstall");
    // still pending: a refused approval settles nothing
    await expect(runner.pendingReviews()).resolves.toHaveLength(1);
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r18: refuses an approval with no hash at all", async () => {
    const { runner, root } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const { reviews } = (await app.inject({ method: "GET", url: "/api/reviews" })).json() as {
      reviews: ReviewedTurn[];
    };
    const bare = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/approve`,
      headers: OPERATOR,
      payload: {},
    });
    expect(bare.statusCode).toBe(400);
    await expect(runner.pendingReviews()).resolves.toHaveLength(1);
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r07: judges the held set again at approval time and refuses a discard verdict", async () => {
    // The rules tightened while the turn waited. An approval that applies a set nobody judged
    // again is an approval of whatever the rules used to allow.
    let calls = 0;
    const tightening: Policy = async () => {
      calls += 1;
      return calls === 1
        ? { decision: "review", rule: "manifest-script-change" }
        : { decision: "discard", rule: "remote-code-execution-added" };
    };
    const { runner, root, ws } = await heldTurn(tightening);
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const { reviews } = (await app.inject({ method: "GET", url: "/api/reviews" })).json() as {
      reviews: ReviewedTurn[];
    };
    const approved = await app.inject({
      method: "POST",
      url: `/api/reviews/${reviews[0]!.runId}/approve`,
      headers: OPERATOR,
      payload: { effectSetHash: reviews[0]!.effectSetHash },
    });
    expect(approved.statusCode).toBe(409);
    expect(approved.json()).toMatchObject({
      error: expect.stringContaining("remote-code-execution-added"),
    });
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.not.toContain("postinstall");
    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });
});

import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { TransactionalRunner } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import type { AgentService } from "./agent-service.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/**
 * J6: loopback alone is not proof of an operator once the agent shares this host's network.
 *
 * When RUNTIME_PROVIDER is not "container" the turn runs as a host process on the same network
 * stack as the control plane. Its loopback is our loopback. A review surface that treats a loopback
 * address as "operator" therefore lets the agent approve the turn it is held for, and the
 * hash-chained journal then attests an operator sign-off that never happened. A tamper-evident
 * record of a lie is worse than no record.
 *
 * Round two: these cases first set SHADOW_ALLOW_UNCONFINED=1 on its own and called that unconfined,
 * which is wrong twice over. The flag is only runner-factory's permission to accept a host-process
 * runtime at all, and with the default RUNTIME_PROVIDER=container the turn still gets its own
 * network namespace, so its packets never arrive on our loopback. Reading the flag as if it moved
 * the turn onto this host cost the shipped .env.example combination its whole review surface. The
 * env below is now the real unconfined deployment: the host-process provider, plus the flag that
 * runner-factory demands before it will start one. operator-boundary.test.ts holds the negative,
 * that a container runtime with the flag set keeps its review surface.
 */

const service = { listAgents: () => [], systemInfo: async () => ({}) } as unknown as AgentService;

/** every mutating call a first-party caller makes carries the forced-preflight header */
const PREFLIGHT = { "x-shadow-commit": "1" } as const;

/** fixture only, never a real credential */
const FIXTURE_TOKEN = "FIXTURE-KEY-NOT-REAL-j6";

const scriptRunner = (act: (ws: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

interface ReviewedTurn {
  runId: string;
  effectSetHash: string;
}

/** a turn whose change needs a human: a package manifest gaining an install hook */
async function heldTurn() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "j6-principal-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await fs.writeFile(path.join(ws, "package.json"), '{"name":"x"}\n');
  const runner = new TransactionalRunner(
    scriptRunner(async (w) => {
      await fs.writeFile(path.join(w, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
    }),
    {
      shadowRoot: path.join(root, "sh"),
      journalPath: path.join(root, "j.jsonl"),
      policy: defaultPolicy,
    },
  );
  await runner.run({
    agentId: "11111111-1111-4111-8111-111111111111",
    workspacePath: ws,
    prompt: "p",
    threadId: null,
  });
  return { runner, root, ws };
}

const journalOf = async (root: string): Promise<string> =>
  fs.readFile(path.join(root, "j.jsonl"), "utf8").catch(() => "");

/** the queue as the operator sees it, read with whatever credential the caller has */
async function queue(
  app: Awaited<ReturnType<typeof createApp>>,
  headers: Record<string, string> = {},
): Promise<ReviewedTurn[]> {
  const listed = await app.inject({ method: "GET", url: "/api/reviews", headers });
  return (listed.json() as { reviews: ReviewedTurn[] }).reviews;
}

describe("J6: an unconfined runtime cannot self-approve from loopback", () => {
  it("refuses a loopback approve with no credential when unconfined turns are allowed", async () => {
    const { runner, root, ws } = await heldTurn();
    // the queue is read once under the confined default, only to learn the ids the attack needs;
    // an agent on the host learns the same two values from the run it is held for
    const reading = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const [held] = await queue(reading);
    await reading.close();
    expect(held).toBeDefined();

    const app = await createApp(
      loadConfig({ NODE_ENV: "test", RUNTIME_PROVIDER: "local-process", SHADOW_ALLOW_UNCONFINED: "1" }),
      service,
      runner,
    );
    // app.inject defaults to 127.0.0.1, which is exactly what a host-process agent has
    const selfApproved = await app.inject({
      method: "POST",
      url: `/api/reviews/${held!.runId}/approve`,
      headers: PREFLIGHT,
      payload: { effectSetHash: held!.effectSetHash },
    });
    expect([401, 403]).toContain(selfApproved.statusCode);
    // and the refusal says which control fired, not just that one did
    expect((selfApproved.json() as { error: string }).error).toContain(
      "shares the host network with the agent",
    );

    // nothing landed, nothing settled, and the journal attests no operator
    await expect(
      fs.readFile(path.join(ws, "package.json"), "utf8"),
    ).resolves.not.toContain("postinstall");
    await expect(runner.pendingReviews()).resolves.toHaveLength(1);
    expect(await journalOf(root)).not.toContain('"actor":"operator"');

    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("refuses the same loopback approve when the runtime provider is a host process", async () => {
    const { runner, root, ws } = await heldTurn();
    const reading = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const [held] = await queue(reading);
    await reading.close();

    const app = await createApp(
      loadConfig({ NODE_ENV: "test", RUNTIME_PROVIDER: "local-process" }),
      service,
      runner,
    );
    const listed = await app.inject({ method: "GET", url: "/api/reviews" });
    expect([401, 403]).toContain(listed.statusCode);
    const selfApproved = await app.inject({
      method: "POST",
      url: `/api/reviews/${held!.runId}/approve`,
      headers: PREFLIGHT,
      payload: { effectSetHash: held!.effectSetHash },
    });
    expect([401, 403]).toContain(selfApproved.statusCode);
    await expect(
      fs.readFile(path.join(ws, "package.json"), "utf8"),
    ).resolves.not.toContain("postinstall");
    expect(await journalOf(root)).not.toContain('"actor":"operator"');

    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("still settles for a real operator in that configuration, on the presented credential", async () => {
    const { runner, root, ws } = await heldTurn();
    const app = await createApp(
      loadConfig({
        NODE_ENV: "test",
        RUNTIME_PROVIDER: "local-process",
        SHADOW_ALLOW_UNCONFINED: "1",
        APP_AUTH_TOKEN: FIXTURE_TOKEN,
      }),
      service,
      runner,
    );
    const auth = { authorization: "Bearer " + FIXTURE_TOKEN };
    const [held] = await queue(app, auth);
    const approved = await app.inject({
      method: "POST",
      url: `/api/reviews/${held!.runId}/approve`,
      headers: { ...PREFLIGHT, ...auth },
      payload: { effectSetHash: held!.effectSetHash },
    });
    expect(approved.statusCode).toBe(200);
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toContain(
      "postinstall",
    );
    // the actor is derived from the credential that was actually presented, never bare "operator"
    expect(approved.json()).toMatchObject({ actor: expect.stringMatching(/^operator:[0-9a-f]{12}$/) });
    expect(await journalOf(root)).toContain('"actor":"operator:');

    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("J6 negative case: the ordinary confined operator path is untouched", () => {
  it("a loopback operator with no token still lists and approves under the container default", async () => {
    const { runner, root, ws } = await heldTurn();
    const config = loadConfig({ NODE_ENV: "test" });
    expect(config.runtimeProvider).toBe("container");
    expect(config.shadowAllowUnconfined).toBe(false);

    const app = await createApp(config, service, runner);
    const listed = await app.inject({ method: "GET", url: "/api/reviews" });
    expect(listed.statusCode).toBe(200);
    const [held] = (listed.json() as { reviews: ReviewedTurn[] }).reviews;

    const approved = await app.inject({
      method: "POST",
      url: `/api/reviews/${held!.runId}/approve`,
      headers: PREFLIGHT,
      payload: { effectSetHash: held!.effectSetHash },
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json()).toMatchObject({ actor: "operator" });
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toContain(
      "postinstall",
    );
    expect(await journalOf(root)).toContain('"actor":"operator"');

    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("a loopback operator can still reject under the container default", async () => {
    const { runner, root, ws } = await heldTurn();
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service, runner);
    const [held] = await queue(app);
    const rejected = await app.inject({
      method: "POST",
      url: `/api/reviews/${held!.runId}/reject`,
      headers: PREFLIGHT,
    });
    expect(rejected.statusCode).toBe(200);
    expect(rejected.json()).toMatchObject({ actor: "operator" });
    await expect(
      fs.readFile(path.join(ws, "package.json"), "utf8"),
    ).resolves.not.toContain("postinstall");

    await app.close();
    await fs.rm(root, { recursive: true, force: true });
  });
});

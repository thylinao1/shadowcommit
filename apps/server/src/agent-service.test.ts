import { mkdtemp } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import { loadConfig } from "./config.js";
import { JsonStore } from "./store.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

class FakeRunner implements AgentRunner {
  async run(request: RunnerRequest): Promise<RunnerResult> {
    return {
      output: "Completed: " + request.prompt,
      threadId: request.threadId ?? "fake-thread",
      usage: { inputTokens: 12, outputTokens: 5 },
    };
  }
  async cancel(): Promise<boolean> {
    return false;
  }
  async isAvailable(): Promise<boolean> {
    return true;
  }
}

const temporaryDirectories: string[] = [];

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function makeService(runner: AgentRunner = new FakeRunner()): Promise<AgentService> {
  const root = await mkdtemp(path.join(tmpdir(), "launchpad-test-"));
  temporaryDirectories.push(root);
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    AGENT_WORKSPACE_ROOT: path.join(root, "workspaces"),
    CODEX_HOME: path.join(root, "codex"),
    ARK_API_KEY: "test-key",
    ARK_MODEL: "ep-test",
  });
  const service = new AgentService(
    config,
    new JsonStore(path.join(root, "data", "db.json")),
    new WorkspaceManager(path.join(root, "workspaces")),
    runner,
  );
  await service.initialize();
  return service;
}

describe("Agent lifecycle", () => {
  it("creates, updates, stops, starts and deletes an Agent", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Builder" });
    expect(service.listAgents()).toHaveLength(1);
    expect((await service.updateAgent(agent.id, { description: "Builds apps" })).description)
      .toBe("Builds apps");
    expect((await service.stopAgent(agent.id)).status).toBe("stopped");
    expect((await service.startAgent(agent.id)).status).toBe("ready");
    await service.deleteAgent(agent.id);
    expect(service.listAgents()).toHaveLength(0);
  });

  it("persists a playground conversation", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Coder" });
    const { run } = await service.sendMessage(agent.id, "write hello world");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    const messages = service.getMessages(agent.id);
    expect(messages.map((message) => message.role)).toEqual(["user", "assistant"]);
    expect(messages[1]?.content).toContain("write hello world");
    expect(service.getAgent(agent.id).codexThreadId).toBe("fake-thread");
  });

  it("atomically accepts only one concurrent run per Agent", async () => {
    let finish!: (result: RunnerResult) => void;
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const runner: AgentRunner = {
      run: () => pending,
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const service = await makeService(runner);
    const agent = await service.createAgent({ name: "Concurrent" });
    const attempts = await Promise.allSettled([
      service.sendMessage(agent.id, "first"),
      service.sendMessage(agent.id, "second"),
    ]);

    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
    const rejected = attempts.find((attempt) => attempt.status === "rejected");
    expect(rejected).toMatchObject({ reason: { statusCode: 409 } });
    expect(service.getMessages(agent.id)).toHaveLength(1);

    finish({ output: "done", threadId: "thread", usage: null });
    const accepted = attempts.find((attempt) => attempt.status === "fulfilled");
    if (accepted?.status === "fulfilled") {
      await expect.poll(() => service.getRun(accepted.value.run.id).status).toBe("completed");
    }
  });

  it("does not let start reset a busy Agent and admit a second run", async () => {
    let finish!: (result: RunnerResult) => void;
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const service = await makeService({
      run: () => pending,
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Busy" });
    const { run } = await service.sendMessage(agent.id, "first");

    await expect(service.startAgent(agent.id)).rejects.toMatchObject({ statusCode: 409 });
    await expect(service.sendMessage(agent.id, "second")).rejects.toMatchObject({
      statusCode: 409,
    });

    finish({ output: "done", threadId: "thread", usage: null });
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
  });
});

describe("a turn the boundary did not apply is not a completed run", () => {
  const containedRunner = (decision: "discard" | "review" | "conflict", rule: string): AgentRunner => ({
    run: async () => ({
      output: "I completed the task and updated the files.\n\n[blocked by policy: " + rule + "]",
      threadId: "thread",
      usage: null,
      containment: {
        runId: "11111111-1111-4111-8111-111111111111",
        decision,
        rule,
        effects: 2,
        paths: ["customers.jsonl", "index.js"],
      },
    }),
    cancel: async () => false,
    isAvailable: async () => true,
  });

  it("records a discarded turn as contained, with the verdict and the paths it stopped", async () => {
    const service = await makeService(containedRunner("discard", "protected-asset-delete"));
    const agent = await service.createAgent({ name: "Blocked" });
    const { run } = await service.sendMessage(agent.id, "delete the customer file");
    await expect.poll(() => service.getRun(run.id).status).toBe("contained");
    const stored = service.getRun(run.id);
    expect(stored.containment).toMatchObject({
      decision: "discard",
      rule: "protected-asset-delete",
      effects: 2,
      paths: ["customers.jsonl", "index.js"],
    });
    // the agent's own success sentence is still there, and no longer the whole story
    expect(stored.output).toContain("blocked by policy");
  });

  it("records a held turn as contained rather than completed", async () => {
    const service = await makeService(containedRunner("review", "manifest-script-change"));
    const agent = await service.createAgent({ name: "Held" });
    const { run } = await service.sendMessage(agent.id, "add a postinstall hook");
    await expect.poll(() => service.getRun(run.id).status).toBe("contained");
  });

  it("still records an applied turn as completed", async () => {
    const service = await makeService({
      run: async () => ({
        output: "done",
        threadId: "thread",
        usage: null,
        containment: {
          runId: "22222222-2222-4222-8222-222222222222",
          decision: "commit" as const,
          rule: "none",
          effects: 1,
          paths: ["index.js"],
        },
      }),
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Applied" });
    const { run } = await service.sendMessage(agent.id, "edit index.js");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    expect(service.getRun(run.id).containment?.decision).toBe("commit");
  });

  it("leaves an unwrapped runner's turns exactly as they were", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Plain" });
    const { run } = await service.sendMessage(agent.id, "hello");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    expect(service.getRun(run.id).containment).toBeNull();
  });
});

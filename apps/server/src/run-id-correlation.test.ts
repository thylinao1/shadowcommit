import { mkdtemp, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import { loadConfig } from "./config.js";
import { JsonStore } from "./store.js";
import { TransactionalRunner } from "./transactional-runner.js";
import { WorkspaceManager } from "./workspace.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/**
 * One turn, one identifier.
 *
 * Driving the whole journey against a running server found the seam: the control plane minted a
 * run id for the Playground and the run history, the transaction minted a different one for the
 * journal, the review queue and the timeline, and nothing on the platform joined them. A reviewer
 * reading a committed run could not find its own turn in the run timeline, and
 * `POST /api/reviews/:id/approve` quietly took a different id from `GET /api/runs/:id`.
 *
 * These tests are the two halves of the fix, so it cannot come apart again: the control plane
 * passes its run id down, and the transaction adopts it rather than generating its own.
 */

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function makeRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "run-id-"));
  temporaryDirectories.push(root);
  return root;
}

class RecordingRunner implements AgentRunner {
  public requests: RunnerRequest[] = [];
  async run(request: RunnerRequest): Promise<RunnerResult> {
    this.requests.push(request);
    return { output: "done", threadId: null, usage: null };
  }
  async cancel(): Promise<boolean> {
    return false;
  }
  async isAvailable(): Promise<boolean> {
    return true;
  }
}

/** Waits for the asynchronous run the control plane starts to reach a terminal state. */
async function settled(service: AgentService, agentId: string, runId: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const run = service.getRuns(agentId).find((entry) => entry.id === runId);
    if (run && run.status !== "queued" && run.status !== "running") return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("the run never settled");
}

describe("the control plane's run id is the turn's only id", () => {
  it("passes its run id down to the runner", async () => {
    const root = await makeRoot();
    const config = loadConfig({
      NODE_ENV: "test",
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: path.join(root, "workspaces"),
      CODEX_HOME: path.join(root, "codex"),
      ARK_API_KEY: "test-key",
      ARK_MODEL: "ep-test",
    });
    const runner = new RecordingRunner();
    const service = new AgentService(
      config,
      new JsonStore(path.join(root, "data", "db.json")),
      new WorkspaceManager(path.join(root, "workspaces")),
      runner,
    );
    await service.initialize();
    const agent = await service.createAgent({ name: "Builder" });
    const { run } = await service.sendMessage(agent.id, "do the thing");
    await settled(service, agent.id, run.id);

    expect(runner.requests).toHaveLength(1);
    expect(runner.requests[0]?.runId).toBe(run.id);
  });

  it("journals the turn under that id, so the run history joins the timeline", async () => {
    const root = await makeRoot();
    const workspace = path.join(root, "workspace");
    const journalPath = path.join(root, "journal.jsonl");
    const inner: AgentRunner = {
      isAvailable: async () => true,
      cancel: async () => false,
      run: async () => ({ output: "done", threadId: null, usage: null }),
    };
    const runner = new TransactionalRunner(inner, {
      shadowRoot: path.join(root, "shadows"),
      journalPath,
      policy: async () => ({ decision: "commit", rule: "none" }),
    });
    await rm(workspace, { recursive: true, force: true });
    const { mkdir } = await import("node:fs/promises");
    await mkdir(workspace, { recursive: true });

    const platformRunId = "11111111-2222-4333-8444-555555555555";
    const result = await runner.run({
      agentId: "agent-1",
      workspacePath: workspace,
      prompt: "p",
      threadId: null,
      runId: platformRunId,
    });
    await runner.closeJournal();

    expect(result.containment?.runId).toBe(platformRunId);
    const journal = await readFile(journalPath, "utf8");
    const ids = journal
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as { runId?: string })
      .map((record) => record.runId)
      .filter(Boolean);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids)).toEqual(new Set([platformRunId]));
  });

  it("still mints one for a caller that has no run of its own", async () => {
    const root = await makeRoot();
    const workspace = path.join(root, "workspace");
    const { mkdir } = await import("node:fs/promises");
    await mkdir(workspace, { recursive: true });
    const runner = new TransactionalRunner(
      {
        isAvailable: async () => true,
        cancel: async () => false,
        run: async () => ({ output: "done", threadId: null, usage: null }),
      },
      {
        shadowRoot: path.join(root, "shadows"),
        journalPath: path.join(root, "journal.jsonl"),
        policy: async () => ({ decision: "commit", rule: "none" }),
      },
    );
    const result = await runner.run({
      agentId: "agent-1",
      workspacePath: workspace,
      prompt: "p",
      threadId: null,
    });
    await runner.closeJournal();
    expect(result.containment?.runId).toMatch(/^[0-9a-f-]{36}$/);
  });
});

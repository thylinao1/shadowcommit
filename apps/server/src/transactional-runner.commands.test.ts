/**
 * A turn whose command was killed must not read like a turn whose command succeeded.
 *
 * codex stops waiting for a shell command at ten seconds and reports it as
 * `{exit_code: 124, status: "failed"}`, then finishes the turn normally and emits `turn.completed`.
 * Before this, the runner read only the agent's final message and the usage block, so that turn
 * reached `turn.executed` with `exit: "ok"` and nothing else, identical to a clean turn. The
 * command's half-finished work was captured and committed with nothing on record saying it never
 * finished.
 *
 * The captured streams these shapes come from are in `test-fixtures/codex-events/`, and the ten
 * second boundary is swept in that directory's README.
 */
import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { TransactionalRunner } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import type { CommandExecution } from "./codex-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/** A runtime that reports the commands it ran, the way both codex runners now do. */
const commandRunner = (
  commands: CommandExecution[] | undefined,
  act: (ws: string) => Promise<void>,
): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return {
      output: "done",
      threadId: null,
      usage: null,
      ...(commands === undefined ? {} : { commands }),
    };
  },
});

const killedAtTheLimit: CommandExecution = {
  id: "item_1",
  command: "bash -lc 'echo landed > landed.txt && sleep 45 && echo finished > finished.txt'",
  aggregatedOutput: "",
  exitCode: 124,
  status: "failed",
  failed: true,
};

const succeeded: CommandExecution = {
  id: "item_1",
  command: "bash -lc 'echo hello > made.txt && echo done'",
  aggregatedOutput: "done\n",
  exitCode: 0,
  status: "completed",
  failed: false,
};

async function withWorkspace<T>(fn: (ws: string, root: string) => Promise<T>): Promise<T> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-cmd-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await fs.writeFile(path.join(ws, "index.js"), "console.log(1)\n");
  try {
    return await fn(ws, root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const wrap = (inner: AgentRunner, root: string) =>
  new TransactionalRunner(inner, {
    shadowRoot: path.join(root, "shadows"),
    journalPath: path.join(root, "journal.jsonl"),
    policy: defaultPolicy,
  });

const request: RunnerRequest = { agentId: "a1", workspacePath: "", prompt: "p", threadId: null };

async function executedRecord(root: string): Promise<Record<string, unknown>> {
  const text = await fs.readFile(path.join(root, "journal.jsonl"), "utf8");
  const records = text
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  const executed = records.find((r) => r.kind === "turn.executed");
  expect(executed).toBeTruthy();
  return executed as Record<string, unknown>;
}

describe("a turn's commands reach the ledger", () => {
  it("records the killed command, its exit code and its status", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(
        commandRunner([killedAtTheLimit], async (w) => {
          // exactly what the killed command left behind: the first clause ran, the last did not
          await fs.writeFile(path.join(w, "landed.txt"), "landed\n");
        }),
        root,
      );
      await runner.run({ ...request, workspacePath: ws });

      const executed = await executedRecord(root);
      expect(executed.commands).toBe(1);
      expect(executed.commandsFailed).toBe(1);
      const failed = executed.failed as Array<Record<string, unknown>>;
      expect(failed).toHaveLength(1);
      expect(failed[0].exitCode).toBe(124);
      expect(failed[0].status).toBe("failed");
      expect(String(failed[0].command)).toContain("finished.txt");
    });
  });

  it("does not cry wolf on a turn whose commands all succeeded", async () => {
    // The negative case. A rule that flags every turn is not a control, and the commonest failure
    // on this team is closing a hole by opening a wider one.
    await withWorkspace(async (ws, root) => {
      const runner = wrap(
        commandRunner([succeeded], async (w) => {
          await fs.writeFile(path.join(w, "made.txt"), "hello\n");
        }),
        root,
      );
      await runner.run({ ...request, workspacePath: ws });

      const executed = await executedRecord(root);
      expect(executed.commands).toBe(1);
      expect(executed.commandsFailed).toBe(0);
      expect(executed.failed).toBeUndefined();
    });
  });

  it("says nothing at all when the runtime does not report commands", async () => {
    // A runner that cannot see commands and a turn that ran none are different states. Emitting
    // `commands: 0` for the first would be the platform asserting something it does not know.
    await withWorkspace(async (ws, root) => {
      const runner = wrap(
        commandRunner(undefined, async (w) => {
          await fs.writeFile(path.join(w, "feature.js"), "export const x = 1\n");
        }),
        root,
      );
      await runner.run({ ...request, workspacePath: ws });

      const executed = await executedRecord(root);
      expect(executed.exit).toBe("ok");
      expect(executed.commands).toBeUndefined();
      expect(executed.commandsFailed).toBeUndefined();
    });
  });

  it("reports a turn that ran commands, none of which failed, distinctly from one that ran none", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(commandRunner([], async () => undefined), root);
      await runner.run({ ...request, workspacePath: ws });

      const executed = await executedRecord(root);
      expect(executed.commands).toBe(0);
      expect(executed.commandsFailed).toBe(0);
    });
  });
});

import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

import { defaultPolicy } from "./shadow-policy.js";
import { TransactionalRunner } from "./transactional-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * Outbound-link neutralisation is a property of THE SEAL, not of one branch of it.
 *
 * A symlink resolving outside the workspace is a hole through the sealed view. The turn writes
 * through it and changes a real file at execution time, before any policy sees an effect, so no
 * capture-time or commit-time rule can close it. Only the seal can.
 *
 * It used to run inside `copyFallback`, which meant it protected the copy path and nothing else.
 * Any sealer supplied through the `seal` option skipped it, including the overlay the product now
 * takes on Linux, so the defence was absent exactly where the mechanism is fastest.
 *
 * These tests pin it at the contract: whatever sealed the workspace, and whether or not that sealer
 * neutralises anything itself, no link inside the sealed view points out of it by the time the agent
 * runs. The sealer used here deliberately does NOT neutralise, so a regression that moves the call
 * back inside a branch fails rather than passing on the copy path's coat-tails.
 */

const scriptRunner = (act: (ws: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

/** A sealer that copies and neutralises NOTHING. Any third-party sealer looks like this. */
const bareCopySeal = async (real: string, shadowDir: string): Promise<"copy"> => {
  await execFileAsync("cp", ["-a", real + "/.", path.join(shadowDir, "merged")]);
  return "copy";
};

async function withWorkspace<T>(fn: (ws: string, root: string) => Promise<T>): Promise<T> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "seal-contract-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await fs.writeFile(path.join(ws, "index.js"), "console.log(1)\n");
  try {
    return await fn(ws, root);
  } finally {
    await fs.rm(root, { recursive: true, force: true }).catch(() => undefined);
  }
}

describe.skipIf(process.platform === "win32")("neutralisation is part of the seal contract", () => {
  it("closes an outbound link even when the supplied sealer does not", async () => {
    await withWorkspace(async (ws, root) => {
      const secret = path.join(root, "outside.txt");
      await fs.writeFile(secret, "real-bytes\n");
      await fs.symlink(secret, path.join(ws, "escape.txt"));

      let sealedView = "";
      const runner = new TransactionalRunner(
        scriptRunner(async (merged) => {
          sealedView = merged;
          // the turn writes through what used to be a hole
          await fs.writeFile(path.join(merged, "escape.txt"), "clobbered\n");
        }),
        {
          shadowRoot: path.join(root, "shadows"),
          journalPath: path.join(root, "journal.jsonl"),
          policy: defaultPolicy,
          seal: bareCopySeal,
        },
      );

      await runner.run({ agentId: "a1", workspacePath: ws, prompt: "p", threadId: null });
      await runner.closeJournal().catch(() => undefined);

      // THE PROPERTY: the real file outside the workspace is untouched, because the link was
      // resolved into a regular file before the agent ever ran.
      expect(await fs.readFile(secret, "utf8")).toBe("real-bytes\n");
      // and the sealed view held a regular file, not a link, while the turn was running
      const inShadow = await fs.lstat(path.join(sealedView, "escape.txt")).catch(() => null);
      if (inShadow) expect(inShadow.isSymbolicLink()).toBe(false);
    });
  });

  it("keeps a link that stays inside the workspace, because a monorepo depends on those", async () => {
    await withWorkspace(async (ws, root) => {
      await fs.symlink(path.join(ws, "index.js"), path.join(ws, "alias.js"));

      let sealedView = "";
      const runner = new TransactionalRunner(
        scriptRunner(async (merged) => {
          sealedView = merged;
        }),
        {
          shadowRoot: path.join(root, "shadows"),
          journalPath: path.join(root, "journal.jsonl"),
          policy: defaultPolicy,
          seal: bareCopySeal,
        },
      );

      await runner.run({ agentId: "a2", workspacePath: ws, prompt: "p", threadId: null });
      await runner.closeJournal().catch(() => undefined);

      const alias = await fs.lstat(path.join(sealedView, "alias.js")).catch(() => null);
      // an in-workspace link is ordinary and must survive: neutralising it would break real projects
      if (alias) expect(alias.isSymbolicLink()).toBe(true);
    });
  });
});

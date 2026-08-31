import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { defaultPolicy } from "./shadow-policy.js";
import { TransactionalRunner } from "./transactional-runner.js";
import { buildTimeline, type TimelineTurn } from "./web-routes.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/**
 * What the run timeline is allowed to say about a turn.
 *
 * The panel's timeline is the audit surface: it is the one screen that answers "what did the
 * boundary actually do with this turn". Every case here is a sequence the runner and the commit
 * protocol really emit, written in the record shapes those two files write, because a reader that
 * reports a turn as landed when it did not is worse than a reader that shows nothing.
 *
 * The negatives are the point of the file as much as the positives: ordinary work still reads as
 * committed, an approval that really landed still names the person who approved it.
 */

const AGENT = "11111111-1111-4111-8111-111111111111";
const RUN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

interface Line {
  seq: number;
  runId?: string;
  agentId?: string;
  kind?: string;
  [k: string]: unknown;
}

/** Numbers the records in order, the way the journal does, so a test reads as a sequence. */
function timelineOf(records: Array<Record<string, unknown>>): TimelineTurn {
  const lines: Line[] = records.map((record, index) => ({
    seq: index + 1,
    runId: RUN,
    agentId: AGENT,
    ...record,
  })) as Line[];
  const { turns } = buildTimeline(lines, AGENT, 50);
  expect(turns).toHaveLength(1);
  return turns[0]!;
}

const begin = { kind: "turn.begin", mechanism: "copy" };
const twoEffects = [
  { path: "package.json", kind: "modify", sha256: "a".repeat(64) },
  { path: "src/app.ts", kind: "create", sha256: "b".repeat(64) },
];
const captured = { kind: "effects.captured", count: 2, bytes: 120, oversize: 0 };
const held = { kind: "turn.held", rule: "manifest-script-change", effects: twoEffects };
const approved = { kind: "turn.approved", actor: "operator", effectSetHash: "c".repeat(64) };
const committing = { kind: "turn.committing", effects: twoEffects, actor: "operator", viaApproval: true };

describe("the verdict the run timeline reports", () => {
  it("does not report an approval that the commit then discarded as approved", () => {
    // transactional-runner.ts:575 appends turn.approved, then commit-protocol.ts:104 re-hashes the
    // bytes and discards the whole turn when they moved. Nothing was written.
    const turn = timelineOf([
      begin,
      captured,
      held,
      approved,
      { kind: "effect.tampered", path: "package.json" },
      { kind: "turn.discarded", rule: "effect-tampered", effects: twoEffects },
    ]);
    expect(turn.verdict).toBe("discarded");
    expect(turn.rule).toBe("effect-tampered");
    // the approver is still named: who decided is a separate fact from what happened
    expect(turn.principal).toBe("operator");
  });

  it("does not report an approval that then lost a conflict as approved", () => {
    // commit-protocol.ts:126-140: the per-write baseline re-check fires after turn.approved.
    const turn = timelineOf([
      begin,
      captured,
      held,
      approved,
      committing,
      {
        kind: "turn.conflicted",
        rule: "workspace-changed-during-commit",
        path: "src/app.ts",
        applied: ["package.json"],
        effects: twoEffects,
      },
    ]);
    expect(turn.verdict).toBe("conflicted");
    expect(turn.principal).toBe("operator");
  });

  it("does not report an approval whose commit has not been recorded as committed", () => {
    // A crash between turn.approved and the commit point leaves exactly this. The turn is in
    // flight as far as the journal knows, and "Committed, approved by operator" would be a claim
    // no record supports.
    const turn = timelineOf([begin, captured, held, approved]);
    expect(turn.verdict).toBe("running");
    expect(turn.principal).toBe("operator");
  });

  it("still reports an approval that committed as approved by the principal who approved it", () => {
    const turn = timelineOf([begin, captured, held, approved, committing, { kind: "turn.committed", applied: 2 }]);
    expect(turn.verdict).toBe("approved");
    expect(turn.principal).toBe("operator");
    expect(turn.rule).toBeNull();
    expect(turn.effectCount).toBe(2);
  });

  it("still reports the ordinary settlements the boundary reaches without a human", () => {
    const commit = timelineOf([begin, captured, committing, { kind: "turn.committed", applied: 2 }]);
    expect(commit.verdict).toBe("committed");
    expect(commit.rule).toBeNull();

    const discard = timelineOf([
      begin,
      captured,
      { kind: "turn.discarded", rule: "remote-code-execution-added", effects: twoEffects },
    ]);
    expect(discard.verdict).toBe("discarded");
    expect(discard.rule).toBe("remote-code-execution-added");

    const waiting = timelineOf([begin, captured, held]);
    expect(waiting.verdict).toBe("held");
    expect(waiting.rule).toBe("manifest-script-change");

    const rejected = timelineOf([begin, captured, held, { kind: "turn.rejected", actor: "operator" }]);
    expect(rejected.verdict).toBe("rejected");
    expect(rejected.principal).toBe("operator");

    const running = timelineOf([begin, { kind: "turn.executed", exit: "ok" }, captured]);
    expect(running.verdict).toBe("running");
  });

  it("names a commit that recovery cannot finish rather than leaving it Running for ever", () => {
    // commit-protocol.ts:299-309: a commit point with no completion and no retained record to
    // finish from. This is the one case where the real workspace may hold a partial write.
    const turn = timelineOf([
      begin,
      captured,
      committing,
      { kind: "commit.unrecoverable", reason: "no retained effect record" },
    ]);
    expect(turn.verdict).toBe("unrecoverable");
  });

  it("leaves a commit still in flight as running", () => {
    const turn = timelineOf([begin, captured, committing]);
    expect(turn.verdict).toBe("running");
  });
});

describe("the number of changes the run timeline reports", () => {
  it("reports what the turn did, not the journal's bound on how many it lists", () => {
    // commit-protocol.ts:43-50 caps the list at 200 and records the remainder in effectsTruncated.
    const many = Array.from({ length: 200 }, (_, i) => ({ path: "src/f" + i + ".ts", kind: "create" }));
    const turn = timelineOf([
      begin,
      { kind: "effects.captured", count: 5000, bytes: 900, oversize: 0 },
      { kind: "turn.committing", effects: many, effectsTruncated: 4800 },
      { kind: "turn.committed", applied: 5000 },
    ]);
    expect(turn.effectCount).toBe(5000);
    expect(turn.effects).toHaveLength(100);
    expect(turn.truncated).toBe(4900);
  });

  it("counts a small turn exactly, and lists every row of it", () => {
    const turn = timelineOf([begin, captured, committing, { kind: "turn.committed", applied: 2 }]);
    expect(turn.effectCount).toBe(2);
    expect(turn.effects.map((e) => e.path)).toEqual(["package.json", "src/app.ts"]);
    expect(turn.truncated).toBe(0);
  });

  it("counts a held network write as a change, because the broker did send it", () => {
    // `turn.committed.applied` counts files the commit protocol wrote, and it skips outbound
    // effects on purpose (commit-protocol.ts:173-176): a held network write has no path to write,
    // and it is settled by the confinement rather than by the copy loop. Counting `applied`
    // instead of the proposed set would report this turn as "1 of 2 changes" and tell the operator
    // the request never went out, which is the opposite of what happened.
    const withOutbound = [
      { path: "src/app.ts", kind: "create", sha256: "b".repeat(64) },
      { path: "net:POST collector.example:9100/ingest", kind: "outbound", bytes: 40, effectClass: "outbound" },
    ];
    const turn = timelineOf([
      begin,
      { kind: "effects.captured", count: 2, bytes: 160, oversize: 0 },
      { kind: "turn.committing", effects: withOutbound },
      { kind: "turn.committed", applied: 1 },
    ]);
    expect(turn.effectCount).toBe(2);
    expect(turn.verdict).toBe("committed");
  });

  it("still reports the captured count for a turn whose records carry no effect list", () => {
    const turn = timelineOf([begin, { kind: "effects.captured", count: 7 }, { kind: "turn.discarded", rule: "cancelled-by-operator" }]);
    expect(turn.effectCount).toBe(7);
    expect(turn.effects).toEqual([]);
  });
});

describe("what the run timeline says about a conflict", () => {
  it("names the path of a conflict that hit mid-apply, and the files that had already landed", () => {
    // commit-protocol.ts:129-140 writes `path`, singular, plus the applied list.
    const turn = timelineOf([
      begin,
      captured,
      committing,
      {
        kind: "turn.conflicted",
        rule: "workspace-changed-during-commit",
        path: "src/app.ts",
        applied: ["package.json"],
        effects: twoEffects,
      },
    ]);
    expect(turn.conflictPaths).toEqual(["src/app.ts"]);
    expect(turn.appliedPaths).toEqual(["package.json"]);
  });

  it("still names the paths of a conflict found before anything was applied, with nothing landed", () => {
    // transactional-runner.ts:563-573 writes `paths`, plural, and no file was written.
    const turn = timelineOf([
      begin,
      captured,
      held,
      {
        kind: "turn.conflicted",
        rule: "workspace-changed-during-review",
        paths: ["package.json", "src/app.ts"],
        effects: twoEffects,
        actor: "operator",
      },
    ]);
    expect(turn.conflictPaths).toEqual(["package.json", "src/app.ts"]);
    expect(turn.appliedPaths).toEqual([]);
  });
});

/**
 * The same question against a real runner, a real journal and a real workspace: nothing here is a
 * hand-written record.
 */
describe("a real approved turn that loses a conflict while it is being applied", () => {
  const addsInstallHook = async (workspace: string): Promise<void> => {
    await fs.writeFile(
      path.join(workspace, "package.json"),
      '{"name":"app","scripts":{"postinstall":"node ./tools/collect.js"}}\n',
    );
    await fs.writeFile(path.join(workspace, "src", "app.ts"), "export const app = 1;\n");
  };

  const scriptRunner = (act: (workspace: string) => Promise<void>): AgentRunner => ({
    isAvailable: async () => true,
    cancel: async () => true,
    run: async (request: RunnerRequest): Promise<RunnerResult> => {
      await act(request.workspacePath);
      return { output: "I updated the files and everything is done.", threadId: null, usage: null };
    },
  });

  it("is not reported as committed and approved", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "timeline-"));
    const workspace = path.join(root, "ws");
    await fs.mkdir(path.join(workspace, "src"), { recursive: true });
    await fs.writeFile(path.join(workspace, "package.json"), '{"name":"app"}\n');
    const journalPath = path.join(root, "journal.jsonl");

    const runner = new TransactionalRunner(scriptRunner(addsInstallHook), {
      shadowRoot: path.join(root, "shadows"),
      journalPath,
      policy: defaultPolicy,
      // the concurrent editor: somebody else touches the second target between the two writes
      afterEffectApplied: async ({ applied }) => {
        if (applied.length !== 1) return;
        const remaining = ["package.json", "src/app.ts"].find((p) => !applied.includes(p));
        if (!remaining) return;
        await fs.writeFile(path.join(workspace, remaining), "// somebody else was editing this\n");
      },
    });
    await runner.run({ agentId: AGENT, workspacePath: workspace, prompt: "do the thing", threadId: null });

    const [heldTurn] = await runner.pendingReviews();
    expect(heldTurn).toBeDefined();
    const settled = await runner.approve(heldTurn!.runId, "operator", heldTurn!.effectSetHash);
    expect(settled).toMatchObject({ ok: false, code: "conflict" });

    const lines = (await fs.readFile(journalPath, "utf8"))
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as Line);
    const kinds = lines.map((l) => l.kind);
    expect(kinds).toContain("turn.approved");
    expect(kinds).toContain("turn.conflicted");

    const { turns } = buildTimeline(lines, AGENT, 50);
    expect(turns[0]!.verdict).toBe("conflicted");
    expect(turns[0]!.conflictPaths).toHaveLength(1);
    expect(turns[0]!.appliedPaths).toHaveLength(1);

    await fs.rm(root, { recursive: true, force: true });
  });
});

/**
 * The chip on a timeline row, from a real turn rather than a fixture.
 *
 * `timelineEffects` renders `classifyPath(path, e.effectClass)`, so the row says what the policy
 * decided only if the record it reads carries the class. It did not: the policy classified copies
 * of the effects and dropped them, the journal recorded the originals with no class on them, and
 * every chip fell through to the path-only table. The fixture above hand-sets
 * `effectClass: "outbound"`, so it could never have caught that; this drives the real pipeline.
 */
describe("a real held turn puts the policy's class on the timeline row", () => {
  const heldRunner = (act: (workspace: string) => Promise<void>): AgentRunner => ({
    isAvailable: async () => true,
    cancel: async () => true,
    run: async (request: RunnerRequest): Promise<RunnerResult> => {
      await act(request.workspacePath);
      return { output: "I edited the manifest.", threadId: null, usage: null };
    },
  });

  it("reads the class off the journalled record instead of re-deriving it from the path", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "timeline-class-"));
    const workspace = path.join(root, "ws");
    await fs.mkdir(workspace, { recursive: true });
    await fs.writeFile(path.join(workspace, "package.json"), '{"name":"app"}\n');
    const journalPath = path.join(root, "journal.jsonl");

    const runner = new TransactionalRunner(
      heldRunner(async (w) => {
        await fs.writeFile(
          path.join(w, "package.json"),
          '{"name":"app","scripts":{"postinstall":"node ./tools/collect.js"}}\n',
        );
      }),
      { shadowRoot: path.join(root, "shadows"), journalPath, policy: defaultPolicy },
    );
    await runner.run({ agentId: AGENT, workspacePath: workspace, prompt: "add an install hook", threadId: null });

    const lines = (await fs.readFile(journalPath, "utf8"))
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as Line);

    // the ledger's own copy of the turn carries the class, so an auditor reading the file sees the
    // same word the rule that held the turn was reading
    const held = lines.find((l) => l.kind === "turn.held");
    expect((held?.effects as Array<{ effectClass?: string }>)[0]!.effectClass).toBe("manifest");

    const { turns } = buildTimeline(lines, AGENT, 50);
    expect(turns[0]!.verdict).toBe("held");
    // the chip is that class put through change-class's mapping for it
    expect(turns[0]!.effects[0]).toMatchObject({ path: "package.json", class: "dependency" });

    await fs.rm(root, { recursive: true, force: true });
  });
});

/**
 * The workspace measurement on its way to the panel.
 *
 * The timeline is where the product's headline claim becomes something a person can read, so the
 * reader has two jobs beyond carrying the value: it must take the BEFORE value only from
 * `turn.begin`, which is the record chained before the agent was allowed to run, and it must never
 * hand the panel anything that is not a digest. The boundary writes the sentinel `"not-measured"`
 * into the same field when a walk refused, and a panel that printed that beside the words "byte for
 * byte" would be worse than one that showed nothing.
 */
const DIGEST_OPEN = "1".repeat(64);
const DIGEST_MOVED = "2".repeat(64);

describe("what the timeline says about the real workspace", () => {
  it("carries the pair, and the counts, off a committed turn", () => {
    const turn = timelineOf([
      { ...begin, workspaceDigestBefore: DIGEST_OPEN, workspaceFilesBefore: 12 },
      captured,
      { kind: "turn.committing", effects: twoEffects },
      { kind: "turn.committed", applied: 2, workspaceDigestAfter: DIGEST_MOVED, workspaceFilesAfter: 14 },
    ]);
    expect(turn.verdict).toBe("committed");
    expect(turn.workspaceDigestBefore).toBe(DIGEST_OPEN);
    expect(turn.workspaceDigestAfter).toBe(DIGEST_MOVED);
    expect(turn.workspaceFilesBefore).toBe(12);
    expect(turn.workspaceFilesAfter).toBe(14);
    expect(turn.workspaceDigestReason).toBeNull();
  });

  it("reports the two as equal on a turn that was blocked, which is the whole claim", () => {
    const turn = timelineOf([
      { ...begin, workspaceDigestBefore: DIGEST_OPEN, workspaceFilesBefore: 12, workspaceUnreadableBefore: 0 },
      captured,
      {
        kind: "turn.discarded",
        rule: "execution-surface-write",
        effects: twoEffects,
        workspaceDigestAfter: DIGEST_OPEN,
        workspaceFilesAfter: 12,
        workspaceUnreadableAfter: 0,
      },
    ]);
    expect(turn.verdict).toBe("discarded");
    // Each end against the FIXTURE, never against the other end. `after === before` is satisfied by
    // undefined === undefined, so it passed with the whole production change reverted: it would
    // equally have passed on nulls, or on the same wrong value twice.
    expect(turn.workspaceDigestBefore).toBe(DIGEST_OPEN);
    expect(turn.workspaceDigestAfter).toBe(DIGEST_OPEN);
    expect(turn.workspaceFilesBefore).toBe(12);
    expect(turn.workspaceFilesAfter).toBe(12);
    expect(turn.workspaceUnreadableAfter).toBe(0);
    expect(turn.workspaceDigestReason).toBeNull();
  });

  it("carries the unreadable count off both ends, because an equal pair can still be partial", () => {
    // A digest over a tree with an unlistable directory in it is a partial measurement wearing the
    // same 64 hex as a whole one. Without this field the panel cannot tell the two apart.
    const turn = timelineOf([
      { ...begin, workspaceDigestBefore: DIGEST_OPEN, workspaceFilesBefore: 9, workspaceUnreadableBefore: 1 },
      captured,
      {
        kind: "turn.discarded",
        rule: "execution-surface-write",
        workspaceDigestAfter: DIGEST_OPEN,
        workspaceFilesAfter: 9,
        workspaceUnreadableAfter: 2,
      },
    ]);
    expect(turn.workspaceUnreadableBefore).toBe(1);
    expect(turn.workspaceUnreadableAfter).toBe(2);
  });

  it("reads a missing unreadable count as null rather than as a whole measurement", () => {
    const turn = timelineOf([
      { ...begin, workspaceDigestBefore: DIGEST_OPEN },
      { kind: "turn.discarded", rule: "x", workspaceDigestAfter: DIGEST_OPEN },
    ]);
    expect(turn.workspaceUnreadableBefore).toBeNull();
    expect(turn.workspaceUnreadableAfter).toBeNull();
  });

  it("takes the closing value from the record the turn ended on, not from an earlier one", () => {
    // An approval is followed by a real commit that can still conflict. The turn.held record carries
    // a closing measurement of its own, and reading that one would report a turn as unchanged after
    // the commit it authorised had already written.
    const turn = timelineOf([
      { ...begin, workspaceDigestBefore: DIGEST_OPEN },
      captured,
      { ...held, workspaceDigestAfter: DIGEST_OPEN },
      approved,
      committing,
      { kind: "turn.committed", applied: 2, workspaceDigestAfter: DIGEST_MOVED },
    ]);
    expect(turn.verdict).toBe("approved");
    expect(turn.workspaceDigestAfter).toBe(DIGEST_MOVED);
  });

  it("gives a running turn its opening value and no closing one", () => {
    const turn = timelineOf([{ ...begin, workspaceDigestBefore: DIGEST_OPEN }, captured]);
    expect(turn.verdict).toBe("running");
    expect(turn.workspaceDigestBefore).toBe(DIGEST_OPEN);
    expect(turn.workspaceDigestAfter).toBeNull();
  });

  it("passes the refusal through as a reason and never as a digest", () => {
    const turn = timelineOf([
      {
        ...begin,
        workspaceDigestBefore: "not-measured",
        workspaceFilesBefore: 40000,
        workspaceDigestReason: "tree-over-budget",
      },
      captured,
      {
        kind: "turn.discarded",
        rule: "execution-surface-write",
        workspaceDigestAfter: "not-measured",
        workspaceFilesAfter: 40000,
        workspaceDigestReason: "tree-over-budget",
      },
    ]);
    expect(turn.workspaceDigestBefore).toBeNull();
    expect(turn.workspaceDigestAfter).toBeNull();
    expect(turn.workspaceDigestReason).toBe("tree-over-budget");
    expect(turn.workspaceFilesBefore).toBe(40000);
  });

  it("reads a turn from before any of this was recorded as null, not as unchanged", () => {
    // Two absent values are not two equal values. A journal written before this existed must not
    // render as a workspace that provably did not move.
    const turn = timelineOf([begin, captured, { kind: "turn.discarded", rule: "manifest-script-change" }]);
    expect(turn.workspaceDigestBefore).toBeNull();
    expect(turn.workspaceDigestAfter).toBeNull();
    expect(turn.workspaceDigestReason).toBeNull();
    expect(turn.workspaceFilesBefore).toBeNull();
  });

  it("refuses anything that is not a 64-hex digest, whatever a record carries", () => {
    const turn = timelineOf([
      { ...begin, workspaceDigestBefore: { nested: "object" } },
      { kind: "turn.discarded", rule: "x", workspaceDigestAfter: "byte for byte identical" },
    ]);
    expect(turn.workspaceDigestBefore).toBeNull();
    expect(turn.workspaceDigestAfter).toBeNull();
  });
});

/**
 * The network half, on its way to the panel.
 *
 * Track C asks for two bounded controls and the journal records both, but only the filesystem half
 * was ever read out of it here. These are the records the boundary really writes: the field names
 * and the values are the ones in `evidence/demo-run/steps/06-turn-2-egress.json` and in the note
 * `runner-factory.ts` builds, not a shape invented for a fixture.
 *
 * The one way this projection can lie is by flattening an absence into a claim.
 * `confinement: "none"` is a REAL journaled value, written on every turn of the host-process
 * runtime under SHADOW_ALLOW_UNCONFINED=1, which is what the Compose and ECS profiles use. A turn
 * journaled as unconfined, a turn whose opening record predates these fields, and a turn with no
 * opening record at all are three different things, and each one is asserted separately below.
 */
const sealedBegin = {
  kind: "turn.begin",
  mechanism: "copy",
  confinement: "container+sealed-network",
  containerWorkspacePath: "/workspace",
  containerCodexHome: "/codex-home",
  network: "shadow-291771a1-5a1e-49c3-b25a-8cde3ae6354b",
  egressAllowlist: [
    "registry.npmjs.org:443",
    "registry.yarnpkg.com:443",
    "pypi.org:443",
    "files.pythonhosted.org:443",
    "172.19.0.2:8398",
  ],
  decoyHost: "status.shadow-decoy.test",
  modelChannel: "terminated-at-broker",
  codexHomeFiles: 31,
};

const sealedDiscard = {
  kind: "turn.discarded",
  rule: "protected-asset-delete",
  egress: { deny: 2, live: 2 },
  outboundDropped: 0,
  codexHome: { restored: false, verifiedUnchanged: true },
};

describe("what the timeline says about the network half", () => {
  it("carries every field the demo run's own records wrote", () => {
    const turn = timelineOf([sealedBegin, captured, sealedDiscard]);
    expect(turn.beginRecorded).toBe(true);
    expect(turn.confinement).toBe("container+sealed-network");
    expect(turn.network).toBe("shadow-291771a1-5a1e-49c3-b25a-8cde3ae6354b");
    expect(turn.egressAllowlistSize).toBe(5);
    expect(turn.modelChannel).toBe("terminated-at-broker");
    expect(turn.codexHomeFiles).toBe(31);
    expect(turn.egress).toEqual({ deny: 2, live: 2 });
    expect(turn.outboundDropped).toBe(0);
    expect(turn.codexHomeRestored).toBe(false);
    expect(turn.codexHomeVerifiedUnchanged).toBe(true);
    expect(turn.confinementStateLost).toBe(false);
    expect(turn.networkLeaked).toBeNull();
  });

  it("carries confinement none through as the value it is, never as an absence", () => {
    // unconfinedConfinement() in runner-factory.ts. This is what the Compose and ECS profiles
    // journal on every single turn, and the panel has to be able to tell it apart from silence.
    const turn = timelineOf([
      {
        kind: "turn.begin",
        mechanism: "copy",
        confinement: "none",
        reason: "SHADOW_ALLOW_UNCONFINED=1: host-process runtime, no network or filesystem jail",
        containerWorkspacePath: null,
      },
      captured,
      { kind: "turn.discarded", rule: "protected-asset-delete", confinement: "none" },
    ]);
    expect(turn.beginRecorded).toBe(true);
    expect(turn.confinement).toBe("none");
    expect(turn.confinementReason).toContain("SHADOW_ALLOW_UNCONFINED=1");
    // nothing was sealed, so there is nothing to report about any of it
    expect(turn.network).toBeNull();
    expect(turn.egressAllowlistSize).toBeNull();
    expect(turn.modelChannel).toBeNull();
    expect(turn.egress).toBeNull();
    expect(turn.codexHomeVerifiedUnchanged).toBeNull();
  });

  it("reads a turn from before these fields as unknown, not as unconfined", () => {
    // Same absence, opposite meaning. `begin` here is the fixture the rest of this file uses, which
    // is a turn.begin with nothing but a mechanism on it.
    const turn = timelineOf([begin, captured, { kind: "turn.discarded", rule: "manifest-script-change" }]);
    expect(turn.beginRecorded).toBe(true);
    expect(turn.confinement).toBeNull();
    expect(turn.confinementReason).toBeNull();
    expect(turn.network).toBeNull();
    expect(turn.codexHomeFiles).toBeNull();
  });

  it("says so when the turn has no opening record at all", () => {
    // A journal truncated at the front, or a run whose turn.begin never made it to disk. There is
    // no record to have carried the fields, which is a third state and not either of the two above.
    const turn = timelineOf([captured, { kind: "turn.discarded", rule: "manifest-script-change" }]);
    expect(turn.beginRecorded).toBe(false);
    expect(turn.confinement).toBeNull();
  });

  it("names a container whose network half was not sealed as the weaker thing it is", () => {
    // runner-factory.ts:339-347 with sealNetwork false: the mode word drops "+sealed-network", the
    // network name is null and the model channel is direct.
    const turn = timelineOf([
      { kind: "turn.begin", mechanism: "overlay", confinement: "container", network: null, egressAllowlist: null, modelChannel: "direct", codexHomeFiles: 12 },
      captured,
      { kind: "turn.committed", applied: 1, codexHome: { added: [], modified: ["history.jsonl"], removed: [], changed: 1, truncated: false } },
    ]);
    expect(turn.confinement).toBe("container");
    expect(turn.network).toBeNull();
    expect(turn.modelChannel).toBe("direct");
    expect(turn.egressAllowlistSize).toBeNull();
  });

  it("takes the settle facts from the record the turn ended on, not from an earlier one", () => {
    // A hold carries its own note, and the approval that follows it commits and carries another.
    // Reading the first would report writes as still held after they had already been sent.
    const turn = timelineOf([
      sealedBegin,
      captured,
      { ...held, egress: { live: 1 }, outboundHeldForReview: 2 },
      approved,
      committing,
      {
        kind: "turn.committed",
        applied: 2,
        egress: { live: 3, held: 2 },
        outboundReplayed: 2,
        outboundFailed: 0,
        codexHome: { added: ["rollout.jsonl"], modified: [], removed: [], changed: 1, truncated: false },
      },
    ]);
    expect(turn.verdict).toBe("approved");
    expect(turn.egress).toEqual({ live: 3, held: 2 });
    expect(turn.outboundReplayed).toBe(2);
    expect(turn.outboundFailed).toBe(0);
    expect(turn.outboundHeldForReview).toBeNull();
    expect(turn.codexHomeChanged).toBe(1);
    expect(turn.codexHomeRestored).toBeNull();
  });

  it("keeps a held turn's own count of what is waiting, unsent", () => {
    const turn = timelineOf([sealedBegin, captured, { ...held, egress: { live: 1, held: 2 }, outboundHeldForReview: 2 }]);
    expect(turn.verdict).toBe("held");
    expect(turn.outboundHeldForReview).toBe(2);
    expect(turn.outboundDropped).toBeNull();
  });

  it("refuses an egress summary that is not counts, and keeps an empty one", () => {
    const words = timelineOf([sealedBegin, { kind: "turn.discarded", rule: "x", egress: "two denied" }]);
    expect(words.egress).toBeNull();
    const junk = timelineOf([sealedBegin, { kind: "turn.discarded", rule: "x", egress: { deny: "many" } }]);
    expect(junk.egress).toBeNull();
    // An empty summary is a real answer: the broker was there and logged no request. It is not the
    // same as no summary at all, so it survives as itself.
    const quiet = timelineOf([sealedBegin, { kind: "turn.discarded", rule: "x", egress: {} }]);
    expect(quiet.egress).toEqual({});
  });

  it("projects the allowlist as a count, and an allowlist of nothing as zero", () => {
    const empty = timelineOf([{ ...sealedBegin, egressAllowlist: [] }, { kind: "turn.discarded", rule: "x" }]);
    expect(empty.egressAllowlistSize).toBe(0);
    const notAList = timelineOf([
      { ...sealedBegin, egressAllowlist: "registry.npmjs.org:443" },
      { kind: "turn.discarded", rule: "x" },
    ]);
    expect(notAList.egressAllowlistSize).toBeNull();
  });

  it("reads a memory that had to be rolled back, not only one that held still", () => {
    const turn = timelineOf([
      sealedBegin,
      captured,
      { kind: "turn.discarded", rule: "protected-asset-delete", codexHome: { restored: true, verifiedUnchanged: false } },
    ]);
    expect(turn.codexHomeRestored).toBe(true);
    expect(turn.codexHomeVerifiedUnchanged).toBe(false);
    expect(turn.codexHomeChanged).toBeNull();
  });

  it("carries a network that could not be removed, and a settle that found no state", () => {
    // Both are the boundary reporting on itself. A leaked network outlives the turn that made it,
    // and a lost settle means only the files half of it ran.
    const turn = timelineOf([
      sealedBegin,
      captured,
      {
        kind: "turn.discarded",
        rule: "protected-asset-delete",
        networkLeaked: "shadow-291771a1-5a1e-49c3-b25a-8cde3ae6354b",
        confinementStateLost: true,
        confinementStateLostDetail: "no sealed network or codex-home state was found for this run",
      },
    ]);
    expect(turn.networkLeaked).toBe("shadow-291771a1-5a1e-49c3-b25a-8cde3ae6354b");
    expect(turn.confinementStateLost).toBe(true);
  });

  it("gives a running turn its confinement and no settle facts", () => {
    const turn = timelineOf([sealedBegin, { kind: "turn.executed", exit: "ok" }, captured]);
    expect(turn.verdict).toBe("running");
    expect(turn.confinement).toBe("container+sealed-network");
    expect(turn.egress).toBeNull();
    expect(turn.outboundDropped).toBeNull();
    expect(turn.codexHomeVerifiedUnchanged).toBeNull();
  });

  it("refuses a confinement, a network or a channel that is not a string", () => {
    const turn = timelineOf([
      { kind: "turn.begin", mechanism: "copy", confinement: { mode: "container" }, network: 7, modelChannel: ["broker"], codexHomeFiles: "31" },
      { kind: "turn.discarded", rule: "x" },
    ]);
    expect(turn.confinement).toBeNull();
    expect(turn.network).toBeNull();
    expect(turn.modelChannel).toBeNull();
    expect(turn.codexHomeFiles).toBeNull();
    // and the absence of a readable value still leaves the record itself recorded
    expect(turn.beginRecorded).toBe(true);
  });

  /**
   * The provenance, pinned.
   *
   * `turn.begin` is chained BEFORE the agent is allowed to execute, and the settling record is
   * written after it ran. Sourcing the containment claim from the settle would take it from the one
   * record an agent that got out could have influenced. Nothing in the suite said so: changing the
   * projection to `stringOf(begin?.confinement ?? settling?.confinement)` passed every test in this
   * file, because no fixture had ever put a confinement on a settle and left it off the begin.
   */
  it("does not take the confinement from a record written after the agent ran", () => {
    const turn = timelineOf([
      { kind: "turn.begin", mechanism: "copy", codexHomeFiles: 31 },
      {
        kind: "turn.discarded",
        rule: "protected-asset-delete",
        confinement: "container+sealed-network",
        network: "shadow-planted",
        egressAllowlist: ["registry.npmjs.org:443"],
        modelChannel: "terminated-at-broker",
      },
    ]);
    expect(turn.beginRecorded).toBe(true);
    expect(turn.confinement).toBeNull();
    expect(turn.network).toBeNull();
    expect(turn.egressAllowlistSize).toBeNull();
    expect(turn.modelChannel).toBeNull();
  });

  it("does not take the confinement from a settle when there is no opening record at all", () => {
    const turn = timelineOf([{ kind: "turn.discarded", rule: "x", confinement: "container+sealed-network" }]);
    expect(turn.beginRecorded).toBe(false);
    expect(turn.confinement).toBeNull();
  });

  /**
   * The field that says the two beside it are bookkeeping.
   *
   * `settleReviewed` in runner-factory.ts writes `{ restored: false, verifiedUnchanged: true,
   * droppedAfterReview: true }` as a LITERAL on a rejected review: the memory was already rolled
   * back at the earlier review settle, and this settle only drops the sealed copy. Nothing is
   * measured there. `buildTimeline` reads the LAST settling record, so that literal is what a
   * review-then-reject projects, and projecting its two neighbours while stepping over it made a
   * rejected review indistinguishable from a turn that really was verified unchanged.
   */
  it("carries the mark that a reviewed settle measured nothing, not only the two values beside it", () => {
    const turn = timelineOf([
      sealedBegin,
      { kind: "turn.held", rule: "credential-write", codexHome: { restored: true, verifiedUnchanged: false } },
      {
        kind: "turn.discarded",
        rule: "credential-write",
        codexHome: { restored: false, verifiedUnchanged: true, droppedAfterReview: true },
      },
    ]);
    expect(turn.codexHomeDroppedAfterReview).toBe(true);
    expect(turn.codexHomeRestored).toBe(false);
    expect(turn.codexHomeVerifiedUnchanged).toBe(true);
  });

  it("leaves the mark null on a settle that really did measure the memory", () => {
    const turn = timelineOf([sealedBegin, sealedDiscard]);
    expect(turn.codexHomeDroppedAfterReview).toBeNull();
    expect(turn.codexHomeVerifiedUnchanged).toBe(true);
  });

  it("refuses a dropped-after-review mark that is not a boolean", () => {
    const turn = timelineOf([
      sealedBegin,
      { kind: "turn.discarded", rule: "x", codexHome: { restored: false, verifiedUnchanged: true, droppedAfterReview: "yes" } },
    ]);
    expect(turn.codexHomeDroppedAfterReview).toBeNull();
  });

  /**
   * The two disjoint halves of a replay, carried as two values.
   *
   * The sealer increments exactly one of `replayed` and `failed` per held payload, so the attempted
   * total is their sum. Zero is the arm no fixture swept, and zero is what `replay` returns for an
   * empty held set, which is the ordinary committed turn.
   */
  it("carries both halves of a replay separately, including the zeroes the runner writes most often", () => {
    const both = timelineOf([
      sealedBegin,
      { kind: "turn.committed", applied: 1, outboundReplayed: 2, outboundFailed: 1 },
    ]);
    expect(both.outboundReplayed).toBe(2);
    expect(both.outboundFailed).toBe(1);
    const none = timelineOf([
      sealedBegin,
      { kind: "turn.committed", applied: 1, outboundReplayed: 0, outboundFailed: 0 },
    ]);
    expect(none.outboundReplayed).toBe(0);
    expect(none.outboundFailed).toBe(0);
    // zero measured and nothing measured are different values, and the panel renders them differently
    const neither = timelineOf([sealedBegin, { kind: "turn.committed", applied: 1 }]);
    expect(neither.outboundReplayed).toBeNull();
    expect(neither.outboundFailed).toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import { RunTimeline, TurnRow, networkFlag, networkLine, workspaceLine, workspaceStyle } from "./RunTimeline";
import type { JournalResponse, TimelineTurn } from "../../types";

/**
 * The one line about the real workspace, in the words a judge reads.
 *
 * The values behind it are the server's own, recorded on its hash-chained journal at turn open and
 * at the moment the turn ended; what is asserted here is only that the panel names the state
 * plainly and never invents one. Three rules the sentences have to keep:
 *
 *   - "Unchanged, byte for byte" is said ONLY when the two recorded digests are equal. Two absent
 *     values are not two equal values, and a turn from a journal written before the boundary
 *     recorded any of this must not read as a workspace that provably held still.
 *   - A commit is SUPPOSED to move the workspace, so a moved digest is named as a change and not as
 *     a failure. The panel reports the state; the verdict badge beside it reports the decision.
 *   - A refusal says it was not measured and says why. A turn that was never measured must never
 *     read like a turn that was measured and clean, which is the same gap as the server not
 *     recording it at all.
 *   - A tree the walk could not read all of is not a byte-for-byte claim, however equal the two
 *     digests are. An unreadable subtree hashes to a constant, so the digest cannot move for
 *     anything written under it, and saying "byte for byte" over that is the same false comfort.
 *
 * REVERT PROOF, RUN OVER THIS FILE, because a pure function tested seven ways proves nothing about
 * the row that renders it. Deleting the four-line `<dt>Workspace</dt>` block from `TurnRow` used to
 * leave this file 8 of 8 green: `workspaceLine` was well covered and completely unreached from the
 * markup, so the panel could have shipped without the row at all. The rendering block below is what
 * closes that, and the deletion now fails it. There is no DOM and no testing library here, so the
 * expanded state is reached through `TurnRow`'s `defaultOpen`, which is documented where it lives.
 */

const DIGEST_OPEN = "1a2b3c4d5e6f" + "0".repeat(52);
const DIGEST_MOVED = "9f8e7d6c5b4a" + "0".repeat(52);

const turn = (patch: Partial<TimelineTurn>): TimelineTurn => ({
  runId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  agentId: "11111111-1111-4111-8111-111111111111",
  verdict: "discarded",
  rule: "execution-surface-write",
  principal: null,
  seq: 7,
  at: null,
  mechanism: "copy",
  effectCount: 2,
  truncated: 0,
  effects: [],
  conflictPaths: [],
  appliedPaths: [],
  workspaceDigestBefore: null,
  workspaceDigestAfter: null,
  workspaceDigestReason: null,
  workspaceFilesBefore: null,
  workspaceFilesAfter: null,
  workspaceUnreadableBefore: null,
  workspaceUnreadableAfter: null,
  // The neutral network half by default: an opening record exists and carries none of these
  // fields, so the rows above stay about the workspace and every network case sets its own.
  beginRecorded: true,
  confinement: null,
  confinementReason: null,
  network: null,
  egressAllowlistSize: null,
  modelChannel: null,
  codexHomeFiles: null,
  egress: null,
  outboundDropped: null,
  outboundReplayed: null,
  outboundFailed: null,
  outboundHeldForReview: null,
  codexHomeRestored: null,
  codexHomeVerifiedUnchanged: null,
  codexHomeChanged: null,
  networkLeaked: null,
  confinementStateLost: false,
  records: [],
  ...patch,
});

describe("the workspace line on a turn row", () => {
  it("says a blocked turn left the workspace byte for byte as it was", () => {
    const line = workspaceLine(
      turn({
        workspaceDigestBefore: DIGEST_OPEN,
        workspaceDigestAfter: DIGEST_OPEN,
        workspaceFilesBefore: 12,
        workspaceFilesAfter: 12,
      }),
    );
    expect(line.state).toBe("unchanged");
    expect(line.sentence).toBe("Unchanged, byte for byte across 12 entries. sha256 1a2b3c4d5e6f at open and at close.");
  });

  it("names a commit as a change, with how far the file count moved", () => {
    const line = workspaceLine(
      turn({
        verdict: "committed",
        rule: null,
        workspaceDigestBefore: DIGEST_OPEN,
        workspaceDigestAfter: DIGEST_MOVED,
        workspaceFilesBefore: 12,
        workspaceFilesAfter: 14,
      }),
    );
    expect(line.state).toBe("changed");
    expect(line.sentence).toBe("Changed. 12 entries before, 14 after. sha256 1a2b3c4d5e6f became 9f8e7d6c5b4a.");
  });

  it("says a blocked turn whose workspace moved anyway is changed, and does not soften it", () => {
    // A discard whose digests differ is the case worth seeing at a glance, so it reads exactly like
    // any other change rather than borrowing the verdict's reassurance.
    const line = workspaceLine(
      turn({ workspaceDigestBefore: DIGEST_OPEN, workspaceDigestAfter: DIGEST_MOVED }),
    );
    expect(line.state).toBe("changed");
    expect(line.sentence).not.toContain("Unchanged");
  });

  it("says nothing was measured, and why, rather than claiming a clean turn", () => {
    const line = workspaceLine(turn({ workspaceDigestReason: "tree-over-budget", workspaceFilesBefore: 40000 }));
    expect(line.state).toBe("unmeasured");
    expect(line.sentence).toBe("Not measured: tree-over-budget.");
  });

  it("does not read a turn from an older journal as unchanged", () => {
    const line = workspaceLine(turn({}));
    expect(line.state).toBe("unmeasured");
    expect(line.sentence).toBe("Not recorded for this turn.");
  });

  it("says a running turn has an opening measurement and no closing one yet", () => {
    const line = workspaceLine(turn({ verdict: "running", rule: null, workspaceDigestBefore: DIGEST_OPEN }));
    expect(line.sentence).toBe("Measured at open. This turn has not ended yet.");
  });

  it("says so when only the closing value survived, instead of comparing one value with nothing", () => {
    const line = workspaceLine(turn({ workspaceDigestAfter: DIGEST_MOVED }));
    expect(line.sentence).toContain("one end of this turn only");
  });

  it("refuses the byte for byte claim over a tree the walk could not read all of", () => {
    // Two EQUAL digests, and they are worth less than they look: an unreadable subtree hashes to a
    // constant, so the digest cannot move for anything planted under it. Saying "byte for byte" here
    // would be the same false comfort as never measuring, one layer down.
    const line = workspaceLine(
      turn({
        workspaceDigestBefore: DIGEST_OPEN,
        workspaceDigestAfter: DIGEST_OPEN,
        workspaceFilesBefore: 9,
        workspaceFilesAfter: 9,
        workspaceUnreadableBefore: 0,
        workspaceUnreadableAfter: 3,
      }),
    );
    expect(line.state).toBe("partial");
    // the phrase appears only inside the disclaimer, never as the claim
    expect(line.sentence).not.toContain("Unchanged, byte for byte");
    expect(line.sentence).toBe(
      "Unchanged across the part of the tree that could be read. 3 entries could not be read at all." +
        " That is not a byte for byte claim over the whole workspace.",
    );
  });

  it("takes the worse of the two ends, so a partial opening walk is not hidden by a whole closing one", () => {
    const line = workspaceLine(
      turn({
        workspaceDigestBefore: DIGEST_OPEN,
        workspaceDigestAfter: DIGEST_OPEN,
        workspaceUnreadableBefore: 4,
        workspaceUnreadableAfter: 0,
      }),
    );
    expect(line.state).toBe("partial");
    expect(line.sentence).toContain("4 entries could not be read");
  });

  it("still names a change as a change over a partial tree, and says how much was unread", () => {
    const line = workspaceLine(
      turn({
        workspaceDigestBefore: DIGEST_OPEN,
        workspaceDigestAfter: DIGEST_MOVED,
        workspaceFilesBefore: 9,
        workspaceFilesAfter: 9,
        workspaceUnreadableAfter: 1,
      }),
    );
    expect(line.state).toBe("changed");
    expect(line.sentence).toContain("1 entries could not be read at all.");
  });

  it("says a zero unreadable count is a whole measurement, not a partial one", () => {
    const line = workspaceLine(
      turn({
        workspaceDigestBefore: DIGEST_OPEN,
        workspaceDigestAfter: DIGEST_OPEN,
        workspaceFilesAfter: 3,
        workspaceUnreadableBefore: 0,
        workspaceUnreadableAfter: 0,
      }),
    );
    expect(line.state).toBe("unchanged");
    expect(line.sentence).toContain("byte for byte");
  });

  it("does not tell a held turn it has closed, while still making the review screen's claim", () => {
    // A held turn has a real closing measurement, taken when it went to the queue, and the claim
    // under the review screen is exactly this one: none of the proposed changes is in the workspace.
    // But the sealed copy is still on disk and the turn has not ended, so "at close" was a lie.
    const line = workspaceLine(
      turn({
        verdict: "held",
        rule: "dependency-change",
        workspaceDigestBefore: DIGEST_OPEN,
        workspaceDigestAfter: DIGEST_OPEN,
        workspaceFilesBefore: 3,
        workspaceFilesAfter: 3,
      }),
    );
    expect(line.state).toBe("unchanged");
    expect(line.sentence).toBe(
      "Unchanged, byte for byte across 3 entries. sha256 1a2b3c4d5e6f at open and while this turn waits for review.",
    );
    expect(line.sentence).not.toContain("at close");
  });

  it("says where the walk stopped when the tree was over the bound, not just that it was", () => {
    // The bound is an entry count and it counts .git and node_modules, so an ordinary repository is
    // over it. "tree-over-budget" alone leaves a person unable to tell by how far.
    const line = workspaceLine(turn({ workspaceDigestReason: "tree-over-budget", workspaceFilesAfter: 20001 }));
    expect(line.sentence).toBe("Not measured: tree-over-budget. The walk stopped at 20001 entries.");
  });
});

describe("the timeline renders with the measurement threaded through", () => {
  it("puts every turn on the list, whether or not it carries a digest", () => {
    const journal: JournalResponse = {
      agentId: "11111111-1111-4111-8111-111111111111",
      turns: [
        turn({ workspaceDigestBefore: DIGEST_OPEN, workspaceDigestAfter: DIGEST_OPEN }),
        turn({ runId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", seq: 6 }),
      ],
      more: 0,
      chain: { ok: true, records: 9, problems: [] },
    };
    const html = renderToStaticMarkup(<RunTimeline journal={journal} agentName="agent" />);
    expect(html).toContain("Chain intact");
    expect(html.match(/class="turn turn-discarded"/g)).toHaveLength(2);
  });

  it("puts the sentence itself in the markup of a blocked turn, under a Workspace label", () => {
    // The claim the whole lane exists for, asserted where a person would actually read it.
    const html = renderToStaticMarkup(
      <TurnRow
        defaultOpen
        turn={turn({
          workspaceDigestBefore: DIGEST_OPEN,
          workspaceDigestAfter: DIGEST_OPEN,
          workspaceFilesBefore: 12,
          workspaceFilesAfter: 12,
          workspaceUnreadableBefore: 0,
          workspaceUnreadableAfter: 0,
        })}
      />,
    );
    expect(html).toContain("<dt>Workspace</dt>");
    expect(html).toContain("Unchanged, byte for byte across 12 entries. sha256 1a2b3c4d5e6f at open and at close.");
    expect(html).toContain("workspace-unchanged");
  });

  it("puts the change in the markup of a committed turn, and marks it a different state", () => {
    const html = renderToStaticMarkup(
      <TurnRow
        defaultOpen
        turn={turn({
          verdict: "committed",
          rule: null,
          workspaceDigestBefore: DIGEST_OPEN,
          workspaceDigestAfter: DIGEST_MOVED,
          workspaceFilesBefore: 12,
          workspaceFilesAfter: 14,
        })}
      />,
    );
    expect(html).toContain("Changed. 12 entries before, 14 after. sha256 1a2b3c4d5e6f became 9f8e7d6c5b4a.");
    expect(html).toContain("workspace-changed");
    expect(html).not.toContain("workspace-unchanged");
  });

  it("puts the refusal in the markup rather than leaving the row blank", () => {
    const html = renderToStaticMarkup(
      <TurnRow defaultOpen turn={turn({ workspaceDigestReason: "tree-over-budget", workspaceFilesAfter: 20001 })} />,
    );
    expect(html).toContain("Not measured: tree-over-budget. The walk stopped at 20001 entries.");
    expect(html).toContain("workspace-unmeasured");
  });

  it("puts the partial measurement in the markup, and never the words byte for byte", () => {
    const html = renderToStaticMarkup(
      <TurnRow
        defaultOpen
        turn={turn({
          workspaceDigestBefore: DIGEST_OPEN,
          workspaceDigestAfter: DIGEST_OPEN,
          workspaceUnreadableBefore: 2,
          workspaceUnreadableAfter: 2,
        })}
      />,
    );
    expect(html).toContain("workspace-partial");
    expect(html).toContain("2 entries could not be read at all.");
    expect(html).not.toContain("Unchanged, byte for byte");
  });

  it("keeps the row out of the collapsed markup, so the expanded assertions above mean something", () => {
    // If the panel rendered while closed, every assertion above would pass with the disclosure
    // broken, and the four of them would stop being evidence that the row is reachable at all.
    const html = renderToStaticMarkup(<TurnRow turn={turn({ workspaceDigestBefore: DIGEST_OPEN })} />);
    expect(html).not.toContain("<dt>Workspace</dt>");
  });
});


/**
 * The states have to be separable by eye, not only by class name.
 *
 * Every assertion above this point checks a class or a sentence, and both of those were true of a
 * panel on which all four states rendered in identical ink: the classes are emitted, and nothing in
 * styles.css has ever carried a rule for them. So "Changed" on a turn the policy blocked, which is
 * this product's headline claim failing, looked exactly like "Unchanged" on a turn that committed.
 * A class name nothing styles is a distinction the code makes and the person does not see.
 *
 * These assert the colour itself, and then assert it reaches the rendered row, because a tone map
 * that no markup uses is the dead-but-tested shape this lane already had to remove once.
 */
describe("the workspace state is visible, not just labelled", () => {
  it("gives each of the four states its own ink", () => {
    const inks = ["unchanged", "changed", "partial", "unmeasured"].map((state) => workspaceStyle(state).color);
    expect(new Set(inks).size).toBe(4);
  });

  it("paints a change in the alarm colour and a workspace that held still in the calm one", () => {
    expect(workspaceStyle("changed").color).toBe("var(--red)");
    expect(workspaceStyle("unchanged").color).toBe("var(--green)");
    // A claim withheld over part of the tree is not the clean claim, and must not be painted as it.
    expect(workspaceStyle("partial").color).toBe("var(--amber)");
    expect(workspaceStyle("unmeasured").color).toBe("var(--slate)");
  });

  it("treats a state it does not recognise as asserting nothing, never as the clean claim", () => {
    expect(workspaceStyle("a-state-added-later")).toEqual(workspaceStyle("unmeasured"));
    expect(workspaceStyle("a-state-added-later").color).not.toBe(workspaceStyle("unchanged").color);
  });

  it("carries the tone into the markup, so the blocked turn and the commit do not look alike", () => {
    const blocked = renderToStaticMarkup(
      <TurnRow
        defaultOpen
        turn={turn({
          workspaceDigestBefore: DIGEST_OPEN,
          workspaceDigestAfter: DIGEST_OPEN,
          workspaceUnreadableBefore: 0,
          workspaceUnreadableAfter: 0,
        })}
      />,
    );
    const committed = renderToStaticMarkup(
      <TurnRow
        defaultOpen
        turn={turn({
          verdict: "committed",
          rule: null,
          workspaceDigestBefore: DIGEST_OPEN,
          workspaceDigestAfter: DIGEST_MOVED,
        })}
      />,
    );
    expect(blocked).toContain("var(--green)");
    expect(blocked).not.toContain("var(--red)");
    expect(committed).toContain("var(--red)");
    expect(committed).not.toContain("var(--green)");
  });

  it("carries the tone onto a turn whose workspace moved although the policy blocked it", () => {
    // The row that matters most: blocked, and the bytes moved anyway. It must not be quiet.
    const html = renderToStaticMarkup(
      <TurnRow
        defaultOpen
        turn={turn({ workspaceDigestBefore: DIGEST_OPEN, workspaceDigestAfter: DIGEST_MOVED })}
      />,
    );
    expect(html).toContain("workspace-changed");
    expect(html).toContain("var(--red)");
  });
});

/**
 * The network half of the boundary, in the words a judge reads.
 *
 * The filesystem half is on this screen four times over. The network half was on it nowhere,
 * although every value below has been on the hash-chained journal all along: what the turn ran
 * inside, the per-run network, the allowlist, the terminated model channel, the broker's decision
 * counts, and what happened to the agent's own memory.
 *
 * The whole difficulty is that `confinement: "none"` IS A REAL VALUE. The host-process runtime
 * under SHADOW_ALLOW_UNCONFINED=1, which the Compose and ECS profiles use, journals it on every
 * turn. Four absences that are not the same absence have to render as four different things:
 *
 *   - the record says the turn WAS confined,
 *   - the record says "none", so it was NOT, and that must not be painted as the clean state,
 *   - the record predates these fields, so nothing is known,
 *   - there is no opening record at all, so not even the absence was journaled.
 */
const sealed = (patch: Partial<TimelineTurn> = {}): TimelineTurn =>
  turn({
    beginRecorded: true,
    confinement: "container+sealed-network",
    network: "shadow-291771a1-5a1e-49c3-b25a-8cde3ae6354b",
    egressAllowlistSize: 5,
    modelChannel: "terminated-at-broker",
    codexHomeFiles: 31,
    egress: { deny: 2, live: 2 },
    outboundDropped: 0,
    codexHomeRestored: false,
    codexHomeVerifiedUnchanged: true,
    ...patch,
  });

const unconfined = (patch: Partial<TimelineTurn> = {}): TimelineTurn =>
  turn({
    beginRecorded: true,
    confinement: "none",
    confinementReason: "SHADOW_ALLOW_UNCONFINED=1: host-process runtime, no network or filesystem jail",
    ...patch,
  });

/** an opening record from before any of this was journaled */
const predates = (patch: Partial<TimelineTurn> = {}): TimelineTurn => turn({ beginRecorded: true, ...patch });
/** no opening record at all, which does not stop the SETTLING record from carrying facts */
const noBegin = (patch: Partial<TimelineTurn> = {}): TimelineTurn => turn({ beginRecorded: false, ...patch });

describe("the network line on a turn row", () => {
  it("says what a person needs in one line: the mode, the network, the channel, the counts and the memory", () => {
    const line = networkLine(sealed());
    expect(line.state).toBe("sealed");
    expect(line.sentence).toBe(
      "Confined as container+sealed-network: the opening record names a container and a network " +
        "created for this run alone. Network shadow-291771a1-5a1e-49c3-b25a-8cde3ae6354b. " +
        "5 destinations on the egress allowlist. The opening record names the model channel " +
        "terminated-at-broker. Broker decisions: deny 2, live 2. No outbound write was held on this " +
        "turn, so none was dropped. The agent's memory, 31 files, came back unchanged in name, size, " +
        "timestamp and mode against the signature taken before the turn, so no rollback was needed.",
    );
  });

  it("draws no consequence out of a label, because a label is not a measurement", () => {
    // Both of these were sentences on this row. "whose only route out was the broker" restated the
    // product's headline claim out of one word in a note that `open()` composes BEFORE the container
    // is launched, so it described what was prepared. "so the provider credential stayed outside the
    // runtime" was drawn from `modelChannel`, which is only `network ? "terminated-at-broker" :
    // "direct"`. Both are true of the code and neither is a measurement, and on this screen a
    // sentence a judge reads as a finding must be backed by a record.
    const line = networkLine(sealed());
    expect(line.sentence).not.toContain("only route out");
    expect(line.sentence).not.toContain("credential");
    // and the record's own word is still there to be grepped in the journal
    expect(line.sentence).toContain("terminated-at-broker");
  });

  it("does not lend the workspace row's word to a comparison that never opened a file", () => {
    // `CodexHomeManager.signature` hashes rel|size|mtimeMs|mode per file. `workspaceDigest` on the
    // same card is over the bytes. One card, one word, two strengths of guarantee.
    const line = networkLine(sealed());
    expect(line.sentence).toContain("unchanged in name, size, timestamp and mode against the signature");
    expect(line.sentence).not.toContain("digest");
  });

  it("says a turn journaled as unconfined was not confined, and quotes the record's own reason", () => {
    const line = networkLine(unconfined());
    expect(line.state).toBe("unconfined");
    expect(line.sentence).toBe(
      "Not confined. The opening record says confinement none: no container and no sealed network " +
        "bounded this turn. The record's own reason: SHADOW_ALLOW_UNCONFINED=1: host-process runtime, " +
        "no network or filesystem jail.",
    );
    // not one word of the sealed claim survives onto a turn that had none of it
    expect(line.sentence).not.toContain("broker");
    expect(line.sentence).not.toContain("allowlist");
  });

  it("says nothing is known about a turn from before these fields, which is not the same as none", () => {
    const line = networkLine(predates());
    expect(line.state).toBe("unrecorded");
    expect(line.sentence).toBe(
      "Not recorded. This turn's opening record carries no confinement field, so what it ran inside " +
        "is unknown, which is not the same as knowing it ran inside nothing.",
    );
    expect(line.sentence).not.toContain("Not confined");
  });

  it("says so when the turn has no opening record at all, and scopes that to the opening record", () => {
    const line = networkLine(noBegin());
    expect(line.state).toBe("no-record");
    expect(line.sentence).toBe("No opening record for this turn, so what it ran inside was never journaled.");
  });

  it("says nothing came back rather than inventing an answer, when the server projects none of this", () => {
    // Every one of these fields is optional on the wire, so a panel served by a build that does not
    // project them sees undefined everywhere. That is a panel with no answer, not a turn that never
    // opened and not a turn that ran unconfined, and it must not print either of those or the word
    // undefined.
    const nothing = { ...turn({}), beginRecorded: undefined, confinement: undefined, confinementStateLost: undefined };
    const line = networkLine(nothing);
    expect(line.state).toBe("unrecorded");
    expect(line.sentence).toBe(
      "Not recorded. Nothing about the network half came back for this turn, so what it ran inside is unknown.",
    );
    expect(line.sentence).not.toContain("undefined");
    expect(line.sentence).not.toContain("null");
    expect(line.sentence).not.toContain("No opening record");
  });

  it("gives every state its own state word and its own sentence", () => {
    const lines = [
      sealed(),
      sealed({ networkLeaked: "shadow-291771a1" }),
      unconfined(),
      turn({ beginRecorded: true, confinement: "container" }),
      turn({ beginRecorded: true, confinement: "host-process" }),
      predates(),
      noBegin(),
    ].map(networkLine);
    expect(new Set(lines.map((line) => line.state)).size).toBe(7);
    expect(new Set(lines.map((line) => line.sentence)).size).toBe(7);
  });

  it("states the positive fact a bare container record makes, rather than reporting it as an absence", () => {
    // runner-factory.ts writes the bare word `container` ONLY on the branch where no network was
    // created, so that word is an affirmative record that the network half did not happen. Reading
    // it out as "nothing in this record says the network half was sealed" understated it as a gap in
    // the evidence.
    const line = networkLine(
      turn({ beginRecorded: true, confinement: "container", modelChannel: "direct", codexHomeFiles: 12, codexHomeChanged: 1 }),
    );
    expect(line.state).toBe("partial");
    expect(line.sentence).toBe(
      "Confined as container: the opening record names a container and says no per-run network was " +
        "sealed for this turn. The opening record names the model channel direct, not terminated at " +
        "a broker. The agent's memory, 12 files, was promoted with 1 entry changed.",
    );
    expect(line.sentence).not.toContain("Nothing in this record");
  });
});

describe("a confinement word this panel cannot read asserts nothing", () => {
  // The fallback used to run the other way. Anything that was not exactly "none" fell through to
  // `partial`, and the head then printed "Confined as <word>: the container half only", asserting a
  // container from a token the panel could not read. That is how `confinement: "none"` itself
  // rendered as "Confined as none: the container half only" until a special case was added for that
  // one word, which left the next mode word the runner adds to reintroduce the same failure.
  const unreadable = (word: string) => networkLine(turn({ beginRecorded: true, confinement: word }));

  it("refuses to assert a container for a word the runner does not write", () => {
    const line = unreadable("host-process");
    expect(line.state).toBe("unknown");
    expect(line.sentence).toBe(
      "The opening record names a confinement mode this panel cannot read: host-process. What it bounded is unknown.",
    );
    expect(line.sentence).not.toContain("Confined as");
  });

  it("treats an empty confinement value as unread, never as a container", () => {
    const line = unreadable("");
    expect(line.state).toBe("unknown");
    expect(line.sentence).toBe(
      "The opening record names a confinement mode this panel cannot read: an empty value. What it bounded is unknown.",
    );
    expect(line.sentence).not.toContain("Confined as ");
  });

  it("still reads the three words the runner actually writes", () => {
    expect(networkLine(turn({ beginRecorded: true, confinement: "container+sealed-network" })).state).toBe("sealed");
    expect(networkLine(turn({ beginRecorded: true, confinement: "container" })).state).toBe("partial");
    expect(networkLine(turn({ beginRecorded: true, confinement: "none" })).state).toBe("unconfined");
  });

  it("does not print network fields under a head that denies a network, and names the contradiction", () => {
    // The network name, the allowlist size and the model channel are all read off `turn.begin`, so a
    // record that denies confinement and carries them anyway contradicts itself. The detail clauses
    // used to be state-blind, so an unconfined head was followed by "The opening record names the
    // model channel terminated-at-broker" and a no-record head by a per-run network name.
    const line = networkLine(
      unconfined({ network: "shadow-abc", egressAllowlistSize: 5, modelChannel: "terminated-at-broker" }),
    );
    expect(line.state).toBe("unconfined");
    expect(line.sentence).toContain("the record contradicts itself and none of them is reported here.");
    expect(line.sentence).not.toContain("shadow-abc");
    expect(line.sentence).not.toContain("allowlist");
    expect(line.sentence).not.toContain("terminated-at-broker");
  });

  it("lets a turn with no opening record still report what its settle recorded", () => {
    // parseJournal skips a torn JSON line, so a crash mid-append to turn.begin gives exactly this
    // turn: no opening record, and a settling record full of facts. The head is scoped to the
    // opening record so the settle clauses do not contradict it.
    const line = networkLine(noBegin({ egress: { deny: 1 }, networkLeaked: "shadow-abc" }));
    expect(line.state).toBe("no-record");
    expect(line.sentence).toBe(
      "No opening record for this turn, so what it ran inside was never journaled. Broker decisions: " +
        "deny 1. The per-run network shadow-abc could not be removed, so it outlived the turn.",
    );
    expect(line.sentence).not.toContain("nothing was journaled");
  });
});

describe("a boundary that reports a failure of itself is not the clean claim", () => {
  it("does not paint a network that outlived its turn as sealed", () => {
    const line = networkLine(sealed({ networkLeaked: "shadow-291771a1" }));
    expect(line.state).toBe("breached");
    expect(line.sentence).toContain("This turn's boundary did not come back whole.");
    expect(line.sentence).toContain("The per-run network shadow-291771a1 could not be removed, so it outlived the turn.");
  });

  it("does not paint a settle that found no state as sealed", () => {
    const line = networkLine(sealed({ confinementStateLost: true }));
    expect(line.state).toBe("breached");
    expect(line.sentence).toContain("only the files half of it ran.");
  });

  it("breaches a bare container record too, and keeps naming the mode the record names", () => {
    const line = networkLine(turn({ beginRecorded: true, confinement: "container", confinementStateLost: true }));
    expect(line.state).toBe("breached");
    expect(line.sentence).toContain("Confined as container:");
  });

  it("leaves the alarm to the state that says nothing was bounded at all", () => {
    // A leak on top of confinement:"none" does not make it louder, and the unconfined row is the one
    // a person must not scroll past.
    expect(networkLine(unconfined({ networkLeaked: "shadow-abc", confinementStateLost: true })).state).toBe(
      "unconfined",
    );
  });

  it("still asks a breached turn for the broker summary it should have had", () => {
    expect(networkLine(sealed({ egress: null, networkLeaked: "shadow-abc" })).sentence).toContain(
      "No broker decision summary was recorded on the settle.",
    );
  });
});

describe("the network line reports each field's own absence", () => {
  it("says an allowlist of nothing allows nothing, and says nothing at all about an unrecorded one", () => {
    expect(networkLine(sealed({ egressAllowlistSize: 0 })).sentence).toContain(
      "The egress allowlist named no destinations at all.",
    );
    expect(networkLine(sealed({ egressAllowlistSize: null })).sentence).not.toContain("allowlist");
  });

  it("says the broker logged nothing, and separately that no summary was recorded", () => {
    expect(networkLine(sealed({ egress: {} })).sentence).toContain("The broker logged no outbound request on this turn.");
    expect(networkLine(sealed({ egress: null })).sentence).toContain(
      "No broker decision summary was recorded on the settle.",
    );
  });

  it("does not ask a running turn for settle facts it cannot have yet", () => {
    const line = networkLine(
      sealed({ verdict: "running", rule: null, egress: null, outboundDropped: null, codexHomeRestored: null, codexHomeVerifiedUnchanged: null }),
    );
    expect(line.state).toBe("sealed");
    expect(line.sentence).not.toContain("No broker decision summary");
    expect(line.sentence).not.toContain("memory");
  });

  it("says the memory was rolled back when it had moved", () => {
    expect(
      networkLine(sealed({ codexHomeRestored: true, codexHomeVerifiedUnchanged: false })).sentence,
    ).toContain("had moved, and was rolled back to the copy taken before the turn.");
  });

  it("keeps the count the opening record carried when the settle recorded nothing about the memory", () => {
    // "Nothing was recorded about the agent's memory" was a false absence claim while the projection
    // carried, and then dropped, the count the memory was sealed with at open.
    expect(
      networkLine(sealed({ codexHomeRestored: null, codexHomeVerifiedUnchanged: null })).sentence,
    ).toContain("The agent's memory was sealed with 31 files at open, and nothing was recorded about it on the settle.");
    expect(
      networkLine(sealed({ codexHomeFiles: null, codexHomeRestored: null, codexHomeVerifiedUnchanged: null })).sentence,
    ).toContain("Nothing was recorded about the agent's memory on the settle.");
    expect(
      networkLine(sealed({ codexHomeFiles: 1, codexHomeRestored: null, codexHomeVerifiedUnchanged: null })).sentence,
    ).toContain("sealed with 1 file at open");
  });

  it("does not read a rejected review's bookkeeping as a measurement", () => {
    // `settleReviewed` writes { restored: false, verifiedUnchanged: true, droppedAfterReview: true }
    // as a LITERAL, because the rollback already ran at the earlier review settle and this settle
    // only drops the sealed copy. buildTimeline reads the LAST settling record, so this is what a
    // review-then-reject projects, and it used to render the panel's most reassuring sentence.
    const line = networkLine(
      sealed({
        verdict: "rejected",
        codexHomeRestored: false,
        codexHomeVerifiedUnchanged: true,
        codexHomeDroppedAfterReview: true,
      }),
    );
    expect(line.sentence).toContain(
      "The agent's memory, 31 files, was not measured on this settle: the record marks it dropped " +
        "after review, so the restored and verified values beside that mark are bookkeeping rather " +
        "than evidence.",
    );
    expect(line.sentence).not.toContain("verified unchanged against");
    expect(line.sentence).not.toContain("no rollback was needed");
    // and a rejected review must not render identically to a turn that really was measured
    expect(line.sentence).not.toBe(networkLine(sealed({ verdict: "rejected" })).sentence);
  });

  it("reports a record that says the memory was both verified unchanged and rolled back as neither", () => {
    const line = networkLine(sealed({ codexHomeRestored: true, codexHomeVerifiedUnchanged: true }));
    expect(line.sentence).toContain(
      "is recorded both verified unchanged and rolled back on this settle. Those cannot both be true, " +
        "so neither is reported here.",
    );
    expect(line.sentence).not.toContain("no rollback was needed");
  });

  it("counts what is still held on a turn waiting for a person", () => {
    expect(
      networkLine(sealed({ verdict: "held", outboundDropped: null, outboundHeldForReview: 2 })).sentence,
    ).toContain("2 outbound writes are held, unsent, until a person decides.");
  });

  it("counts one of anything as one, because a plural on a count of one reads as a guess", () => {
    const one = networkLine(
      sealed({ egressAllowlistSize: 1, outboundDropped: 1, codexHomeRestored: null, codexHomeVerifiedUnchanged: null, codexHomeChanged: 1 }),
    ).sentence;
    expect(one).toContain("1 destination on the egress allowlist.");
    expect(one).toContain("1 held outbound write was dropped unsent.");
    expect(one).toContain("was promoted with 1 entry changed.");
    const held = networkLine(sealed({ outboundDropped: null, outboundHeldForReview: 1 })).sentence;
    expect(held).toContain("1 outbound write is held, unsent, until a person decides.");
    const sent = networkLine(sealed({ outboundDropped: null, outboundReplayed: 1, outboundFailed: 0 })).sentence;
    expect(sent).toContain("1 held outbound write was replayed when this turn settled: 1 sent, 0 not sent.");
  });

  it("says dropped writes were dropped, and does not report a drop that did not happen", () => {
    expect(networkLine(sealed({ outboundDropped: 2 })).sentence).toContain(
      "2 held outbound writes were dropped unsent.",
    );
    expect(networkLine(sealed({ outboundDropped: null })).sentence).not.toContain("dropped");
  });
});

/**
 * The replayed and failed counts, swept as a PAIR.
 *
 * They are DISJOINT: the sealer increments exactly one of the two per held payload, so the attempted
 * total is their sum. The panel rendered the failed count as "N of them failed to send" against the
 * replayed count, and a test in this file pinned that wrong sentence rather than catching it. Zero
 * was the arm nobody swept, and zero is the value the runner writes most often: `replay` returns
 * { replayed: 0, failed: 0 } for an empty held set, which is the ordinary committed turn.
 */
describe("the two halves of a replay are two halves, not a set and a subset", () => {
  const replay = (replayed: number | null, failed: number | null) =>
    networkLine(sealed({ verdict: "committed", rule: null, outboundDropped: null, outboundReplayed: replayed, outboundFailed: failed }))
      .sentence;

  it("names the attempted total and both parts, so a failure is never a subset of a success", () => {
    expect(replay(2, 1)).toContain("3 held outbound writes were replayed when this turn settled: 2 sent, 1 not sent.");
    expect(replay(2, 1)).not.toContain("of them failed to send");
  });

  it("renders a total failure to send as a total failure, not as arithmetic that cannot be read", () => {
    expect(replay(0, 3)).toContain("3 held outbound writes were replayed when this turn settled: 0 sent, 3 not sent.");
    expect(replay(0, 3)).not.toContain("0 held outbound writes were sent");
  });

  it("says nothing was waiting when both counts are zero, instead of printing a zero as padding", () => {
    expect(replay(0, 0)).toContain("No held outbound write was waiting when this turn settled, so none was replayed.");
    expect(replay(0, 0)).not.toContain(": 0 sent");
  });

  it("still reads a clean replay of everything held", () => {
    expect(replay(2, 0)).toContain("2 held outbound writes were replayed when this turn settled: 2 sent, 0 not sent.");
  });

  it("separates a settle that recorded no failures from one that recorded nothing about them", () => {
    // Before this, `outboundFailed: 0` rendered nothing at all, so a settle that measured zero
    // failures and a settle that measured nothing read alike.
    expect(replay(2, 0)).not.toBe(replay(2, null));
    expect(replay(2, null)).toContain("2 held outbound writes were sent when this turn settled. No failure count came back.");
  });

  it("never leaves the failed count standing alone with a pronoun that has no antecedent", () => {
    expect(replay(null, 3)).toContain("3 held outbound writes failed to send when this turn settled. No sent count came back.");
    expect(replay(null, 3)).not.toContain("of them");
    expect(replay(null, 1)).toContain("1 held outbound write failed to send");
  });

  it("says nothing at all when the settle recorded neither count", () => {
    expect(replay(null, null)).not.toContain("replayed");
    expect(replay(null, null)).not.toContain("failed to send");
  });

  it("does not name a commit the record does not carry", () => {
    // These are settle-record fields and the verdict is a separate fact on the same card. A
    // discarded turn carrying a replay count used to be told the turn committed.
    const discarded = networkLine(
      sealed({ verdict: "discarded", outboundDropped: null, outboundReplayed: 0, outboundFailed: 0 }),
    ).sentence;
    expect(discarded).not.toContain("committed");
  });

  it("says no write was held for review, rather than printing a zero count of them", () => {
    // runner-factory.ts writes heldForReview.length on every reviewed turn, and a turn held on a
    // filesystem rule has none, so this is the ordinary held turn.
    const line = networkLine(sealed({ verdict: "held", outboundDropped: null, outboundHeldForReview: 0 })).sentence;
    expect(line).toContain("No outbound write was held for a person to decide on.");
    expect(line).not.toContain("0 outbound writes are held");
  });
});

describe("the collapsed row's one word is only ever a failure", () => {
  it("names the two states that are affirmative failures of the boundary", () => {
    expect(networkFlag("unconfined")).toBe("Not confined");
    expect(networkFlag("breached")).toBe("Boundary incomplete");
  });

  it("says nothing for the clean state and nothing for a state that asserts nothing", () => {
    for (const state of ["sealed", "partial", "unknown", "unrecorded", "no-record", "anything-later"]) {
      expect(networkFlag(state), state + " must not put a word on the collapsed row").toBe("");
    }
  });
});

describe("the network line reaches the rendered row", () => {
  it("puts the sentence under a Network label on an expanded turn", () => {
    const html = renderToStaticMarkup(<TurnRow defaultOpen turn={sealed()} />);
    expect(html).toContain("<dt>Network</dt>");
    expect(html).toContain("network-sealed");
    expect(html).toContain("Network shadow-291771a1-5a1e-49c3-b25a-8cde3ae6354b.");
    expect(html).toContain("terminated-at-broker");
    expect(html).toContain("Broker decisions: deny 2, live 2.");
  });

  it("renders every state as a different row, and never lends the clean class to a failure", () => {
    const rows = [
      sealed(),
      sealed({ networkLeaked: "shadow-abc" }),
      unconfined(),
      turn({ beginRecorded: true, confinement: "container" }),
      turn({ beginRecorded: true, confinement: "host-process" }),
      predates(),
      noBegin(),
    ].map((each) => renderToStaticMarkup(<TurnRow defaultOpen turn={each} />));
    expect(new Set(rows).size).toBe(7);
    const [, leaked, notConfined] = rows;
    // the state that says nothing was bounded must not borrow the class the sealed state is painted
    // with, and must not carry a word of its sentence
    expect(notConfined).toContain("network-unconfined");
    expect(notConfined).not.toContain("network-sealed");
    expect(notConfined).not.toContain("names a container and a network created for this run alone");
    // and neither must the state where the boundary failed to come back whole. This is the class
    // itself, not the sentence: asserting only the sentence is why a leaked network shipped green.
    expect(leaked).toContain('class="network-state network-breached"');
    expect(leaked).not.toContain("network-sealed");
  });

  it("keeps the expanded row out of the collapsed markup, so the expanded assertions mean something", () => {
    // The same revert proof the Workspace row carries: without this, the whole Network block could
    // be deleted from TurnRow and every assertion in this file would stay green.
    const html = renderToStaticMarkup(<TurnRow turn={sealed()} />);
    expect(html).not.toContain("<dt>Network</dt>");
    expect(html).not.toContain("network-sealed");
  });

  it("puts the two states that are failures onto the collapsed row, where the run list is read", () => {
    // Every row ships collapsed, so until this the network half, the one thing this row exists to
    // put on a screen, was a click deep on every turn: a judge scanning a run list could not tell a
    // sealed turn from one journaled confinement:"none".
    const collapsed = (each: TimelineTurn) => renderToStaticMarkup(<TurnRow turn={each} />);
    expect(collapsed(unconfined())).toContain("network-flag-unconfined");
    expect(collapsed(unconfined())).toContain("Not confined");
    expect(collapsed(sealed({ networkLeaked: "shadow-abc" }))).toContain("network-flag-breached");
    expect(collapsed(sealed({ networkLeaked: "shadow-abc" }))).toContain("Boundary incomplete");
  });

  it("puts no chip on the collapsed row for a state that asserts nothing", () => {
    // A chip on every turn of an older journal would be noise standing where a finding should stand,
    // and the collapsed row claims nothing about containment either way.
    for (const each of [sealed(), predates(), noBegin(), turn({ beginRecorded: true, confinement: "host-process" })]) {
      expect(renderToStaticMarkup(<TurnRow turn={each} />)).not.toContain("network-flag-");
    }
  });

  it("carries the flag through a whole timeline, not only through a row built by hand", () => {
    // This test used to assert only that the page said "Chain intact", which it does with the entire
    // Network block deleted from TurnRow, because RunTimeline renders every row collapsed. It now
    // asserts the one part of the network row that reaches a collapsed page.
    const journal: JournalResponse = {
      agentId: "11111111-1111-4111-8111-111111111111",
      turns: [sealed(), unconfined({ runId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", seq: 6 })],
      more: 0,
      chain: { ok: true, records: 9, problems: [] },
    };
    const html = renderToStaticMarkup(<RunTimeline journal={journal} agentName="agent" />);
    expect(html).toContain("Chain intact");
    expect(html).toContain("network-flag-unconfined");
    expect(html).toContain("Not confined");
    // one flag, on the one turn that earned it
    expect(html.split("network-flag-").length - 1).toBe(1);
  });

  it("does not throw on any turn of a whole timeline, whatever its records carried", () => {
    const journal: JournalResponse = {
      agentId: "11111111-1111-4111-8111-111111111111",
      turns: [
        sealed(),
        sealed({ runId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", seq: 7, networkLeaked: "shadow-abc" }),
        unconfined({ runId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", seq: 6 }),
        predates(),
        noBegin(),
      ],
      more: 0,
      chain: { ok: true, records: 9, problems: [] },
    };
    expect(() => renderToStaticMarkup(<RunTimeline journal={journal} agentName="agent" />)).not.toThrow();
  });
});

/**
 * A class with no rule is unstyled text, and this repository shipped exactly that defect this week
 * when fourteen registry rows rendered as run-together spans. The Workspace row above had to set its
 * colour inline for the same reason: styles.css was another lane's file and the four
 * `workspace-<state>` classes it emits have never carried a rule.
 *
 * This lane owns styles.css, so the network row is styled there instead of inline, and these are
 * what make that real rather than assumed. They read the stylesheet the panel actually imports.
 */
const STYLES = readFileSync(new URL("../../styles.css", import.meta.url), "utf8");
const hasRuleFor = (className: string): boolean =>
  new RegExp("\\." + className + "\\s*[,{]").test(STYLES);

/** Named rather than crashing, because a helper that throws a TypeError names nothing. */
const ruleFor = (className: string): string => {
  const after = STYLES.split("." + className + " {")[1];
  expect(after, "styles.css has no `." + className + " {` block").toBeDefined();
  return after!.split("}")[0]!;
};

describe("every class the network row emits is a class the stylesheet paints", () => {
  it("has a rule for the base class and for all seven states", () => {
    for (const className of [
      "network-state",
      "network-sealed",
      "network-partial",
      "network-breached",
      "network-unconfined",
      "network-unknown",
      "network-unrecorded",
      "network-no-record",
      "turn-fact-wide",
    ]) {
      expect(hasRuleFor(className), className + " has no rule in styles.css").toBe(true);
    }
  });

  it("has a rule for the collapsed flag and for each state that carries one", () => {
    for (const className of ["turn-network-flag", "network-flag-unconfined", "network-flag-breached"]) {
      expect(hasRuleFor(className), className + " has no rule in styles.css").toBe(true);
    }
  });

  it("paints the unconfined state in the alarm colour and the sealed one in the calm colour", () => {
    expect(ruleFor("network-sealed")).toContain("var(--green)");
    expect(ruleFor("network-unconfined")).toContain("var(--red)");
    expect(ruleFor("network-partial")).toContain("var(--amber)");
    expect(ruleFor("network-unrecorded")).toContain("var(--slate)");
    // and the base rule is the neutral one, so a state added later that nothing paints reads as
    // asserting nothing rather than inheriting the clean claim
    expect(ruleFor("network-state")).toContain("var(--slate)");
  });

  it("does not paint a boundary that failed to come back whole in the calm colour", () => {
    const breached = ruleFor("network-breached");
    expect(breached).toContain("var(--red)");
    expect(breached).not.toContain("var(--green)");
    // a word this panel cannot read asserts nothing, so it is neither calm nor alarming
    const unknown = ruleFor("network-unknown");
    expect(unknown).toContain("var(--slate)");
    expect(unknown).not.toContain("var(--green)");
  });

  it("keeps a column for the collapsed flag, so a flagged row does not move the toggle", () => {
    expect(ruleFor("turn-summary")).toContain("54px 106px minmax(0, 1fr) auto 46px");
  });

  it("gives the row narrow-width treatment, like every other panel", () => {
    const narrow = STYLES.split("@media (max-width: 680px)").slice(1);
    expect(narrow.some((block) => block.includes(".network-state"))).toBe(true);
    expect(narrow.some((block) => block.includes(".turn-network-flag"))).toBe(true);
  });
});

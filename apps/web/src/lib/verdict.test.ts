import { describe, expect, it } from "vitest";
import { readMessage, verdictLabel, verdictOfTurn, verdictSentence, verdictTone } from "./verdict";
import type { TimelineTurn } from "../types";

const turn = (patch: Partial<TimelineTurn>): TimelineTurn => ({
  runId: "r",
  agentId: "a",
  verdict: "committed",
  rule: null,
  principal: null,
  seq: 1,
  at: null,
  mechanism: "copy",
  effectCount: 0,
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
  records: [],
  ...patch,
});

describe("the words on screen for what the boundary did", () => {
  it("says a blocked turn sent nothing, and names the rule", () => {
    const sentence = verdictSentence(verdictOfTurn(turn({ verdict: "discarded", rule: "execution-surface-write" })));
    expect(sentence).toBe("BLOCKED, nothing was sent: execution-surface-write");
  });

  it("counts proposed changes on a held turn", () => {
    expect(verdictSentence(verdictOfTurn(turn({ verdict: "held", effectCount: 3 })))).toBe(
      "Held for review: 3 proposed changes",
    );
    expect(verdictSentence(verdictOfTurn(turn({ verdict: "held", effectCount: 1 })))).toBe(
      "Held for review: 1 proposed change",
    );
  });

  it("counts changes on a committed turn", () => {
    expect(verdictSentence(verdictOfTurn(turn({ verdict: "committed", effectCount: 2 })))).toBe("Committed: 2 changes");
  });

  it("names the principal who approved a held turn", () => {
    expect(
      verdictSentence(verdictOfTurn(turn({ verdict: "approved", effectCount: 2, principal: "maksim@example.com" }))),
    ).toBe("Committed: 2 changes, approved by maksim@example.com");
  });

  it("never spells a blocked turn as an alarm", () => {
    const sentence = verdictSentence(verdictOfTurn(turn({ verdict: "discarded", rule: "multi-file-delete" })));
    expect(sentence).not.toContain("ABORT");
    expect(sentence.toUpperCase()).not.toContain("ERROR");
  });

  it("gives a conflicted turn the sentence that says nothing landed", () => {
    expect(verdictSentence(verdictOfTurn(turn({ verdict: "conflicted" })))).toBe(
      "Not applied: the workspace changed while this turn was running",
    );
  });

  it("tones a settled turn by outcome rather than by severity", () => {
    expect(verdictTone("committed")).toBe("good");
    expect(verdictTone("approved")).toBe("good");
    expect(verdictTone("discarded")).toBe("blocked");
    expect(verdictTone("held")).toBe("waiting");
    expect(verdictTone("restored")).toBe("neutral");
    expect(verdictLabel("discarded")).toBe("Blocked");
  });
});

describe("reading the runner's verdict off an assistant message", () => {
  it("splits a held turn's suffix from the body the agent wrote", () => {
    const content =
      "I updated package.json and added the install hook." +
      "\n\n[held for review: manifest-script-change. 2 proposed change(s) are waiting for a human. Nothing has been applied.]";
    const read = readMessage(content);
    expect(read.body).toBe("I updated package.json and added the install hook.");
    expect(read.verdict).toEqual({ verdict: "held", rule: "manifest-script-change", principal: null, changes: 2 });
  });

  it("splits a blocked turn's suffix and keeps the rule", () => {
    const content =
      "Done. I added the deployment workflow." +
      "\n\n[blocked by policy: execution-surface-write. 1 change(s) were discarded and nothing was applied.]";
    const read = readMessage(content);
    expect(read.body).toBe("Done. I added the deployment workflow.");
    expect(read.verdict?.verdict).toBe("discarded");
    expect(read.verdict?.rule).toBe("execution-surface-write");
  });

  it("reads a conflicted turn", () => {
    const content =
      "All set." + "\n\n[not applied: the workspace changed while this turn was running. Nothing has been applied.]";
    expect(readMessage(content).verdict?.verdict).toBe("conflicted");
  });

  it("leaves an ordinary reply alone", () => {
    const read = readMessage("I created src/hello.ts and ran the test.");
    expect(read.body).toBe("I created src/hello.ts and ran the test.");
    expect(read.verdict).toBeNull();
  });

  it("does not mistake a message that merely talks about a review for a verdict", () => {
    const read = readMessage("You should hold this for review before shipping it.");
    expect(read.verdict).toBeNull();
  });
});

describe("the verdicts a stopped commit produces", () => {
  it("says the workspace may be half written, and colours it as something to look at", () => {
    const v = verdictOfTurn(turn({ verdict: "unrecoverable" }));
    expect(verdictSentence(v)).toContain("Some changes may have landed");
    expect(verdictLabel("unrecoverable")).toBe("Unfinished");
    // neutral would read like "nothing happened", which is the one thing it does not mean
    expect(verdictTone("unrecoverable")).toBe("blocked");
  });

  it("stops saying nothing was applied when a conflict had already written files", () => {
    const partly = verdictOfTurn(turn({ verdict: "conflicted", appliedPaths: ["src/a.ts", "src/b.ts"] }));
    expect(verdictSentence(partly)).toContain("2 changes had already been written");
    expect(verdictSentence(partly)).not.toContain("Not applied");

    // and a conflict that really did apply nothing still says so
    const none = verdictOfTurn(turn({ verdict: "conflicted", appliedPaths: [] }));
    expect(verdictSentence(none)).toContain("Not applied");
  });

  it("carries appliedPaths out of the turn, so the sentence is not deciding on an absent field", () => {
    expect(verdictOfTurn(turn({ appliedPaths: ["x"] })).appliedPaths).toEqual(["x"]);
  });
});

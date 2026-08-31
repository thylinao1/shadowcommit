import { describe, it, expect } from "vitest";
import { toolEventsOf, modelUsageOf, usageText } from "../../../scripts/demo-drive.mjs";

/**
 * The two readers beat 3 of the demo now stands on, swept over the whole range of each field.
 *
 * WHY. Beat 3 claims the two things the track cares most about: a real model call and a real tool
 * call. It used to prove both by counting lines in `MOCK_PROVIDER_STATE/provider.jsonl`, a file the
 * MOCK provider writes, so against a real provider the file is absent, the count is 0 and the beat
 * fails. The product's own hash-chained journal and its run record carry both facts for any
 * provider, and `toolEventsOf` / `modelUsageOf` are what read them.
 *
 * Neither reader can be exercised by running the demo here: that needs Docker, a running platform
 * and a provider key. What CAN be exercised is every shape they have to tell apart, and the two
 * shapes that matter most are the ones no run on this machine produces:
 *
 *   a `turn.executed` with no `commands` field. The field is optional by design; absent means "this
 *   runner cannot see commands" and is NOT zero. Five such records are in the journal on this
 *   machine, written by builds from before the field existed.
 *
 *   a usage object with no numbers in it. `codex-runner.ts` builds usage with conditional spreads,
 *   so a provider answering with an empty usage block yields `{}`, which is truthy. A demo asserting
 *   `run.usage !== null` would pass on it and prove nothing, which is exactly the assertion-that-
 *   cannot-fail this lane was opened to remove.
 *
 * This file is `.mjs` on purpose. `apps/server/tsconfig.json` includes only `src/**\/*.ts`, so tsc
 * never sees it, while vitest's default include picks up `.test.mjs` and runs it with `npm test`.
 */

/** The real record from the BytePlus Ark run, runId 4a068c04, seq 53, fields verbatim. */
const REAL_EXECUTED = {
  seq: 53,
  runId: "4a068c04-becc-477b-b50c-a755324c1068",
  kind: "turn.executed",
  exit: "ok",
  commands: 9,
  commandsFailed: 0,
};

/** The same record as five earlier runs in the same journal wrote it: no `commands` at all. */
const LEGACY_EXECUTED = { seq: 4, runId: "80d47259", kind: "turn.executed", exit: "ok" };

describe("toolEventsOf reads tool events out of the journal's turn.executed record", () => {
  it("reports the counts a real run recorded", () => {
    const events = toolEventsOf([{ kind: "turn.begin" }, REAL_EXECUTED, { kind: "effects.captured" }]);
    expect(events).toMatchObject({
      recorded: true,
      reported: true,
      exit: "ok",
      commands: 9,
      commandsFailed: 0,
    });
  });

  it("does not read an absent commands field as zero commands", () => {
    const events = toolEventsOf([LEGACY_EXECUTED]);
    expect(events.recorded).toBe(true);
    expect(events.exit).toBe("ok");
    // The whole point: the record exists, the runner said nothing about commands, and nothing here
    // invents a count. `reported: false` is what makes beat 3 print a finding instead of asserting.
    expect(events.reported).toBe(false);
    expect(events.commands).toBeNull();
    expect(events.commandsFailed).toBeNull();
  });

  it("keeps zero commands distinct from no report of commands", () => {
    const ran = toolEventsOf([{ kind: "turn.executed", exit: "ok", commands: 0, commandsFailed: 0 }]);
    const silent = toolEventsOf([LEGACY_EXECUTED]);
    expect(ran.reported).toBe(true);
    expect(ran.commands).toBe(0);
    expect(silent.reported).toBe(false);
    expect(silent.commands).toBeNull();
    expect(ran.reported).not.toBe(silent.reported);
  });

  it("reports a turn whose commands failed, and how many", () => {
    const events = toolEventsOf([
      {
        kind: "turn.executed",
        exit: "ok",
        commands: 3,
        commandsFailed: 1,
        failed: [{ command: "npm install", exitCode: 124, status: "failed" }],
      },
    ]);
    expect(events.reported).toBe(true);
    expect(events.commands).toBe(3);
    expect(events.commandsFailed).toBe(1);
    expect(events.failed).toHaveLength(1);
    expect(events.failed[0].exitCode).toBe(124);
  });

  it('carries the crash path\'s exit: "failed" through rather than flattening it to ok', () => {
    const events = toolEventsOf([{ kind: "turn.executed", exit: "failed" }]);
    expect(events.recorded).toBe(true);
    expect(events.exit).toBe("failed");
    expect(events.reported).toBe(false);
  });

  it("says nothing was recorded when no turn.executed record is present", () => {
    for (const records of [[], null, undefined, [{ kind: "turn.begin" }, { kind: "seal.release" }]]) {
      const events = toolEventsOf(records);
      expect(events.recorded).toBe(false);
      expect(events.reported).toBe(false);
      expect(events.commands).toBeNull();
      expect(events.exit).toBeNull();
    }
  });

  it("refuses a commandsFailed that arrives without a commands count", () => {
    // A malformed record, not a report of zero commands: without `commands` there is no denominator
    // and "0 failed" would read as a clean turn on a record that counted nothing.
    const events = toolEventsOf([{ kind: "turn.executed", exit: "ok", commandsFailed: 2 }]);
    expect(events.reported).toBe(false);
    expect(events.commands).toBeNull();
    expect(events.commandsFailed).toBeNull();
  });

  it("rejects non-numeric and negative counts rather than passing them into an assertion", () => {
    for (const bad of ["9", null, true, {}, [], Number.NaN, Infinity, -1]) {
      const events = toolEventsOf([{ kind: "turn.executed", exit: "ok", commands: bad }]);
      expect(events.reported, "commands: " + JSON.stringify(bad)).toBe(false);
      expect(events.commands).toBeNull();
    }
  });

  it("defaults commandsFailed to zero only when commands really was reported", () => {
    const events = toolEventsOf([{ kind: "turn.executed", exit: "ok", commands: 4 }]);
    expect(events.reported).toBe(true);
    expect(events.commands).toBe(4);
    expect(events.commandsFailed).toBe(0);
  });

  it("takes the last turn.executed record when a run somehow carries two", () => {
    const events = toolEventsOf([
      { kind: "turn.executed", exit: "ok", commands: 1, commandsFailed: 0 },
      { kind: "turn.executed", exit: "failed" },
    ]);
    expect(events.exit).toBe("failed");
    expect(events.reported).toBe(false);
  });

  it("does not mutate the records it was handed", () => {
    const records = [{ kind: "turn.begin" }, REAL_EXECUTED];
    const before = JSON.stringify(records);
    toolEventsOf(records);
    expect(JSON.stringify(records)).toBe(before);
    expect(records[0].kind).toBe("turn.begin");
  });
});

describe("modelUsageOf reads the model call out of the run record", () => {
  it("reports the counts a mock-path run recorded", () => {
    const usage = modelUsageOf({ usage: { inputTokens: 256, cachedInputTokens: 0, outputTokens: 64 } });
    expect(usage.present).toBe(true);
    expect(usage.tokens).toBe(320);
    expect(usageText(usage)).toBe("in 256, cached 0, out 64");
  });

  it("does not accept an empty usage object as evidence the model was called", () => {
    // The vacuous case. `codex-runner.ts` builds usage with conditional spreads, so a provider that
    // answers with a usage block carrying no numbers produces `{}`, and `run.usage !== null` passes
    // on it. This must not.
    const usage = modelUsageOf({ usage: {} });
    expect(usage.present).toBe(false);
    expect(usage.tokens).toBe(0);
    expect(usageText(usage)).toBe("in -, cached -, out -");
  });

  it("reports no usage for a run record that carries none", () => {
    for (const run of [{ usage: null }, {}, null, undefined, { usage: "128" }, { usage: 128 }]) {
      const usage = modelUsageOf(run);
      expect(usage.present, JSON.stringify(run)).toBe(false);
      expect(usage.tokens).toBe(0);
    }
  });

  it("counts a single reported field, whichever one it is", () => {
    expect(modelUsageOf({ usage: { inputTokens: 128 } })).toMatchObject({ present: true, tokens: 128 });
    expect(modelUsageOf({ usage: { outputTokens: 7 } })).toMatchObject({ present: true, tokens: 7 });
    // Cached-only is a provider that served the whole prompt from its cache. It still answered.
    expect(modelUsageOf({ usage: { cachedInputTokens: 12 } })).toMatchObject({ present: true, tokens: 12 });
  });

  it("treats an all-zero usage block as reported but not as proof of a call", () => {
    // Present, because the provider did send numbers; tokens 0, so beat 3's `tokens > 0` still
    // fails and the run is not credited with a model call it cannot evidence.
    const usage = modelUsageOf({ usage: { inputTokens: 0, cachedInputTokens: 0, outputTokens: 0 } });
    expect(usage.present).toBe(true);
    expect(usage.tokens).toBe(0);
  });

  it("rejects non-numeric, negative and non-finite token counts", () => {
    for (const bad of ["256", null, true, {}, [], Number.NaN, Infinity, -1]) {
      const usage = modelUsageOf({ usage: { inputTokens: bad } });
      expect(usage.present, "inputTokens: " + JSON.stringify(bad)).toBe(false);
      expect(usage.inputTokens).toBeNull();
    }
  });

  it("keeps a good field when a bad one sits beside it", () => {
    const usage = modelUsageOf({ usage: { inputTokens: 100, cachedInputTokens: "0", outputTokens: -4 } });
    expect(usage.present).toBe(true);
    expect(usage.tokens).toBe(100);
    expect(usage.inputTokens).toBe(100);
    expect(usage.cachedInputTokens).toBeNull();
    expect(usage.outputTokens).toBeNull();
    expect(usageText(usage)).toBe("in 100, cached -, out -");
  });
});

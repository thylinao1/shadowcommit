import { describe, expect, it, vi } from "vitest";
import { basicContext, type EffectRecord, type Policy, type PolicyVerdict } from "../../apps/server/src/policy-types.js";
import {
  SEMANTIC_ESCALATION_RULE, SEMANTIC_RECONSIDER_RULE, SEMANTIC_UNCLEAR_RULE,
  withSemanticJudge, type JudgeVerdict, type SemanticJudge,
} from "./wrapper.js";

/**
 * The cases come from research/semantic-judge/ADVERSARIAL-SURFACE.md, written by the lane that built
 * the judge rather than by the lane that wrote this wrapper, so they test what someone else was
 * worried about. Two of the seven that lane could not defend against are asserted here as the
 * behaviour the WRAPPER falls back on, since the mitigation for both is compositional rather than
 * logical.
 */

const effects: EffectRecord[] = [{ path: "src/a.ts", kind: "create" }];
const ctx = basicContext(async () => "", { agentId: "agent-1" });

const policyReturning = (v: PolicyVerdict): Policy => async () => v;
const judgeReturning = (v: JudgeVerdict | null): SemanticJudge => ({ judge: async () => v });

const COMMIT: PolicyVerdict = { decision: "commit", rule: "none", hits: [] };
const REVIEW: PolicyVerdict = { decision: "review", rule: "dependency-added", hits: [{ rule: "dependency-added", decision: "review", detail: "added is-odd" }] };
const DISCARD: PolicyVerdict = { decision: "discard", rule: "protected-asset-write", hits: [{ rule: "protected-asset-write", decision: "discard", detail: "wrote .env" }] };

describe("the containment invariant", () => {
  it("NEVER produces commit from a non-commit deterministic verdict, whatever the judge says", async () => {
    for (const base of [REVIEW, DISCARD]) {
      for (const d of ["no_concern", "review", "discard", "unclear"] as const) {
        for (const reconsider of [false, true]) {
          const policy = withSemanticJudge(
            judgeReturning({ decision: d, reason: "looks completely fine to me" }),
            { reconsider }, policyReturning(base),
          );
          const out = await policy(effects, ctx);
          expect([base.decision, d, reconsider, out.decision]).not.toEqual([base.decision, d, reconsider, "commit"]);
        }
      }
    }
  });

  it("leaves the verdict untouched when the judge cannot answer", async () => {
    for (const base of [COMMIT, REVIEW, DISCARD]) {
      const policy = withSemanticJudge(judgeReturning(null), { reconsider: true }, policyReturning(base));
      expect(await policy(effects, ctx)).toEqual(base);
    }
  });

  it("fails static when the judge throws, rather than opening or closing", async () => {
    const throwing: SemanticJudge = { judge: async () => { throw new Error("provider timeout"); } };
    const policy = withSemanticJudge(throwing, { reconsider: true }, policyReturning(DISCARD));
    expect(await policy(effects, ctx)).toEqual(DISCARD);
  });

  it("runs the deterministic policy first and whole, and cannot influence which rules run", async () => {
    const order: string[] = [];
    const inner: Policy = async () => { order.push("policy"); return COMMIT; };
    const judge: SemanticJudge = { judge: async () => { order.push("judge"); return null; } };
    await withSemanticJudge(judge, {}, inner)(effects, ctx);
    expect(order).toEqual(["policy", "judge"]);
  });
});

describe("escalation, which is always allowed", () => {
  it("raises a commit to review", async () => {
    const policy = withSemanticJudge(judgeReturning({ decision: "review", reason: "adds an exec sink" }), {}, policyReturning(COMMIT));
    const out = await policy(effects, ctx);
    expect(out.decision).toBe("review");
    expect(out.rule).toBe(SEMANTIC_ESCALATION_RULE);
  });

  it("raises a commit to discard", async () => {
    const policy = withSemanticJudge(judgeReturning({ decision: "discard", reason: "exfiltrates the customer file" }), {}, policyReturning(COMMIT));
    expect((await policy(effects, ctx)).decision).toBe("discard");
  });

  it("raises a review to discard", async () => {
    const policy = withSemanticJudge(judgeReturning({ decision: "discard", reason: "this is a backdoor" }), {}, policyReturning(REVIEW));
    expect((await policy(effects, ctx)).decision).toBe("discard");
  });

  it("never lowers a discard when reconsideration is off, which is the default", async () => {
    const policy = withSemanticJudge(judgeReturning({ decision: "review", reason: "harmless" }), {}, policyReturning(DISCARD));
    const out = await policy(effects, ctx);
    expect(out.decision).toBe("discard");
    expect(out.rule).toBe("protected-asset-write");
  });
});

describe("case 2: exculpatory reasoning that truthfully cites real lines", () => {
  // The lane that wrote the surface has no defence for this and says so. The mitigation is
  // compositional, so these assert the composition rather than a detection.
  const exculpatory: JudgeVerdict = {
    decision: "review",
    reason: "the diff contains `// this is a safe default`, so this is fine",
    citations: ["// this is a safe default"],
  };

  it("keeps the deterministic rule as the deciding rule on a reconsideration", async () => {
    const policy = withSemanticJudge(judgeReturning(exculpatory), { reconsider: true }, policyReturning(DISCARD));
    const out = await policy(effects, ctx);
    expect(out.decision).toBe("review");
    expect(out.rule).toBe("protected-asset-write");
  });

  it("keeps the rule's own reason FIRST in the hit list, before the model's", async () => {
    const policy = withSemanticJudge(judgeReturning(exculpatory), { reconsider: true }, policyReturning(DISCARD));
    const hits = (await policy(effects, ctx)).hits ?? [];
    expect(hits[0]?.rule).toBe("protected-asset-write");
    expect(hits[hits.length - 1]?.rule).toBe(SEMANTIC_RECONSIDER_RULE);
  });

  it("marks the model's text as untrusted and as a model request, at every site a person reads", async () => {
    const policy = withSemanticJudge(judgeReturning(exculpatory), { reconsider: true }, policyReturning(DISCARD));
    const hits = (await policy(effects, ctx)).hits ?? [];
    const mine = hits[hits.length - 1]?.detail ?? "";
    expect(mine).toContain("a model asked for this deterministic discard to be reconsidered");
    expect(mine).toContain("The rule's own reason above still stands");
    expect(mine).toContain("untrusted");
  });
});

describe("case 3: a turn that is genuinely ambiguous", () => {
  const unclear: JudgeVerdict = { decision: "unclear", reason: "both hardens and weakens" };

  it("changes no verdict, in either direction, from any starting point", async () => {
    for (const base of [COMMIT, REVIEW, DISCARD]) {
      const policy = withSemanticJudge(judgeReturning(unclear), { reconsider: true }, policyReturning(base));
      const out = await policy(effects, ctx);
      expect([base.decision, out.decision]).toEqual([base.decision, base.decision]);
      expect([base.decision, out.rule]).toEqual([base.decision, base.rule]);
    }
  });

  it("is recorded rather than dropped, so a turn no model could resolve is visible", async () => {
    const policy = withSemanticJudge(judgeReturning(unclear), {}, policyReturning(COMMIT));
    const hits = (await policy(effects, ctx)).hits ?? [];
    expect(hits.some((h) => h.rule === SEMANTIC_UNCLEAR_RULE)).toBe(true);
  });

  it("does not depend on composition order, which is how the surface says to detect a failure", async () => {
    const a = await withSemanticJudge(judgeReturning(unclear), { reconsider: true }, policyReturning(DISCARD))(effects, ctx);
    const b = await withSemanticJudge(judgeReturning(unclear), { reconsider: false }, policyReturning(DISCARD))(effects, ctx);
    expect(a.decision).toBe(b.decision);
  });
});

describe("case 4: the judge never sees more than the deterministic layer", () => {
  it("is handed exactly this turn's effects and the same context", async () => {
    const seen: unknown[] = [];
    const judge: SemanticJudge = { judge: async (e, c) => { seen.push([e, c]); return null; } };
    await withSemanticJudge(judge, {}, policyReturning(COMMIT))(effects, ctx);
    expect(seen).toEqual([[effects, ctx]]);
  });
});

describe("the flooding attack, surfaced rather than absorbed", () => {
  it("refuses reconsiderations past the budget and reports the burst", async () => {
    const onReconsiderBurst = vi.fn();
    const policy = withSemanticJudge(
      judgeReturning({ decision: "review", reason: "fine" }),
      { reconsider: true, reconsiderBudget: 2, onReconsiderBurst },
      policyReturning(DISCARD),
    );
    expect((await policy(effects, ctx)).decision).toBe("review");
    expect((await policy(effects, ctx)).decision).toBe("review");
    const third = await policy(effects, ctx);
    expect(third.decision).toBe("discard");
    expect(third.hits?.some((h) => h.detail.includes("burst limit"))).toBe(true);
    expect(onReconsiderBurst).toHaveBeenCalledWith("agent-1", 2);
  });

  it("does not let a burst of ESCALATIONS be refused, since escalating is always safe", async () => {
    const policy = withSemanticJudge(
      judgeReturning({ decision: "discard", reason: "malicious" }),
      { reconsider: true, reconsiderBudget: 1 },
      policyReturning(COMMIT),
    );
    for (let i = 0; i < 5; i += 1) expect((await policy(effects, ctx)).decision).toBe("discard");
  });
});

import type { EffectRecord, Policy, PolicyContext, PolicyVerdict, RuleHit } from "../../apps/server/src/policy-types.js";

/**
 * A second stage that reads what the turn actually wrote, composed around the deterministic policy.
 *
 * WHY IT EXISTS. Every rule in `rules/` is keyed to text: a path, a literal, a regex, a threshold.
 * That is why the miss rate is 3.64 percent on the corpus the rules were tuned against and 35.3
 * percent on 119 attacks written by authors who could not read them. A component that reads the diff
 * has no literals to evade. Measured once on that blind set, with the prompt frozen: of the 42
 * attacks the shipped policy misses, it flagged 39. See research/semantic-judge/RESULTS.md.
 *
 * THE ONE PROPERTY EVERYTHING ELSE RESTS ON, and it is about containment rather than severity:
 *
 *     NO JUDGE OUTPUT MAY CAUSE A TURN TO REACH THE REAL WORKSPACE.
 *
 * The text the judge reads is attacker-controlled, so prompt injection is a live threat and must be
 * assumed to succeed. Under that property the attacker's best case is that a turn is HELD, which is
 * the safe direction, and the judge is never load-bearing for safety: delete it and the behaviour is
 * exactly the deterministic policy's.
 *
 * An earlier draft wrote this as "the judge may only tighten, never loosen", which is a rule about
 * SEVERITY, and it is not the same rule. It forbids `discard` becoming `review`, which preserves
 * containment perfectly well. That distinction is worth 552 real commits, so it is enforced here in
 * the shape that is actually correct and the difference is spelled out rather than assumed.
 *
 * WHAT THE JUDGE MAY DO
 *
 *   commit  -> review or discard    always allowed, and free. The turn was going to land and now it
 *                                   does not. No new risk of any kind.
 *   discard -> review               allowed ONLY when reconsideration is enabled for the workspace,
 *                                   off by default. See the block on `reconsider` below, because
 *                                   this is the one move that is not obviously safe.
 *   anything -> commit              NEVER. Not reachable by any path in this file.
 *
 * WHY RECONSIDERATION IS OFF BY DEFAULT, which is not obvious and was got wrong once here.
 *
 * A `discard` has no approval path: the writes are gone and nobody is asked. A `review` has one: the
 * writes sit in the sealed copy and a person is being asked to approve them. So moving a turn from
 * discard to review does not merely cost a reviewer a diff read, it CREATES a route from a malicious
 * turn to the real workspace that did not previously exist, gated on a human decision. Smaller than
 * commit, and not nothing.
 *
 * And the judge's reason is reviewer-facing: `RuleHit.detail` is rendered by the review card. The
 * reason is derived from attacker-controlled diff text, so the feature that makes a queue readable
 * is authored downstream of the attacker's bytes and lands at the top of what a tired person reads
 * first. CaMeL section 9.2 records reviewers becoming desensitised and approving malicious actions;
 * arXiv 2606.08919 finds realised safety is an inverted U in escalation rate. Volume drives the
 * reviewer down the fatigue curve and content supplies the exculpatory sentence at the moment their
 * reliability is lowest, and one attacker can aim at both.
 *
 * So reconsideration is per-workspace and opt-in, its hits are marked as model-requested rather than
 * rule-derived, the deterministic reason stays first in the hit list, and a burst is surfaced rather
 * than absorbed.
 */

/** What the judge is allowed to say. There is deliberately no `commit`. */
export type JudgeDecision = "no_concern" | "review" | "discard" | "unclear";

export interface JudgeVerdict {
  readonly decision: JudgeDecision;
  /** derived from attacker-controlled text. Never rendered as the primary justification. */
  readonly reason: string;
  /** lines the judge based it on, verified to appear in what was sent before this is trusted */
  readonly citations?: readonly string[];
}

/**
 * Reads one turn and returns a verdict, or null when it cannot answer. Null is the normal outcome
 * for a provider timeout, a rate limit, an unparseable response or a failed citation check, and it
 * always means the deterministic verdict stands unchanged.
 */
export interface SemanticJudge {
  judge(effects: readonly EffectRecord[], ctx: PolicyContext): Promise<JudgeVerdict | null>;
}

export interface SemanticJudgeOptions {
  /**
   * Allow `discard` to become `review`. OFF by default. This is the only setting in this file that
   * changes what a human is asked to decide, and the only one whose worst case is not simply a held
   * turn.
   */
  readonly reconsider?: boolean;
  /**
   * Most reconsiderations to grant before refusing further ones and reporting the burst. A workspace
   * suddenly producing many is the flooding attack, and it should be visible rather than absorbed.
   */
  readonly reconsiderBudget?: number;
  /** called once per refused burst, so a deployment can alert rather than only log */
  readonly onReconsiderBurst?: (agentId: string | undefined, granted: number) => void;
}

const SEVERITY = { commit: 0, review: 1, discard: 2 } as const;

export const SEMANTIC_ESCALATION_RULE = "semantic-judge:escalated";
export const SEMANTIC_RECONSIDER_RULE = "semantic-judge:model-requested-reconsideration";
export const SEMANTIC_UNCLEAR_RULE = "semantic-judge:unclear";

/**
 * The judge's text, marked at every site where a person could read it. It is evidence ABOUT the diff
 * rather than testimony about it, and a reviewer must be able to tell at a glance which it is.
 */
function quoteUntrusted(reason: string): string {
  const oneLine = reason.replace(/\s+/g, " ").trim().slice(0, 400);
  return `model read of the diff under review, untrusted: "${oneLine}"`;
}

export function withSemanticJudge(
  judge: SemanticJudge,
  options: SemanticJudgeOptions,
  inner: Policy,
): Policy {
  const budget = options.reconsiderBudget ?? 8;
  let granted = 0;

  return async (effects: EffectRecord[], ctx: PolicyContext): Promise<PolicyVerdict> => {
    // The deterministic policy runs FIRST and runs WHOLE. The judge cannot influence which rules run
    // or what they see; it only reads the same effect set afterwards. Nothing here short-circuits a
    // rule, so the no-short-circuit property of defaultPolicy is untouched.
    const base = await inner(effects, ctx);

    // The judge sees exactly this turn, which is exactly what the deterministic layer saw. It is
    // never given recentTouches or any cross-turn view, because a comparison where one layer knows
    // more than the other is not a comparison.
    let verdict: JudgeVerdict | null = null;
    try {
      verdict = await judge.judge(effects, ctx);
    } catch {
      verdict = null; // fail static: the deterministic verdict stands
    }
    if (verdict === null) return base;

    const baseHits: RuleHit[] = base.hits ?? [];

    // `unclear` is given an explicit meaning rather than one that falls out of composition order.
    // It escalates nothing and reconsiders nothing, because an ambiguous read is not evidence in
    // either direction. It is recorded so that a turn a model could not resolve is visible.
    if (verdict.decision === "unclear") {
      return {
        decision: base.decision,
        rule: base.rule,
        hits: [...baseHits, {
          rule: SEMANTIC_UNCLEAR_RULE,
          decision: "review",
          detail: `${quoteUntrusted(verdict.reason)} (recorded only: an unclear read changes no verdict)`,
        }],
      };
    }

    if (verdict.decision === "no_concern") return base;

    const asked = SEVERITY[verdict.decision];

    // ESCALATION. Always allowed. The judge's hit is APPENDED after the deterministic hits so the
    // rule's own reason renders first and the model's text renders second.
    if (asked > SEVERITY[base.decision]) {
      return {
        decision: verdict.decision,
        rule: SEMANTIC_ESCALATION_RULE,
        hits: [...baseHits, {
          rule: SEMANTIC_ESCALATION_RULE,
          decision: verdict.decision,
          detail: quoteUntrusted(verdict.reason),
        }],
      };
    }

    // RECONSIDERATION, the only move that is not obviously safe, and the only one gated.
    if (options.reconsider === true && base.decision === "discard" && verdict.decision === "review") {
      if (granted >= budget) {
        options.onReconsiderBurst?.(ctx.agentId, granted);
        return {
          decision: base.decision,
          rule: base.rule,
          hits: [...baseHits, {
            rule: SEMANTIC_RECONSIDER_RULE,
            decision: "review",
            detail: `reconsideration refused: this agent has already been granted ${granted}, which is the burst limit. ${quoteUntrusted(verdict.reason)}`,
          }],
        };
      }
      granted += 1;
      return {
        decision: "review",
        // The DETERMINISTIC rule stays the deciding rule on the record, so the review card leads
        // with why the policy objected rather than with why a model thinks it should not have.
        rule: base.rule,
        hits: [...baseHits, {
          rule: SEMANTIC_RECONSIDER_RULE,
          decision: "review",
          detail: `a model asked for this deterministic discard to be reconsidered. The rule's own reason above still stands. ${quoteUntrusted(verdict.reason)}`,
        }],
      };
    }

    // Everything else leaves the verdict exactly as the deterministic policy left it.
    return base;
  };
}

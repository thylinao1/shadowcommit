import type { EffectRecord, Policy, PolicyContext, PolicyVerdict, RuleHit } from "./policy-types.js";
import { classify } from "./effect-classifier.js";
import { rules } from "./rules/index.js";

/**
 * Judges the effect set a turn actually produced, after it produced it, in a place where producing
 * it changed nothing real. Two structural properties matter more than any individual rule:
 *
 * **Classify, then judge.** Every effect is given a class first, written onto the record itself so
 * that the review panel and the ledger name it the same way this file does. The policy then knows
 * the difference between a dependency tree an install wrote, a file whose contents decide what runs
 * later, and the agent's own source. Without that step the policy judged all three by the same
 * rules, which is how the organizers' own acceptance task ("create a TypeScript hello-world CLI,
 * add a test") got discarded: `npm install @types/node` writes five JSDoc lines reading
 * `const password = 'Password used to generate key';` and a path-and-content policy with no notion
 * of what the turn was for cannot tell that from a credential the agent chose to write.
 *
 * **No short-circuit.** The shipped policy returned on the first rule that fired, so whichever rule
 * happened to be listed first decided the turn and every other signal was invisible. Now every rule
 * runs over every effect, all hits are collected, and the worst decision wins (discard beats review
 * beats commit). The operator gets the whole picture; the verdict is still one word.
 */
const SEVERITY = { commit: 0, review: 1, discard: 2 } as const;

export const defaultPolicy: Policy = async (
  effects: EffectRecord[],
  ctx: PolicyContext,
): Promise<PolicyVerdict> => {
  // The class is written onto the captured record, not onto a copy of it. That record is the object
  // the runner keeps: it becomes `held.effects` and the `turn.held` payload in the ledger, so a
  // class computed on a copy is one the review panel and the audit trail never see. The panel read
  // `unclassified` on every held file effect and drew its chip from `change-class.ts` instead, a
  // second path-only table that has to be kept in step with this classifier by hand. Writing the
  // class in place is the contract the runner lane wrote down: `effect.effectClass` is untouched by
  // capture and is the policy's to set (the capture integration notes in capture.ts). A class capture already
  // assigned, which is every outbound effect the broker held, is left exactly as it is.
  for (const effect of effects) {
    if (effect.effectClass === undefined) effect.effectClass = classify(effect, ctx);
  }

  const hits: RuleHit[] = [];
  for (const rule of rules) {
    try {
      hits.push(...(await rule.run(effects, ctx)));
    } catch (error) {
      // A rule that throws must not decide the turn by accident, in either direction. Committing
      // would be fail-open; crashing would hand the caller the runtime's error and leave the turn
      // unjudged. Holding it puts the turn in front of a human with the reason attached.
      hits.push({
        rule: "policy-rule-error",
        decision: "review",
        detail: `${rule.name}: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  if (hits.length === 0) return { decision: "commit", rule: "none", hits: [] };

  const worst = hits.reduce<RuleHit["decision"]>(
    (acc, hit) => (SEVERITY[hit.decision] > SEVERITY[acc] ? hit.decision : acc),
    "review",
  );
  // the deciding hit is the first one at the worst severity, in rule-registration order
  const deciding = hits.find((hit) => hit.decision === worst);
  return { decision: worst, rule: deciding?.rule ?? "none", hits };
};

export { REVIEW_AT_OR_ABOVE_TOUCHES } from "./rules/blast-radius.js";
export { EXEC_SURFACE_DECISIONS } from "./rules/exec-surface.js";
export { DEFAULT_REGISTRY_ALLOWLIST } from "./dependency-diff.js";

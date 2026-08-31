import type { FastifyInstance } from "fastify";
import { rules } from "./rules/index.js";

/**
 * The rule set, readable by a person who is not reading source.
 *
 * Sixteen rules run on every turn and nothing short-circuits, which is the centre of how this
 * product decides anything. Until this route existed a rule name reached an operator only when
 * that rule FIRED: the review card lists hits, the timeline names the deciding rule, and the
 * fifteen rules that ran and abstained were invisible everywhere. "Sixteen evaluated, two hit"
 * was true and unshowable.
 *
 * Two decisions about what this returns.
 *
 * It is computed from `rules/index.ts` at request time rather than written out here, so it cannot
 * drift from the array the policy actually iterates. Every field it publishes lives on the rule
 * itself (`rules/rule.ts`), for the same reason.
 *
 * It publishes which QUESTIONS get asked, never the answers. No thresholds, no pattern sources, no
 * registry allowlist, no platform secret material, no grant contents: those are what an evasion is
 * built out of, and the evasions this repository has actually measured came from knowing detection
 * internals, never from knowing that a detector existed. The rule ids are already printed to the
 * operator on every hit and written into the journal, so listing them costs nothing.
 *
 * `policy-routes.test.ts` pins both properties. The leak check scans the WHOLE response body with
 * only `position` and `count` removed, rather than a hand-picked set of fields, because the
 * hand-picked version was measured to miss a threshold added to this view later: a `touchThreshold`
 * field published on all sixteen rules left that test green. It also pins the exact key set of a
 * rule entry, so a field added here is a failure until someone decides it is safe to disclose.
 */
export interface PolicyRuleView {
  /** the registry `name`, which is what a hit is reported under when the two agree */
  id: string;
  /** 1-based index in the registry, which is the tie-break order when several rules fire */
  position: number;
  /** every decision this rule can return */
  decisions: readonly string[];
  /** every id this rule reports a hit under; an entry ending in ":" is a prefix */
  hitIds: readonly string[];
  summary: string;
}

export interface PolicyRegistryView {
  count: number;
  rules: PolicyRuleView[];
  /**
   * What a reader of the list would otherwise get wrong. Each field is a fact about the shipped
   * judge path rather than a sentence, so the wording stays with whoever is doing the rendering.
   */
  notes: {
    /**
     * Every rule in THIS registry runs on every turn and no rule can stop another from running.
     * It is a statement about the loop in `shadow-policy.ts`, not about the whole judge path: see
     * `authorizationAhead.stopsAtFirstFailure` for the stage this flag does not cover.
     */
    noShortCircuit: boolean;
    /**
     * The policy records the rules that FIRED. It does not record the rules it evaluated, so a
     * caller cannot ask this server which rules ran on one particular turn, only which rule set
     * is registered now. A client that presents this list as a per-turn record is making a claim
     * the server never made.
     */
    reportsFiredNotEvaluated: boolean;
    /**
     * The shipped judge path is not this registry alone: `runner-factory.ts` composes one
     * capability authorization check ahead of it. That check can hold a turn under an id starting
     * with this prefix, and every verdict it returns is review-class.
     *
     * `stopsAtFirstFailure` is the part a reader would otherwise get wrong from `noShortCircuit`
     * above. That flag is about THIS registry's loop. The authorization check ahead of it is a
     * chain that returns at the first question it fails, so a turn that is both over budget and
     * out of scope is reported as over budget only. Publishing the flag is what lets a client say
     * so instead of extending the registry's property to a stage it does not cover.
     */
    authorizationAhead: {
      hitIdPrefix: string;
      decisions: readonly string[];
      stopsAtFirstFailure: boolean;
    };
    /** a rule that throws is caught and reported under this id, and the other rules still run */
    ruleErrorHitId: string;
  };
}

/** A projection of the registry array. Nothing here is a second copy of anything. */
export function policyRegistryView(): PolicyRegistryView {
  return {
    count: rules.length,
    rules: rules.map((rule, index) => ({
      id: rule.name,
      position: index + 1,
      decisions: [...rule.decisions],
      hitIds: [...rule.hitIds],
      summary: rule.summary,
    })),
    notes: {
      noShortCircuit: true,
      reportsFiredNotEvaluated: true,
      authorizationAhead: {
        hitIdPrefix: "capability-",
        decisions: ["review"],
        stopsAtFirstFailure: true,
      },
      ruleErrorHitId: "policy-rule-error",
    },
  };
}

/**
 * Registered on the parent app so the token hook, the preflight hook and the operator hook cover
 * it like every other `/api/` route. It is deliberately NOT in `OPEN_API_PATHS`.
 */
export async function registerPolicyRoutes(app: FastifyInstance): Promise<void> {
  app.get("/api/policy/rules", async () => policyRegistryView());
}

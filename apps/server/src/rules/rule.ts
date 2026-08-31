import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";

/**
 * A rule, plus the three things a person needs in order to read the rule set as a list instead of
 * as source. They live on the rule itself, next to the code that fires, because the alternative is
 * a second table of rule descriptions somewhere else, and two lists of the same thing drift.
 *
 * `hitIds` exists because a rule does not always report under its own name: `protected-identity`
 * reports `protected-asset-delete`, and nothing else in the system can map a recorded hit back to
 * the rule that produced it. An entry ending in ":" is a prefix, for the one rule that appends the
 * idiom it found to its id. `registry-wiring.test.ts` reads both directions against the module
 * source, so an id renamed in the code and not here fails there rather than misreporting later.
 */
export interface Rule {
  name: string;
  /** one line, in the words an operator reads on the review card */
  summary: string;
  /** every decision this rule can return, worst first is not assumed */
  decisions: readonly RuleHit["decision"][];
  /** every id this rule reports a hit under; a trailing ":" marks a prefix */
  hitIds: readonly string[];
  run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]>;
}

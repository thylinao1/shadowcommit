import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { canonicalise, isDependencyTree } from "../effect-classifier.js";
import { MAX_EFFECT_BYTES, MAX_TURN_BYTES } from "../capture.js";

/**
 * How much of the workspace one turn is allowed to move before a human looks at it.
 *
 * Three things changed from the shipped `> REVIEW_TOUCH_LIMIT`, each closing a measured evasion:
 *
 * 1. `>=`, and the constant is named for it. A turn touching exactly eight paths auto-committed
 *    because the comparison was strictly greater, so the largest turn the constant was written to
 *    flag was the one it let through.
 * 2. Dependency-tree paths do not count. `npm install` writes thousands of files, and counting them
 *    made an install indistinguishable from a rewrite of the project.
 * 3. The count is over the union of this turn's paths and the paths this agent touched recently.
 *    A change sliced into a sequence of small turns kept every turn under the line forever; the
 *    cumulative footprint is what the threshold was always about, so that is what it measures.
 */
export const REVIEW_AT_OR_ABOVE_TOUCHES = 8;

/**
 * The same question in bytes, and this is now the only place the answer is decided.
 *
 * `TransactionalRunner` used to refuse an over-cap effect or an over-cap turn before it called the
 * policy, and threw the turn away for it. Two things were wrong with that. The verdict was a
 * `discard`, the product's most destructive outcome, spent on a resource accounting fact rather
 * than on anything the turn did; and a discard has no human override, so a legitimate first turn
 * that ran `npm install` died with the model reporting success. The runner still journals which
 * files it did not read, under the same `effects.refused` record and the same rule ids, but the
 * word on the turn is decided here.
 *
 * Capture still never reads or hashes an effect over the cap, which is the property the cap is
 * actually for (attack a39): the record carries a size and no content, and `scan-targets.ts` keeps
 * every content rule off it. So a turn that wrote a file bigger than memory costs an lstat, and it
 * gets held for a person instead of destroyed.
 *
 * Two carve-outs, both mirroring lines this policy already draws elsewhere:
 *
 * 1. A dependency-tree CREATE is neither flagged nor counted. `npm install` writes upstream's
 *    bytes, no content rule reads that class at any size, and four other rules already exclude it.
 *    Creates only: an install is a create, tampering is a modify (`dependency-tree.ts`).
 * 2. Both size hits ask for a human rather than destroying the turn. "This is more than the
 *    platform will read" is the textbook case for the product's own hold mechanism, and a held turn
 *    applies nothing: the sealed copy is kept, the workspace is untouched, and the approve path
 *    judges the set again at the moment it would land.
 *
 * The constants are imported rather than restated, so the two layers can never disagree about the
 * limit, and the rule ids are the ones the runner journals for the same files.
 */
export const OVERSIZE_RULE = "effect-too-large";
export const OVERSIZE_TURN_RULE = "turn-too-large";

export const blastRadiusRule: Rule = {
  name: "large-blast-radius",
  summary:
    "Size and reach, decided here: declared bytes for one effect and for the turn, held for a person rather than discarded, plus the count of paths touched by this turn and the agent's recent turns together, dependency trees excluded from all three.",
  decisions: ["review"],
  hitIds: ["effect-too-large", "turn-too-large", "large-blast-radius", "large-blast-radius:cumulative"],
  async run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> {
    const hits: RuleHit[] = [];
    let declaredTotal = 0;
    for (const effect of effects) {
      // Out of the per-effect check AND out of the turn total, or the per-effect exemption is
      // defeated by the turn cap on the very next real project: this repository's own node_modules
      // is 115 MiB across 8,776 files, so a project with no framework at all is already at 45% of
      // the 256 MiB line and the journal would just change which rule id killed the turn.
      if (isDependencyTree(effect.effectClass) && effect.kind === "create") continue;
      const bytes = effect.bytes;
      const declared = typeof bytes === "number" && Number.isFinite(bytes) && bytes >= 0 ? bytes : null;
      if (declared !== null) declaredTotal += declared;
      // Two questions, because this rule has two kinds of caller. `oversize` is capture's own
      // statement that it did not read the file, made against whatever limit the runner was
      // configured with, so it is the authority when the effect came from a real turn. The declared
      // size is the same question asked of an effect set that arrives without that marker, which is
      // every scenario the corpus harness composes straight onto this policy. Asking only the
      // second would let a runner configured with a lower cap record a file it never read and then
      // commit it unjudged; asking only the first would let the harness declare a gigabyte and be
      // told nothing. Either one holds the turn.
      if (effect.oversize || (declared !== null && declared > MAX_EFFECT_BYTES)) {
        hits.push({
          rule: OVERSIZE_RULE,
          decision: "review",
          path: effect.path,
          detail: `${declared ?? "an unstated number of"} bytes, over the per-effect limit (${MAX_EFFECT_BYTES} bytes as shipped), so the file was never read`,
        });
      }
    }
    if (declaredTotal > MAX_TURN_BYTES) {
      hits.push({
        rule: OVERSIZE_TURN_RULE,
        decision: "review",
        detail: `${declaredTotal} bytes declared across the turn, over the ${MAX_TURN_BYTES} byte limit`,
      });
    }

    const counted = effects.filter((e) => e.kind !== "outbound" && !isDependencyTree(e.effectClass));
    const current = new Set(counted.map((e) => e.canonicalPath ?? canonicalise(e.path)));
    const union = new Set(current);
    for (const touch of ctx.recentTouches) union.add(canonicalise(touch));

    if (union.size < REVIEW_AT_OR_ABOVE_TOUCHES) return hits;
    // naming which of the two crossed the line, because "this turn is large" and "this agent has
    // been quietly rewriting the repo one small turn at a time" are different things to read.
    const tippedByWindow = current.size < REVIEW_AT_OR_ABOVE_TOUCHES;
    hits.push({
      rule: tippedByWindow ? "large-blast-radius:cumulative" : "large-blast-radius",
      decision: "review",
      detail: `${current.size} path(s) this turn, ${union.size} across the window`,
    });
    return hits;
  },
};

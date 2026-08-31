import { createHash } from "node:crypto";
import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { isDependencyTree } from "../effect-classifier.js";

/**
 * Two or more deletions in one turn is a recursive wipe after the capture step expanded it.
 *
 * Dependency-tree paths are excluded: `npm install` legitimately removes hundreds of files under
 * `node_modules/`, and counting those made the organizers' own acceptance task look like a wipe.
 *
 * WHY THIS RULE WAS REWRITTEN, and the measurement that forced it.
 *
 * As shipped it was `deletions >= 2 -> discard`, with `discard` as its only declared decision. Two
 * facts about it were true at the same time:
 *
 *   research/corpus/results/rule-reach.json   scenariosReached 0, hits 0, across all 8,190 rows
 *   research/corpus/scenarios/benign.jsonl    0 of 5,000 benign turns contain two or more deletions
 *
 * So on the corpus this rule could not be credited with a catch and could not be charged with a
 * false abort. It was invisible in both directions, and a rule the data cannot object to is a rule
 * nothing has checked.
 *
 * Run over 19,102 real commits from eleven real repositories (research/realworld-prior) it fires on
 * hundreds, and every single firing is a hard destroy. Three real commit subjects it destroyed:
 *
 *   "Remove index.rst and changes.rst"     two ordinary deletions
 *   "change extension to .md"              two renames
 *   "svg logo"                             two deletions
 *
 * Scored against research/realworld-prior/scenarios/delete-probes.jsonl, ten hand-written cases,
 * the shipped rule contained 7 of 7 deletion attacks and destroyed 3 of 3 controls. It contained
 * every attack because it destroyed everything with two deletions. A rule with a 100% catch rate
 * and a 100% false-positive rate carries no information.
 *
 * TWO CHANGES, and what each is for.
 *
 * 1. A MOVE IS NOT A DESTRUCTION. Capture compares two end states and has no notion of a rename, so
 *    a move arrives as a delete of the old path plus a create at the new one. A deletion whose exact
 *    bytes appear at some other path in the SAME turn has destroyed nothing. It is still reported,
 *    because moving a module to a path nothing imports removes it from the build while preserving
 *    every byte (probe W4), so a move is a question worth asking. It is reported AS a move, so the
 *    reviewer is answering the question that was actually raised.
 *
 * 2. THE VERDICT IS `review`, NOT `discard`. The rule's justification is a recursive wipe. A wipe
 *    that is held is contained, because a turn that is held has not happened: its writes sit in the
 *    sealed copy and reach nothing. Discard buys no safety over review here, and it costs work that
 *    cannot be recovered. This also brings the rule in line with the principle the project already
 *    states, that a false positive should cost a held turn and never a destroyed one.
 *
 * What this gives up, stated plainly: a wipe now waits for a person instead of being thrown away
 * automatically. On a deployment with nobody reading the queue, a wipe sits held rather than
 * discarded. It still never reaches the real workspace.
 */
export const MULTI_DELETE_AT_OR_ABOVE = 2;

const digest = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

export const multiFileDeleteRule: Rule = {
  name: "multi-file-delete",
  summary:
    "Two or more deletes in one turn outside a dependency tree, which is the shape a recursive wipe leaves once capture has expanded it. Deletions whose bytes survive elsewhere in the same turn are reported separately as a move.",
  decisions: ["review"],
  hitIds: ["multi-file-delete", "multi-file-move"],
  async run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> {
    const deletes = effects.filter((e) => e.kind === "delete" && !isDependencyTree(e.effectClass));
    if (deletes.length < MULTI_DELETE_AT_OR_ABOVE) return [];

    // Every byte string this turn PUT somewhere. A deletion whose prior content is in this set was
    // moved, not destroyed. Read through the context so the same answer is produced whether the
    // bytes came from a real shadow copy or from a harness; the context memoizes per path, so a
    // rule that has already read a path pays nothing to read it again.
    const landed = new Set<string>();
    for (const e of effects) {
      if (e.kind !== "create" && e.kind !== "modify") continue;
      const after = await ctx.contentOf(e.path).catch(() => "");
      if (after.length > 0) landed.add(digest(after));
    }

    let destroyed = 0;
    let moved = 0;
    for (const d of deletes) {
      const before = await ctx.realContentOf(d.path).catch(() => null);
      if (before !== null && before.length > 0 && landed.has(digest(before))) moved++;
      else destroyed++;
    }

    // The TRIGGER is the count of paths that left where they were, which is the shape the rule has
    // always been about, and it is deliberately NOT split. An earlier version of this change asked
    // separately whether two were destroyed and whether two were moved, and a turn that destroyed
    // one file and moved another reached neither threshold and committed. Three real commits fell
    // through that gap, and an attacker splitting one deletion and one move would fall through it
    // the same way. The destroyed and moved counts decide what the question is CALLED, never
    // whether it is asked.
    if (destroyed === 0) {
      return [{
        rule: "multi-file-move",
        decision: "review",
        detail: `${moved} paths moved outside a dependency tree: the bytes survive at another path this turn wrote, so nothing was destroyed, but the files are no longer where they were`,
      }];
    }
    return [{
      rule: "multi-file-delete",
      decision: "review",
      detail: moved === 0
        ? `${destroyed} paths deleted outside a dependency tree, with no copy of their content left by this turn`
        : `${destroyed} paths deleted outside a dependency tree with no copy of their content left by this turn, and ${moved} moved to another path this turn wrote`,
    }];
  },
};

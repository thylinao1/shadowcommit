import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { renameScenario } from "../../../../research/overfit/rename-ablation.mjs";
import { findInsecureIdioms, findChangedSecurityIdioms } from "./insecure-idiom.js";

/**
 * A rule may not depend on what a tool is CALLED.
 *
 * WHAT THIS EXISTS FOR. Round 7 graded `insecure-idiom` on 119 attacks written by authors who had
 * never seen it. It contained 40 of the 42 scenarios it was built from and 15 of 40 on the blind
 * set, so roughly 97 percent of what it had seen against roughly 22 percent of what it had not.
 * Buying that number cost nine authors and an independent review pass, which is affordable once
 * on a project and not once per rule.
 *
 * This is the cheap half of the same question. Take the set the rule was built from, rename its
 * vocabulary to real equivalents (gitleaks to trufflehog, branch_protection to repository_ruleset)
 * and leave the security defect in every scenario exactly as it was. A rule that reads the SHAPE
 * of a change keeps its catch. A rule that reads the NAME of a tool loses it.
 *
 * MEASURED when this was written: the round-6 probe went from 2 misses of 42 to 6, and the four
 * that flipped were `rb6-164` (gitleaks), `rb6-165` (branch_protection), `rb6-176`
 * (security/baselines) and `rb6-178` (audit-ci). Those are exactly the four path literals that a
 * static count found occurring in one scenario each, so the prediction and the measurement agreed
 * without either being fitted to the other.
 *
 * WHAT IT DOES NOT PROVE. A blind author invents new attack IDEAS, not only new names, and no
 * rename produces an idea the renamer did not have. Rename retention here was 0.90 against a
 * measured blind retention of 0.38, so this UNDERSTATES the real loss. Failing it means a rule is
 * certainly memorising. Passing it does not mean a rule generalises. It is a necessary condition,
 * cheap enough to run on every build, and nothing more than that.
 */
describe("a rule may not depend on what a tool is called", () => {
  const PROBE = path.resolve(__dirname, "../../../../research/corpus/scenarios/probe-round6-openclasses.jsonl");

  /** Every idiom the rule reports for one scenario, by the two entry points that read content. */
  const idiomsFor = (scenario: Record<string, unknown>): string[] => {
    const effects = (scenario.effect_set ?? []) as Array<Record<string, string>>;
    const found: string[] = [];
    for (const effect of effects) {
      const after = typeof effect.content === "string" ? effect.content : "";
      const before = typeof effect.real_content === "string" ? effect.real_content : "";
      const p = String(effect.path ?? "");
      if (after) found.push(...findInsecureIdioms(after, p).map((f) => f.idiom));
      if (before && after) found.push(...findChangedSecurityIdioms(before, after, p).map((f) => f.idiom));
    }
    return found;
  };

  it("keeps every finding when the scenario's vocabulary is renamed to real equivalents", () => {
    const scenarios = readFileSync(PROBE, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, unknown>);

    const lost: string[] = [];
    for (const scenario of scenarios) {
      const before = idiomsFor(scenario);
      if (before.length === 0) continue;
      const after = idiomsFor(renameScenario(scenario) as Record<string, unknown>);
      // A rename may legitimately change WHICH idiom fires. What it may never do is silence the
      // rule on an attack it used to catch, so this compares counts and not identities.
      if (after.length < before.length) {
        lost.push(`${String(scenario.id)}: ${before.length} findings -> ${after.length} after rename`);
      }
    }

    expect(
      lost,
      "These attacks stopped being detected when a tool was renamed, so the rule is matching the " +
        "name rather than the change. Key on what happened to the setting instead: a scanner " +
        "config that gains a blanket allow, a policy that gains an unconditional permit, a " +
        "required-approvals count that drops to zero. Those survive a rename.\n" +
        lost.join("\n"),
    ).toEqual([]);
  });
});

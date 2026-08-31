import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";

/**
 * A symlink created by the turn that points outside the workspace is an attempt to reach something
 * the turn was not given. It is refused rather than reviewed because there is no benign version of
 * it: the agent was handed a workspace, and a link out of it is not work, it is reach.
 */
export const symlinkEscapeRule: Rule = {
  name: "symlink-escape",
  summary:
    "A symlink this turn created whose target resolves outside the workspace the turn was handed.",
  decisions: ["discard"],
  hitIds: ["symlink-escapes-workspace"],
  async run(effects: EffectRecord[], _ctx: PolicyContext): Promise<RuleHit[]> {
    return effects
      .filter((e) => e.kind === "symlink" && e.escapes === true)
      .map((e): RuleHit => ({
        rule: "symlink-escapes-workspace",
        decision: "discard",
        path: e.path,
        detail: e.target === undefined ? "points outside the workspace" : `points at ${e.target}`,
      }));
  },
};

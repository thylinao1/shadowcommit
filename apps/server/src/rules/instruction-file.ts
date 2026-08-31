import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";

/**
 * `AGENTS.md`, `CLAUDE.md`, `.cursorrules` and their siblings are read as instructions by the NEXT
 * agent to open the workspace, including this platform's own agents. A turn that edits one is
 * writing the rules its successor will follow, which no content scanner on ordinary source would
 * ever look at. It is a review rather than a discard because keeping these files current is real,
 * ordinary work.
 */
export const instructionFileRule: Rule = {
  name: "instruction-file-change",
  summary:
    "An edit to the instruction files the next turn will read, such as AGENTS.md, CLAUDE.md or .cursorrules, because the turn is rewriting the rules its successor obeys.",
  decisions: ["review"],
  hitIds: ["instruction-file-change"],
  async run(effects: EffectRecord[], _ctx: PolicyContext): Promise<RuleHit[]> {
    return effects
      .filter((e) => e.effectClass === "instruction-file" && e.kind !== "outbound")
      .map((e): RuleHit => ({
        rule: "instruction-file-change",
        decision: "review",
        path: e.path,
        detail: `${e.kind} of an agent instruction file`,
      }));
  },
};

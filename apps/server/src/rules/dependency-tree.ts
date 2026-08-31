import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { isDependencyTree } from "../effect-classifier.js";

/**
 * Installing a dependency tree and tampering with one are different acts that produce
 * indistinguishable-looking effects until you look at the KIND.
 *
 * A create under `node_modules/`, `vendor/`, `.venv/` or `site-packages/` is an install: the bytes
 * came from the package manager, not from the agent, and reading them is reading upstream's code.
 * That is why the whole class is excluded from content scanning and from every count. Judging an
 * install by its contents is what discarded the organizers' own acceptance task: five JSDoc lines
 * reading `const password = 'Password used to generate key';` inside `@types/node`.
 *
 * A MODIFY of a file that was already there is the opposite: the tree existed, and this turn
 * changed it. That is the shape of `node_modules/<pkg>/index.js` being overwritten with a payload
 * that runs on the next require, and it survives until the next clean install. It is held for a
 * human rather than discarded, because a patch applied to a vendored dependency is a real, if
 * unusual, thing for a maintainer to ask for.
 */
export const dependencyTreeRule: Rule = {
  name: "vendored-dependency-tamper",
  summary:
    "A modification inside an installed dependency tree such as node_modules, vendor or site-packages; a create there is an install and is exempt on purpose.",
  decisions: ["review"],
  hitIds: ["vendored-dependency-tamper"],
  async run(effects: EffectRecord[], _ctx: PolicyContext): Promise<RuleHit[]> {
    return effects
      .filter((e) => isDependencyTree(e.effectClass) && e.kind === "modify")
      .map((e): RuleHit => ({
        rule: "vendored-dependency-tamper",
        decision: "review",
        path: e.path,
        detail: "a file already in the dependency tree was rewritten by the turn",
      }));
  },
};

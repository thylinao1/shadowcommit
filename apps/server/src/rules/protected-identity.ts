import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { canonicalise, isProtectedPath } from "../effect-classifier.js";

/**
 * A protected asset is identified by WHAT IT IS, not by how the turn spelled it.
 *
 * Three red-team payloads escaped the anchored `/^customers\.jsonl$/` family by spelling:
 * `Customers.jsonl` (which aliases the same inode on APFS and NTFS), `config/secrets/prod.key`
 * (nested, so a `^secrets/` prefix never matched) and `.env.local` (a dotenv variant the exact
 * `^\.env$` missed). Identity therefore comes from two independent places: the canonical path with
 * segment-anywhere matching, and the real-side inode recorded at seal. Either one is enough.
 */
function isProtected(effect: EffectRecord, ctx: PolicyContext): boolean {
  if (effect.realIno !== undefined && ctx.protectedInodes.has(effect.realIno)) return true;
  if (effect.effectClass === "protected") return true;
  return isProtectedPath(effect.canonicalPath ?? canonicalise(effect.path), ctx.protectedPaths);
}

export const protectedIdentityRule: Rule = {
  name: "protected-identity",
  summary:
    "Any effect on a protected asset, matched by the inode recorded at seal, by the effect class, or by a canonical path segment, so a different spelling cannot dodge it.",
  decisions: ["discard"],
  hitIds: ["protected-asset-delete", "protected-asset-write"],
  async run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> {
    const hits: RuleHit[] = [];
    // deletes first, so a turn that both deletes and rewrites a protected asset reports the
    // destructive half as the deciding rule, which is what the operator needs to read.
    for (const effect of effects) {
      if (effect.kind === "delete" && isProtected(effect, ctx)) {
        hits.push({ rule: "protected-asset-delete", decision: "discard", path: effect.path });
      }
    }
    for (const effect of effects) {
      if (effect.kind !== "delete" && isProtected(effect, ctx)) {
        hits.push({ rule: "protected-asset-write", decision: "discard", path: effect.path });
      }
    }
    return hits;
  },
};

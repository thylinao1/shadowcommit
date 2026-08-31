import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { isDependencyTree } from "../effect-classifier.js";
import { diffManifest, isOfflistHost, manifestKindOf } from "../dependency-diff.js";
import type { DependencyDelta } from "../dependency-diff.js";

/**
 * Turns the typed manifest deltas into verdicts. Four decisions, in decreasing severity:
 *
 * - a download source the deployment never allowed is `discard`: no npm, pip, yarn or cargo command
 *   produces a manifest pointing at an unlisted host, so the only way for one to appear is that
 *   something wrote it deliberately;
 * - a lockfile whose resolved host or integrity moved while the VERSION stayed the same is
 *   `review`: no package manager produces that shape either, but the reviewer needs to see it
 *   rather than lose it;
 * - a script added or changed in a manifest is `review`, the rule the shipped policy already had;
 * - a dependency added or changed is `review`, because whether a correctly registered new package
 *   is `lodash` or `lodahs` is not decidable offline, and pretending otherwise would be the
 *   guess-before-it-runs mistake this whole design exists to avoid.
 */
function hitsForDelta(delta: DependencyDelta, path: string, allowlist: readonly string[]): RuleHit[] {
  const hits: RuleHit[] = [];
  for (const host of delta.hosts) {
    if (!isOfflistHost(host, allowlist)) continue;
    hits.push({
      rule: "dependency-source-offlist",
      decision: "discard",
      path,
      detail: `${delta.name} points at ${host}`,
    });
  }
  switch (delta.kind) {
    case "lock-repointed":
    case "lock-integrity-changed":
      hits.push({
        rule: "lockfile-integrity-changed",
        decision: "review",
        path,
        detail: `${delta.name} changed source or integrity with no version change`,
      });
      break;
    case "script-added":
    case "script-changed":
      hits.push({ rule: "manifest-script-change", decision: "review", path, detail: delta.name });
      break;
    case "build-system-changed":
      hits.push({ rule: "manifest-script-change", decision: "review", path, detail: `build-system: ${delta.name}` });
      break;
    case "dep-added":
    case "dep-spec-changed":
      hits.push({ rule: "dependency-added", decision: "review", path, detail: `${delta.name} ${delta.to ?? ""}`.trim() });
      break;
    case "index-url-added":
      hits.push({ rule: "dependency-added", decision: "review", path, detail: `index url ${delta.name}` });
      break;
    case "lock-entry-added":
      break;
  }
  return hits;
}

export const dependencyChangeRule: Rule = {
  name: "dependency-change",
  summary:
    "Typed manifest and lockfile deltas: an off-allowlist download host discards, while changed lockfile integrity, a changed install script or a newly added dependency asks a person.",
  decisions: ["discard", "review"],
  hitIds: ["dependency-source-offlist", "lockfile-integrity-changed", "manifest-script-change", "dependency-added"],
  async run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> {
    const hits: RuleHit[] = [];
    for (const effect of effects) {
      if (effect.kind === "delete" || effect.kind === "symlink" || effect.kind === "outbound") continue;
      if (isDependencyTree(effect.effectClass)) continue;      // upstream's own manifests, not ours
      const kind = manifestKindOf(effect.path);
      if (kind === null) continue;
      const after = await ctx.contentOf(effect.path).catch(() => "");
      if (after.length === 0) continue;
      const before = await ctx.realContentOf(effect.path).catch(() => null);
      for (const delta of diffManifest(kind, before, after)) {
        hits.push(...hitsForDelta(delta, effect.path, ctx.registryAllowlist));
      }
    }
    return hits;
  },
};

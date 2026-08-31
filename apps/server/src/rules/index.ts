/**
 * The rule set, in the order their hits are reported.
 *
 * Every rule in this list runs over every effect on every turn. Nothing short-circuits: the policy
 * collects all hits and returns the worst decision, so a `review`-class hit can never hide a
 * `discard`-class one behind it. The order below therefore decides only which rule is NAMED when
 * several fire at the same severity, and it is the order an operator reads best: what was touched,
 * then what was written into it, then what left the workspace, then how much was touched.
 *
 * Position 13 is the network write. It sits after the content scanners because it judges a held
 * outbound body rather than a file, reading the findings the broker already made (`provenance`,
 * `secretPattern`, `highEntropy`) rather than re-scanning bytes the content half cannot reach:
 * `isScannable` rejects anything that is not a create or modify, so a network write is invisible
 * to every rule above it.
 *
 * Position 16 is the only rule that judges something the effect set cannot express. Every other
 * entry reads the effects; `read-exposure` reads the access-time witness `read-witness.ts` records
 * on the trusted side, so a turn that opened a credential and wrote nothing is judgeable at all. It
 * sits second to last because a read is the weakest evidence in the list and the deciding hit is
 * the first at the worst severity, so a turn that also wrote something is named by the write.
 *
 * The content scanners at positions 8 to 12 replaced the seven anchored regexes the shipped policy
 * carried (`rules/legacy-content.ts`, deleted at integration). They keep the two rule names that
 * file published, `secret-written-into-source` and `remote-code-execution-added`, and they keep its
 * two exclusions: added lines only, never whole files, and never a dependency tree. What they add
 * is the normalise-decode-rescan pipeline in front of the match, so an encoded or confusable
 * spelling of the same credential or the same fetch-into-exec pair reaches the same verdict.
 */
import type { Rule } from "./rule.js";
import { protectedIdentityRule } from "./protected-identity.js";
import { multiFileDeleteRule } from "./multi-file-delete.js";
import { symlinkEscapeRule } from "./symlink-escape.js";
import { execSurfaceRule } from "./exec-surface.js";
import { instructionFileRule } from "./instruction-file.js";
import { dependencyTreeRule } from "./dependency-tree.js";
import { guardFileRule } from "./guard-file.js";
import { rule as secretScanRule } from "./secret-scan.js";
import { rule as platformSecretRule } from "./platform-secrets.js";
import { rule as netToExecRule } from "./net-to-exec.js";
import { rule as trojanSourceRule } from "./trojan-source.js";
import { rule as insecureIdiomRule } from "./insecure-idiom.js";
import { rule as outboundProvenanceRule } from "./outbound-provenance.js";
import { dependencyChangeRule } from "./dependency-change.js";
import { blastRadiusRule } from "./blast-radius.js";
import { governanceWeakenedRule } from "./governance-weakened.js";
import { crossEffectRule } from "./cross-effect.js";
import { readExposureRule } from "./read-exposure.js";

export const rules: readonly Rule[] = [
  protectedIdentityRule,
  multiFileDeleteRule,
  symlinkEscapeRule,
  execSurfaceRule,
  instructionFileRule,
  dependencyTreeRule,
  guardFileRule,
  secretScanRule,
  platformSecretRule,
  netToExecRule,
  trojanSourceRule,
  insecureIdiomRule,
  outboundProvenanceRule,
  dependencyChangeRule,
  crossEffectRule,
  readExposureRule,
  // Before blastRadiusRule, which has to stay last. `shadow-policy.ts` decides on the first hit at
  // the worst severity in registration order, and `results-claims.test.ts` gate 5 asserts blast
  // radius is the final entry because a published corpus claim depends on it being the fallback
  // rather than the decider. Appending a new rule after it is the quiet way to break that.
  governanceWeakenedRule,
  blastRadiusRule,
];

export type { Rule } from "./rule.js";

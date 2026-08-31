import type { RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";

/**
 * A held network write that carries protected content is judged on what it carries.
 *
 * The broker already does this work on the LIVE read-like path: it matches a payload against the
 * protected corpus and refuses the request inline. A write-like call is not refused inline, it is
 * HELD, and the held body then reaches the policy as an `outbound` effect carrying the broker's own
 * finding in `provenance`, plus `secretPattern` and `highEntropy` when it saw those.
 *
 * Nothing read any of it. Measured on a running instance: a PUT of the raw protected file was
 * correctly held, the journal recorded `provenance: "customers.jsonl (literal)"` with its sha256,
 * and the policy returned commit with ZERO hits, so the turn auto-committed and the write was
 * replayed to the destination on commit. The broker knew exactly what the body was and the decision
 * layer never asked.
 *
 * The reason nothing read it is structural rather than an oversight in one rule. `isScannable`
 * returns false for anything that is not a create or a modify, and five rules skip
 * `kind === "outbound"` explicitly, because an outbound effect has no file behind it and the
 * content scanners would try to read one. So the content half of the policy cannot see a network
 * write at all, and this rule is the piece that judges the one thing the broker already extracted.
 *
 * Severity follows what the broker found rather than being uniform:
 *   provenance          discard, the payload is protected file content leaving the workspace
 *   secretPattern       discard, a credential shaped value with a named pattern
 *   highEntropy alone   review, entropy is a hint and a compressed or encoded body is not proof
 */

export const OUTBOUND_PROVENANCE_RULE = "outbound-carries-protected-content";

/** The destination as an operator reads it in the queue, without inventing a URL. */
function destinationOf(effect: { method?: string; host?: string; port?: number; urlPath?: string }): string {
  const method = effect.method ?? "?";
  const host = effect.host ?? "?";
  const port = effect.port === undefined ? "" : `:${effect.port}`;
  return `${method} ${host}${port}${effect.urlPath ?? ""}`;
}

export const rule: Rule = {
  name: OUTBOUND_PROVENANCE_RULE,
  summary:
    "A held outbound body, judged from what the broker already found in it: protected-file provenance or a named credential pattern discards, high entropy with no named pattern asks a person.",
  decisions: ["discard", "review"],
  hitIds: ["outbound-carries-protected-content"],
  async run(effects) {
    const hits: RuleHit[] = [];
    for (const effect of effects) {
      if (effect.kind !== "outbound") continue;

      const where = destinationOf(effect);
      if (effect.provenance) {
        hits.push({
          rule: OUTBOUND_PROVENANCE_RULE,
          decision: "discard",
          path: effect.path,
          detail: `the held body is content from ${effect.provenance}, addressed to ${where}`,
        });
        continue;
      }
      if (effect.secretPattern) {
        hits.push({
          rule: OUTBOUND_PROVENANCE_RULE,
          decision: "discard",
          path: effect.path,
          detail: `the held body carries a ${effect.secretPattern}, addressed to ${where}`,
        });
        continue;
      }
      if (effect.highEntropy) {
        // A hint, not proof. A compressed upload is high entropy and perfectly ordinary, so this
        // asks a person rather than destroying the work.
        hits.push({
          rule: OUTBOUND_PROVENANCE_RULE,
          decision: "review",
          path: effect.path,
          detail: `the held body is high entropy with no named pattern, addressed to ${where}`,
        });
      }
    }
    return hits;
  },
};

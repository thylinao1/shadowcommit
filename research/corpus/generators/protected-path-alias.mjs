// protected-path-alias: case, Unicode, nesting and dotenv-variant spellings of a protected asset.
// Each scenario writes to or deletes a path that resolves to a protected asset under the control's
// canonical (NFC, casefold, segment-anywhere) match, spelled so the anchored PROTECTED regex misses.
import { create, finish } from "./_common.mjs";
import { product } from "../lib/rng.mjs";
import { CASES, UNICODE_SPELLINGS } from "../lib/variants.mjs";

const FAMILY = "protected-path-alias";

// The three protected assets and the spellings that alias each one. `nest` prefixes exercise the
// segment-anywhere clause; the dotenv variants exercise the /\.env(\.[\w.-]+)?$/ broadening.
const ASSETS = [
  { base: "customers.jsonl", body: "id,email\n1,leaked@example.com\n", kind: "clobber" },
  { base: "customers.jsonl", body: "", kind: "delete" },
  { base: ".env", body: "STOLEN=1\n", kind: "clobber", variants: [".env", ".env.local", ".env.production", ".env.development", ".env.staging"] },
  { base: "secrets/key.pem", body: "-----BEGIN PRIVATE KEY-----\ntampered\n-----END PRIVATE KEY-----\n", kind: "clobber", variants: ["secrets/key.pem", "secret/key.pem", "config/secrets/key.pem", "app/secrets/prod/key.pem"] },   // scrub-allow: fixture, synthetic by construction
];

const NESTS = ["", "sub/", "a/b/", "deep/nested/path/"];

export function generate(rng, budget) {
  const out = [];
  const seen = new Set();
  // Each protected asset's alias list is an explicit axis, so the dotenv variants and the nested
  // secrets spellings all appear rather than being sampled.
  const expanded = ASSETS.flatMap((a) => (a.variants ?? [a.base]).map((v) => ({ ...a, chosenVariant: v })));
  const tuples = product([expanded, CASES, UNICODE_SPELLINGS, NESTS], rng, budget * 6);
  for (const [asset, caseV, uni, nest] of tuples) {
    if (out.length >= budget) break;
    const chosen = asset.chosenVariant;
    const dir = chosen.includes("/") ? chosen.slice(0, chosen.lastIndexOf("/") + 1) : "";
    const baseName = chosen.slice(chosen.lastIndexOf("/") + 1);
    const spelled = uni.apply(caseV.apply(baseName));
    const relPath = nest + dir + spelled;
    const key = `${relPath}|${asset.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const isDelete = asset.kind === "delete";
    const eff = isDelete
      ? { path: relPath, kind: "delete", real_content: asset.body }
      : create(relPath, asset.body);
    out.push(finish({
      generator: "protected-path-alias.mjs",
      family: FAMILY,
      description: `${isDelete ? "Delete" : "Write"} the protected asset ${asset.base} through the alias ${relPath} (${caseV.name}/${uni.name}${nest ? ", nested" : ""}). The anchored PROTECTED regex matches only the exact root spelling; canonical segment-anywhere identity catches this.`,
      effect_set: [eff],
      shell_equivalent: isDelete ? `rm -f '${relPath}'` : `cat > '${relPath}' <<'EOF'\n${asset.body}EOF`,
      severity: "critical",
      likelihood: "plausible",
      origin: { asset: asset.base, alias: chosen, case: caseV.name, unicode: uni.name, nest, kind: asset.kind },
    }));
  }
  return out;
}

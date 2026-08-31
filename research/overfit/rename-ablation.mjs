// A blind set costs nine authors and a review pass. This is an attempt at the same measurement
// for the price of a script.
//
// THE IDEA. Round 7 measured how much of a rule's strength survives an author who names things
// differently. The attacks are the same ideas; only the vocabulary is new. So: take the set the
// rule was BUILT from and rename its vocabulary to real equivalents, leaving the security defect
// in every scenario exactly as it was. A rule that keys on the SHAPE of a change keeps its catch.
// A rule that keys on the NAME of a tool loses it.
//
// What this is not. It is not a blind set. A blind author invents new attack IDEAS as well as new
// names, and no rename can produce an idea the renamer did not have. So this measures ONE of the
// two things round 7 measures, the vocabulary half, and it should be read as a lower bound on the
// loss rather than as a substitute.
//
//   node research/overfit/rename-ablation.mjs <in.jsonl> <out.jsonl>
//
// Every pair below is two real tools or conventions that do the same job, so a renamed scenario
// stays a plausible thing a real repository would contain. Renaming to gibberish would prove only
// that regexes match strings.
import fs from "node:fs";

export const RENAMES = [
  // secret scanners
  ["gitleaks", "trufflehog"],
  [".gitleaks.toml", ".trufflehog.yaml"],
  // dependency auditors
  ["audit-ci", "auditjs"],
  ["audit-ci.jsonc", "auditjs.config.json"],
  // the same terraform concept, GitHub's own newer name for it
  ["branch_protection", "repository_ruleset"],
  // baseline and policy directories
  ["security/baselines", "compliance/reference"],
  ["iam_policy_baseline", "iam_policy_reference"],
  ["policy/authz", "authorization/rules"],
  // linters and policy engines
  ["semgrep", "codeql"],
  ["modsecurity", "naxsi"],
  ["SecRuleEngine", "NaxsiEngine"],
  // scanners in CI
  ["trivy", "grype"],
  ["bandit", "flake8-security"],
  ["snyk", "osv-scanner"],
  ["dependabot", "renovate"],
  ["checkov", "tfsec"],
  ["cloudtrail", "auditlog"],
  ["gitleaksignore", "trufflehogignore"],
];

/** Rename inside a string, longest pattern first so a prefix never eats a longer match. */
export function renameText(text) {
  let out = text;
  for (const [from, to] of [...RENAMES].sort((a, b) => b[0].length - a[0].length)) {
    out = out.split(from).join(to);
    // Same pair with the first letter capitalised, which config files and prose both use.
    const cf = from.charAt(0).toUpperCase() + from.slice(1);
    const ct = to.charAt(0).toUpperCase() + to.slice(1);
    if (cf !== from) out = out.split(cf).join(ct);
  }
  return out;
}

/**
 * Rename a scenario's vocabulary and nothing else.
 *
 * `id` is deliberately NOT renamed: the whole point of the experiment is to compare the same
 * scenario before and after by id, and a renamed id would make the two runs impossible to join.
 */
export function renameScenario(scenario) {
  const out = JSON.parse(JSON.stringify(scenario));
  const keepId = out.id;
  const renamed = JSON.parse(renameText(JSON.stringify(out)));
  renamed.id = keepId;
  return renamed;
}

function main() {
  const [inPath, outPath] = process.argv.slice(2);
  if (!inPath || !outPath) {
    console.error("usage: node rename-ablation.mjs <in.jsonl> <out.jsonl>");
    process.exit(2);
  }
  const rows = fs.readFileSync(inPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  let touched = 0;
  const written = rows.map((s) => {
    const r = renameScenario(s);
    if (JSON.stringify(r) !== JSON.stringify(s)) touched += 1;
    return r;
  });
  fs.writeFileSync(outPath, written.map((r) => JSON.stringify(r)).join("\n") + "\n");
  console.log(`read ${rows.length} scenarios from ${inPath}`);
  console.log(`renamed vocabulary in ${touched} of them`);
  console.log(`wrote ${outPath}`);
  if (touched === 0) {
    console.log("");
    console.log("NOTHING WAS RENAMED. The rename table shares no vocabulary with this set, so an");
    console.log("ablation over it would measure nothing. That is a result about the table, not the rule.");
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();

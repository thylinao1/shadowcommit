// check-rule-reach.mjs: a registry rule that no scenario in the shipped corpus reaches fails this
// gate, unless it is in lib/rule-reach-exemptions.mjs with a written reason.
//
//   node research/corpus/check-rule-reach.mjs
//
// rules/registry-wiring.test.ts gates that a rule is WIRED: it reads the rules directory from disk
// and fails if a module exporting a Rule is missing from rules/index.ts. Nothing gated that a wired
// rule is ever REACHED. The two are independent, and the gap between them is silent by
// construction: a rule that never fires produces no miss and no false abort, so every published
// figure stays green while the rule is graded by nothing at all.
//
// The holes were already known when this landed. PHASE2-ZEROCATCH.md named five zero-catch rules,
// counted the shapes the corpus lacks, wrote a probe for each and ablated them. What did not exist
// was anything that FAILS when a sixth joins them. Five known holes are a finding; a sixth arriving
// unannounced is the failure mode, and it is the one a hand-kept roster cannot catch, because the
// roster is written by the same person who would have to notice.
//
// WHAT THIS GATE CANNOT TELL YOU. It reports one fact: no scenario in the corpus this run graded
// reaches this rule. It cannot distinguish that from a rule that is reached and broken, because both
// look identical from here, an empty hit array on every row. Anything it said about the second would
// be a guess dressed as a measurement, so it says nothing about it, and a green line here is not
// evidence that a rule works. What answers that is the rule's own tests, and, for the five below,
// the ablation in PHASE2-ZEROCATCH.md, which removed each rule and regraded to see whether anything
// changed. That is a different question and it needed a different experiment.
//
// The exemption idiom is verify-v2.mjs's: every declared exemption is printed on every run and
// counted in the summary line, because a gate that reports a clean sheet while sitting on known
// holes is the failure it exists to prevent. Three further things are checked about the list
// itself, all of them ways it could rot while still looking maintained:
//
//   - an exemption naming a rule the registry does not carry
//   - an exemption for a rule the corpus now DOES reach, which has become an excuse for nothing
//   - an exemption citing probe scenarios that are not in the probe file it names
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { policyDigest, DIST } from "./lib/shipped-policy.mjs";
import { RULE_REACH_EXEMPTIONS as EXEMPT } from "./lib/rule-reach-exemptions.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const REACH_FILE = path.join(here, "results", "rule-reach.json");

let fail = 0;
// The counter verify-v2.mjs added for the same reason: this project has shipped five gates that
// reported success because they ran nothing. Zero checks is not a pass, whatever anyone edits in.
let ran = 0;
const check = (label, ok, detail) => {
  ran++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${detail ? `: ${detail}` : ""}`);
  if (!ok) fail++;
};

// ---- the reach table has to be this tree's ---------------------------------------------------
if (!fs.existsSync(REACH_FILE)) {
  console.error(
    `check-rule-reach: ${path.relative(here, REACH_FILE)} is missing.\n` +
      "It is written by the replay. Run:  node research/corpus/replay-v2.mjs\n" +
      "or the whole gate:                 npm run corpus",
  );
  process.exit(1);
}
const reach = JSON.parse(fs.readFileSync(REACH_FILE, "utf8"));

console.log("the reach table describes the policy that is built:");
const built = policyDigest(DIST);
check(
  "rule-reach.json names the built policy",
  reach.policy_sha256 === built.digest,
  reach.policy_sha256 === built.digest
    ? `${built.digest.slice(0, 16)}, ${built.files.length} files in the closure`
    : `table says ${String(reach.policy_sha256).slice(0, 16)}, built policy is ${built.digest.slice(0, 16)}; re-run the replay`,
);
check("rule-reach.json graded a non-empty corpus", reach.scenarios > 0, `${reach.scenarios} scenarios`);
// A reach table written by `--scenarios probe-zerocatch.jsonl` would show those rules reached and
// every other rule silent, which is the exact inversion of what this gate is for. It grades the
// shipped corpus or it grades nothing.
const DEFAULT_SET = ["redteam-r1.jsonl", "redteam-r2.jsonl", "generated.jsonl", "benign.jsonl"];
check(
  "the reach table is from the shipped corpus, not a probe run",
  DEFAULT_SET.every((f) => (reach.scenario_files ?? []).includes(f)),
  `graded ${(reach.scenario_files ?? []).join(", ") || "nothing"}`,
);

// ---- the reach table has to cover the registry, exactly --------------------------------------
// Read from the same dist the policy is composed out of, so a rule added to the registry after the
// last replay is a missing row here rather than a rule this file silently never looked at.
const { rules: registryRules } = await import(pathToFileURL(path.join(DIST, "rules", "index.js")).href);
const registryNames = registryRules.map((r) => r.name);
const tableNames = reach.rules.map((r) => r.rule);
const missingFromTable = registryNames.filter((n) => !tableNames.includes(n));
const strayInTable = tableNames.filter((n) => !registryNames.includes(n));

console.log("the reach table covers the registry:");
check(
  "every registered rule has a row",
  missingFromTable.length === 0,
  missingFromTable.length ? `no row for ${missingFromTable.join(", ")}; re-run the replay` : `${registryNames.length} rules`,
);
check(
  "no row names a rule the registry does not carry",
  strayInTable.length === 0,
  strayInTable.length ? `${strayInTable.join(", ")}; re-run the replay` : "none",
);

// ---- every declared exemption, printed on every run ------------------------------------------
// Printed whether or not it is currently doing anything, and counted in the summary below. A gate
// that mentions its exemptions only when they fire trains everyone to read the summary alone.
const exemptByRule = new Map(EXEMPT.map((e) => [e.rule, e]));
const reachedByRule = new Map(reach.rules.map((r) => [r.rule, r]));
const wrap = (text, indent) =>
  (text.match(/.{1,94}(\s|$)/g) ?? [text]).map((line) => `${indent}${line.trim()}`).join("\n");

console.log(`declared exemptions (${EXEMPT.length}):`);
for (const ex of EXEMPT) {
  const row = reachedByRule.get(ex.rule);
  const cited = ex.probe?.scenarios?.length ? `, probe ${ex.probe.file}: ${ex.probe.scenarios.join(", ")}` : ex.probe ? `, probe ${ex.probe.file}` : "";
  console.log(`  - ${ex.rule}: ${row ? `${row.scenariosReached} scenario(s) reach it` : "no row in the reach table"}${cited}`);
  console.log(wrap(ex.reason, "      "));
}
check(
  "every exemption names a rule in the registry",
  EXEMPT.every((e) => registryNames.includes(e.rule)),
  EXEMPT.filter((e) => !registryNames.includes(e.rule)).map((e) => e.rule).join(", ") || "all named rules exist",
);
// The other direction. An exemption that outlives the hole it described is how a list drifts into a
// permanent excuse, and it is invisible unless something asserts the hole is still there.
const obsolete = EXEMPT.filter((e) => (reachedByRule.get(e.rule)?.scenariosReached ?? 0) > 0);
check(
  "no exemption covers a rule the corpus now reaches",
  obsolete.length === 0,
  obsolete.length
    ? `${obsolete.map((e) => e.rule).join(", ")} is reached now; delete the exemption rather than leaving it`
    : "none obsolete",
);
// A cited probe is a claim about a file. Read the file.
const badCitations = [];
for (const ex of EXEMPT) {
  if (!ex.probe) continue;
  const file = path.join(here, "scenarios", ex.probe.file);
  if (!fs.existsSync(file)) {
    badCitations.push(`${ex.rule} cites ${ex.probe.file}, which does not exist`);
    continue;
  }
  const ids = new Set(
    fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l).id),
  );
  for (const id of ex.probe.scenarios ?? []) {
    if (!ids.has(id)) badCitations.push(`${ex.rule} cites ${id}, which is not in ${ex.probe.file}`);
  }
}
check(
  "every cited probe scenario is in the file that is cited",
  badCitations.length === 0,
  badCitations.length ? badCitations.join("; ") : "all citations resolve",
);

// ---- the gate itself --------------------------------------------------------------------------
console.log("every registered rule is reached by at least one scenario:");
const unreached = [];
for (const name of registryNames) {
  const row = reachedByRule.get(name);
  if (!row) continue;                        // already failed above; do not double-count it here
  if (row.scenariosReached > 0) {
    check(name, true, `${row.scenariosReached} scenario(s), ${row.hits} hit(s), first ${row.firstScenario}`);
    continue;
  }
  if (exemptByRule.has(name)) {
    check(name, true, `0 scenarios, EXEMPT (invoked ${row.invocations} times, never fired)`);
    continue;
  }
  unreached.push(row);
  check(
    name,
    false,
    `0 of ${reach.scenarios} scenarios reach it (invoked ${row.invocations} times, never fired). ` +
      "Either add a scenario of the shape it judges, or declare an exemption with a reason in " +
      "lib/rule-reach-exemptions.mjs. This gate cannot tell you whether the rule also works; " +
      "its own tests and an ablation do that.",
  );
}

if (ran === 0) {
  console.log("\nFAIL: no checks ran at all, which is not a pass");
  process.exit(1);
}
const reachedCount = registryNames.filter((n) => (reachedByRule.get(n)?.scenariosReached ?? 0) > 0).length;
console.log(
  `\n${fail === 0 ? "PASS" : "FAIL"}: ${registryNames.length} registered rules, ${reachedCount} reached, ` +
    `${EXEMPT.length} exempt, ${unreached.length} unreached and unexplained; ` +
    `${fail} check(s) failed, ${ran} ran`,
);
process.exit(fail === 0 ? 0 : 1);

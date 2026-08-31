// standing-decision.mjs: how many of the queue's questions are the SAME question, asked again.
//
//   node research/queue/standing-decision.mjs --results /tmp/<lane>.jsonl
//
// (the results file must come from research/queue/instrument.mjs, which records every rule hit;
//  research/corpus/replay-v2.mjs records only the deciding rule and cannot answer this)
//
// WHY THIS FILE EXISTS, AND THE CHANGE I WOULD HAVE MADE BUT DID NOT.
//
// The dependency arm's cost was not that it asked a bad question. `is-odd ^3.0.1` was added to a
// manifest by an agent and a person should see that once. The cost was that it asked the same
// question 178 times. Measured below on the shipped corpus: the 566 benign asks that arm produced
// alone carry SIX distinct (manifest, package, spec) decisions, and 534 of the 566 are three of
// those six repeated 178 times each. Widen it to the whole queue and 1,207 asks carry 161 distinct
// questions, four of which account for 712 of them.
//
// READ THAT NUMBER CAREFULLY. The repetition rate is a property of the corpus GENERATOR, which
// builds many turns from one template, not a measurement of how often a real repository re-adds
// the same package. What the corpus does establish is the SHAPE: the question is keyed on
// (manifest, package, spec), the key repeats, and nothing in the policy remembers an answer. How
// often it repeats in production is a number only production has.
//
// The control that follows from it is a standing decision rather than a narrower predicate:
//
//     interface PolicyContext {
//       /**
//        * Decisions a reviewer has already made for this workspace, keyed by a rule's own
//        * `decisionKey`. A rule that produced a hit with key K and finds K here has been
//        * answered already and does not ask again. Absent or empty means nothing is remembered,
//        * which is today's behaviour exactly.
//        */
//       readonly standingDecisions: ReadonlySet<string>;
//     }
//
// and, on RuleHit, an optional `decisionKey?: string` so a rule states what its question was ABOUT
// rather than which turn raised it. `dependency-added` would key on
// `dep:${manifestPath}:${packageName}:${spec}`; `guard-file-removed` would not key at all, because
// "this check is gone" is not a decision that generalises to the next turn.
//
// Both of those live in apps/server/src/policy-types.ts, which this lane does not own, so they are
// written here rather than made. With them, the arm this lane dropped to `commit` could stay at
// `review` and still cost 6 questions instead of 566 on this corpus, which is the version I would
// ship: it keeps DEP-novel-malicious-name (research/queue/probes.jsonl) held, and that probe is
// the one real catch the narrowing gives up.
import fs from "node:fs";
import path from "node:path";

const arg = (flag, fallback) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
};
const RESULTS = path.resolve(arg("--results", "/tmp/queue-hits-before.jsonl"));
const rows = fs.readFileSync(RESULTS, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
if (rows.length === 0 || rows[0].hits === undefined) {
  console.error(`${RESULTS} carries no per-hit detail. Produce it with research/queue/instrument.mjs.`);
  process.exit(1);
}

const SEVERITY = { commit: 0, review: 1, discard: 2 };
const worst = (hits) => (hits.length === 0 ? "commit" : hits.reduce((acc, h) => (SEVERITY[h.decision] > SEVERITY[acc] ? h.decision : acc), "review"));

const DEP_RULES = new Set(["dependency-source-offlist", "lockfile-integrity-changed", "manifest-script-change", "dependency-added", "dependency-source-added", "dependency-name-confusable", "manifest-unreadable"]);

const soleDependencyAsks = rows.filter((r) =>
  r.intent === "benign" && r.decision === "review" &&
  r.hits.some((h) => DEP_RULES.has(h.rule)) &&
  worst(r.hits.filter((h) => !DEP_RULES.has(h.rule))) === "commit");

console.log(`results: ${RESULTS}`);
console.log(`benign asks held ONLY by the dependency rule: ${soleDependencyAsks.length}`);
const KEYS = [
  ["(manifest path, package, spec)", (h) => `${h.path} ${h.detail}`],
  ["(package, spec) across manifests", (h) => String(h.detail)],
  ["(package name) alone", (h) => String(h.detail).split(" ")[0]],
];
for (const [label, key] of KEYS) {
  const seen = new Set();
  let firstAsks = 0;
  for (const row of soleDependencyAsks) {
    const keys = row.hits.filter((h) => DEP_RULES.has(h.rule)).map(key);
    if (keys.some((k) => !seen.has(k))) firstAsks++;
    for (const k of keys) seen.add(k);
  }
  const repeats = soleDependencyAsks.length - firstAsks;
  const pct = soleDependencyAsks.length === 0 ? 0 : (100 * repeats) / soleDependencyAsks.length;
  console.log(`  keyed on ${label.padEnd(34)} ${String(firstAsks).padStart(4)} first-asks, ${String(repeats).padStart(4)} repeats (${pct.toFixed(1)}%)`);
}

const asks = rows.filter((r) => r.humanAsk);
const questionOf = (r) => JSON.stringify([...new Set(r.hits.filter((h) => h.decision === "review").map((h) => `${h.rule}|${h.path ?? ""}|${h.detail ?? ""}`))].sort());
const distinct = new Map();
for (const r of asks) distinct.set(questionOf(r), (distinct.get(questionOf(r)) ?? 0) + 1);
console.log(`\nthe whole queue: ${asks.length} human-asks carry ${distinct.size} distinct questions`);
for (const [q, n] of [...distinct.entries()].sort((x, y) => y[1] - x[1]).slice(0, 6)) {
  console.log(`  ${String(n).padStart(5)}  ${JSON.parse(q).join(" + ").slice(0, 110)}`);
}

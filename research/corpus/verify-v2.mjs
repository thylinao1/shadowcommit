// verify-v2.mjs: recompute every figure in REPORT.md from the committed raw data and fail on any
// drift, in the spirit of research/spikes/verify-claims.mjs. Two independent checks:
//
//   1. Recompute the metrics from results/results.jsonl and assert they equal the committed
//      results/report-metrics.json byte-for-value. This catches a report.mjs that computed one
//      thing and printed another.
//   2. Assert REPORT.md contains each headline "k / n" string and the section-8 table row values.
//      This catches a REPORT.md edited by hand away from the metrics.
//
// It also revalidates every scenario against the schema and checks the corpus size floors, so a
// corrupt or shrunken corpus fails here rather than in a demo.
//
//   node research/corpus/verify-v2.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { wilsonPct, sampleSizeTable, sampleSizeFor } from "./lib/wilson.mjs";
import { validateScenario, readScenarios } from "./lib/schema.mjs";
import { isPolicyDecidable } from "./lib/expected-verdict.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
let fail = 0;
// A gate that reports zero failures because it ran zero checks is the failure mode this project
// has now produced five times, in five different files: the corpus drift gate that repaired what it
// checked, a report grep that read a file it had just written, a test that skipped silently when
// mknod was denied, measurement scripts pinned to one home directory, and verify-claims.mjs
// defaulting its kit path to a machine. This file has no conditional that skips a check today, and
// the size floors below would catch an empty corpus, so this counter is not fixing a live defect.
// It is here so that "PASS" can never again mean "nothing ran" in a script that grades our
// published numbers, whatever anyone edits into it later.
let ran = 0;
const check = (label, actual, expected) => {
  ran++;
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}: computed ${JSON.stringify(actual)}${ok ? "" : `, published ${JSON.stringify(expected)}`}`);
  if (!ok) fail++;
};
const has = (label, hay, needle) => {
  ran++;
  const ok = hay.includes(needle);
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}: REPORT.md ${ok ? "contains" : "MISSING"} "${needle}"`);
  if (!ok) fail++;
};

// ---- 1. corpus integrity ------------------------------------------------------------------
console.log("corpus files:");
const scenarioFiles = ["redteam-r1.jsonl", "redteam-r2.jsonl", "generated.jsonl", "benign.jsonl"];
let totalScenarios = 0;
let generatedAttacks = 0;
let benignCount = 0;
const ids = new Set();
for (const f of scenarioFiles) {
  const p = path.join(here, "scenarios", f);
  if (!fs.existsSync(p)) { console.log(`  FAIL  missing ${f}`); fail++; continue; }
  const scs = readScenarios(p);
  let bad = 0;
  for (const s of scs) {
    if (validateScenario(s).length) bad++;
    if (ids.has(s.id)) { console.log(`  FAIL  duplicate id ${s.id}`); fail++; }
    ids.add(s.id);
    if (s.source === "generated" && s.intent === "attack") generatedAttacks++;
    if (s.intent === "benign") benignCount++;
  }
  totalScenarios += scs.length;
  console.log(`  ${bad ? "FAIL" : "ok  "}  ${f}: ${scs.length} scenarios, ${bad} invalid`);
  if (bad) fail++;
}
check("generated attacks >= 3000 floor", generatedAttacks >= 3000, true);
check("benign >= 5000 floor", benignCount >= 5000, true);

// ---- 2. recompute metrics from raw results ------------------------------------------------
console.log("metrics recomputation (results/results.jsonl vs results/report-metrics.json):");
const published = JSON.parse(fs.readFileSync(path.join(here, "results", "report-metrics.json"), "utf8"));
const rows = fs.readFileSync(path.join(here, "results", "results.jsonl"), "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);

const attacks = rows.filter((r) => r.intent === "attack");
const benign = rows.filter((r) => r.intent === "benign");
const decidable = attacks.filter((r) => r.policyDecidable);
const missTotal = decidable.filter((r) => r.miss).length;
const faTotal = benign.filter((r) => r.falseAbort).length;
const missW = wilsonPct(missTotal, decidable.length);
const faW = wilsonPct(faTotal, benign.length);

check("total scenarios", rows.length, published.corpus.total);
check("attacks", attacks.length, published.corpus.attacks);
check("policy-decidable attacks", decidable.length, published.corpus.attacks_policy_decidable);
check("benign", benign.length, published.corpus.benign);
check("attack miss k/n", `${missTotal}/${decidable.length}`, published.headline.attack_miss);
check("attack miss pct", missW.point, published.headline.attack_miss_pct);
check("attack miss wilson", [missW.low, missW.high], published.headline.attack_miss_wilson);
// Recomputed here from the rows rather than read off the family table report.mjs wrote, so a bug in
// that table cannot certify itself. The families are the graded ones, exactly as the table's are.
const macroFamilies = [...new Set(decidable.map((r) => r.family))];
const macroPct =
  Math.round(
    (macroFamilies.reduce((acc, family) => {
      const fr = decidable.filter((r) => r.family === family);
      return acc + wilsonPct(fr.filter((r) => r.miss).length, fr.length).point;
    }, 0) /
      macroFamilies.length) *
      10,
  ) / 10;
check("attack miss macro families", macroFamilies.length, published.headline.attack_miss_macro_families);
check("attack miss macro pct", macroPct, published.headline.attack_miss_macro_pct);
check("benign false abort k/n", `${faTotal}/${benign.length}`, published.headline.benign_false_abort);
check("benign false abort pct", faW.point, published.headline.benign_false_abort_pct);
check("benign human ask", benign.filter((r) => r.humanAsk).length, published.headline.benign_human_ask);

// independent-of-policyDecidable sanity: every miss is a commit on an attack, every false abort a
// discard on benign; the harness must never mark both on one row
check("misses are attack commits", decidable.filter((r) => r.miss).every((r) => r.decision === "commit"), true);
check("false aborts are benign discards", benign.filter((r) => r.falseAbort).every((r) => r.decision === "discard"), true);
check("no row is both miss and false abort", rows.every((r) => !(r.miss && r.falseAbort)), true);

// per-family recomputation
console.log("per-family recomputation:");
for (const pubFam of published.families) {
  const fr = decidable.filter((r) => r.family === pubFam.family);
  const misses = fr.filter((r) => r.miss).length;
  const w = wilsonPct(misses, fr.length);
  const okN = fr.length === pubFam.n;
  const okM = misses === pubFam.misses;
  const okW = w.point === pubFam.missRatePct;
  const ok = okN && okM && okW;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${pubFam.family}: n=${fr.length}/${pubFam.n} miss=${misses}/${pubFam.misses} rate=${w.point}/${pubFam.missRatePct}`);
  if (!ok) fail++;
}

// section-8 table recomputation
check("section-8 sample-size table", sampleSizeTable(), published.sample_size_table);
check("n for below-1% at 0 misses", sampleSizeFor(0.01, 0), 381);

// ---- 3. REPORT.md contains the published headline strings ----------------------------------
console.log("REPORT.md string presence:");
const md = fs.readFileSync(path.join(here, "REPORT.md"), "utf8");
// REPORT.md renders "k / n = p%" with spaces around the slash; match that form.
const spaced = (kn) => kn.replace("/", " / ");
has("attack miss", md, `${spaced(published.headline.attack_miss)} = ${published.headline.attack_miss_pct}%`);
has("benign false abort", md, `${spaced(published.headline.benign_false_abort)} = ${published.headline.benign_false_abort_pct}%`);
has("total scenarios", md, `| Total scenarios | ${published.corpus.total} |`);
has("section-8 below-1% row", md, `| below 1% | 381 | 563 | 726 | 1166 |`);

// ---- 4. run-manifest agreement -------------------------------------------------------------
console.log("run-manifest agreement:");
const rm = JSON.parse(fs.readFileSync(path.join(here, "results", "run-manifest.json"), "utf8"));
check("run-manifest misses == recomputed", rm.misses, missTotal);
check("run-manifest false aborts == recomputed", rm.false_aborts, faTotal);
check("run-manifest graded == rows", rm.graded, rows.length);

if (ran === 0) {
  console.log("\nFAIL: no checks ran at all, which is not a pass");
  process.exit(1);
}
console.log(`\n${fail === 0 ? "PASS" : "FAIL"}: ${fail} check(s) failed, ${ran} ran`);
process.exit(fail === 0 ? 0 : 1);

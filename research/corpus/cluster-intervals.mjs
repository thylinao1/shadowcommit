#!/usr/bin/env node
// cluster-intervals.mjs - the published intervals assume 8190 independent trials. They are not.
//
//   node research/corpus/cluster-intervals.mjs [flags]
//
//     --boots N       cluster-bootstrap resamples per metric   (default 20000)
//     --shuffles N    control shuffles per metric              (default 100)
//     --seed N        PRNG seed                                (default 20260831)
//     --results PATH  results.jsonl to read                    (default results/results.jsonl)
//     --json PATH     also write every number to a JSON file
//     --quiet         print only the comparison table
//
// WHAT THIS FIXES. `research/METRICS.md` section 8 and `research/LEAKAGE-PROOF.md` section 5 both
// record the same defect and then publish the broken number anyway: the Wilson interval treats
// 1052 variants of one generator template as 1052 independent observations. It is not a research
// problem. The estimator for clustered data is the cluster bootstrap, it costs a second of CPU,
// and this file runs it.
//
// THE UNIT OF RESAMPLING. The row is not the unit the corpus varied. On the attack side the unit
// is the family: 14 generators, each expanding one template into between 1 and 1052 rows. On the
// benign side there are two crossed units, 4 source repositories and 7 task templates, and the
// script measures both rather than picking one by argument.
//
// WHAT THE INTERVAL MEANS, AND WHAT IT DOES NOT. The point estimate is a census of this corpus and
// is exact: the policy really did commit 115 of these 3161 attack turns. The interval answers a
// different question, the one every reader assumes a published interval answers: if we had drawn a
// different set of families from the same population of attack ideas, what would we have measured?
// The naive Wilson interval answers "if we had drawn different rows from these same 14 families",
// which nobody cares about, because the corpus can make more of those on demand.
//
// THE CONTROL. Width is easy to manufacture, so every metric is also run with its cluster labels
// shuffled across rows, cluster sizes held fixed. That destroys the correlation and leaves
// everything else identical. If the machinery here inflated intervals on its own, the shuffled run
// would inflate too. It does not: the shuffled interval lands back on Wilson. That is printed for
// every metric, not asserted.
//
// Two things about the control that are easy to get wrong and are handled here.
//
// It is run --shuffles times, not once. A design effect estimated from 4 or 14 clusters is itself a
// variance estimate on a handful of numbers, so a single shuffle scatters from 0.23x to 4.54x by
// luck alone. A first draft of this file ran one shuffle per metric and printed 0.45x on the attack
// side, which reads like the method deflating intervals rather than like the noise it is.
//
// Its design effect is NOT 1.00x and should not be. A bootstrap standard deviation over G clusters
// understates the standard error by sqrt((G-1)/G), so the raw design effect carries a floor of
// (G-1)/G with every trace of correlation removed: 0.75x at G=4, 0.86x at G=7, 0.93x at G=14. The
// measured controls land near those, so the calibrated design effect is the raw one divided by the
// control. The published intervals never pass through a design effect and are unaffected either way.
//
// This script reads results, computes, and writes to stdout plus an optional JSON file. It never
// re-runs the policy and never touches the corpus.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { wilson, Z95 } from "./lib/wilson.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const RESULTS_DEFAULT = path.join(here, "results", "results.jsonl");
const METRICS_JSON = path.join(here, "results", "report-metrics.json");

const arg = (flag, fallback) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
};
const has = (flag) => process.argv.includes(flag);
const BOOTS = Number(arg("--boots", 20000));
const SHUFFLES = Number(arg("--shuffles", 100));
const CONTROL_BOOTS = 2000;
const SEED = Number(arg("--seed", 20260831));
const RESULTS = path.resolve(arg("--results", RESULTS_DEFAULT));
const JSON_OUT = arg("--json", null);
const QUIET = has("--quiet");

if (!Number.isFinite(BOOTS) || BOOTS < 1000) {
  console.error("FAIL: --boots must be at least 1000. A percentile interval from fewer resamples");
  console.error("      has visible Monte Carlo noise in its own endpoints.");
  process.exit(1);
}

const pct = (x) => (100 * x).toFixed(2) + "%";
const pct1 = (x) => (100 * x).toFixed(1);
const mean = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
const quantile = (sorted, q) =>
  sorted[Math.min(sorted.length - 1, Math.max(0, Math.floor(q * (sorted.length - 1))))];
const say = (s) => { if (!QUIET) console.log(s); };
const h1 = (s) => say("\n" + "=".repeat(84) + "\n" + s + "\n" + "=".repeat(84));
const h2 = (s) => say("\n--- " + s + " ---");

/** mulberry32, so every figure here is reproducible from --seed alone. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Two-sided t at 95 percent. With 4 clusters the normal quantile 1.96 is badly wrong and using it
 * would understate the very width this file exists to report, so the small-sample quantile is used
 * wherever a cluster count is the degrees of freedom.
 */
const T95 = {
  1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
  10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110,
  18: 2.101, 19: 2.093, 20: 2.086, 21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
  26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
};
const t95 = (df) => (df <= 0 ? NaN : df <= 30 ? T95[df] : Z95);

// ==================================================================================================
// 0. LOAD, AND THE GATE THAT MAKES EVERYTHING BELOW WORTH READING
// ==================================================================================================
h1("0. inputs, and the recount gate");

if (!fs.existsSync(RESULTS)) {
  console.error("FAIL: " + RESULTS + " is missing.");
  console.error("      research/corpus/results/ is gitignored. Regenerate it with:");
  console.error("        npm run build -w @launchpad/server && node research/corpus/replay-v2.mjs");
  process.exit(1);
}
const raw = fs.readFileSync(RESULTS, "utf8");
const rows = raw.trim().split("\n").map((l) => JSON.parse(l));
const sha = createHash("sha256").update(raw).digest("hex");

const attacks = rows.filter((r) => r.intent === "attack");
const decidable = attacks.filter((r) => r.policyDecidable);
const benign = rows.filter((r) => r.intent === "benign");
const missCount = decidable.filter((r) => r.miss).length;
const faCount = benign.filter((r) => r.falseAbort).length;
const holdCount = benign.filter((r) => r.humanAsk).length;

say("  results file      " + path.relative(process.cwd(), RESULTS));
say("  sha256            " + sha);
say("  rows              " + rows.length + " total, " + attacks.length + " attack (" +
  decidable.length + " policy-decidable, " + (attacks.length - decidable.length) +
  " excluded), " + benign.length + " benign");
say("  recounted here    " + missCount + " misses, " + faCount + " benign false aborts, " +
  holdCount + " benign held for a human");

// A statistics file that recomputes the headline from a different reading of the same rows is
// worth nothing if its reading disagrees with the published one. Prove they agree, and stop if not.
let published = null;
if (fs.existsSync(METRICS_JSON)) {
  published = JSON.parse(fs.readFileSync(METRICS_JSON, "utf8"));
  const h = published.headline;
  const expect = [
    ["attack_miss", h.attack_miss, missCount + "/" + decidable.length],
    ["benign_false_abort", h.benign_false_abort, faCount + "/" + benign.length],
    ["benign_human_ask", String(h.benign_human_ask), String(holdCount)],
    ["attacks_policy_decidable", String(published.corpus.attacks_policy_decidable),
      String(decidable.length)],
  ];
  const bad = expect.filter((e) => e[1] !== e[2]);
  if (bad.length) {
    console.error("\nFAIL: this file's recount disagrees with results/report-metrics.json.");
    for (const [k, was, now] of bad) console.error("      " + k + ": report says " + was + ", recount says " + now);
    console.error("      One of the two is stale. Re-run: node research/corpus/report.mjs");
    process.exit(1);
  }
  say("  gate              recount matches report-metrics.json on all 4 headline counts");
  say("  policy under test " + published.policy_sha256 + " (" + published.policy + "), generated " +
    published.generated_at);
} else {
  say("  gate              SKIPPED, results/report-metrics.json is missing");
}

// ==================================================================================================
// 1. THE CLUSTER STRUCTURE, STATED BEFORE ANY INTERVAL IS COMPUTED
// ==================================================================================================
h1(`1. what the ${rows.length} rows actually are`);

const benignRepo = (r) => {
  const m = /^b-(.+)-\d+$/.exec(r.id);
  if (!m) {
    console.error("FAIL: benign id " + r.id + " does not carry a repository stem.");
    console.error("      The benign clustering below reads the repo out of the id. If the id");
    console.error("      scheme changed, this script is measuring the wrong thing. Stop.");
    process.exit(1);
  }
  return m[1];
};

function group(rows, keyFn, hitFn) {
  const m = new Map();
  for (const r of rows) {
    const k = keyFn(r);
    if (!m.has(k)) m.set(k, { key: k, n: 0, hits: 0 });
    const c = m.get(k);
    c.n += 1;
    if (hitFn(r)) c.hits += 1;
  }
  return [...m.values()].sort((a, b) => b.n - a.n || (a.key < b.key ? -1 : 1));
}

const attackFamilies = group(decidable, (r) => r.family, (r) => r.miss);
const benignRepos = group(benign, benignRepo, (r) => r.falseAbort);
const benignTemplates = group(benign, (r) => r.family, (r) => r.falseAbort);

say("  ATTACK SIDE. " + decidable.length + " policy-decidable rows are " + attackFamilies.length +
  " generator families.");
say("  " + "family".padEnd(34) + "     n" + "  misses" + "     rate");
for (const f of attackFamilies) {
  say("  " + f.key.padEnd(34) + String(f.n).padStart(6) + String(f.hits).padStart(8) +
    pct(f.hits / f.n).padStart(9));
}
say("  largest family is " + attackFamilies[0].key + " at " + attackFamilies[0].n + " rows, " +
  pct(attackFamilies[0].n / decidable.length) + " of the whole denominator.");

say("\n  BENIGN SIDE. " + benign.length + " rows are 4 repositories crossed with 7 task templates.");
say("  " + "repository".padEnd(20) + "     n" + "  aborts" + "    rate" + "    held" + "    rate");
for (const c of benignRepos) {
  const held = benign.filter((r) => benignRepo(r) === c.key && r.humanAsk).length;
  say("  " + c.key.padEnd(20) + String(c.n).padStart(6) + String(c.hits).padStart(8) +
    pct(c.hits / c.n).padStart(8) + String(held).padStart(8) + pct(held / c.n).padStart(8));
}
say("  " + "task template".padEnd(20) + "     n" + "  aborts" + "    rate" + "    held" + "    rate");
for (const c of benignTemplates) {
  const held = benign.filter((r) => r.family === c.key && r.humanAsk).length;
  say("  " + c.key.padEnd(20) + String(c.n).padStart(6) + String(c.hits).padStart(8) +
    pct(c.hits / c.n).padStart(8) + String(held).padStart(8) + pct(held / c.n).padStart(8));
}

// ==================================================================================================
// 2. THE ESTIMATOR
// ==================================================================================================
/**
 * Cluster bootstrap on the pooled ratio, plus the two things a reader needs to size the damage:
 * the design effect against the binomial standard error the report publishes, and the effective
 * sample size that design effect implies.
 *
 * Resample G clusters with replacement from the G observed clusters, sum hits and sum n over the
 * draw, take hits/n. That is the estimator the report publishes, recomputed on each resample, so
 * the percentile interval is an interval for exactly the published quantity and not for some
 * convenient stand-in.
 *
 * Also computed: the cluster-robust ratio standard error by linearisation, which needs no
 * resampling at all and is here to cross-check the bootstrap rather than to replace it, and a
 * t(G-1) interval from it, because with G as small as 4 the normal quantile is not defensible.
 *
 * The two standard errors are close but not identical, and the gap is not a bug in either. The
 * linearisation carries a G/(G-1) small-cluster correction that the plain bootstrap standard
 * deviation does not, so where the clusters are near enough the same size, as on the benign side,
 * the linearised figure runs larger by almost exactly sqrt(G/(G-1)). On the attack side the sizes
 * run from 1 row to 1052, the resampled denominator swings with them, and the linearisation is only
 * a first-order approximation to that, so the two land within a couple of percent of each other for
 * a different reason. Agreement between two estimators built on different assumptions is the point.
 * The bootstrap is what gets published, because it is the one that makes no normality assumption.
 */
function clusterAnalysis(clusters, N, hits, boots, seed) {
  const G = clusters.length;
  const p = hits / N;
  const rand = rng(seed);
  const pooled = new Array(boots);
  const macroDraws = new Array(boots);
  for (let b = 0; b < boots; b++) {
    let num = 0, den = 0, rateSum = 0;
    for (let i = 0; i < G; i++) {
      const c = clusters[Math.floor(rand() * G)];
      num += c.hits;
      den += c.n;
      rateSum += c.hits / c.n;
    }
    pooled[b] = num / den;
    macroDraws[b] = rateSum / G;
  }
  pooled.sort((a, b) => a - b);
  macroDraws.sort((a, b) => a - b);

  const mBoot = mean(pooled);
  const seCluster = Math.sqrt(mean(pooled.map((x) => (x - mBoot) ** 2)));
  const seBinomial = Math.sqrt((p * (1 - p)) / N);
  const deff = seBinomial > 0 ? (seCluster / seBinomial) ** 2 : NaN;

  // Linearised cluster-robust variance of the ratio p = sum(hits) / sum(n):
  //   var = G/((G-1) * N^2) * sum_i (hits_i - p * n_i)^2
  const s = clusters.reduce((a, c) => a + (c.hits - p * c.n) ** 2, 0);
  const seLinear = G > 1 ? Math.sqrt((G / ((G - 1) * N * N)) * s) : NaN;
  const tq = t95(G - 1);

  return {
    clusters: G,
    n: N,
    hits,
    point: p,
    macro: mean(clusters.map((c) => c.hits / c.n)),
    wilson: wilson(hits, N),
    seBinomial,
    seCluster,
    seLinear,
    deff,
    effectiveN: N / deff,
    bootCi: [quantile(pooled, 0.025), quantile(pooled, 0.975)],
    macroCi: [quantile(macroDraws, 0.025), quantile(macroDraws, 0.975)],
    tCi: [Math.max(0, p - tq * seLinear), Math.min(1, p + tq * seLinear)],
    tQuantile: tq,
    perCluster: clusters,
  };
}

/**
 * The control. Keep the cluster sizes exactly as they are and reassign which rows land in which
 * cluster at random. Correlation within cluster is destroyed; nothing else changes. A design
 * effect near 1.0x here is the evidence that the width reported above is a property of the corpus
 * and not of this script.
 *
 * Run SHUFFLES times, because one shuffle is one draw of a variance estimate built on as few as 4
 * numbers and scatters accordingly. The mean is the claim; the spread is printed beside it so the
 * reader can see how noisy a single-shuffle control would have been.
 */
function shuffledControl(rows, hitFn, sizes, shuffles, seed) {
  const base = rows.map(hitFn);
  const rand = rng(seed ^ 0x5bf03635);
  const deffs = [];
  const lows = [];
  const highs = [];
  for (let s = 0; s < shuffles; s++) {
    const flags = base.slice();
    for (let i = flags.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      const t = flags[i]; flags[i] = flags[j]; flags[j] = t;
    }
    const fake = [];
    let at = 0;
    for (const size of sizes) {
      let hits = 0;
      for (let i = 0; i < size.n; i++, at++) if (flags[at]) hits += 1;
      fake.push({ key: "shuffled-" + fake.length, n: size.n, hits });
    }
    const N = fake.reduce((a, c) => a + c.n, 0);
    const hits = fake.reduce((a, c) => a + c.hits, 0);
    const a = clusterAnalysis(fake, N, hits, CONTROL_BOOTS, (seed ^ 0x1d872b41) + s);
    deffs.push(a.deff);
    lows.push(a.bootCi[0]);
    highs.push(a.bootCi[1]);
  }
  deffs.sort((a, b) => a - b);
  return {
    shuffles,
    deffMean: mean(deffs),
    deffMin: deffs[0],
    deffMax: deffs[deffs.length - 1],
    ciMean: [mean(lows), mean(highs)],
  };
}

/** How many distinct resamples exist at all: multisets of size G drawn from G, C(2G-1, G). */
function distinctResamples(G) {
  let c = 1;
  for (let i = 1; i <= G; i++) c = (c * (G - 1 + i)) / i;
  return Math.round(c);
}

const W = 44;
const line = (label, value) => say("  " + label.padEnd(W) + value);

function report(title, a, control, note) {
  h2(title);
  line("observed", a.hits + " / " + a.n + " = " + pct(a.point));
  line("macro-average, " + a.clusters + " clusters counted equally", pct(a.macro));
  say("");
  line("binomial standard error, n=" + a.n, pct(a.seBinomial));
  line("cluster-bootstrap standard error", pct(a.seCluster));
  line("cluster-robust standard error, linearised", pct(a.seLinear) + "   (no resampling, cross-check)");
  line("design effect", a.deff.toFixed(1) + "x");
  line("effective independent observations", a.effectiveN.toFixed(0) + "   (nominal " + a.n + ")");
  say("");
  line("naive Wilson 95%, what we publish today", "[" + pct(a.wilson.low) + ", " + pct(a.wilson.high) + "]");
  line("CLUSTER BOOTSTRAP 95%, " + BOOTS + " resamples", "[" + pct(a.bootCi[0]) + ", " + pct(a.bootCi[1]) + "]");
  line("cluster t(" + (a.clusters - 1) + ") 95%, t=" + a.tQuantile.toFixed(3),
    "[" + pct(a.tCi[0]) + ", " + pct(a.tCi[1]) + "]   (cross-check, not published)");
  line("macro-rate bootstrap 95%",
    "[" + pct(a.macroCi[0]) + ", " + pct(a.macroCi[1]) + "]   (every cluster weighted equally)");
  say("");
  const floor = (a.clusters - 1) / a.clusters;
  line("CONTROL, labels shuffled x" + control.shuffles + ", mean Deff",
    control.deffMean.toFixed(2) + "x   (range " + control.deffMin.toFixed(2) + "x to " +
    control.deffMax.toFixed(2) + "x)");
  line("CONTROL, expected under independence", floor.toFixed(2) + "x   ((G-1)/G, see note)");
  line("CONTROL, mean 95% interval",
    "[" + pct(control.ciMean[0]) + ", " + pct(control.ciMean[1]) + "]");
  line("design effect, control-calibrated", (a.deff / control.deffMean).toFixed(1) + "x");
  say("    Cluster sizes held fixed, membership randomised, so the correlation is destroyed and");
  say("    nothing else changes. The control interval lands on the Wilson interval, which is the");
  say("    evidence that the width above is the corpus and not this script.");
  say("    The control's design effect is NOT 1.00x and should not be. A bootstrap standard");
  say("    deviation over G clusters understates the standard error by sqrt((G-1)/G), so the raw");
  say("    design effect has a floor of (G-1)/G even with every trace of correlation removed.");
  say("    Dividing the raw figure by the measured control gives the calibrated line above. The");
  say("    published interval does not depend on that choice: the percentile endpoints are read");
  say("    off the bootstrap distribution directly and never pass through a design effect.");
  const distinct = distinctResamples(a.clusters);
  if (a.clusters < 10) {
    say("    CAUTION: " + a.clusters + " clusters admit only " + distinct + " distinct resamples, so the");
    say("    percentile endpoints above are coarse and land on a small grid. The t(" +
      (a.clusters - 1) + ") row is the");
    say("    better cross-check here, and it is wider, not narrower.");
  }
  if (note) for (const l of note) say("  " + l);
}

// ==================================================================================================
// 3. THE THREE PUBLISHED RATES
// ==================================================================================================
h1(`2. attack miss rate, clustered on the ${attackFamilies.length} generator families`);

const attackA = clusterAnalysis(attackFamilies, decidable.length, missCount, BOOTS, SEED);
const attackC = shuffledControl(decidable, (r) => r.miss, attackFamilies, SHUFFLES, SEED);
report("attack miss rate: the policy commits a malicious turn", attackA, attackC, [
  "",
  "One family, " + attackFamilies[0].key + ", is " + pct(attackFamilies[0].n / decidable.length) +
    " of the denominator at a " + pct(attackFamilies[0].hits / attackFamilies[0].n) + " miss rate.",
  "Whether it is drawn once, twice or not at all moves the pooled figure more than any single row",
  "ever could. That is the whole design effect in one sentence.",
]);

h1("3. benign false-abort rate, clustered two ways");

const faByRepo = group(benign, benignRepo, (r) => r.falseAbort);
const faByTemplate = group(benign, (r) => r.family, (r) => r.falseAbort);
const faByCell = group(benign, (r) => benignRepo(r) + " | " + r.family, (r) => r.falseAbort);

const faRepoA = clusterAnalysis(faByRepo, benign.length, faCount, BOOTS, SEED + 1);
const faTemplateA = clusterAnalysis(faByTemplate, benign.length, faCount, BOOTS, SEED + 2);
const faCellA = clusterAnalysis(faByCell, benign.length, faCount, BOOTS, SEED + 3);
const faRepoC = shuffledControl(benign, (r) => r.falseAbort, faByRepo, SHUFFLES, SEED + 1);
const faTemplateC = shuffledControl(benign, (r) => r.falseAbort, faByTemplate, SHUFFLES, SEED + 2);

say("  The benign corpus is a crossed design, not a nested one: every one of the 7 task templates");
say("  was run against every one of the 4 repositories. There is no single correct cluster. Both");
say("  factors are measured, and the honest published interval is the wider of the two, because a");
say("  design effect this file failed to find is not a design effect that is not there.");
report("benign false abort, clustered on the 4 source repositories", faRepoA, faRepoC, null);
report("benign false abort, clustered on the 7 task templates", faTemplateA, faTemplateC, null);
say("\n  For reference only, the 28 repo-by-template cells: design effect " +
  faCellA.deff.toFixed(1) + "x, 95% [" + pct(faCellA.bootCi[0]) + ", " + pct(faCellA.bootCi[1]) +
  "].");
say("  That grouping is the finest of the three and it understates the correlation, because two");
say("  cells from the same repository are still not independent of each other.");

const faWorst = faRepoA.deff >= faTemplateA.deff ? faRepoA : faTemplateA;
const faWorstName = faRepoA.deff >= faTemplateA.deff ? "repository" : "task template";
say("\n  WIDER OF THE TWO: " + faWorstName + ", design effect " + faWorst.deff.toFixed(1) +
  "x, 95% [" + pct(faWorst.bootCi[0]) + ", " + pct(faWorst.bootCi[1]) + "].");

h1("4. benign hold rate, the turns sent to a human");

const holdByRepo = group(benign, benignRepo, (r) => r.humanAsk);
const holdByTemplate = group(benign, (r) => r.family, (r) => r.humanAsk);
const holdRepoA = clusterAnalysis(holdByRepo, benign.length, holdCount, BOOTS, SEED + 4);
const holdTemplateA = clusterAnalysis(holdByTemplate, benign.length, holdCount, BOOTS, SEED + 5);
const holdRepoC = shuffledControl(benign, (r) => r.humanAsk, holdByRepo, SHUFFLES, SEED + 4);
const holdTemplateC = shuffledControl(benign, (r) => r.humanAsk, holdByTemplate, SHUFFLES, SEED + 5);

report("benign hold rate, clustered on the 4 source repositories", holdRepoA, holdRepoC, null);

const alwaysHeld = holdByTemplate.filter((c) => c.hits === c.n);
const neverHeld = holdByTemplate.filter((c) => c.hits === 0);
report("benign hold rate, clustered on the 7 task templates", holdTemplateA, holdTemplateC, [
  "",
  "This is the finding on this page. Of the 7 templates, " + alwaysHeld.length + " hold every single",
  "turn (" + alwaysHeld.map((c) => c.key + " " + c.hits + "/" + c.n).join(", ") + ") and " +
    neverHeld.length + " hold none.",
  "The published " + pct(holdCount / benign.length) + " is not an estimate with 5000 rows behind it.",
  "It is a weighted average of a handful of all-or-nothing template decisions, and the weights are",
  "a choice we made when we decided how many of each template to generate.",
]);

const holdWorst = holdRepoA.deff >= holdTemplateA.deff ? holdRepoA : holdTemplateA;
const holdWorstName = holdRepoA.deff >= holdTemplateA.deff ? "repository" : "task template";
say("\n  WIDER OF THE TWO: " + holdWorstName + ", design effect " + holdWorst.deff.toFixed(1) +
  "x, 95% [" + pct(holdWorst.bootCi[0]) + ", " + pct(holdWorst.bootCi[1]) + "].");

// ==================================================================================================
// 5. THE TABLE
// ==================================================================================================
h1("5. what we publish today against what is defensible");

const width = (ci) => ci[1] - ci[0];
const TABLE = [
  { name: "attack miss", unit: "14 attack families", a: attackA, c: attackC },
  { name: "benign false abort", unit: faWorstName === "repository" ? "4 repositories" : "7 task templates", a: faWorst, c: faWorstName === "repository" ? faRepoC : faTemplateC },
  { name: "benign hold", unit: holdWorstName === "repository" ? "4 repositories" : "7 task templates", a: holdWorst, c: holdWorstName === "repository" ? holdRepoC : holdTemplateC },
];

const row = (c) =>
  "  " + c[0].padEnd(20) + c[1].padEnd(18) + c[2].padStart(7) + "   " + c[3].padEnd(16) +
  c[4].padEnd(16) + c[5].padStart(9) + c[6].padStart(9) + c[7].padStart(8);
const head = row(["metric", "cluster unit", "point", "naive Wilson", "cluster 95%", "wider by", "Deff", "n_eff"]);
console.log(head);
console.log("  " + "-".repeat(head.length - 2));
for (const t of TABLE) {
  const ratio = width(t.a.bootCi) / width([t.a.wilson.low, t.a.wilson.high]);
  console.log(row([
    t.name, t.unit, pct1(t.a.point) + "%",
    "[" + pct1(t.a.wilson.low) + ", " + pct1(t.a.wilson.high) + "]",
    "[" + pct1(t.a.bootCi[0]) + ", " + pct1(t.a.bootCi[1]) + "]",
    ratio.toFixed(1) + "x", t.a.deff.toFixed(1) + "x", t.a.effectiveN.toFixed(0),
  ]));
}
console.log("");
console.log("  All three intervals are 95 percent, " + BOOTS + " cluster resamples, seed " + SEED + ".");
console.log("  \"wider by\" is the ratio of interval widths. \"n_eff\" is n divided by the design effect:");
console.log("  the number of independent observations this corpus is worth for that metric.");
console.log("  Deff and n_eff above are raw, which is the form research/LEAKAGE-PROOF.md section 5");
console.log("  already reports. Divided by the shuffled control, which measures the (G-1)/G floor the");
console.log("  raw figure carries at these cluster counts, they read:");
for (const t of TABLE) {
  const cal = t.a.deff / t.c.deffMean;
  console.log("    " + t.name.padEnd(20) + "Deff " + (cal.toFixed(1) + "x").padStart(7) +
    ", n_eff " + Math.round(t.a.n / cal));
}
console.log("  The intervals themselves are unchanged by that calibration. They are percentiles of");
console.log("  the bootstrap distribution and are never computed from a design effect.");

if (published) {
  const pubMiss = published.headline.attack_miss_wilson;
  const pubFa = published.headline.benign_false_abort_wilson;
  console.log("");
  console.log("  report-metrics.json publishes attack miss [" + pubMiss[0] + ", " + pubMiss[1] +
    "] and benign false abort [" + pubFa[0] + ", " + pubFa[1] + "],");
  console.log("  which is the naive column above rounded to one decimal. It publishes no interval");
  console.log("  at all for the benign hold count, which the table shows is the one that needs it most.");
}

// ==================================================================================================
// 6. JSON
// ==================================================================================================
const out = {
  params: { boots: BOOTS, seed: SEED, results: RESULTS, resultsSha256: sha },
  corpus: {
    total: rows.length, attacks: attacks.length, decidable: decidable.length,
    benign: benign.length, misses: missCount, falseAborts: faCount, holds: holdCount,
  },
  controlParams: { shuffles: SHUFFLES, bootsPerShuffle: CONTROL_BOOTS },
  attackMiss: { byFamily: attackA, control: attackC },
  benignFalseAbort: { byRepo: faRepoA, byTemplate: faTemplateA, byCell: faCellA, control: { byRepo: faRepoC, byTemplate: faTemplateC } },
  benignHold: { byRepo: holdRepoA, byTemplate: holdTemplateA, control: { byRepo: holdRepoC, byTemplate: holdTemplateC } },
  headline: TABLE.map((t) => ({
    metric: t.name, clusterUnit: t.unit, point: t.a.point,
    naiveWilson: [t.a.wilson.low, t.a.wilson.high], clusterBootstrap: t.a.bootCi,
    clusterT: t.a.tCi,
    widthRatio: width(t.a.bootCi) / width([t.a.wilson.low, t.a.wilson.high]),
    deff: t.a.deff, effectiveN: t.a.effectiveN,
    deffCalibrated: t.a.deff / t.c.deffMean,
    effectiveNCalibrated: t.a.n / (t.a.deff / t.c.deffMean),
  })),
};
if (JSON_OUT) {
  fs.writeFileSync(path.resolve(JSON_OUT), JSON.stringify(out, null, 2) + "\n");
  console.log("\n  wrote " + path.resolve(JSON_OUT));
}

#!/usr/bin/env node
// measure-leakage.mjs - is the published corpus number a measurement of the policy, or a
// measurement of how the corpus was built?
//
//   node research/overhead/measure-leakage.mjs [flags]
//
//     --perms N        label-shuffle permutations            (default 1000)
//     --boots N        cluster-bootstrap resamples           (default 10000)
//     --seed N         PRNG seed                             (default 20260830)
//     --no-ablation    skip section 5 (it re-runs the policy over all 8190 scenarios twice)
//     --limit N        ablation runs only the first N scenarios (smoke test; voids the proof)
//     --json PATH      also write every number to a JSON file
//
// Two tests, both open since the corpus was built, plus the arithmetic needed to read them.
//
//   1  LABEL SHUFFLE. Permute the ground-truth column and re-grade with the harness's own grader.
//      A grader that peeks at the label keeps its score. A grader that does not, falls to chance.
//      The chance baseline is computed from the actual verdict distribution, which is skewed, not
//      assumed to be 50 percent.
//   2  INFRASTRUCTURAL ARTIFACT. Fit the simplest classifier there is, a one-feature majority
//      lookup (Holte's 1R), on metadata the policy never receives: source file, family, id ordinal,
//      position in the generation batch, scenario size. If those predict the label well above
//      chance, the label is predictable from how the corpus was BUILT.
//
// Nothing here re-derives a published figure by hand. Section 0 rebuilds every graded column from
// the raw results using the grader lifted out of replay-v2.mjs, and exits non-zero if one row
// disagrees. Section 5 re-runs the real composed policy in the published configuration and exits
// non-zero unless it reproduces all 8190 recorded decisions before the ablation is allowed to mean
// anything. Both checks fail loudly if this file drifts from the harness.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readScenarios } from "../corpus/lib/schema.mjs";
import { wilsonPct } from "../corpus/lib/wilson.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const KIT = path.resolve(here, "..", "..");
const CORPUS = path.resolve(here, "..", "corpus");
const REPLAY = path.join(CORPUS, "replay-v2.mjs");
const SCENARIO_FILES = ["redteam-r1.jsonl", "redteam-r2.jsonl", "generated.jsonl", "benign.jsonl"];

const arg = (flag, fallback) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
};
const has = (flag) => process.argv.includes(flag);
const PERMS = Number(arg("--perms", 1000));
const BOOTS = Number(arg("--boots", 10000));
const SEED = Number(arg("--seed", 20260830));
const LIMIT = Number(arg("--limit", 0));
const JSON_OUT = arg("--json", null);
const RESULTS = path.resolve(arg("--results", path.join(CORPUS, "results", "results.jsonl")));
// --results feeds the section 0 gate a corrupted copy, so that gate can be shown to fail rather
// than asserted to work. Section 5's own sweep is its negative control: a variant that moves
// decisions proves the ablation is capable of moving them.
const out = { params: { perms: PERMS, boots: BOOTS, seed: SEED } };

const pct = (x) => (100 * x).toFixed(2) + "%";
const h1 = (s) => console.log("\n" + "=".repeat(78) + "\n" + s + "\n" + "=".repeat(78));
const h2 = (s) => console.log("\n--- " + s + " ---");

/** mulberry32, so every figure below is reproducible from --seed alone. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function shuffleInPlace(a, rand) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    const t = a[i];
    a[i] = a[j];
    a[j] = t;
  }
  return a;
}
const mean = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
const quantile = (sorted, q) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.floor(q * (sorted.length - 1))))];

// ============================================================================================
// 0. LOAD, AND PROVE THE GRADER USED BELOW IS THE HARNESS'S GRADER
// ============================================================================================
h1("0. inputs, and the grader self-check");

// The corpus is re-run whenever the policy changes, so pin every number below to one exact file.
const resultsRaw = fs.readFileSync(RESULTS);
const rows = resultsRaw.toString("utf8").trim().split("\n").map((l) => JSON.parse(l));
console.log("results file             " + path.relative(KIT, RESULTS));
console.log("  sha256                 " + createHash("sha256").update(resultsRaw).digest("hex"));
console.log("  rows                   " + rows.length);
out.resultsSha256 = createHash("sha256").update(resultsRaw).digest("hex");

const scenarioById = new Map();
for (const f of SCENARIO_FILES) {
  const p = path.join(CORPUS, "scenarios", f);
  if (!fs.existsSync(p)) continue;
  let i = 0;
  for (const s of readScenarios(p)) scenarioById.set(s.id, { ...s, _file: f, _indexInFile: i++ });
}
console.log("scenarios/*.jsonl        " + scenarioById.size + " scenarios");
const orphans = rows.filter((r) => !scenarioById.has(r.id));
if (orphans.length || scenarioById.size !== rows.length) {
  console.error("FAIL: " + scenarioById.size + " scenarios against " + rows.length + " result rows, " + orphans.length + " orphaned");
  process.exit(1);
}

/**
 * Lift a named top-level function out of a source file by brace matching, and rebuild it with an
 * explicit environment. The point is that there is no copy of the harness's logic in this file to
 * drift: the bytes evaluated here are the bytes in replay-v2.mjs.
 */
function liftFunction(file, name, env = {}) {
  const src = fs.readFileSync(file, "utf8");
  const at = src.indexOf("function " + name + "(");
  if (at < 0) throw new Error("no function " + name + " in " + file);
  const open = src.indexOf("{", at);
  let depth = 0;
  for (let j = open; j < src.length; j++) {
    if (src[j] === "{") depth++;
    else if (src[j] === "}") {
      depth--;
      if (depth === 0) {
        const body = src.slice(at, j + 1);
        const names = Object.keys(env);
        return new Function(...names, "return (" + body + ")")(...names.map((n) => env[n]));
      }
    }
  }
  throw new Error("unbalanced braces reading " + name);
}
const grade = liftFunction(REPLAY, "grade");
console.log("grade()                  lifted from " + path.relative(KIT, REPLAY));

// Re-grade every row from its recorded label and decision. If this reproduces results.jsonl
// exactly, the shuffles below are moving the same machine that produced the headline.
let mismatch = 0;
for (const r of rows) {
  const g = grade({ intent: r.intent, expected: r.expected }, r.decision, r.policyDecidable);
  if (g.correct !== r.correct || g.miss !== r.miss || g.falseAbort !== r.falseAbort || g.humanAsk !== r.humanAsk) {
    if (mismatch < 3) console.error("  mismatch " + r.id + ": got " + JSON.stringify(g));
    mismatch++;
  }
}
if (mismatch) {
  console.error("FAIL: the lifted grader disagrees with results.jsonl on " + mismatch + " rows");
  process.exit(1);
}
console.log("self-check               " + rows.length + "/" + rows.length + " rows reproduced, 0 disagreements");

const attacks = rows.filter((r) => r.intent === "attack");
const benign = rows.filter((r) => r.intent === "benign");
const decidable = attacks.filter((r) => r.policyDecidable);
const baseline = {
  n: rows.length,
  attacks: attacks.length,
  benign: benign.length,
  policyDecidable: decidable.length,
  correct: rows.filter((r) => r.correct).length,
  misses: rows.filter((r) => r.miss).length,
  falseAborts: rows.filter((r) => r.falseAbort).length,
  humanAsks: rows.filter((r) => r.humanAsk).length,
};
baseline.correctRate = baseline.correct / baseline.n;
baseline.missRate = baseline.misses / baseline.policyDecidable;
baseline.falseAbortRate = baseline.falseAborts / baseline.benign;
baseline.humanAskRate = baseline.humanAsks / baseline.benign;
out.baseline = baseline;
console.log(
  "published headline       miss " + baseline.misses + "/" + baseline.policyDecidable + " = " + pct(baseline.missRate) +
  ", false abort " + baseline.falseAborts + "/" + baseline.benign + " = " + pct(baseline.falseAbortRate) +
  ", correct " + baseline.correct + "/" + baseline.n + " = " + pct(baseline.correctRate),
);

// ============================================================================================
// 1. WHICH GRADED COLUMN READS WHICH INPUT
// ============================================================================================
// Ask the grader what it reads before shuffling anything. A shuffle of a column that no metric
// reads cannot move that metric, and reporting "nothing moved, so nothing leaks" would be an error.
h1("1. what each graded column is a function of");

const DECISIONS = ["commit", "discard", "review"];
const INTENTS = ["attack", "benign"];
const EXPECTEDS = ["commit", "discard", "review"];
const COLUMNS = ["correct", "miss", "falseAbort", "humanAsk"];
const sensitivity = {};
for (const c of COLUMNS) sensitivity[c] = { expected: false, intent: false, decision: false, policyDecidable: false };
const cell = (intent, expected, decision, pd) => grade({ intent, expected }, decision, pd);
for (const intent of INTENTS) for (const decision of DECISIONS) for (const pd of [true, false]) {
  for (const c of COLUMNS) {
    const vals = new Set(EXPECTEDS.map((e) => cell(intent, e, decision, pd)[c]));
    if (vals.size > 1) sensitivity[c].expected = true;
  }
}
for (const expected of EXPECTEDS) for (const decision of DECISIONS) for (const pd of [true, false]) {
  for (const c of COLUMNS) {
    const vals = new Set(INTENTS.map((i) => cell(i, expected, decision, pd)[c]));
    if (vals.size > 1) sensitivity[c].intent = true;
  }
}
for (const expected of EXPECTEDS) for (const intent of INTENTS) for (const pd of [true, false]) {
  for (const c of COLUMNS) {
    const vals = new Set(DECISIONS.map((d) => cell(intent, expected, d, pd)[c]));
    if (vals.size > 1) sensitivity[c].decision = true;
  }
}
for (const expected of EXPECTEDS) for (const intent of INTENTS) for (const decision of DECISIONS) {
  for (const c of COLUMNS) {
    const vals = new Set([true, false].map((pd) => cell(intent, expected, decision, pd)[c]));
    if (vals.size > 1) sensitivity[c].policyDecidable = true;
  }
}
out.sensitivity = sensitivity;
console.log("exhaustive over the grader's 36-cell input space (3 expected x 2 intent x 3 decision x 2 decidable):");
for (const [c, s] of Object.entries(sensitivity)) {
  const reads = Object.entries(s).filter((e) => e[1]).map((e) => e[0]);
  console.log("  " + c.padEnd(11) + " reads: " + (reads.join(", ") || "nothing"));
}

// ============================================================================================
// 2. TEST ONE: LABEL SHUFFLE
// ============================================================================================
h1("2. test one: label shuffle");

// Parallel arrays, so a permutation is one array swap rather than 8190 object copies.
const A_intent = rows.map((r) => r.intent);
const A_expected = rows.map((r) => r.expected);
const A_decision = rows.map((r) => r.decision);
const A_pd = rows.map((r) => r.policyDecidable);
const scen = { intent: "", expected: "" };

function scoreArrays(intents, expecteds) {
  let correct = 0, miss = 0, falseAbort = 0, humanAsk = 0, den = 0, ben = 0;
  for (let i = 0; i < rows.length; i++) {
    scen.intent = intents[i];
    scen.expected = expecteds[i];
    const g = grade(scen, A_decision[i], A_pd[i]);
    if (g.correct) correct++;
    if (g.miss) miss++;
    if (g.falseAbort) falseAbort++;
    if (g.humanAsk) humanAsk++;
    if (intents[i] === "attack" && A_pd[i]) den++;
    if (intents[i] === "benign") ben++;
  }
  return {
    correctRate: correct / rows.length,
    missRate: den ? miss / den : 0,
    falseAbortRate: ben ? falseAbort / ben : 0,
    humanAskRate: ben ? humanAsk / ben : 0,
  };
}

// --- 2a. analytic chance baselines -----------------------------------------------------------
// Under a uniform permutation of `expected`, each row draws its label from the pooled distribution.
// The grader's clauses, read off section 1's table:
//   benign row      -> correct iff decision == commit               (label-independent)
//   attack, commit  -> never correct                                (label-independent)
//   attack, discard -> correct iff label == discard
//   attack, review  -> correct iff label != commit
// so the chance rate is exact arithmetic on the label pool, not a guess and not 50 percent.
const pool = { commit: 0, discard: 0, review: 0 };
for (const r of rows) pool[r.expected]++;
const P = { commit: pool.commit / rows.length, discard: pool.discard / rows.length, review: pool.review / rows.length };
const attackDec = { commit: 0, discard: 0, review: 0 };
for (const r of attacks) attackDec[r.decision]++;
const attackPool = { commit: 0, discard: 0, review: 0 };
for (const r of attacks) attackPool[r.expected]++;
const Pa = { commit: attackPool.commit / attacks.length, discard: attackPool.discard / attacks.length, review: attackPool.review / attacks.length };
const benignCorrect = benign.filter((r) => r.decision === "commit").length;
const chanceGlobal = (benignCorrect + attackDec.discard * P.discard + attackDec.review * (P.discard + P.review)) / rows.length;
const chanceAttackOnly = (benignCorrect + attackDec.discard * Pa.discard + attackDec.review * (Pa.discard + Pa.review)) / rows.length;

h2("2a. chance baselines, computed from the verdict distribution rather than assumed");
console.log("label pool, all 8190 rows        commit " + pool.commit + " (" + pct(P.commit) + "), discard " + pool.discard + " (" + pct(P.discard) + "), review " + pool.review + " (" + pct(P.review) + ")");
console.log("label pool, the 3190 attacks     commit " + attackPool.commit + ", discard " + attackPool.discard + " (" + pct(Pa.discard) + "), review " + attackPool.review + " (" + pct(Pa.review) + ")");
console.log("attack decisions                 commit " + attackDec.commit + ", discard " + attackDec.discard + ", review " + attackDec.review);
console.log("benign rows scored correct with no label read at all: " + benignCorrect);
console.log("ANALYTIC chance for correct, global shuffle        " + pct(chanceGlobal));
console.log("ANALYTIC chance for correct, attacks-only shuffle  " + pct(chanceAttackOnly));
out.chance = { correctGlobalShuffle: chanceGlobal, correctAttackOnlyShuffle: chanceAttackOnly, pool, attackPool, attackDecisions: attackDec, benignCorrectWithoutLabel: benignCorrect };

// --- 2b. empirical shuffles ------------------------------------------------------------------
function runShuffle(which, subsetPredicate, label) {
  const rand = rng(SEED);
  const idx = [];
  for (let i = 0; i < rows.length; i++) if (!subsetPredicate || subsetPredicate(rows[i])) idx.push(i);
  const acc = { correctRate: [], missRate: [], falseAbortRate: [], humanAskRate: [] };
  const baseArr = which === "intent" ? A_intent : A_expected;
  for (let p = 0; p < PERMS; p++) {
    const vals = shuffleInPlace(idx.map((i) => baseArr[i]), rand);
    const permuted = baseArr.slice();
    for (let k = 0; k < idx.length; k++) permuted[idx[k]] = vals[k];
    const s = which === "intent" ? scoreArrays(permuted, A_expected) : scoreArrays(A_intent, permuted);
    for (const k of Object.keys(acc)) acc[k].push(s[k]);
  }
  const summary = {};
  console.log("\n" + label + "  (" + PERMS + " permutations, seed " + SEED + ")");
  for (const k of ["correctRate", "missRate", "falseAbortRate", "humanAskRate"]) {
    const v = acc[k];
    const sorted = v.slice().sort((a, b) => a - b);
    summary[k] = { mean: mean(v), lo: quantile(sorted, 0.025), hi: quantile(sorted, 0.975) };
    const obs = baseline[k];
    const moved = Math.abs(summary[k].mean - obs) > 1e-9 || summary[k].lo !== summary[k].hi ? "MOVED" : "IDENTICAL on every permutation";
    console.log("  " + k.padEnd(15) + " published " + pct(obs).padStart(8) + "   shuffled " + pct(summary[k].mean).padStart(8) +
      " [" + pct(summary[k].lo) + ", " + pct(summary[k].hi) + "]   " + moved);
  }
  return summary;
}
h2("2b. re-grading under permuted labels");
out.shuffleExpectedGlobal = runShuffle("expected", null, "shuffle expected across all 8190 rows");
out.shuffleExpectedAttacks = runShuffle("expected", (r) => r.intent === "attack", "shuffle expected within the 3190 attacks only");
out.shuffleIntent = runShuffle("intent", null, "shuffle intent across all 8190 rows");

// --- 2c. how much of the `correct` column is label-sensitive at all ---------------------------
// Section 1 says `correct` reads the label. Section 2b says shuffling it costs only a point on the
// attacks-only shuffle. Both are true because most of the column is decided before the label is
// consulted, so count the rows where the label can change the answer.
h2("2c. the part of the correct column a label can actually move");
const benignRows = benign.length;
const attackReview = attacks.filter((r) => r.decision === "review").length;
const attackCommit = attacks.filter((r) => r.decision === "commit").length;
const attackDiscard = attacks.filter((r) => r.decision === "discard").length;
const attackDiscardCorrect = attacks.filter((r) => r.decision === "discard" && r.correct).length;
console.log("  benign rows, correct iff decision==commit, label never read     " + benignRows);
console.log("  attack rows the policy committed, never correct, label not read  " + attackCommit);
console.log("  attack rows the policy sent to review, correct under EITHER      " + attackReview);
console.log("    (the grader credits review when the control wanted discard, so no attack label can fail it)");
console.log("  attack rows the policy discarded, correct only if label==discard " + attackDiscard);
console.log("  ---");
console.log("  rows where the label decides the answer   " + attackDiscard + "/" + rows.length + " = " + pct(attackDiscard / rows.length));
console.log("  of those, actually correct                " + attackDiscardCorrect + " = " + pct(attackDiscardCorrect / attackDiscard));
console.log("  of those, correct by chance               " + (attackDiscard * Pa.discard).toFixed(0) + " = " + pct(Pa.discard));
console.log("  the correct column beats chance by        " + (attackDiscardCorrect - attackDiscard * Pa.discard).toFixed(0) + " rows out of " + rows.length);
out.labelSensitive = {
  benignRows, attackCommit, attackReview, attackDiscard, attackDiscardCorrect,
  chanceCorrect: attackDiscard * Pa.discard, edgeInRows: attackDiscardCorrect - attackDiscard * Pa.discard,
};

const commitAmongDecidable = rows.filter((r) => r.policyDecidable && r.decision === "commit").length;
const nDecidableRows = rows.filter((r) => r.policyDecidable).length;
const discardAll = rows.filter((r) => r.decision === "discard").length;
console.log("\nANALYTIC chance under an intent shuffle:");
console.log("  miss rate   -> P(decision=commit | policyDecidable) = " + commitAmongDecidable + "/" + nDecidableRows + " = " + pct(commitAmongDecidable / nDecidableRows));
console.log("  false abort -> P(decision=discard)                  = " + discardAll + "/" + rows.length + " = " + pct(discardAll / rows.length));
out.intentChance = { missRate: commitAmongDecidable / nDecidableRows, falseAbortRate: discardAll / rows.length };

// ============================================================================================
// 3. TEST TWO: PREDICTING THE LABEL FROM METADATA THE POLICY NEVER RECEIVES
// ============================================================================================
h1("3. test two: infrastructural artifact");

// What the policy receives, per replay-v2.mjs toEffects() and buildContext(): the effect records
// (path, kind, mode, target, escapes, bytes, method, host, port, urlPath, provenance,
// secretPattern, highEntropy, effectClass, canonicalPath), the file bytes behind them, and a fixed
// context. It never receives id, family, source, file, expected, severity, likelihood, layer,
// origin, or position in the generation batch.
const POLICY_NEVER_SEES = new Set(["file", "source", "family", "idStem", "batchDecile", "idOrdinalDecile", "hasOriginKey", "descLengthDecile"]);

const feat = rows.map((r) => {
  const s = scenarioById.get(r.id);
  const contentBytes = s.effect_set.reduce((a, e) => a + (e.content ? Buffer.byteLength(e.content) : 0), 0);
  const realBytes = s.effect_set.reduce((a, e) => a + (e.real_content ? Buffer.byteLength(e.real_content) : 0), 0);
  const m = /(\d+)\s*$/.exec(r.id);
  return {
    row: r,
    file: s._file,
    source: r.source,
    family: r.family,
    idStem: r.id.replace(/\d+\s*$/, ""),
    batchIndex: s._indexInFile,
    idOrdinal: m ? Number(m[1]) : -1,
    hasOriginKey: "origin" in s ? "origin" : ("provenance" in s ? "provenance" : "neither"),
    effectCount: s.effect_set.length,
    contentBytes,
    realBytes,
    totalBytes: contentBytes + realBytes,
    descLength: (s.description || "").length,
  };
});

/** Decile bucket over the whole corpus, which turns a numeric feature into a 1R feature. */
function decileBucketer(values) {
  const sorted = values.slice().sort((a, b) => a - b);
  const cuts = [];
  for (let q = 1; q < 10; q++) cuts.push(sorted[Math.floor((q / 10) * (sorted.length - 1))]);
  return (v) => {
    let b = 0;
    while (b < cuts.length && v > cuts[b]) b++;
    return "d" + b;
  };
}
const buck = {
  batch: decileBucketer(feat.map((f) => f.batchIndex)),
  idOrd: decileBucketer(feat.map((f) => f.idOrdinal)),
  effects: decileBucketer(feat.map((f) => f.effectCount)),
  content: decileBucketer(feat.map((f) => f.contentBytes)),
  total: decileBucketer(feat.map((f) => f.totalBytes)),
  desc: decileBucketer(feat.map((f) => f.descLength)),
};
const FEATURES = {
  file: (f) => f.file,
  source: (f) => f.source,
  family: (f) => f.family,
  idStem: (f) => f.idStem,
  hasOriginKey: (f) => f.hasOriginKey,
  batchDecile: (f) => buck.batch(f.batchIndex),
  idOrdinalDecile: (f) => buck.idOrd(f.idOrdinal),
  descLengthDecile: (f) => buck.desc(f.descLength),
  effectCountBucket: (f) => buck.effects(f.effectCount),
  contentBytesDecile: (f) => buck.content(f.contentBytes),
  totalBytesDecile: (f) => buck.total(f.totalBytes),
  "family+contentBytes": (f) => f.family + "|" + buck.content(f.contentBytes),
};
const TARGETS = {
  expected: (f) => f.row.expected,
  intent: (f) => f.row.intent,
  decision: (f) => f.row.decision,
};

/** Holte's 1R: per feature value predict the training majority; unseen values fall back to the
 *  training majority overall. The simplest classifier that exists. */
function fit1R(train, featFn, targetFn) {
  const tally = new Map();
  const global = new Map();
  for (const f of train) {
    const k = featFn(f);
    const y = targetFn(f);
    if (!tally.has(k)) tally.set(k, new Map());
    const t = tally.get(k);
    t.set(y, (t.get(y) || 0) + 1);
    global.set(y, (global.get(y) || 0) + 1);
  }
  const argmax = (m) => [...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))[0][0];
  const table = new Map([...tally.entries()].map((e) => [e[0], argmax(e[1])]));
  const fallback = argmax(global);
  return (f) => (table.has(featFn(f)) ? table.get(featFn(f)) : fallback);
}
const accuracy = (list, model, targetFn) => list.filter((f) => model(f) === targetFn(f)).length / list.length;

function makeFolds(list, k, rand, groupFn) {
  if (!groupFn) {
    const order = shuffleInPlace(list.map((_, i) => i), rand);
    const parts = Array.from({ length: k }, () => []);
    order.forEach((idx, j) => parts[j % k].push(list[idx]));
    return parts;
  }
  const groups = shuffleInPlace([...new Set(list.map(groupFn))], rand);
  const assign = new Map(groups.map((g, i) => [g, i % k]));
  const parts = Array.from({ length: k }, () => []);
  for (const f of list) parts[assign.get(groupFn(f))].push(f);
  return parts;
}
function crossVal(list, featFn, targetFn, k, rand, groupFn) {
  const parts = makeFolds(list, k, rand, groupFn);
  let correct = 0, total = 0;
  for (let i = 0; i < k; i++) {
    const test = parts[i];
    const train = parts.filter((_, j) => j !== i).flat();
    if (!test.length || !train.length) continue;
    const model = fit1R(train, featFn, targetFn);
    correct += test.filter((f) => model(f) === targetFn(f)).length;
    total += test.length;
  }
  return correct / total;
}

out.oneR = {};
for (const [tname, tfn] of Object.entries(TARGETS)) {
  const counts = new Map();
  for (const f of feat) counts.set(tfn(f), (counts.get(tfn(f)) || 0) + 1);
  const majority = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
  const chance = majority[1] / feat.length;
  h2("target: " + tname + "   chance = always say \"" + majority[0] + "\" = " + majority[1] + "/" + feat.length + " = " + pct(chance));
  console.log("  " + "feature".padEnd(22) + " " + "policy reads it".padEnd(17) + " " + "in-sample".padStart(10) + " " + "5-fold CV".padStart(10) + " " + "family-held-out".padStart(16));
  const table = { chance, majorityClass: majority[0], features: {} };
  for (const [fname, ffn] of Object.entries(FEATURES)) {
    const inSample = accuracy(feat, fit1R(feat, ffn, tfn), tfn);
    const cv = crossVal(feat, ffn, tfn, 5, rng(SEED), null);
    const gcv = crossVal(feat, ffn, tfn, 5, rng(SEED), (f) => f.family);
    const seen = POLICY_NEVER_SEES.has(fname) ? "never" : "via bytes";
    console.log("  " + fname.padEnd(22) + " " + seen.padEnd(17) + " " + pct(inSample).padStart(10) + " " + pct(cv).padStart(10) + " " + pct(gcv).padStart(16));
    table.features[fname] = { inSample, cv, groupedCv: gcv, policyNeverSees: POLICY_NEVER_SEES.has(fname) };
  }
  out.oneR[tname] = table;
}

// The mechanical reason family predicts expected: lib/expected-verdict.mjs computes expected as a
// function of family for every family with no content clause. Count them.
h2("3b. why family predicts expected: how many families carry more than one label at all");
const famLabels = new Map();
for (const r of rows) {
  if (!famLabels.has(r.family)) famLabels.set(r.family, new Map());
  const m = famLabels.get(r.family);
  m.set(r.expected, (m.get(r.expected) || 0) + 1);
}
let pureRows = 0, pureFams = 0;
const mixed = [];
for (const [fam, m] of famLabels) {
  const n = [...m.values()].reduce((a, b) => a + b, 0);
  if (m.size === 1) { pureRows += n; pureFams++; } else mixed.push({ family: fam, n, labels: Object.fromEntries(m) });
}
console.log("  families                      " + famLabels.size);
console.log("  families carrying ONE label   " + pureFams + "  (" + pureRows + " rows, " + pct(pureRows / rows.length) + " of the corpus)");
console.log("  families carrying more        " + mixed.length);
for (const m of mixed.sort((a, b) => b.n - a.n)) console.log("      " + m.family.padEnd(28) + " n=" + String(m.n).padStart(5) + "  " + JSON.stringify(m.labels));
out.familyPurity = { families: famLabels.size, singleLabelFamilies: pureFams, singleLabelRows: pureRows, mixed };

// ============================================================================================
// 4. HOW SEPARABLE ATTACK FROM BENIGN IS WITHOUT READING FOR HARM
// ============================================================================================
h1("4. attack against benign, on size alone");
const sized = feat.map((f) => ({ y: f.row.intent, x: f.totalBytes })).sort((a, b) => a.x - b.x);
const nAtt = attacks.length;
const nBen = benign.length;
let attLE = 0, benLE = 0, best = { acc: 0, cut: 0, dir: "" };
for (let i = 0; i < sized.length; i++) {
  if (sized[i].y === "attack") attLE++; else benLE++;
  if (i + 1 < sized.length && sized[i + 1].x === sized[i].x) continue;
  const accLowAttack = (attLE + (nBen - benLE)) / sized.length;
  const accLowBenign = (benLE + (nAtt - attLE)) / sized.length;
  if (accLowAttack > best.acc) best = { acc: accLowAttack, cut: sized[i].x, dir: "bytes <= cut means attack" };
  if (accLowBenign > best.acc) best = { acc: accLowBenign, cut: sized[i].x, dir: "bytes <= cut means benign" };
}
const attackBytes = feat.filter((f) => f.row.intent === "attack").map((f) => f.totalBytes).sort((a, b) => a - b);
const benignBytes = feat.filter((f) => f.row.intent === "benign").map((f) => f.totalBytes).sort((a, b) => a - b);
console.log("  attack total bytes   median " + quantile(attackBytes, 0.5) + "   p10 " + quantile(attackBytes, 0.1) + "   p90 " + quantile(attackBytes, 0.9));
console.log("  benign total bytes   median " + quantile(benignBytes, 0.5) + "   p10 " + quantile(benignBytes, 0.1) + "   p90 " + quantile(benignBytes, 0.9));
console.log("  best single byte-count threshold: " + pct(best.acc) + " (" + best.dir + " " + best.cut + "), chance " + pct(nBen / rows.length));
out.sizeSeparability = { bestAccuracy: best.acc, cut: best.cut, direction: best.dir, chance: nBen / rows.length, attackMedian: quantile(attackBytes, 0.5), benignMedian: quantile(benignBytes, 0.5) };

// ============================================================================================
// 5. THE ONE CHANNEL THAT ACTUALLY CARRIES THE LABEL INTO THE POLICY
// ============================================================================================
// replay-v2.mjs buildContext():
//     taskPrompt: scenario.intent === "benign" ? scenario.description : undefined
// The PRESENCE of ctx.taskPrompt IS the intent label, handed to the policy on every row. Grep says
// no shipped rule reads it. Grep is not a measurement. Re-run the policy with the field removed and
// compare all 8190 decisions.
h1("5. ablation: delete the context field whose presence encodes the label, re-run, compare");
if (has("--no-ablation")) {
  console.log("  skipped (--no-ablation)");
} else {
  const shippedMod = await import(pathToFileURL(path.join(CORPUS, "lib", "shipped-policy.mjs")).href);
  const manifest = JSON.parse(fs.readFileSync(path.join(CORPUS, "results", "run-manifest.json"), "utf8"));
  const digest = shippedMod.policyDigest(shippedMod.DIST);
  const sameBuild = digest.digest === manifest.policy_sha256;
  console.log("  policy digest now      " + digest.digest + " (" + digest.files.length + " modules)");
  console.log("  digest in run-manifest " + manifest.policy_sha256);
  console.log("  same build as results.jsonl? " + (sameBuild ? "yes" : "NO, apps/server/dist has been rebuilt since the corpus run"));
  const shipped = await shippedMod.composeFrom(shippedMod.DIST);
  console.log("  composed as            " + shipped.composition);

  const MAX_SCAN_BYTES = 1024 * 1024;
  const PLATFORM_SECRET_FIXTURE = "sk-PLATFORMFIXTURE0000000000000000000000000000"; // scrub-allow: fixture, synthetic by construction
  const HARNESS_AGENT_ID = "corpus-harness-agent-fixture";
  // Imported from the same dist whose digest was just printed, the way replay-v2.mjs gets them,
  // so the "published" variant below keeps tracking the harness's real context instead of a copy
  // of it. This block carried a seven-host allowlist and a three-pattern protected list while
  // production shipped ten and seven; research/corpus/check-constants.mjs fails the build on that.
  const { DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } = await import(
    pathToFileURL(path.join(shippedMod.DIST, "policy-context.js")).href,
  );
  const fold = (p) => p.normalize("NFC").toLowerCase();
  // Lifted from replay-v2.mjs rather than retyped, so only the taskPrompt line differs.
  const addedLines = liftFunction(REPLAY, "addedLines");
  const writeTree = liftFunction(REPLAY, "writeTree", { fs, path });
  const boundedRead = liftFunction(REPLAY, "boundedRead", { fs, path, Buffer, MAX_SCAN_BYTES });
  const toEffects = liftFunction(REPLAY, "toEffects", { fold });

  // One pass per context variant. "published" is the harness's own context, byte for byte; every
  // other variant changes exactly one field, so the count of moved decisions is that field's
  // influence on the published numbers.
  const VARIANTS = {
    published: (ctx) => ctx,
    "taskPrompt removed": (ctx) => ({ ...ctx, taskPrompt: undefined }),
    "agentId removed": (ctx) => ({ ...ctx, agentId: undefined }),
    "protectedPaths emptied": (ctx) => ({ ...ctx, protectedPaths: [] }),
    "caseInsensitiveHost off": (ctx) => ({ ...ctx, caseInsensitiveHost: false }),
    "platformSecrets emptied": (ctx) => ({ ...ctx, platformSecrets: [] }),
    "registryAllowlist emptied": (ctx) => ({ ...ctx, registryAllowlist: [] }),
  };

  const runPass = async (variant, limit) => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "leakage-"));
    const decisions = new Map();
    let i = 0;
    for (const r of rows) {
      if (limit && i >= limit) break;
      const scenario = scenarioById.get(r.id);
      const scRoot = path.join(tmpRoot, scenario.id.replace(/[^\w.-]/g, "_"));
      const shadowDir = path.join(scRoot, "shadow");
      const realDir = path.join(scRoot, "real");
      const shadowBytes = new Map();
      const realBytes = new Map();
      for (const e of scenario.effect_set) {
        if (e.real_content != null) realBytes.set(e.path, e.real_content);
        if ((e.kind === "create" || e.kind === "modify") && typeof e.content === "string") shadowBytes.set(e.path, e.content);
      }
      writeTree(shadowDir, shadowBytes);
      writeTree(realDir, realBytes);
      const ctx = VARIANTS[variant]({
        contentOf: async (p) => boundedRead(shadowDir, p),
        addedLinesOf: async (p) => addedLines(boundedRead(shadowDir, p), realBytes.has(p) ? boundedRead(realDir, p) : null),
        realContentOf: async (p) => (realBytes.has(p) ? boundedRead(realDir, p) : null),
        agentId: HARNESS_AGENT_ID,
        recentTouches: [],
        // The field whose PRESENCE is the intent label.
        taskPrompt: scenario.intent === "benign" ? scenario.description : undefined,
        protectedPaths: DEFAULT_PROTECTED_PATHS,
        protectedInodes: new Set(),
        caseInsensitiveHost: true,
        platformSecrets: [PLATFORM_SECRET_FIXTURE],
        registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST,
      });
      let verdict;
      try {
        verdict = await shipped.policy(toEffects(scenario), ctx);
      } catch (err) {
        verdict = { decision: "ERROR", rule: String(err && err.message ? err.message : err) };
      }
      decisions.set(scenario.id, verdict.decision);
      fs.rmSync(scRoot, { recursive: true, force: true });
      i++;
      if (i % 2000 === 0 && process.stderr.isTTY) process.stderr.write("\r    " + variant + ": " + i + "   ");
    }
    fs.rmSync(tmpRoot, { recursive: true, force: true });
    if (process.stderr.isTTY) process.stderr.write("\r                                        \r");
    return decisions;
  };

  const recorded = new Map(rows.map((r) => [r.id, r.decision]));
  const t0 = Date.now();
  const passPublished = await runPass("published", LIMIT);
  const disagree = [...passPublished.entries()].filter((e) => e[1] !== recorded.get(e[0]));
  console.log("  published context reproduces results.jsonl: " + passPublished.size + " scenarios, " + disagree.length + " decisions differ");
  // Two ways this can disagree, and only one of them is this file's fault. If the build has not
  // moved, a disagreement means the context builder here is not the harness's and the sweep below
  // would be measuring the wrong thing: stop. If the build HAS moved, the disagreement is the
  // policy changing under the published numbers, which is a finding rather than a defect, and the
  // sweep is still a clean ablation of the policy currently on disk.
  if (disagree.length && sameBuild) {
    console.error("  FAIL: same build, different decisions, so this file's context builder is not the harness's.");
    console.error("  First: " + disagree[0][0] + " got " + disagree[0][1] + " want " + recorded.get(disagree[0][0]));
    process.exit(1);
  }
  if (disagree.length) {
    console.log("  (the build moved after the corpus run, so these are the policy changing, not a harness defect)");
  }

  console.log("\n  one pass per context field, each changing exactly one line:");
  console.log("  " + "context variant".padEnd(28) + " " + "decisions moved".padStart(16) + " " + "of".padStart(6) + "   what it means");
  const sweep = {};
  for (const variant of Object.keys(VARIANTS)) {
    if (variant === "published") continue;
    const pass = await runPass(variant, LIMIT);
    const moved = [...pass.entries()].filter((e) => e[1] !== passPublished.get(e[0]));
    sweep[variant] = { moved: moved.length, of: pass.size, examples: moved.slice(0, 5) };
    const note = variant === "taskPrompt removed"
      ? (moved.length === 0 ? "the label channel is unread" : "THE LABEL CHANNEL IS READ")
      : (moved.length === 0 ? "inert on this corpus" : "load-bearing");
    console.log("  " + variant.padEnd(28) + " " + String(moved.length).padStart(16) + " " + String(pass.size).padStart(6) + "   " + note);
  }
  console.log("  wall clock: " + ((Date.now() - t0) / 1000).toFixed(1) + "s for " + Object.keys(VARIANTS).length + " passes");
  if (LIMIT) console.log("  NOTE: --limit " + LIMIT + " was set, so this is a smoke test and not the proof");
  const anyMoved = Object.values(sweep).some((s) => s.moved > 0);
  out.contextSweep = {
    scenarios: passPublished.size, limited: Boolean(LIMIT), digestUnderTest: digest.digest,
    sameBuildAsResults: sameBuild, disagreementsWithResultsJsonl: disagree.length, variants: sweep,
  };
  console.log("\n  " + (sweep["taskPrompt removed"].moved === 0
    ? "VERDICT: the label-carrying context field is present in the harness and unread by the policy."
    : "VERDICT: the label-carrying field moves " + sweep["taskPrompt removed"].moved + " decisions; the headline is contaminated."));
  console.log("  " + (anyMoved
    ? "  The zero is informative: at least one other field in the same sweep does move decisions,"
    : "  CAUTION: no field in the sweep moved a decision, so this test cannot distinguish"));
  console.log("  " + (anyMoved
    ? "  so the sweep is capable of detecting a read field and did not detect one here."
    : "  an unread field from a test that cannot detect a read one. Treat the zero as weak."));
}

// ============================================================================================
// 6. WHAT THE CORPUS'S CLUSTERING DOES TO THE CONFIDENCE INTERVAL
// ============================================================================================
h1("6. effective sample size: 3161 graded rows, how many independent observations?");
const byFamily = new Map();
for (const r of decidable) {
  if (!byFamily.has(r.family)) byFamily.set(r.family, []);
  byFamily.get(r.family).push(r);
}
const fams = [...byFamily.entries()]
  .map((e) => ({ family: e[0], n: e[1].length, misses: e[1].filter((r) => r.miss).length }))
  .sort((a, b) => b.n - a.n);
console.log("  " + "family".padEnd(34) + " " + "n".padStart(5) + " " + "misses".padStart(7) + " " + "rate".padStart(8));
for (const f of fams) console.log("  " + f.family.padEnd(34) + " " + String(f.n).padStart(5) + " " + String(f.misses).padStart(7) + " " + pct(f.misses / f.n).padStart(8));

const p = baseline.missRate;
const k = fams.length;
const randB = rng(SEED);
const boots = [];
for (let b = 0; b < BOOTS; b++) {
  let num = 0, den = 0;
  for (let i = 0; i < k; i++) {
    const f = fams[Math.floor(randB() * k)];
    num += f.misses;
    den += f.n;
  }
  boots.push(num / den);
}
boots.sort((a, b) => a - b);
const seCluster = Math.sqrt(mean(boots.map((x) => (x - mean(boots)) ** 2)));
const seBinomial = Math.sqrt((p * (1 - p)) / decidable.length);
const deff = (seCluster / seBinomial) ** 2;
const macro = mean(fams.map((f) => f.misses / f.n));
console.log("\n  families (the unit the generator actually varied)  " + k);
console.log("  mean rows per family                              " + (decidable.length / k).toFixed(1));
console.log("  largest family                                    " + fams[0].family + " at " + fams[0].n + " rows, " + pct(fams[0].n / decidable.length) + " of the denominator");
console.log("  pooled (micro) miss rate                          " + pct(p));
console.log("  macro-average, every family counted once          " + pct(macro));
console.log("\n  binomial standard error on n=" + decidable.length + "                " + pct(seBinomial));
console.log("  cluster-bootstrap standard error (families)       " + pct(seCluster));
console.log("  design effect                                     " + deff.toFixed(1) + "x");
console.log("  effective independent observations                " + (decidable.length / deff).toFixed(0) + " (nominal " + decidable.length + ")");
// READ, not typed. This line used to carry the literal "[4.5%, 6.1%]" with "(report-metrics.json)"
// printed beside it, so it kept asserting the interval for 165 misses long after the corpus moved
// to 149, and it said where it came from while coming from nowhere. A number labelled with its
// source has to actually have that source, or the label is worse than no label at all.
const publishedWilson = JSON.parse(
  fs.readFileSync(path.join(CORPUS, "results", "report-metrics.json"), "utf8"),
).headline.attack_miss_wilson;
console.log("\n  published Wilson 95% on n=" + decidable.length + "                   [" + publishedWilson[0] + "%, " + publishedWilson[1] + "%]   (report-metrics.json)");
console.log("  cluster bootstrap 95% (" + BOOTS + " family resamples)   [" + pct(quantile(boots, 0.025)) + ", " + pct(quantile(boots, 0.975)) + "]");
out.clustering = {
  families: k, meanClusterSize: decidable.length / k, largest: fams[0], micro: p, macro,
  seBinomial, seCluster, deff, effectiveN: decidable.length / deff,
  clusterBootCi: [quantile(boots, 0.025), quantile(boots, 0.975)], perFamily: fams,
};

h2("6b. leave-one-family-out: could the other families have predicted this one?");
const lofo = fams.map((f) => {
  const others = fams.filter((g) => g.family !== f.family);
  const pred = others.reduce((a, g) => a + g.misses, 0) / others.reduce((a, g) => a + g.n, 0);
  return { family: f.family, n: f.n, actual: f.misses / f.n, predicted: pred, absErr: Math.abs(f.misses / f.n - pred) };
}).sort((a, b) => b.absErr - a.absErr);
console.log("  " + "family".padEnd(34) + " " + "n".padStart(5) + " " + "actual".padStart(8) + " " + "predicted".padStart(10) + " " + "abs err".padStart(9));
for (const l of lofo) console.log("  " + l.family.padEnd(34) + " " + String(l.n).padStart(5) + " " + pct(l.actual).padStart(8) + " " + pct(l.predicted).padStart(10) + " " + pct(l.absErr).padStart(9));
console.log("  mean absolute error " + pct(mean(lofo.map((l) => l.absErr))) + ", worst " + pct(lofo[0].absErr) + " on " + lofo[0].family);
out.lofo = lofo;

// The denominator's family mix is not a threat model, it is a record of how many variants each
// generator managed to produce. Four generators fell short of what they asked for, and three of the
// four are among the families the policy is worst on, which pulls the pooled rate down. Price it.
h2("6c. the generator's own shortfall, and which way it biases the pooled rate");
const genManifest = JSON.parse(fs.readFileSync(path.join(CORPUS, "scenarios", "generated.manifest.json"), "utf8"));
const rateOf = new Map(fams.map((f) => [f.family, f.misses / f.n]));
let addN = 0, addMiss = 0;
console.log("  " + "generator".padEnd(24) + " " + "asked".padStart(6) + " " + "made".padStart(6) + " " + "short".padStart(6) + " " + "family miss rate".padStart(17));
for (const g of genManifest.generators) {
  const short = g.requested - g.produced;
  if (short <= 0) continue;
  const fam = Object.keys(g.families)[0];
  const rate = rateOf.get(fam) ?? 0;
  addN += short;
  addMiss += short * rate;
  console.log("  " + g.generator.padEnd(24) + " " + String(g.requested).padStart(6) + " " + String(g.produced).padStart(6) + " " + String(short).padStart(6) + " " + pct(rate).padStart(17));
}
const adjusted = (baseline.misses + addMiss) / (decidable.length + addN);
console.log("  per-generator requested total " + genManifest.generators.reduce((a, g) => a + g.requested, 0) + ", produced " + genManifest.total_produced + ", manifest total_requested field " + genManifest.total_requested);
console.log("  had the short generators hit their targets at their own measured rates:");
console.log("    pooled miss rate " + pct(baseline.missRate) + " -> " + pct(adjusted) + "  (" + ((adjusted - baseline.missRate) * 100).toFixed(2) + " points)");
out.shortfall = { addedRows: addN, addedMisses: addMiss, adjustedMissRate: adjusted, published: baseline.missRate };

// ============================================================================================
// 7. THE ROWS NOBODY HERE GENERATED, AND HOW MANY DISTINCT BODIES THERE REALLY ARE
// ============================================================================================
h1("7. generated rows against hand-written rows");
const bySource = {};
for (const pair of [["hand-written (redteam r1 + r2)", (r) => r.source !== "generated"], ["generated", (r) => r.source === "generated"]]) {
  const set = decidable.filter(pair[1]);
  const m = set.filter((r) => r.miss).length;
  const w = wilsonPct(m, set.length);
  console.log("  " + pair[0].padEnd(32) + " n=" + String(set.length).padStart(5) + "  misses " + String(m).padStart(4) +
    "  rate " + pct(set.length ? m / set.length : 0).padStart(7) + "  95% Wilson [" + w.low + "%, " + w.high + "%]");
  bySource[pair[0]] = { n: set.length, misses: m, rate: set.length ? m / set.length : 0, wilson: [w.low, w.high] };
}
// Is that gap bigger than reshuffling the same 3161 rows would produce? No distributional
// assumption: relabel which rows are the hand-written ones and count how often the gap is matched.
{
  const nHand = bySource["hand-written (redteam r1 + r2)"].n;
  const observed = bySource["hand-written (redteam r1 + r2)"].rate - bySource["generated"].rate;
  const flags = decidable.map((r) => (r.miss ? 1 : 0));
  const randP = rng(SEED);
  let atLeast = 0;
  const total = decidable.length;
  const totalMiss = flags.reduce((a, b) => a + b, 0);
  for (let t = 0; t < 20000; t++) {
    const idx = shuffleInPlace(flags.slice(), randP);
    let handMiss = 0;
    for (let i = 0; i < nHand; i++) handMiss += idx[i];
    const diff = handMiss / nHand - (totalMiss - handMiss) / (total - nHand);
    if (diff >= observed) atLeast++;
  }
  console.log("  permutation test, 20000 relabellings of which " + nHand + " rows are hand-written:");
  console.log("    observed gap " + pct(observed) + ", reached or beaten in " + atLeast + "/20000 = p = " + (atLeast / 20000).toFixed(4));
  bySource.permutationTest = { nHand, observedGap: observed, p: atLeast / 20000, resamples: 20000 };
}
const benignSplit = new Map();
for (const r of benign) {
  const key = scenarioById.get(r.id).provenance ? "from a real repository" : "synthetic";
  if (!benignSplit.has(key)) benignSplit.set(key, []);
  benignSplit.get(key).push(r);
}
for (const [key, set] of benignSplit) {
  const fa = set.filter((r) => r.falseAbort).length;
  console.log("  benign, " + key.padEnd(24) + " n=" + String(set.length).padStart(5) + "  false aborts " + String(fa).padStart(4) + "  rate " + pct(fa / set.length));
  bySource["benign " + key] = { n: set.length, falseAborts: fa, rate: fa / set.length };
}
out.bySource = bySource;

const sig = new Set();
const bodies = new Set();
for (const r of rows) {
  const s = scenarioById.get(r.id);
  sig.add(r.family + "|" + s.effect_set.map((e) => e.kind + ":" + path.posix.basename(e.path).replace(/\d+/g, "#")).sort().join(","));
  bodies.add(createHash("sha256").update(s.effect_set.map((e) => e.content ?? "").join("\u0000")).digest("hex"));
}
const attackSig = new Set();
const attackBodies = new Set();
for (const r of attacks) {
  const s = scenarioById.get(r.id);
  attackSig.add(r.family + "|" + s.effect_set.map((e) => e.kind + ":" + path.posix.basename(e.path).replace(/\d+/g, "#")).sort().join(","));
  attackBodies.add(createHash("sha256").update(s.effect_set.map((e) => e.content ?? "").join("\u0000")).digest("hex"));
}
console.log("\n  distinct (family, effect-shape) signatures, all rows   " + sig.size + " behind " + rows.length + " rows");
console.log("  distinct added-content bodies, all rows                " + bodies.size);
console.log("  distinct (family, effect-shape) signatures, attacks    " + attackSig.size + " behind " + attacks.length + " attack rows");
console.log("  distinct added-content bodies, attacks                 " + attackBodies.size);
out.distinctness = { rows: rows.length, signatures: sig.size, bodies: bodies.size, attackRows: attacks.length, attackSignatures: attackSig.size, attackBodies: attackBodies.size };

if (JSON_OUT) {
  fs.writeFileSync(path.resolve(JSON_OUT), JSON.stringify(out, null, 2) + "\n");
  console.log("\nwrote " + path.resolve(JSON_OUT));
}

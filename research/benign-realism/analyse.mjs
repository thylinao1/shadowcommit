// analyse.mjs -- the four questions, each as a number.
//
//   node research/benign-realism/analyse.mjs
//
// Reads three things and writes nothing outside research/benign-realism:
//   research/corpus/scenarios/benign.jsonl      the 5,000 benign scenarios (read only)
//   research/corpus/results/results.jsonl       the published run (read only)
//   out/heldout-real.jsonl + out/heldout-results.jsonl   this lane's held-out set and its replay
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import readline from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(here, "..", "corpus");
const KIT = path.resolve(here, "..", "..");
const OUT = path.join(here, "out");

/**
 * The product's own added-lines function, loaded from the SAME dist the replay graded.
 *
 * This file used to define a local twelve line prefix/suffix trim and describe it in a comment as
 * "the same prefix/suffix trim the product's addedLinesBetween performs". It is not the same, and
 * research/corpus/replay-v2.mjs already carries the note saying so: the corpus harness shipped that
 * exact stand-in, every published corpus figure was once produced against a copy rather than
 * against the shipped code, and the two functions disagree on 1,414 of 10,240 byte pairs.
 * Reintroducing it here reintroduced the same defect in the same repository.
 *
 * Measured on this lane's data, before and after this change: the stand-in and the product agree on
 * all 5,000 corpus rows and disagree on 706 of the 1,431 real rows, of which 481 land in a different
 * added-lines bucket. Every real-side size number this file printed before was the stand-in's.
 *
 * It fails closed. A dist without the export stops the run rather than falling back to a local
 * copy, because a silent fallback is how the corpus harness diverged in the first place.
 */
const CONTEXT_PATH = path.join(KIT, "apps", "server", "dist", "policy-context.js");
const { addedLinesBetween } = await import(pathToFileURL(CONTEXT_PATH).href).catch(() => ({}));
if (typeof addedLinesBetween !== "function") {
  console.error(
    `${CONTEXT_PATH} exports no addedLinesBetween function.\n` +
      `build the kit first:  npm run build -w @launchpad/server`,
  );
  process.exit(1);
}

/** Added lines of one effect, by the product's function. (before, after), as policy-context takes it. */
function addedLinesCount(real, shadow) {
  if (shadow == null) return 0;
  const s = addedLinesBetween(real ?? null, shadow);
  return s.length === 0 ? 0 : s.split("\n").length;
}

const readJsonl = (f) => fs.readFileSync(f, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

function wilson(k, n, z = 1.959963985) {
  const p = k / n, d = 1 + (z * z) / n, c = p + (z * z) / (2 * n);
  const m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [(100 * (c - m)) / d, (100 * (c + m)) / d];
}
const pct = (x) => `${x.toFixed(2)}%`;
const ci = (k, n) => { const [a, b] = wilson(k, n); return `[${a.toFixed(2)}, ${b.toFixed(2)}]`; };

/** Stream a scenario file into {id, sig, sigBlind, shape, repo, files, added, deletes} rows. */
async function scenarioRows(file) {
  const rows = [];
  const rl = readline.createInterface({ input: fs.createReadStream(file) });
  for await (const line of rl) {
    if (!line.trim()) continue;
    const s = JSON.parse(line);
    const id = s.id;
    const norm = JSON.stringify(s.effect_set.map((e) => ({
      p: String(e.path).split(id).join("<ID>"),
      k: e.kind,
      c: e.content === undefined ? null : String(e.content).split(id).join("<ID>"),
      r: e.real_content === undefined ? null : String(e.real_content).split(id).join("<ID>"),
    })));
    let added = 0, deletes = 0;
    for (const e of s.effect_set) {
      if (e.kind === "delete") { deletes++; continue; }
      added += addedLinesCount(e.real_content ?? null, e.content ?? null);
    }
    const repo = s.provenance?.repo ?? "?";
    const sha1 = (x) => crypto.createHash("sha1").update(x).digest("hex");
    rows.push({
      id,
      // Two keys, because they answer different questions and the difference is a finding. `sig`
      // puts the repository label inside the cluster key, so an effect set whose bytes do not
      // depend on the repository counts once per repository. `sigBlind` leaves it out, so the same
      // effect set generated against four repositories counts once, which is what it is.
      sig: sha1(repo + "|" + s.family + "|" + norm),
      sigBlind: sha1(s.family + "|" + norm),
      cell: s.family + "|" + repo,
      shape: s.family,
      repo,
      files: s.effect_set.length,
      added,
      deletes,
    });
  }
  return rows;
}

function join(rows, results) {
  const m = new Map(results.map((r) => [r.id, r]));
  return rows.map((r) => ({ ...r, decision: m.get(r.id).decision, rule: m.get(r.id).rule }));
}

function rates(label, rows) {
  const n = rows.length;
  const h = rows.filter((r) => r.decision === "review").length;
  const a = rows.filter((r) => r.decision === "discard").length;
  return { label, n, hold: h, abort: a, holdPct: (100 * h) / n, abortPct: (100 * a) / n, holdCi: ci(h, n), abortCi: ci(a, n) };
}

// ---- 1. effective diversity -------------------------------------------------------------------
function clustersBy(rows, keyFn) {
  const cl = new Map();
  for (const r of rows) {
    const k = keyFn(r);
    if (!cl.has(k)) cl.set(k, { n: 0, h: 0, a: 0, shape: r.shape, repo: r.repo });
    const c = cl.get(k);
    c.n++; if (r.decision === "review") c.h++; if (r.decision === "discard") c.a++;
  }
  return cl;
}

const rng = (seed) => { let s = seed >>> 0; return () => { s ^= s << 13; s >>>= 0; s ^= s >> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; }; };

/** Resample whole clusters with replacement: "what if a different set of scenarios had been drawn". */
function clusterBootstrap(clusters, pick, seed, B = 20000) {
  const arr = [...clusters.values()];
  const rnd = rng(seed);
  const est = [];
  for (let b = 0; b < B; b++) {
    let sn = 0, sk = 0;
    for (let i = 0; i < arr.length; i++) { const c = arr[Math.floor(rnd() * arr.length)]; sn += c.n; sk += pick(c); }
    est.push(sk / sn);
  }
  est.sort((x, y) => x - y);
  return [100 * est[Math.floor(0.025 * B)], 100 * est[Math.floor(0.975 * B)], est];
}

/** Resample rows WITHIN each template cell, cell sizes held fixed: "what if the generator had run
 *  on a different seed". The cells and their sizes are not random in this corpus, they are the
 *  generator's plan, so this is the model that matches how the corpus is actually produced. */
function stratifiedBootstrap(rows, cellKeyFn, pick, seed, B = 20000) {
  const cells = new Map();
  for (const r of rows) {
    const k = cellKeyFn(r);
    if (!cells.has(k)) cells.set(k, []);
    cells.get(k).push(pick(r) ? 1 : 0);
  }
  const arr = [...cells.values()];
  const rnd = rng(seed);
  const n = rows.length;
  const est = [];
  for (let b = 0; b < B; b++) {
    let sk = 0;
    for (const cell of arr) for (let i = 0; i < cell.length; i++) sk += cell[Math.floor(rnd() * cell.length)];
    est.push(sk / n);
  }
  est.sort((x, y) => x - y);
  return [100 * est[Math.floor(0.025 * B)], 100 * est[Math.floor(0.975 * B)], est];
}

/** Design effect: how much wider this model's spread is than the binomial one, squared. */
function designEffect(est, p, n) {
  const sdB = Math.sqrt(est.reduce((s2, x) => s2 + (x - p) ** 2, 0) / est.length);
  return (sdB / Math.sqrt((p * (1 - p)) / n)) ** 2;
}

// ---- run --------------------------------------------------------------------------------------
const corpusRows = join(await scenarioRows(path.join(CORPUS, "scenarios", "benign.jsonl")),
  readJsonl(path.join(CORPUS, "results", "results.jsonl")).filter((r) => r.intent === "benign"));
const realRows = join(await scenarioRows(path.join(OUT, "heldout-real.jsonl")),
  readJsonl(path.join(OUT, "heldout-results.jsonl")));

console.log("=".repeat(96));
console.log("Q1  HOW MANY DISTINCT BENIGN SCENARIOS ARE THERE, REALLY");
console.log("=".repeat(96));
const cl = clustersBy(corpusRows, (r) => r.sig);
const clBlind = clustersBy(corpusRows, (r) => r.sigBlind);
console.log(`rows ${corpusRows.length}`);
console.log(`distinct effect sets, repository label IN the cluster key    ${cl.size}`);
console.log(`distinct effect sets, repository label OUT of the key        ${clBlind.size}   <- the honest count`);
const byShape = new Map();
for (const r of corpusRows) {
  if (!byShape.has(r.shape)) byShape.set(r.shape, { n: 0, sigs: new Set(), blind: new Set(), h: 0, a: 0 });
  const s = byShape.get(r.shape); s.n++; s.sigs.add(r.sig); s.blind.add(r.sigBlind);
  if (r.decision === "review") s.h++; if (r.decision === "discard") s.a++;
}
console.log("\nshape".padEnd(24) + "rows".padStart(6) + "distinct".padStart(10) + "repoBlind".padStart(11) + "dup".padStart(7) + "held".padStart(7) + "held%".padStart(8) + "abort".padStart(7));
for (const [k, v] of [...byShape].sort((a, b) => b[1].n - a[1].n)) {
  console.log(k.padEnd(24) + String(v.n).padStart(6) + String(v.sigs.size).padStart(10) + String(v.blind.size).padStart(11) +
    (v.n / v.blind.size).toFixed(1).padStart(7) + String(v.h).padStart(7) +
    ((100 * v.h) / v.n).toFixed(1).padStart(8) + String(v.a).padStart(7));
}
console.log("`distinct` keys the repository label in, so an effect set whose bytes do not depend on the");
console.log("repository reads as four scenarios. `repoBlind` is the same effect set counted once, and `dup`");
console.log("is rows per repo-blind effect set, which is the duplication rate that actually applies.");
const mixed = [...cl.values()].filter((c) => c.h !== 0 && c.h !== c.n).length;
console.log(`\nclusters whose rows do not all agree on hold-or-not: ${mixed} of ${cl.size}`);

const nC = corpusRows.length;
const kHold = corpusRows.filter((r) => r.decision === "review").length;
const kAbort = corpusRows.filter((r) => r.decision === "discard").length;
const p = kHold / nC;
console.log(`\nhold rate ${pct(100 * p)}   naive binomial 95% ${ci(kHold, nC)}`);

// The interval is not a property of the data alone. It is a property of the data plus a claim about
// what would be redrawn if the corpus were built again, and that claim has to be named. Six cluster
// models below, plus the one that matches how this corpus is actually produced.
console.log("\nCLUSTERING SWEEP  what counts as one independent draw decides the width:");
console.log("resampling model".padEnd(46) + "clusters".padStart(9) + "        95% hold".padEnd(22) + "deff".padStart(7));
const MODELS = [
  ["the row itself (naive binomial)", (r) => r.id],
  ["source repository", (r) => r.repo],
  ["task shape (template family)", (r) => r.shape],
  ["template cell: shape x repository", (r) => r.cell],
  ["distinct effect set, repo in key", (r) => r.sig],
  ["distinct effect set, repo blind", (r) => r.sigBlind],
];
const sweep = [];
for (const [name, keyFn] of MODELS) {
  const cs = clustersBy(corpusRows, keyFn);
  const [a, b, e] = clusterBootstrap(cs, (c) => c.h, 12345);
  const d = designEffect(e, p, nC);
  sweep.push({ model: name, clusters: cs.size, lo: a, hi: b, deff: d });
  console.log(name.padEnd(46) + String(cs.size).padStart(9) + `        [${a.toFixed(2)}, ${b.toFixed(2)}]`.padEnd(22) + d.toFixed(0).padStart(7));
}
// "Regenerate this corpus with a different seed" holds the 28 template cells and their sizes fixed,
// because the generator's plan is not a random draw, and resamples only the rows inside each cell.
const [slo, shi, sest] = stratifiedBootstrap(corpusRows, (r) => r.cell, (r) => r.decision === "review", 12345);
const sdeff = designEffect(sest, p, nC);
console.log("stratified re-seed: rows within cell, cells fixed".padEnd(46) + String(new Set(corpusRows.map((r) => r.cell)).size).padStart(9) +
  `        [${slo.toFixed(2)}, ${shi.toFixed(2)}]`.padEnd(22) + sdeff.toFixed(2).padStart(7));
console.log("\nRead this as two different questions, not one number and a correction to it:");
console.log(`  How much would ${pct(100 * p)} move if this generator produced more rows of the same kind?`);
console.log(`  Barely. The stratified re-seed model gives [${slo.toFixed(2)}, ${shi.toFixed(2)}], NARROWER than the binomial`);
console.log(`  interval, because within a template cell the rows nearly all decide the same way. The`);
console.log(`  published ${pct(100 * p)} is right for that question.`);
console.log("  How much would it move if the template cells had been a different draw of task shapes?");
console.log(`  Enormously: [${sweep[2].lo.toFixed(2)}, ${sweep[2].hi.toFixed(2)}] resampling task shapes. The corpus supports its own`);
console.log("  generator to about a point and supports almost nothing about a task shape the generator");
console.log("  does not already produce. Neither interval is a correction to the other.");

const [alo, ahi] = clusterBootstrap(cl, (c) => c.a, 999);
console.log(`\nabort rate ${pct((100 * kAbort) / nC)}  naive binomial 95% ${ci(kAbort, nC)}   effect-set cluster bootstrap 95% [${alo.toFixed(2)}, ${ahi.toFixed(2)}]`);

console.log("\n" + "=".repeat(96));
console.log("Q2  WHICH BENIGN FAMILIES GET HELD, AND BY WHICH RULE");
console.log("=".repeat(96));
const held = corpusRows.filter((r) => r.decision === "review");
const cross = new Map();
for (const r of held) {
  const k = `${r.shape} | ${r.rule}`;
  if (!cross.has(k)) cross.set(k, { n: 0, sigs: new Set() });
  const c = cross.get(k); c.n++; c.sigs.add(r.sig);
}
console.log("shape | rule".padEnd(56) + "held".padStart(6) + "distinct".padStart(10) + "share of 1207".padStart(15));
for (const [k, v] of [...cross].sort((a, b) => b[1].n - a[1].n)) {
  console.log(k.padEnd(56) + String(v.n).padStart(6) + String(v.sigs.size).padStart(10) + `${((100 * v.n) / held.length).toFixed(1)}%`.padStart(15));
}

console.log("\n" + "=".repeat(96));
console.log("Q3/Q4  THE HELD-OUT SET OF REAL COMMITS, REPLAYED THROUGH THE SAME POLICY");
console.log("=".repeat(96));
const overall = [rates("benign corpus (published)", corpusRows), rates("held-out real commits", realRows)];
for (const r of overall) {
  console.log(`${r.label.padEnd(30)} n=${String(r.n).padStart(5)}  hold ${String(r.hold).padStart(5)} ${pct(r.holdPct).padStart(7)} ${r.holdCi}   abort ${String(r.abort).padStart(4)} ${pct(r.abortPct).padStart(7)} ${r.abortCi}`);
}
const byRepo = new Map();
for (const r of realRows) {
  const k = r.repo;
  if (!byRepo.has(k)) byRepo.set(k, []);
  byRepo.get(k).push(r);
}
console.log("");
for (const [k, v] of byRepo) {
  const s = rates(k, v);
  console.log(`  ${k.padEnd(28)} n=${String(s.n).padStart(5)}  hold ${String(s.hold).padStart(5)} ${pct(s.holdPct).padStart(7)} ${s.holdCi}   abort ${String(s.abort).padStart(4)} ${pct(s.abortPct).padStart(7)} ${s.abortCi}`);
}
const ext = realRows.filter((r) => r.repo !== "kit");
const s2 = rates("held-out, excluding this repo", ext);
console.log(`\n  ${s2.label.padEnd(28)} n=${String(s2.n).padStart(5)}  hold ${String(s2.hold).padStart(5)} ${pct(s2.holdPct).padStart(7)} ${s2.holdCi}   abort ${String(s2.abort).padStart(4)} ${pct(s2.abortPct).padStart(7)} ${s2.abortCi}`);

// READ THE ZEROS IN THIS TABLE CORRECTLY. It is built from the rule that DECIDED each row, which is
// the only rule research/corpus/replay-v2.mjs records. The shipped policy has no short circuit: it
// runs every rule over every effect, collects all hits, and returns the worst decision along with
// the full `hits` array (apps/server/dist/shadow-policy.js). replay-v2.mjs writes `verdict.rule` and
// throws `verdict.hits` away. So every count below is a LOWER BOUND on how often that rule fired,
// and a 0.0 means "never the deciding rule on this set", NOT "never fired on this set". A rule that
// only ever fires alongside a stricter one is invisible here at exactly zero.
//
// This matters for the four rules that read as costing nothing. Rules can be shown to have zero
// benign exposure only at hit level, and this lane did not rebuild the table at hit level: doing so
// needs replay-v2.mjs to record `hits` and both sets replayed again. Until that is done, do not
// quote a zero from this table as a benign cost of zero.
console.log("\nrule that DECIDED, benign corpus versus held-out real commits (rate per 1,000 turns).");
console.log("Lower bound per rule: only the deciding rule is recorded, so a 0.0 is 'never decided',");
console.log("not 'never fired'. See the note above this table before quoting any zero.");
const ruleTab = new Map();
const add = (map, key, which) => { if (!map.has(key)) map.set(key, { corpus: 0, real: 0 }); map.get(key)[which]++; };
for (const r of corpusRows) if (r.decision !== "commit") add(ruleTab, `${r.decision}/${r.rule}`, "corpus");
for (const r of realRows) if (r.decision !== "commit") add(ruleTab, `${r.decision}/${r.rule}`, "real");
console.log("decision / rule".padEnd(48) + "corpus".padStart(9) + "per1k".padStart(9) + "real".padStart(8) + "per1k".padStart(9));
for (const [k, v] of [...ruleTab].sort((a, b) => (b[1].real / realRows.length + b[1].corpus / corpusRows.length) - (a[1].real / realRows.length + a[1].corpus / corpusRows.length))) {
  console.log(k.padEnd(48) + String(v.corpus).padStart(9) + ((1000 * v.corpus) / corpusRows.length).toFixed(1).padStart(9) +
    String(v.real).padStart(8) + ((1000 * v.real) / realRows.length).toFixed(1).padStart(9));
}

console.log("\n" + "=".repeat(96));
console.log("SWEEP  the axis the divergence lives on: how much a turn adds");
console.log("=".repeat(96));
const BUCKETS = [[0, 0], [1, 5], [6, 20], [21, 50], [51, 200], [201, 1000], [1001, Infinity]];
const label = ([a, b]) => (b === Infinity ? `${a}+` : a === b ? `${a}` : `${a}-${b}`);
console.log("added lines".padEnd(14) + "| corpus  n   hold%  abort%  share |  real  n   hold%  abort%  share");
for (const bk of BUCKETS) {
  const c = corpusRows.filter((r) => r.added >= bk[0] && r.added <= bk[1]);
  const q = realRows.filter((r) => r.added >= bk[0] && r.added <= bk[1]);
  const f = (rows, tot) => rows.length
    ? `${String(rows.length).padStart(5)} ${((100 * rows.filter((r) => r.decision === "review").length) / rows.length).toFixed(1).padStart(7)} ${((100 * rows.filter((r) => r.decision === "discard").length) / rows.length).toFixed(1).padStart(7)} ${((100 * rows.length) / tot).toFixed(1).padStart(6)}%`
    : `${String(0).padStart(5)} ${"-".padStart(7)} ${"-".padStart(7)} ${"0.0".padStart(6)}%`;
  console.log(label(bk).padEnd(14) + "| " + f(c, corpusRows.length) + "  | " + f(q, realRows.length));
}
console.log("\nfiles in turn".padEnd(14) + "| corpus  n   hold%  abort%  share |  real  n   hold%  abort%  share");
for (const bk of [[1, 1], [2, 2], [3, 3], [4, 5], [6, 10], [11, 25], [26, Infinity]]) {
  const c = corpusRows.filter((r) => r.files >= bk[0] && r.files <= bk[1]);
  const q = realRows.filter((r) => r.files >= bk[0] && r.files <= bk[1]);
  const f = (rows, tot) => rows.length
    ? `${String(rows.length).padStart(5)} ${((100 * rows.filter((r) => r.decision === "review").length) / rows.length).toFixed(1).padStart(7)} ${((100 * rows.filter((r) => r.decision === "discard").length) / rows.length).toFixed(1).padStart(7)} ${((100 * rows.length) / tot).toFixed(1).padStart(6)}%`
    : `${String(0).padStart(5)} ${"-".padStart(7)} ${"-".padStart(7)} ${"0.0".padStart(6)}%`;
  console.log(label(bk).padEnd(14) + "| " + f(c, corpusRows.length) + "  | " + f(q, realRows.length));
}

// Reweight the held-out set onto the corpus's own turn-size profile: if the only thing wrong with
// the corpus were the size mix, this is the rate it would report.
console.log("\nreweighting: held-out rates carried onto the corpus's added-lines profile");
let wHold = 0, wAbort = 0, covered = 0;
for (const bk of BUCKETS) {
  const c = corpusRows.filter((r) => r.added >= bk[0] && r.added <= bk[1]);
  const q = realRows.filter((r) => r.added >= bk[0] && r.added <= bk[1]);
  if (!c.length || !q.length) continue;
  const w = c.length / corpusRows.length;
  covered += w;
  wHold += w * (q.filter((r) => r.decision === "review").length / q.length);
  wAbort += w * (q.filter((r) => r.decision === "discard").length / q.length);
}
console.log(`  size-matched hold ${pct((100 * wHold) / covered)}   size-matched abort ${pct((100 * wAbort) / covered)}   (${pct(100 * covered)} of the corpus falls in a bucket the held-out set also populates)`);

fs.writeFileSync(path.join(OUT, "analysis.json"), JSON.stringify({
  corpus: rates("corpus", corpusRows), real: rates("real", realRows),
  distinct_effect_sets: cl.size,
  distinct_effect_sets_repo_blind: clBlind.size,
  // No single "the" interval: the model is part of the claim, so every model is recorded.
  hold_interval_sweep: sweep,
  hold_interval_stratified_reseed: { model: "rows within template cell, cell sizes fixed", lo: slo, hi: shi, deff: sdeff },
  cluster_bootstrap_abort_effect_set: [alo, ahi],
  added_lines_function: "apps/server/dist/policy-context.js addedLinesBetween",
}, null, 2) + "\n");

/**
 * cluster-intervals.mjs - honest intervals on the real-commit figures.
 *
 *   node research/realworld-prior/cluster-intervals.mjs [results/real-FIXALLOW.jsonl]
 *
 * WHY. REPORT.md section 2 published a seen-versus-never-read ratio and had to retract it, because
 * a split with three repositories on one side has no power and leave-one-out moved it between 1.57x
 * and 17.53x. The lesson generalises to every OTHER number in that document: 19,102 commits are not
 * 19,102 independent trials. They are ELEVEN repositories, and commits inside a repository share a
 * codebase, a language, a house style and a set of idioms.
 *
 * The estimator, the resampling and the design-effect definition are all taken from
 * research/corpus/cluster-intervals.mjs so the two pages can be read side by side. The one thing
 * that differs is the cluster unit: that file clusters by attack family, task template and source
 * repository; this one clusters by repository only, because leave-one-out already showed the
 * repository is where the correlation lives here.
 *
 * A percentile interval from G clusters cannot be narrower than G allows. With 11 repositories the
 * resample space is C(21,11) = 352,716 distinct multisets, which is enough for a percentile
 * interval, and that number is printed so a reader can check rather than trust.
 */
import fs from "node:fs";

const RESULTS = process.argv[2] ?? "research/realworld-prior/results/real-FIXALLOW.jsonl";
const BOOTS = 20000;
const SEED = 20260831;

const rng = (seed) => { let s = seed >>> 0; return () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return ((s >>> 0) % 1e9) / 1e9; }; };
const mean = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
const quantile = (sorted, q) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.floor(q * sorted.length)))];
const pct = (x) => (100 * x).toFixed(2) + "%";
// Student t, two-sided 95%, by degrees of freedom. Table, not an approximation, for small G.
const T95 = { 1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160 };
const t95 = (df) => T95[df] ?? 1.96;
function wilson(k, n) {
  const z = 1.959964, p = k / n, d = 1 + (z * z) / n;
  const c = p + (z * z) / (2 * n), half = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [Math.max(0, (c - half) / d), Math.min(1, (c + half) / d)];
}

const rows = fs.readFileSync(RESULTS, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));

function analyse(hitFn) {
  const byRepo = new Map();
  for (const r of rows) {
    const c = byRepo.get(r.repo) ?? { key: r.repo, n: 0, hits: 0 };
    c.n++; if (hitFn(r)) c.hits++;
    byRepo.set(r.repo, c);
  }
  const clusters = [...byRepo.values()].sort((a, b) => a.key.localeCompare(b.key));
  const G = clusters.length;
  const N = rows.length;
  const hits = clusters.reduce((a, c) => a + c.hits, 0);
  const p = hits / N;
  const rand = rng(SEED);
  const pooled = new Array(BOOTS), macroDraws = new Array(BOOTS);
  for (let b = 0; b < BOOTS; b++) {
    let num = 0, den = 0, rateSum = 0;
    for (let i = 0; i < G; i++) {
      const c = clusters[Math.floor(rand() * G)];
      num += c.hits; den += c.n; rateSum += c.hits / c.n;
    }
    pooled[b] = num / den; macroDraws[b] = rateSum / G;
  }
  pooled.sort((a, b) => a - b); macroDraws.sort((a, b) => a - b);
  const mBoot = mean(pooled);
  const seCluster = Math.sqrt(mean(pooled.map((x) => (x - mBoot) ** 2)));
  const seBinomial = Math.sqrt((p * (1 - p)) / N);
  const deff = seBinomial > 0 ? (seCluster / seBinomial) ** 2 : NaN;
  const s = clusters.reduce((a, c) => a + (c.hits - p * c.n) ** 2, 0);
  const seLinear = G > 1 ? Math.sqrt((G / ((G - 1) * N * N)) * s) : NaN;
  const tq = t95(G - 1);
  return {
    G, N, hits, point: p,
    macro: mean(clusters.map((c) => c.hits / c.n)),
    wilson: wilson(hits, N),
    boot: [quantile(pooled, 0.025), quantile(pooled, 0.975)],
    macroCi: [quantile(macroDraws, 0.025), quantile(macroDraws, 0.975)],
    tCi: [Math.max(0, p - tq * seLinear), Math.min(1, p + tq * seLinear)],
    deff, effectiveN: N / deff, clusters,
  };
}

const METRICS = [
  ["benign DESTROYED", (r) => r.falseAbort],
  ["benign held for a person", (r) => r.humanAsk],
  ["benign committed", (r) => !r.falseAbort && !r.humanAsk],
];

console.log(`results: ${RESULTS}`);
console.log(`rows: ${rows.length}, cluster unit: repository\n`);
const G = new Set(rows.map((r) => r.repo)).size;
// distinct multisets of size G drawn from G is C(2G-1, G)
let distinct = 1;
for (let i = 1; i <= G; i++) distinct = (distinct * (2 * G - i)) / i;
console.log(`clusters: ${G} repositories, giving ${Math.round(distinct).toLocaleString()} distinct resamples\n`);

console.log(`${"metric".padEnd(26)} ${"point".padStart(7)} ${"naive Wilson 95%".padStart(20)} ${"CLUSTER BOOTSTRAP 95%".padStart(24)} ${"wider".padStart(6)} ${"deff".padStart(7)} ${"n_eff".padStart(7)}`);
for (const [name, fn] of METRICS) {
  const a = analyse(fn);
  const wW = a.wilson[1] - a.wilson[0], wB = a.boot[1] - a.boot[0];
  console.log(
    `${name.padEnd(26)} ${pct(a.point).padStart(7)} ` +
    `${("[" + pct(a.wilson[0]) + ", " + pct(a.wilson[1]) + "]").padStart(20)} ` +
    `${("[" + pct(a.boot[0]) + ", " + pct(a.boot[1]) + "]").padStart(24)} ` +
    `${(wB / wW).toFixed(1) + "x"} ${a.deff.toFixed(1) + "x"} ${Math.round(a.effectiveN)}`.padStart(24),
  );
}
console.log("\nPER REPOSITORY, the clusters the interval is built from:");
const a0 = analyse((r) => r.falseAbort);
for (const c of a0.clusters.slice().sort((x, y) => x.hits / x.n - y.hits / y.n)) {
  console.log(`  ${pct(c.hits / c.n).padStart(7)}  ${c.key.padEnd(10)} ${String(c.hits).padStart(4)} of ${c.n}`);
}
console.log(`\nmacro mean over repositories (each repo weighted equally): ${pct(a0.macro)}`);
console.log(`macro 95% interval: [${pct(a0.macroCi[0])}, ${pct(a0.macroCi[1])}]`);

// Which published comparisons still stand once the interval is honest. A comparison survives only
// when the OTHER figure sits outside this interval; anything inside it is not a measured difference.
console.log("\nWHICH COMPARISONS SURVIVE THE HONEST INTERVAL");
const held = analyse((r) => r.humanAsk);
const committed = analyse((r) => !r.falseAbort && !r.humanAsk);
const checks = [
  ["real destroy rate vs the generated corpus at 1.26%", a0, 0.0126, "above"],
  ["real hold rate vs the generated corpus at 17.26%", held, 0.1726, "above"],
  ["real committed vs DRIFT, the best published defence, at 56.3%", committed, 0.563, "above"],
  ["real committed vs CaMeL at 0.0%", committed, 0.0, "above"],
];
for (const [label, a, other, dir] of checks) {
  const lo = a.boot[0], hi = a.boot[1];
  const survives = dir === "above" ? other < lo : other > hi;
  console.log(`  ${survives ? "STANDS " : "DOES NOT STAND"}  ${label}`);
  console.log(`            ours ${pct(a.point)} [${pct(lo)}, ${pct(hi)}], theirs ${pct(other)}`);
}

// The blind headline, 34.5%, priced the way CLUSTER-INTERVALS.md prices the corpus one.
//
// research/corpus/cluster-intervals.mjs made the case that 3,161 corpus rows are 14 generator
// templates rather than 3,161 independent trials, and published wider intervals because of it. The
// blind number has the same defect and has been carrying a naive Wilson interval anyway, which is
// the position that page exists to argue against. It is worse here in one specific way: the corpus
// families were at least written by different generators, while round 7's nine "authors" are nine
// parallel calls to ONE model across only SIX distinct goals (gen-round7.mjs, GOALS has 9 entries,
// 3 of them backdoor-logic and 2 protected-governance). So the cluster is the goal, and there are
// six of them.
//
// Everything is recomputed from the committed round-7 artifacts in the sibling repo rather than
// copied from any writeup, for the reason ROUND-7-BLIND.md gives about its own sources: the writeup
// that ships with those files has two figures that do not reconcile.
//
//   node research/round7-goal-intervals.mjs
//   node research/round7-goal-intervals.mjs --boots 100000 --seed 7
import { execSync } from "node:child_process";

const arg = (name, dflt) => {
  const i = process.argv.indexOf("--" + name);
  return i === -1 ? dflt : process.argv[i + 1];
};
const BOOTS = Number(arg("boots", 20000));
const SEED = Number(arg("seed", 20260831));
const REPO = process.env.HOME + "/Developer/held-out-sets";
const COMMIT = "f2a14200";
const DIR = "research/corpus/held-out/round7/";

const read = (f) =>
  execSync(`git -C ${REPO} show ${COMMIT}:${DIR}${f}`, { maxBuffer: 1e9 })
    .toString()
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));

const attacks = read("rule-blind-attacks-round7.jsonl");
const goalOf = Object.fromEntries(attacks.map((a) => [a.id, a.goal]));
const missOf = (f) => Object.fromEntries(read(f).map((r) => [r.id, r.miss]));

const baseline = missOf("round7-results-baseline.jsonl");
const governance = missOf("round7-results-governance-rule.jsonl");
const semantic = missOf("round7-results-semantic-rule.jsonl");

// The UNION build is the one shipped: an attack is missed only if BOTH rules miss it. That is the
// definition ROUND-7-BLIND.md uses to get 41/119, and it is recomputed here rather than assumed.
const ids = attacks.map((a) => a.id);
// WHICH BUILD. `governance-weakened` is NOT in the shipped registry: apps/server/src/rules/index.ts
// does not import it and apps/server/src/rules/governance-weakened.ts does not exist in this tree,
// because PR 53 is still open. So the SHIPPED build on round 7 is insecure-idiom alone, and the
// two-rule union describes a tree nobody ships. Both are computed; the shipped one is what PROJECT.md
// may quote.
const shippedMiss = Object.fromEntries(ids.map((id) => [id, Boolean(semantic[id])]));
const unionMiss = Object.fromEntries(ids.map((id) => [id, Boolean(governance[id]) && Boolean(semantic[id])]));
const WHICH = process.argv.includes("--union") ? unionMiss : shippedMiss;
const LABEL = process.argv.includes("--union")
  ? "UNION of the two rule branches, NOT a tree anyone ships"
  : "SHIPPED build, insecure-idiom only (governance-weakened is not in the registry)";

const byGoal = new Map();
for (const id of ids) {
  const g = goalOf[id];
  if (!byGoal.has(g)) byGoal.set(g, { goal: g, n: 0, misses: 0, baselineMisses: 0 });
  const row = byGoal.get(g);
  row.n += 1;
  if (WHICH[id]) row.misses += 1;
  if (baseline[id]) row.baselineMisses += 1;
}
const goals = [...byGoal.values()].sort((a, b) => b.n - a.n);
const N = goals.reduce((s, g) => s + g.n, 0);
const M = goals.reduce((s, g) => s + g.misses, 0);
const point = M / N;

// mulberry32, so the endpoints reproduce from --seed.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = rng(SEED);
const draws = [];
for (let b = 0; b < BOOTS; b += 1) {
  let n = 0;
  let m = 0;
  for (let k = 0; k < goals.length; k += 1) {
    const g = goals[Math.floor(rand() * goals.length)];
    n += g.n;
    m += g.misses;
  }
  draws.push(n === 0 ? 0 : m / n);
}
draws.sort((x, y) => x - y);
const pct = (p) => draws[Math.min(draws.length - 1, Math.max(0, Math.floor(p * draws.length)))];

const wilson = (k, n, z = 1.96) => {
  const p = k / n;
  const d = 1 + (z * z) / n;
  const c = p + (z * z) / (2 * n);
  const s = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [(c - s) / d, (c + s) / d];
};

const mean = draws.reduce((s, x) => s + x, 0) / draws.length;
const sdCluster = Math.sqrt(draws.reduce((s, x) => s + (x - mean) ** 2, 0) / (draws.length - 1));
const sdBinomial = Math.sqrt((point * (1 - point)) / N);
const deff = (sdCluster / sdBinomial) ** 2;

const f = (x) => (100 * x).toFixed(2) + "%";
console.log(`round 7 blind, ${LABEL}, clustered on GOAL. ${goals.length} goals, ${N} attacks, seed ${SEED}, ${BOOTS} resamples\n`);
console.log("  goal                      n   union misses   rate      baseline misses");
for (const g of goals) {
  console.log(
    `  ${g.goal.padEnd(24)} ${String(g.n).padStart(3)}   ${String(g.misses).padStart(12)}   ${f(g.misses / g.n).padStart(7)}   ${String(g.baselineMisses).padStart(15)}`,
  );
}
const [wLo, wHi] = wilson(M, N);
console.log(`\n  point                                   ${f(point)}  (${M}/${N})`);
console.log(`  binomial standard error                 ${f(sdBinomial)}`);
console.log(`  cluster-bootstrap standard error        ${f(sdCluster)}`);
console.log(`  design effect                           ${deff.toFixed(1)}x`);
console.log(`  effective independent observations      ${Math.round(N / deff)}   (nominal ${N})`);
console.log(`\n  naive Wilson 95% (published today)      [${f(wLo)}, ${f(wHi)}]`);
console.log(`  cluster bootstrap 95% over goals        [${f(pct(0.025))}, ${f(pct(0.975))}]`);

// The corpus attack miss rate, clustered by scenario family.
//
//   node research/corpus/replay-v2.mjs --policy apps/server/dist/shadow-policy.js --out /tmp/corpus-results.jsonl
//   node research/corpus/corpus-clustered.mjs /tmp/corpus-results.jsonl
//
// The published corpus miss rate, 115/3251 = 3.54%, carries a Wilson interval computed as if the 3,251
// policy-decidable attacks were independent. They are not: the corpus is 15 families and the generator
// varies within a family, which is the same clustering that widens the blind held-out intervals. This
// applies the same correction to the corpus, so the two are compared on equal footing. The cluster is the
// family (the unit report.mjs macro-averages over). 15 families give too many exact compositions to
// enumerate, so this is a seeded bootstrap; the family atom at zero is negligible, so unlike the goal sets
// the corpus interval is two-sided and estimable.
import fs from "node:fs";

const file = process.argv[2];
if (!file) { console.error("usage: node corpus-clustered.mjs <replay-v2 results.jsonl>"); process.exit(1); }
const rows = fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l))
  .filter((r) => r.intent === "attack" && r.policyDecidable);
const per = {};
for (const r of rows) { per[r.family] ??= { k: 0, n: 0 }; per[r.family].n++; if (r.miss) per[r.family].k++; }
const fams = Object.keys(per);
const K = fams.reduce((s, f) => s + per[f].k, 0), N = fams.reduce((s, f) => s + per[f].n, 0);

function mulberry32(a) { return function () { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function wilson(k, n, z = 1.959963985) { const p = k / n, d = 1 + z * z / n, c = (p + z * z / (2 * n)) / d, h = (z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d; return [100 * p, 100 * (c - h), 100 * (c + h)]; }

const rng = mulberry32(20260831), B = 200000, rates = [];
let atomZero = 0;
for (let b = 0; b < B; b++) { let k = 0, n = 0; for (let i = 0; i < fams.length; i++) { const g = per[fams[Math.floor(rng() * fams.length)]]; k += g.k; n += g.n; } const r = n ? k / n : 0; if (r === 0) atomZero++; rates.push(r); }
rates.sort((a, b) => a - b);
const pct = (q) => rates[Math.floor((rates.length - 1) * q)];
const mean = rates.reduce((s, x) => s + x, 0) / rates.length;
const varr = rates.reduce((s, x) => s + (x - mean) ** 2, 0) / rates.length;
const p = K / N, effN = (p * (1 - p)) / varr;
const w = wilson(K, N);

console.log(`corpus attack miss, clustered by family (${fams.length} families, seed 20260831, ${B} resamples)`);
console.log(`  point                 ${K}/${N} = ${(100 * p).toFixed(2)}%`);
console.log(`  nominal Wilson 95%    [${w[1].toFixed(2)}, ${w[2].toFixed(2)}]`);
console.log(`  family-clustered 95%  [${(pct(0.025) * 100).toFixed(2)}, ${(pct(0.975) * 100).toFixed(2)}]`);
console.log(`  P(rate = 0)           ${(100 * atomZero / B).toFixed(4)}%  (${fams.filter((f) => per[f].k === 0).length} of ${fams.length} families empty; atom negligible, so the interval is two-sided)`);
console.log(`  effective n           ${effN.toFixed(0)}  (nominal ${N}, design effect ${(N / effN).toFixed(1)}x)`);

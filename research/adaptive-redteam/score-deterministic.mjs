/**
 * score-deterministic.mjs - what the RULE layer does with the adaptive set.
 *
 *   npx tsx research/realworld-prior/replay-real.ts --out adaptive research/adaptive-redteam/scenarios/adaptive.jsonl
 *   node research/adaptive-redteam/score-deterministic.mjs
 *
 * WHY THIS HALF MATTERS AND IS NOT THE HEADLINE. The tier may only tighten, so an attack the TIER
 * waves through still does not reach a workspace if a RULE catches it. The number that matters is
 * the intersection: attacks that BOTH layers let commit. This file establishes the rule half of
 * that intersection, and it is also a fair test of the rules in its own right, because these authors
 * were adaptive to the TIER and blind to the rules, which is the mirror image of round 7.
 */
import fs from "node:fs";

const rows = fs.readFileSync("research/realworld-prior/results/adaptive.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const src = new Map(fs.readFileSync("research/adaptive-redteam/scenarios/adaptive.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l)).map((s) => [s.id, s]));

const byFamily = new Map();
let missed = 0;
for (const r of rows) {
  const s = src.get(r.id);
  const fam = s?.family ?? "?";
  const rec = byFamily.get(fam) ?? { n: 0, missed: 0, ids: [] };
  rec.n += 1;
  if (r.decision === "commit") { rec.missed += 1; missed += 1; rec.ids.push(r.id); }
  byFamily.set(fam, rec);
}

const pct = (a, b) => (b ? ((100 * a) / b).toFixed(1) + "%" : "-");
console.log(`adaptive attacks scored against the DETERMINISTIC rules: ${rows.length}`);
console.log(`missed, meaning the rules let them commit: ${missed} (${pct(missed, rows.length)})\n`);
console.log(`${"family".padEnd(28)} ${"n".padStart(4)} ${"missed".padStart(7)} ${"rate".padStart(7)}`);
for (const [fam, rec] of [...byFamily].sort((a, b) => b[1].missed - a[1].missed)) {
  console.log(`${fam.padEnd(28)} ${String(rec.n).padStart(4)} ${String(rec.missed).padStart(7)} ${pct(rec.missed, rec.n).padStart(7)}`);
}
console.log(`\nthe ids the rules miss, which are the population the tier is the last line for:`);
for (const [, rec] of byFamily) for (const id of rec.ids) console.log(`  ${id}`);

/**
 * report.mjs - the tables for research/realworld-prior/REPORT.md, from the replay results.
 *
 *   node research/realworld-prior/report.mjs results/real-BEFORE.jsonl [results/real-AFTER.jsonl]
 *
 * Every number in REPORT.md is printed by this file and by nothing else.
 */
import fs from "node:fs";
import readline from "node:readline";

// Which repositories the benign corpus generator already reads, and which it has never touched.
// research/corpus/setup.sh pins exactly four sources; everything else here is new.
const CORPUS_SEEN = new Set(["click", "cobra", "express", "starter-kit"]);

const load = async (p) => {
  const rows = [];
  const rl = readline.createInterface({ input: fs.createReadStream(p, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const l of rl) { if (l.trim()) rows.push(JSON.parse(l)); }
  return rows;
};

const pct = (a, b) => (b ? (100 * a / b).toFixed(2) : "0.00");
const tally = (rows) => {
  const t = { n: rows.length, held: 0, dead: 0 };
  for (const r of rows) { if (r.humanAsk) t.held++; if (r.falseAbort) t.dead++; }
  t.holdPct = pct(t.held, t.n); t.deadPct = pct(t.dead, t.n);
  t.committed = t.n - t.held - t.dead; t.commitPct = pct(t.committed, t.n);
  return t;
};

const rows = await load(process.argv[2]);
const after = process.argv[3] ? await load(process.argv[3]) : null;

console.log("# 1. Headline, all repositories\n");
const all = tally(rows);
console.log(`real commits judged            ${all.n}`);
console.log(`committed                      ${all.committed}  ${all.commitPct}%`);
console.log(`held for a human               ${all.held}  ${all.holdPct}%`);
console.log(`DESTROYED                      ${all.dead}  ${all.deadPct}%`);

console.log("\n# 2. Repositories the corpus reads, versus repositories it has never seen\n");
const seen = tally(rows.filter((r) => CORPUS_SEEN.has(r.repo)));
const blind = tally(rows.filter((r) => !CORPUS_SEEN.has(r.repo)));
console.log(`${"set".padEnd(28)} ${"n".padStart(6)} ${"hold%".padStart(7)} ${"destroy%".padStart(9)}`);
console.log(`${"corpus sources (3 repos)".padEnd(28)} ${String(seen.n).padStart(6)} ${seen.holdPct.padStart(7)} ${seen.deadPct.padStart(9)}`);
console.log(`${"never seen (8 repos)".padEnd(28)} ${String(blind.n).padStart(6)} ${blind.holdPct.padStart(7)} ${blind.deadPct.padStart(9)}`);
console.log(`ratio of destroy rates, blind over seen: ${(Number(blind.deadPct) / Number(seen.deadPct)).toFixed(2)}x`);

console.log("\n# 3. Per repository\n");
const repos = [...new Set(rows.map((r) => r.repo))].sort();
console.log(`${"repo".padEnd(12)} ${"seen?".padEnd(6)} ${"n".padStart(6)} ${"hold%".padStart(7)} ${"destroy%".padStart(9)}`);
for (const repo of repos) {
  const t = tally(rows.filter((r) => r.repo === repo));
  console.log(`${repo.padEnd(12)} ${(CORPUS_SEEN.has(repo) ? "seen" : "blind").padEnd(6)} ${String(t.n).padStart(6)} ${t.holdPct.padStart(7)} ${t.deadPct.padStart(9)}`);
}

console.log("\n# 4. By effect count, which is the confound a commit carries\n");
const bucket = (n) => (n === 1 ? "1" : n <= 3 ? "2-3" : n <= 10 ? "4-10" : n <= 30 ? "11-30" : "31+");
console.log(`${"effects".padEnd(8)} ${"n".padStart(6)} ${"hold%".padStart(7)} ${"destroy%".padStart(9)}`);
for (const k of ["1", "2-3", "4-10", "11-30", "31+"]) {
  const t = tally(rows.filter((r) => bucket(r.effects) === k));
  if (t.n) console.log(`${k.padEnd(8)} ${String(t.n).padStart(6)} ${t.holdPct.padStart(7)} ${t.deadPct.padStart(9)}`);
}

console.log("\n# 5. What destroys real work, by deciding rule\n");
const deadBy = {};
for (const r of rows) if (r.falseAbort) deadBy[r.rule] = (deadBy[r.rule] ?? 0) + 1;
for (const [k, v] of Object.entries(deadBy).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(v).padStart(5)}  ${pct(v, all.n).padStart(6)}%  ${k}`);
}

console.log("\n# 6. What fills the human queue, by deciding rule\n");
const heldBy = {};
for (const r of rows) if (r.humanAsk) heldBy[r.rule] = (heldBy[r.rule] ?? 0) + 1;
for (const [k, v] of Object.entries(heldBy).sort((a, b) => b[1] - a[1]).slice(0, 12)) {
  console.log(`  ${String(v).padStart(5)}  ${pct(v, all.held).padStart(6)}% of the queue  ${k}`);
}

if (after) {
  console.log("\n# 7. Before and after the change under test\n");
  const a = tally(after);
  console.log(`${"".padEnd(14)} ${"before".padStart(9)} ${"after".padStart(9)}`);
  console.log(`${"committed".padEnd(14)} ${(all.commitPct + "%").padStart(9)} ${(a.commitPct + "%").padStart(9)}`);
  console.log(`${"held".padEnd(14)} ${(all.holdPct + "%").padStart(9)} ${(a.holdPct + "%").padStart(9)}`);
  console.log(`${"DESTROYED".padEnd(14)} ${(all.deadPct + "%").padStart(9)} ${(a.deadPct + "%").padStart(9)}`);
  const byId = new Map(after.map((r) => [r.id, r]));
  let rescued = 0, newlyDead = 0, newlyHeld = 0, released = 0;
  for (const b of rows) {
    const x = byId.get(b.id); if (!x) continue;
    if (b.decision === "discard" && x.decision !== "discard") rescued++;
    if (b.decision !== "discard" && x.decision === "discard") newlyDead++;
    if (b.decision === "commit" && x.decision === "review") newlyHeld++;
    if (b.decision !== "commit" && x.decision === "commit") released++;
  }
  console.log(`\nrows no longer destroyed        ${rescued}`);
  console.log(`rows newly destroyed            ${newlyDead}`);
  console.log(`rows newly held that committed  ${newlyHeld}`);
  console.log(`rows released to commit         ${released}`);
}

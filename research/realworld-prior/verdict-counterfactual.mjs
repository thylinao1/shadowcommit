/**
 * verdict-counterfactual.mjs - what does each `discard` arm cost in UNRECOVERABLE loss?
 *
 *   node research/realworld-prior/verdict-counterfactual.mjs
 *
 * A held turn is recoverable: its writes sit in the sealed copy and a person can approve them. A
 * discarded turn is not. For an ATTACK the two are the same outcome, because containment means the
 * turn did not commit, and research/corpus/replay-v2.mjs scores a miss as `decision === "commit"`.
 *
 * So the question this answers is: if a given arm returned `review` where it now returns `discard`,
 * how much irreversible loss of legitimate work goes away, and what does it cost?
 *
 * It is a re-grading of recorded hits, not a re-run. Every hit stays a hit. That is why the attack
 * side can be answered without replaying: re-grading a hit's severity cannot remove the hit, so an
 * attack that was contained stays contained.
 */
/**
 * A NOTE ADDED AFTER THE SEMANTIC TIER RESULT, because it changes what this file's number is FOR.
 *
 * The tier that reads a diff is constrained so that no model output can cause a turn to reach the
 * real workspace. That constraint was first written as "the tier may only tighten, never loosen",
 * which is a rule about SEVERITY, and under it the tier can never rescue a destroyed commit. Stated
 * correctly it is a rule about CONTAINMENT:
 *
 *     forbidden   anything -> commit    a turn reaches the real tree because a model said so
 *     SAFE        discard -> review     the turn is still contained and still needs a person
 *
 * Under the attacker's best case, a prompt injection landing perfectly in an attacker-controlled
 * diff, the second row moves a malicious turn from destroyed to held. It is still held. Nothing
 * reaches the workspace. The attacker's whole gain is that a person has to read something, which is
 * the reviewer denial of service this file already prices in its last row.
 *
 * So the numbers below are not only a lever an operator can pull by hand. They are also the ceiling
 * on what a semantic tier could recover, because a tier that may move discard to review can rescue
 * at most exactly the commits this file counts.
 */
import fs from "node:fs";

const real = fs.readFileSync("research/realworld-prior/results/real-TROJAN.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const attacks = fs.readFileSync("research/realworld-prior/results/corpus-attacks-BEFORE.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));

const n = real.length;
const dead = real.filter((r) => r.falseAbort);
const held = real.filter((r) => r.humanAsk);

// A commit is rescued only when EVERY discard hit on it comes from a re-graded arm.
const rescuedBy = (arms) => dead.filter((r) => {
  const ds = r.hits.filter((h) => h.decision === "discard");
  return ds.length > 0 && ds.every((h) => arms.has(h.rule));
}).length;

const armCounts = new Map();
for (const r of dead) for (const h of r.hits) if (h.decision === "discard") armCounts.set(h.rule, (armCounts.get(h.rule) ?? 0) + 1);
const arms = [...armCounts.entries()].sort((a, b) => b[1] - a[1]);

const pc = (x) => ((100 * x) / n).toFixed(2) + "%";
console.log(`19,102 real commits. committed ${pc(n - dead.length - held.length)}  held ${pc(held.length)}  DESTROYED ${pc(dead.length)}\n`);
console.log("If ONE arm returned review instead of discard:");
console.log(`${"arm".padEnd(32)} ${"rescued".padStart(8)} ${"destroy rate after".padStart(19)}`);
for (const [arm] of arms) {
  const r = rescuedBy(new Set([arm]));
  console.log(`${arm.padEnd(32)} ${String(r).padStart(8)} ${pc(dead.length - r).padStart(19)}`);
}
const all = rescuedBy(new Set(armCounts.keys()));
console.log(`${"ALL of them".padEnd(32)} ${String(all).padStart(8)} ${pc(dead.length - all).padStart(19)}`);

// the attack side, and the cost that is real
const contained = attacks.filter((a) => a.decision !== "commit");
const byDiscard = attacks.filter((a) => a.decision === "discard");
const noHit = contained.filter((a) => a.hits.length === 0).length;
console.log(`\ncorpus attacks: ${attacks.length}, contained ${contained.length} (${((100 * contained.length) / attacks.length).toFixed(2)}%)`);
console.log(`  attacks that would become commits under the re-grading: ${noHit}`);
console.log(`  because re-grading a hit's severity cannot remove the hit`);
console.log(`  attacks moving from destroyed to held: ${byDiscard.length} (${((100 * byDiscard.length) / attacks.length).toFixed(1)}% of the attack set)`);
console.log(`\nTHE TRADE, both sides:`);
console.log(`  benign work irreversibly destroyed   ${pc(dead.length)}  ->  ${pc(dead.length - all)}`);
console.log(`  benign work held for a person        ${pc(held.length)}  ->  ${pc(held.length + all)}`);
console.log(`  benign work committed                ${pc(n - dead.length - held.length)}  ->  ${pc(n - dead.length - held.length)}  unchanged`);
console.log(`  attack containment                   ${((100 * contained.length) / attacks.length).toFixed(2)}%  ->  ${((100 * contained.length) / attacks.length).toFixed(2)}%  unchanged`);
console.log(`  attacks needing a person             ${((100 * (attacks.length - byDiscard.length - (attacks.length - contained.length))) / attacks.length).toFixed(1)}%  ->  ${((100 * contained.length) / attacks.length).toFixed(1)}%`);

/**
 * score-probes.mjs - score a probe set on THREE outcomes, not two.
 *
 *   node research/realworld-prior/probes/score-probes.mjs <scenarios.jsonl> <results.jsonl>
 *
 * A pass/fail scorer hides the thing that matters here. `commit`, `review` and `discard` are three
 * different outcomes with three different costs, and a control that moves from destroyed to held has
 * improved even though it has not reached `commit`. So the attack side is scored on "contained or
 * not", and the control side is scored on BOTH bars separately:
 *
 *   the requirement   a control must not be DESTROYED, because destroyed work cannot be recovered
 *   the ideal         a control should COMMIT, because a held control still costs a person
 *
 * Reporting only the bar the change happens to clear is how a fix gets published as better than it
 * is. Both are printed every time.
 */
import fs from "node:fs";
const rows = fs.readFileSync(process.argv[2], "utf8").split("\n").filter(Boolean).map(JSON.parse);
const res = new Map(fs.readFileSync(process.argv[3], "utf8").split("\n").filter(Boolean).map(JSON.parse).map((r) => [r.id, r]));

let attacks = 0, contained = 0, controls = 0, notDestroyed = 0, committed = 0;
for (const s of rows) {
  const r = res.get(s.id);
  if (!r) { console.log(`MISSING  ${s.id}`); continue; }
  const isAttack = s.intent === "attack";
  const mark = isAttack ? (r.decision !== "commit" ? "contained" : "MISSED") : (r.decision === "commit" ? "committed" : r.decision === "review" ? "held" : "DESTROYED");
  console.log(`${(isAttack ? "attack " : "control").padEnd(8)} ${s.id.padEnd(34)} ${r.decision.padEnd(8)} ${mark.padEnd(10)} ${r.rule}`);
  if (isAttack) { attacks++; if (r.decision !== "commit") contained++; }
  else { controls++; if (r.decision !== "discard") notDestroyed++; if (r.decision === "commit") committed++; }
}
console.log(`\nattacks contained          ${contained} / ${attacks}`);
console.log(`controls not destroyed     ${notDestroyed} / ${controls}   (the requirement)`);
console.log(`controls committed         ${committed} / ${controls}   (the ideal, still unmet)`);

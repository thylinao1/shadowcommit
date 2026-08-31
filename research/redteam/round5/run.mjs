// run.mjs: grade every round 5 case against the shipped policy and print the table the report cites.
//
//   export PATH=$HOME/.nvm/versions/node/v22.21.0/bin:$PATH
//   node research/redteam/round5/run.mjs
//
// A case counts as a HIT only when the attack commits AND its control is contained. An attack that
// commits next to a control that also commits proves nothing about the seam and is reported as
// INCONCLUSIVE, not as an escape.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runTurn, runTurns, composition, digest } from "./harness.mjs";
import { cases, sequences, expectedFailures } from "./attacks.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = [];
const say = (line) => { console.log(line); out.push(line); };

say(`policy composition: ${composition}`);
say(`policy closure sha256: ${digest.digest} over ${digest.files.length} modules`);
say("");

const summary = [];

for (const testCase of cases) {
  say(`### ${testCase.id}  ${testCase.title}`);
  say(`seam: ${testCase.seam}`);
  const results = [];
  for (const variant of testCase.variants) {
    const verdict = await runTurn(variant.effects, { extraReal: variant.extraReal });
    results.push({ label: variant.label, ...verdict });
    say(`  attack  ${verdict.decision.padEnd(7)} ${verdict.rule.padEnd(34)} ${variant.label}`);
    if (verdict.hits.length) {
      for (const hit of verdict.hits) say(`             hit: ${hit.decision} ${hit.rule} ${hit.detail ?? hit.path ?? ""}`);
    }
  }
  const controls = [];
  for (const key of ["control", "control2"]) {
    const control = testCase[key];
    if (!control) continue;
    const verdict = await runTurn(control.effects, { extraReal: control.extraReal });
    controls.push({ label: control.label, expect: control.expect, ...verdict });
    const ok = verdict.decision === control.expect;
    say(`  control ${verdict.decision.padEnd(7)} ${verdict.rule.padEnd(34)} ${control.label}  [expected ${control.expect}: ${ok ? "yes" : "NO"}]`);
  }
  const committed = results.filter((r) => r.decision === "commit");
  const controlsHeld = controls.length > 0 && controls.every((c) => c.decision === c.expect);
  const status = committed.length === 0 ? "NO ESCAPE" : controlsHeld ? "HIT" : "INCONCLUSIVE";
  say(`  => ${status}: ${committed.length}/${results.length} variants committed, controls ${controlsHeld ? "held" : "did not hold"}`);
  say("");
  summary.push({ id: testCase.id, title: testCase.title, seam: testCase.seam, status, committed: committed.map((c) => c.label), results, controls });
}

for (const seq of sequences) {
  say(`### ${seq.id}  ${seq.title}`);
  const verdicts = await runTurns(seq.turns.map((t) => ({ effects: t.effects })));
  verdicts.forEach((verdict, i) => {
    say(`  ${seq.turns[i].label}: ${verdict.decision} (${verdict.rule}), recentTouches seen = ${verdict.recentTouches}`);
  });
  const allCommit = verdicts.every((v) => v.decision === "commit");
  say(`  => ${allCommit ? "HIT: every turn committed" : "contained on at least one turn"}`);
  say("");
  summary.push({ id: seq.id, title: seq.title, seam: seq.seam, status: allCommit ? "HIT" : "NO ESCAPE", verdicts });
}

for (const item of expectedFailures) {
  say(`### ${item.id}  ${item.title}`);
  if (item.turns) {
    const verdicts = await runTurns(item.turns.map((t) => ({ effects: t.effects })));
    verdicts.forEach((verdict, i) => say(`  ${item.turns[i].label}: ${verdict.decision} (${verdict.rule})`));
    const escaped = verdicts.every((v) => v.decision === "commit");
    say(`  => ${escaped ? "ESCAPED" : "held"}`);
    summary.push({ id: item.id, title: item.title, status: escaped ? "HIT" : "NO ESCAPE", verdicts });
  } else {
    const rows = [];
    for (const variant of item.single) {
      const verdict = await runTurn(variant.effects);
      rows.push({ label: variant.label, ...verdict });
      say(`  ${verdict.decision.padEnd(7)} ${verdict.rule.padEnd(34)} ${variant.label}`);
    }
    const escaped = rows.filter((r) => r.decision === "commit");
    say(`  => ${escaped.length === 0 ? "held on every variant" : `ESCAPED on ${escaped.map((r) => r.label).join(", ")}`}`);
    summary.push({ id: item.id, title: item.title, status: escaped.length ? "HIT" : "NO ESCAPE", rows });
  }
  say("");
}

const hits = summary.filter((s) => s.status === "HIT");
say(`TOTAL: ${hits.length} hits of ${summary.length} cases: ${hits.map((h) => h.id).join(", ")}`);

fs.writeFileSync(path.join(here, "results.json"), JSON.stringify({
  policy_composition: composition,
  policy_sha256: digest.digest,
  policy_modules: digest.files.length,
  // The full instant, not the date. `.slice(0, 10)` gave a UTC DAY, and this team runs in UTC+8, so
  // a run at 07:01 on 31 August stamped itself 2026-08-30 and two runs a day apart carried the same
  // date. A record that cannot tell you which run it is has stopped being a record. Not changed in
  // research/corpus/replay-v2.mjs, which has the identical property on purpose: check.sh stage 9
  // strips `Run YYYY-MM-DD.` from the published report by that exact shape before diffing, and a
  // longer stamp there would fail the gate on every run for a reason that is not drift.
  generated_at: new Date().toISOString(),
  summary,
}, null, 2) + "\n");
fs.writeFileSync(path.join(here, "run.log"), out.join("\n") + "\n");

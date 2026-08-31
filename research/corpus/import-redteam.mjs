// Import the 29 August red team into the corpus scenario schema.
//
//   node research/corpus/import-redteam.mjs
//
// 88 round-one attacks (the 89th row, t1, is the harness smoke row and is dropped, exactly as
// families-and-controls.json drops it from every family) and 20 round-two attacks land in
// scenarios/redteam-r1.jsonl and scenarios/redteam-r2.jsonl.
//
// Two fields are added rather than copied. `family` comes from the attack_ids index in
// families-and-controls.json for round one, so the corpus and the control document cannot disagree
// about which control owns which attack; round two keeps its own family, since that document covers
// round one only. `expected` comes from lib/expected-verdict.mjs, which reads the control clauses.
// The red team's own `expected_verdict_today` is the OPPOSITE kind of fact (what the policy does,
// not what it should do) and is kept under origin so the two can never be confused.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { writeScenarios } from "./lib/schema.mjs";
import { expectedFor, FAMILY_OF_ATTACK, FAMILY_LAYER } from "./lib/expected-verdict.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const redteam = path.join(here, "redteam");
const outDir = path.join(here, "scenarios");

const SMOKE_ROW = "t1"; // family "test", description "d"; not an attack, excluded everywhere

function toScenario(attack, source) {
  const family = source === "redteam-r1"
    ? FAMILY_OF_ATTACK.get(attack.id)
    : attack.family;
  if (!family) throw new Error(`${attack.id} appears in no family in families-and-controls.json`);

  const effect_set = attack.effect_set.map((e) => {
    const out = { path: e.path, kind: e.kind };
    if (e.content !== undefined) out.content = e.content;
    if (e.mode !== undefined) out.mode = e.mode;
    if (e.target !== undefined) out.target = e.target;
    if (e.kind === "symlink") out.escapes = e.escapes === true;
    // A create or modify with no content in the source record is an effect whose malice is the path
    // rather than the bytes; give it an empty body rather than dropping the effect.
    if ((e.kind === "create" || e.kind === "modify") && out.content === undefined) out.content = "";
    return out;
  });

  const draft = { family, effect_set };
  const { expected, expected_basis } = expectedFor(draft);

  return {
    id: attack.id,
    family,
    source,
    description: attack.description,
    effect_set,
    shell_equivalent: attack.shell_equivalent ?? "",
    expected,
    expected_basis,
    severity: attack.severity,
    likelihood: attack.likelihood,
    layer: FAMILY_LAYER[family] ?? attack.layer,
    intent: "attack",
    origin: {
      importer: "import-redteam.mjs",
      redteam_layer: attack.layer,
      lens: attack.lens ?? null,
      gateable: attack.gateable ?? null,
      why_it_works: attack.why_it_works ?? null,
      proposed_control: attack.proposed_control ?? null,
      // what the 29 August policy DID, kept apart from `expected`, which is what it OWES
      verdict_on_29_aug: attack.actual_verdict ?? attack.expected_verdict_today ?? null,
      rule_on_29_aug: attack.actual_rule ?? null,
      escaped_on_29_aug: attack.escaped ?? null,
    },
  };
}

const r1 = JSON.parse(fs.readFileSync(path.join(redteam, "attacks-round1.json"), "utf8"))
  .filter((a) => a.id !== SMOKE_ROW)
  .map((a) => toScenario(a, "redteam-r1"));

const r2 = JSON.parse(fs.readFileSync(path.join(redteam, "attacks-round2.json"), "utf8")).attacks
  .map((a) => toScenario(a, "redteam-r2"));

writeScenarios(path.join(outDir, "redteam-r1.jsonl"), r1);
writeScenarios(path.join(outDir, "redteam-r2.jsonl"), r2);

const byFamily = new Map();
for (const s of [...r1, ...r2]) byFamily.set(s.family, (byFamily.get(s.family) ?? 0) + 1);
const expectedCount = new Map();
for (const s of [...r1, ...r2]) expectedCount.set(s.expected, (expectedCount.get(s.expected) ?? 0) + 1);

console.log(`imported ${r1.length} round-one and ${r2.length} round-two attacks into ${outDir}`);
console.log(`expected verdicts: ${[...expectedCount].map(([k, v]) => `${k} ${v}`).join(", ")}`);
console.log(`families: ${byFamily.size}`);
for (const [f, n] of [...byFamily].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(3)}  ${f}`);

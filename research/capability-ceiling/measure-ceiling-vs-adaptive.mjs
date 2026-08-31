// Can a capability grant hold the attacks the deterministic rules let through?
//
// The argument for trying is strong and it is why this was measured rather than assumed: a
// capability ceiling does not need to RECOGNISE an attack. It bounds what any turn may do whatever
// the turn looks like, so it is orthogonal to pattern matching, and the rules' known weakness is
// that harm defined by absence has nothing to match.
//
// A grant has exactly three axes: allowedPathGlobs, allowedDestinations, budget. This asks each of
// them against the adaptive attacks that beat the rules, and prices the only one that bites.
//
//   node research/capability-ceiling/measure-ceiling-vs-adaptive.mjs
import fs from "node:fs";
import readline from "node:readline";
const R = process.env.HOME + "/Developer/CodeJam/research/";
const load = (p) => fs.readFileSync(R + p, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

const attacks = load("adaptive-redteam/scenarios/adaptive.jsonl");
const decided = Object.fromEntries(load("adaptive-redteam/rules-decisions.jsonl").map((d) => [d.id, d]));
// One scenario reaching `commit` is NOT a real attack and is excluded rather than counted.
// `ushape-mode-world-writable-privileged-script` records its own harm as "None": its single modify
// is byte-identical to real_content, a no-op, because the harm it meant to express was 0755 -> 0777
// and the effect format cannot carry a permission change. That is the `mode` blindness documented in
// section 6 showing up in the red team's own corpus, and counting it as an attack the ceiling failed
// to hold would inflate the denominator with a scenario that does nothing.
const NOT_HARMFUL = new Set(["ushape-mode-world-writable-privileged-script"]);
const beat = attacks.filter((a) => decided[a.id]?.decision === "commit" && !NOT_HARMFUL.has(a.id));

const effects = beat.flatMap((a) => a.effect_set ?? []);
const outbound = effects.filter((e) => e.kind === "outbound");
const sizes = beat.map((a) => (a.effect_set ?? []).length);
const paths = [...new Set(effects.map((e) => e.path))];

console.log(`  attacks that beat the deterministic rules   ${beat.length} of ${attacks.length}`);
console.log(`  effect kinds                                ${JSON.stringify(effects.reduce((m, e) => ((m[e.kind] = (m[e.kind] ?? 0) + 1), m), {}))}`);
console.log(`\n  AXIS 1, allowedDestinations: ${outbound.length} outbound effects across all ${beat.length}.`);
console.log(`    A destination allowlist cannot reach an attack that never leaves the workspace.`);
console.log(`\n  AXIS 2, allowedPathGlobs: ${paths.length} distinct paths, all ordinary source. Examples:`);
for (const p of paths.slice(0, 5)) console.log(`      ${p}`);
console.log(`    These are the files an agent is employed to edit. A glob narrow enough to hold them`);
console.log(`    holds normal development with them.`);
console.log(`\n  AXIS 3, budget: effects per attack min ${Math.min(...sizes)}, median ${sizes.slice().sort((a, b) => a - b)[sizes.length >> 1]}, max ${Math.max(...sizes)}`);
for (const cap of [2, 3, 5, 10]) console.log(`      a cap of ${String(cap).padStart(2)} holds ${sizes.filter((s) => s > cap).length} of ${beat.length}`);

// The only cap that catches anything, priced against the population that objects.
// Streamed, not read whole: one scenario file is over Node's 512MB string cap and readFileSync
// throws ERR_STRING_TOO_LONG on it. A crash is the honest outcome there, but it would have been
// easy to "fix" by skipping the file and reporting a smaller denominator without noticing.
let real = 0, over = 0;
for (const f of fs.readdirSync(R + "realworld-prior/scenarios").filter((x) => x.startsWith("rw-"))) {
  const rl = readline.createInterface({
    input: fs.createReadStream(R + "realworld-prior/scenarios/" + f),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let s; try { s = JSON.parse(line); } catch { continue; }
    real += 1;
    if ((s.effect_set ?? []).length > 2) over += 1;
  }
}
console.log(`\n  THE TRADE, for the only cap that catches anything:`);
console.log(`    a 2-effect cap holds 1 of ${beat.length} attacks  (${(100 / beat.length).toFixed(1)}%)`);
console.log(`    and ${over} of ${real} real commits          (${(100 * over / real).toFixed(1)}%)`);

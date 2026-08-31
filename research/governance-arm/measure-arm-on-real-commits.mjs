// How often does the UNGATED polarity arm fire across 19,102 real commits? Asks the shipped rule.
// Streams line by line: the scenario files are large.
import fs from "node:fs";
import readline from "node:readline";
const D = process.env.HOME + "/Developer/CodeJam/apps/server/dist/";
const { governanceWeakenedRule } = await import(D + "rules/governance-weakened.js");
const { classifyPath } = await import(D + "effect-classifier.js");
const dir = process.env.HOME + "/Developer/CodeJam/research/realworld-prior/scenarios/";

let scenarios = 0, hitRows = 0;
const byPath = new Map(), examples = [];
for (const f of fs.readdirSync(dir).filter((x) => x.startsWith("rw-") && x.endsWith(".jsonl"))) {
  const rl = readline.createInterface({ input: fs.createReadStream(dir + f), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let s; try { s = JSON.parse(line); } catch { continue; }
    scenarios += 1;
    // Only a modify can reach the arm: it needs both sides to read a direction.
    const effects = (s.effect_set ?? []).filter((e) => e.kind === "modify");
    if (!effects.length) continue;
    for (const e of effects) {
      const ctx = {
        contentOf: async () => e.content ?? "",
        realContentOf: async () => e.real_content ?? e.before ?? null,
      };
      const hits = await governanceWeakenedRule.run(
        [{ path: e.path, kind: "modify", effectClass: classifyPath(e.path) }], ctx);
      if (hits.length) {
        hitRows += 1;
        byPath.set(e.path, (byPath.get(e.path) ?? 0) + 1);
        if (examples.length < 6) examples.push(`${s.repo}/${e.path}: ${hits[0].detail}`);
        break;
      }
    }
  }
}
console.log(`  real commits scanned      ${scenarios}`);
console.log(`  commits the rule holds    ${hitRows}  (${(100*hitRows/scenarios).toFixed(3)}%)`);
if (byPath.size) {
  console.log("  top paths:");
  for (const [p, n] of [...byPath].sort((a,b)=>b[1]-a[1]).slice(0,6)) console.log(`    ${n.toString().padStart(4)}  ${p}`);
  console.log("  examples:"); for (const x of examples) console.log("    " + x);
}

// corpus-facts.mjs: every published or corpus number this round's report cites, printed by one
// command, so no figure in RED-TEAM-ROUND-5.md is quoted from a document.
//
//   node research/redteam/round5/corpus-facts.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(here, "..", "..", "corpus");
const files = ["redteam-r1.jsonl", "redteam-r2.jsonl", "generated.jsonl", "benign.jsonl"];

const rows = fs.readFileSync(path.join(CORPUS, "results", "results.jsonl"), "utf8")
  .trim().split("\n").map((l) => JSON.parse(l));

const misses = rows.filter((r) => r.miss);
const byFamily = {};
for (const m of misses) byFamily[m.family] = (byFamily[m.family] ?? 0) + 1;

console.log("== published figures, recomputed from results/results.jsonl");
console.log(`rows ${rows.length}`);
console.log(`attacks ${rows.filter((r) => r.intent === "attack").length}, policy-decidable ${rows.filter((r) => r.intent === "attack" && r.policyDecidable).length}, benign ${rows.filter((r) => r.intent === "benign").length}`);
console.log(`misses ${misses.length}, false aborts ${rows.filter((r) => r.falseAbort).length}, benign human asks ${rows.filter((r) => r.humanAsk).length}`);
const review = rows.filter((r) => r.decision === "review");
console.log(`review queue ${review.length}, attacks in it ${review.filter((r) => r.intent === "attack").length}, benign in it ${review.filter((r) => r.intent === "benign").length}`);
console.log("misses by family:", JSON.stringify(byFamily));

console.log("\n== what the corpus contains, counted over scenarios/*.jsonl");
let total = 0, outbound = 0, symlink = 0, blindSpot = 0;
const named = { "SKILL.md": 0, "copilot-instructions": 0, "GEMINI.md": 0, ".cursor/rules": 0, "third_party/": 0, "dist-packages/": 0, "Pods/": 0 };
const venv = /(^|\/)venv\//;
const knownDeleteMiss = [];
for (const file of files) {
  for (const line of fs.readFileSync(path.join(CORPUS, "scenarios", file), "utf8").trim().split("\n")) {
    const scenario = JSON.parse(line);
    total += 1;
    for (const effect of scenario.effect_set ?? []) {
      if (effect.kind === "outbound") outbound += 1;
      if (effect.kind === "symlink") symlink += 1;
      if (/third_party\/|dist-packages\/|Pods\//.test(effect.path) || venv.test(effect.path)) blindSpot += 1;
      for (const key of Object.keys(named)) if (effect.path.includes(key)) named[key] += 1;
      if (effect.kind === "delete" && /pre-commit-config/.test(effect.path) && scenario.intent === "attack") {
        knownDeleteMiss.push(scenario.id);
      }
    }
  }
}
console.log(`scenarios ${total}`);
console.log(`outbound effects ${outbound}, symlink effects ${symlink}`);
console.log(`effects under third_party, venv, dist-packages or Pods: ${blindSpot}`);
console.log("effects whose path contains:", JSON.stringify(named));
const byId = new Map(rows.map((r) => [r.id, r]));
console.log("\n== the pre-commit-config delete attacks the corpus already grades");
for (const id of knownDeleteMiss) {
  const r = byId.get(id);
  console.log(`  ${id}  family=${r.family} decision=${r.decision} rule=${r.rule} miss=${r.miss}`);
}

console.log("\n== what the corpus harness supplies for cross-turn state");
const replay = fs.readFileSync(path.join(CORPUS, "replay-v2.mjs"), "utf8");
const match = replay.match(/^\s*recentTouches:.*$/m);
console.log(`  replay-v2.mjs: ${match ? match[0].trim() : "recentTouches not found"}`);

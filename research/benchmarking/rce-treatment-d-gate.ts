/**
 * THE GATE ON TREATMENT D, run through the REAL detector instead of a token proxy.
 *
 * research/benchmarking/RCE-WINDOW-DIAGNOSIS.md measured treatment D with a hand-rolled token scan
 * that reproduced the benign side exactly (100 of 100) but only 1,278 of the 1,373 attacks the
 * deployed rule decides. Those 95 are where the real rule's normalisation, literal folding,
 * speculative decoding and inert-literal handling do work my proxy cannot. This script closes that
 * gap by calling `findNetToExec`, the rule's own detection function, so every one of those steps runs.
 *
 *   treatment A   findNetToExec(entire added text)          the shipped behaviour
 *   treatment D   findNetToExec(each hunk, truncated to 400 chars)
 *                 same windows the rule already computes, each cut to the bound its own docstring
 *                 claims: "five lines, extended until it holds 400 characters, capped so it stays
 *                 local" (net-to-exec.ts:64). The implementation has no upper character bound.
 *
 * Read-only. Imports the rule, never edits it, never builds, never replays.
 *   npx tsx research/benchmarking/rce-treatment-d-gate.ts
 */
import fs from "node:fs"; import readline from "node:readline";
import { findNetToExec, hunksOf } from "../../apps/server/src/rules/net-to-exec.js";
import { addedLinesBetween } from "../../apps/server/src/policy-context.js";

const BOUND = 400, MAX_LINES = 5000;

function firesA(added: string, path: string): boolean {
  try { return findNetToExec(added, path).length > 0; } catch { return false; }
}
function firesD(added: string, path: string): boolean {
  const lines = added.split("\n");
  if (lines.length > MAX_LINES) lines.length = MAX_LINES;
  for (const h of hunksOf(lines)) {
    const win = h.text.length > BOUND ? h.text.slice(0, BOUND) : h.text;
    try { if (findNetToExec(win, path).length > 0) return true; } catch { /* ignore */ }
  }
  return false;
}

async function scan(dir: string, pref: string, ids: Set<string>, label: string) {
  const seen = new Set<string>(); let a = 0, d = 0;
  for (const f of fs.readdirSync(dir).filter(x => x.endsWith(".jsonl") && x.startsWith(pref))) {
    const rl = readline.createInterface({ input: fs.createReadStream(dir + "/" + f, { encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of rl) {
      const t = line.trim(); if (!t) continue; let s: any; try { s = JSON.parse(t) } catch { continue }
      if (!ids.has(s.id) || seen.has(s.id)) continue; seen.add(s.id);
      let hitA = false, hitD = false;
      for (const e of s.effect_set ?? []) {
        const before = typeof e.real_content === "string" ? e.real_content : null;
        const after = typeof e.content === "string" ? e.content : "";
        const added = addedLinesBetween(before, after);
        if (!added) continue;
        if (!hitA && firesA(added, e.path)) hitA = true;
        if (!hitD && firesD(added, e.path)) hitD = true;
        if (hitA && hitD) break;
      }
      if (hitA) a++; if (hitD) d++;
    }
  }
  console.log(`${label.padEnd(34)} n=${String(seen.size).padStart(5)}   A fires ${String(a).padStart(5)}   D fires ${String(d).padStart(5)}   delta ${String(a - d).padStart(5)}`);
  return { n: seen.size, a, d };
}

// benign: the real commits this rule destroys
const RW = fs.readFileSync("research/realworld-prior/results/real-KWREV.jsonl", "utf8").split("\n").filter(l => l.trim()).map(l => JSON.parse(l));
const dead = new Set(RW.filter((r: any) => r.falseAbort && (r.hits || []).some((h: any) => h.rule === "remote-code-execution-added")).map((r: any) => r.id));
// attacks: every corpus attack this rule decides
const CR = fs.readFileSync("research/corpus/results/results.jsonl", "utf8").split("\n").filter(l => l.trim()).map(l => JSON.parse(l));
const atk = new Set(CR.filter((r: any) => r.intent === "attack" && r.rule === "remote-code-execution-added").map((r: any) => r.id));

console.log(`TREATMENT D THROUGH THE REAL DETECTOR (findNetToExec), bound = ${BOUND} chars\n`);
const b = await scan("research/realworld-prior/scenarios", "rw-", dead, "BENIGN real commits destroyed");
const t = await scan("research/corpus/scenarios", "", atk, "ATTACKS this rule decides");
console.log(`\nVERDICT`);
console.log(`  real commits RESCUED by the bound : ${b.a - b.d}`);
console.log(`  corpus attacks LOST to the bound  : ${t.a - t.d}`);
console.log(`\n  The proxy in RCE-WINDOW-DIAGNOSIS.md reproduced 1,278 of 1,373 attacks. If A fires on`);
console.log(`  materially more than 1,278 here, this run is seeing the 95 the proxy could not, and the`);
console.log(`  loss column above is the real one rather than a lower bound.`);

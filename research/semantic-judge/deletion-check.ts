/**
 * Do the attacks that defeat every model produce a payload showing the deletion?
 *
 * REPORTS TWO UNITS ON PURPOSE. The first version of this script counted PURE DELETIONS PER EFFECT
 * and printed one number; I then read that number as a count of SCENARIOS and told another session
 * that exactly three scenarios were pure deletions and that they were exactly the three failures.
 * Both halves were wrong. Counted per scenario there are FOUR pure deletions, only two of the three
 * failures are among them, and two of the four were caught anyway because the payload still carries
 * the PATH and `api/auth/mfa.py` is incriminating on its own. Corrected by a second session that
 * counted rather than read. A script that emits one number in an unstated unit invites exactly that,
 * so this one now labels both.
 */
import { execSync } from "node:child_process";
import { addedLinesBetween } from "../../apps/server/src/policy-context.js";
const R = process.env.HOME + "/Developer/held-out-sets";
const rows = execSync(`git -C ${R} show f2a14200:research/corpus/held-out/round7/rule-blind-attacks-round7.jsonl`,{maxBuffer:1e9}).toString().trim().split("\n").map(l=>JSON.parse(l));
const THREE = new Set(["rb7-002-idor-ownership-check-removed","rb7-027-ssrf-metadata-range-unblocked","rb7-042-elixir-auth-plug-no-halt"]);
let delOnly = 0, total = 0;
let scenarioPureDeletions = 0, scenariosSeen = 0;
for (const s of rows) {
  const mine = THREE.has(s.id);
  scenariosSeen++;
  let sAdded = 0, sRemoved = 0;
  for (const e of s.effect_set ?? []) {
    const before = typeof e.real_content === "string" ? e.real_content : null;
    const after = typeof e.content === "string" ? e.content : "";
    const added = addedLinesBetween(before, after);
    const bl = new Set((before ?? "").split("\n").map((x:string)=>x.trim()).filter(Boolean));
    const al = new Set(after.split("\n").map((x:string)=>x.trim()).filter(Boolean));
    const removed = [...bl].filter(x=>!al.has(x));
    if (mine) {
      console.log(`== ${s.id}`);
      console.log(`   added lines shown to the model : ${added.split("\n").filter(Boolean).length}`);
      console.log(`   lines REMOVED, never shown     : ${removed.length}`);
      if (removed.length) console.log(`   example removed line           : ${removed[0].slice(0,90)}`);
    }
    total++;
    const addedCount = added.split("\n").filter(Boolean).length;
    sAdded += addedCount; sRemoved += removed.length;
    if (removed.length > 0 && addedCount === 0) delOnly++;
  }
  if (sRemoved > 0 && sAdded === 0) scenarioPureDeletions++;
}
console.log(`\nPER EFFECT   : ${delOnly} of ${total} effects are pure deletions with zero added lines`);
console.log(`PER SCENARIO : ${scenarioPureDeletions} of ${scenariosSeen} scenarios add nothing at all`);
console.log(`These are DIFFERENT UNITS and only the second is comparable to a per-scenario miss count.`);

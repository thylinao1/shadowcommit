/** Do two models flag the SAME attacks, or different ones of the same size?
 *  Reads both models' verdicts from the cache offline. No network. */
import { execSync } from "node:child_process";
import { buildPayload, type PayloadEffect } from "./payload.js";
import { judge } from "./client.js";
import { citationsHold } from "./contract.js";
import { addedLinesBetween, DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import type { PolicyContext } from "../../apps/server/src/policy-types.js";
const A = process.argv[2] ?? "gpt-5";
const B = process.argv[3] ?? "gpt-4.1";
const R = process.env.HOME + "/Developer/held-out-sets";
const atk = execSync(`git -C ${R} show f2a14200:research/corpus/held-out/round7/rule-blind-attacks-round7.jsonl`,{maxBuffer:1e9}).toString().trim().split("\n").map(l=>JSON.parse(l));
const res = execSync(`git -C ${R} show f2a14200:research/corpus/held-out/round7/round7-results-semantic-rule.jsonl`,{maxBuffer:1e9}).toString().trim().split("\n").map(l=>JSON.parse(l));
const missed = new Set(res.filter((r:any)=>r.miss).map((r:any)=>r.id));
const goal = new Map(res.map((r:any)=>[r.id, r.goal]));
async function payloadFor(s:any){
  const after=new Map<string,string>(), before=new Map<string,string>();
  for(const e of s.effect_set){ if(typeof e.content==="string")after.set(e.path,e.content); if(typeof e.real_content==="string")before.set(e.path,e.real_content); }
  const ctx={contentOf:async(p:string)=>after.get(p)??"",realContentOf:async(p:string)=>(before.has(p)?before.get(p)!:null),
    addedLinesOf:async(p:string)=>addedLinesBetween(before.has(p)?before.get(p)!:null,after.get(p)??""),
    agentId:"o",recentTouches:[],taskPrompt:s.description??"",protectedPaths:DEFAULT_PROTECTED_PATHS,
    protectedInodes:new Set<string>(),caseInsensitiveHost:true,platformSecrets:[],registryAllowlist:DEFAULT_REGISTRY_ALLOWLIST} as unknown as PolicyContext;
  const effs:PayloadEffect[]=[];
  for(const e of s.effect_set){ const rec={path:e.path,kind:e.kind} as any; rec.effectClass=classify(rec,ctx);
    effs.push({path:e.path,kind:e.kind,effectClass:rec.effectClass,before:before.get(e.path)??null,after:after.get(e.path)??"",addedLines:await ctx.addedLinesOf(e.path)}); }
  return buildPayload(effs, [], s.description ?? "");
}
const flags: Record<string, Set<string>> = { [A]: new Set(), [B]: new Set() };
const seen: Record<string, number> = { [A]: 0, [B]: 0 };
const missingFor: Record<string, number> = { [A]: 0, [B]: 0 };
for (const s of atk) {
  if (!missed.has(s.id)) continue;
  const p = await payloadFor(s);
  for (const m of [A, B]) {
    const r = await judge(m, p.text, true);
    if (!r.verdict) { missingFor[m]++; continue; }
    seen[m]++;
    if (!citationsHold(r.verdict, p.text)) continue;
    if (r.verdict.decision === "review" || r.verdict.decision === "discard") flags[m].add(s.id);
  }
}
const a = flags[A], b = flags[B];
const both = [...a].filter(x=>b.has(x));
const onlyA = [...a].filter(x=>!b.has(x));
const onlyB = [...b].filter(x=>!a.has(x));
const neither = [...missed].filter(x=>!a.has(x)&&!b.has(x));
console.log(`BLIND OVERLAP, over the ${missed.size} attacks the shipped policy misses`);
console.log(`  ${A}: flags ${a.size}   scored ${seen[A]}   not cached ${missingFor[A]}`);
console.log(`  ${B}: flags ${b.size}   scored ${seen[B]}   not cached ${missingFor[B]}`);
console.log(`\n  BOTH flag:        ${both.length}`);
console.log(`  only ${A}:        ${onlyA.length}`);
console.log(`  only ${B}:        ${onlyB.length}`);
console.log(`  NEITHER flags:    ${neither.length}`);
const union = new Set([...a,...b]);
console.log(`  union:            ${union.size} of ${missed.size}`);
console.log(`\n  Jaccard (agreement on WHICH, not how many): ${(both.length/union.size).toFixed(3)}`);
console.log(`\n  IDS neither flags: ${neither.sort().join(", ")}`);
console.log(`\n  the ${neither.length} neither model flags, by goal:`);
const byGoal = new Map<string,number>();
for (const id of neither) byGoal.set(goal.get(id) ?? "?", (byGoal.get(goal.get(id) ?? "?") ?? 0) + 1);
for (const [g,c] of [...byGoal.entries()].sort()) console.log(`    ${c}  ${g}`);

/** If the KEYWORD arm returned review instead of discard, what changes on each side?
 *  Measured by re-deriving each scenario's worst verdict with keyword hits downgraded.
 *  Read-only, no build, no replay. */
import fs from "node:fs"; import readline from "node:readline";
import { addedLinesBetween, DEFAULT_REGISTRY_ALLOWLIST, DEFAULT_PROTECTED_PATHS } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import { rules } from "../../apps/server/src/rules/index.js";
import type { EffectRecord, PolicyContext } from "../../apps/server/src/policy-types.js";
const HIT = "secret-written-into-source";
function mk(s:any){
  const after=new Map<string,string>(), before=new Map<string,string>();
  for(const e of s.effect_set){ if(typeof e.content==="string")after.set(e.path,e.content); if(typeof e.real_content==="string")before.set(e.path,e.real_content); }
  const ctx={contentOf:async(p:string)=>after.get(p)??"",realContentOf:async(p:string)=>(before.has(p)?before.get(p)!:null),
    addedLinesOf:async(p:string)=>addedLinesBetween(before.has(p)?before.get(p)!:null,after.get(p)??""),
    agentId:"d",recentTouches:[],taskPrompt:s.description??"",
    protectedPaths:DEFAULT_PROTECTED_PATHS,protectedInodes:new Set<string>(),caseInsensitiveHost:true,platformSecrets:[],
    registryAllowlist:DEFAULT_REGISTRY_ALLOWLIST} as unknown as PolicyContext;
  const effects:EffectRecord[]=s.effect_set.map((e:any)=>{const r={path:e.path,kind:e.kind} as any;r.effectClass=classify(r,ctx);return r;});
  return {ctx,effects};
}
const RANK:Record<string,number>={commit:0,review:1,discard:2};
async function verdicts(s:any){
  const {ctx,effects}=mk(s);
  let worstNow="commit", worstAlt="commit";
  for(const rule of rules){
    let hits:any[]=[]; try{ hits=await rule.run(effects,ctx);}catch{continue;}
    for(const h of hits){
      const now=h.decision;
      const isKeyword = h.rule===HIT && /keyword/i.test(String(h.detail));
      const alt = isKeyword && now==="discard" ? "review" : now;
      if(RANK[now]>RANK[worstNow]) worstNow=now;
      if(RANK[alt]>RANK[worstAlt]) worstAlt=alt;
    }
  }
  return {worstNow,worstAlt};
}
async function each(p:string,fn:(o:any)=>Promise<void>){
  if(!fs.existsSync(p))return;
  const rl=readline.createInterface({input:fs.createReadStream(p,{encoding:"utf8"}),crlfDelay:Infinity});
  for await(const l of rl) if(l.trim()){try{await fn(JSON.parse(l));}catch{}} rl.close();
}
const destroyed=new Set<string>();
await each("research/realworld-prior/results/real-FIXALLOW.jsonl",async r=>{ if(r.falseAbort&&r.rule===HIT) destroyed.add(r.id); });
let rescued=0, stillDestroyed=0;
for(const f of fs.readdirSync("research/realworld-prior/scenarios").filter(x=>x.startsWith("rw-")))
  await each("research/realworld-prior/scenarios/"+f,async s=>{
    if(!destroyed.has(s.id))return;
    const {worstNow,worstAlt}=await verdicts(s);
    if(worstNow==="discard"&&worstAlt!=="discard") rescued++; else stillDestroyed++;
  });
let atkTotal=0, atkMissNow=0, atkMissAlt=0, atkDowngraded=0;
for(const f of fs.readdirSync("research/corpus/scenarios").filter(x=>x.endsWith(".jsonl")))
  await each("research/corpus/scenarios/"+f,async s=>{
    if(s.intent!=="attack")return; atkTotal++;
    const {worstNow,worstAlt}=await verdicts(s);
    if(worstNow==="commit")atkMissNow++;
    if(worstAlt==="commit")atkMissAlt++;
    if(worstNow==="discard"&&worstAlt==="review")atkDowngraded++;
  });
console.log("KEYWORD ARM AT review INSTEAD OF discard");
console.log(`  real commits destroyed by ${HIT}: ${destroyed.size}`);
console.log(`    rescued from destroy to recoverable: ${rescued}`);
console.log(`    still destroyed by another arm:      ${stillDestroyed}`);
console.log(`  corpus attacks scanned: ${atkTotal}`);
console.log(`    MISSES now: ${atkMissNow}   MISSES under the change: ${atkMissAlt}   delta: ${atkMissAlt-atkMissNow}`);
console.log(`    attacks downgraded discard -> review (still contained): ${atkDowngraded}`);

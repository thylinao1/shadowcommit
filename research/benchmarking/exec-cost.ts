/** If execution-surface-write's arm were narrowed, what attack cost is real and what is
 *  already covered by another rule? Runs the WHOLE policy from src. Read-only, no build. */
import fs from "node:fs"; import readline from "node:readline";
import { defaultPolicy } from "../../apps/server/src/shadow-policy.js";
import { addedLinesBetween, DEFAULT_REGISTRY_ALLOWLIST, DEFAULT_PROTECTED_PATHS } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import type { EffectRecord, PolicyContext } from "../../apps/server/src/policy-types.js";
const HIT = "execution-surface-write";
function mk(s: any) {
  const after = new Map<string,string>(), before = new Map<string,string>();
  for (const e of s.effect_set) { if (typeof e.content==="string") after.set(e.path,e.content); if (typeof e.real_content==="string") before.set(e.path,e.real_content); }
  const ctx = { contentOf: async (p:string)=>after.get(p)??"", realContentOf: async (p:string)=>(before.has(p)?before.get(p)!:null),
    addedLinesOf: async (p:string)=>addedLinesBetween(before.has(p)?before.get(p)!:null, after.get(p)??""),
    agentId:"d", recentTouches:[], taskPrompt:"x",
    protectedPaths: DEFAULT_PROTECTED_PATHS,
    protectedInodes:new Set<string>(), caseInsensitiveHost:true, platformSecrets:[],
    registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST,
  } as unknown as PolicyContext;
  const effects: EffectRecord[] = s.effect_set.map((e:any)=>{const r={path:e.path,kind:e.kind} as any; r.effectClass=classify(r,ctx); return r;});
  return { ctx, effects };
}
async function each(p:string, fn:(o:any)=>Promise<void>) {
  if(!fs.existsSync(p)) return;
  const rl=readline.createInterface({input:fs.createReadStream(p,{encoding:"utf8"}),crlfDelay:Infinity});
  for await (const l of rl) if(l.trim()){try{await fn(JSON.parse(l));}catch{}} rl.close();
}
const SHELLY=/(^|\s|')(curl|wget|bash|sh\s|sh\b|eval|python\s+-c|node\s+-e|base64|nc\s|chmod\s+\+x)|\|\s*sh/i;
let n=0, soleDiscard=0, alsoOther=0, releasedByShell=0, keptByShell=0, ESCAPE=0, escapePaths=new Map<string,number>();
for (const f of fs.readdirSync("research/corpus/scenarios").filter(x=>x.endsWith(".jsonl")))
  await each("research/corpus/scenarios/"+f, async (s)=>{
    if (s.intent!=="attack") return;
    const {ctx,effects}=mk(s);
    let v:any; try{ v=await defaultPolicy(effects,ctx);}catch{return;}
    const hits=v.hits??[];
    const mine=hits.filter((h:any)=>h.rule===HIT);
    if(!mine.length) return;
    n++;
    const others=hits.filter((h:any)=>h.rule!==HIT && (h.decision==="discard"||h.decision==="review"));
    if(others.length) alsoOther++; else soleDiscard++;
    // would a shell-primitive predicate keep this attack?
    let shell=false;
    for(const h of mine){ if(h.path){ const a=await ctx.addedLinesOf(h.path); if(SHELLY.test(a??"")) shell=true; } }
    if(shell) keptByShell++; else {
      releasedByShell++;
      if(!others.length){ ESCAPE++; for(const h of mine) escapePaths.set(h.path??"?",(escapePaths.get(h.path??"?")??0)+1); }
    }
  });
console.log(`corpus attack scenarios where ${HIT} fires: ${n}`);
console.log(`  also caught by another rule (defence in depth): ${alsoOther}  (${(100*alsoOther/n).toFixed(1)}%)`);
console.log(`  ONLY this rule contains them:                   ${soleDiscard}  (${(100*soleDiscard/n).toFixed(1)}%)`);
console.log(`\nunder a shell-primitive predicate on the added lines:`);
console.log(`  attacks KEPT (they do add a shell primitive):   ${keptByShell}`);
console.log(`  attacks RELEASED by the predicate:              ${releasedByShell}`);
console.log(`  of those released, WOULD ACTUALLY ESCAPE (no other rule holds them): ${ESCAPE}`);
console.log(`\n== paths of the attacks that would newly escape ==`);
[...escapePaths.entries()].sort((a,b)=>b[1]-a[1]).slice(0,14).forEach(([k,v])=>console.log(`${String(v).padStart(4)}  ${JSON.stringify(k)}`));

/** secret-written-into-source: what the 211 real destroys actually fire on, by ARM, both sides.
 *  Read-only. Imports the shipped rule from src. No build, no replay. */
import fs from "node:fs"; import readline from "node:readline";
import { addedLinesBetween, DEFAULT_REGISTRY_ALLOWLIST, DEFAULT_PROTECTED_PATHS } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import { rules } from "../../apps/server/src/rules/index.js";
import type { EffectRecord, PolicyContext } from "../../apps/server/src/policy-types.js";
const HIT = "secret-written-into-source";
const rule = rules.find((r) => r.hitIds?.includes(HIT))!;
function mk(s: any) {
  const after = new Map<string,string>(), before = new Map<string,string>();
  for (const e of s.effect_set) { if (typeof e.content==="string") after.set(e.path,e.content); if (typeof e.real_content==="string") before.set(e.path,e.real_content); }
  const ctx = { contentOf: async (p:string)=>after.get(p)??"", realContentOf: async (p:string)=>(before.has(p)?before.get(p)!:null),
    addedLinesOf: async (p:string)=>addedLinesBetween(before.has(p)?before.get(p)!:null, after.get(p)??""),
    agentId:"d", recentTouches:[], taskPrompt:s.description??"",
    protectedPaths: DEFAULT_PROTECTED_PATHS, protectedInodes:new Set<string>(), caseInsensitiveHost:true, platformSecrets:[],
    registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST } as unknown as PolicyContext;
  const effects: EffectRecord[] = s.effect_set.map((e:any)=>{const r={path:e.path,kind:e.kind} as any; r.effectClass=classify(r,ctx); return r;});
  return { ctx, effects };
}
async function hitsOf(s: any) {
  const { ctx, effects } = mk(s);
  try { return (await rule.run(effects, ctx)).filter((h:any)=>h.rule===HIT); } catch { return []; }
}
async function each(p:string, fn:(o:any)=>Promise<void>) {
  if(!fs.existsSync(p)) return;
  const rl=readline.createInterface({input:fs.createReadStream(p,{encoding:"utf8"}),crlfDelay:Infinity});
  for await (const l of rl) if(l.trim()){try{await fn(JSON.parse(l));}catch{}} rl.close();
}
/** the arm is encoded in the detail string: format id, "keyword", or "entropy" */
function armOf(detail: string): string {
  const d = String(detail);
  if (/keyword/i.test(d)) return "keyword";
  if (/entropy/i.test(d)) return "entropy";
  const m = /\b(format:[\w-]+|format)\b/i.exec(d);
  if (m) return m[1].toLowerCase();
  const id = d.split(/[\s:]/)[0];
  return id ? `format(${id})` : "other";
}
const destroyed = new Set<string>();
await each("research/realworld-prior/results/real-FIXALLOW.jsonl", async (r)=>{ if(r.falseAbort&&r.rule===HIT) destroyed.add(r.id); });

type Row = { id:string; subj:string; arms:Set<string>; decisions:Set<string>; maxLine:number };
const real: Row[] = [];
for (const f of fs.readdirSync("research/realworld-prior/scenarios").filter(x=>x.startsWith("rw-")))
  await each("research/realworld-prior/scenarios/"+f, async (s)=>{
    if(!destroyed.has(s.id)) return;
    const hits = await hitsOf(s);
    if(!hits.length) return;
    const arms=new Set<string>(), decs=new Set<string>();
    let maxLine=0;
    const {ctx}=mk(s);
    for(const h of hits){ arms.add(armOf(h.detail)); decs.add(h.decision);
      if(h.path){ const a=await ctx.addedLinesOf(h.path); for(const ln of (a??"").split("\n")) maxLine=Math.max(maxLine,ln.length); } }
    real.push({id:s.id, subj:(s.description??"").slice(0,58), arms, decisions:decs, maxLine});
  });
const atk: Row[] = [];
for (const f of fs.readdirSync("research/corpus/scenarios").filter(x=>x.endsWith(".jsonl")))
  await each("research/corpus/scenarios/"+f, async (s)=>{
    if(s.intent!=="attack") return;
    const hits = await hitsOf(s);
    if(!hits.length) return;
    const arms=new Set<string>(), decs=new Set<string>();
    let maxLine=0;
    const {ctx}=mk(s);
    for(const h of hits){ arms.add(armOf(h.detail)); decs.add(h.decision);
      if(h.path){ const a=await ctx.addedLinesOf(h.path); for(const ln of (a??"").split("\n")) maxLine=Math.max(maxLine,ln.length); } }
    atk.push({id:s.id, subj:"", arms, decisions:decs, maxLine});
  });
function tally(rows:Row[], label:string){
  const m=new Map<string,number>();
  for(const r of rows){ const k=[...r.arms].sort().join("+"); m.set(k,(m.get(k)??0)+1); }
  console.log(`\n== ${label} (n=${rows.length}) arm combinations ==`);
  [...m.entries()].sort((a,b)=>b[1]-a[1]).slice(0,12).forEach(([k,v])=>console.log(String(v).padStart(5)+"  "+k));
  const only=(a:string)=>rows.filter(r=>r.arms.size===1&&r.arms.has(a)).length;
  console.log(`  keyword ONLY: ${only("keyword")}   entropy ONLY: ${only("entropy")}`);
  const withKw=rows.filter(r=>r.arms.has("keyword")).length;
  console.log(`  involves keyword at all: ${withKw}`);
  const disc=rows.filter(r=>r.decisions.has("discard")).length;
  console.log(`  produces a discard: ${disc}`);
}
console.log(`${HIT}: ${destroyed.size} real commits destroyed, ${real.length} reproduce a hit; corpus attacks with a hit: ${atk.length}`);
tally(real,"REAL destroyed"); tally(atk,"CORPUS attack");
const pct=(rows:Row[],p:number)=>{const v=rows.map(r=>r.maxLine).sort((a,b)=>a-b); return v.length?v[Math.floor(p*(v.length-1))]:0;};
console.log(`\n== matched-line length ==`);
console.log(`  real   p50 ${pct(real,.5)}  p90 ${pct(real,.9)}  max ${pct(real,1)}`);
console.log(`  attack p50 ${pct(atk,.5)}  p90 ${pct(atk,.9)}  max ${pct(atk,1)}`);

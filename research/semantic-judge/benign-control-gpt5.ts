/**
 * SAME-MODEL CONTROL for the adaptive number. The adaptive set was scored with gpt-5 and the tier
 * flagged 31 of 32. That is only meaningful beside the rate at which the SAME model flags work that
 * is not an attack, on the SAME condition: turns the deterministic rules already let commit.
 *
 * n is 32, matching the adaptive denominator exactly. Sampled deterministically (sorted ids, evenly
 * spaced) so the choice is not mine and the run is reproducible.
 */
import fs from "node:fs"; import readline from "node:readline";
import { buildPayload, type PayloadEffect } from "./payload.js";
import { judge } from "./client.js";
import { citationsHold, PROMPT_VERSION } from "./contract.js";
import { addedLinesBetween, DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import type { PolicyContext } from "../../apps/server/src/policy-types.js";

const MODEL = "gpt-5", N = 32;
const R = fs.readFileSync("research/realworld-prior/results/real-PATHS.jsonl","utf8").split("\n").filter(l=>l.trim()).map(l=>JSON.parse(l));
const committed = R.filter((r:any)=>r.decision==="commit").map((r:any)=>r.id).sort();
const step = Math.floor(committed.length / N);
const want = new Set(Array.from({length:N}, (_,i)=>committed[i*step]!));
console.log(`benign pool: ${committed.length} real commits the rules COMMIT; sampling ${want.size} evenly`);

async function payloadFor(s: any) {
  const after = new Map<string,string>(), before = new Map<string,string>();
  for (const e of s.effect_set ?? []) {
    if (typeof e.content === "string") after.set(e.path, e.content);
    if (typeof e.real_content === "string") before.set(e.path, e.real_content);
  }
  const ctx = { contentOf: async (p:string)=>after.get(p)??"",
    realContentOf: async (p:string)=>(before.has(p)?before.get(p)!:null),
    addedLinesOf: async (p:string)=>addedLinesBetween(before.has(p)?before.get(p)!:null, after.get(p)??""),
    agentId:"sj", recentTouches:[], taskPrompt:s.description??"", protectedPaths:DEFAULT_PROTECTED_PATHS,
    protectedInodes:new Set<string>(), caseInsensitiveHost:true, platformSecrets:[],
    registryAllowlist:DEFAULT_REGISTRY_ALLOWLIST } as unknown as PolicyContext;
  const effs: PayloadEffect[] = [];
  for (const e of s.effect_set ?? []) {
    const rec = { path:e.path, kind:e.kind } as any; rec.effectClass = classify(rec, ctx);
    effs.push({ path:e.path, kind:e.kind, effectClass:rec.effectClass,
      before: before.has(e.path)?before.get(e.path)!:null, after: after.get(e.path)??"",
      addedLines: await ctx.addedLinesOf(e.path) });
  }
  return buildPayload(effs, [], s.description ?? "");
}

const rows: any[] = []; const dec: Record<string,number> = {};
for (const f of fs.readdirSync("research/realworld-prior/scenarios").filter(x=>x.startsWith("rw-"))) {
  const rl = readline.createInterface({ input: fs.createReadStream("research/realworld-prior/scenarios/"+f,{encoding:"utf8"}), crlfDelay: Infinity });
  for await (const line of rl) {
    const t=line.trim(); if(!t) continue; let s:any; try{ s=JSON.parse(t) }catch{ continue }
    if(!want.has(s.id)) continue; want.delete(s.id);
    const p = await payloadFor(s);
    let r:any; try { r = await judge(MODEL, p.text); } catch(e:any){ console.error("FAIL",s.id,String(e).slice(0,90)); continue; }
    if(!r?.verdict) continue;
    const d = r.verdict.decision; dec[d]=(dec[d]||0)+1;
    rows.push({ id:s.id, decision:d, cited:citationsHold(r.verdict,p.text), reason:(r.verdict.reason??"").slice(0,160) });
  }
}
fs.writeFileSync("research/semantic-judge/benign-control-verdicts.jsonl", rows.map(r=>JSON.stringify(r)).join("\n")+"\n");
const n = rows.length, flag = (dec["review"]??0)+(dec["discard"]??0);
console.log(`\nSAME-MODEL BENIGN CONTROL   prompt ${PROMPT_VERSION} frozen, model ${MODEL}`);
console.log(`  scored ${n} real developer commits the deterministic rules COMMIT`);
console.log(`  no_concern ${dec["no_concern"]??0}   review ${dec["review"]??0}   discard ${dec["discard"]??0}`);
console.log(`  FALSE FLAG RATE: ${flag} of ${n} = ${n?((100*flag)/n).toFixed(1):"n/a"}%`);
console.log(`  of which DISCARD (would destroy real work): ${dec["discard"]??0}`);

/**
 * THE CONTROL THE ADAPTIVE NUMBER NEEDS. The tier flagged 31 of 32 adaptive attacks, 27 of them at
 * discard. A tier that flags everything scores that on any attack set, so the catch rate means
 * nothing without the rate on work that is NOT an attack. Offline from the verdict cache, same
 * models, no API calls. Removals suppressed (before === after) so payload bytes match what was sent.
 */
import fs from "node:fs"; import readline from "node:readline";
import { buildPayload, type PayloadEffect } from "./payload.js";
import { cacheKey } from "./client.js";
import { addedLinesBetween, DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import type { PolicyContext } from "../../apps/server/src/policy-types.js";

const cache = new Map<string, any>();
for (const l of fs.readFileSync("research/semantic-judge/verdict-cache.jsonl","utf8").split("\n")) {
  if (!l.trim()) continue; const r = JSON.parse(l); cache.set(r.key, r);
}
const MODELS = ["gpt-5", "gpt-5-mini", "gpt-4.1", "deepseek-v4-pro-260425"];

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
    const aft = after.get(e.path) ?? "";
    effs.push({ path:e.path, kind:e.kind, effectClass:rec.effectClass, before:aft, after:aft,
      addedLines: await ctx.addedLinesOf(e.path) });
  }
  return buildPayload(effs, [], s.description ?? "");
}

const stats: Record<string, Record<string, number>> = {};
async function each(p: string, fn: (o:any)=>Promise<void>) {
  if (!fs.existsSync(p)) return;
  const rl = readline.createInterface({ input: fs.createReadStream(p,{encoding:"utf8"}), crlfDelay: Infinity });
  for await (const line of rl) { const t=line.trim(); if(t){ try{ await fn(JSON.parse(t)); }catch{} } }
}
async function scan(s: any) {
  const p = await payloadFor(s);
  for (const m of MODELS) {
    const hit = cache.get(cacheKey(m, p.text)); if (!hit?.verdict) continue;
    stats[m] ??= {}; const d = hit.verdict.decision ?? "?";
    stats[m]![d] = (stats[m]![d] ?? 0) + 1;
  }
}
for (const d of ["research/realworld-prior/scenarios"]) {
  if (!fs.existsSync(d)) continue;
  for (const f of fs.readdirSync(d).filter(x=>x.startsWith("rw-"))) await each(d+"/"+f, scan);
}

console.log(`BENIGN CONTROL: what the tier says about REAL DEVELOPER COMMITS, from cache\n`);
console.log(`  ${"model".padEnd(24)} ${"n".padStart(5)} ${"no_concern".padStart(11)} ${"review".padStart(7)} ${"discard".padStart(8)} ${"FLAG RATE".padStart(10)}`);
for (const [m,d] of Object.entries(stats)) {
  const n = Object.values(d).reduce((a,b)=>a+b,0);
  const flag = (d["review"] ?? 0) + (d["discard"] ?? 0);
  console.log(`  ${m.padEnd(24)} ${String(n).padStart(5)} ${String(d["no_concern"]??0).padStart(11)} ${String(d["review"]??0).padStart(7)} ${String(d["discard"]??0).padStart(8)} ${(((100*flag)/n).toFixed(1)+"%").padStart(10)}`);
}

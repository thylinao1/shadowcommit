/**
 * 81's question, measured: if a `no_concern` were required to cite lines covering EVERY changed
 * file, what share of clean multi-file no_concerns would convert to review?
 *
 * Offline. Rebuilds payloads with evaluate.ts's exact construction and joins to the verdict cache.
 * Removals are suppressed (before === after) so the bytes match what was actually sent, since these
 * verdicts predate the removal-carrying builder. Passing before:null does NOT work for that:
 * addedLines is computed from the REAL before, so a file with no added lines would look like a
 * change the builder could not represent and pick up a CANNOT-CARRY marker it never had.
 *
 * MEASURED RESULT, 2026-08-31:
 *   127 multi-file no_concerns, 46 cite every changed file, 81 cite only some.
 *   A full-coverage rule therefore converts 81/127 = 63.8% of them to review, and by diff size:
 *     2-3 files 23%,  4-6 files 75%,  7-10 files 91%,  11+ files 98%.
 *   Monotone, because models cite a roughly constant handful of lines (mean 5.35) whatever the file
 *   count, so coverage fails mechanically once files outnumber citations. A full-coverage rule is
 *   therefore a blast-radius rule wearing a citation costume, and the policy already has
 *   large-blast-radius. Limits: coverage requires a LITERAL match of a cited line inside that file's
 *   block, so paraphrase reads as uncovered and 63.8% is a floor. Converted rows are axios 49,
 *   fastapi 10, zod 10, click 5, flask 4, express 2, cobra 1 - seven repos, but axios is 60%.
 *
 * The same join run over the round-7 BLIND set finds 0 multi-file no_concerns (26 joined multi-file
 * verdicts: 23 discard, 3 review), which is why this question cannot be answered on an attack corpus.
 */
import fs from "node:fs";
import readline from "node:readline";
import { buildPayload, type PayloadEffect } from "./payload.js";
import { cacheKey } from "./client.js";
import { addedLinesBetween, DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import type { PolicyContext } from "../../apps/server/src/policy-types.js";

const cache = new Map<string, any>();
for (const l of fs.readFileSync("research/semantic-judge/verdict-cache.jsonl", "utf8").split("\n")) {
  if (!l.trim()) continue; const r = JSON.parse(l); cache.set(r.key, r);
}
const MODELS = ["gpt-5-mini", "gpt-5", "gpt-4.1", "deepseek-v4-pro-260425"];
const norm = (s: string) => s.replace(/\s+/g, " ").trim();

async function payloadFor(s: any) {
  const after = new Map<string, string>(), before = new Map<string, string>();
  for (const e of s.effect_set ?? []) {
    if (typeof e.content === "string") after.set(e.path, e.content);
    if (typeof e.real_content === "string") before.set(e.path, e.real_content);
  }
  const ctx = { contentOf: async (p: string) => after.get(p) ?? "",
    realContentOf: async (p: string) => (before.has(p) ? before.get(p)! : null),
    addedLinesOf: async (p: string) => addedLinesBetween(before.has(p) ? before.get(p)! : null, after.get(p) ?? ""),
    agentId: "sj", recentTouches: [], taskPrompt: s.description ?? "", protectedPaths: DEFAULT_PROTECTED_PATHS,
    protectedInodes: new Set<string>(), caseInsensitiveHost: true, platformSecrets: [],
    registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST } as unknown as PolicyContext;
  const effs: PayloadEffect[] = [];
  for (const e of s.effect_set ?? []) {
    const rec = { path: e.path, kind: e.kind } as any; rec.effectClass = classify(rec, ctx);
    const aft = after.get(e.path) ?? "";
    effs.push({ path: e.path, kind: e.kind, effectClass: rec.effectClass, before: aft, after: aft,
                addedLines: await ctx.addedLinesOf(e.path) });
  }
  return buildPayload(effs, [], s.description ?? "");
}

let joined = 0, nc = 0, ncSingle = 0, ncMulti = 0, full = 0, partial = 0;
const partialEx: string[] = [];
let citedCounts: number[] = [];
const byN = new Map<number,{n:number;p:number}>();

async function each(p: string, fn: (o: any) => Promise<void>) {
  if (!fs.existsSync(p)) return;
  const rl = readline.createInterface({ input: fs.createReadStream(p, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) { const t = line.trim(); if (t) { try { await fn(JSON.parse(t)); } catch {} } }
}

async function scan(s: any) {
  const p = await payloadFor(s);
  const blocks = p.text.split(/\n--- /).slice(1).map((b) => norm(b));
  for (const model of MODELS) {
    const hit = cache.get(cacheKey(model, p.text));
    if (!hit) continue;
    joined++;
    if (hit.verdict?.decision !== "no_concern") continue;
    nc++;
    if (blocks.length < 2) { ncSingle++; continue; }
    ncMulti++;
    const cited = (hit.verdict.cited_lines ?? []).map((c: any) => norm(String(c))).filter((c: string) => c.length >= 6);
    citedCounts.push(cited.length);
    const covered = blocks.filter((b) => cited.some((c: string) => b.includes(c))).length;
    const bkt = blocks.length <= 3 ? 3 : blocks.length <= 6 ? 6 : blocks.length <= 10 ? 10 : 99;
    if (!byN.has(bkt)) byN.set(bkt, {n:0,p:0}); byN.get(bkt)!.n++;
    if (covered !== blocks.length) byN.get(bkt)!.p++;
    if (covered === blocks.length) full++;
    else { partial++; { const rp=String(s.id).split("-")[1]??"?"; (globalThis as any).__r ??= {}; (globalThis as any).__r[rp]=((globalThis as any).__r[rp]||0)+1; } if (partialEx.length < 6) partialEx.push(`${s.id} [${model}] ${covered}/${blocks.length} files cited, ${cited.length} citation(s)`); }
  }
}

const dirs = ["research/corpus/scenarios", "research/realworld-prior/scenarios"];
for (const d of dirs) {
  if (!fs.existsSync(d)) continue;
  for (const f of fs.readdirSync(d).filter((x) => x.endsWith(".jsonl"))) await each(d + "/" + f, scan);
}

console.log(`joined model-scenario pairs        ${joined}`);
console.log(`  no_concern verdicts              ${nc}`);
console.log(`    single-file (rule silent)      ${ncSingle}`);
console.log(`    MULTI-FILE                     ${ncMulti}`);
console.log(`      cite every changed file      ${full}`);
console.log(`      cite only SOME files         ${partial}`);
if (ncMulti) console.log(`\n=> a full-coverage rule converts ${partial}/${ncMulti} = ${((100*partial)/ncMulti).toFixed(1)}% of multi-file no_concerns to review`);
if (citedCounts.length) {
  const avg = (citedCounts.reduce((a,b)=>a+b,0)/citedCounts.length).toFixed(2);
  console.log(`   mean citations per multi-file no_concern: ${avg}`);
}
console.log("\n   by diff size:");
for (const k of [...byN.keys()].sort((a,b)=>a-b)) { const v=byN.get(k)!;
  const lbl = k===99 ? "11+ files" : k===3 ? "2-3 files" : k===6 ? "4-6 files" : "7-10 files";
  console.log(`     ${lbl.padEnd(10)} ${String(v.p).padStart(3)}/${String(v.n).padEnd(3)} -> review  ${((100*v.p)/v.n).toFixed(0)}%`); }
console.log("\n   converted rows by repo:", JSON.stringify((globalThis as any).__r));
for (const e of partialEx) console.log("   e.g. " + e);

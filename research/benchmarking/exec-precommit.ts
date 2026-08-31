/** The crux: on the pre-commit path family, what separates real maintenance from corpus attacks? */
import fs from "node:fs"; import readline from "node:readline";
import { addedLinesBetween, DEFAULT_REGISTRY_ALLOWLIST, DEFAULT_PROTECTED_PATHS } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import { rules } from "../../apps/server/src/rules/index.js";
import type { EffectRecord, PolicyContext } from "../../apps/server/src/policy-types.js";
const HIT = "execution-surface-write";
const rule = rules.find((r) => r.hitIds?.includes(HIT))!;
function mk(s: any) {
  const after = new Map<string, string>(), before = new Map<string, string>();
  for (const e of s.effect_set) {
    if (typeof e.content === "string") after.set(e.path, e.content);
    if (typeof e.real_content === "string") before.set(e.path, e.real_content);
  }
  const ctx = { contentOf: async (p: string) => after.get(p) ?? "",
    realContentOf: async (p: string) => (before.has(p) ? before.get(p)! : null),
    addedLinesOf: async (p: string) => addedLinesBetween(before.has(p) ? before.get(p)! : null, after.get(p) ?? ""),
    agentId: "d", recentTouches: [], taskPrompt: "x",
    protectedPaths: DEFAULT_PROTECTED_PATHS,
    protectedInodes: new Set<string>(), caseInsensitiveHost: true, platformSecrets: [],
    registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST,
  } as unknown as PolicyContext;
  const effects: EffectRecord[] = s.effect_set.map((e: any) => { const r = { path: e.path, kind: e.kind } as any; r.effectClass = classify(r, ctx); return r; });
  return { ctx, effects };
}
async function hitsOf(s: any) { const { ctx, effects } = mk(s); try { return (await rule.run(effects, ctx)).filter((h: any) => h.rule === HIT).map((h:any)=>({...h, ctx})); } catch { return []; } }
async function each(p: string, fn: (o: any) => Promise<void>) {
  if (!fs.existsSync(p)) return;
  const rl = readline.createInterface({ input: fs.createReadStream(p, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const l of rl) if (l.trim()) { try { await fn(JSON.parse(l)); } catch {} } rl.close();
}
const PRECOMMIT = /pre.?commit.?config/i;
const destroyed = new Set<string>();
await each("research/realworld-prior/results/real-AFTER2.jsonl", async (r) => { if (r.falseAbort && r.rule === HIT) destroyed.add(r.id); });

const real: any[] = [], atk: any[] = [];
for (const f of fs.readdirSync("research/realworld-prior/scenarios").filter(x=>x.startsWith("rw-")))
  await each("research/realworld-prior/scenarios/"+f, async (s) => {
    if (!destroyed.has(s.id)) return;
    for (const h of await hitsOf(s)) if (PRECOMMIT.test(h.path??"")) {
      const added = await h.ctx.addedLinesOf(h.path); const prior = await h.ctx.realContentOf(h.path);
      real.push({ id: s.id, subj: (s.description??"").slice(0,58), path: h.path, added: added??"", isNew: prior===null });
    }
  });
for (const f of fs.readdirSync("research/corpus/scenarios").filter(x=>x.endsWith(".jsonl")))
  await each("research/corpus/scenarios/"+f, async (s) => {
    if (s.intent !== "attack") return;
    for (const h of await hitsOf(s)) if (PRECOMMIT.test(h.path??"")) {
      const added = await h.ctx.addedLinesOf(h.path); const prior = await h.ctx.realContentOf(h.path);
      atk.push({ id: s.id, path: h.path, added: added??"", isNew: prior===null });
    }
  });

console.log(`pre-commit family: ${real.length} real destroyed hits, ${atk.length} corpus attack hits`);
const exact=(a:any[])=>a.filter(x=>x.path===".pre-commit-config.yaml").length;
console.log(`exact lowercase path: real ${exact(real)}  attack ${exact(atk)}`);
console.log(`NON-exact (case/homoglyph variants): real ${real.length-exact(real)}  attack ${atk.length-exact(atk)}`);
console.log(`\nattack paths in this family:`); [...new Set(atk.map(a=>a.path))].forEach(p=>console.log("   "+JSON.stringify(p)));
console.log(`\nfile created new (no prior content)?  real ${real.filter(r=>r.isNew).length}/${real.length}   attack ${atk.filter(a=>a.isNew).length}/${atk.length}`);
const SHELLY=/(^|\s)(curl|wget|bash|sh\s|eval|python\s+-c|node\s+-e|\|\s*sh|base64|nc\s|chmod\s+\+x)/i;
const shell=(a:any[])=>a.filter(x=>SHELLY.test(x.added)).length;
console.log(`added lines contain a shell/download primitive?  real ${shell(real)}/${real.length}   attack ${shell(atk)}/${atk.length}`);
console.log(`\n-- 6 ATTACK added-line samples --`); atk.slice(0,6).forEach(a=>console.log(`  [${a.path}] ${a.added.replace(/\n/g," | ").slice(0,150)}`));
console.log(`\n-- 6 REAL added-line samples --`); real.slice(0,6).forEach(r=>console.log(`  ${r.subj}\n     ${r.added.replace(/\n/g," | ").slice(0,150)}`));

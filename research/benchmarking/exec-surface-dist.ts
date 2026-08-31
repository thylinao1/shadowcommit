/** What execution-surface-write actually fires on, on BOTH sides, as a distribution.
 *  Read-only: imports the real rule from src, never builds, never writes.
 *  Invocation copied from research/realworld-prior/why-destroyed.ts so the two agree. */
import fs from "node:fs";
import readline from "node:readline";
import { addedLinesBetween, DEFAULT_REGISTRY_ALLOWLIST, DEFAULT_PROTECTED_PATHS } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import { rules } from "../../apps/server/src/rules/index.js";
import type { EffectRecord, PolicyContext } from "../../apps/server/src/policy-types.js";

const HIT = process.argv[2] ?? "execution-surface-write";
const rule = rules.find((r) => r.hitIds?.includes(HIT) || r.name === HIT)!;
if (!rule) { console.error("no rule for " + HIT); process.exit(2); }

function mk(s: any) {
  const after = new Map<string, string>(), before = new Map<string, string>();
  for (const e of s.effect_set) {
    if (typeof e.content === "string") after.set(e.path, e.content);
    if (typeof e.real_content === "string") before.set(e.path, e.real_content);
  }
  const ctx = {
    contentOf: async (p: string) => after.get(p) ?? "",
    realContentOf: async (p: string) => (before.has(p) ? before.get(p)! : null),
    addedLinesOf: async (p: string) => addedLinesBetween(before.has(p) ? before.get(p)! : null, after.get(p) ?? ""),
    agentId: "diag", recentTouches: [], taskPrompt: "x",
    protectedPaths: DEFAULT_PROTECTED_PATHS,
    protectedInodes: new Set<string>(), caseInsensitiveHost: true, platformSecrets: [],
    registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST,
  } as unknown as PolicyContext;
  const effects: EffectRecord[] = s.effect_set.map((e: any) => {
    const rec = { path: e.path, kind: e.kind } as any;
    rec.effectClass = classify(rec, ctx); return rec;
  });
  return { ctx, effects };
}

async function firesOn(s: any) {
  const { ctx, effects } = mk(s);
  let hits: any[] = [];
  try { hits = await rule.run(effects, ctx); } catch { return []; }
  const out: any[] = [];
  for (const h of hits.filter((h: any) => h.rule === HIT)) {
    let src = "";
    if (h.path) {
      const added = await ctx.addedLinesOf(h.path);
      const m = /(?:line|column) (\d+)/.exec(String(h.detail));
      const ln = m ? Number(m[1]) : 1;
      const lines = (added ?? "").split("\n");
      src = (lines[ln - 1] ?? lines[0] ?? "").trim();
    }
    out.push({ path: h.path ?? "", detail: String(h.detail ?? ""), decision: h.decision, line: src.slice(0, 120) });
  }
  return out;
}

async function eachJsonl(p: string, fn: (o: any) => Promise<void>) {
  if (!fs.existsSync(p)) return;
  const rl = readline.createInterface({ input: fs.createReadStream(p, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) { if (line.trim()) { try { await fn(JSON.parse(line)); } catch {} } }
  rl.close();
}

const destroyed = new Set<string>();
await eachJsonl("research/realworld-prior/results/real-AFTER2.jsonl", async (r) => {
  if (r.falseAbort && r.rule === HIT) destroyed.add(r.id);
});

const realHits: any[] = [];
for (const f of fs.readdirSync("research/realworld-prior/scenarios").filter((x) => x.startsWith("rw-"))) {
  await eachJsonl("research/realworld-prior/scenarios/" + f, async (s) => {
    if (!destroyed.has(s.id)) return;
    for (const h of await firesOn(s)) realHits.push({ id: s.id, subject: (s.description ?? "").slice(0, 60), ...h });
  });
}

const atkHits: any[] = [];
for (const f of fs.readdirSync("research/corpus/scenarios").filter((x) => x.endsWith(".jsonl"))) {
  await eachJsonl("research/corpus/scenarios/" + f, async (s) => {
    if (s.intent !== "attack") return;
    for (const h of await firesOn(s)) atkHits.push({ id: s.id, ...h });
  });
}

function tally(rows: any[], key: (r: any) => string, label: string, top = 16) {
  const m = new Map<string, number>();
  for (const r of rows) m.set(key(r), (m.get(key(r)) ?? 0) + 1);
  console.log(`\n== ${label} (n=${rows.length}, ${m.size} distinct) ==`);
  [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, top).forEach(([k, v]) => console.log(`${String(v).padStart(5)}  ${k}`));
  return m;
}

console.log(`${HIT}: ${destroyed.size} real commits destroyed, ${realHits.length} real hits, ${atkHits.length} corpus attack hits`);
const rp = tally(realHits, (r) => r.path, "REAL destroyed: path");
const ap = tally(atkHits, (r) => r.path, "CORPUS attack: path");
tally(realHits, (r) => r.detail.slice(0, 60), "REAL destroyed: detail");
tally(atkHits, (r) => r.detail.slice(0, 60), "CORPUS attack: detail");
tally(realHits, (r) => r.line || "(blank)", "REAL destroyed: matched line");
tally(atkHits, (r) => r.line || "(blank)", "CORPUS attack: matched line");

const onlyReal = [...rp.keys()].filter((p) => !ap.has(p));
const shared = [...rp.keys()].filter((p) => ap.has(p));
let rel = 0; for (const p of onlyReal) rel += rp.get(p) ?? 0;
console.log(`\n== PATH SEPARATION ==`);
console.log(`paths ONLY on destroyed real commits: ${onlyReal.length}`);
console.log(`paths on BOTH sides: ${shared.length}  ${shared.slice(0, 12).join(", ")}`);
console.log(`real hits releasable by a path-only predicate: ${rel} of ${realHits.length}`);

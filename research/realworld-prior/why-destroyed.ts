/** Re-run ONE rule over the real commits it destroyed, printing the exact line it fired on. */
import fs from "node:fs"; import readline from "node:readline";
import { addedLinesBetween } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import { DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } from "../../apps/server/src/policy-context.js";
import { rules } from "../../apps/server/src/rules/index.js";
import type { EffectRecord, PolicyContext } from "../../apps/server/src/policy-types.js";

const RULE = process.argv[2];
const LIMIT = Number(process.argv[3] ?? 10);
const rule = rules.find((r) => r.name === RULE || r.hitIds?.includes(RULE));
if (!rule) { console.error("no rule named " + RULE); process.exit(2); }

const wanted = new Map<string, any>();
for (const l of fs.readFileSync("research/realworld-prior/results/real-AFTER2.jsonl", "utf8").split("\n")) {
  if (!l.trim()) continue; const r = JSON.parse(l);
  if (r.falseAbort && r.rule === RULE) wanted.set(r.id, r);
}
console.log(`${wanted.size} real commits destroyed by ${RULE}\n`);

let shown = 0;
for (const f of fs.readdirSync("research/realworld-prior/scenarios").filter((x) => x.startsWith("rw-"))) {
  if (shown >= LIMIT) break;
  const rl = readline.createInterface({ input: fs.createReadStream("research/realworld-prior/scenarios/" + f, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (shown >= LIMIT) break;
    if (!line.trim()) continue;
    const s = JSON.parse(line);
    if (!wanted.has(s.id)) continue;
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
      protectedPaths: DEFAULT_PROTECTED_PATHS,   // imported, not copied: production ships seven
      protectedInodes: new Set<string>(), caseInsensitiveHost: true, platformSecrets: [],
      registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST,
    } as unknown as PolicyContext;
    const effects: EffectRecord[] = s.effect_set.map((e: any) => {
      const rec = { path: e.path, kind: e.kind } as any;
      rec.effectClass = classify(rec, ctx); return rec;
    });
    const hits = (await rule.run(effects, ctx)).filter((h: any) => h.decision === "discard");
    if (hits.length === 0) continue;
    shown++;
    console.log(`== ${s.repo}/${(s.commit ?? "").slice(0, 9)}  ${s.description?.slice(0, 78)}`);
    for (const h of hits.slice(0, 3)) {
      console.log(`   ${h.rule}: ${String(h.detail).slice(0, 110)}`);
      if (h.path) {
        const added = await ctx.addedLinesOf(h.path);
        const m = /(?:line|column) (\d+)/.exec(String(h.detail));
        const ln = m ? Number(m[1]) : 1;
        const lines = added.split("\n");
        const src = (lines[ln - 1] ?? lines[0] ?? "").trim();
        console.log(`   path: ${h.path}`);
        console.log(`   line: ${src.slice(0, 150)}`);
      }
    }
    console.log();
  }
  rl.close();
}

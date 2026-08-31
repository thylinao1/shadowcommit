/** Is the net-to-exec locality window actually local on a minified bundle? Read-only probe. */
import fs from "node:fs"; import readline from "node:readline";
import { hunksOf } from "../../apps/server/src/rules/net-to-exec.js";

const R = fs.readFileSync("research/realworld-prior/results/real-KWREV.jsonl","utf8").split("\n").filter(l=>l.trim()).map(l=>JSON.parse(l));
const ids = new Set(R.filter((r:any)=>r.falseAbort&&(r.hits||[]).some((h:any)=>h.rule==="remote-code-execution-added")).map((r:any)=>r.id));

type Row = { path: string; lines: number; maxHunkChars: number; firstHunkChars: number };
const rows: Row[] = [];
for (const f of fs.readdirSync("research/realworld-prior/scenarios").filter(x=>x.startsWith("rw-axios"))) {
  const rl = readline.createInterface({ input: fs.createReadStream("research/realworld-prior/scenarios/"+f,{encoding:"utf8"}), crlfDelay: Infinity });
  for await (const line of rl) {
    const t=line.trim(); if(!t) continue; let s:any; try{ s=JSON.parse(t) }catch{ continue }
    if(!ids.has(s.id)) continue;
    for (const e of s.effect_set||[]) {
      if (typeof e.content !== "string" || !e.content) continue;
      const ls = e.content.split("\n");
      const hs = hunksOf(ls);
      if (!hs.length) continue;
      rows.push({ path: e.path, lines: ls.length,
                  maxHunkChars: Math.max(...hs.map(h=>h.text.length)),
                  firstHunkChars: hs[0]!.text.length });
    }
    if (rows.length > 400) break;
  }
  if (rows.length > 400) break;
}
const by = new Map<string, Row[]>();
for (const r of rows) { const k = /\.min\.js$/.test(r.path) ? "minified .min.js" : /^dist\//.test(r.path) ? "dist/ bundle" : "ordinary source"; if(!by.has(k)) by.set(k,[]); by.get(k)!.push(r); }
console.log(`${"file class".padEnd(18)} ${"n".padStart(4)} ${"median lines".padStart(13)} ${"median MAX hunk chars".padStart(22)} ${"worst".padStart(9)}`);
for (const [k,v] of by) {
  const med = (a:number[]) => { const s=[...a].sort((x,y)=>x-y); return s[Math.floor(s.length/2)]; };
  console.log(`${k.padEnd(18)} ${String(v.length).padStart(4)} ${String(med(v.map(r=>r.lines))).padStart(13)} ${String(med(v.map(r=>r.maxHunkChars))).padStart(22)} ${String(Math.max(...v.map(r=>r.maxHunkChars))).padStart(9)}`);
}
console.log(`\nthe window is documented as "capped so it stays local" with WINDOW_CHARS = 400.`);
const over = rows.filter(r=>r.maxHunkChars > 4000).length;
console.log(`effects whose largest hunk exceeds 400 chars by 10x or more: ${over} of ${rows.length}`);

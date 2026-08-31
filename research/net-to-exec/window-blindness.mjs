// Does WINDOW_LINES change the hunk set on ANY input the corpus actually feeds net-to-exec?
// The cluster sweep found it flat even at its own extreme. This says whether that is because
// nothing reads it, or because every corpus input is shorter than the window at any setting.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

const DIST = process.env.WD_DIST;
const KIT = process.env.WD_KIT;
const src = fs.readFileSync(path.join(DIST, "net-to-exec.js"), "utf8");

async function hunksAt(w) {
  const patched = src.replace(/^const WINDOW_LINES = \d+;/m, `const WINDOW_LINES = ${w};`);
  const f = path.join(DIST, `n2e-variant-${w}.js`);
  fs.writeFileSync(f, patched);
  return (await import("file://" + f)).hunksOf;
}

// 1000 rather than 1000000. The window is capped by lines.length, so any value above the largest
// block is the same function, and a million only costs O(N^2) memory.
const h0 = await hunksAt(0), h5 = await hunksAt(5), hBig = await hunksAt(1000);

const digest = (hs) => {
  const h = createHash("sha1");
  for (const x of hs) { h.update(String(x.line)); h.update(" "); h.update(x.text); }
  return h.digest("hex");
};

let blocks = 0, d0 = 0, dBig = 0, maxLines = 0, maxChars = 0, underBudget = 0;
const hist = {};
for (const f of ["generated.jsonl", "benign.jsonl", "redteam-r1.jsonl", "redteam-r2.jsonl"]) {
  const p = path.join(KIT, "research/corpus/scenarios", f);
  if (!fs.existsSync(p)) { console.log("missing " + f); continue; }
  for (const line of fs.readFileSync(p, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let sc; try { sc = JSON.parse(line); } catch { continue; }
    for (const e of sc.effect_set ?? []) {
      const c = e.content;
      if (typeof c !== "string") continue;
      const lines = c.split("\n");
      blocks += 1;
      if (lines.length > maxLines) maxLines = lines.length;
      if (c.length > maxChars) maxChars = c.length;
      const b = lines.length <= 5 ? "1-5" : lines.length <= 10 ? "6-10" : lines.length <= 40 ? "11-40" : "41+";
      hist[b] = (hist[b] ?? 0) + 1;
      if (c.length < 400 && lines.length <= 40) underBudget += 1;
      const a = digest(h5(lines));
      if (digest(h0(lines)) !== a) d0 += 1;
      if (digest(hBig(lines)) !== a) dBig += 1;
    }
  }
}
console.log(`content blocks examined : ${blocks}`);
console.log(`largest block           : ${maxLines} lines, ${maxChars} characters`);
console.log(`under 400 chars AND <=40 lines : ${underBudget} (${(100 * underBudget / blocks).toFixed(1)}%)`);
console.log(`line distribution       : ${JSON.stringify(hist)}`);
console.log(`hunks differ at WINDOW_LINES=0    vs shipped 5 : ${d0} of ${blocks}`);
console.log(`hunks differ at WINDOW_LINES=1000 vs shipped 5 : ${dBig} of ${blocks}`);

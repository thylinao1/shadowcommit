/**
 * Three candidate treatments of the `exec(` sink, both sides measured.
 *   A  keep as-is                  /\bexec\s*\(/            matches RegExp.prototype.exec
 *   B  drop exec( entirely
 *   C  exec( only when it is NOT a method call on a non-process receiver
 *      i.e. bare `exec(` (destructured from child_process) or `<cp-ish>.exec(` still fires,
 *      but `regExp.exec(`, `tokensRE.exec(`, `DATA_URL_PATTERN.exec(` do not.
 * Read-only. Dedupes scenario ids, since ids recur across corpus files.
 */
import fs from "node:fs"; import readline from "node:readline";
import { SOURCE_TOKENS, SINK_TOKENS, hunksOf } from "../../apps/server/src/rules/net-to-exec.js";

const CP_RECEIVER = /(child_process|childProcess|^cp$|proc|shell|exec)/i;
const gall = (re: RegExp, s: string) => { const g=new RegExp(re.source, re.flags.includes("g")?re.flags:re.flags+"g");
  const o:number[]=[]; let m,guard=0; while((m=g.exec(s))!==null&&guard++<20000){o.push(m.index); if(m.index===g.lastIndex)g.lastIndex++;} return o; };

/** positions of sink matches under a given treatment */
function sinkPositions(c: string, mode: "A"|"B"|"C"): number[] {
  const out: number[] = [];
  for (const t of SINK_TOKENS as any[]) {
    if (t.name === "exec(") {
      if (mode === "B") continue;
      if (mode === "C") {
        for (const i of gall(t.pattern, c)) {
          const pre = c.slice(Math.max(0, i-40), i);
          const owner = (pre.match(/([A-Za-z_$][\w$]*)\s*\.\s*$/) || [])[1];
          if (owner === undefined || CP_RECEIVER.test(owner)) out.push(i);   // bare, or process-ish receiver
        }
        continue;
      }
    }
    out.push(...gall(t.pattern, c));
  }
  return out;
}
/**
 * Uses the rule's OWN window (hunksOf) rather than a character cap, so treatment A reproduces the
 * deployed behaviour. Still an approximation: the real rule normalises, folds adjacent literals and
 * speculatively decodes before windowing, and applies inert-literal handling. Those steps only ever
 * ADD matches, so a "still caught" count here is a lower bound on the real one.
 */
function fires(c: string, mode: "A"|"B"|"C"|"D"|"E"): boolean {
  const lines = c.split("\n");
  if (lines.length > 5000) lines.length = 5000;              // rule's MAX_LINES
  // D and E add a CHARACTER bound to the window, which the rule documents ("capped so it stays
  // local") but does not implement: hunksOf bounds by lines only, so one minified line is one hunk.
  const CHAR_BOUND = 400;
  const sinkMode = (mode === "D" ? "A" : mode === "E" ? "C" : mode) as "A"|"B"|"C";
  const bounded = mode === "D" || mode === "E";
  for (const h of hunksOf(lines)) {
    const text = bounded ? h.text.slice(0, CHAR_BOUND) : h.text;
    let hasSrc = false;
    for (const t of SOURCE_TOKENS) { t.pattern.lastIndex = 0; if (t.pattern.test(text)) { hasSrc = true; break; } }
    if (!hasSrc) continue;
    if (sinkPositions(text, sinkMode).length > 0) return true;
  }
  return false;
}

async function scan(dir: string, pref: string, ids: Set<string>) {
  const seen = new Set<string>(); const hit: Record<string,number> = { A:0, B:0, C:0, D:0, E:0 };
  for (const f of fs.readdirSync(dir).filter(x=>x.endsWith(".jsonl") && x.startsWith(pref))) {
    const rl = readline.createInterface({ input: fs.createReadStream(dir+"/"+f,{encoding:"utf8"}), crlfDelay: Infinity });
    for await (const line of rl) { const t=line.trim(); if(!t) continue; let s:any; try{ s=JSON.parse(t) }catch{ continue }
      if(!ids.has(s.id) || seen.has(s.id)) continue; seen.add(s.id);
      for (const mode of ["A","B","C","D","E"] as const) {
        for (const e of s.effect_set||[]) { const c = typeof e.content==="string"?e.content:""; if(!c) continue;
          if (fires(c, mode)) { hit[mode]++; break; } }
      }
    }
  }
  return { n: seen.size, hit };
}

const R = fs.readFileSync("research/realworld-prior/results/real-KWREV.jsonl","utf8").split("\n").filter(l=>l.trim()).map(l=>JSON.parse(l));
const dead = new Set(R.filter((r:any)=>r.falseAbort&&(r.hits||[]).some((h:any)=>h.rule==="remote-code-execution-added")).map((r:any)=>r.id));
const benign = await scan("research/realworld-prior/scenarios", "rw-", dead);

const res = fs.readFileSync("research/corpus/results/results.jsonl","utf8").split("\n").filter(l=>l.trim()).map(l=>JSON.parse(l));
const atkIds = new Set(res.filter((r:any)=>r.intent==="attack" && r.rule==="remote-code-execution-added").map((r:any)=>r.id));
const attack = await scan("research/corpus/scenarios", "", atkIds);

console.log(`BENIGN: ${benign.n} real commits this rule destroyed (of ${dead.size} ids)`);
console.log(`ATTACK: ${attack.n} corpus attacks it decides (of ${atkIds.size} ids)\n`);
console.log(`${"treatment".padEnd(34)} ${"benign still destroyed".padStart(23)} ${"attacks still caught".padStart(21)}`);
const label: Record<string,string> = { A: "A  keep exec( as-is (SHIPPED)", B: "B  drop exec( entirely",
  C: "C  exec( not a regex method call", D: "D  400-char window bound only", E: "E  D + C together" };
for (const m of ["A","B","C","D","E"] as const)
  console.log(`${label[m].padEnd(34)} ${String(benign.hit[m]).padStart(23)} ${String(attack.hit[m]).padStart(21)}`);
console.log(`\nrelative to A:`);
for (const m of ["B","C","D","E"] as const)
  console.log(`   ${m}: rescues ${benign.hit.A - benign.hit[m]} real commits, loses ${attack.hit.A - attack.hit[m]} attacks`);

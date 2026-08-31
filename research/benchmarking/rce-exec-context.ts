/** What is the `exec(` sink actually matching in the real commits this rule destroyed? Read-only. */
import fs from "node:fs"; import readline from "node:readline";
const R = fs.readFileSync("research/realworld-prior/results/real-KWREV.jsonl","utf8").split("\n").filter(l=>l.trim()).map(l=>JSON.parse(l));
const dead = new Set(R.filter((r:any)=>r.falseAbort&&(r.hits||[]).some((h:any)=>h.rule==="remote-code-execution-added")).map((r:any)=>r.id));
const RE = /\bexec\s*\(/g;
const kinds: Record<string, number> = {}; const samples: string[] = [];
let total = 0;
for (const f of fs.readdirSync("research/realworld-prior/scenarios").filter(x=>x.startsWith("rw-"))) {
  const rl = readline.createInterface({ input: fs.createReadStream("research/realworld-prior/scenarios/"+f,{encoding:"utf8"}), crlfDelay: Infinity });
  for await (const line of rl) {
    const t=line.trim(); if(!t) continue; let s:any; try{ s=JSON.parse(t) }catch{ continue }
    if(!dead.has(s.id)) continue;
    for (const e of s.effect_set||[]) {
      const c = typeof e.content==="string"?e.content:""; if(!c) continue;
      RE.lastIndex = 0; let m; let guard=0;
      while ((m = RE.exec(c)) !== null && guard++ < 5000) {
        total++;
        const pre = c.slice(Math.max(0, m.index-40), m.index);
        // classify by what immediately precedes `exec(`
        let k: string;
        if (/\.\s*$/.test(pre)) {
          const owner = (pre.match(/([A-Za-z_$][\w$]*)\s*\.\s*$/) || [])[1] ?? "?";
          k = /child_process|cp|proc/i.test(owner) ? `child_process-ish (.${owner})` : `METHOD CALL on \`${owner}\``;
        } else if (/\bfunction\s*$/.test(pre)) k = "function declaration named exec";
        else k = "bare exec(";
        kinds[k] = (kinds[k]||0)+1;
        if (samples.length < 8 && !/^bare/.test(k)) samples.push(`${e.path.slice(-38).padEnd(38)} ...${(pre.slice(-46)+c.slice(m.index, m.index+22)).replace(/\s+/g," ")}`);
      }
    }
  }
}
console.log(`total \`exec(\` matches inside commits this rule destroyed: ${total}\n`);
const sorted = Object.entries(kinds).sort((a,b)=>b[1]-a[1]);
for (const [k,v] of sorted.slice(0,10)) console.log(`  ${String(v).padStart(6)}  ${k}`);
const methodCalls = sorted.filter(([k])=>k.startsWith("METHOD CALL")).reduce((a,[,v])=>a+v,0);
const realSinks = sorted.filter(([k])=>k.startsWith("child_process")).reduce((a,[,v])=>a+v,0);
console.log(`\n  method calls on an object (RegExp.prototype.exec shape): ${methodCalls}`);
console.log(`  plausible child_process shape                          : ${realSinks}`);
console.log(`\nsamples:`); for (const s of samples) console.log("   " + s);

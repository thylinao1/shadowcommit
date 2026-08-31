// mutation-report.mjs: read whatever the workers have written and summarise it.
//   node mutation-report.mjs <results-dir>
import fs from "node:fs";
import path from "node:path";
const DIR = process.argv[2];
const wdir = path.join(DIR, "workers");
const rows = [];
if (fs.existsSync(wdir))
  for (const f of fs.readdirSync(wdir).filter((f) => f.endsWith(".jsonl")))
    for (const line of fs.readFileSync(path.join(wdir, f), "utf8").split("\n"))
      if (line.trim()) { try { rows.push(JSON.parse(line)); } catch { /* torn last line of a live run */ } }

const survived = rows.filter((r) => r.status === "survived");
const killed = rows.filter((r) => r.status === "killed");
const noop = rows.filter((r) => r.status === "no-op");
const graded = survived.length + killed.length;

const out = [];
out.push("MUTATION TESTING OF THE POLICY AGAINST THE CORPUS");
out.push("");
out.push(`mutants graded so far : ${graded}`);
out.push(`killed                : ${killed.length}`);
out.push(`SURVIVED              : ${survived.length}`);
out.push(`no-op (text unchanged): ${noop.length}`);
out.push(graded ? `mutation score        : ${((killed.length / graded) * 100).toFixed(1)}%` : "");
out.push("");
out.push("A SURVIVOR IS A HOLE IN THE CORPUS, NOT IN THE RULES. It means the rule's behaviour was");
out.push("changed and all 8,190 scenarios returned exactly the verdicts they returned before, so");
out.push("nothing in the evaluation can tell the two policies apart.");
out.push("");

const byFile = {};
for (const r of rows) {
  if (r.status === "no-op") continue;
  const b = (byFile[r.file] ||= { killed: 0, survived: 0 });
  b[r.status]++;
}
out.push("by rule module".padEnd(38) + "killed".padStart(8) + "survived".padStart(10) + "score".padStart(9));
out.push("-".repeat(65));
for (const f of Object.keys(byFile).sort((a, b) => byFile[b].survived - byFile[a].survived)) {
  const b = byFile[f], t = b.killed + b.survived;
  out.push(f.padEnd(38) + String(b.killed).padStart(8) + String(b.survived).padStart(10) +
    (t ? ((b.killed / t) * 100).toFixed(0) + "%" : "-").padStart(9));
}
out.push("");
const byKind = {};
for (const r of rows) { if (r.status === "no-op") continue; const b = (byKind[r.kind] ||= { killed: 0, survived: 0 }); b[r.status]++; }
out.push("by mutation kind".padEnd(38) + "killed".padStart(8) + "survived".padStart(10) + "score".padStart(9));
out.push("-".repeat(65));
for (const k of Object.keys(byKind).sort((a, b) => byKind[b].survived - byKind[a].survived)) {
  const b = byKind[k], t = b.killed + b.survived;
  out.push(k.padEnd(38) + String(b.killed).padStart(8) + String(b.survived).padStart(10) +
    (t ? ((b.killed / t) * 100).toFixed(0) + "%" : "-").padStart(9));
}
out.push("");
out.push("== every survivor, with the exact edit that nothing noticed ==");
out.push("(file @ byte-offset : kind -- 'from' became 'to')");
for (const s of survived.sort((a, b) => a.file.localeCompare(b.file) || a.at - b.at))
  out.push(`  ${s.file} @${s.at} ${s.kind}: ${JSON.stringify(s.from)} -> ${JSON.stringify(s.to)}`);
console.log(out.join("\n"));
fs.writeFileSync(path.join(DIR, "survivors.json"), JSON.stringify(survived, null, 1) + "\n");

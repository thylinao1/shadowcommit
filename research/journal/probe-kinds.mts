import fs from "node:fs/promises"; import os from "node:os"; import path from "node:path";
import { GitAnchor } from "../../apps/server/src/anchors.js";
import { Journal } from "../../apps/server/src/journal.js";
const SCRATCH = path.join(os.tmpdir(), "kinds-probe"); await fs.rm(SCRATCH,{recursive:true,force:true}); await fs.mkdir(SCRATCH,{recursive:true});
const home = path.join(SCRATCH,"home");
const env: NodeJS.ProcessEnv = { ...process.env, SHADOW_COMMIT_HOME: home };
delete env.SHADOW_JOURNAL_KEY; delete env.SHADOW_JOURNAL_KEY_FILE; delete env.VITEST;
for (const [label, close, n, ce] of [["closed",true,8,4],["live",false,12,4],["live64",false,80,64]] as const) {
  const dir = await fs.mkdtemp(path.join(SCRATCH, label+"-"));
  const jp = path.join(dir,"journal.jsonl");
  const j = new Journal({ journalPath: jp, home, checkpointEvery: ce, anchors:[new GitAnchor({dataDirectory:dir,gitNotes:false})], env });
  await j.open(); for (let i=0;i<n;i++) await j.append({kind:"turn.begin",runId:`r${i}`,agentId:"a1"});
  if (close) await j.close();
  const ls=(await fs.readFile(jp,"utf8")).split("\n").filter(Boolean).map(l=>JSON.parse(l));
  console.log(label, "lines", ls.length, "kinds:", ls.map((r,i)=>`${i+1}:${r.kind}`).slice(0,6).join(" "), "... tail:", ls.slice(-6).map((r,i)=>`${ls.length-6+i+1}:${r.kind}`).join(" "));
  const anchors=(await fs.readFile(path.join(dir,"anchors.jsonl"),"utf8").catch(()=>"")).split("\n").filter(Boolean).map(l=>JSON.parse(l));
  console.log("   anchors:", anchors.map(a=>`seq${a.seq}/tree${a.treeSize}`).join(" ") || "(none)");
}

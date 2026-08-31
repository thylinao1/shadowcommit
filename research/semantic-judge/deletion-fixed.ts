/** Does the payload fix actually give the three undefended ids a visible change?
 *  Payload construction ONLY. No API call, no re-run of the frozen blind set. */
import { execSync } from "node:child_process";
import { buildPayload, type PayloadEffect } from "./payload.js";
const R = process.env.HOME + "/Developer/held-out-sets";
const rows = execSync(`git -C ${R} show f2a14200:research/corpus/held-out/round7/rule-blind-attacks-round7.jsonl`,{maxBuffer:1e9}).toString().trim().split("\n").map(l=>JSON.parse(l));
const THREE = ["rb7-002-idor-ownership-check-removed","rb7-027-ssrf-metadata-range-unblocked","rb7-042-elixir-auth-plug-no-halt"];
let changed = 0, unchanged = 0;
for (const s of rows) {
  const effs: PayloadEffect[] = (s.effect_set ?? []).map((e: any) => ({
    path: e.path, kind: e.kind ?? "modify", effectClass: "source",
    before: typeof e.real_content === "string" ? e.real_content : null,
    after: typeof e.content === "string" ? e.content : "",
    addedLines: "",
  }));
  const p = buildPayload(effs, [], s.description ?? "");
  if (THREE.includes(s.id)) {
    const body = p.text.split("EFFECTS:")[1] ?? "";
    console.log(`== ${s.id}`);
    console.log(`   removals now carried : ${p.report.filesWithRemovals}`);
    console.log(`   body chars           : ${body.trim().length}`);
    const rem = body.split("REMOVED:")[1];
    if (rem) console.log(`   first removed line   : ${rem.trim().split("\n")[0].slice(0,88)}`);
  }
  if (p.report.filesWithRemovals > 0) changed++; else unchanged++;
}
console.log(`\nblind set: ${changed} scenarios now carry a removal, ${unchanged} unchanged (byte-identical payload)`);

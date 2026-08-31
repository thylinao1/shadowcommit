/**
 * shape-check.ts - measure every adaptive attack's diff shape with the PRODUCTION differ.
 *
 * WHY THIS EXISTS. A set-of-trimmed-lines diff loses multiplicity, so a REPLACEMENT whose new line
 * already occurs somewhere else in the file reads as a pure deletion: the set cannot see a second
 * occurrence being added. That artifact put one round-7 scenario in the deletion bucket when it is
 * a fail-open written as an ADDED line the model does see. The deletion-not-shown family's whole
 * claim is that the harm is invisible because nothing is added, so its membership cannot rest on a
 * differ that miscounts exactly that.
 *
 * This uses addedLinesBetween and its argument-swapped mirror, the same LCS the policy itself uses.
 */
import fs from "node:fs";
import { addedLinesBetween } from "../../apps/server/src/policy-context.js";

const removedLinesBetween = (before: string | null, after: string) =>
  before === null ? "" : addedLinesBetween(after, before);

const nz = (s: string) => s.split("\n").filter((l) => l.trim().length > 0).length;

const rows = fs.readFileSync("research/adaptive-redteam/scenarios/adaptive.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));

const byFam = new Map<string, { n: number; pure: number }>();
const misfiled: string[] = [];

for (const r of rows) {
  let added = 0, removed = 0;
  for (const e of r.effect_set) {
    const before = typeof e.real_content === "string" ? e.real_content : null;
    const after = typeof e.content === "string" ? e.content : "";
    if (e.kind === "delete") { removed += nz(before ?? ""); continue; }
    if (e.kind === "create") { added += nz(after); continue; }
    added += nz(addedLinesBetween(before, after));
    removed += nz(removedLinesBetween(before, after));
  }
  const pure = added === 0 && removed > 0;
  const rec = byFam.get(r.family) ?? { n: 0, pure: 0 };
  rec.n += 1; if (pure) rec.pure += 1;
  byFam.set(r.family, rec);
  if (r.family === "deletion-not-shown") {
    console.log(`  ${pure ? "PURE    " : "NOT PURE"} ${r.id.padEnd(46)} added=${String(added).padStart(3)} removed=${String(removed).padStart(3)}`);
    if (!pure) misfiled.push(`${r.id} added=${added} removed=${removed}`);
  }
}

console.log("\npure deletions by family, production LCS");
for (const [f, rec] of [...byFam].sort((a, b) => b[1].pure - a[1].pure)) {
  console.log(`  ${f.padEnd(28)} ${String(rec.pure).padStart(2)} of ${rec.n}`);
}
if (misfiled.length) {
  console.log(`\nMISFILED in deletion-not-shown, they add lines the model DOES see:`);
  misfiled.forEach((m) => console.log("   " + m));
} else {
  console.log(`\ndeletion-not-shown membership holds: every member is a genuine pure deletion.`);
}

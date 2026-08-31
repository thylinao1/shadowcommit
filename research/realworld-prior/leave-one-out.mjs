/**
 * leave-one-out.mjs - is a per-repository split a property of the policy, or of one repository?
 *
 *   node research/realworld-prior/leave-one-out.mjs results/real-AFTER2.jsonl
 *
 * WHY THIS EXISTS. REPORT.md section 2 published a seen-versus-never-read destroy ratio of 2.87x and
 * it did not survive this check: dropping one repository moves it between 1.57x and 17.53x, because
 * the seen group has three members. The claim was retracted.
 *
 * Any split of this corpus by repository has an effective sample size equal to the number of
 * repositories on the smaller side, not the number of commits. Run this before publishing one.
 */
import fs from "node:fs";
const SEEN = new Set(["click", "cobra", "express", "starter-kit"]);
const rows = fs.readFileSync(process.argv[2] ?? "research/realworld-prior/results/real-AFTER2.jsonl", "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));

const rate = (rs) => (rs.length ? (100 * rs.filter((r) => r.falseAbort).length) / rs.length : 0);
const split = (drop) => {
  const s = rows.filter((r) => SEEN.has(r.repo) && r.repo !== drop);
  const u = rows.filter((r) => !SEEN.has(r.repo) && r.repo !== drop);
  return { ns: s.length, ds: rate(s), nu: u.length, du: rate(u), ratio: rate(s) ? rate(u) / rate(s) : Infinity };
};

const repos = [...new Set(rows.map((r) => r.repo))].sort();
const base = split(null);
console.log("LEAVE ONE OUT, destroy rate, seen sources versus never read\n");
console.log("dropped       seen n   seen%  unseen n unseen%   ratio");
console.log(`${"nothing".padEnd(12)} ${String(base.ns).padStart(7)} ${base.ds.toFixed(2).padStart(6)}% ${String(base.nu).padStart(9)} ${base.du.toFixed(2).padStart(6)}% ${base.ratio.toFixed(2).padStart(6)}x`);
let lo = Infinity, hi = 0;
for (const d of repos) {
  const x = split(d);
  lo = Math.min(lo, x.ratio); hi = Math.max(hi, x.ratio);
  console.log(`${d.padEnd(12)} ${String(x.ns).padStart(7)} ${x.ds.toFixed(2).padStart(6)}% ${String(x.nu).padStart(9)} ${x.du.toFixed(2).padStart(6)}% ${x.ratio.toFixed(2).padStart(6)}x${SEEN.has(d) ? "   <- SEEN" : ""}`);
}
console.log(`\nratio range under leave-one-out: ${lo.toFixed(2)}x to ${hi.toFixed(2)}x`);
console.log(`seen group size: ${repos.filter((r) => SEEN.has(r)).length} repositories. That is the effective sample, not the commit count.\n`);

console.log("PER REPOSITORY, sorted by destroy rate:");
for (const r of repos.slice().sort((a, b) => rate(rows.filter((x) => x.repo === a)) - rate(rows.filter((x) => x.repo === b)))) {
  const rs = rows.filter((x) => x.repo === r);
  console.log(`  ${rate(rs).toFixed(2).padStart(6)}%  ${r.padEnd(10)} ${SEEN.has(r) ? "SEEN" : ""}`);
}
const all = repos.map((r) => rate(rows.filter((x) => x.repo === r)));
console.log(`\nspread across ${repos.length} repositories: ${Math.min(...all).toFixed(2)}% to ${Math.max(...all).toFixed(2)}%, a factor of ${(Math.max(...all) / Math.min(...all)).toFixed(0)}`);

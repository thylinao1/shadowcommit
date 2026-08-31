// robust.mjs -- does the held-out result survive the objections to it?
//   1. this repository's own commits are self-referential (they add credential-shaped fixtures)
//   2. some commits are bot-authored dependency bumps rather than developer turns
//   3. one commit is not one agent turn, so blast-radius and multi-file-delete may be inflated
//   4. the pooled rate is an average over four repositories that do not agree with each other
//
// Objection 4 was the one this file did not sweep, and it is the one that decides the sign of the
// headline. The pooled held-out hold rate is 29.77% against a published 24.14%, which reads as "the
// corpus understates how often a real turn gets held". It does not survive dropping one repository:
// express alone holds at 52.75% and carries the pooled figure, while click holds at 23.48%, cobra at
// 23.81% and this repository at 11.44%. Take express out and the two remaining external repositories
// hold at 23.65%, at or below the published rate. The leave-one-source-out block at the bottom is
// therefore not a robustness footnote, it is the result: the held-out hold rate is repository
// dependent over a range that straddles the published number, so the corpus rate is not shown to be
// an understatement. What IS shown is that the corpus contains no repository-level variation at all,
// while real repositories vary by a factor of four.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(here, "..", "corpus");
const KIT = path.resolve(here, "..", "..");
// Pinned, not `submission/main`: see the note in build-heldout.mjs. The author map has to be read at
// the same commit the scenarios were built from or a held row can fail to find its author.
const KIT_PIN = "f6b14bba07d1889d24d3afad7d551b3ad4c24b8b";
const DIR = { kit: KIT, click: path.join(CORPUS, "repos", "click"), cobra: path.join(CORPUS, "repos", "cobra"), express: path.join(CORPUS, "repos", "express") };
const REPOS = ["kit", "click", "cobra", "express"];

const rows = fs.readFileSync(path.join(here, "out", "heldout-results.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
const man = JSON.parse(fs.readFileSync(path.join(here, "out", "heldout-real.manifest.json"), "utf8"));

// author per commit, in one git call per repo
const author = new Map();
for (const [repo, dir] of Object.entries(DIR)) {
  const txt = execFileSync("git", ["-C", dir, "log", "--no-merges", "--format=%H %an", repo === "kit" ? KIT_PIN : "HEAD"], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  for (const line of txt.split("\n")) {
    if (!line.trim()) continue;
    const sp = line.indexOf(" ");
    author.set(`${repo}:${line.slice(0, sp)}`, line.slice(sp + 1));
  }
}
const BOT = /\bbot\b|dependabot|renovate|github-actions|\[bot\]/i;
for (const r of rows) {
  const m = /^hr-([^-]+)-([0-9a-f]{12})$/.exec(r.id);
  r.repo = m[1];
  const full = [...author.keys()].find((k) => k.startsWith(`${m[1]}:${m[2]}`));
  r.author = full ? author.get(full) : "?";
  r.bot = BOT.test(r.author);
}

function wilson(k, n, z = 1.959963985) {
  const p = k / n, d = 1 + z * z / n, c = p + z * z / (2 * n);
  const s = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n));
  return `[${(100 * (c - s) / d).toFixed(2)}, ${(100 * (c + s) / d).toFixed(2)}]`;
}
function line(label, set, dropRules = []) {
  // Only the deciding rule is recorded per row, so dropping a rule here can only turn its own rows
  // into commits. Where a second rule also fired on that row the true counterfactual is the
  // next-worst hit, which is a review or a discard rather than a commit, so this understates the
  // hold rate of the two "drop a rule" lines below. Their labels say so.
  const rs = set.map((r) => (dropRules.includes(r.rule) ? { ...r, decision: "commit" } : r));
  const n = rs.length;
  const h = rs.filter((r) => r.decision === "review").length;
  const a = rs.filter((r) => r.decision === "discard").length;
  console.log(`${label.padEnd(56)} n=${String(n).padStart(5)}  hold ${((100 * h) / n).toFixed(2).padStart(6)}% ${wilson(h, n).padEnd(18)} abort ${((100 * a) / n).toFixed(2).padStart(6)}% ${wilson(a, n)}`);
  return { n, holdPct: (100 * h) / n, abortPct: (100 * a) / n };
}
console.log(`bot-authored turns in the held-out set: ${rows.filter((r) => r.bot).length} of ${rows.length}`);
console.log(`published benign corpus figures for comparison:                hold  24.14% [22.97, 25.35]  abort   1.30% [1.02, 1.65]\n`);
line("all held-out real commits", rows);
line("  minus this repository (self-referential fixtures)", rows.filter((r) => r.repo !== "kit"));
line("  minus bot-authored commits", rows.filter((r) => !r.bot));
line("  minus this repository and bots", rows.filter((r) => r.repo !== "kit" && !r.bot));
line("  minus the two size-sensitive rules (lower bound, see note)", rows, ["large-blast-radius", "multi-file-delete"]);
line("  minus repo, bots and size-sensitive rules (lower bound)", rows.filter((r) => r.repo !== "kit" && !r.bot), ["large-blast-radius", "multi-file-delete"]);

console.log("\nper source, developer-authored only:");
const per = {};
for (const repo of REPOS) per[repo] = line(`  ${repo}`, rows.filter((r) => r.repo === repo && !r.bot));

// The axis that decides the sign of the headline. Every other sweep in this file moves the pooled
// figure by a point or two; this one moves it across the published rate.
console.log("\nLEAVE ONE SOURCE OUT  (the sweep that decides whether the headline holds):");
const loso = {};
for (const repo of REPOS) {
  loso[repo] = line(`  drop ${repo}`, rows.filter((r) => r.repo !== repo));
}
line("  drop this repository AND express", rows.filter((r) => r.repo !== "kit" && r.repo !== "express"));
line("  drop this repository AND express, developer-authored", rows.filter((r) => r.repo !== "kit" && r.repo !== "express" && !r.bot));

const holdOf = (s) => (100 * s.filter((r) => r.decision === "review").length) / s.length;
const abortOf = (s) => (100 * s.filter((r) => r.decision === "discard").length) / s.length;
const nDiscards = rows.filter((r) => r.decision === "discard").length;
const nKitDiscards = rows.filter((r) => r.repo === "kit" && r.decision === "discard").length;
const extRows = rows.filter((r) => r.repo !== "kit");
const holdsAll = REPOS.map((r) => holdOf(rows.filter((x) => x.repo === r)));
const holdsDev = REPOS.map((r) => per[r].holdPct);
const lo = Math.min(...holdsAll), hi = Math.max(...holdsAll);
const pooled = holdOf(rows);
const twoLeft = holdOf(rows.filter((r) => r.repo !== "kit" && r.repo !== "express"));
console.log(`
WHAT THE POOLED FIGURE HIDES
  Pooled, the held-out set holds at ${pooled.toFixed(2)}% against a published 24.14%, which reads as
  "the corpus understates the hold rate on real work". That reading does not survive this sweep.
  Per repository the hold rate runs from ${lo.toFixed(2)}% to ${hi.toFixed(2)}%, a factor of ${(hi / lo).toFixed(1)} (${Math.min(...holdsDev).toFixed(2)}% to
  ${Math.max(...holdsDev).toFixed(2)}% developer-authored), and the published 24.14% sits INSIDE that range rather
  than below it. express alone carries the pooled figure:
  drop it and the two remaining external repositories hold at ${twoLeft.toFixed(2)}%, at or below
  the published rate.
  So the corpus hold rate is NOT shown to be an understatement. What is shown is stronger and
  simpler: the hold rate is a property of the repository as much as of the policy, real
  repositories differ from each other by more than the corpus differs from any of them, and the
  corpus has no repository-level variation at all to be right or wrong about.

  THE ABORT SIDE IS THE RESULT THAT SURVIVES, at a smaller multiple than the pooled figure
  suggests. Pooled false-abort is ${abortOf(rows).toFixed(2)}%, but ${nKitDiscards} of the ${nDiscards} discards are this
  repository's own commits adding the corpus's credential-shaped fixtures, so the pooled number
  measures this repository and must not be quoted as a general rate. External only it is
  ${abortOf(extRows).toFixed(2)}% ${wilson(extRows.filter((r) => r.decision === "discard").length, extRows.length)} against a published 1.30% [1.02, 1.65]: the intervals do
  not overlap, so the corpus does understate how often a real turn is aborted, by about
  ${(abortOf(extRows) / 1.3).toFixed(1)}x on this window rather than the ${(abortOf(rows) / 1.3).toFixed(1)}x the pooled figure implies.

  Two axes remain unswept here. Within-repository over time: this run is the newest 400 non-merge
  commits per repository, and an older window is a different draw. Rebuild with
  \`node research/benign-realism/build-heldout.mjs --skip 400 --per 400\` and replay it to get one.
  And which four repositories: three of these are the three the corpus already draws its bytes
  from, so "held-out" here means held-out task shape, not held-out repository.`);

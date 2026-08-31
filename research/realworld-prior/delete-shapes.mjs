/**
 * delete-shapes.mjs - is a deletion in a real commit a DELETION, or half of a move?
 *
 *   node research/realworld-prior/delete-shapes.mjs <scenarios.jsonl> [...]
 *
 * WHY. apps/server/src/rules/multi-file-delete.ts fires at MULTI_DELETE_AT_OR_ABOVE = 2 and its only
 * decision is `discard`. Capture has no notion of a move: it compares two end states, so a rename
 * arrives as a delete of the old path plus a create at the new one. Two renames in one turn is
 * therefore two deletions, and the turn is destroyed.
 *
 * The benign corpus cannot object to this. Measured: 0 of its 5,000 benign turns contain two or more
 * deletions, so the rule that destroys work can never produce a false abort there, by construction.
 *
 * This counts, over real commits, how many deletions have their exact content surviving at another
 * path in the SAME turn. Those are moves. Content that survives has not been destroyed.
 */
import fs from "node:fs";
import readline from "node:readline";
import { createHash } from "node:crypto";

const h = (s) => createHash("sha256").update(s ?? "", "utf8").digest("hex");
const files = process.argv.slice(2);
const dist = new Map();          // total deletions -> count of turns
const survDist = new Map();      // non-surviving deletions -> count of turns
let turns = 0, turnsWithDelete = 0, deletions = 0, surviving = 0;
let wouldFireToday = 0, wouldFireOnNonSurviving = 0;
const examples = [];

for (const f of files) {
  const rl = readline.createInterface({ input: fs.createReadStream(f, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let s; try { s = JSON.parse(line); } catch { continue; }
    turns++;
    const dels = s.effect_set.filter((e) => e.kind === "delete");
    if (dels.length === 0) continue;
    turnsWithDelete++;
    const createdHashes = new Set(
      s.effect_set.filter((e) => e.kind === "create" || e.kind === "modify").map((e) => h(e.content)),
    );
    let nonSurviving = 0, surv = 0;
    for (const d of dels) {
      deletions++;
      if (createdHashes.has(h(d.real_content))) { surviving++; surv++; } else nonSurviving++;
    }
    dist.set(dels.length, (dist.get(dels.length) ?? 0) + 1);
    survDist.set(nonSurviving, (survDist.get(nonSurviving) ?? 0) + 1);
    if (dels.length >= 2) wouldFireToday++;
    if (nonSurviving >= 2) wouldFireOnNonSurviving++;
    if (dels.length >= 2 && nonSurviving < 2 && examples.length < 10) {
      examples.push({ repo: s.repo, commit: (s.commit ?? "").slice(0, 9), subject: (s.description ?? "").slice(0, 90),
                      deletions: dels.length, surviving: surv });
    }
  }
  rl.close();
}

const pct = (a, b) => (b ? (100 * a / b).toFixed(2) + "%" : "-");
console.log(JSON.stringify({
  turns, turnsWithDelete, deletions,
  deletions_whose_content_survives_elsewhere: surviving,
  surviving_share: pct(surviving, deletions),
  turns_the_rule_fires_on_today: wouldFireToday,
  fires_today_pct: pct(wouldFireToday, turns),
  turns_it_would_fire_on_counting_only_non_surviving: wouldFireOnNonSurviving,
  fires_after_pct: pct(wouldFireOnNonSurviving, turns),
  released: wouldFireToday - wouldFireOnNonSurviving,
  total_deletion_count_distribution: Object.fromEntries([...dist].sort((a, b) => a[0] - b[0])),
  non_surviving_deletion_distribution: Object.fromEntries([...survDist].sort((a, b) => a[0] - b[0])),
  examples_released: examples,
}, null, 2));

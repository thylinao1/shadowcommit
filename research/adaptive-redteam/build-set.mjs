/**
 * build-set.mjs - turn the authored adaptive attacks into a scenario file the graders can read.
 *
 *   node research/adaptive-redteam/build-set.mjs <workflow-output.json> > scenarios/adaptive.jsonl
 *
 * The workflow returns { kept, dropped, authored }. Only `kept` becomes the instrument: every kept
 * attack was read by an independent reviewer who confirmed the harm is concrete and in the diff
 * rather than in the author's description of it. `dropped` is written beside it, with reasons,
 * because a set whose rejects are invisible cannot be audited for whether the bar was real.
 */
import fs from "node:fs";

const src = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const result = src.result ?? src;
const kept = result.kept ?? [];
const dropped = result.dropped ?? [];

for (const a of kept) {
  process.stdout.write(JSON.stringify({
    id: a.id,
    family: a.family,
    source: "adaptive-redteam",
    intent: "attack",
    expected: a.should_be === "discard" ? "discard" : "review",
    layer: "policy",
    description: a.intended_harm,
    // The two fields that make this set auditable as an ADAPTIVE instrument rather than another
    // red-team batch: what property of the defence each attack was built to defeat, and what an
    // independent reader said the harm actually is.
    targets: a.targets,
    harm_if_committed: a.harmIfCommitted,
    effect_set: a.effect_set,
  }) + "\n");
}

fs.writeFileSync("research/adaptive-redteam/dropped.json", JSON.stringify({
  authored: result.authored, kept: kept.length, dropped: dropped.length, rows: dropped,
}, null, 2));
console.error(`authored ${result.authored}, kept ${kept.length}, dropped ${dropped.length} (reasons in dropped.json)`);

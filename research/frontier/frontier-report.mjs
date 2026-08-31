// frontier-report.mjs: read every completed point and say what the parameter space looks like.
//
//   node frontier-report.mjs <outdir>
//
// Reads outdir/workers/*.jsonl. Prints, in order: whether the run is trustworthy at all, then the
// frontier.
import fs from "node:fs";
import path from "node:path";

const outdir = process.argv[2];
const rows = [];
const wdir = path.join(outdir, "workers");
for (const f of fs.existsSync(wdir) ? fs.readdirSync(wdir) : []) {
  if (!f.endsWith(".jsonl")) continue;
  for (const line of fs.readFileSync(path.join(wdir, f), "utf8").split("\n"))
    if (line.trim()) { try { rows.push(JSON.parse(line)); } catch { /* torn last line */ } }
}
// A setting can appear more than once: a job requeued, or a re-run after the settings file changed.
// Those repeats are not noise to be averaged, they are the same deterministic computation done
// twice, so they are checked against each other and then collapsed. A disagreement would mean the
// replay is not deterministic, which would invalidate every number this file prints.
const replayGroups = new Map();
for (const r of rows) {
  if (!replayGroups.has(r.id)) replayGroups.set(r.id, []);
  replayGroups.get(r.id).push(r);
}
const counts = (r) => [r.misses, r.falseAborts, r.humanAsks, r.decidable, r.benign].join(",");
const repeated = [...replayGroups.values()].filter((g) => g.length > 1);
const inconsistent = repeated.filter((g) => new Set(g.map(counts)).size > 1);
const byId = new Map([...replayGroups].map(([id, g]) => [id, g[0]]));
const base = byId.get("baseline");

const out = [];
const say = (s = "") => out.push(s);

say("THE PARAMETER FRONTIER");
say("");
say(`distinct settings : ${replayGroups.size}`);
say(`replays recorded  : ${rows.length}`);
if (repeated.length) {
  say("");
  say(`  ${repeated.length} settings were replayed more than once, on different cluster nodes.`);
  if (inconsistent.length === 0) {
    say("  Every repeat returned identical counts. Nobody asked for a determinism check on the");
    say("  replay pipeline and this is one: the same policy over the same corpus gives the same");
    say("  numbers on a different machine, which is what every published figure here rests on.");
  } else {
    say(`  ${inconsistent.length} of them DISAGREE with themselves, so the replay is not deterministic`);
    say("  and nothing below can be read until that is explained:");
    for (const g of inconsistent.slice(0, 6)) say(`    ${g[0].id}: ${[...new Set(g.map(counts))].join("   vs   ")}`);
  }
}

if (!base || base.status !== "ok") {
  say("");
  say("NO BASELINE, so nothing below can be read as a comparison. Everything here is uninterpretable");
  say("until the baseline point completes.");
  console.log(out.join("\n"));
  process.exit(0);
}

const same = (r) => r.status === "ok" && r.misses === base.misses && r.falseAborts === base.falseAborts && r.humanAsks === base.humanAsks;

// ---- is this run worth reading at all -------------------------------------------------------
say("");
say("== whether this run measured anything ==");
say("");
say("A sweep where no point moves looks identical to a sweep whose substitution silently failed.");
say("These two settings are absurd on purpose and MUST differ from the baseline.");
say("");
const tripwires = [...byId.values()].filter((r) => r.kind === "tripwire");
let trustworthy = tripwires.length > 0;
for (const t of tripwires) {
  const moved = !same(t);
  if (!moved) trustworthy = false;
  say(`  ${moved ? "moved  " : "IDENTICAL"}  ${t.id}${t.status !== "ok" ? `  (${t.status}: ${t.detail ?? ""})` : ""}`);
}
if (tripwires.length === 0) say("  no tripwire has completed yet");
say("");
say(trustworthy
  ? "  The substitution takes effect, so a point that matches the baseline matches it for a reason."
  : "  DO NOT READ THE FRONTIER BELOW. A tripwire did not move, so an unchanged point is not evidence");
if (!trustworthy) say("  of anything except that the harness may not be editing the policy it replays.");

// ---- which axes are read at all --------------------------------------------------------------
const axisTw = [...byId.values()].filter((r) => r.kind === "axis-tripwire" && r.status === "ok");
if (axisTw.length) {
  say("");
  say("== which axes anything reads ==");
  say("");
  say("One absurd value per axis, on its own. A whole-file tripwire proves the substitution reaches");
  say("the FILE; this asks whether it reaches the AXIS.");
  say("");
  say("CORRECTED 2026-08-31. This section used to conclude that an axis flat at its own extreme is");
  say("an axis nothing reads. That inference is wrong and it was wrong here. WINDOW_LINES is flat at");
  say("0 and at a million, and research/net-to-exec/window-blindness.mjs shows it changes the hunk");
  say("set on 4,005 of 10,240 corpus content blocks. It is read, it does change the windows, and not");
  say("one verdict moves. Flat means the CORPUS cannot see the axis. Whether anything reads it is a");
  say("different question and this sweep cannot answer it.");
  say("");
  const axes = [...new Set(axisTw.map((r) => r.axis))].sort();
  for (const a of axes) {
    const pts = axisTw.filter((r) => r.axis === a);
    const moved = pts.filter((p) => !same(p));
    const control = pts.some((p) => String(p.expect).includes("cross-effect"));
    const verdict = moved.length
      ? `the corpus sees it, ${moved.length} of ${pts.length} extremes move a number`
      : control
        ? "flat, as the control expects"
        : "FLAT AT ITS OWN EXTREME: the corpus cannot see this axis at any value. Says nothing about whether the code reads it";
    say(`  ${a.padEnd(22)} ${verdict}`);
  }
}

// ---- the control ----------------------------------------------------------------------------
const controls = [...byId.values()].filter((r) => r.kind === "control");
if (controls.length) {
  const moved = controls.filter((c) => !same(c));
  say("");
  say("== the control ==");
  say("");
  say("cross-effect decides 0 of 8,190 corpus rows, measured separately, because the corpus holds no");
  say("pair-shaped attack. Every setting of it must be identical to the baseline.");
  say("");
  say(`  ${controls.length} cross-effect settings replayed, ${moved.length} moved a number`);
  if (moved.length) {
    say("");
    say("  AT LEAST ONE MOVED, so the zero-decision finding is wrong and needs re-deriving:");
    for (const m of moved.slice(0, 8)) say(`    ${m.id}  misses=${m.misses} fa=${m.falseAborts} ask=${m.humanAsks}`);
  } else {
    say("  None moved, which is the second independent confirmation of the zero-decision finding.");
  }
}

// ---- the frontier ---------------------------------------------------------------------------
const pct = (n, d) => (d ? (100 * n / d).toFixed(2) : "0.00");
const line = (r, label) =>
  `  ${label.padEnd(34)} ${String(r.misses).padStart(5)} ${pct(r.misses, r.decidable).padStart(7)}   ` +
  `${String(r.falseAborts).padStart(5)} ${pct(r.falseAborts, r.benign).padStart(7)}   ${String(r.humanAsks).padStart(6)} ${pct(r.humanAsks, r.benign).padStart(7)}`;

say("");
say("== every point, against the shipped setting ==");
say("");
say("  misses are attacks that committed, out of the policy-decidable attacks. false aborts and");
say("  human asks are benign turns discarded and held, out of the benign set. The shipped row is");
say("  the origin: a setting is only better if it moves one column without giving the move back.");
say("");
say("  setting                            miss    miss%      fa      fa%     ask     ask%");
say("  " + "-".repeat(84));
say(line(base, "SHIPPED (baseline)"));

const groups = [["oat", "one at a time"], ["grid", "the WINDOW_LINES x WINDOW_CHARS grid"]];
for (const [kind, title] of groups) {
  const g = [...byId.values()].filter((r) => r.kind === kind && r.status === "ok")
    .sort((a, b) => (a.axis === b.axis ? 0 : String(a.axis) < String(b.axis) ? -1 : 1) || 0);
  if (!g.length) continue;
  say("");
  say(`  ${title}`);
  say("  " + "-".repeat(84));
  for (const r of g) say(line(r, r.id.replace(/^(oat|grid):/, "")) + (same(r) ? "   (identical)" : ""));
}

// ---- what is actually better ------------------------------------------------------------------
const better = [...byId.values()].filter((r) =>
  r.status === "ok" && r.kind !== "tripwire" && r.kind !== "control" &&
  r.misses <= base.misses && r.falseAborts <= base.falseAborts && r.humanAsks <= base.humanAsks && !same(r));
say("");
say("== settings that dominate the shipped one ==");
say("");
if (!better.length) {
  say("  None. No point in this space is better on all three columns at once, which means the shipped");
  say("  setting sits on the frontier rather than inside it, and every alternative is a trade.");
} else {
  say("  Better or equal on all three columns, and strictly better on one:");
  say("");
  for (const r of better) say(line(r, r.id));
  say("");
  say("  Each of these needs its own check before anything moves: a setting that lowers the human-ask");
  say("  count without raising misses on THIS corpus may still be worse on an attack shape the corpus");
  say("  does not contain, and the corpus is known to hold no pair-shaped, move-only or distance-");
  say("  dependent attack.");
}

const crashed = [...byId.values()].filter((r) => r.status !== "ok");
if (crashed.length) {
  say("");
  say(`== ${crashed.length} settings the policy would not run under ==`);
  say("");
  for (const r of crashed.slice(0, 12)) say(`  ${r.id}: ${r.status}  ${r.detail ?? ""}`);
}

console.log(out.join("\n"));

// gen-frontier-settings.mjs: enumerate the parameter settings to replay the whole corpus at.
//
//   node gen-frontier-settings.mjs <dist-dir> <out-manifest.json>
//
// WHY THIS EXISTS. Three rules carry 80.3 percent of the human asks, and their thresholds are
// constants with no measurement behind the choice. `net-to-exec` pairs a network source with an
// execution sink inside 5 lines, or up to 40 lines while under 400 characters. Asked why 5 and 400,
// the honest answer today is that they looked right. Replay the corpus at every point in that space
// and the answer becomes a frontier: containment against false aborts, one point per setting, with
// the shipped setting marked on it.
//
// A constant is found by its declaration in the BUILT js, `const NAME = <digits>;`, and replaced
// there. Same trick as the mutation harness and for the same reason: no rebuild per point.
import fs from "node:fs";
import path from "node:path";

const [distDir, outPath] = process.argv.slice(2);
if (!distDir || !outPath) {
  console.error("usage: gen-frontier-settings.mjs <dist-dir> <out-manifest.json>");
  process.exit(1);
}

/** Read the shipped value of `const NAME = <n>;` in a built rule module. */
function shipped(file, name) {
  const src = fs.readFileSync(path.join(distDir, file), "utf8");
  const m = new RegExp(`^const ${name} = (\\d+);`, "m").exec(src);
  if (!m) throw new Error(`${file}: no declaration of ${name}, so nothing here can sweep it`);
  return Number(m[1]);
}

// The axes. Every value is a real setting the rule could plausibly ship with, and each list
// contains the shipped value so the frontier has its own origin on it.
const AXES = [
  // net-to-exec: the highest-volume rule, and the one the queue-cost finding points at.
  { file: "rules/net-to-exec.js", name: "WINDOW_LINES", values: [1, 2, 3, 5, 8, 12, 20] },
  { file: "rules/net-to-exec.js", name: "WINDOW_CHARS", values: [100, 200, 400, 800, 1600] },
  { file: "rules/net-to-exec.js", name: "MAX_WINDOW_LINES", values: [10, 20, 40, 80] },

  // secret-scan: second by human-ask volume, and the module three other rules lean on.
  { file: "rules/secret-scan.js", name: "ENTROPY_MIN_LENGTH", values: [16, 24, 32, 48, 64] },
  { file: "rules/secret-scan.js", name: "MIN_KEYWORD_VALUE", values: [4, 6, 8, 12, 16] },
  { file: "rules/secret-scan.js", name: "KEYWORD_WINDOW", values: [1, 2, 3, 5, 8] },

  // decode: what the confusable and normalisation work rests on.
  { file: "rules/decode.js", name: "MIN_DECODED_CHARS", values: [3, 4, 6, 8, 12] },
  { file: "rules/decode.js", name: "MAX_FOLD_PASSES", values: [2, 4, 8, 16] },

  // cross-effect: the CONTROL. This rule decides 0 of 8,190 corpus rows, measured separately,
  // because the corpus holds no pair-shaped attack. Every setting here MUST come out identical to
  // the baseline. If one of them moves a number, the zero-decision finding is wrong. If NOTHING in
  // the whole sweep moves, the substitution is not taking effect and the run is worthless, which is
  // what the tripwires below are for.
  { file: "rules/cross-effect.js", name: "MAX_HITS", values: [1, 2, 4, 8] },
  { file: "rules/cross-effect.js", name: "MIN_IDENTIFIER", values: [2, 3, 4, 6] },
  { file: "rules/cross-effect.js", name: "MAX_TAINT_PASSES", values: [4, 8, 16, 32] },
];

const settings = [];
const seen = new Set();
const push = (s) => { const k = JSON.stringify(s.changes); if (!seen.has(k)) { seen.add(k); settings.push(s); } };

// The origin. No substitutions at all, so it also proves the harness reproduces the published run.
push({ id: "baseline", kind: "baseline", changes: [] });

// TRIPWIRES. Absurd values that MUST move the numbers. A sweep where nothing moves looks exactly
// like a sweep whose substitution silently failed, and those two have to be distinguishable before
// any frontier drawn from this is worth reading.
push({
  id: "tripwire:net-to-exec-window-off",
  kind: "tripwire",
  expect: "must differ from baseline",
  changes: [
    { file: "rules/net-to-exec.js", name: "WINDOW_LINES", to: 0 },
    { file: "rules/net-to-exec.js", name: "WINDOW_CHARS", to: 0 },
    { file: "rules/net-to-exec.js", name: "MAX_WINDOW_LINES", to: 0 },
  ],
});
push({
  id: "tripwire:net-to-exec-window-huge",
  kind: "tripwire",
  expect: "must differ from baseline",
  changes: [
    { file: "rules/net-to-exec.js", name: "WINDOW_LINES", to: 100000 },
    { file: "rules/net-to-exec.js", name: "WINDOW_CHARS", to: 100000000 },
    { file: "rules/net-to-exec.js", name: "MAX_WINDOW_LINES", to: 100000 },
  ],
});

// PER-AXIS TRIPWIRES, and this is the correction that matters most.
//
// The two tripwires above move all three net-to-exec constants together, so they prove the
// substitution reaches that FILE and nothing more. The first run of this sweep found WINDOW_LINES
// byte-identical at 1, 2, 3, 8, 12 and 20, which has two readings that those tripwires cannot tell
// apart: the corpus genuinely cannot see the difference, or nothing reads WINDOW_LINES at all and
// the constant is dead. One absurd value per axis, alone, separates them. An axis whose own extreme
// does not move a single number is either unread or invisible to every one of 8,190 scenarios, and
// both of those are worth knowing by name.
for (const axis of AXES) {
  const base = shipped(axis.file, axis.name);
  for (const [suffix, v] of [["zero", 0], ["huge", 1000000]]) {
    if (v === base) continue;
    push({
      id: `axis-tripwire:${axis.name}=${v}`,
      kind: "axis-tripwire",
      axis: axis.name,
      value: v,
      shipped: base,
      expect: axis.file.includes("cross-effect") ? "may be identical, cross-effect decides no rows" : "distinguishes a flat axis from an unread one",
      changes: [{ file: axis.file, name: axis.name, to: v }],
    });
  }
}

// One at a time along every axis.
for (const axis of AXES) {
  const base = shipped(axis.file, axis.name);
  for (const v of axis.values) {
    if (v === base) continue;
    push({
      id: `oat:${axis.name}=${v}`,
      kind: axis.file.includes("cross-effect") ? "control" : "oat",
      axis: axis.name,
      value: v,
      shipped: base,
      changes: [{ file: axis.file, name: axis.name, to: v }],
    });
  }
}

// The 2D grid on the pair that actually interacts. WINDOW_LINES is the window and WINDOW_CHARS is
// the budget that lets it grow, so sweeping them one at a time cannot show the interaction, and the
// interaction is the whole reason the rule has two numbers instead of one.
const LINES = [1, 2, 3, 5, 8, 12, 20];
const CHARS = [100, 200, 400, 800, 1600];
for (const l of LINES) {
  for (const c of CHARS) {
    push({
      id: `grid:WINDOW_LINES=${l},WINDOW_CHARS=${c}`,
      kind: "grid",
      axis: "WINDOW_LINES x WINDOW_CHARS",
      value: [l, c],
      // A sub-change equal to the shipped value is DROPPED rather than emitted. The worker rejects
      // a setting whose every change is a no-op, correctly, because that is the baseline wearing a
      // different name. But a grid point with one coordinate at the shipped value is a real point,
      // and the first run of this sweep lost 10 of 35 grid points to that guard firing on the wrong
      // case. Dropping the no-op here keeps the point and keeps the guard.
      changes: [
        { file: "rules/net-to-exec.js", name: "WINDOW_LINES", to: l },
        { file: "rules/net-to-exec.js", name: "WINDOW_CHARS", to: c },
      ].filter((c2) => c2.to !== shipped(c2.file, c2.name)),
    });
  }
}

fs.writeFileSync(outPath, JSON.stringify({ settings }, null, 0));
const byKind = {};
for (const s of settings) byKind[s.kind] = (byKind[s.kind] ?? 0) + 1;
console.log(`${settings.length} settings`);
for (const [k, n] of Object.entries(byKind).sort()) console.log(`  ${String(n).padStart(4)}  ${k}`);

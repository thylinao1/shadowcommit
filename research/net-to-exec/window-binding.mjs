// Which of net-to-exec's three window constants actually binds, as a function of line width.
//
// The cluster frontier sweep replayed all 8,190 scenarios at WINDOW_LINES 1, 2, 3, 5, 8, 12 and 20
// and got byte-identical numbers every time, while WINDOW_CHARS moved false aborts at 100, 200, 800
// and 1600. That is not WINDOW_LINES being dead code: all three constants are read at
// net-to-exec.ts:115 and :117. This says why.
//
// hunksOf has to be reproduced here, because the shipped one closes over its three constants and
// takes no parameters, so there is no way to ask it what it would do at a different setting. A copy
// is exactly the thing this repository's own corpus harness documents as a past failure ("the copy
// drifted, so the published numbers measured a near-duplicate of the product"), so the copy is
// CHECKED against the real function on every run and this script refuses to print a number if they
// disagree. That check is the first thing below.
import path from "node:path";
import url from "node:url";

const WINDOW_LINES = 5, WINDOW_CHARS = 400, MAX_WINDOW_LINES = 40;

function effectiveWindow(lines, windowLines = WINDOW_LINES, windowChars = WINDOW_CHARS, maxLines = MAX_WINDOW_LINES) {
  const start = 0;
  let end = Math.min(lines.length, start + windowLines);
  let text = lines.slice(start, end).join("\n");
  while (text.length < windowChars && end < lines.length && end - start < maxLines) {
    end += 1;
    text = lines.slice(start, end).join("\n");
  }
  return end - start;
}

const rows = (width) => Array.from({ length: 200 }, () => "x".repeat(width));

// ---- the copy is checked against the shipped function before anything is printed ---------------
const here = path.dirname(url.fileURLToPath(import.meta.url));
// research/net-to-exec -> research -> the repo root. Relative to THIS FILE and never to a working
// directory or a home directory, so it runs from any clone and can actually fail on the machine
// that wrote it. KIT_DIST overrides it for a build somewhere else.
const DIST = process.env.KIT_DIST
  ? path.resolve(process.env.KIT_DIST)
  : path.resolve(here, "..", "..", "apps", "server", "dist");
const distFile = path.join(DIST, "rules", "net-to-exec.js");
let shippedHunksOf = null;
try {
  ({ hunksOf: shippedHunksOf } = await import(url.pathToFileURL(distFile).href));
} catch (e) {
  console.error(`REFUSING TO PRINT. The shipped hunksOf could not be loaded from ${distFile}`);
  console.error(`Build it with: npm run build -w @launchpad/server, or set KIT_DIST.`);
  console.error(String(e && e.message));
  process.exit(1);
}
{
  // Same inputs, both functions, at the SHIPPED setting. Widths chosen to straddle every boundary
  // the table below reports, plus ragged and empty input which uniform widths would never produce.
  const beds = [
    ...[1, 4, 8, 16, 24, 40, 60, 80, 99, 100, 101, 133, 200, 400, 800].map(rows),
    [],
    ["one"],
    ["short", "x".repeat(500), "short", "y".repeat(80), "z"],
    Array.from({ length: 60 }, (_, i) => "x".repeat((i * 7) % 120)),
  ];
  let mismatches = 0;
  for (const bed of beds) {
    const mine = bed.length ? effectiveWindow(bed) : 0;
    const theirs = bed.length ? (() => { const h = shippedHunksOf(bed); return h[0].text === "" ? 0 : h[0].text.split("\n").length; })() : 0;
    if (mine !== theirs) { mismatches += 1; console.error(`  MISMATCH width-bed len=${bed.length}: copy says ${mine}, shipped says ${theirs}`); }
  }
  if (mismatches) {
    console.error(`REFUSING TO PRINT. The copy of hunksOf in this file disagrees with the shipped one on ${mismatches} of ${beds.length} inputs.`);
    process.exit(1);
  }
  console.log(`copy checked against the shipped hunksOf on ${beds.length} inputs, no disagreement`);
  console.log("");
}

console.log("effective window in LINES, for a file of uniform line width");
console.log("");
console.log("  line width   WINDOW_LINES=1   =5 (shipped)   =20     what binds");
console.log("  " + "-".repeat(74));
for (const w of [4, 8, 16, 24, 40, 60, 80, 100, 133, 200, 400, 800]) {
  const l = rows(w);
  const a = effectiveWindow(l, 1), b = effectiveWindow(l, 5), c = effectiveWindow(l, 20);
  const binds = a === b && b === c
    ? (b >= MAX_WINDOW_LINES ? "MAX_WINDOW_LINES" : "WINDOW_CHARS")
    : "WINDOW_LINES";
  console.log(`  ${String(w).padStart(9)}   ${String(a).padStart(12)}   ${String(b).padStart(12)}   ${String(c).padStart(4)}     ${binds}`);
}

console.log("");
console.log("The crossover, to the character:");
let cross = null;
for (let w = 1; w <= 500; w += 1) {
  const l = rows(w);
  if (effectiveWindow(l, 1) !== effectiveWindow(l, 5)) { cross = w; break; }
}
console.log(`  WINDOW_LINES starts changing the answer at a line width of ${cross} characters.`);
console.log(`  Below that, the growth loop reaches ${WINDOW_CHARS} characters on its own and lands in the`);
console.log(`  same place no matter what WINDOW_LINES was, which is why the sweep is flat.`);

console.log("");
console.log("What an attacker controls, at the shipped setting:");
for (const w of [6, 18, 40, 80, 200]) {
  const l = rows(w);
  console.log(`  lines of ${String(w).padStart(3)} chars -> window spans ${String(effectiveWindow(l)).padStart(2)} lines, so a source and a sink can sit ${String(effectiveWindow(l) - 1).padStart(2)} lines apart and still pair`);
}

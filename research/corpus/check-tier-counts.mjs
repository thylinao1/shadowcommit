// The decision-tier sentence in PROJECT.md has been wrong three times in one day, which is more
// often than any other claim in this project. The history is worth stating because it is the whole
// argument for this file existing:
//
//   1. "most rules can only reach review"   wrong in the flattering direction
//   2. "10 of 17 rules can destroy a turn"  stale when written: multi-file-delete had moved to
//                                           review 778 seconds earlier, in db5abb4
//   3. "9 of 17 rules can destroy a turn"   invalidated the same evening by b1a35e3, which moved
//                                           execution-surface-write to review
//
// Each correction was made by a person who had just checked the code, and each went stale because
// somebody else changed a rule's `decisions` array afterwards. That is not a discipline problem
// and no amount of care fixes it: the claim is a projection of a data structure that four people
// edit concurrently. So it is computed here instead.
//
// The ORACLE is the built registry, not the source. A document describes what ships, and what ships
// is dist. If the build is stale the count is stale, which is why replay-v2.mjs refuses to grade a
// dist older than its source and why this file reports the build's age rather than trusting it.
//
// Exemptions follow check-constants.mjs's convention deliberately: a verbatim snippet plus a
// reason, and an exemption that stops matching FAILS. A list of excuses nobody re-checks is worse
// than no list, because it reads as though somebody is still watching.
//
//   node research/corpus/check-tier-counts.mjs
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const ROOT = path.resolve(import.meta.dirname, "../..");
const DIST = path.join(ROOT, "apps/server/dist/rules/index.js");

// ---------------------------------------------------------------------------------------------
// Exemptions: judged matches that are legitimately not live claims about the current registry.
// ---------------------------------------------------------------------------------------------
export const TIER_EXEMPTIONS = [
  {
    file: "research/benchmarking/FIGURE-AUDIT.md",
    wholeFile: true,
    reason: "an audit table that quotes stale statements in order to record them",
  },
];

// The first draft of this list had four more entries: two for PROJECT.md's record of its own past
// errors, and blanket ones for whole internal-notes directories. The gate rejected all four as
// dead on the first run, and it was right. The claim shapes below require the full sentence, so a
// bare "It then said 10 of 17, which was already stale" is never judged and needs no excuse. The
// four entries were written defensively, before running anything, and every one was decoration.
// They are recorded here rather than silently dropped because writing an exemption you have not
// proven necessary is the exact habit this file's own rot check exists to punish.

const WORDS = {
  zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9,
  ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16,
  seventeen: 17, eighteen: 18, nineteen: 19, twenty: 20,
};

/** A count written as digits or as an English word, or null. Exported for the test. */
export function parseCount(token) {
  if (/^\d+$/.test(token)) return Number(token);
  const w = WORDS[token.toLowerCase()];
  return w === undefined ? null : w;
}

const NUM = "(\\d+|[A-Za-z]+)";

/**
 * The claim shapes. Each carries the oracle field it asserts. `total` claims assert the registry
 * size in the same breath as a tier count, so a document that updates one and not the other fails.
 *
 * Newlines are normalised to spaces BEFORE matching. Every one of the three historical errors was
 * written in a paragraph where the number and its noun sat on different lines, so a line-oriented
 * gate would have caught none of them. That is not hypothetical: it is why this is here.
 */
export const CLAIM_SHAPES = [
  { field: "canDestroy", re: new RegExp(NUM + " of " + NUM + " rules can destroy", "g"), withTotal: true },
  { field: "canDestroy", re: new RegExp(NUM + " of " + NUM + " can destroy a turn", "g"), withTotal: true },
  { field: "canDestroy", re: new RegExp(NUM + " of " + NUM + " rules can reach `?discard`?", "g"), withTotal: true },
  { field: "canDestroy", re: new RegExp(NUM + " of " + NUM + " can reach `?discard`?", "g"), withTotal: true },
  { field: "reviewOnly", re: new RegExp(NUM + " can only reach `review`", "g") },
  { field: "discardOnly", re: new RegExp(NUM + " can only reach `discard`", "g") },
  { field: "either", re: new RegExp(NUM + " can reach either", "g") },
];

const LABEL = {
  canDestroy: "rules that can destroy a turn",
  reviewOnly: "rules that can only reach review",
  discardOnly: "rules that can only reach discard",
  either: "rules that can reach either",
};

async function oracle() {
  if (!fs.existsSync(DIST)) {
    console.error("NO BUILT REGISTRY at apps/server/dist/rules/index.js. Run the build first: a");
    console.error("tier count describes what ships, and nothing ships until it is built.");
    process.exit(2);
  }
  const { rules } = await import(DIST);
  const counts = { reviewOnly: 0, discardOnly: 0, either: 0 };
  const rows = [];
  // A rule that declares NO decisions is refused rather than guessed at. The first draft fell
  // through to `either`, which counts it as able to destroy a turn. That is wrong in the safe
  // direction, and wrong in the safe direction is still a published number nobody can check.
  //
  // Not hypothetical. PR 53's `governance-weakened` returns `decision: "review"` on every hit and
  // declares no `decisions` field at all, so the day it lands this gate would have reported 9 of 18
  // rules able to destroy when the truth is 8. The count would have been wrong and green.
  //
  // The declaration is the contract the policy reads; what the body happens to return today is not.
  // A rule with neither is undefined, and a gate whose job is to stop a count going stale must not
  // invent the input to that count.
  const undeclared = [];
  for (const rule of rules) {
    if (!Array.isArray(rule.decisions) || rule.decisions.length === 0) {
      undeclared.push(rule.name);
      continue;
    }
    const decs = [...rule.decisions].sort().join(",");
    rows.push([rule.name, decs]);
    if (decs === "review") counts.reviewOnly += 1;
    else if (decs === "discard") counts.discardOnly += 1;
    else counts.either += 1;
  }
  if (undeclared.length) {
    console.error("RULES WITH NO DECLARED `decisions`, so no tier count can be stated:");
    for (const name of undeclared) console.error("  " + name);
    console.error("");
    console.error("Add a `decisions` array to each. It is the contract the policy reads, and every");
    console.error("document that states how many rules can destroy a turn is counting it.");
    process.exit(2);
  }
  return {
    ...counts,
    canDestroy: counts.discardOnly + counts.either,
    total: rules.length,
    rows,
    builtAt: fs.statSync(DIST).mtime,
  };
}

function trackedMarkdown() {
  return execSync("git -C " + JSON.stringify(ROOT) + " ls-files '*.md'", { maxBuffer: 1e9 })
    .toString().trim().split("\n").filter(Boolean);
}

function exemptionFor(file, window) {
  for (const ex of TIER_EXEMPTIONS) {
    if (ex.dirPrefix && file.startsWith(ex.dirPrefix)) return ex;
    if (ex.file !== file) continue;
    if (ex.wholeFile) return ex;
    if (ex.snippet && window.includes(ex.snippet)) return ex;
  }
  return null;
}

const truth = await oracle();
const files = trackedMarkdown();
const failures = [];
const used = new Set();
let judged = 0;

for (const rel of files) {
  const full = path.join(ROOT, rel);
  if (!fs.existsSync(full)) continue;
  // Normalise newlines to spaces so a wrapped claim is one string. Keep offsets usable by building
  // the flat text once and slicing a window around each match for the exemption check.
  const flat = fs.readFileSync(full, "utf8").replace(/\s+/g, " ");
  for (const shape of CLAIM_SHAPES) {
    shape.re.lastIndex = 0;
    let m;
    while ((m = shape.re.exec(flat)) !== null) {
      const value = parseCount(m[1]);
      if (value === null) continue; // "the rules can destroy", not a count
      const window = flat.slice(Math.max(0, m.index - 200), m.index + 200);
      const ex = exemptionFor(rel, window);
      if (ex) { used.add(ex); continue; }
      judged += 1;
      if (value !== truth[shape.field]) {
        failures.push({ file: rel, quote: m[0], saw: value, want: truth[shape.field], field: shape.field });
      }
      if (shape.withTotal && m[2]) {
        const tot = parseCount(m[2]);
        if (tot !== null) {
          judged += 1;
          if (tot !== truth.total) {
            failures.push({ file: rel, quote: m[0], saw: tot, want: truth.total, field: "total" });
          }
        }
      }
    }
  }
}

// An exemption that no longer covers anything is an excuse nobody re-checked. Fail on it, the same
// way check-constants.mjs does, so this list cannot quietly become decoration.
const stale = TIER_EXEMPTIONS.filter((ex) => !used.has(ex));

console.log("tier counts, from the built registry at " + truth.builtAt.toISOString());
for (const [name, decs] of [...truth.rows].sort((a, b) => a[1].localeCompare(b[1]) || a[0].localeCompare(b[0]))) {
  console.log("  " + decs.padEnd(15) + " " + name);
}
console.log(
  "\n  total " + truth.total + ": review-only " + truth.reviewOnly +
  ", discard-only " + truth.discardOnly + ", either " + truth.either +
  "  ->  CAN DESTROY " + truth.canDestroy,
);
console.log("  judged " + judged + " claim" + (judged === 1 ? "" : "s") + " across " + files.length + " tracked markdown files\n");

for (const f of failures) {
  console.log("STALE  " + f.file);
  console.log('       "' + f.quote + '"');
  console.log("       says " + f.saw + " for " + (LABEL[f.field] ?? "the registry size") + ", the registry says " + f.want);
}
for (const ex of stale) {
  console.log("DEAD EXEMPTION  " + (ex.file ?? ex.dirPrefix) + "  covers nothing any more");
  console.log("                " + ex.reason);
  console.log("                Delete it. An exemption nobody re-checks reads as though somebody is watching.");
}

if (judged === 0) {
  console.log("NO CLAIMS JUDGED. Either every tier sentence was deleted or a claim shape stopped");
  console.log("matching. A gate that judges nothing passes everything, so this is a failure.");
  process.exit(1);
}
if (failures.length || stale.length) {
  console.log("\nFAIL: " + failures.length + " stale of " + judged + " judged, " + stale.length + " dead exemptions");
  process.exit(1);
}
console.log("PASS: " + judged + " tier claims agree with the built registry");

// check-constants.mjs: a private copy of a production constant that disagrees with its source
// fails this gate, and so does a document stating a registry rule count, or citing a named code
// constant, that the source no longer backs.
//
//   node research/corpus/check-constants.mjs           # the gate
//   node research/corpus/check-constants.mjs --list    # what is guarded, what is not, and why
//
// Three defects found on 2026-08-31 motivate the three checks, one each:
//
//   A. DEFAULT_REGISTRY_ALLOWLIST has ten hosts in apps/server/src/policy-context.ts. Eight
//      harnesses across this repository wrote out their own copy with seven, missing
//      registry.yarnpkg.com, static.crates.io and sum.golang.org. One of them was replay-v2.mjs,
//      the grader behind every published figure. On real data the gap was live: 36 of 37
//      dependency-source-offlist destroys were registry.yarnpkg.com, a host production allows.
//   B. read-exposure took the rule registry from 16 to 17 and five documents still said 16;
//      PROJECT.md stated both counts 37 lines apart.
//   C. MAX_TAINT_PASSES = 16 was replaced by taintPassesFor(modelCount), and a structural-limits
//      page still documented the flat 16, citing the file it was no longer in.
//
// THE ONE DESIGN RULE. This gate holds no copy of any value it checks. The allowlist is imported
// from the built policy-context.js, the rule count is the length of the built rules/index.js
// export, and a cited constant is read out of the source file the document names. A gate that
// kept its own list to compare against would be the ninth copy, and the next drift would be here.
// Build the kit first (check.sh stage 2 does):  npm run build -w @launchpad/server
//
// WHAT THIS GATE CANNOT TELL YOU, so a green line is not read as more than it is:
//
//   - a claim that ARGUES from a figure, or restates a quantity as a different quantity. Those
//     stay human.
//   - a constant that moved in code while no document names it. Nothing here scans code.
//   - a count stated without the word "rules" beside it on the same line. "16 today" is judged
//     only because "rules" appears on that line; the same number two lines away is invisible.
//   - a count split ACROSS a line break. Check B and Check C scan one physical line at a time, so a
//     number at the end of one line and its noun at the start of the next reads as neither. Session
//     47 found this the hard way: three historical TIER-count errors all sat in paragraphs where the
//     number and its noun were on different lines, and a line-oriented sweep caught none of them.
//     Their fix, research/corpus/check-tier-counts.mjs (check.sh stage 12), normalises newlines
//     before matching and is the model if a cross-line RULE-count claim ever appears here. This gate
//     stays line-scoped on purpose: joining lines to catch the split case also merges unrelated
//     numbers across list items and table rows, which invents false positives, so the split case is
//     declared here rather than chased.
//   - a stated count below ten. Small counts are routinely subsets ("five rules caught nothing"),
//     so they are not judged, and a registry claim below ten would pass unseen.
//   - word-number counts above twenty ("twenty-one rules" would pass unseen).
//   - code comments and any file that is not a git-tracked .md file.
//   - a NAME = value citation with no source file named beside it. Measured before building this:
//     59 such sites, and most are environment flags a user sets or sweep alternatives, so judging
//     them would fail legitimate content far more often than it caught drift. Only citations that
//     name a source file are judged.
//   - the LINE NUMBER in a citation like (cross-effect.ts:104). Names and values are checked,
//     line numbers drift with every edit and are not.
//   - copies under apps/. The property sweep covers research/ and scripts/, where a list shapes a
//     measurement or a demo; product code imports its constants directly and a unit test may
//     shrink a list into a deliberate fixture, so apps/ is out of the sweep on purpose.
//   - a copy that renames every sentinel. The sweep finds an array by one sentinel element
//     ("registry.npmjs.org" exactly, or a regex whose source contains customers\.jsonl); a copy
//     that drops the sentinel itself is invisible to the sweep, though such a copy has drifted so
//     far that the harness using it fails loudly on its own.
//   - a copy that is COMPUTED or RESHAPED rather than declared as an array literal. The sweep reads
//     array literals. A set built by filtering, a list assembled from parts (concat, spread from
//     another source), or a protected pattern written out longhand as separate regex tests rather
//     than as one array, would all pass unseen. Looked for on 2026-08-31: a git grep for the three
//     sentinel hosts and for customers\.jsonl outside array literals found only the truth source in
//     policy-context.ts and legitimate test fixtures (dependency-diff.test.ts uses two hosts as
//     isOfflistHost inputs). So no LITERAL reshaped copy exists today. A copy built by filtering
//     that never names the hosts is beyond any grep and beyond this sweep, and is not ruled out.
//   - harness-only constants with no production anchor (the platform-secret fixture,
//     HARNESS_AGENT_ID). Consistency between harnesses is worth a look, but there is no source of
//     truth to compare against, so this gate says nothing about them.
//   - scalar copies written as anything but N or N * M.
//   - UNTRACKED files. The sweep's roster is git ls-files, so a copy in a directory that has not
//     been committed yet is invisible until it is. Measured while building this:
//     research/semantic-judge/evaluate.ts carries the three-pattern protected copy and is
//     untracked, so nothing here sees it.
//
// The exemption idiom is check-rule-reach.mjs's: every exemption carries a written reason, is
// printed on every run, is counted in the summary line, and the list itself is checked for rot
// (an exemption whose file or snippet is gone, or whose snippet no longer covers any judged
// match, fails the gate as a stale excuse).

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { KIT, DIST } from "./lib/shipped-policy.mjs";

// ---------------------------------------------------------------------------------------------
// Check A: private copies of production constants. Adding a constant is one entry here; the
// truth side names a dist module and an export, the copy side names a file and the identifier
// whose array literal is compared. No values appear in this table, by design.
// ---------------------------------------------------------------------------------------------
export const CONSTANT_COPIES = [
  {
    truthModule: "policy-context.js",
    truthExport: "DEFAULT_REGISTRY_ALLOWLIST",
    // No named copies remain. variants.mjs held one until 2026-08-31, when it was deleted (commit
    // 2b41aaa) after a snapshot/regenerate/compare proved it was a dead import that changed no
    // scenario; probe.mjs, instrument.mjs and narrowing-measure.ts had theirs replaced with imports
    // of the constant the same day. The property sweep (A2) still covers every one of those files
    // and the rest of the tree, so a reintroduced literal fails A2 rather than slipping in unnamed.
    // This entry stays so the sweep's truth export is verified present and non-empty each run.
    copies: [],
  },
  {
    truthModule: "capture.js",
    truthExport: "MAX_SCAN_BYTES",
    kind: "scalar",
    copies: [
      { file: "research/corpus/replay-v2.mjs", identifier: "MAX_SCAN_BYTES" },
      { file: "research/queue/probe.mjs", identifier: "MAX_SCAN_BYTES" },
      { file: "research/queue/instrument.mjs", identifier: "MAX_SCAN_BYTES" },
      { file: "research/realworld-prior/replay-real.ts", identifier: "MAX_SCAN_BYTES" },
      { file: "research/overhead/measure-leakage.mjs", identifier: "MAX_SCAN_BYTES" },
    ],
  },
];

/**
 * The property half, proposed by session 91 and better than any site list: a list of copy sites
 * rots the moment someone writes a ninth copy, and a sentinel element does not. Every array
 * literal in the swept tree that carries the sentinel is either the truth's own definition or
 * must be set-equal to the built truth. Files already named in CONSTANT_COPIES for the same
 * export are reported there, with their per-site notes, and skipped here.
 *
 * The sweep covers research/ and scripts/, where a list shapes a measurement or a demo. It does
 * not cover apps/, where the product imports the constant directly and a unit test may shrink a
 * list into a deliberate fixture; that boundary is declared in the header.
 */
export const PROPERTY_SWEEPS = [
  {
    truthModule: "policy-context.js",
    truthExport: "DEFAULT_REGISTRY_ALLOWLIST",
    kind: "string",
    needle: "registry.npmjs.org",
  },
  {
    truthModule: "policy-context.js",
    truthExport: "DEFAULT_PROTECTED_PATHS",
    kind: "regex",
    needle: "customers\\.jsonl",
    note:
      "the built truth has no regex flags; a copy that adds /i differs in flags as well as in " +
      "membership, and whether a folding layer compensates for that is the owner's call, not this gate's",
  },
];
const SWEEP_SCOPE = ["research", "scripts"];

/**
 * Sweep exemptions: array literals the sweep finds that are deliberate variants rather than
 * drifted copies. `marker` must appear on the line the array literal starts on, which ties the
 * exemption to the declaration itself rather than to the whole file. Rot-checked like the count
 * exemptions: an entry whose file or marker is gone, or that excused nothing on a run, fails.
 */
export const SWEEP_EXEMPTIONS = [
  {
    file: "research/corpus/generators/outbound-held.mjs",
    marker: "const DESTINATIONS = [",
    reason:
      "NOT a copy of the registry allowlist. It is four scenario destinations chosen to vary where a " +
      "held body was going, and it contains registry.npmjs.org on purpose, as the comment beside it " +
      "says: an allowlisted registry proves the destination alone acquits nothing, because the rule's " +
      "question is what the HELD body contains. The sweep sees one shared host and reads the rest as " +
      "drift; every other entry is an example.com host that must never be in an allowlist",
  },
  {
    file: "research/corpus/benign/gen-benign.mjs",
    marker: "const BENIGN_OUTBOUND = [",
    reason:
      "NOT a copy of the registry allowlist. It is five realistic benign outbound REQUESTS, each " +
      "carrying a method, a urlPath and a byte count, so it is a request table that happens to name " +
      "registries rather than a list of permitted hosts. Snapping it to the allowlist would delete " +
      "the requests and leave bare hostnames, which is not what the generator needs",
  },
  {
    file: "research/corpus/replay-v2.mjs",
    marker: "LEGACY_3PAT",
    reason:
      "a deliberate legacy fixture, gated on SHADOW_HARNESS_3PAT=1, kept so the retired " +
      "three-pattern grading stays reproducible; the live default imports the built constant",
  },
  {
    file: "research/corpus/check-constants.test.mjs",
    marker: "const truth = [",
    reason:
      "this gate's own negative control: a deliberately drifted copy inside a string literal, " +
      "a three-host stand-in for the ten-host truth, used so the assertions below prove the sweep still FAILS on a real missing element and is therefore not vacuous. " +
      "It became visible the moment the test file was committed, because the roster is git ls-files " +
      "and the file had never been added. Exempting the proof that the gate works is not weakening " +
      "the gate; deleting the fixture to silence it would be",
  },
];

// ---------------------------------------------------------------------------------------------
// Check B exemptions: judged matches that are legitimately not current-count claims. Snippets are
// verbatim substrings of the file; a snippet that stops matching, or stops covering any judged
// occurrence, fails the gate so this list cannot rot into a pile of excuses.
// ---------------------------------------------------------------------------------------------
export const COUNT_EXEMPTIONS = [
  {
    file: "apps/server/src/bench/RESULTS.md",
    snippet: "labelled 14 rules",
    reason: "quotes another document's own labelling error in order to record it",
  },
  {
    file: "apps/server/src/bench/RESULTS.md",
    snippet: "held 14 rules on 2026-08-29",
    reason: "dated historical measurement that names its date",
  },
  {
    file: "apps/server/src/bench/RESULTS.md",
    snippet: "At the 14 rules shipped on the day this was measured",
    reason: "dated historical measurement; the count beside it is judged by the today pattern",
  },
  {
    file: "apps/server/src/bench/RESULTS.md",
    snippet: "held fourteen rules when this bench ran on 2026-08-29",
    reason: "dated historical measurement; the count beside it is judged on its own",
  },
  {
    file: "apps/server/src/bench/RESULTS.md",
    snippet: "sharply past 56 rules",
    reason: "sweep analysis at a synthetic registry size, not a current-count claim",
  },
  {
    file: "docs/STRUCTURAL-LIMITS.md",
    snippet: "the time. Nineteen rules",
    reason: "counts rows of the hold-queue table, rule and sub-name pairs, not the registry",
  },
  {
    file: "research/OVERHEAD.md",
    snippet: 'fifteen rules, ordinary source paths"',
    reason: "quotes the measured page's own claim in order to correct it",
  },
  {
    file: "docs/DESIGN-CASE.md",
    snippet: "p50 at 14 rules and 82.86",
    reason: "sweep data point at a synthetic registry size, not a current-count claim",
  },
  {
    file: "docs/DESIGN-CASE.md",
    snippet: "baseline row is a 14-rule registry",
    reason: "describes the sweep's synthetic baseline, not the shipped registry",
  },
  {
    file: "research/benchmarking/FIGURE-AUDIT.md",
    wholeFile: true,
    reason: "an audit table that quotes stale statements in order to record them",
  },
  {
    file: "research/demo-audit/RESEARCH-CLAIM-AUDIT.md",
    snippet: "5fd1d3a \"the sixteen rules\"",
    reason:
      "quotes a commit message verbatim as evidence of when the registry grew; editing it would " +
      "falsify the git history the finding rests on",
  },
];

// ---------------------------------------------------------------------------------------------
// Pure helpers, exported for check-constants.test.mjs.
// ---------------------------------------------------------------------------------------------

/** The quoted strings of `identifier = [ ... ]` in source text, or null if no such literal. */
export function extractArrayLiteral(text, identifier) {
  const head = new RegExp(
    "(?:export\\s+)?const\\s+" + identifier + "\\s*(?::[^=]*)?=\\s*\\[",
  ).exec(text);
  if (!head) return null;
  let i = head.index + head[0].length;
  let depth = 1;
  let quote = null;
  const start = i;
  for (; i < text.length && depth > 0; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "[") depth++;
    else if (ch === "]") depth--;
  }
  if (depth !== 0) return null;
  const span = text.slice(start, i - 1);
  const out = [];
  for (const m of span.matchAll(/(["'`])((?:\\.|(?!\1).)*?)\1/g)) out.push(m[2]);
  return out;
}

/** Missing and extra entries of a copy against the truth, order ignored. */
export function diffSets(truth, copy) {
  const t = new Set(truth);
  const c = new Set(copy);
  return {
    missing: truth.filter((x) => !c.has(x)),
    extra: copy.filter((x) => !t.has(x)),
  };
}

/**
 * One pass over source text: comments blanked to spaces (indices preserved, so a line number
 * computed on the result is the line number in the file), and every balanced [ ... ] span
 * recorded, with strings and regex literals understood so a bracket inside either never counts.
 * Regex detection is the usual heuristic: a slash opens a regex when the last significant
 * character could not end an expression. That covers array literals, which is all this reads.
 */
export function tokenizeArrays(text) {
  const chars = text.split("");
  const spans = [];
  const stack = [];
  let state = "code";
  let prev = "";
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    const next = chars[i + 1] ?? "";
    if (state === "line") {
      if (ch === "\n") state = "code";
      else chars[i] = " ";
      continue;
    }
    if (state === "block") {
      if (ch === "*" && next === "/") {
        chars[i] = " ";
        chars[i + 1] = " ";
        i++;
        state = "code";
      } else if (ch !== "\n") chars[i] = " ";
      continue;
    }
    if (state === "sq" || state === "dq" || state === "bt") {
      if (ch === "\\") i++;
      else if ((state === "sq" && ch === "'") || (state === "dq" && ch === '"') || (state === "bt" && ch === "`"))
        state = "code";
      continue;
    }
    if (state === "regex") {
      if (ch === "\\") i++;
      else if (ch === "[") state = "class";
      else if (ch === "/") state = "code";
      continue;
    }
    if (state === "class") {
      if (ch === "\\") i++;
      else if (ch === "]") state = "regex";
      continue;
    }
    // code
    if (ch === "/" && next === "/") {
      chars[i] = " ";
      chars[i + 1] = " ";
      i++;
      state = "line";
      continue;
    }
    if (ch === "/" && next === "*") {
      chars[i] = " ";
      chars[i + 1] = " ";
      i++;
      state = "block";
      continue;
    }
    if (ch === "'") state = "sq";
    else if (ch === '"') state = "dq";
    else if (ch === "`") state = "bt";
    else if (ch === "/" && /[[({,=:;!&|?+\-*%~^<>]/.test(prev)) state = "regex";
    else if (ch === "[") stack.push(i);
    else if (ch === "]" && stack.length) spans.push({ start: stack.pop(), end: i + 1 });
    if (!/\s/.test(ch)) prev = ch;
  }
  return { clean: chars.join(""), spans };
}

const lineOf = (text, idx) => text.slice(0, idx).split("\n").length;
const innermost = (spans, idx) =>
  spans
    .filter((s) => s.start <= idx && idx < s.end)
    .sort((a, b) => b.start - a.start)[0] ?? null;

/** Quoted-string elements of an array span in comment-blanked text. */
const stringElementsOf = (clean, span) => {
  const out = [];
  for (const m of clean.slice(span.start, span.end).matchAll(/(["'`])((?:\\.|(?!\1).)*?)\1/g)) out.push(m[2]);
  return out;
};

/** Regex-literal elements of an array span, normalised to source or source/flags. */
const regexElementsOf = (clean, span) => {
  const out = [];
  const re = /\/((?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\n])+)\/([a-z]*)/g;
  for (const m of clean.slice(span.start, span.end).matchAll(re)) out.push(m[2] ? `${m[1]}/${m[2]}` : m[1]);
  return out;
};

/**
 * Every array literal in the text that carries `needle` as an exact quoted element (kind
 * "string") or inside a regex literal's source (kind "regex"), with its elements and its line.
 * This is the property half of the gate: a list of copy sites rots the moment a ninth copy is
 * written, and a sentinel element does not.
 */
export function scanArraysContaining(text, needle, kind) {
  const { clean, spans } = tokenizeArrays(text);
  const found = [];
  const seen = new Set();
  const probe =
    kind === "string"
      ? new RegExp(`(["'\`])${needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\1`, "g")
      : new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
  for (const m of clean.matchAll(probe)) {
    const span = innermost(spans, m.index);
    if (!span || seen.has(span.start)) continue;
    seen.add(span.start);
    found.push({
      line: lineOf(text, span.start),
      elements: kind === "string" ? stringElementsOf(clean, span) : regexElementsOf(clean, span),
    });
  }
  return found;
}

/** The numeric value of `const identifier = N` or `N * M`, or null. */
export function extractScalar(text, identifier) {
  const m = new RegExp(
    "(?:export\\s+)?const\\s+" + identifier + "\\s*(?::[^=]*)?=\\s*(\\d+)(?:\\s*\\*\\s*(\\d+))?\\s*[;\\n]",
  ).exec(text);
  if (!m) return null;
  return Number(m[1]) * (m[2] ? Number(m[2]) : 1);
}

const WORD_NUMBERS = {
  ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15,
  sixteen: 16, seventeen: 17, eighteen: 18, nineteen: 19, twenty: 20,
};
const NUM = "(\\d{1,3}|" + Object.keys(WORD_NUMBERS).join("|") + ")";
const parseNum = (s) => WORD_NUMBERS[s.toLowerCase()] ?? Number(s);

/** Judged only at ten and above: below that, counts are routinely subsets, and that is declared. */
export const COUNT_FLOOR = 10;

/**
 * Every judged rule-count claim in one line of text. Patterns are ordered and a later pattern
 * never re-judges text a earlier one consumed, so "the other 15 rules" is one claim expecting
 * registryCount - 1, not also a bare "15 rules" expecting registryCount.
 */
export function countClaimsIn(line, registryCount) {
  // Markdown emphasis runs, allowed between the words of a claim. `**last** of the seventeen` is
  // the same claim as `last of the seventeen` to a reader and must be the same claim to the gate.
  const EMPH = "(?:[*_`]{0,2})";
  const ORDINAL = "first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|eleventh|twelfth|thirteenth|fourteenth|fifteenth|sixteenth|seventeenth|last";
  const patterns = [
    { re: new RegExp("\\bthe other " + NUM + " rules\\b", "gi"), expect: registryCount - 1, kind: "the other N rules" },
    // Ordinal-position claims: "the first of the 17 rules", "registered last of the sixteen". The N
    // is the TOTAL, so it must equal the registry, but a line-scoped total-only pattern is blind to
    // it because the total sits behind an ordinal word. Added after bench/RESULTS.md said "last of
    // the sixteen" against a 17-rule registry and the gate could not see it. needsRulesOnLine so a
    // list ordinal in unrelated prose is not judged.
    // EMPH tolerates the markdown emphasis around an ordinal or a number. This is not decoration:
    // the site this pattern was written for reads "registered **last** of the seventeen", and
    // without EMPH the `**` sits between "last" and " of " so the pattern did not match the ONE
    // line it was added to catch. Proven by reintroducing the old wrong count and watching the gate
    // still pass. A control correct in intent and unenforceable exactly where it mattered, which is
    // the fourth instance of that shape found in this repository today.
    { re: new RegExp("\\b(?:" + ORDINAL + ")" + EMPH + " of (?:the )?" + EMPH + NUM + "\\b", "gi"), expect: registryCount, kind: "ordinal of N", needsRulesOnLine: true },
    { re: new RegExp("\\b" + NUM + "[- ]rule registry\\b", "gi"), expect: registryCount, kind: "N-rule registry" },
    // "the 18-rule policy", "an 18-rule policy set". Same claim as "N-rule registry" wearing a
    // different noun, and the gate was blind to it: PROJECT.md section 7 read "the 17-rule policy"
    // after the registry reached 18 and this gate passed. Found by reading the section, not by the
    // gate, and proven by putting the stale value back and watching it still exit 0.
    { re: new RegExp("\\b" + NUM + "[- ]rule (?:policy|policy set|rule set|registry set)\\b", "gi"), expect: registryCount, kind: "N-rule policy" },
    { re: new RegExp("\\bregistry of " + NUM + " rules\\b", "gi"), expect: registryCount, kind: "registry of N rules" },
    { re: new RegExp("\\b" + NUM + " rules\\b", "gi"), expect: registryCount, kind: "N rules" },
    { re: new RegExp("\\b" + NUM + " today\\b", "gi"), expect: registryCount, kind: "N today", needsRulesOnLine: true },
  ];
  const claimed = [];
  const overlaps = (a, b) => a.start < b.end && b.start < a.end;
  const out = [];
  const lineMentionsRules = /\brules?\b/i.test(line);
  for (const p of patterns) {
    if (p.needsRulesOnLine && !lineMentionsRules) continue;
    for (const m of line.matchAll(p.re)) {
      const span = { start: m.index, end: m.index + m[0].length };
      if (claimed.some((c) => overlaps(c, span))) continue;
      claimed.push(span);
      // A sweep row label like "224 rules (16x)" is a synthetic registry size, not a claim about
      // the shipped registry. Recognised by shape, so no snippet exemption is spent on each row.
      if (p.kind === "N rules" && /^\s*\(\d+x\)/.test(line.slice(span.end))) {
        out.push({ text: m[0], value: parseNum(m[1]), expect: p.expect, kind: "sweep label", span, sweepLabel: true });
        continue;
      }
      const value = parseNum(m[1]);
      if (value < COUNT_FLOOR) continue;
      out.push({ text: m[0], value, expect: p.expect, kind: p.kind, span, sweepLabel: false });
    }
  }
  return out;
}

/** Every NAME = value citation that names a source file, in one line of text. */
export function codeCitedConstantsIn(line) {
  const out = [];
  const re = /`?\b([A-Z][A-Z0-9_]{3,})\s*=\s*(\d+)\b`?\s*\(`?([A-Za-z0-9_./-]+\.(?:ts|mjs|js))(?::\d+)?`?\)/g;
  for (const m of line.matchAll(re)) {
    out.push({ name: m[1], value: Number(m[2]), citedFile: m[3], text: m[0] });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The runner. Everything below does I/O and only runs when this file is the program.
// ---------------------------------------------------------------------------------------------

async function main() {
  const listOnly = process.argv.includes("--list");
  let fail = 0;
  let ran = 0;
  const check = (label, ok, detail) => {
    ran++;
    console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${detail ? `: ${detail}` : ""}`);
    if (!ok) fail++;
  };

  const distFile = (name) => {
    const file = path.join(DIST, name);
    if (!fs.existsSync(file)) {
      console.error(
        `check-constants: ${file} is missing.\n` +
          "The truth this gate compares against is the BUILT kit, the same artifact the corpus\n" +
          "grades, so there is no second hand-kept list here to drift.\n" +
          "build it first:  npm run build -w @launchpad/server",
      );
      process.exit(1);
    }
    return pathToFileURL(file).href;
  };

  const rulesModule = await import(distFile(path.join("rules", "index.js")));
  const registryCount = Array.isArray(rulesModule.rules) ? rulesModule.rules.length : 0;
  if (registryCount === 0) {
    console.error("check-constants: dist rules/index.js exports no non-empty rules array.");
    process.exit(1);
  }

  if (listOnly) {
    console.log("check-constants guards, against the built kit as the only source of truth:");
    console.log("");
    console.log("A. private copies of production constants:");
    for (const c of CONSTANT_COPIES) {
      console.log(`   ${c.truthExport} from dist/${c.truthModule}${c.kind === "scalar" ? " (scalar)" : ""}`);
      for (const copy of c.copies) console.log(`     - ${copy.file} (${copy.identifier})`);
    }
    console.log("");
    console.log("A2. property sweep over every tracked .mjs/.ts/.js file in " + SWEEP_SCOPE.join(", ") + ":");
    for (const s of PROPERTY_SWEEPS) {
      console.log(
        `   any array literal carrying ${s.kind === "string" ? `the exact element "${s.needle}"` : `a regex matching ${s.needle}`}` +
          ` must be set-equal to ${s.truthExport}`,
      );
    }
    console.log("");
    console.log(`B. registry rule counts stated in every git-tracked .md file, judged against the`);
    console.log(`   built registry (currently ${registryCount}). Patterns: "the other N rules" expects`);
    console.log(`   ${registryCount - 1}; "N-rule registry", "registry of N rules", "N rules" and, on lines that`);
    console.log(`   mention rules, "N today" expect ${registryCount}. Counts below ${COUNT_FLOOR} are not judged.`);
    console.log(`   "N rules (Mx)" is recognised as a sweep row label and not judged.`);
    console.log("");
    console.log("C. NAME = value citations that name a source file, checked against that file");
    console.log("   under apps/server/src. Line numbers in citations are not checked.");
    console.log("");
    console.log("exemptions, each printed and rot-checked on every run:");
    for (const e of COUNT_EXEMPTIONS) {
      const label = e.dirPrefix
        ? `${e.dirPrefix} (whole directory)`
        : `${e.file}${e.wholeFile ? " (whole file)" : ` "${e.snippet}"`}`;
      console.log(`   - ${label}: ${e.reason}`);
    }
    console.log("");
    console.log("");
    console.log("declared blind spot: Check B and C scan one physical line at a time, so a count split");
    console.log("  across a line break (number on one line, its noun on the next) is invisible. Ordinal");
    console.log("  shapes ('first of the 17 rules', 'last of the sixteen') ARE judged now. The rule-count");
    console.log("  patterns and the tier-count gate (check-tier-counts.mjs, stage 12) are complementary.");
    console.log("declared blind spot: the sweep reads ARRAY LITERALS. A copy that is computed (built");
    console.log("  by filtering, assembled from parts) or reshaped (a set, longhand regex tests) is");
    console.log("  invisible to it. A grep on 2026-08-31 found no literal reshaped copy, but a copy");
    console.log("  that never names the sentinel is beyond both grep and this sweep. Full list of");
    console.log("  what it cannot check is in the header of this file; read it before trusting a pass.");
    return;
  }

  // ---- A. private copies against the built constant ------------------------------------------
  console.log("A. private copies of production constants:");
  for (const c of CONSTANT_COPIES) {
    const truthModule = await import(distFile(c.truthModule));
    const truth = truthModule[c.truthExport];
    if (c.kind === "scalar") {
      check(
        `dist/${c.truthModule} exports ${c.truthExport}`,
        Number.isFinite(truth),
        Number.isFinite(truth) ? String(truth) : "not a finite number; the truth side is broken",
      );
      if (!Number.isFinite(truth)) continue;
      for (const copy of c.copies) {
        const file = path.join(KIT, copy.file);
        if (!fs.existsSync(file)) {
          check(`${copy.file} still exists`, false, "the guarded copy site is gone; update CONSTANT_COPIES");
          continue;
        }
        const value = extractScalar(fs.readFileSync(file, "utf8"), copy.identifier);
        if (value === null) {
          check(
            `${copy.file} defines ${copy.identifier}`,
            false,
            "no N or N * M literal found; if the copy now imports the constant, delete its entry",
          );
          continue;
        }
        check(
          `${copy.file} ${copy.identifier} matches ${c.truthExport}`,
          value === truth,
          value === truth ? String(value) : `copy says ${value}, the source says ${truth}`,
        );
      }
      continue;
    }
    check(
      `dist/${c.truthModule} exports ${c.truthExport}`,
      Array.isArray(truth) && truth.length > 0,
      Array.isArray(truth) ? `${truth.length} entries` : "not an array; the truth side is broken, nothing below can be trusted",
    );
    if (!Array.isArray(truth) || truth.length === 0) continue;
    for (const copy of c.copies) {
      const file = path.join(KIT, copy.file);
      if (!fs.existsSync(file)) {
        check(`${copy.file} still exists`, false, "the guarded copy site is gone; update CONSTANT_COPIES");
        continue;
      }
      const found = extractArrayLiteral(fs.readFileSync(file, "utf8"), copy.identifier);
      if (found === null) {
        check(
          `${copy.file} defines ${copy.identifier}`,
          false,
          "no array literal found; if the copy was removed in favour of importing the constant, " +
            "delete its entry from CONSTANT_COPIES so this table cannot rot",
        );
        continue;
      }
      const { missing, extra } = diffSets(truth, found);
      const same = missing.length === 0 && extra.length === 0;
      check(
        `${copy.file} ${copy.identifier} matches ${c.truthExport}`,
        same,
        same
          ? `${found.length} entries`
          : [
              missing.length ? `missing ${missing.join(", ")}` : "",
              extra.length ? `extra ${extra.join(", ")}` : "",
              copy.note ?? "",
            ].filter(Boolean).join("; "),
      );
    }
  }

  // ---- A2. the property sweep: sentinel elements find the copies no table names ---------------
  console.log("A2. property sweep for unlisted copies, by sentinel element:");
  const sweepFiles = execFileSync("git", ["ls-files", "--", ...SWEEP_SCOPE], { cwd: KIT, encoding: "utf8" })
    .split("\n")
    .filter((f) => /\.(mjs|ts|js|mts|cjs)$/.test(f));
  const HERE_REL = path.relative(KIT, fileURLToPath(import.meta.url));
  const sweepExemptionUsed = SWEEP_EXEMPTIONS.map(() => false);
  for (const sweep of PROPERTY_SWEEPS) {
    const truthModule = await import(distFile(sweep.truthModule));
    const raw = truthModule[sweep.truthExport];
    const truth =
      sweep.kind === "regex" ? raw.map((r) => (r.flags ? `${r.source}/${r.flags}` : r.source)) : raw;
    check(
      `dist/${sweep.truthModule} exports ${sweep.truthExport}`,
      Array.isArray(truth) && truth.length > 0,
      `${truth.length} entries; sentinel "${sweep.needle}"`,
    );
    const named = new Set(
      CONSTANT_COPIES.filter((c) => c.truthExport === sweep.truthExport).flatMap((c) =>
        c.copies.map((x) => x.file),
      ),
    );
    let swept = 0;
    let copiesFound = 0;
    for (const rel of sweepFiles) {
      if (rel === HERE_REL || named.has(rel)) continue;
      swept++;
      const text = fs.readFileSync(path.join(KIT, rel), "utf8");
      if (!text.includes(sweep.needle)) continue;
      const fileLines = text.split("\n");
      for (const hit of scanArraysContaining(text, sweep.needle, sweep.kind)) {
        const declLine = fileLines[hit.line - 1] ?? "";
        const exemptIndex = SWEEP_EXEMPTIONS.findIndex(
          (e) => e.file === rel && declLine.includes(e.marker),
        );
        if (exemptIndex >= 0) {
          sweepExemptionUsed[exemptIndex] = true;
          console.log(`  exempt ${rel}:${hit.line} (${SWEEP_EXEMPTIONS[exemptIndex].marker}): ${SWEEP_EXEMPTIONS[exemptIndex].reason}`);
          continue;
        }
        copiesFound++;
        const { missing, extra } = diffSets(truth, hit.elements);
        const same = missing.length === 0 && extra.length === 0;
        check(
          `${rel}:${hit.line} array carrying "${sweep.needle}" is set-equal to ${sweep.truthExport}`,
          same,
          same
            ? `${hit.elements.length} entries`
            : [
                missing.length ? `missing ${missing.join(", ")}` : "",
                extra.length ? `extra ${extra.join(", ")}` : "",
                sweep.note ?? "",
              ].filter(Boolean).join("; "),
        );
      }
    }
    console.log(
      `         swept ${swept} files for "${sweep.needle}", found ${copiesFound} unlisted ` +
        `cop${copiesFound === 1 ? "y" : "ies"} beyond the ${named.size} named ones`,
    );
  }

  // ---- the md corpus for B and C --------------------------------------------------------------
  const mdFiles = execFileSync("git", ["ls-files", "--", "*.md"], { cwd: KIT, encoding: "utf8" })
    .split("\n")
    .filter(Boolean);

  // exemption bookkeeping: every entry must earn its place on this run
  const exemptionUsed = COUNT_EXEMPTIONS.map(() => false);
  const exemptionFor = (file, line, span) => {
    for (let i = 0; i < COUNT_EXEMPTIONS.length; i++) {
      const e = COUNT_EXEMPTIONS[i];
      if (e.dirPrefix) {
        if (!file.startsWith(e.dirPrefix)) continue;
        exemptionUsed[i] = true;
        return e;
      }
      if (e.file !== file) continue;
      if (e.wholeFile) {
        exemptionUsed[i] = true;
        return e;
      }
      const at = line.indexOf(e.snippet);
      if (at >= 0 && at < span.end && span.start < at + e.snippet.length) {
        exemptionUsed[i] = true;
        return e;
      }
    }
    return null;
  };

  // ---- B. stated rule counts ------------------------------------------------------------------
  console.log(`B. registry rule counts in ${mdFiles.length} tracked documents, registry is ${registryCount}:`);
  let judged = 0;
  let exempted = 0;
  let sweepLabels = 0;
  const countFailures = [];
  for (const rel of mdFiles) {
    const lines = fs.readFileSync(path.join(KIT, rel), "utf8").split("\n");
    for (let n = 0; n < lines.length; n++) {
      for (const claim of countClaimsIn(lines[n], registryCount)) {
        if (claim.sweepLabel) {
          sweepLabels++;
          continue;
        }
        judged++;
        if (claim.value === claim.expect) continue;
        const e = exemptionFor(rel, lines[n], claim.span);
        if (e) {
          exempted++;
          console.log(`  exempt ${rel}:${n + 1} "${claim.text}": ${e.reason}`);
          continue;
        }
        countFailures.push(`${rel}:${n + 1} says "${claim.text}" (${claim.kind} expects ${claim.expect})`);
      }
    }
  }
  check(
    `every stated registry count agrees with the built registry`,
    countFailures.length === 0,
    countFailures.length === 0
      ? `${judged} claims judged, ${exempted} exempt, ${sweepLabels} sweep labels recognised`
      : `${countFailures.length} stale of ${judged} judged`,
  );
  for (const f of countFailures) console.log(`         ${f}`);
  check("the count patterns judged at least one claim", judged > 0, `${judged}; zero would mean the scan is broken, not that the docs are clean`);

  // ---- C. code-cited constants ----------------------------------------------------------------
  console.log("C. named constants cited with a source file:");
  const srcRoot = path.join(KIT, "apps", "server", "src");
  const byBasename = new Map();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else {
        if (!byBasename.has(entry.name)) byBasename.set(entry.name, []);
        byBasename.get(entry.name).push(full);
      }
    }
  };
  walk(srcRoot);
  let cited = 0;
  let citedExempt = 0;
  for (const rel of mdFiles) {
    const lines = fs.readFileSync(path.join(KIT, rel), "utf8").split("\n");
    for (let n = 0; n < lines.length; n++) {
      for (const c of codeCitedConstantsIn(lines[n])) {
        const e = exemptionFor(rel, lines[n], { start: 0, end: lines[n].length });
        if (e) {
          citedExempt++;
          console.log(`  exempt ${rel}:${n + 1} "${c.text}": ${e.reason}`);
          continue;
        }
        cited++;
        const candidates = byBasename.get(path.basename(c.citedFile)) ?? [];
        if (candidates.length === 0) {
          check(`${rel}:${n + 1} cites ${c.citedFile}`, false, "no such file under apps/server/src");
          continue;
        }
        const texts = candidates.map((f) => fs.readFileSync(f, "utf8"));
        const holding = texts.filter((t) => t.includes(c.name));
        if (holding.length === 0) {
          check(
            `${rel}:${n + 1} cites ${c.name} in ${c.citedFile}`,
            false,
            "the named constant is not in that file any more; a retired boundary is still documented as current",
          );
          continue;
        }
        const defined = holding
          .map((t) => new RegExp("\\b" + c.name + "\\s*=\\s*(\\d+)").exec(t))
          .find(Boolean);
        if (!defined) {
          console.log(
            `  note  ${rel}:${n + 1} ${c.name} exists in ${c.citedFile} but is not defined as a` +
              ` bare numeric literal there, so the stated value ${c.value} is not compared`,
          );
          ran++;
          continue;
        }
        check(
          `${rel}:${n + 1} ${c.name} = ${c.value} matches ${c.citedFile}`,
          Number(defined[1]) === c.value,
          Number(defined[1]) === c.value ? undefined : `the source says ${defined[1]}`,
        );
      }
    }
  }
  console.log(`         ${cited} citation${cited === 1 ? "" : "s"} judged, ${citedExempt} exempt`);

  // ---- exemption rot --------------------------------------------------------------------------
  console.log("exemption list self-check:");
  for (let i = 0; i < COUNT_EXEMPTIONS.length; i++) {
    const e = COUNT_EXEMPTIONS[i];
    const label = e.dirPrefix ?? `${e.file}${e.wholeFile || !e.snippet ? "" : ` "${e.snippet}"`}`;
    if (!e.dirPrefix) {
      const file = path.join(KIT, e.file);
      if (!fs.existsSync(file)) {
        check(`exemption file ${e.file} exists`, false, "the excuse outlived the file");
        continue;
      }
      if (!e.wholeFile && !fs.readFileSync(file, "utf8").includes(e.snippet)) {
        check(`exemption snippet still in ${e.file}`, false, `"${e.snippet}" is gone; delete the entry`);
        continue;
      }
    }
    check(
      `exemption ${label} still covers something`,
      exemptionUsed[i],
      exemptionUsed[i] ? e.reason : "it excused nothing on this run; delete the entry",
    );
  }
  for (let i = 0; i < SWEEP_EXEMPTIONS.length; i++) {
    const e = SWEEP_EXEMPTIONS[i];
    const file = path.join(KIT, e.file);
    if (!fs.existsSync(file)) {
      check(`sweep exemption file ${e.file} exists`, false, "the excuse outlived the file");
      continue;
    }
    if (!fs.readFileSync(file, "utf8").includes(e.marker)) {
      check(`sweep exemption marker still in ${e.file}`, false, `"${e.marker}" is gone; delete the entry`);
      continue;
    }
    check(
      `sweep exemption ${e.file} (${e.marker}) still covers something`,
      sweepExemptionUsed[i],
      sweepExemptionUsed[i] ? e.reason : "it excused nothing on this run; delete the entry",
    );
  }

  console.log("");
  if (ran === 0) {
    console.log("FAIL: zero checks ran, which is not a pass.");
    process.exit(1);
  }
  if (fail > 0) {
    console.log(`FAIL: ${fail} of ${ran} checks. This gate never rewrites a file: every fix above`);
    console.log("      belongs to the file's owner. Before snapping a copy to production, check");
    console.log("      whether the copy is actually READ where it lives: a copy that feeds corpus");
    console.log("      generation needs a regenerate and a replay, while a dead copy can just be");
    console.log("      deleted with a pointer to the real constant. Do not assume which; grep it.");
    process.exit(1);
  }
  console.log(`PASS: ${ran} checks. What this does not cover is stated in the file header and --list.`);
}

const HERE = fileURLToPath(import.meta.url);
const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invoked === HERE) await main();

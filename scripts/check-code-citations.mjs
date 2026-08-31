// Every `path/to/file.ts:NNN` citation in the documents, checked against the file it names.
//
//   node scripts/check-code-citations.mjs            # the gate
//   node scripts/check-code-citations.mjs --list     # every citation it found, resolved
//
// WHY THIS EXISTS. Documents here cite code by line, which is the right thing to do and is only true
// until somebody edits the file. On 31 August 2026 two lanes ran at once: one wrote a page citing
// `transactional-runner.ts` by line, the other added 87 lines to that file, and four citations that
// were correct against HEAD were wrong in the working tree before either was committed. Nothing
// would have caught it. A reviewer reading the page follows a line number into unrelated code and
// stops trusting the page, which is a worse outcome than the page not citing anything.
//
// WHAT IT CAN AND CANNOT DO, stated because a gate that implies more than it checks is the defect it
// is meant to prevent:
//   - It CAN prove a cited line exists, that a cited file exists, and that a fenced quotation
//     immediately following a citation still appears in the file it points at. Note "in the file":
//     the quotation is searched whole-file, never at the cited line, so it cannot catch a citation
//     whose number drifted away from the text quoted under it.
//   - It does NOT read a quotation written in inline backticks, which is how these pages write
//     most of them. Measured on 31 August 2026: exactly one citation across all of these documents
//     carried a fenced quotation, so the quotation half of this gate covers almost nothing. The
//     summary prints that count live, so it cannot imply a coverage it does not have.
//   - It CANNOT prove the cited line still does what the sentence says. That needs a reader.
//
// It never edits a document. A gate that repairs what it checks passes next run whether or not
// anybody looked.
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const LIST = process.argv.includes("--list");

// The documents a judge or a reviewer actually opens. Test files and code comments are excluded:
// they cite freely as working notes and holding them to this would produce noise nobody acts on.
const DOC_GLOBS = [
  "README.md",
  "docs/ARCHITECTURE.md",
  "docs/README.md",
  "docs/DESIGN-CASE.md",
  "research/METRICS.md",
  "research/LEAKAGE-PROOF.md",
  "apps/server/src/bench/RESULTS.md",
  "evidence/demo-run/README.md",
  "evidence/demo-run/BEATS.md",
];

// A citation is a source path with a line, in backticks or bare: apps/server/src/x.ts:123 and
// x.ts:123-140 both count. The extension list is deliberate: `.md:12` is a document reference and
// `3161:` in prose is a ratio, and neither is a code citation.
const CITE = /([A-Za-z0-9_./-]+\.(?:ts|tsx|js|mjs|cjs|sh|yml|yaml|json))[:#](\d+)(?:\s*[-–]\s*(\d+))?/g;

const problems = [];
const found = [];
let quotesChecked = 0;
const lineCache = new Map();

function linesOf(rel) {
  if (lineCache.has(rel)) return lineCache.get(rel);
  const abs = path.join(ROOT, rel);
  const v = fs.existsSync(abs) && fs.statSync(abs).isFile()
    ? fs.readFileSync(abs, "utf8").split("\n")
    : null;
  lineCache.set(rel, v);
  return v;
}

// A quotation matches if some real line of the file contains it, or if the quotation contains a
// real line (a quote can carry slightly more than the line, such as a trailing comment). Blank
// lines are excluded, and that exclusion is the entire point: every source file has a blank line,
// `quoted.includes("")` is true, and until 31 August 2026 that made this comparison accept every
// quotation it was ever handed, including deliberately wrong ones. A check that cannot fail is not
// a check, and the summary was reporting it as one.
function quoteAppearsIn(rel, quoted) {
  return (linesOf(rel) ?? []).some((raw) => {
    const line = raw.trim();
    if (!line) return false;
    return line.includes(quoted) || (line.length >= 12 && quoted.includes(line));
  });
}

// These pages cite by bare basename far more often than by path: `overlay-sealer.ts:466`, not
// `apps/server/src/overlay-sealer.ts:466`. That is the house convention and it reads better, so the
// resolver has to follow it rather than the documents being rewritten to suit a checker. The index
// is built from the tracked file list, and a basename matching more than one tracked file is
// reported as AMBIGUOUS rather than guessed at: guessing is how a checker starts certifying the
// wrong file.
const tracked = execSync("git ls-files", { cwd: ROOT, encoding: "utf8" }).split("\n").filter((r) => r.trim());
const byBasename = new Map();
for (const rel of tracked) {
  if (!rel.trim()) continue;
  const base = path.basename(rel);
  if (!byBasename.has(base)) byBasename.set(base, []);
  byBasename.get(base).push(rel);
}

/** Repo root, then the document's own directory, then the tracked-file basename index. */
function resolveCited(cited, docDir) {
  for (const candidate of [cited, path.join(docDir, cited)]) {
    const normalised = path.normalize(candidate);
    if (linesOf(normalised)) return normalised;
  }
  if (!cited.includes("/")) {
    const hits = byBasename.get(cited) ?? [];
    if (hits.length === 1) return hits[0];
    if (hits.length > 1) return { ambiguous: hits };
    return null;
  }
  // A partial path, which is the third convention in use: `rules/blast-radius.ts` for a file under
  // apps/server/src, `lib/expected-verdict.mjs` for one under research/corpus. Matched on a path
  // SUFFIX at a segment boundary, so `rules/blast-radius.ts` cannot be satisfied by a file called
  // `other-rules/blast-radius.ts`.
  const suffix = "/" + cited;
  const hits = tracked.filter((rel) => rel.endsWith(suffix));
  if (hits.length === 1) return hits[0];
  if (hits.length > 1) return { ambiguous: hits };
  return null;
}

for (const doc of DOC_GLOBS) {
  const abs = path.join(ROOT, doc);
  if (!fs.existsSync(abs)) continue;
  const text = fs.readFileSync(abs, "utf8");
  const docDir = path.dirname(doc);
  const docLines = text.split("\n");

  for (const m of text.matchAll(CITE)) {
    const [whole, cited, fromStr, toStr] = m;
    const from = Number(fromStr);
    const to = toStr ? Number(toStr) : from;
    const at = text.slice(0, m.index).split("\n").length;

    const resolved = resolveCited(cited, docDir);
    if (!resolved) {
      problems.push({ doc, at, whole, why: `no such file: ${cited}` });
      continue;
    }
    if (resolved.ambiguous) {
      problems.push({
        doc, at, whole,
        why: `${cited} names ${resolved.ambiguous.length} tracked files, so this citation is ambiguous`,
        hint: resolved.ambiguous.join(", "),
      });
      continue;
    }
    const lines = linesOf(resolved);
    if (to > lines.length) {
      problems.push({
        doc, at, whole,
        why: `${resolved} has ${lines.length} lines, the citation names ${to}`,
        hint: "a lane editing that file can shorten it under a document that cites it",
      });
      continue;
    }
    found.push({ doc, at, whole, resolved, from, to, text: (lines[from - 1] ?? "").trim().slice(0, 90) });
  }

  // A fenced block within three lines after a citation is treated as a quotation OF that citation,
  // which is the shape these pages use. Only single-line quotes are checked: a multi-line block may
  // be elided or reformatted on purpose, and flagging those would train people to ignore this.
  //
  // Inline backtick quotations are NOT checked, and that was measured before it was decided rather
  // than assumed. Extending this to the tightest defensible inline shape, a code-shaped span on the
  // citation's own line with paths and other citations excluded, flagged 5 places on 31 August 2026
  // and 3 of them were correct prose. These pages quote code by paraphrase on purpose: they write
  // Pick<..., "seal" | "release"> for a type whose argument is spelled out in the source, and
  // allowedPathGlobs: ["**"] for a line that wraps that value in Object.freeze. Both read better
  // than the literal text and both are true. Widening the window to three lines took it to 33 flags,
  // nearly all of them identifiers and references to other files that were never quotations at all.
  // A gate at that false-positive rate gets switched off, so the summary reports the narrow coverage
  // instead of the checker growing a reach it cannot hold.
  for (let i = 0; i < docLines.length; i++) {
    const cite = [...(docLines[i] ?? "").matchAll(CITE)][0];
    if (!cite) continue;
    let j = i + 1;
    while (j < docLines.length && j <= i + 3 && !docLines[j].trim().startsWith("```")) j++;
    if (j > i + 3 || j >= docLines.length) continue;
    const close = docLines.indexOf("```", j + 1);
    if (close < 0 || close - j !== 2) continue;              // exactly one line inside the fence
    const quoted = (docLines[j + 1] ?? "").trim();
    if (quoted.length < 12) continue;
    const resolved = resolveCited(cite[1], docDir);
    if (!resolved || resolved.ambiguous) continue;
    quotesChecked++;
    if (!quoteAppearsIn(resolved, quoted)) {
      problems.push({
        doc, at: i + 1, whole: cite[0],
        why: `the quoted line is not in ${resolved} any more`,
        hint: quoted.slice(0, 80),
      });
    }
  }
}

if (LIST) {
  for (const f of found) console.log(`  ${f.doc}:${f.at}  ${f.whole}  ->  ${f.text}`);
  console.log(`\n${found.length} resolvable citation(s) across ${DOC_GLOBS.length} document(s)`);
}

if (problems.length === 0) {
  console.log(`ok   ${found.length} code citation(s) resolve, in ${DOC_GLOBS.filter((d) => fs.existsSync(path.join(ROOT, d))).length} document(s)`);
  console.log("     This proves each cited file exists and each cited line number is inside that file.");
  console.log(`     Quotations actually compared against the file: ${quotesChecked} of ${found.length}. The one shape read here`);
  console.log("     is a fenced one-line block right after a citation, and it is looked for ANYWHERE in the");
  console.log("     file rather than at the cited line, so a quotation can match while the line number next");
  console.log("     to it is stale. The rest were checked for line existence alone. A quotation in inline");
  console.log("     backticks is not read at all, because these pages quote code by paraphrase, and checking");
  console.log("     those literally flagged 5 places on 31 August 2026 of which 3 were correct prose.");
  console.log("     IT DOES NOT PROVE THE CITED LINE STILL DOES WHAT THE SENTENCE SAYS. A lane that");
  console.log("     inserts 87 lines above a citation leaves it resolving, and pointing at the wrong");
  console.log("     code. That happened here on 31 August 2026 and only a reader caught it. Read the");
  console.log("     citations in any document a lane edited while another lane edited the code.");
  process.exit(0);
}

console.log(`FAIL: ${problems.length} code citation(s) do not resolve.\n`);
for (const p of problems) {
  console.log(`  ${p.doc}:${p.at}  ${p.whole}`);
  console.log(`      ${p.why}`);
  if (p.hint) console.log(`      ${p.hint}`);
  console.log("");
}
console.log("      Fix the document. If the code moved, re-read it and re-cite; do not shift the");
console.log("      number until it lands somewhere, because a citation that resolves to the wrong");
console.log("      line is worse than one that resolves to none.");
process.exit(1);

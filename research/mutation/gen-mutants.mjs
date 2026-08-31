// gen-mutants.mjs: enumerate mutants of the BUILT rule modules.
//
//   node gen-mutants.mjs <dist-dir> <out-manifest.json> [--max N] [--seed s]
//
// Mutating the built JS rather than the TypeScript means no rebuild per mutant: a mutant is a
// one-file text substitution inside a copy of dist/, and the harness already accepts
// `--policy <any-dist>/shadow-policy.js`.
//
// THE THING THAT WOULD MAKE THIS DISHONEST. tsc keeps comments, and the rule modules in this repo
// are heavily commented -- several are more prose than code. A mutation that lands in a comment or
// inside a string literal cannot change any verdict, so it survives every time, and a survivor
// count polluted with them measures the comment density of the source rather than the coverage of
// the corpus. So positions are masked first: the scanner below tracks line comments, block
// comments, both quote forms, template literals and regex literals, and ordinary mutations are
// only ever applied at positions the scanner calls CODE. Regex mutations are applied only inside
// regex literals, deliberately, because widening a pattern is one of the mutations we most want.
import fs from "node:fs";
import path from "node:path";

const DIST = process.argv[2];
const OUT = process.argv[3];
const argOf = (f, d) => { const i = process.argv.indexOf(f); return i >= 0 ? process.argv[i + 1] : d; };
const MAX = Number(argOf("--max", "100000"));

// ---------------------------------------------------------------------------
// Position classifier. Returns an array of one char per source char:
//   'c' code, '#' comment, 's' string/template, 'r' regex literal body
// ---------------------------------------------------------------------------
function classify(src) {
  const m = new Array(src.length).fill("c");
  let i = 0;
  const prevSignificant = (k) => { let j = k - 1; while (j >= 0 && /\s/.test(src[j])) j--; return j >= 0 ? src[j] : ""; };
  while (i < src.length) {
    const ch = src[i], nx = src[i + 1];
    if (ch === "/" && nx === "/") { while (i < src.length && src[i] !== "\n") m[i++] = "#"; continue; }
    if (ch === "/" && nx === "*") { m[i++] = "#"; m[i++] = "#";
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) m[i++] = "#";
      if (i < src.length) { m[i++] = "#"; m[i++] = "#"; } continue; }
    if (ch === '"' || ch === "'" || ch === "`") { const q = ch; m[i++] = "s";
      while (i < src.length) { if (src[i] === "\\") { m[i++] = "s"; if (i < src.length) m[i++] = "s"; continue; }
        if (src[i] === q) { m[i++] = "s"; break; } m[i++] = "s"; } continue; }
    if (ch === "/") {
      // A '/' starts a regex only where a value cannot precede it. Good enough for emitted tsc output.
      const p = prevSignificant(i);
      if (p === "" || "(=,:[!&|?{};+-*%<>~^".includes(p) || /[\s]/.test(p)) {
        let j = i + 1, inClass = false, ok = false;
        while (j < src.length && src[j] !== "\n") {
          if (src[j] === "\\") { j += 2; continue; }
          if (src[j] === "[") inClass = true;
          else if (src[j] === "]") inClass = false;
          else if (src[j] === "/" && !inClass) { ok = true; break; }
          j++;
        }
        if (ok) { m[i] = "c"; for (let k = i + 1; k < j; k++) m[k] = "r"; m[j] = "c"; i = j + 1; continue; }
      }
    }
    i++;
  }
  return m;
}

const allCode = (mask, at, len) => { for (let k = at; k < at + len; k++) if (mask[k] !== "c") return false; return true; };
const allRe   = (mask, at, len) => { for (let k = at; k < at + len; k++) if (mask[k] !== "r") return false; return true; };

// ---------------------------------------------------------------------------
// Operators.
// ---------------------------------------------------------------------------
const CODE_SWAPS = [
  [">=", ">", "comparison"], [">", ">=", "comparison"],
  ["<=", "<", "comparison"], ["<", "<=", "comparison"],
  ["===", "!==", "equality"], ["!==", "===", "equality"],
  ["&&", "||", "logical"],   ["||", "&&", "logical"],
];
const RE_SWAPS = [["+", "*", "regex-widen"], ["*", "+", "regex-narrow"], ["\\b", "", "regex-drop-word-boundary"]];

function mutantsFor(rel, src) {
  const mask = classify(src);
  const out = [];
  const push = (at, len, to, kind, from) =>
    out.push({ file: rel, at, len, to, kind, from, id: `${rel.replace(/[^\w]/g, "_")}@${at}:${kind}` });

  // Longest-token-first so '>=' is not matched as '>'.
  const ordered = [...CODE_SWAPS].sort((a, b) => b[0].length - a[0].length);
  const claimed = new Set();
  for (const [from, to, kind] of ordered) {
    let at = src.indexOf(from);
    while (at !== -1) {
      const clash = [...Array(from.length)].some((_, k) => claimed.has(at + k));
      if (!clash && allCode(mask, at, from.length)) {
        // '<' and '>' also appear as arrow-function and generic syntax in emitted JS; require an
        // adjacent space, which tsc emits around real comparison operators and not around '=>'.
        const looksBinary = !(from === "<" || from === ">") || (src[at - 1] === " " && src[at + 1] === " ");
        if (looksBinary && src[at - 1] !== "=" && src[at + 1] !== "=") {
          push(at, from.length, to, kind, from);
          for (let k = 0; k < from.length; k++) claimed.add(at + k);
        }
      }
      at = src.indexOf(from, at + 1);
    }
  }

  // Numeric literals: +1 and -1. Thresholds are where an off-by-one actually decides something.
  for (const m of src.matchAll(/\b\d+\b/g)) {
    const at = m.index, len = m[0].length;
    if (!allCode(mask, at, len)) continue;
    if (src[at - 1] === "." || src[at + len] === ".") continue;   // not a version-ish fragment
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) continue;
    push(at, len, String(n + 1), "off-by-one-up", m[0]);
    if (n > 0) push(at, len, String(n - 1), "off-by-one-down", m[0]);
  }

  // Regex literal bodies.
  for (const [from, to, kind] of RE_SWAPS) {
    let at = src.indexOf(from);
    while (at !== -1) {
      if (allRe(mask, at, from.length) && src[at - 1] !== "\\") push(at, from.length, to, kind, from);
      at = src.indexOf(from, at + 1);
    }
  }

  // Negate an if condition: `if (` -> `if (!(` ... needs the matching paren, so find it.
  for (const m of src.matchAll(/\bif\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    if (!allCode(mask, m.index, m[0].length)) continue;
    let depth = 0, j = open;
    for (; j < src.length; j++) {
      if (mask[j] !== "c") continue;
      if (src[j] === "(") depth++;
      else if (src[j] === ")") { depth--; if (depth === 0) break; }
    }
    if (j >= src.length) continue;
    out.push({ file: rel, at: open, len: j - open + 1, to: "(!(" + src.slice(open + 1, j) + "))",
               from: src.slice(open, j + 1), kind: "negate-condition",
               id: `${rel.replace(/[^\w]/g, "_")}@${open}:negate-condition` });
  }
  return out;
}

const ruleFiles = fs.readdirSync(path.join(DIST, "rules"))
  .filter((f) => f.endsWith(".js") && f !== "index.js" && f !== "rule.js")
  .sort();

let all = [];
const perFile = {};
for (const f of ruleFiles) {
  const rel = path.join("rules", f);
  const src = fs.readFileSync(path.join(DIST, rel), "utf8");
  const ms = mutantsFor(rel, src);
  perFile[rel] = ms.length;
  all = all.concat(ms);
}

// Interleave by file so a run that is cut short still covers every rule rather than the first two
// alphabetically. This is the difference between a partial result that is usable and one that is not.
const byFile = new Map();
for (const m of all) { if (!byFile.has(m.file)) byFile.set(m.file, []); byFile.get(m.file).push(m); }
const lists = [...byFile.values()];
const interleaved = [];
for (let i = 0; interleaved.length < all.length; i++)
  for (const l of lists) if (i < l.length) interleaved.push(l[i]);

const chosen = interleaved.slice(0, MAX);
fs.writeFileSync(OUT, JSON.stringify({ dist: DIST, total: all.length, chosen: chosen.length, perFile, mutants: chosen }, null, 1) + "\n");
console.log(`${all.length} mutants across ${ruleFiles.length} rule modules; running ${chosen.length}`);
for (const f of Object.keys(perFile).sort()) console.log(`  ${String(perFile[f]).padStart(5)}  ${f}`);

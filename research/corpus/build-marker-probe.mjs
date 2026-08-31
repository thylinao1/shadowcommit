// Two arms of the same scenarios: the marker the generator writes today, and the marker the format
// actually uses. Nothing else differs, so any verdict that moves between the two arms moves because
// of the marker.
//
//   node research/corpus/build-marker-probe.mjs
//
// The two probe files are NOT committed: 5.7 MB each, and every byte of them is derivable from
// scenarios/benign.jsonl, which regenerates byte-identically from its seeds. See
// PROBE-COMMENT-MARKERS.md for what they measured.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CORPUS = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(CORPUS, "scenarios", "benign.jsonl");

// The formats commentFor hands a "#" that is not that format's line comment. Each entry says how the
// format really comments, and whether it has a line form at all.
const WRONG = {
  mod:  { line: "//" },                                  // go.mod comments with //, never #
  xml:  { open: "<!-- ", close: " -->" },                // # is content, and content after the root is a parse error
  css:  { open: "/* ",   close: " */" },
  html: { open: "<!-- ", close: " -->" },
  ejs:  { open: "<%# ",  close: " %>" },
  hbs:  { open: "{{! ",  close: " }}" },
  tmpl: { open: "{{/* ", close: " */}}" },               // the cobra/express .tmpl files are Go templates
};

const extOf = (p) => (/\.([A-Za-z0-9]+)$/.exec(p) ?? [])[1] ?? "";
const comment = (ext, text) => {
  const f = WRONG[ext];
  return f.line ? `${f.line} ${text}` : `${f.open}${text}${f.close}`;
};

// The generator writes exactly two shapes of marker line. Recover the text between "# " and the end
// of the injected line, so the fixed arm carries the identical words in the format's own syntax.
const MARKER = /^# (touched by benign edit \S+|refactor \S+)$/;

let scanned = 0, hit = 0, rewritten = 0;
const broken = [], fixed = [];

for (const line of fs.readFileSync(SRC, "utf8").split("\n")) {
  if (!line.trim()) continue;
  scanned++;
  const s = JSON.parse(line);
  let touched = false;
  const fixedEffects = s.effect_set.map((e) => {
    const ext = extOf(e.path);
    if (!WRONG[ext] || typeof e.content !== "string") return e;
    const lines = e.content.split("\n");
    const idx = lines.findIndex((l) => MARKER.test(l));
    if (idx < 0) return e;                     // this effect happens to carry no marker (addDep etc)
    touched = true; rewritten++;
    const text = MARKER.exec(lines[idx])[1];
    const out = lines.slice();
    out[idx] = comment(ext, text);
    return { ...e, content: out.join("\n") };
  });
  if (!touched) continue;
  hit++;
  broken.push(JSON.stringify(s));
  fixed.push(JSON.stringify({ ...s, effect_set: fixedEffects }));
}

const outA = path.join(CORPUS, "scenarios", "probe-marker-broken.jsonl");
const outB = path.join(CORPUS, "scenarios", "probe-marker-fixed.jsonl");
fs.writeFileSync(outA, broken.join("\n") + "\n");
fs.writeFileSync(outB, fixed.join("\n") + "\n");
console.log(`scanned ${scanned} benign scenarios`);
console.log(`carrying a wrong-format marker: ${hit} scenarios, ${rewritten} effects rewritten`);
console.log(`wrote ${path.basename(outA)} and ${path.basename(outB)}`);

// What `net-to-exec` costs in precision, measured on real code rather than argued.
//
//   node research/net-to-exec/precision.mjs
//
// THE RULE. It is the highest-volume control in the registry: ablation credits it with 864 attacks
// uniquely caught against 7 benign holds, a ratio of 123 to 1, and it returns DISCARD, which
// destroys the turn's work. So its precision matters more than any other rule's.
//
// HOW IT DECIDES. `hunksOf` builds a window of five lines, grown until it holds 400 characters, and
// a hunk containing both a SOURCE token and a SINK token is a finding. It is CO-OCCURRENCE, not
// data flow: nothing checks that the fetched value reaches the exec sink.
//
//   fetched body saved, new Function on a literal        DISCARD   (no data flow)
//   fetch in one function, eval of a literal in another  DISCARD   (no data flow)
//   fetched body reaches new Function                    DISCARD   (the real attack)
//   fetch alone / exec alone                             commit
//
// A source is matched against comment-stripped text, so a URL in a licence header does not count.
// A sink is matched against the RAW text, so an exec token inside a string literal does count.
//
// MEASURED ON THE FOUR VENDORED REPOSITORIES. 2 of 277 real source files would be discarded if an
// agent wrote them, and both are false positives:
//
//   click/src/click/_termui_impl.py:420   http-literal + subprocess.   the pager resolver
//   express/test/res.redirect.js:114      http-literal + eval          an XSS-PREVENTION test
//
// The second is the one to keep in mind. It is a test named "should not render evil javascript
// links in anchor href (prevent XSS)", and the `eval` is inside the string literal that IS the
// payload the test defends against. Our policy would refuse express's own XSS test as an attack.
//
// WHY THE OBVIOUS FIX IS WRONG, and this is the part worth reading. Stripping string literals
// before the sink match removes both false positives. It also removes 40 of the 1,380 detections
// this rule currently makes, and the reason is not an accident: every one is a manifest.
//
//   exec-surface-enumeration-0143   src/pyproject.toml
//   exec-surface-enumeration-0148   services/api/internal/handlers/v2/Pyproject.Toml
//   exec-surface-enumeration-0166   ｐｙｐｒｏｊｅｃｔ.ｔｏｍｌ
//
// **In a manifest, the string literal IS the executable content.** `build-backend = "..."` is a
// command. So string-stripping is correct for JavaScript, Python and Go source, where a string is
// data, and wrong for TOML, JSON and YAML, where a string is what runs.
//
// So the fix has a shape, and it is not a one-liner: strip literals only where the file's language
// treats them as data, which means the sink match needs to know what kind of file it is looking at.
// `classifyPath` already distinguishes manifests from source. That is a real change to a rule
// carrying 864 unique catches, and it wants its own measurement rather than a 3am patch.
//
// NOT FIXED HERE ON PURPOSE. This file is the measurement and the argument; the change is routed.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { findNetToExec } from "../../apps/server/dist/rules/net-to-exec.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, "..", "corpus", "repos");
const CODE = /\.(js|mjs|cjs|ts|tsx|py|go|rb|java|php)$/;

if (!fs.existsSync(ROOT)) {
  console.error(`${ROOT} is missing. Run: bash research/corpus/setup.sh`);
  process.exit(1);
}

let scanned = 0;
const hits = [];
function walk(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name === ".git" || e.name === "node_modules") continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { walk(p); continue; }
    if (!CODE.test(e.name)) continue;
    let src;
    try { src = fs.readFileSync(p, "utf8"); } catch { continue; }
    if (src.length > 1_000_000) continue;
    scanned += 1;
    const found = findNetToExec(src, path.relative(ROOT, p));
    if (found.length) hits.push({ rel: path.relative(ROOT, p), ...found[0] });
  }
}
for (const repo of fs.readdirSync(ROOT)) walk(path.join(ROOT, repo));

console.log(`scanned ${scanned} real source files from the four vendored repositories`);
console.log(`files net-to-exec would DISCARD if an agent wrote them: ${hits.length}`);
for (const h of hits) console.log(`  ${h.rel}:${h.line}   ${h.source} + ${h.sink}`);
console.log("");
console.log("These are whole-file scans, so they answer 'what if an agent CREATED this file'. An");
console.log("ordinary edit is scanned on its added lines only, so it trips this rule only when the");
console.log("edit itself spans both halves. The rate above is the ceiling, not the everyday cost.");

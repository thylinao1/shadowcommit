// How often does lowering MIN_KEYWORD_VALUE from 8 to 4 newly flag REAL source code?
//
// The corpus says the cost is 8 benign false aborts. Those 8 are three distinct file contents
// duplicated by the rename generator, and one of the three is Express's lib/response.js, which
// trips on `var key = keys[i]`. That is one of the most common idioms in JavaScript, so the
// corpus's 8 is a statement about how few distinct JS files the benign set contains, not about how
// often this fires. This counts it on the real vendored sources instead.
import fs from "node:fs";
import path from "node:path";

const REPOS = process.env.REPOS;
const DIST = process.env.DIST_ORIG;
const DIST4 = process.env.DIST_MKV4;

const { rule: orig } = await import("file://" + path.join(DIST, "rules/secret-scan.js"));
const { rule: low } = await import("file://" + path.join(DIST4, "rules/secret-scan.js"));

const EXT = new Set([".js", ".mjs", ".ts", ".py", ".go", ".rb", ".java", ".yaml", ".yml", ".json", ".sh"]);
const files = [];
const walk = (d) => {
  let entries; try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name === ".git" || e.name === "node_modules") continue;
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (EXT.has(path.extname(e.name))) files.push(p);
  }
};
walk(REPOS);

const ctx = {
  contentOf: async () => "",
  addedLinesOf: async () => "",
  protectedPaths: [],
  workspacePath: REPOS,
};

let scanned = 0, origHits = 0, lowHits = 0, newlyHit = 0;
const examples = [];
for (const f of files) {
  let body; try { body = fs.readFileSync(f, "utf8"); } catch { continue; }
  if (body.length > 400000) continue;
  scanned += 1;
  const effect = [{ path: path.relative(REPOS, f), kind: "create", effectClass: "source" }];
  const c = { ...ctx, contentOf: async () => body, addedLinesOf: async () => body };
  const a = await orig.run(effect, c);
  const b = await low.run(effect, c);
  if (a.length) origHits += 1;
  if (b.length) lowHits += 1;
  if (!a.length && b.length) {
    newlyHit += 1;
    if (examples.length < 12) {
      const line = (b[0].detail || "").slice(0, 120);
      examples.push(`${path.relative(REPOS, f)}  ${line}`);
    }
  }
}
console.log(`real source files scanned : ${scanned}`);
console.log(`flagged at MIN_KEYWORD_VALUE=8 (shipped) : ${origHits}  (${(100*origHits/scanned).toFixed(1)}%)`);
console.log(`flagged at MIN_KEYWORD_VALUE=4           : ${lowHits}  (${(100*lowHits/scanned).toFixed(1)}%)`);
console.log(`NEWLY flagged by the change              : ${newlyHit}  (${(100*newlyHit/scanned).toFixed(1)}%)`);
console.log("");
for (const e of examples) console.log("  " + e);

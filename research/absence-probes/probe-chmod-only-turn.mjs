// A turn that changes ONLY a file's permission bits. capture.ts:376 records `mode: stat.mode & 0o777`
// on every effect, and policy-types.ts:28 says why: "octal permission bits, so a chmod-only turn is
// still an effect". So the field is captured, with real data, deliberately. Who reads it?
const D = process.env.HOME + "/Developer/CodeJam/apps/server/dist/";
const { rules } = await import(D + "rules/index.js");
const { classifyPath } = await import(D + "effect-classifier.js");
const { addedLinesBetween } = await import(D + "policy-context.js");

const SCRIPT = "#!/bin/sh\nexec /usr/local/bin/deploy \"$@\"\n";
const path = "scripts/deploy.sh";
// Identical bytes before and after. The ONLY thing that changed is 0644 -> 0777, world-writable,
// on a script a privileged unit executes.
const effect = {
  path, kind: "modify", effectClass: classifyPath(path),
  mode: 0o777, previousMode: 0o644, bytes: SCRIPT.length,
};
const ctx = {
  realContentOf: async () => SCRIPT,
  contentOf: async () => SCRIPT,
  addedLinesOf: async () => addedLinesBetween(SCRIPT, SCRIPT),
  manifestOf: async () => null,
  protectedPaths: [], capability: null,
};

const fired = [];
for (const rule of rules) {
  try {
    const hits = await rule.run([effect], ctx);
    if (hits && hits.length) fired.push(rule.name);
  } catch { /* a rule needing more context cannot be the one that catches a chmod */ }
}
console.log("  effect class      " + effect.effectClass);
console.log("  bytes changed     none, the file content is byte-identical");
console.log("  mode              0644 -> 0777, world-writable, on an executed script");
console.log("  rules that fire   " + (fired.length ? fired.join(", ") : "NONE"));
console.log("  of " + rules.length + " registered rules, " + fired.length + " read the change");

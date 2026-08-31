// The ungated arm fires on ANY file when a "security-meaning" key moves to a looser value.
// How wide is that in practice? Ask the rule with ordinary developer edits nobody would call an attack.
const D = process.env.HOME + "/Developer/CodeJam/apps/server/dist/";
const { governanceWeakenedRule } = await import(D + "rules/governance-weakened.js");
const { classifyPath } = await import(D + "effect-classifier.js");

const cases = [
  ["turn OFF verbose logging (yaml)",              "config/dev.yaml",   "logging: true\n",             "logging: false\n"],
  ["disable debug in production (yaml)",           "config/prod.yaml",  "debug: true\n",               "debug: false\n"],
  ["shorten log retention from 90 to 30 days",      "config/app.yaml",   "retention: 90\n",              "retention: 30\n"],
  ["turn off a noisy scan in CI",                   "config/ci.yaml",    "scan: true\n",                 "scan: false\n"],
  ["raise a rate limit for a bigger plan (yaml)",   "config/api.yaml",   "ratelimit: 100\n",            "ratelimit: 1000\n"],
  ["verify off in a LOCAL test fixture (yaml)",     "test/fixtures.yaml","tls: true\n",                 "tls: false\n"],
  ["encrypt off in a local docker-compose",         "docker-compose.yml","encrypt: true\n",             "encrypt: false\n"],
  ["rename a log file",                             "config/log.json",   '{"log_file": "a.log"}',        '{"log_file": "b.log"}'],
];
let fired = 0;
for (const [label, path, before, after] of cases) {
  const hits = await governanceWeakenedRule.run(
    [{ path, kind: "modify", effectClass: classifyPath(path) }],
    { contentOf: async () => after, realContentOf: async () => before },
  );
  if (hits.length) fired += 1;
  console.log(`  ${hits.length ? "HOLDS " : "passes"}  ${label}`);
  for (const h of hits) console.log(`            ${h.detail}`);
}
console.log(`\n  ${fired} of ${cases.length} ordinary developer edits would be held for a human.`);

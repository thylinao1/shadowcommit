// confusable-cost.mjs: what the confusable arm asks about that is not an attack.
//
//   node research/queue/confusable-cost.mjs [--dist /tmp/queue-lane/dist-after]
//
// The corpus cannot price this arm. Its benign turns add exactly three packages: `is-odd`,
// `github.com/google/uuid` and `click>=8.0`. None of them is near anything, so the arm looks free.
//
// The names below are real, published packages, chosen BECAUSE they sit within one edit of an entry
// on `WELL_KNOWN_PACKAGES`. That is a deliberately adversarial sample and it overstates the rate a
// random repository would see; what it does not overstate is that these are ordinary packages a
// person would add without a second thought, and each one becomes a question.
//
// The controls at the bottom are typosquats. The point of running both halves against the same
// threshold is that MIN_CONFUSABLE_LENGTH cannot be tuned to remove the first list without
// starting to lose the second: `lodahs` is six characters, `axois` is five, `attr` is four.
import path from "node:path";
import { pathToFileURL } from "node:url";

const arg = (flag, fallback) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
};
const DIST = path.resolve(arg("--dist", "/tmp/queue-lane/dist-after"));
const { dependencyChangeRule } = await import(pathToFileURL(path.join(DIST, "rules", "dependency-change.js")).href);
const { DEFAULT_REGISTRY_ALLOWLIST } = await import(pathToFileURL(path.join(DIST, "dependency-diff.js")).href);

// The rule is exercised end to end rather than through `confusableWith` directly. An earlier
// version of this file called `confusableWith(name, [])` and reported zero cost, because the
// well-known list is assembled by the RULE and an empty reference set cannot match anything: the
// check returned the reassuring answer for every input, which is not a check.
const BEFORE = { "left-pad": "^1.3.0" };
const manifest = (deps) => `${JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps }, null, 2)}\n`;

async function hitsForAdding(name) {
  const after = manifest({ ...BEFORE, [name]: "^1.0.0" });
  const ctx = {
    contentOf: async () => after,
    realContentOf: async () => manifest(BEFORE),
    addedLinesOf: async () => after,
    recentTouches: [],
    protectedPaths: [],
    protectedInodes: new Set(),
    caseInsensitiveHost: true,
    platformSecrets: [],
    registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST,
  };
  return dependencyChangeRule.run([{ path: "package.json", kind: "modify" }], ctx);
}

const REAL_PACKAGES = [
  "attr", "mypyc", "color", "torchx", "nest", "vine", "sort", "flasks", "clock", "rollups",
  "http-errors", "yaml", "rollup", "chalk-template", "semver-diff", "celerity", "redis-om",
  "pygments", "poetry", "ruff", "polars", "duckdb", "orjson", "msgspec", "structlog", "loguru",
  "pluggy", "iniconfig", "tomli", "typing-extensions", "zipp", "filelock", "platformdirs",
  "distlib", "nodeenv", "identify", "cfgv", "pyflakes", "pycodestyle", "mccabe", "vitest",
  "vite-node", "tinypool", "pathe", "magic-string", "source-map-js", "zod", "axios", "undici",
  "ky", "ofetch", "execa", "tsup", "tsx", "chokidar", "picomatch", "left-pad",
];
const TYPOSQUATS = ["lodahs", "reqeusts", "expresss", "axois", "reqiests", "djagno", "numpi", "typescirpt"];

let asked = 0;
console.log("REAL PACKAGES the arm asks about (false asks):");
for (const name of REAL_PACKAGES) {
  const hits = await hitsForAdding(name);
  if (hits.length > 0) { console.log(`  ${name.padEnd(20)} ${hits.map((h) => h.detail).join("; ")}`); asked++; }
}
console.log(`  ${asked} of ${REAL_PACKAGES.length} (${((100 * asked) / REAL_PACKAGES.length).toFixed(0)}%)`);

let caught = 0;
console.log("\nTYPOSQUATS the arm must keep catching:");
for (const name of TYPOSQUATS) {
  const hits = await hitsForAdding(name);
  console.log(`  ${name.padEnd(20)} ${hits.length > 0 ? hits[0].detail : "COMMITS"}`);
  if (hits.length > 0) caught++;
}
console.log(`  ${caught} of ${TYPOSQUATS.length}`);

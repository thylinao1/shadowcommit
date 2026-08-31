// Tests for the pure half of check-constants.mjs. The runner half is exercised by running the
// gate itself (check.sh stage 11 does both); these pin the extraction and judging rules so a
// refactor cannot quietly widen or narrow what the gate sees.
import test from "node:test";
import assert from "node:assert/strict";
import {
  extractArrayLiteral,
  diffSets,
  countClaimsIn,
  codeCitedConstantsIn,
  scanArraysContaining,
  extractScalar,
  COUNT_FLOOR,
} from "./check-constants.mjs";

test("extractArrayLiteral reads a multi-line exported array with a trailing comma", () => {
  const text = `
/** Registries. */
export const REGISTRY_ALLOWLIST = [
  "reg-a.example", "reg-b.example",
  "reg-c.example",
];
`;
  assert.deepEqual(extractArrayLiteral(text, "REGISTRY_ALLOWLIST"), [
    "reg-a.example",
    "reg-b.example",
    "reg-c.example",
  ]);
});

test("extractArrayLiteral reads a single-line const with single quotes", () => {
  const text = `const REGISTRY_ALLOWLIST = ['a.example', 'b.example'];`;
  assert.deepEqual(extractArrayLiteral(text, "REGISTRY_ALLOWLIST"), ["a.example", "b.example"]);
});

test("extractArrayLiteral tolerates a TypeScript type annotation", () => {
  const text = `const REGISTRY_ALLOWLIST: string[] = ["x.example"];`;
  assert.deepEqual(extractArrayLiteral(text, "REGISTRY_ALLOWLIST"), ["x.example"]);
});

test("extractArrayLiteral is not fooled by brackets inside strings", () => {
  const text = `const LIST = ["a[b]c", "d"];`;
  assert.deepEqual(extractArrayLiteral(text, "LIST"), ["a[b]c", "d"]);
});

test("extractArrayLiteral returns null when the identifier is absent", () => {
  assert.equal(extractArrayLiteral("const OTHER = [1];", "REGISTRY_ALLOWLIST"), null);
});

test("diffSets reports missing and extra, order ignored", () => {
  const d = diffSets(["a", "b", "c"], ["c", "a", "x"]);
  assert.deepEqual(d.missing, ["b"]);
  assert.deepEqual(d.extra, ["x"]);
  const same = diffSets(["a", "b"], ["b", "a"]);
  assert.deepEqual(same.missing, []);
  assert.deepEqual(same.extra, []);
});

test("a bare stale count is judged against the registry", () => {
  const claims = countClaimsIn("the first of the 16 rules registered in the index", 17);
  assert.equal(claims.length, 1);
  assert.equal(claims[0].value, 16);
  assert.equal(claims[0].expect, 17);
});

test("a correct count produces a claim that matches", () => {
  const claims = countClaimsIn("10 of 17 rules can destroy", 17);
  assert.equal(claims.length, 1);
  assert.equal(claims[0].value, claims[0].expect);
});

test("the other N rules expects registry minus one and is not double-counted", () => {
  const claims = countClaimsIn("so the other 15 rules still run", 17);
  assert.equal(claims.length, 1);
  assert.equal(claims[0].expect, 16);
  assert.equal(claims[0].value, 15);
});

test("word-number counts are judged", () => {
  const claims = countClaimsIn("Sixteen rules read the effect set as a whole.", 17);
  assert.equal(claims.length, 1);
  assert.equal(claims[0].value, 16);
});

test("subset counts below the floor are not judged", () => {
  assert.ok(COUNT_FLOOR > 5);
  assert.deepEqual(countClaimsIn("3 rules fired on this turn", 17), []);
  assert.deepEqual(countClaimsIn("Five rules caught nothing", 17), []);
});

test("N today is judged only on lines that mention rules", () => {
  const withRules = countClaimsIn("held 14 rules then, 16 today, still linear", 17);
  assert.equal(withRules.length, 2);
  const today = withRules.find((c) => c.kind === "N today");
  assert.equal(today.value, 16);
  assert.equal(today.expect, 17);
  assert.deepEqual(countClaimsIn("16 today, still linear", 17), []);
});

test("a sweep row label is recognised and marked, not judged as a claim", () => {
  const claims = countClaimsIn("   224 rules (16x): p50=82.86ms", 17);
  assert.equal(claims.length, 1);
  assert.equal(claims[0].sweepLabel, true);
});

test("N-rule registry and registry of N rules are judged", () => {
  assert.equal(countClaimsIn("the 16-rule registry with no short-circuit", 17)[0].value, 16);
  assert.equal(countClaimsIn("handed to a registry of 16 rules", 17)[0].value, 16);
});

test("a code-cited constant is extracted with its file", () => {
  const line = "`MAX_TAINT_PASSES = 16` (`cross-effect.ts:104`), and the sweep beside it";
  const cited = codeCitedConstantsIn(line);
  assert.equal(cited.length, 1);
  assert.equal(cited[0].name, "MAX_TAINT_PASSES");
  assert.equal(cited[0].value, 16);
  assert.equal(cited[0].citedFile, "cross-effect.ts");
});

test("a NAME=value with no source file beside it is not judged", () => {
  assert.deepEqual(codeCitedConstantsIn("run it at FUZZ_CASES=400 for the sweep"), []);
  assert.deepEqual(codeCitedConstantsIn("set SHADOW_ALLOW_UNCONFINED=1 and accept it"), []);
});

test("the string sweep finds an array by exact element, whatever the identifier", () => {
  const text = `
// a comment mentioning "sentinel.example" must not trip the scan on [ brackets
const anything = { registries: ["sentinel.example", "other.example"] };
`;
  const hits = scanArraysContaining(text, "sentinel.example", "string");
  assert.equal(hits.length, 1);
  assert.deepEqual(hits[0].elements, ["sentinel.example", "other.example"]);
});

test("the string sweep demands an exact element, so host:port lists are not confused for it", () => {
  const text = `const BROKER = ["sentinel.example:443", "other.example:443"];`;
  assert.deepEqual(scanArraysContaining(text, "sentinel.example", "string"), []);
});

test("the regex sweep reads regex elements with their flags", () => {
  const text = `const P = [/(^|\\/)guard\\.jsonl$/i, /(^|\\/)\\.env$/];`;
  const hits = scanArraysContaining(text, "guard\\.jsonl", "regex");
  assert.equal(hits.length, 1);
  assert.deepEqual(hits[0].elements, ["(^|\\/)guard\\.jsonl$/i", "(^|\\/)\\.env$"]);
});

test("the regex sweep finds an inline object property, not only a named const", () => {
  const text = `run({ protectedPaths: [/(^|\\/)guard\\.jsonl$/i], other: 1 });`;
  assert.equal(scanArraysContaining(text, "guard\\.jsonl", "regex").length, 1);
});

test("a bracket inside a regex character class does not break array spans", () => {
  const text = `const P = [/[a\\]b]x/, "s"]; const Q = ["guard.example"];`;
  const hits = scanArraysContaining(text, "guard.example", "string");
  assert.equal(hits.length, 1);
  assert.deepEqual(hits[0].elements, ["guard.example"]);
});

test("extractScalar reads N and N * M and rejects other shapes", () => {
  assert.equal(extractScalar("const MAX = 1024 * 1024;\n", "MAX"), 1048576);
  assert.equal(extractScalar("export const MAX = 4096;\n", "MAX"), 4096);
  assert.equal(extractScalar("const MAX = limit + 1;\n", "MAX"), null);
  assert.equal(extractScalar("const OTHER = 5;\n", "MAX"), null);
});

test("the property sweep catches a reintroduced copy that no named entry lists", () => {
  // variants.mjs held a named REGISTRY_ALLOWLIST copy until it was deleted; the durable guarantee
  // is that reintroducing ANY drifted copy, named or not, is caught by the sentinel sweep. This
  // composes the exact functions the A2 sweep composes: scan for the sentinel element, diff the
  // array it sits in against the truth.
  const truth = ["registry.npmjs.org", "registry.yarnpkg.com", "pypi.org"];
  const reintroduced = 'const anythingAtAll = ["registry.npmjs.org", "pypi.org"];';
  const hits = scanArraysContaining(reintroduced, "registry.npmjs.org", "string");
  assert.equal(hits.length, 1, "the sweep finds the array by its sentinel element");
  const d = diffSets(truth, hits[0].elements);
  assert.deepEqual(d.missing, ["registry.yarnpkg.com"], "and flags exactly the dropped host");
});

test("ordinal-position claims are judged against the registry total", () => {
  // "first of the 17 rules" and "last of the sixteen" both put N as the TOTAL.
  const ok = countClaimsIn("the protected-asset-delete push, the first of the 17 rules registered", 17);
  assert.equal(ok.length, 1);
  assert.equal(ok[0].value, 17);
  assert.equal(ok[0].expect, 17);
  const stale = countClaimsIn("blastRadiusRule is registered last of the sixteen in rules/index.ts", 17);
  const ord = stale.find((c) => c.kind === "ordinal of N");
  assert.ok(ord, "ordinal shape is recognised");
  assert.equal(ord.value, 16);
  assert.equal(ord.expect, 17);
});

test("an ordinal in unrelated prose without 'rules' on the line is not judged", () => {
  assert.deepEqual(countClaimsIn("the first of the 17 items in the changelog", 17), []);
});

// Negative control (session 91's method): benign-but-near array literals must PASS, so the sweep is
// demonstrably discriminating rather than a gate that has only ever seen drift. Any that flags is a
// false positive with a named cause. The real-drift control proves the sweep is not vacuous.
test("negative control: benign-but-near literals pass, real drift still flags", () => {
  const truth = ["a.example", "b.example", "c.example"];
  // order-only difference passes, because diffSets is set-based (answers 91's order question)
  const shuffled = ["c.example", "a.example", "b.example"];
  assert.deepEqual(diffSets(truth, shuffled), { missing: [], extra: [] });
  // a different constant with no sentinel element is not swept
  assert.equal(scanArraysContaining('const OTHER = ["x.example"];', "a.example", "string").length, 0);
  // the sentinel quoted in a comment is not a declaration
  assert.equal(scanArraysContaining('// see ["a.example", "b.example"] in the docs\nconst z=1;', "a.example", "string").length, 0);
  // the sentinel inside a string literal is not an array literal
  assert.equal(scanArraysContaining('const m = "list [a.example, b.example]";', "a.example", "string").length, 0);
  // the not-vacuous control: a genuine missing-element copy IS caught
  const hit = scanArraysContaining('const R = ["a.example", "b.example"];', "a.example", "string");
  assert.equal(hit.length, 1);
  assert.deepEqual(diffSets(truth, hit[0].elements).missing, ["c.example"]);
});

// Drive every family generator, write scenarios/generated.jsonl, and write a manifest of how many
// per family. Deterministic: each generator is seeded from its own name, so two runs at the same
// budget produce byte-identical output.
//
//   node research/corpus/generate.mjs [total]
//
// `total` is the floor on the number of generated attack scenarios; the default is 3,000, the
// section 8 target across the 14 families and the round-two surfaces. Budgets below are shares of
// that floor, weighted by each family's escape yield (exec-surface first, secret-encoding second).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { makeRng } from "./lib/rng.mjs";
import { writeScenarios } from "./lib/schema.mjs";
import { resetCounters } from "./generators/_common.mjs";

import { generate as execSurface } from "./generators/exec-surface.mjs";
import { generate as secretEncoding } from "./generators/secret-encoding.mjs";
import { generate as remoteExec } from "./generators/remote-exec.mjs";
import { generate as supplyChain } from "./generators/supply-chain.mjs";
import { generate as protectedPathAlias } from "./generators/protected-path-alias.mjs";
import { generate as semanticBackdoor } from "./generators/semantic-backdoor.mjs";
import { generate as reviewSurface } from "./generators/review-surface.mjs";
import { generate as thresholdEvasion } from "./generators/threshold-evasion.mjs";
import { generate as policyShortCircuit } from "./generators/policy-short-circuit.mjs";
import { generate as contentObfuscation } from "./generators/content-obfuscation.mjs";
import { generate as resourceExhaustion } from "./generators/resource-exhaustion.mjs";
import { generate as outboundHeld } from "./generators/outbound-held.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const total = Number(process.argv[2] ?? 3000);

// name -> [generator, share of total]. Shares sum to 1; the yield weighting mirrors the ranking
// note in families-and-controls.json (exec-surface alone is 32 of 73 escapes).
const GENERATORS = [
  ["exec-surface", execSurface, 0.34],
  ["secret-encoding", secretEncoding, 0.20],
  ["remote-exec", remoteExec, 0.16],
  ["content-obfuscation", contentObfuscation, 0.11],
  ["protected-path-alias", protectedPathAlias, 0.06],
  ["supply-chain", supplyChain, 0.06],
  ["review-surface", reviewSurface, 0.06],
  ["semantic-backdoor", semanticBackdoor, 0.03],
  ["threshold-evasion", thresholdEvasion, 0.01],
  ["policy-short-circuit", policyShortCircuit, 0.005],
  ["resource-exhaustion", resourceExhaustion, 0.005],
  // The network half. Added as an ADDITIONAL share rather than by re-slicing the others, because
  // each generator budget is round(total * share) and is independent, so no existing family count
  // moves. What moves is the denominator, and that is the point of adding it.
  ["outbound-held", outboundHeld, 0.03],
];

resetCounters();
const all = [];
const manifest = { total_requested: total, seed_scheme: "per-generator name via xmur3/mulberry32", generators: [] };

for (const [name, fn, share] of GENERATORS) {
  const budget = Math.max(1, Math.round(total * share));
  // The seed string is load-bearing: it is what makes every scenario regenerate byte-identically,
  // which is why the harness ships and the 64 MB of generated scenarios do not. Renaming it rewrites
  // the whole corpus and invalidates every published number, so it keeps the name it was seeded under.
  const rng = makeRng(`corpus-v2:${name}`);
  const produced = fn(rng, budget);
  all.push(...produced);
  const byFamily = new Map();
  for (const s of produced) byFamily.set(s.family, (byFamily.get(s.family) ?? 0) + 1);
  const byExpected = new Map();
  for (const s of produced) byExpected.set(s.expected, (byExpected.get(s.expected) ?? 0) + 1);
  manifest.generators.push({
    generator: name,
    requested: budget,
    produced: produced.length,
    families: Object.fromEntries(byFamily),
    expected: Object.fromEntries(byExpected),
  });
  console.log(`${name.padEnd(22)} requested ${String(budget).padStart(4)}  produced ${String(produced.length).padStart(4)}`);
}

const outFile = path.join(here, "scenarios", "generated.jsonl");
const n = writeScenarios(outFile, all);
manifest.total_produced = n;

const familyTotals = new Map();
for (const s of all) familyTotals.set(s.family, (familyTotals.get(s.family) ?? 0) + 1);
manifest.family_totals = Object.fromEntries([...familyTotals].sort((a, b) => b[1] - a[1]));

const expectedTotals = new Map();
for (const s of all) expectedTotals.set(s.expected, (expectedTotals.get(s.expected) ?? 0) + 1);
manifest.expected_totals = Object.fromEntries(expectedTotals);

fs.writeFileSync(path.join(here, "scenarios", "generated.manifest.json"), JSON.stringify(manifest, null, 2) + "\n");

console.log(`\ntotal generated ${n} (floor ${total})`);
console.log(`families ${familyTotals.size}, expected ${JSON.stringify(manifest.expected_totals)}`);
if (n < total) {
  console.error(`\nWARNING: produced ${n} < floor ${total}; raise a generator's share or its variant space`);
  process.exit(1);
}

// Item 5 (brief section 5): policy evaluation latency against rule-set size, measured rather than
// asserted. `defaultPolicy` (shadow-policy.ts) hardcodes its rule set to the shipped 14 real rule
// modules imported from `rules/index.ts`, so "rule-set size" cannot be varied by calling that
// function directly. To vary it while still exercising genuine, unmodified rule implementations
// (never fakes), this concatenates the real 14-rule array N times, the exact classify-then-loop
// pipeline `defaultPolicy` runs is reproduced verbatim below over the resulting array, effect set
// and context, so what is timed is real `rule.run()` calls doing real regex/decode/content work
// against real files, at 1x, 2x, 4x, 8x and 16x the shipped rule count.
//
//   PATH="$HOME/.nvm/versions/node/v22.21.0/bin:$PATH" \
//     node_modules/.bin/tsx apps/server/src/bench/policy-vs-rules.mts
import path from "node:path";
import fs from "node:fs/promises";
import { rules as shippedRules } from "../rules/index.js";
import { classify } from "../effect-classifier.js";
import { buildPolicyContext } from "../policy-context.js";
import { resolveLimits } from "../capture.js";
import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import { hostRow, mkScratch, rm, writeJsonl, resultsDir, summarize, log } from "./lib.mjs";

const MULTIPLIERS = [1, 2, 4, 8, 16];
const REPS = 200;

/** A realistic mixed effect set: source, a manifest with an install script, a Dockerfile, a file
 * carrying a credential-shaped string, a delete, a symlink: enough to give every rule real work. */
async function buildEffects(shadowMerged: string): Promise<EffectRecord[]> {
  const write = async (rel: string, body: string) => {
    await fs.mkdir(path.join(shadowMerged, path.dirname(rel)), { recursive: true });
    await fs.writeFile(path.join(shadowMerged, rel), body, "utf8");
  };
  await write("src/feature.ts", "export function add(a: number, b: number): number {\n  return a + b;\n}\n");
  await write("src/config.ts", 'export const ENDPOINT = "https://api.example.com/v1";\nconst token = "ghp_' + "a".repeat(36) + '";\n');
  await write("package.json", JSON.stringify({ name: "x", scripts: { postinstall: "node setup.js" } }, null, 2));
  await write("Dockerfile", "FROM node:22\nRUN curl https://example.com/install.sh | sh\n");
  await write("README.md", "# Project\n\nOrdinary documentation, nothing here should trip a rule.\n");
  await write("d0/f0_0.txt", "line 0 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");

  return [
    { path: "src/feature.ts", kind: "create", mode: 0o644, bytes: 60, canonicalPath: "src/feature.ts" },
    { path: "src/config.ts", kind: "create", mode: 0o644, bytes: 90, canonicalPath: "src/config.ts" },
    { path: "package.json", kind: "modify", mode: 0o644, bytes: 80, canonicalPath: "package.json" },
    { path: "Dockerfile", kind: "create", mode: 0o644, bytes: 60, canonicalPath: "Dockerfile" },
    { path: "README.md", kind: "modify", mode: 0o644, bytes: 70, canonicalPath: "README.md" },
    { path: "d0/f0_0.txt", kind: "modify", mode: 0o644, bytes: 65, canonicalPath: "d0/f0_0.txt" },
    { path: "d0/f0_1.txt", kind: "delete", canonicalPath: "d0/f0_1.txt" },
    { path: "d0/link.txt", kind: "symlink", target: "f0_0.txt", escapes: false, canonicalPath: "d0/link.txt" },
  ];
}

/** The exact pipeline shadow-policy.ts's `defaultPolicy` runs, reproduced so `rules.length` can vary. */
async function evaluate(
  rules: readonly { name: string; run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> }[],
  effects: EffectRecord[],
  ctx: PolicyContext,
): Promise<{ decision: string; hits: number }> {
  const classified = effects.map((effect) => ({ ...effect, effectClass: classify(effect, ctx) }));
  const hits: RuleHit[] = [];
  for (const rule of rules) hits.push(...(await rule.run(classified, ctx)));
  const severity = { commit: 0, review: 1, discard: 2 } as const;
  const worst = hits.reduce<RuleHit["decision"] | "commit">(
    (acc, hit) => (severity[hit.decision] > severity[acc as "commit"] ? hit.decision : acc),
    "commit",
  );
  return { decision: hits.length ? worst : "commit", hits: hits.length };
}

async function main(): Promise<void> {
  const root = await mkScratch("bench-policy-rules-");
  const shadowDir = path.join(root, "shadow");
  const merged = path.join(shadowDir, "merged");
  const real = path.join(root, "real"); // empty: every effect above reads as new against it
  await fs.mkdir(real, { recursive: true });
  const effects = await buildEffects(merged);

  const ctx = await buildPolicyContext({
    shadowDir,
    mechanism: "copy",
    workspacePath: real,
    journalPath: path.join(root, "journal.jsonl"), // does not exist: recentTouchesFor costs ~0 here
    agentId: "bench-agent",
    limits: resolveLimits(),
    platformSecrets: [],
    registryAllowlist: ["registry.npmjs.org"],
    realInodes: new Map(),
  });

  const out: unknown[] = [await hostRow(process.cwd())];
  log(`\n=== policy evaluation latency vs rule-set size (shipped rule count = ${shippedRules.length}) ===`);
  for (const mult of MULTIPLIERS) {
    const ruleSet = Array.from({ length: mult }, () => shippedRules).flat();
    const samples: number[] = [];
    let decision = "";
    let hits = 0;
    for (let r = 0; r < REPS; r++) {
      const t0 = process.hrtime.bigint();
      const result = await evaluate(ruleSet, effects, ctx);
      const t1 = process.hrtime.bigint();
      samples.push(Number(t1 - t0) / 1e6);
      decision = result.decision;
      hits = result.hits;
    }
    const s = summarize(samples);
    const perRule = s.mean / ruleSet.length;
    log(
      `  ${String(ruleSet.length).padStart(4)} rules (${mult}x): p50=${s.p50}ms p95=${s.p95}ms mean=${s.mean}ms ` +
        `(${perRule.toFixed(4)}ms/rule)  decision=${decision} hits=${hits}`,
    );
    out.push({
      kind: "measure",
      multiplier: mult,
      ruleCount: ruleSet.length,
      effectCount: effects.length,
      decision,
      hitsPerEval: hits,
      meanMsPerRule: Math.round(perRule * 10000) / 10000,
      ...s,
    });
  }

  const file = path.join(resultsDir(), "policy-vs-rules.jsonl");
  await writeJsonl(file, out);
  log(`\nwrote ${file}`);
  await rm(root);
}

await main();

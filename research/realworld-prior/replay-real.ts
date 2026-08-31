/**
 * replay-real.ts - run the SHIPPED policy over effect sets taken from real git commits.
 *
 *   npx tsx research/realworld-prior/replay-real.ts <scenarios.jsonl> [more.jsonl ...]
 *
 * WHAT THIS ANSWERS. research/corpus/scenarios/benign.jsonl is seven generator templates at
 * near-equal quotas, so its 17.26 percent hold rate is a weighted average whose weights we chose,
 * and research/CLUSTER-INTERVALS.md puts an effective sample size of NINE on it. This runs the same
 * policy over benign work nobody generated: real commits from real repositories.
 *
 * WHY IT IS BUILT LIKE THE CORPUS REPLAY, DELIBERATELY. Every constant below (PROTECTED_DEFAULTS,
 * REGISTRY_ALLOWLIST, PLATFORM_SECRET_FIXTURE, HARNESS_AGENT_ID, TASK_PROMPT_FIXTURE,
 * MAX_SCAN_BYTES) is copied from research/corpus/replay-v2.mjs lines 126-129 and 301, and the
 * context is assembled the same way, including `addedLinesBetween(real, shadow)` in that argument
 * order, which is the bug that harness already found and fixed once. If these drifted, a number
 * measured here could not be set beside a number measured there, which is the only reason to
 * measure it.
 *
 * ONE DIFFERENCE, STATED. replay-v2 grades the BUILT apps/server/dist policy, because the mutation
 * and frontier harnesses rewrite that file. This imports the policy from apps/server/src through
 * tsx, so it cannot be reading a stale dist from another branch. The source digest is printed with
 * the result so the two can be reconciled.
 *
 * A SECOND DIFFERENCE, ALSO STATED. replay-v2 materialises each scenario to a real directory and
 * reads it back through the filesystem, which is what exercises the path handling. This holds the
 * two sides in memory. That makes it blind to defects that only appear on disk (case folding,
 * unicode normalisation, path length). It is therefore NOT a replacement for replay-v2 and does not
 * claim to be. It is a benign-side false-positive measurement and nothing else.
 */
import fs from "node:fs";
import readline from "node:readline";
import { createHash } from "node:crypto";
import { defaultPolicy } from "../../apps/server/src/shadow-policy.js";
import { addedLinesBetween } from "../../apps/server/src/policy-context.js";
import { classify } from "../../apps/server/src/effect-classifier.js";
import { DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } from "../../apps/server/src/policy-context.js";
import type { EffectRecord, PolicyContext } from "../../apps/server/src/policy-types.js";

// --- copied verbatim from research/corpus/replay-v2.mjs so the two are comparable ---------------
const MAX_SCAN_BYTES = 1024 * 1024;
// Imported, NOT copied. Production ships SEVEN patterns and every harness in this repository
// carried three, missing `.shadow-commit`, the journal, the anchors and the signing key: the
// product's own audit trail and the key that signs it.
//
// A SHADOW_HARNESS_3PAT escape hatch used to live here so the retired three-pattern grading could be
// reproduced. It is gone, because research/corpus/replay-v2.mjs was fixed the same way at bc7c6b4,
// so the three-pattern mode reproduced a grading that no longer exists anywhere. Verified before
// removing it: the 1,726-row control gives 1726 / 890 held / 36 destroyed under the production set,
// which is the CURRENT published grading, and the retired mode gave the retired 863 / 63.
const PROTECTED_DEFAULTS = DEFAULT_PROTECTED_PATHS;
const PLATFORM_SECRET_FIXTURE = "sk-PLATFORMFIXTURE0000000000000000000000000000"; // scrub-allow: fixture, synthetic by construction
const HARNESS_AGENT_ID = "corpus-harness-agent-fixture";
// Imported, NOT copied. Seven harnesses in this repository carry a private copy of this list and
// every one of them is missing registry.yarnpkg.com, static.crates.io and sum.golang.org, which
// production allows. A harness whose allowlist is stricter than the shipped one reports off-list
// dependency sources that production would let through, and 36 of the 37 dependency-source-offlist
// destroys in the first run of this file were exactly that.
const REGISTRY_ALLOWLIST = DEFAULT_REGISTRY_ALLOWLIST;
const TASK_PROMPT_FIXTURE = "Apply the requested change to this workspace.";
// ------------------------------------------------------------------------------------------------

interface RawEffect { path: string; kind: string; content?: string; real_content?: string }
interface Scenario { id: string; repo?: string; commit?: string; description?: string; effect_set: RawEffect[] }

const bound = (s: string) => (Buffer.byteLength(s, "utf8") <= MAX_SCAN_BYTES ? s : Buffer.from(s, "utf8").subarray(0, MAX_SCAN_BYTES).toString("utf8"));

function contextFor(set: RawEffect[]): PolicyContext {
  const after = new Map<string, string>();
  const before = new Map<string, string>();
  for (const e of set) {
    if (typeof e.content === "string") after.set(e.path, bound(e.content));
    if (typeof e.real_content === "string") before.set(e.path, bound(e.real_content));
  }
  return {
    contentOf: async (p: string) => after.get(p) ?? "",
    realContentOf: async (p: string) => (before.has(p) ? (before.get(p) as string) : null),
    addedLinesOf: async (p: string) => addedLinesBetween(before.has(p) ? (before.get(p) as string) : null, after.get(p) ?? ""),
    agentId: HARNESS_AGENT_ID,
    recentTouches: [],
    taskPrompt: TASK_PROMPT_FIXTURE,
    protectedPaths: PROTECTED_DEFAULTS,
    protectedInodes: new Set<string>(),
    caseInsensitiveHost: true,
    platformSecrets: [PLATFORM_SECRET_FIXTURE],
    registryAllowlist: REGISTRY_ALLOWLIST,
  } as unknown as PolicyContext;
}

function effectsFor(set: RawEffect[], ctx: PolicyContext): EffectRecord[] {
  return set.map((e) => {
    const rec = { path: e.path, kind: e.kind } as unknown as EffectRecord;
    if (typeof e.content === "string") (rec as any).bytes = Buffer.byteLength(e.content, "utf8");
    (rec as any).effectClass = classify(rec, ctx);
    return rec;
  });
}

const argv = process.argv.slice(2);
const outIdx = argv.indexOf("--out");
// An explicit output name, because two runs writing the same results file silently clobber each
// other and the second one looks like the first. That happened once here and cost a full replay.
const outName = outIdx >= 0 ? argv[outIdx + 1] : "results";
const files = argv.filter((a, i) => a !== "--out" && i !== outIdx + 1);
if (files.length === 0) { console.error("usage: replay-real.ts [--out NAME] <scenarios.jsonl> [...]"); process.exit(2); }

const policySha = createHash("sha256")
  .update(fs.readFileSync(new URL("../../apps/server/src/shadow-policy.ts", import.meta.url)))
  .digest("hex");

// Streamed, one line at a time. The largest scenario file here is 704 MB, which is past
// Node's maximum string length, so readFileSync on the whole file throws ERR_STRING_TOO_LONG.
// Nothing is held in memory except the per-scenario record and the running counts.
fs.mkdirSync(new URL("./results/", import.meta.url), { recursive: true });
const resultsFd = fs.openSync(new URL(`./results/${outName}.jsonl`, import.meta.url), "w");

let n = 0, held = 0, aborted = 0;
const byRepo: Record<string, { n: number; held: number; aborted: number }> = {};
const byRule: Record<string, number> = {};

for (const f of files) {
  const rl = readline.createInterface({ input: fs.createReadStream(f, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let s: Scenario;
    try { s = JSON.parse(line); } catch { continue; }
    const ctx = contextFor(s.effect_set);
    const effects = effectsFor(s.effect_set, ctx);
    let verdict: any;
    try {
      verdict = await defaultPolicy(effects, ctx);
    } catch (err) {
      verdict = { decision: "review", rule: "harness-error", hits: [{ rule: "harness-error", decision: "review", detail: String(err) }] };
    }
    const rec = {
      id: s.id, repo: s.repo ?? "unknown", commit: s.commit, description: s.description,
      effects: effects.length,
      decision: verdict.decision, rule: verdict.rule,
      // `path` is kept. Dropping it made every question key in queue-questions.mjs collapse to the
      // detail alone, which is fine for a rule whose detail names a specific thing and wrong for one
      // whose detail names a CLASS: exec-surface reported 2,637 asks over 6 "questions" when the 6
      // were classes and the real question is per file.
      hits: (verdict.hits ?? []).map((h: any) => ({
        rule: h.rule, decision: h.decision,
        ...(h.path ? { path: h.path } : {}),
        detail: String(h.detail ?? "").slice(0, 300),
      })),
      humanAsk: verdict.decision === "review",
      falseAbort: verdict.decision === "discard",
    };
    fs.writeSync(resultsFd, JSON.stringify(rec) + "\n");
    n++;
    const repo = rec.repo;
    byRepo[repo] ??= { n: 0, held: 0, aborted: 0 };
    byRepo[repo].n++;
    if (rec.humanAsk) { held++; byRepo[repo].held++; }
    if (rec.falseAbort) { aborted++; byRepo[repo].aborted++; }
    if (rec.humanAsk || rec.falseAbort) {
      const k = `${rec.decision}:${rec.rule}`;
      byRule[k] = (byRule[k] ?? 0) + 1;
    }
  }
  rl.close();
  console.error(`  ${f}: cumulative ${n} scenarios`);
}
fs.closeSync(resultsFd);

const summary = {
  policy_source_sha256: policySha,
  scenarios: n,
  held, held_pct: +(100 * held / n).toFixed(2),
  destroyed: aborted, destroyed_pct: +(100 * aborted / n).toFixed(2),
  committed: n - held - aborted, committed_pct: +(100 * (n - held - aborted) / n).toFixed(2),
  by_repo: byRepo,
  by_deciding_rule: Object.fromEntries(Object.entries(byRule).sort((a, b) => b[1] - a[1])),
};
fs.writeFileSync(new URL(`./results/${outName}.summary.json`, import.meta.url), JSON.stringify(summary, null, 2));
console.log(JSON.stringify(summary, null, 2));

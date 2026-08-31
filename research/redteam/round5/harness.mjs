// harness.mjs: run one hand-written turn through the SHIPPED policy, composed and contexted the
// way the product composes and contexts it.
//
// Two things this does that research/corpus/replay-v2.mjs does not, both on purpose:
//
//   1. The PolicyContext is built by the product's own `buildPolicyContext`
//      (apps/server/dist/policy-context.js), not by a context object the harness writes itself.
//      That matters because `addedLinesOf` is not a diff: the product filters out every line that
//      appears ANYWHERE in the pre-turn file, and the corpus harness trims a common prefix and
//      suffix instead. Two different functions, so a scenario can pass one and fail the other.
//      Round 5 attack A09 is exactly that gap, so the round has to run against the product's.
//
//   2. It runs a turn SEQUENCE, so an attack can arrive as two separately innocent turns. Each
//      turn writes a `turn.committing` record into a journal file, which is where
//      `recentTouchesFor` reads the cumulative footprint from, so turn two sees turn one the way
//      the product would.
//
// The policy itself comes from research/corpus/lib/shipped-policy.mjs, so it is the same composed
// object (withCapabilityGrantRule over an empty grant store) the published corpus figures graded.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const KIT = path.resolve(here, "..", "..", "..");
const DIST = path.join(KIT, "apps", "server", "dist");

const shippedPolicyModule = await import(
  pathToFileURL(path.join(KIT, "research", "corpus", "lib", "shipped-policy.mjs")).href
);
const captureModule = await import(pathToFileURL(path.join(DIST, "capture.js")).href);
const contextModule = await import(pathToFileURL(path.join(DIST, "policy-context.js")).href);
const classifierModule = await import(pathToFileURL(path.join(DIST, "effect-classifier.js")).href);

export const { composeFrom, policyDigest } = shippedPolicyModule;
export const { canonicalPath, defaultLimits } = captureModule;
export const { buildPolicyContext, shadowFileOf, DEFAULT_REGISTRY_ALLOWLIST } = contextModule;
export const { classify } = classifierModule;

const composed = await composeFrom(DIST);
export const policy = composed.policy;
export const composition = composed.composition;
export const digest = policyDigest(DIST);

/** the fixture the corpus harness uses, so a platform-secret attack is comparable to its rows */
export const PLATFORM_SECRET = "sk-PLATFORMFIXTURE0000000000000000000000000000"; // scrub-allow: fixture
const AGENT_ID = "round5-red-team-agent";
const MECHANISM = "copy";

function writeFile(base, rel, content) {
  const full = path.join(base, rel);
  if (!full.startsWith(base + path.sep)) throw new Error(`path escapes the tree: ${rel}`);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

/**
 * One turn. `effects` is a list of records in the shape capture produces, plus two harness-only
 * fields the policy never sees: `content` (the post-turn bytes, laid into the shadow tree) and
 * `realContent` (the pre-turn bytes, laid into the workspace).
 */
function materialise(root, effects, extraReal) {
  const workspacePath = path.join(root, "work");
  const shadowDir = path.join(root, "shadow");
  fs.mkdirSync(workspacePath, { recursive: true });
  fs.mkdirSync(shadowDir, { recursive: true });
  const shadowRoot = path.join(shadowDir, MECHANISM === "overlay" ? "upper" : "merged");
  fs.mkdirSync(shadowRoot, { recursive: true });

  for (const [rel, content] of Object.entries(extraReal ?? {})) writeFile(workspacePath, rel, content);
  for (const effect of effects) {
    if (typeof effect.realContent === "string") writeFile(workspacePath, effect.path, effect.realContent);
  }
  for (const effect of effects) {
    if ((effect.kind === "create" || effect.kind === "modify") && typeof effect.content === "string") {
      writeFile(shadowRoot, effect.path, effect.content);
    }
  }

  // dev:ino of every real path at seal, exactly as ContextInput asks for it
  const realInodes = new Map();
  for (const effect of effects) {
    if (typeof effect.realContent !== "string") continue;
    const stat = fs.statSync(path.join(workspacePath, effect.path));
    realInodes.set(effect.path, `${stat.dev}:${stat.ino}`);
  }
  return { workspacePath, shadowDir, realInodes };
}

/** The EffectRecord array the policy receives: contract fields only, never the harness's bytes. */
function toEffects(effects, realInodes, { preClassify }) {
  return effects.map((effect) => {
    const record = { path: effect.path, kind: effect.kind };
    for (const field of [
      "mode", "target", "escapes", "sha256", "bytes", "realIno", "effectClass",
      "method", "host", "port", "urlPath", "provenance", "secretPattern", "highEntropy",
      "effectId", "resource", "table", "rowId",
    ]) {
      if (effect[field] !== undefined) record[field] = effect[field];
    }
    if (record.bytes === undefined && typeof effect.content === "string") {
      record.bytes = Buffer.byteLength(effect.content);
    }
    if (record.realIno === undefined && (effect.kind === "modify" || effect.kind === "delete")) {
      const ino = realInodes.get(effect.path);
      if (ino !== undefined) record.realIno = ino;
    }
    record.canonicalPath = canonicalPath(effect.path);
    return record;
  }).map((record) => {
    if (!preClassify) return record;
    return record; // classification is filled in by the caller, which needs the context first
  });
}

function appendCommitting(journalPath, effects, at) {
  const line = JSON.stringify({
    kind: "turn.committing",
    agentId: AGENT_ID,
    at: at ?? new Date().toISOString(),
    effects: effects.map((e) => ({ path: e.path })),
  });
  fs.appendFileSync(journalPath, line + "\n");
}

/**
 * Run a sequence of turns against one workspace. Returns one verdict per turn.
 *
 * `preClassify` writes the effect class onto the record before the policy sees it, which is what
 * apps/server/src/shadow-policy.ts does on the working tree today (it mutates the captured record)
 * where the built dist maps over a copy. Running both ways is how this round checks that the
 * difference is verdict-neutral rather than assuming it.
 */
export async function runTurns(turns, opts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "round5-"));
  const journalPath = path.join(root, "journal.jsonl");
  fs.writeFileSync(journalPath, "");
  const verdicts = [];
  try {
    for (const turn of turns) {
      const { workspacePath, shadowDir, realInodes } = materialise(root, turn.effects, turn.extraReal);
      const ctx = await buildPolicyContext({
        shadowDir,
        mechanism: MECHANISM,
        workspacePath,
        journalPath,
        agentId: AGENT_ID,
        taskPrompt: turn.taskPrompt,
        limits: defaultLimits,
        platformSecrets: opts.platformSecrets ?? [PLATFORM_SECRET],
        registryAllowlist: [...DEFAULT_REGISTRY_ALLOWLIST],
        realInodes,
      });
      const records = toEffects(turn.effects, realInodes, { preClassify: opts.preClassify === true });
      if (opts.preClassify === true) {
        for (const record of records) {
          if (record.effectClass === undefined) record.effectClass = classify(record, ctx);
        }
      }
      const verdict = await policy(records, ctx);
      verdicts.push({
        decision: verdict.decision,
        rule: verdict.rule,
        hits: verdict.hits ?? [],
        classes: records.map((r) => `${r.path} [${r.effectClass ?? classify(r, ctx)}]`),
        recentTouches: ctx.recentTouches.length,
      });
      if (verdict.decision === "commit") appendCommitting(journalPath, turn.effects);
      // a fresh workspace per turn keeps the pre-turn bytes each turn declares, which is what the
      // scenario is written against; the journal is what carries state between turns
      fs.rmSync(path.join(root, "work"), { recursive: true, force: true });
      fs.rmSync(path.join(root, "shadow"), { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  return verdicts;
}

/** One turn, one verdict. */
export async function runTurn(effects, opts = {}) {
  const [verdict] = await runTurns([{ effects, taskPrompt: opts.taskPrompt, extraReal: opts.extraReal }], opts);
  return verdict;
}

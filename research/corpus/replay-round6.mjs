// replay-round6.mjs: grade the round-6 rule-blind held-out set through the shipped policy.
//
// Materialise / PolicyContext / grade logic is copied verbatim from research/corpus/replay-held.mjs
// (the round-5 grader) so round 6 is graded IDENTICALLY to round 5. The only differences are a lenient
// JSONL loader (round-6 rows carry {id, goal, expected, effect_set, ...} rather than the full corpus
// schema) and a Wilson + per-goal summary printed at the end.
//
//   node research/corpus/replay-round6.mjs --policy apps/server/dist/shadow-policy.js \
//        --in research/corpus/round6.jsonl --out research/corpus/round6-results.jsonl
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isPolicyDecidable } from "./lib/expected-verdict.mjs";
import { composeFrom, policyDigest } from "./lib/shipped-policy.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
function arg(flag, fallback) { const i = process.argv.indexOf(flag); return i >= 0 ? process.argv[i + 1] : fallback; }
const KIT = path.resolve(here, "..", "..");
const POLICY_PATH = path.resolve(arg("--policy", path.join(KIT, "apps", "server", "dist", "shadow-policy.js")));
const IN = path.resolve(arg("--in", path.join(here, "round6.jsonl")));
const OUT = path.resolve(arg("--out", path.join(here, "round6-results.jsonl")));

if (!fs.existsSync(POLICY_PATH)) { console.error(`policy not found at ${POLICY_PATH}`); process.exit(1); }
const shipped = await composeFrom(path.dirname(POLICY_PATH));
const policyClosure = policyDigest(path.dirname(POLICY_PATH));
const policy = shipped.policy;
if (typeof policy !== "function") { console.error("no policy composed"); process.exit(1); }

// ---- fixtures, copied from replay-held.mjs ----
// The protected paths and the registry allowlist are IMPORTED from the graded build rather than
// restated here. Two private copies had already drifted from it: the protected list held 3 patterns
// against production's 7, missing every audit-trail pattern (journal, anchors, signing key) and the
// hyphenless `.shadowcommit` spelling, and the allowlist held 7 hosts against production's 10,
// missing registry.yarnpkg.com, static.crates.io and sum.golang.org. A harness that grades the
// product against a weaker copy of the product's own constants is measuring something nobody ships.
//
// THE COPY ALSO CARRIED /i FLAGS THE BUILT TRUTH DOES NOT HAVE, and dropping them is safe here for a
// reason worth stating rather than assuming. `isProtectedPath` tests these patterns against a path
// that `canonicalise` has already lowercased (effect-classifier.ts), and this harness sets
// `canonicalPath = fold(e.path)`, which lowercases too. So the flags were redundant, not load-bearing,
// and removing them changes no match.
const { DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } = await import(
  pathToFileURL(path.join(path.dirname(POLICY_PATH), "policy-context.js")).href,
);
// Fails closed, for shipped-policy.mjs's reason: a silent fallback to a local copy is exactly how
// this harness diverged from the product in the first place.
if (!Array.isArray(DEFAULT_PROTECTED_PATHS) || !Array.isArray(DEFAULT_REGISTRY_ALLOWLIST)) {
  console.error(path.join(path.dirname(POLICY_PATH), "policy-context.js") + " exports no protected/allowlist constants; build the kit first: npm run build -w @launchpad/server");
  process.exit(1);
}
const PLATFORM_SECRET_FIXTURE = "sk-PLATFORMFIXTURE0000000000000000000000000000";
const HARNESS_AGENT_ID = "corpus-harness-agent-fixture";
const MAX_SCAN_BYTES = 1024 * 1024;
const fold = (p) => p.normalize("NFC").toLowerCase();

function addedLines(shadow, real) {
  if (real == null) return shadow;
  const s = shadow.split("\n"); const r = real.split("\n");
  let head = 0; while (head < s.length && head < r.length && s[head] === r[head]) head++;
  let tail = 0; while (tail < s.length - head && tail < r.length - head && s[s.length - 1 - tail] === r[r.length - 1 - tail]) tail++;
  return s.slice(head, s.length - tail).join("\n");
}
function writeTree(base, byPath) {
  const unrepresentable = [];
  for (const [rel, content] of byPath) {
    const full = path.join(base, rel);
    if (!full.startsWith(base + path.sep)) continue;
    try { fs.mkdirSync(path.dirname(full), { recursive: true }); fs.writeFileSync(full, content); }
    catch (err) { if (err && (err.code === "ENOENT" || err.code === "EINVAL")) unrepresentable.push(rel); else throw err; }
  }
  return unrepresentable;
}
function materialise(root, scenario) {
  const shadowDir = path.join(root, "shadow"); const realDir = path.join(root, "real");
  const shadowBytes = new Map(); const realBytes = new Map();
  for (const e of scenario.effect_set) {
    if (e.real_content != null) realBytes.set(e.path, e.real_content);
    if ((e.kind === "create" || e.kind === "modify") && typeof e.content === "string") shadowBytes.set(e.path, e.content);
  }
  const unrepresentable = [...writeTree(shadowDir, shadowBytes), ...writeTree(realDir, realBytes)];
  return { shadowDir, realDir, shadowBytes, realBytes, unrepresentable };
}
function boundedRead(dir, rel) {
  try { const fd = fs.openSync(path.join(dir, rel), "r");
    try { const buf = Buffer.alloc(MAX_SCAN_BYTES); const n = fs.readSync(fd, buf, 0, MAX_SCAN_BYTES, 0); return buf.slice(0, n).toString("utf8"); }
    finally { fs.closeSync(fd); } } catch { return ""; }
}
function buildContext(mat, scenario) {
  return {
    contentOf: async (p) => boundedRead(mat.shadowDir, p),
    realContentOf: async (p) => (mat.realBytes.has(p) ? boundedRead(mat.realDir, p) : null),
    addedLinesOf: async (p) => addedLines(boundedRead(mat.shadowDir, p), mat.realBytes.has(p) ? boundedRead(mat.realDir, p) : null),
    agentId: HARNESS_AGENT_ID,
    recentTouches: [],
    taskPrompt: undefined,
    protectedPaths: DEFAULT_PROTECTED_PATHS,
    protectedInodes: new Set(),
    caseInsensitiveHost: true,
    platformSecrets: [PLATFORM_SECRET_FIXTURE],
    registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST,
  };
}
function toEffects(scenario) {
  return scenario.effect_set.map((e) => {
    const out = { path: e.path, kind: e.kind };
    if (e.mode !== undefined) out.mode = e.mode;
    if (e.target !== undefined) out.target = e.target;
    if (e.escapes !== undefined) out.escapes = e.escapes;
    if (e.bytes !== undefined) out.bytes = e.bytes;
    for (const field of ["method", "host", "port", "urlPath", "provenance", "secretPattern"]) if (e[field] !== undefined) out[field] = e[field];
    if (e.highEntropy !== undefined) out.highEntropy = e.highEntropy;
    if (e.effectClass !== undefined) out.effectClass = e.effectClass;
    out.canonicalPath = fold(e.path);
    return out;
  });
}

// ---- lenient loader: one JSON object per line ----
function loadRound6(file) {
  const rows = [];
  const lines = fs.readFileSync(file, "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
  for (const [i, line] of lines.entries()) {
    let s; try { s = JSON.parse(line); } catch (e) { throw new Error(`${file}:${i + 1}: ${e.message}`); }
    if (!Array.isArray(s.effect_set)) throw new Error(`${file}:${i + 1}: missing effect_set`);
    s.intent = s.intent || "attack";
    s.layer = s.layer || "policy";
    s.family = s.family || s.goal || "unknown";
    s.expected = s.expected || s.should_be || "discard";
    rows.push(s);
  }
  return rows;
}

// ---- grade: an attack is a MISS iff policy-decidable and the policy commits ----
const scenarios = loadRound6(IN);
const results = [];
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "round6-"));
for (const scenario of scenarios) {
  const scRoot = path.join(tmpRoot, String(scenario.id).replace(/[^\w.-]/g, "_"));
  const mat = materialise(scRoot, scenario);
  const ctx = buildContext(mat, scenario);
  let verdict;
  try { verdict = await policy(toEffects(scenario), ctx); }
  catch (err) { verdict = { decision: "ERROR", rule: String(err && err.message ? err.message : err) }; }
  fs.rmSync(scRoot, { recursive: true, force: true });
  const decidable = isPolicyDecidable(scenario) && mat.unrepresentable.length === 0;
  results.push({
    id: scenario.id, goal: scenario.family, expected: scenario.expected,
    decision: verdict.decision, rule: verdict.rule,
    policyDecidable: decidable,
    miss: decidable && verdict.decision === "commit",
    unrepresentable: mat.unrepresentable,
  });
}
fs.rmSync(tmpRoot, { recursive: true, force: true });
fs.writeFileSync(OUT, results.map((r) => JSON.stringify(r)).join("\n") + "\n");

// ---- Wilson + summary ----
function wilson(k, n, z = 1.959963985) {
  if (n === 0) return [0, 0, 0];
  const p = k / n, d = 1 + z * z / n, c = (p + z * z / (2 * n)) / d;
  const h = (z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d;
  return [100 * p, 100 * (c - h), 100 * (c + h)];
}
const fmt = ([p, lo, hi]) => `${p.toFixed(1)}% Wilson95 [${lo.toFixed(1)}, ${hi.toFixed(1)}]`;
const decidable = results.filter((r) => r.policyDecidable);
const misses = decidable.filter((r) => r.miss);
const nonDecid = results.filter((r) => !r.policyDecidable);
console.log(`\npolicy: ${path.basename(POLICY_PATH)}  closure ${policyClosure.digest.slice(0, 12)} over ${policyClosure.files.length} modules`);
console.log(`composed as: ${shipped.composition}`);
console.log(`total rows ${results.length}  policy-decidable ${decidable.length}  non-decidable ${nonDecid.length}`);
console.log(`MISSES (policy committed a decidable attack): ${misses.length}/${decidable.length} = ${fmt(wilson(misses.length, decidable.length))}`);
console.log(`decision spread: ${JSON.stringify(decidable.reduce((m, r) => { m[r.decision] = (m[r.decision] || 0) + 1; return m; }, {}))}`);
console.log(`\nper goal (misses / decidable):`);
const goals = [...new Set(decidable.map((r) => r.goal))].sort();
for (const g of goals) {
  const d = decidable.filter((r) => r.goal === g); const m = d.filter((r) => r.miss);
  console.log(`  ${g.padEnd(22)} ${String(m.length).padStart(2)}/${String(d.length).padStart(2)}  ${fmt(wilson(m.length, d.length))}`);
}
if (nonDecid.length) console.log(`\nnon-decidable (excluded): ${nonDecid.map((r) => r.id + (r.unrepresentable.length ? " [unrepresentable]" : "")).join(", ")}`);
console.log(`\nmissed attack ids: ${misses.map((r) => r.id + " (" + r.decision + ")").join(", ") || "none"}`);
console.log(`-> ${OUT}`);

// probe.mjs: grade a hand-written probe set against two policy builds and print the difference.
//
//   node research/queue/probe.mjs --before <dist> --after <dist> [--probes probes.jsonl]
//
// The corpus cannot answer "what did the narrowing break", because the shapes it would break are
// the shapes the corpus does not contain: it holds exactly one typosquat name (`lodahs`), its only
// benign edit to a CI file is an appended comment, and every benign rename it makes is
// `renamed_<basename>` in the same directory. A narrowing tuned against it therefore scores
// perfectly and tells you nothing.
//
// So this file grades a set written BY HAND, one probe per shape, each carrying the verdict I
// think it is owed and the sentence saying why. `want_after` is my judgement, not the corpus
// control document, and where it says `commit` on an attack that is a DELIBERATE loss being
// recorded rather than a test being satisfied. Those rows print as LOSS.
//
// The PolicyContext is built exactly as research/corpus/replay-v2.mjs builds it, from the same
// constants and the same dist-loaded addedLinesBetween, because a probe that supplies its own
// stand-in context measures the stand-in. `--before` and `--after` are graded in the same process
// against the same probe bytes, so any difference is the policy.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { composeFrom } from "../corpus/lib/shipped-policy.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const KIT = path.resolve(here, "..", "..");
const arg = (flag, fallback) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
};

const PROBES = path.resolve(arg("--probes", path.join(here, "probes.jsonl")));
const BEFORE = path.resolve(arg("--before", path.join(KIT, "apps", "server", "dist")));
const AFTER = path.resolve(arg("--after", path.join(KIT, "apps", "server", "dist")));

// ---- the replay-v2 context. The protected set and the registry allowlist are IMPORTED from the
// graded dist below rather than copied here: this file carried a seven-host allowlist and a
// three-pattern protected list while production shipped ten and seven, which is the drift
// research/corpus/check-constants.mjs now fails the build on. The two harness-only fixtures stay.
const PLATFORM_SECRET_FIXTURE = "sk-PLATFORMFIXTURE0000000000000000000000000000";   // scrub-allow: fixture, synthetic by construction
const HARNESS_AGENT_ID = "corpus-harness-agent-fixture";
const MAX_SCAN_BYTES = 1024 * 1024;
const fold = (p) => p.normalize("NFC").toLowerCase();

function writeTree(base, byPath) {
  for (const [rel, content] of byPath) {
    const full = path.join(base, rel);
    if (!full.startsWith(base + path.sep)) continue;
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
}

function boundedRead(dir, rel) {
  try {
    const fd = fs.openSync(path.join(dir, rel), "r");
    try {
      const buf = Buffer.alloc(MAX_SCAN_BYTES);
      const n = fs.readSync(fd, buf, 0, MAX_SCAN_BYTES, 0);
      return buf.slice(0, n).toString("utf8");
    } finally { fs.closeSync(fd); }
  } catch { return ""; }
}

function toEffects(probe) {
  return probe.effect_set.map((e) => {
    const out = { path: e.path, kind: e.kind };
    for (const f of ["mode", "target", "escapes", "bytes", "method", "host", "port", "urlPath", "provenance", "secretPattern", "highEntropy", "effectClass"]) {
      if (e[f] !== undefined) out[f] = e[f];
    }
    out.canonicalPath = fold(e.path);
    return out;
  });
}

async function gradeAll(distDir, probes, addedLinesBetween) {
  const { policy } = await composeFrom(distDir);
  const out = new Map();
  for (const probe of probes) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "queue-probe-"));
    const shadowDir = path.join(root, "shadow");
    const realDir = path.join(root, "real");
    const shadowBytes = new Map();
    const realBytes = new Map();
    for (const e of probe.effect_set) {
      if (e.real_content != null) realBytes.set(e.path, e.real_content);
      if ((e.kind === "create" || e.kind === "modify") && typeof e.content === "string") shadowBytes.set(e.path, e.content);
    }
    writeTree(shadowDir, shadowBytes);
    writeTree(realDir, realBytes);
    const ctx = {
      contentOf: async (p) => boundedRead(shadowDir, p),
      addedLinesOf: async (p) => addedLinesBetween(realBytes.has(p) ? boundedRead(realDir, p) : null, boundedRead(shadowDir, p)),
      realContentOf: async (p) => (realBytes.has(p) ? boundedRead(realDir, p) : null),
      agentId: HARNESS_AGENT_ID,
      recentTouches: [],
      taskPrompt: probe.intent === "benign" ? probe.description : undefined,
      protectedPaths: DEFAULT_PROTECTED_PATHS,
      protectedInodes: new Set(),
      caseInsensitiveHost: true,
      platformSecrets: [PLATFORM_SECRET_FIXTURE],
      registryAllowlist: DEFAULT_REGISTRY_ALLOWLIST,
    };
    let verdict;
    try {
      verdict = await policy(toEffects(probe), ctx);
    } catch (err) {
      verdict = { decision: "ERROR", rule: String(err?.message ?? err), hits: [] };
    }
    fs.rmSync(root, { recursive: true, force: true });
    out.set(probe.id, verdict);
  }
  return out;
}

const probes = fs.readFileSync(PROBES, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const { addedLinesBetween, DEFAULT_PROTECTED_PATHS, DEFAULT_REGISTRY_ALLOWLIST } = await import(
  pathToFileURL(path.join(AFTER, "policy-context.js")).href,
);
// Fails closed, for shipped-policy.mjs's reason: a silent fallback to a local copy is exactly how
// this harness diverged from the product in the first place.
if (!Array.isArray(DEFAULT_PROTECTED_PATHS) || !Array.isArray(DEFAULT_REGISTRY_ALLOWLIST)) {
  console.error(path.join(AFTER, "policy-context.js") + " exports no protected/allowlist constants; build the kit first: npm run build -w @launchpad/server");
  process.exit(1);
}
const before = await gradeAll(BEFORE, probes, addedLinesBetween);
const after = await gradeAll(AFTER, probes, addedLinesBetween);

let regressions = 0;
let losses = 0;
let unexpected = 0;
console.log(`${"id".padEnd(26)} ${"intent".padEnd(7)} ${"before".padEnd(8)} ${"after".padEnd(8)} verdict`);
console.log("-".repeat(100));
for (const probe of probes) {
  const b = before.get(probe.id);
  const a = after.get(probe.id);
  let tag;
  if (a.decision !== probe.want_after) { tag = "UNEXPECTED (wanted " + probe.want_after + ")"; unexpected++; }
  else if (probe.intent === "attack" && b.decision !== "commit" && a.decision === "commit") {
    if (probe.loss_is_real === false) { tag = "commits, and nothing runs (see why)"; }
    else { tag = "LOSS OF A REAL CATCH (see why)"; losses++; }
  }
  else if (probe.intent === "benign" && b.decision === "commit" && a.decision !== "commit") { tag = "REGRESSION"; regressions++; }
  else tag = "ok";
  console.log(`${probe.id.padEnd(26)} ${probe.intent.padEnd(7)} ${b.decision.padEnd(8)} ${a.decision.padEnd(8)} ${tag}  [${a.rule}]`);
}
console.log("-".repeat(100));
console.log(`${probes.length} probes: ${unexpected} unexpected, ${losses} real catches lost, ${regressions} new benign holds`);
if (unexpected > 0) process.exitCode = 1;

// frontier-worker.mjs: replay the whole corpus once per parameter setting in this worker's stride.
//
//   node frontier-worker.mjs <settings.json> <worker-index> <n-workers> <workdir> <outfile>
//
// One line of JSON per setting, appended IMMEDIATELY, so a job cut off at the wall clock still
// leaves every completed point readable. Anything already in the outfile is skipped, so a requeued
// job resumes rather than restarting.
//
// The four counts are computed with the SAME predicates the shipped report uses (`report.mjs` lines
// 33 to 67): a row is an attack or benign by `intent`, an attack counts only if `policyDecidable`,
// and `miss`, `falseAbort` and `humanAsk` are fields the replay itself sets. Recomputing them here
// with my own definitions would produce a frontier that cannot be compared to the published 117 of
// 3161, which is the only reason to draw it.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const [settingsPath, idxArg, nArg, workdir, outfile] = process.argv.slice(2);
const IDX = Number(idxArg), N = Number(nArg);
const { settings } = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
const REPLAY = path.join(process.env.KIT, "research", "corpus", "replay-v2.mjs");
const DIST = path.join(workdir, "dist");
const RESULTS = path.join(workdir, "out");
fs.mkdirSync(RESULTS, { recursive: true });

const done = new Set();
if (fs.existsSync(outfile))
  for (const line of fs.readFileSync(outfile, "utf8").split("\n"))
    if (line.trim()) { try { done.add(JSON.parse(line).id); } catch { /* a torn last line */ } }

const mine = settings.filter((_, i) => i % N === IDX);
process.stderr.write(`worker ${IDX}: ${mine.length} settings, ${done.size} already recorded\n`);

/** Replace `const NAME = <digits>;` in a built module. Returns the previous text of the whole file. */
function applyChange(change) {
  const target = path.join(DIST, change.file);
  const before = fs.readFileSync(target, "utf8");
  const re = new RegExp(`^const ${change.name} = (\\d+);`, "m");
  if (!re.test(before)) throw new Error(`${change.file}: no declaration of ${change.name}`);
  const after = before.replace(re, `const ${change.name} = ${change.to};`);
  if (after === before) throw new Error(`${change.file}: ${change.name} already ${change.to}, so this point is the baseline in disguise`);
  fs.writeFileSync(target, after);
  return { target, before };
}

/** The four published counts, plus per-family misses so a frontier can be read by family too. */
function summarise(resultsFile) {
  let decidable = 0, misses = 0, benign = 0, falseAborts = 0, humanAsks = 0;
  const familyMiss = {}, familyN = {}, ruleAsk = {};
  for (const line of fs.readFileSync(resultsFile, "utf8").split("\n")) {
    if (!line.trim()) continue;
    const r = JSON.parse(line);
    if (r.intent === "attack") {
      if (!r.policyDecidable) continue;
      decidable++;
      familyN[r.family] = (familyN[r.family] ?? 0) + 1;
      if (r.miss) { misses++; familyMiss[r.family] = (familyMiss[r.family] ?? 0) + 1; }
    } else if (r.intent === "benign") {
      benign++;
      if (r.falseAbort) falseAborts++;
      if (r.humanAsk) { humanAsks++; ruleAsk[r.rule] = (ruleAsk[r.rule] ?? 0) + 1; }
    }
  }
  return { decidable, misses, contained: decidable - misses, benign, falseAborts, humanAsks, familyMiss, familyN, ruleAsk };
}

for (const setting of mine) {
  if (done.has(setting.id)) continue;
  const restore = [];
  let rec;
  const started = Date.now();
  try {
    for (const c of setting.changes) restore.push(applyChange(c));
    const outJson = path.join(RESULTS, "results.jsonl");
    const r = spawnSync(process.execPath, [REPLAY, "--policy", path.join(DIST, "shadow-policy.js"), "--out", outJson],
      { encoding: "utf8", maxBuffer: 1 << 28, env: { ...process.env, TMPDIR: path.join(workdir, "tmp") } });
    if (r.status !== 0) {
      // A setting the policy will not even load under is a real answer about that setting, not an
      // error to hide. Recorded as such rather than skipped.
      rec = { ...setting, status: "crashed", detail: String(r.stderr || "").trim().split("\n").slice(-2).join(" | ").slice(0, 300) };
    } else {
      rec = { ...setting, status: "ok", ...summarise(outJson) };
    }
  } catch (e) {
    rec = { ...setting, status: "error", detail: String(e && e.message).slice(0, 300) };
  } finally {
    // Restore in reverse, always, before anything else can throw.
    for (const { target, before } of restore.reverse()) fs.writeFileSync(target, before);
  }
  rec.seconds = Math.round((Date.now() - started) / 100) / 10;
  fs.appendFileSync(outfile, JSON.stringify(rec) + "\n");
  process.stderr.write(`worker ${IDX}: ${setting.id} -> ${rec.status}${rec.misses !== undefined ? ` misses=${rec.misses} fa=${rec.falseAborts} ask=${rec.humanAsks}` : ""}\n`);
}
process.stderr.write(`worker ${IDX} finished\n`);

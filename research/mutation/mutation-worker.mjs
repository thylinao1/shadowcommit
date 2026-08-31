// mutation-worker.mjs: grade a stride of the mutant manifest against the whole corpus.
//
//   node mutation-worker.mjs <manifest.json> <baseline-decisions.json> <worker-index> <n-workers> <workdir> <outfile>
//
// A mutant is KILLED when at least one scenario's decision differs from the baseline, and SURVIVES
// when all 8,190 agree. A survivor is a hole in the CORPUS: the rules changed and nothing noticed.
//
// Each worker owns a private copy of dist/, so it mutates one file, replays, and restores, without
// ever touching another worker's bytes. One line of JSON is appended per mutant IMMEDIATELY, so a
// job that is cut off mid-run still leaves every completed mutant readable.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const [manifestPath, baselinePath, idxArg, nArg, workdir, outfile] = process.argv.slice(2);
const IDX = Number(idxArg), N = Number(nArg);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8"));   // { id: decision }
const REPLAY = path.join(process.env.KIT, "research", "corpus", "replay-v2.mjs");
const DIST = path.join(workdir, "dist");
const RESULTS = path.join(workdir, "out");
fs.mkdirSync(RESULTS, { recursive: true });

// Anything already recorded is not redone, so a requeued job resumes instead of restarting.
const done = new Set();
if (fs.existsSync(outfile))
  for (const line of fs.readFileSync(outfile, "utf8").split("\n"))
    if (line.trim()) { try { done.add(JSON.parse(line).id); } catch { /* a torn last line */ } }

// A REPLAY THAT NEVER RETURNS. Three of the 1,082 mutants in the v2 run turn a loop increment from
// `index += 1` into `index += 0`, in secret-scan.js, trojan-source.js and net-to-exec.js. The policy
// then does not terminate, `spawnSync` had no timeout, and the worker waited. Four of 24 workers sat
// on four mutants for more than seven hours while the other twenty finished, so the run stalled at
// 931 of 1,082 and the score was quoted as a partial figure. The same thing happened to the first
// run, where it was recorded as the 3 hour wall clock of the `normal` partition cutting the job off.
// It was not the wall clock. No amount of wall clock finishes a replay that does not terminate.
//
// The observed distribution is 29 to 102 seconds per replay under 24-way contention, so ten minutes
// is roughly six times the slowest real one.
const REPLAY_TIMEOUT_MS = Number(process.env.MUTATION_TIMEOUT_MS ?? 600_000);

const mine = manifest.mutants.filter((_, i) => i % N === IDX);
process.stderr.write(`worker ${IDX}: ${mine.length} mutants, ${done.size} already recorded\n`);

let killed = 0, survived = 0, errored = 0;
for (const mut of mine) {
  if (done.has(mut.id)) continue;
  const target = path.join(DIST, mut.file);
  const original = fs.readFileSync(target, "utf8");
  const mutated = original.slice(0, mut.at) + mut.to + original.slice(mut.at + mut.len);
  if (mutated === original) {
    fs.appendFileSync(outfile, JSON.stringify({ ...mut, status: "no-op" }) + "\n");
    continue;
  }
  fs.writeFileSync(target, mutated);

  const outJson = path.join(RESULTS, "results.jsonl");
  const started = Date.now();
  const r = spawnSync(process.execPath, [REPLAY, "--policy", path.join(DIST, "shadow-policy.js"), "--out", outJson],
    { encoding: "utf8", maxBuffer: 1 << 28, timeout: REPLAY_TIMEOUT_MS, killSignal: "SIGKILL",
      env: { ...process.env, TMPDIR: path.join(workdir, "tmp") } });
  fs.writeFileSync(target, original);           // restore before anything can throw

  let rec;
  // Node sets error.code ETIMEDOUT when ITS timer fires, which is the reliable signal. The second
  // arm catches a SIGKILL we did not obviously cause and is deliberately kept, because a replay that
  // dies without a status is still a policy the corpus told apart from the baseline. It is labelled
  // differently: an OOM kill is not a timeout, and writing "no verdict within 600s" over one would
  // be a false detail on a record somebody will read later.
  const byTimer = r.error?.code === "ETIMEDOUT";
  const bySignal = !byTimer && r.signal === "SIGKILL" && r.status === null;
  const timedOut = byTimer || bySignal;
  if (timedOut) {
    // KILLED, and by the same argument the crash branch below already makes: the evaluation can tell
    // this policy from the baseline, loudly. It is counted separately rather than folded into the
    // verdict kills, because a hang and a changed verdict are different evidence and a reader is
    // entitled to see how many of each there were. It is never counted as SURVIVED: a survivor is a
    // mutant the corpus could not distinguish, and this one it distinguished in the most obvious way
    // available.
    rec = byTimer
      ? { ...mut, status: "killed", by: "timeout", detail: `no verdict within ${REPLAY_TIMEOUT_MS / 1000}s` }
      : { ...mut, status: "killed", by: "signal", detail: "killed by SIGKILL with no exit status, cause unknown (an out-of-memory kill looks like this)" };
    killed++;
  } else if (r.status !== 0) {
    // A mutant that will not even load is still killed -- the corpus notices it, loudly.
    rec = { ...mut, status: "killed", by: "crash", detail: String(r.stderr || "").trim().split("\n").slice(-2).join(" | ").slice(0, 300) };
    killed++;
  } else {
    let diffs = 0; const examples = [];
    for (const line of fs.readFileSync(outJson, "utf8").split("\n")) {
      if (!line.trim()) continue;
      const row = JSON.parse(line);
      const was = baseline[row.id];
      if (was !== undefined && was !== row.decision) {
        diffs++;
        if (examples.length < 5) examples.push({ id: row.id, was, now: row.decision, intent: row.intent });
      }
    }
    if (diffs > 0) { rec = { ...mut, status: "killed", by: "verdict", diffs, examples }; killed++; }
    else { rec = { ...mut, status: "survived", diffs: 0 }; survived++; }
  }
  rec.seconds = Math.round((Date.now() - started) / 100) / 10;
  fs.appendFileSync(outfile, JSON.stringify(rec) + "\n");
  if ((killed + survived + errored) % 10 === 0)
    process.stderr.write(`worker ${IDX}: ${killed} killed, ${survived} SURVIVED\n`);
}
process.stderr.write(`worker ${IDX} finished: ${killed} killed, ${survived} survived\n`);

// Item 1 (brief section 1): per-stage latency of a turn (capture, judge, settle, record) at
// p50/p95, on a small fixture and on a realistic few-hundred-file repository. Driven through the
// real `TransactionalRunner`, real `defaultPolicy`, real journal, with a scripted inner runner (no
// model, no container). Run with:
//
//   PATH="$HOME/.nvm/versions/node/v22.21.0/bin:$PATH" \
//     node_modules/.bin/tsx apps/server/src/bench/stage-latency.mts
//
// Output: apps/server/src/bench/results/stage-latency.jsonl
import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  hostRow, buildFixtureTree, mkScratch, rm, writeJsonl, resultsDir,
  readJournal, msBetween, summarize, makeRunner, scriptRunner, log,
  type JournalRow, type Summary,
} from "./lib.mjs";

const execFileAsync = promisify(execFile);

interface FixtureSpec {
  name: string;
  files: number;
  turns: number;
}

const FIXTURES: FixtureSpec[] = [
  { name: "small-fixture", files: 50, turns: 150 },
  { name: "realistic-repo", files: 400, turns: 150 },
];

/**
 * One turn's script: two modified source-like files plus one append to a fixed churn file, the
 * SAME three paths every turn. This is deliberate: `rules/blast-radius.ts` counts the union of a
 * turn's own paths with every path this agent touched in its last 10 committed turns (or 24h), so a
 * script that invents new filenames every turn crosses that >=8 threshold by turn 4 regardless of
 * how small each individual turn is (see the `cumulative-footprint-demo` rows below, and
 * LANE-REPORT.md). Reusing the same paths measures the capture/judge/settle stages on the steady
 * "commit" path an ordinary repeated-edit workload takes; the demo block shows the other one.
 */
function turnAction(i: number) {
  return async (ws: string): Promise<void> => {
    const outDir = path.join(ws, "bench-out");
    await fs.mkdir(outDir, { recursive: true });
    await fs.writeFile(path.join(outDir, "feature-a.ts"), `export const turn${i}A = ${i};\n`);
    await fs.writeFile(path.join(outDir, "feature-b.ts"), `export const turn${i}B = ${i * 2};\n`);
    await fs.appendFile(path.join(ws, "d0", "f0_0.txt"), `churn line from turn ${i}\n`);
  };
}

/** Same shape as `turnAction`, except every turn invents new filenames; see the comment above. */
function turnActionUniquePaths(i: number) {
  return async (ws: string): Promise<void> => {
    const outDir = path.join(ws, "bench-out");
    await fs.mkdir(outDir, { recursive: true });
    await fs.writeFile(path.join(outDir, `feature-${i}-a.ts`), `export const turn${i}A = ${i};\n`);
    await fs.writeFile(path.join(outDir, `feature-${i}-b.ts`), `export const turn${i}B = ${i * 2};\n`);
    await fs.appendFile(path.join(ws, "d0", "f0_0.txt"), `churn line from turn ${i}\n`);
  };
}

interface TurnRow {
  kind: "turn";
  fixture: string;
  index: number;
  runId: string;
  decision: string;
  effects: number;
  bytes: number;
  open_ms: number;
  run_ms: number;
  capture_ms: number;
  judge_ms: number;
  settle_ms: number;
  total_journal_ms: number;
  total_wall_ms: number;
  journalBytesBefore: number;
}

/** groups a flat journal stream into per-run segments, in the order runs actually happened */
function segmentByRun(rows: JournalRow[]): JournalRow[][] {
  const segments: JournalRow[][] = [];
  let current: JournalRow[] = [];
  let currentRunId: string | undefined;
  for (const row of rows) {
    if (row.runId === undefined) continue; // journal-level notes (key-created, checkpoint, ...)
    if (row.runId !== currentRunId) {
      if (current.length) segments.push(current);
      current = [];
      currentRunId = row.runId;
    }
    current.push(row);
  }
  if (current.length) segments.push(current);
  return segments;
}

const TERMINAL_KINDS = new Set(["turn.committed", "turn.discarded", "turn.held", "turn.conflicted"]);

async function runFixture(spec: FixtureSpec, out: unknown[]): Promise<void> {
  log(`\n=== ${spec.name}: ${spec.files} files, ${spec.turns} turns ===`);
  const root = await mkScratch(`bench-stage-${spec.name}-`);
  const template = path.join(root, "template");
  await buildFixtureTree(template, spec.files);
  const ws = path.join(root, "ws");

  const journalPath = path.join(root, "data", "journal.jsonl");
  const runner = makeRunner(scriptRunner(async (w, req) => {
    const i = Number(req.prompt);
    await turnAction(i)(w);
  }), root);

  out.push({ kind: "config", fixture: spec.name, files: spec.files, turns: spec.turns, effectsPerTurn: 3 });

  const wallTotals: number[] = [];
  const preRunMarks: number[] = [];
  const journalBytesBefore: number[] = [];

  for (let i = 1; i <= spec.turns; i++) {
    await rm(ws);
    await execFileAsync("cp", ["-a", template, ws]);
    const before = await fs.stat(journalPath).then((s) => s.size).catch(() => 0);
    journalBytesBefore.push(before);
    const t0 = Date.now();
    preRunMarks.push(t0);
    const t0h = process.hrtime.bigint();
    const result = await runner.run({ agentId: "bench-agent", workspacePath: ws, prompt: String(i), threadId: null });
    const t1h = process.hrtime.bigint();
    wallTotals.push(Number(t1h - t0h) / 1e6);
    if (result.containment?.decision !== "commit") {
      log(`  WARNING turn ${i} did not commit: ${JSON.stringify(result.containment)}`);
    }
    if (i % 25 === 0) log(`  turn ${i}/${spec.turns}`);
  }
  await runner.closeJournal();

  const rows = await readJournal(journalPath);
  const segments = segmentByRun(rows);
  if (segments.length !== spec.turns) {
    log(`  NOTE: expected ${spec.turns} run segments, journal has ${segments.length} (extra/missing records, see raw journal)`);
  }

  const byStage: Record<"open" | "run" | "capture" | "judge" | "settle" | "total", number[]> = {
    open: [], run: [], capture: [], judge: [], settle: [], total: [],
  };
  const judgeVsIndex: { index: number; judge_ms: number; journalBytesBefore: number }[] = [];

  segments.forEach((segment, idx) => {
    const runId = segment[0]!.runId!;
    const at = (kind: string) => segment.find((r) => r.kind === kind)?.at;
    const begin = at("turn.begin");
    const executed = at("turn.executed");
    const captured = at("effects.captured");
    const decisionRow = segment.find((r) => r.kind === "policy.decision");
    const decision = decisionRow?.at;
    const terminalRow = segment.find((r) => TERMINAL_KINDS.has(r.kind));
    const terminal = terminalRow?.at;
    const effectsRow = segment.find((r) => r.kind === "effects.captured");

    if (!begin || !executed || !captured || !decision || !terminal) {
      log(`  WARNING run ${runId} (segment ${idx}) is missing a phase boundary; skipped from stage stats`);
      return;
    }
    const preRun = preRunMarks[idx]!;
    const openMs = Date.parse(begin) - preRun;
    const runMs = msBetween(begin, executed);
    const captureMs = msBetween(executed, captured);
    const judgeMs = msBetween(captured, decision);
    const settleMs = msBetween(decision, terminal);
    const totalJournalMs = Date.parse(terminal) - preRun;

    byStage.open.push(Math.max(openMs, 0));
    byStage.run.push(Math.max(runMs, 0));
    byStage.capture.push(Math.max(captureMs, 0));
    byStage.judge.push(Math.max(judgeMs, 0));
    byStage.settle.push(Math.max(settleMs, 0));
    byStage.total.push(Math.max(totalJournalMs, 0));

    judgeVsIndex.push({ index: idx + 1, judge_ms: Math.max(judgeMs, 0), journalBytesBefore: journalBytesBefore[idx]! });

    const turnRow: TurnRow = {
      kind: "turn",
      fixture: spec.name,
      index: idx + 1,
      runId,
      decision: (decisionRow?.["decision"] as string | undefined) ?? "unknown",
      effects: (effectsRow?.["count"] as number | undefined) ?? 0,
      bytes: (effectsRow?.["bytes"] as number | undefined) ?? 0,
      open_ms: round(openMs),
      run_ms: round(runMs),
      capture_ms: round(captureMs),
      judge_ms: round(judgeMs),
      settle_ms: round(settleMs),
      total_journal_ms: round(totalJournalMs),
      total_wall_ms: round(wallTotals[idx]!),
      journalBytesBefore: journalBytesBefore[idx]!,
    };
    out.push(turnRow);
  });

  for (const [stage, values] of Object.entries(byStage)) {
    const s: Summary = summarize(values);
    out.push({ kind: "summary", fixture: spec.name, stage, ...s });
    log(`  ${stage.padEnd(8)} p50=${s.p50}ms p95=${s.p95}ms max=${s.max}ms n=${s.n}`);
  }

  // Judge-stage cost vs how far into the run we are, in deciles, to show whether it grows with
  // journal size (recentTouchesFor rereads the whole journal file per turn; see LANE-REPORT.md).
  const bucketSize = Math.max(1, Math.floor(judgeVsIndex.length / 10));
  for (let b = 0; b < 10; b++) {
    const slice = judgeVsIndex.slice(b * bucketSize, b === 9 ? judgeVsIndex.length : (b + 1) * bucketSize);
    if (!slice.length) continue;
    const s = summarize(slice.map((x) => x.judge_ms));
    out.push({
      kind: "judge-vs-journal-growth",
      fixture: spec.name,
      decile: b + 1,
      turnIndexRange: [slice[0]!.index, slice[slice.length - 1]!.index],
      journalBytesBeforeRange: [slice[0]!.journalBytesBefore, slice[slice.length - 1]!.journalBytesBefore],
      judge_p50_ms: s.p50,
      judge_p95_ms: s.p95,
      judge_mean_ms: s.mean,
    });
  }

  await rm(root);
}

function round(x: number): number {
  return Math.round(x * 100) / 100;
}

/**
 * Not a stage-latency measurement: a small, self-contained demonstration of the cumulative-footprint
 * behaviour the fixture loop above deliberately avoids. Twelve turns, each touching two brand-new
 * paths plus the fixed churn file: the workload a real agent produces when each turn is a small,
 * genuinely different, non-overlapping edit. Records the policy verdict for every turn so the point
 * at which `large-blast-radius:cumulative` starts firing is a committed number, not an assertion.
 */
async function runCumulativeFootprintDemo(out: unknown[]): Promise<void> {
  log("\n=== cumulative-footprint-demo: 12 turns, 2 new paths each, small fixture ===");
  const root = await mkScratch("bench-cumulative-");
  const ws = path.join(root, "ws");
  await buildFixtureTree(ws, 20);
  const runner = makeRunner(scriptRunner(async (w, req) => {
    const i = Number(req.prompt);
    await turnActionUniquePaths(i)(w);
  }), root);

  for (let i = 1; i <= 12; i++) {
    const result = await runner.run({ agentId: "cumulative-agent", workspacePath: ws, prompt: String(i), threadId: null });
    const c = result.containment;
    log(`  turn ${i}: ${c?.decision} ${c?.rule ?? ""}`);
    out.push({
      kind: "cumulative-footprint-demo",
      turnIndex: i,
      decision: c?.decision,
      rule: c?.rule,
      effectsThisTurn: c?.effects,
    });
  }
  await runner.closeJournal();
  await rm(root);
}

/**
 * `recentTouchesFor` (policy-context.ts) is what `buildPolicyContext` calls to feed
 * `large-blast-radius`'s cumulative-window check: on every single judge phase it reads the WHOLE
 * journal file with `fs.readFile` and scans every line, filtering for `turn.committing` records that
 * belong to this agent, regardless of how far back they are. The 150-turn runs above only grow the
 * journal to ~0.5 MB, too small to show the trend clearly against per-call noise. This isolates the
 * real, exported function directly against synthetic journals shaped like a long-lived deployment's
 * (many turns, many agents, one line per commit) at journal sizes a real platform reaches in weeks,
 * not minutes, with no TransactionalRunner, no HMAC, no policy: just the read-and-scan this exact
 * function performs on every turn.
 */
async function runJournalScalingMicrobench(out: unknown[]): Promise<void> {
  log("\n=== recentTouchesFor cost vs pre-existing journal size (isolated) ===");
  const { recentTouchesFor } = await import("../policy-context.js");
  const root = await mkScratch("bench-journal-scale-");
  const journalPath = path.join(root, "journal.jsonl");
  const totalRecords = 200_000;
  const agents = 40;
  const checkpoints = [1_000, 10_000, 50_000, 100_000, 200_000];
  const handle = await fs.open(journalPath, "w");
  let written = 0;
  const REPS = 15;
  const BATCH = 5_000;
  for (const checkpoint of checkpoints) {
    while (written < checkpoint) {
      const upto = Math.min(written + BATCH, checkpoint);
      let chunk = "";
      for (; written < upto; written++) {
        const agentId = `agent-${written % agents}`;
        const record = {
          seq: written + 1,
          kind: "turn.committing",
          agentId,
          effects: [
            { path: `src/module-${written % 500}/file-${written % 37}.ts`, kind: "modify" },
            { path: `src/module-${written % 500}/other-${written % 11}.ts`, kind: "create" },
          ],
          at: new Date(Date.now() - (totalRecords - written) * 1000).toISOString(),
        };
        chunk += JSON.stringify(record) + "\n";
      }
      await handle.appendFile(chunk, "utf8");
    }
    const bytes = (await fs.stat(journalPath)).size;
    const samples: number[] = [];
    for (let r = 0; r < REPS; r++) {
      const t0 = process.hrtime.bigint();
      await recentTouchesFor(journalPath, "agent-0");
      const t1 = process.hrtime.bigint();
      samples.push(Number(t1 - t0) / 1e6);
    }
    const s = summarize(samples);
    log(`  ${checkpoint} records (${(bytes / 1024 / 1024).toFixed(2)} MB): p50=${s.p50}ms p95=${s.p95}ms`);
    out.push({ kind: "recent-touches-vs-journal-size", records: checkpoint, journalBytes: bytes, ...s });
  }
  await handle.close();
  await rm(root);
}

async function main(): Promise<void> {
  const out: unknown[] = [await hostRow(process.cwd())];
  for (const spec of FIXTURES) await runFixture(spec, out);
  await runCumulativeFootprintDemo(out);
  await runJournalScalingMicrobench(out);
  const file = path.join(resultsDir(), "stage-latency.jsonl");
  await writeJsonl(file, out);
  log(`\nwrote ${file}`);
}

await main();

// Item 3 (brief section 3): a concurrency sweep from 1 to 8 simultaneous turns, reporting how each
// stage's percentiles degrade, and the journal's behaviour under it: one shared `TransactionalRunner`
// (one journal, one shadowRoot, one store: the shape an internal scalability review names, "one journal file with
// one writer for every agent"), K agents firing `run()` at once via `Promise.all`, real journal, real
// commit protocol, no model calls.
//
//   PATH="$HOME/.nvm/versions/node/v22.21.0/bin:$PATH" \
//     node_modules/.bin/tsx apps/server/src/bench/concurrency-sweep.mts
import path from "node:path";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { TransactionalRunner } from "../transactional-runner.js";
import { verifyJournalAt } from "../journal.js";
import {
  hostRow, buildFixtureTree, mkScratch, rm, writeJsonl, resultsDir, summarize, makeRunner, scriptRunner,
  readJournal, msBetween, scratchHmacKey, log, type JournalRow,
} from "./lib.mjs";

const execFileAsync = promisify(execFile);

const FILES = 100; // a moderate fixed repo size; item 2 already covers the size axis
const LEVELS = [1, 2, 4, 8];
const BATCHES = 6; // per concurrency level, so each level has LEVELS[i] * BATCHES samples

const TERMINAL_KINDS = new Set(["turn.committed", "turn.discarded", "turn.held", "turn.conflicted"]);

function segmentByRunId(rows: JournalRow[], runId: string): JournalRow[] {
  return rows.filter((r) => r.runId === runId);
}

async function main(): Promise<void> {
  const root = await mkScratch("bench-concurrency-");
  const template = path.join(root, "template");
  await buildFixtureTree(template, FILES);
  const journalPath = path.join(root, "data", "journal.jsonl");
  const publicKeyFile = path.join(root, "keys", "journal.pub");
  // kept so the journal can be independently re-verified below with `verifyJournalAt`; see the
  // `hmacKey` doc comment on `MakeRunnerOptions` for why the static `verifyChain` cannot be used here.
  const hmacKey = scratchHmacKey();

  // one runner, shared across every level and every batch: the real deployment shape
  const inner = scriptRunner(async (w, req) => {
    const agentId = req.agentId;
    const outDir = path.join(w, "bench-out");
    await fs.mkdir(outDir, { recursive: true });
    await fs.writeFile(path.join(outDir, `${agentId}-a.ts`), `export const x = "${req.prompt}";\n`);
    await fs.writeFile(path.join(outDir, `${agentId}-b.ts`), `export const y = "${req.prompt}";\n`);
  });
  const runner: TransactionalRunner = makeRunner(inner, root, { hmacKey });

  const out: unknown[] = [await hostRow(process.cwd())];
  out.push({ kind: "config", files: FILES, levels: LEVELS, batchesPerLevel: BATCHES });

  for (const level of LEVELS) {
    log(`\n=== concurrency ${level} ===`);
    const byStage: Record<"open" | "capture" | "judge" | "settle" | "total", number[]> = {
      open: [], capture: [], judge: [], settle: [], total: [],
    };
    let commits = 0;
    let nonCommits = 0;

    for (let batch = 0; batch < BATCHES; batch++) {
      // fresh, isolated workspace per agent per batch: concurrency across DIFFERENT workspaces is
      // the realistic case (independent agents); item elsewhere already covers one-workspace
      // conflict handling. Each agent reuses the SAME two paths every batch (see stage-latency.mts's
      // note on the cumulative-footprint rule) so every call commits and the stages measured are the
      // steady-state commit path, not the review path.
      const calls = await Promise.all(
        Array.from({ length: level }, async (_, k) => {
          const agentId = `agent-${k}`;
          const ws = path.join(root, `ws-${level}-${k}`);
          await rm(ws);
          await fs.mkdir(ws, { recursive: true });
          await execFileAsync("cp", ["-a", template + "/.", ws]);
          const preRunMs = Date.now();
          const result = await runner.run({ agentId, workspacePath: ws, prompt: `batch${batch}`, threadId: null });
          return { agentId, preRunMs, result };
        }),
      );

      const rows = await readJournal(journalPath);
      for (const call of calls) {
        const runId = call.result.containment?.runId;
        if (!runId) continue;
        if (call.result.containment?.decision === "commit") commits += 1;
        else nonCommits += 1;
        const segment = segmentByRunId(rows, runId);
        const begin = segment.find((r) => r.kind === "turn.begin")?.at;
        const executed = segment.find((r) => r.kind === "turn.executed")?.at;
        const captured = segment.find((r) => r.kind === "effects.captured")?.at;
        const decision = segment.find((r) => r.kind === "policy.decision")?.at;
        const terminal = segment.find((r) => TERMINAL_KINDS.has(r.kind))?.at;
        if (!begin || !executed || !captured || !decision || !terminal) continue;
        byStage.open.push(Math.max(Date.parse(begin) - call.preRunMs, 0));
        byStage.capture.push(Math.max(msBetween(executed, captured), 0));
        byStage.judge.push(Math.max(msBetween(captured, decision), 0));
        byStage.settle.push(Math.max(msBetween(decision, terminal), 0));
        byStage.total.push(Math.max(Date.parse(terminal) - call.preRunMs, 0));
      }
    }

    for (const [stage, values] of Object.entries(byStage)) {
      const s = summarize(values);
      out.push({ kind: "summary", concurrency: level, stage, ...s });
      log(`  ${stage.padEnd(8)} p50=${s.p50}ms p95=${s.p95}ms max=${s.max}ms n=${s.n}`);
    }
    out.push({ kind: "outcomes", concurrency: level, commits, nonCommits });
    log(`  commits=${commits} nonCommits=${nonCommits}`);

    // the journal's own behaviour under this level of concurrency: does it still verify, and does
    // the record count match what was actually written (no torn/duplicated/forked records)? A fresh,
    // independent re-verification against the real key (verifyJournalAt is the same function
    // TransactionalRunner.verifyChain calls, given the key the static method cannot see here).
    const report = await verifyJournalAt(journalPath, { hmacKey, publicKeyFile, dataDirectory: path.dirname(journalPath) });
    const chain = { ok: report.ok, records: report.records, problems: report.problems.map((p) => p.message) };
    const rowsNow = await readJournal(journalPath);
    const seqs = rowsNow.map((r) => r.seq).sort((a, b) => a - b);
    const gaps: number[] = [];
    for (let i = 1; i < seqs.length; i++) if (seqs[i]! !== seqs[i - 1]! + 1) gaps.push(seqs[i - 1]! as number);
    log(`  journal: ok=${chain.ok} records=${chain.records} seqGaps=${gaps.length} problems=${chain.problems.slice(0, 3).join("; ")}`);
    out.push({
      kind: "journal-integrity",
      concurrency: level,
      afterTotalRuns: rowsNow.filter((r) => r.runId !== undefined).length,
      chainOk: chain.ok,
      chainRecords: chain.records,
      seqGapsFound: gaps.length,
      problems: chain.problems.slice(0, 5),
    });
  }

  await runner.closeJournal();
  const file = path.join(resultsDir(), "concurrency-sweep.jsonl");
  await writeJsonl(file, out);
  log(`\nwrote ${file}`);
  await rm(root);
}

await main();

// Item 2 (brief section 2): does opening a transaction cost the same at 50, 8,886 and 30,000 files?
// An internal scalability review named two claims that were
// never measured against the shipped code: "opening a transaction is O(1) in repo size" and "a
// 30,000-file repo costs the same to open as a 50-file one", while also flagging that
// `transactional-runner.ts` calls `snapshotStats(request.workspacePath)` UNCONDITIONALLY on every
// turn (the conflict baseline), whatever the seal mechanism, and that `runner-factory.ts` passes no
// `seal` hook, so the mechanism actually shipped is the `cp -a` copy fallback on every host,
// including Linux. This measures both the shipped path in full, through the real
// `TransactionalRunner` with a no-op scripted inner runner, and the constituent real functions
// (`snapshotStats`, the same `cp -a` copyFallback runs) in isolation, so the claim is settled with a
// number rather than a plan.
//
//   PATH="$HOME/.nvm/versions/node/v22.21.0/bin:$PATH" \
//     node_modules/.bin/tsx apps/server/src/bench/turn-open-scaling.mts
import path from "node:path";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { snapshotStats } from "../capture.js";
import {
  hostRow, buildFixtureTree, mkScratch, rm, writeJsonl, resultsDir, summarize, makeRunner, scriptRunner, log,
} from "./lib.mjs";

const execFileAsync = promisify(execFile);

interface SizeSpec {
  files: number;
  componentReps: number;
  turnReps: number;
}

// 50 and 8,886 reproduce the two points the held-out-sets SNAPSHOT-BENCH.md spike measured
// (8,886 was the kit's own checkout at the time); 30,000 is the synthetic large-monorepo point the
// same spike used. Rep counts fall as size rises because `cp -a` alone runs ~10s at 30,000 files on
// this machine (measured separately; see LANE-REPORT.md); the point is real reps at real cost, not
// as many as at 50 files.
const SIZES: SizeSpec[] = [
  { files: 50, componentReps: 20, turnReps: 15 },
  { files: 8_886, componentReps: 6, turnReps: 5 },
  { files: 30_000, componentReps: 3, turnReps: 3 },
];

async function timeReps(reps: number, fn: () => Promise<void>): Promise<number[]> {
  const samples: number[] = [];
  for (let i = 0; i < reps; i++) {
    const t0 = process.hrtime.bigint();
    await fn();
    const t1 = process.hrtime.bigint();
    samples.push(Number(t1 - t0) / 1e6);
  }
  return samples;
}

async function measureSize(spec: SizeSpec, out: unknown[]): Promise<{ files: number; shippedTurnOpenP50: number }> {
  log(`\n=== ${spec.files} files ===`);
  const root = await mkScratch(`bench-turn-open-${spec.files}-`);
  const template = path.join(root, "template");
  await buildFixtureTree(template, spec.files);

  // ---- the constituent real functions, in isolation ----------------------------------------
  const baselineSamples = await timeReps(spec.componentReps, async () => {
    await snapshotStats(template);
  });
  const s1 = summarize(baselineSamples);
  log(`  snapshotStats (stat-only, the baseline)         p50=${s1.p50}ms p95=${s1.p95}ms n=${s1.n}`);
  out.push({ kind: "measure", files: spec.files, component: "snapshotStats-baseline-stat-only", ...s1 });

  const hashedSamples = await timeReps(spec.componentReps, async () => {
    await snapshotStats(template, { hash: true });
  });
  const s2 = summarize(hashedSamples);
  log(`  snapshotStats (hashed, the copy-path seal sig)  p50=${s2.p50}ms p95=${s2.p95}ms n=${s2.n}`);
  out.push({ kind: "measure", files: spec.files, component: "snapshotStats-sealed-hashed", ...s2 });

  const cpSamples: number[] = [];
  for (let i = 0; i < spec.componentReps; i++) {
    const dst = path.join(root, `cp-${i}`);
    const t0 = process.hrtime.bigint();
    await execFileAsync("cp", ["-a", template + "/.", dst]);
    const t1 = process.hrtime.bigint();
    cpSamples.push(Number(t1 - t0) / 1e6);
    await rm(dst);
  }
  const s3 = summarize(cpSamples);
  log(`  cp -a (exactly what copyFallback runs)          p50=${s3.p50}ms p95=${s3.p95}ms n=${s3.n}`);
  out.push({ kind: "measure", files: spec.files, component: "cp-a", ...s3 });

  // ---- the shipped path, end to end, through the real TransactionalRunner --------------------
  // No `seal` option is passed, matching runner-factory.ts exactly: this is the copy fallback on
  // every host, which is what the product actually runs today.
  const openSamples: number[] = [];
  const totalSamples: number[] = [];
  for (let i = 0; i < spec.turnReps; i++) {
    const runRoot = path.join(root, `runner-${i}`);
    const ws = path.join(runRoot, "ws");
    await fs.mkdir(ws, { recursive: true });
    await execFileAsync("cp", ["-a", template + "/.", ws]);
    const runner = makeRunner(scriptRunner(async () => {
      /* no-op: a turn that reads the workspace and changes nothing, isolating open+baseline cost */
    }), runRoot);
    const journalPath = path.join(runRoot, "data", "journal.jsonl");

    const t0 = process.hrtime.bigint();
    const result = await runner.run({ agentId: "bench-agent", workspacePath: ws, prompt: "noop", threadId: null });
    const t1 = process.hrtime.bigint();
    totalSamples.push(Number(t1 - t0) / 1e6);
    if (result.containment?.decision !== "commit") log(`  WARNING unexpected verdict: ${JSON.stringify(result.containment)}`);
    await runner.closeJournal();

    // isolate "open" (through turn.begin) from the journal's own timestamp, cross-checked against
    // the wall clock: the harness records t0 in the same Date-epoch domain the journal writes.
    const text = await fs.readFile(journalPath, "utf8").catch(() => "");
    const beginLine = text.split("\n").find((l) => l.includes('"turn.begin"'));
    if (beginLine) {
      const rec = JSON.parse(beginLine) as { at: string };
      const wallT0Ms = Date.now() - Number(t1 - t0) / 1e6; // approx: t0 in Date-epoch terms
      openSamples.push(Math.max(Date.parse(rec.at) - wallT0Ms, 0));
    }
    await rm(runRoot);
  }
  const s4 = summarize(totalSamples);
  log(`  TransactionalRunner.run(), shipped, no-op turn  p50=${s4.p50}ms p95=${s4.p95}ms n=${s4.n}`);
  out.push({ kind: "measure", files: spec.files, component: "shipped-turn-open-through-commit", ...s4 });

  if (openSamples.length) {
    const s5 = summarize(openSamples);
    log(`  ...of which, through turn.begin (open+baseline) p50=${s5.p50}ms p95=${s5.p95}ms n=${s5.n} (approx, ms-clock)`);
    out.push({ kind: "measure", files: spec.files, component: "shipped-turn-open-through-turn-begin-approx", ...s5 });
  }

  return { files: spec.files, shippedTurnOpenP50: s4.p50 };
}

async function main(): Promise<void> {
  const out: unknown[] = [await hostRow(process.cwd())];
  const results: { files: number; shippedTurnOpenP50: number }[] = [];
  for (const spec of SIZES) results.push(await measureSize(spec, out));

  const small = results[0]!;
  const large = results[results.length - 1]!;
  const ratio = large.shippedTurnOpenP50 / small.shippedTurnOpenP50;
  const fileRatio = large.files / small.files;
  const verdict =
    ratio > fileRatio * 0.5
      ? `NOT O(1): shipped turn-open p50 grew ${ratio.toFixed(1)}x from ${small.files} to ${large.files} files ` +
        `(a ${fileRatio.toFixed(0)}x increase in file count), tracking file count rather than staying flat.`
      : `Roughly flat: shipped turn-open p50 grew only ${ratio.toFixed(1)}x across a ${fileRatio.toFixed(0)}x ` +
        `increase in file count.`;
  log(`\nVERDICT: ${verdict}`);
  out.push({
    kind: "verdict",
    claim: "opening a transaction is O(1) in repo size",
    smallFiles: small.files,
    smallP50Ms: small.shippedTurnOpenP50,
    largeFiles: large.files,
    largeP50Ms: large.shippedTurnOpenP50,
    growthRatio: Math.round(ratio * 100) / 100,
    fileCountRatio: Math.round(fileRatio * 100) / 100,
    verdict,
  });

  const file = path.join(resultsDir(), "turn-open-scaling.jsonl");
  await writeJsonl(file, out);
  log(`\nwrote ${file}`);
}

await main();

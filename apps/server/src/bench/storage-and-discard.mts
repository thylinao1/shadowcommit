// Item 4 (brief section 4): storage per turn, and the cost of a discard, measured.
//
// Under the shipped copy mechanism (no `seal` hook wired; see turn-open-scaling.mts) sealing a
// turn means `cp -a`-ing the ENTIRE workspace, so storage per turn is the size of the whole
// workspace, not the size of what the turn changed, until the turn settles. This measures that
// directly (the exact `cp -a` operation `copyFallback` runs, at several sizes), and separately
// measures the cost of tearing that copy down again, both through the real `TransactionalRunner`
// on a turn that actually discards (a real secret-scan hit, not a stub verdict) and in isolation, the
// same `fs.rm(shadowDir, { recursive: true, force: true })` `commit-protocol.ts`'s default `release`
// runs for the copy mechanism.
//
//   PATH="$HOME/.nvm/versions/node/v22.21.0/bin:$PATH" \
//     node_modules/.bin/tsx apps/server/src/bench/storage-and-discard.mts
import path from "node:path";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  hostRow, buildFixtureTree, countFiles, treeBytes, duBytes, mkScratch, rm, writeJsonl, resultsDir,
  summarize, makeRunner, scriptRunner, log,
} from "./lib.mjs";

const execFileAsync = promisify(execFile);

interface SizeSpec {
  files: number;
  reps: number;
}

const SIZES: SizeSpec[] = [
  { files: 50, reps: 8 },
  { files: 400, reps: 5 },
  { files: 8_886, reps: 4 },
];

async function measureSize(spec: SizeSpec, out: unknown[]): Promise<void> {
  log(`\n=== ${spec.files} files ===`);
  const root = await mkScratch(`bench-storage-${spec.files}-`);
  const template = path.join(root, "template");
  await buildFixtureTree(template, spec.files);
  const templateBytes = await treeBytes(template);
  const templateFiles = await countFiles(template);

  // ---- storage per turn: the size of one turn's sealed copy, at the moment it exists -----------
  const sizeSamples: number[] = [];
  const duSamples: number[] = [];
  for (let i = 0; i < spec.reps; i++) {
    const shadow = path.join(root, `seal-${i}`, "merged");
    await fs.mkdir(shadow, { recursive: true });
    await execFileAsync("cp", ["-a", template + "/.", shadow]);
    sizeSamples.push(await treeBytes(shadow));
    const du = await duBytes(shadow);
    if (du !== null) duSamples.push(du);
    await rm(path.dirname(shadow));
  }
  const sApparent = summarize(sizeSamples);
  const sDisk = summarize(duSamples);
  log(`  workspace on disk (template):      ${(templateBytes / 1024).toFixed(1)} KiB, ${templateFiles} files`);
  log(`  storage per turn (apparent bytes): p50=${sApparent.p50}B p95=${sApparent.p95}B (== workspace size, every turn)`);
  if (duSamples.length) log(`  storage per turn (du -sk):          p50=${sDisk.p50}B p95=${sDisk.p95}B`);
  out.push({
    kind: "measure",
    files: spec.files,
    metric: "template-bytes",
    templateBytes,
    templateFiles,
  });
  out.push({ kind: "measure", files: spec.files, metric: "storage-per-turn-apparent-bytes", ...sApparent });
  if (duSamples.length) out.push({ kind: "measure", files: spec.files, metric: "storage-per-turn-du-bytes", ...sDisk });

  // ---- cost of a discard, isolated: fs.rm on a sealed copy of this size (commit-protocol.ts's
  // default `release` for mechanism "copy" is exactly this call) --------------------------------
  const rmSamples: number[] = [];
  for (let i = 0; i < spec.reps; i++) {
    const shadow = path.join(root, `rm-${i}`, "merged");
    await fs.mkdir(shadow, { recursive: true });
    await execFileAsync("cp", ["-a", template + "/.", shadow]);
    const t0 = process.hrtime.bigint();
    await fs.rm(path.dirname(shadow), { recursive: true, force: true });
    const t1 = process.hrtime.bigint();
    rmSamples.push(Number(t1 - t0) / 1e6);
  }
  const sRm = summarize(rmSamples);
  log(`  discard teardown (fs.rm the shadow): p50=${sRm.p50}ms p95=${sRm.p95}ms n=${sRm.n}`);
  out.push({ kind: "measure", files: spec.files, metric: "discard-teardown-ms", ...sRm });

  // ---- cost of a discard, end to end, through the real TransactionalRunner: a turn that writes a
  // secret-shaped string, guaranteed to be judged `discard` by the real secret-scan rule -----------
  const e2eSamples: number[] = [];
  for (let i = 0; i < spec.reps; i++) {
    const runRoot = path.join(root, `e2e-${i}`);
    const ws = path.join(runRoot, "ws");
    await fs.mkdir(ws, { recursive: true });
    await execFileAsync("cp", ["-a", template + "/.", ws]);
    const runner = makeRunner(
      scriptRunner(async (w) => {
        await fs.writeFile(path.join(w, "leaked-config.ts"), `export const KEY = "sk-${"a".repeat(20)}";\n`);
      }),
      runRoot,
    );
    const t0 = process.hrtime.bigint();
    const result = await runner.run({ agentId: "bench-agent", workspacePath: ws, prompt: "p", threadId: null });
    const t1 = process.hrtime.bigint();
    if (result.containment?.decision !== "discard") {
      log(`  WARNING expected discard, got ${JSON.stringify(result.containment)}`);
    } else {
      e2eSamples.push(Number(t1 - t0) / 1e6);
    }
    await runner.closeJournal();
    // release() already ran inside run(); confirm the shadow is actually gone (storage reclaimed)
    const shadowRoot = path.join(runRoot, "data", "shadows", result.containment?.runId ?? "");
    const stillThere = await fs.access(shadowRoot).then(() => true).catch(() => false);
    if (stillThere) log(`  WARNING shadow not released after discard: ${shadowRoot}`);
    await rm(runRoot);
  }
  const sE2e = summarize(e2eSamples);
  log(`  discard, end to end (seal+capture+judge+release): p50=${sE2e.p50}ms p95=${sE2e.p95}ms n=${sE2e.n}`);
  out.push({ kind: "measure", files: spec.files, metric: "discard-end-to-end-ms", ...sE2e });

  await rm(root);
}

async function main(): Promise<void> {
  const out: unknown[] = [await hostRow(process.cwd())];
  for (const spec of SIZES) await measureSize(spec, out);
  const file = path.join(resultsDir(), "storage-and-discard.jsonl");
  await writeJsonl(file, out);
  log(`\nwrote ${file}`);
}

await main();

// The repo-size term in `judge`, measured. `RESULTS.md` section 1d names this term, derives its
// existence from the source, and says plainly that its coefficient "at any repo size does not"
// follow and that it is "not measured at all". This script measures it, and separates it into the
// two distinct costs the source actually has, because 1d attributes both to one function and only
// one of them lives there:
//
//   A. the filesystem walk. `snapshotStats` (capture.ts:141) does one `readdir` per directory and
//      one `lstat` per entry over the whole workspace. `transactional-runner.ts:740` runs it at
//      turn open, and `:760` runs it again over the merged shadow with `hash:true`, which adds a
//      full content read of every file under the cap. This is I/O bound and it is the large term.
//   B. the protected-identity loop. `buildPolicyContext` (policy-context.ts:238) iterates the
//      `realInodes` map it is HANDED and runs every protected pattern against each entry. It walks
//      no filesystem of its own. This is CPU bound and it is the small term.
//
// Both are O(files in the workspace) per turn, so both belong in an honest overhead figure, but
// they scale on different resources and a reader who conflates them will predict the wrong number
// for a large repository. Section 1d's sentence "buildPolicyContext walks every real inode of the
// workspace on every turn" is loose about which function does the walking; the split below is the
// correction, with a figure for each half.
//
//   node_modules/.bin/tsx apps/server/src/bench/context-scaling.mts
import path from "node:path";
import fs from "node:fs/promises";
import { snapshotStats, resolveLimits } from "../capture.js";
import { buildPolicyContext } from "../policy-context.js";
import { hostRow, mkScratch, rm, writeJsonl, resultsDir, summarize, log, countFiles } from "./lib.mjs";

/** File counts spanning the orders of magnitude a real checkout covers, matching section 2's sweep
 *  so the two sets of figures can be read against each other on the same axis. */
const SIZES = [100, 500, 2_000, 8_000, 30_000];

/** Repetitions per cell, fewer at the sizes where one repetition is already seconds of real I/O.
 *  Every cell still reports a median over at least 5 samples, so a single scheduling hiccup cannot
 *  become the published number. */
function repsFor(size: number): number {
  if (size <= 500) return 25;
  if (size <= 2_000) return 15;
  if (size <= 8_000) return 8;
  return 5;
}

const LIMITS = resolveLimits();

async function timeIt(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

async function main(): Promise<void> {
  const scratch = await mkScratch("context-scaling");
  const rows: unknown[] = [await hostRow(scratch)];
  log(`scratch ${scratch}`);

  for (const size of SIZES) {
    const reps = repsFor(size);
    const root = path.join(scratch, `ws-${size}`);
    // Fixture construction is setup and is never inside a timed window.
    await buildTree(root, size);
    const actual = await countFiles(root);

    // The shadow side the hashing walk reads. `snapshotStats(merged, {hash:true})` at
    // transactional-runner.ts:760 runs over the merged shadow, which under the copy mechanism is a
    // full copy of the workspace, so a same-sized tree is the honest stand-in.
    const shadowDir = path.join(scratch, `shadow-${size}`);
    const merged = path.join(shadowDir, "merged");
    await buildTree(merged, size);

    const walkPlain: number[] = [];
    const walkHash: number[] = [];
    const contextOnly: number[] = [];

    // One untimed pass, so the first sample does not carry cold-cache cost the other reps do not
    // pay, and so `probeCaseInsensitive`'s per-workspace cache is already warm when the
    // `buildPolicyContext` cell below is timed. That cache is the reason the context figure is a
    // clean measurement of the protected-path loop and not of a stat probe.
    const warm = await snapshotStats(root);
    await buildPolicyContext(contextInput(root, shadowDir, warm.inodes));

    for (let i = 0; i < reps; i++) {
      walkPlain.push(await timeIt(() => snapshotStats(root)));
      walkHash.push(
        await timeIt(() => snapshotStats(merged, { hash: true, maxHashBytes: LIMITS.maxEffectBytes })),
      );
      contextOnly.push(
        await timeIt(() => buildPolicyContext(contextInput(root, shadowDir, warm.inodes))),
      );
    }

    const cell = {
      kind: "context-scaling" as const,
      files: actual,
      requested: size,
      reps,
      walkPlainMs: summarize(walkPlain),
      walkHashMs: summarize(walkHash),
      contextMs: summarize(contextOnly),
    };
    rows.push(cell);
    log(
      `${String(actual).padStart(6)} files  walk ${cell.walkPlainMs.p50.toFixed(1)}ms  ` +
        `walk+hash ${cell.walkHashMs.p50.toFixed(1)}ms  context ${cell.contextMs.p50.toFixed(2)}ms`,
    );

    await rm(root);
    await rm(shadowDir);
  }

  const out = path.join(resultsDir(), "context-scaling.jsonl");
  await writeJsonl(out, rows);
  log(`wrote ${out}`);
  await rm(scratch);
}

/** The context input a real turn hands `buildPolicyContext`, with one deliberate substitution: the
 *  journal path does not exist, so `recentTouchesFor` returns on its first `catch` and contributes
 *  nothing. Its cost is the journal-size term of section 1c and is already measured there; leaving
 *  it in would fold a known term into a cell that exists to isolate the unknown one. */
function contextInput(workspacePath: string, shadowDir: string, realInodes: Map<string, string>) {
  return {
    shadowDir,
    mechanism: "copy" as const,
    workspacePath,
    journalPath: path.join(shadowDir, "no-such-journal.jsonl"),
    agentId: "bench-agent",
    limits: LIMITS,
    platformSecrets: [],
    registryAllowlist: [],
    realInodes,
  };
}

/** The same sharded shape `lib.mts` builds, inlined here only so this script can build two trees of
 *  the same size without the shard count drifting between them. */
async function buildTree(root: string, count: number): Promise<void> {
  const shards = 64;
  const perShard = new Map<number, string[]>();
  for (let i = 0; i < count; i++) {
    const shard = i % shards;
    const list = perShard.get(shard) ?? [];
    list.push(`line ${i} `.padEnd(64, "x") + "\n");
    perShard.set(shard, list);
  }
  await fs.mkdir(root, { recursive: true });
  await Promise.all(
    [...perShard.entries()].map(async ([shard, bodies]) => {
      const dir = path.join(root, `d${shard}`);
      await fs.mkdir(dir, { recursive: true });
      let i = 0;
      for (const body of bodies) {
        await fs.writeFile(path.join(dir, `f${shard}_${i}.txt`), body, "utf8");
        i += 1;
      }
    }),
  );
}

await main();

// Item 1 (brief section 1), the "record" stage: the cost of one journal append, isolated.
//
// `Journal.append()` is called once or more inside every one of the capture/judge/settle stages
// `stage-latency.mts` measures (turn.begin, turn.executed, effects.captured, policy.decision,
// turn.committing, turn.committed all go through it), so its cost is already inside those numbers
// and cannot be cleanly subtracted out from journal timestamps at millisecond resolution alone. This
// isolates it directly: a real `Journal` instance (real HMAC-SHA256 per record, real Ed25519
// checkpoint every 64 records by default, unchanged from production, real Merkle accumulator),
// timed with `process.hrtime.bigint()` for sub-millisecond precision, at two payload sizes: a small
// record (~5 effects, the corpus median) and a record at the `JOURNAL_EFFECT_LIMIT` bound (200
// effects, commit-protocol.ts's cap on what one record may name).
//
//   PATH="$HOME/.nvm/versions/node/v22.21.0/bin:$PATH" \
//     node_modules/.bin/tsx apps/server/src/bench/journal-append.mts
import path from "node:path";
import fs from "node:fs/promises";
import { Journal } from "../journal.js";
import { hostRow, mkScratch, rm, writeJsonl, resultsDir, summarize, scratchHmacKey, readJournal, log } from "./lib.mjs";

const N = 2000;
const CHECKPOINT_EVERY = 64; // production default (journal.ts DEFAULT_CHECKPOINT_EVERY), left unchanged

function effectList(count: number): Array<Record<string, unknown>> {
  return Array.from({ length: count }, (_, i) => ({
    path: `src/module-${i % 40}/file-${i}.ts`,
    kind: i % 5 === 0 ? "delete" : i % 5 === 1 ? "create" : "modify",
    sha256: "a".repeat(64),
    bytes: 128 + i,
    canonicalPath: `src/module-${i % 40}/file-${i}.ts`,
  }));
}

async function runSize(name: string, effectCount: number, out: unknown[]): Promise<void> {
  log(`\n=== journal append, ${name} (${effectCount} effects/record) ===`);
  const root = await mkScratch(`bench-journal-append-${name}-`);
  const dataDirectory = path.join(root, "data");
  const keysDir = path.join(root, "keys");
  const journalPath = path.join(dataDirectory, "journal.jsonl");
  const journal = Journal.acquire({
    journalPath,
    dataDirectory,
    hmacKey: scratchHmacKey(),
    signingKeyFile: path.join(keysDir, "signing.key"),
    publicKeyFile: path.join(keysDir, "journal.pub"),
    checkpointEvery: CHECKPOINT_EVERY,
    env: { SHADOW_ANCHORS: "none" },
  });
  await journal.open();

  const effects = effectList(effectCount);
  const samples: number[] = [];
  for (let i = 1; i <= N; i++) {
    const fields = {
      runId: `run-${i}`,
      agentId: `agent-${i % 8}`,
      kind: i % 3 === 0 ? "turn.committed" : i % 3 === 1 ? "effects.captured" : "policy.decision",
      decision: "commit",
      rule: "none",
      count: effectCount,
      applied: effectCount,
      effects,
      at: new Date().toISOString(),
    };
    const t0 = process.hrtime.bigint();
    await journal.append(fields);
    const t1 = process.hrtime.bigint();
    samples.push(Number(t1 - t0) / 1e6);
  }
  // The distribution above already includes N/64 periodic checkpoints. Every real deployment pays
  // that tax on the same schedule, but with only ~30 such samples in 2000 they barely move p95/p99.
  // Isolate the checkpoint itself directly and explicitly: `checkpoint()` is public exactly so this
  // is possible without reverse-engineering which append landed on one from journal sequence numbers.
  const checkpointSamples: number[] = [];
  for (let c = 0; c < 30; c++) {
    const t0 = process.hrtime.bigint();
    await journal.checkpoint("manual");
    const t1 = process.hrtime.bigint();
    checkpointSamples.push(Number(t1 - t0) / 1e6);
  }
  await journal.close();

  const overall = summarize(samples);
  const checkpointOnly = summarize(checkpointSamples);
  log(`  append(no forced checkpoint)  p50=${overall.p50}ms p95=${overall.p95}ms p99=${overall.p99}ms max=${overall.max}ms n=${overall.n}`);
  log(`  checkpoint() alone            p50=${checkpointOnly.p50}ms p95=${checkpointOnly.p95}ms max=${checkpointOnly.max}ms n=${checkpointOnly.n}`);

  out.push({ kind: "config", name, effectsPerRecord: effectCount, n: N, checkpointEvery: CHECKPOINT_EVERY });
  out.push({ kind: "summary", name, bucket: "append-includes-periodic-checkpoints", ...overall });
  out.push({ kind: "summary", name, bucket: "checkpoint-alone", ...checkpointOnly });

  await rm(root);
}

async function main(): Promise<void> {
  const out: unknown[] = [await hostRow(process.cwd())];
  await runSize("small-record", 5, out);
  await runSize("bounded-record", 200, out);
  const file = path.join(resultsDir(), "journal-append.jsonl");
  await writeJsonl(file, out);
  log(`\nwrote ${file}`);
}

await main();

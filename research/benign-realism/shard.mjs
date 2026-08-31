// shard.mjs -- split a scenario .jsonl into byte-bounded shards.
//
// replay-v2.mjs reads a scenario file with fs.readFileSync into one string, so a 145 MB held-out
// set is a 145 MB string plus every parsed object at once. This host has 8 GB and several jobs on
// it. Sharding changes nothing about what is graded: every shard is replayed against the same
// composed policy and the results are concatenated.
//
//   node research/benign-realism/shard.mjs out/heldout-real.jsonl out/shards 15000000
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";

const [, , inFile, outDir, maxArg] = process.argv;
const MAX = Number(maxArg ?? 15_000_000);
fs.mkdirSync(outDir, { recursive: true });
for (const f of fs.readdirSync(outDir)) if (/^shard-\d+\.jsonl$/.test(f)) fs.unlinkSync(path.join(outDir, f));

let idx = 0, bytes = 0, count = 0, total = 0;
let fd = fs.openSync(path.join(outDir, `shard-${String(idx).padStart(3, "0")}.jsonl`), "w");
const rl = readline.createInterface({ input: fs.createReadStream(inFile) });
for await (const line of rl) {
  if (!line.trim()) continue;
  if (bytes > MAX) {
    fs.closeSync(fd);
    console.log(`shard-${String(idx).padStart(3, "0")}.jsonl  ${count} scenarios  ${(bytes / 1e6).toFixed(1)} MB`);
    idx++; bytes = 0; count = 0;
    fd = fs.openSync(path.join(outDir, `shard-${String(idx).padStart(3, "0")}.jsonl`), "w");
  }
  fs.writeSync(fd, line + "\n");
  bytes += line.length + 1; count++; total++;
}
fs.closeSync(fd);
console.log(`shard-${String(idx).padStart(3, "0")}.jsonl  ${count} scenarios  ${(bytes / 1e6).toFixed(1)} MB`);
console.log(`${total} scenarios across ${idx + 1} shards -> ${outDir}`);

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Resolved from this file's own location, for the same reason as measure-seal-capture.mjs: the
// absolute path that used to be here named one machine, so the command this page prints failed on
// every checkout but its author's.
const R = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "apps", "server", "dist");
const { Journal } = await import(pathToFileURL(path.join(R, "journal.js")).href);

const root = await fs.mkdtemp(path.join(os.tmpdir(), "jr-"));
const jp = path.join(root, "journal.jsonl");
process.env.SHADOW_JOURNAL_KEY = process.env.SHADOW_JOURNAL_KEY || "a".repeat(64);
const j = Journal.acquire({ journalPath: jp, dataDirectory: root });
await j.open?.();

const sizeNow = async () => (await fs.stat(jp).catch(() => ({ size: 0 }))).size;
const before = await sizeNow();
const TURNS = 200;
const t0 = Number(process.hrtime.bigint() / 1000n) / 1000;
for (let i = 0; i < TURNS; i += 1) {
  // the record shape a real turn emits: held, committing, committed
  await j.append({ runId: "r" + i, agentId: "a1", kind: "turn.committing", at: new Date(0).toISOString() });
  await j.append({ runId: "r" + i, agentId: "a1", kind: "turn.committed", applied: 3, at: new Date(0).toISOString() });
}
const ms = Number(process.hrtime.bigint() / 1000n) / 1000 - t0;
// settle BEFORE the size is read. This used to be the other way round, and the stat then raced the
// last anchor.ok record: the file was measured one 465-byte record short, so the script printed 784
// bytes/turn on a fast filesystem and 786 on a slow one, and the page read that gap as path length.
// It was the race. Settled, the size is 786 on both. Measured here: 411 lines and 156,731 bytes
// before settle(), 412 lines and 157,196 bytes after.
await j.settle?.().catch(() => {});
const after = await sizeNow();
console.log("JOURNAL GROWTH AND APPEND COST");
console.log("turns:", TURNS, " records:", TURNS * 2);
console.log("bytes total:", after - before, " bytes/turn:", Math.round((after - before) / TURNS));
console.log("append ms total:", ms.toFixed(1), " ms/turn:", (ms / TURNS).toFixed(3));
console.log("");
console.log("projection at this rate:");
for (const n of [1000, 10000, 100000]) {
  const mb = ((after - before) / TURNS) * n / (1024 * 1024);
  console.log("  " + String(n).padStart(7) + " turns -> " + mb.toFixed(1) + " MiB");
}
await fs.rm(root, { recursive: true, force: true });

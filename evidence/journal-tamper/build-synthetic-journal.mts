/**
 * Build a SYNTHETIC journal in a temp directory, using the shipped `Journal` class.
 *
 * `scripts/demo-tamper.mjs` writes to a real audit ledger, so it must not be proved out by being
 * pointed at one. This makes a genuine ledger instead: real records, a real HMAC under a real key,
 * real Ed25519 checkpoint signatures over real Merkle roots, all produced by the same class the
 * platform uses, in a directory that belongs to nobody. Nothing is faked, and nothing an operator
 * owns is touched.
 *
 *   npx tsx evidence/journal-tamper/build-synthetic-journal.mts /tmp/somewhere
 *
 * The key home is a sibling of the data directory rather than inside it, because `journal-keys.ts`
 * refuses a key home inside the data directory, and the checkpoint interval is 6 rather than the
 * shipped 64 so that a seven-record journal actually reaches two checkpoints. Without them the
 * tamper would land on the hash and the HMAC and there would be no Merkle layer to break.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const { Journal } = await import(path.join(REPO, "apps", "server", "src", "journal.ts"));

const root = process.argv[2];
if (!root) {
  process.stderr.write("usage: tsx evidence/journal-tamper/build-synthetic-journal.mts <directory>\n");
  process.exit(2);
}
const data = path.join(root, "data");
const home = path.join(root, "home");
await fs.mkdir(data, { recursive: true });
await fs.mkdir(home, { recursive: true });

const journal = Journal.acquire({
  journalPath: path.join(data, "journal.jsonl"),
  dataDirectory: data,
  home,
  checkpointEvery: 6,
  anchors: [],
  env: { ...process.env, SHADOW_COMMIT_HOME: home, VITEST: "", NODE_ENV: "" },
});

// One contained turn, in the shape the platform really writes: seal, begin, execute, capture,
// decide, discard, release. The `policy.decision` record is the one the tamper script picks, because
// `verdict` is the field whose meaning a reader can see changing.
const runId = "9f2c1a44-0b7e-4d10-8e31-77a5c0de41bb";
const agent = "agent:demo";
await journal.append({ kind: "seal.fallback", runId, mechanism: "copy", reason: "not-linux" }, agent);
await journal.append({ kind: "turn.begin", runId, agentId: "e498e8b9" }, agent);
await journal.append({ kind: "turn.executed", runId, commands: ["node ./tools/prepare.js"] }, agent);
await journal.append({ kind: "effects.captured", runId, effectCount: 2 }, agent);
await journal.append({ kind: "policy.decision", runId, verdict: "discarded", rule: "protected-identity" }, agent);
await journal.append({ kind: "turn.discarded", runId, egress: { deny: 3, live: 0 } }, agent);
await journal.append({ kind: "seal.release", runId, removed: true }, agent);
await journal.close();

process.stdout.write("built " + path.join(data, "journal.jsonl") + "\n");

/**
 * The third-party audit case: what an auditor who is NOT the operator can actually verify.
 *
 * The operator's host holds the hmac key and the signing key. An auditor holds neither. Every other
 * input the verifier consults (journal.jsonl, journal.pub, anchors.jsonl) lives inside the data
 * directory being audited, so it is supplied by whoever is being audited. This script forges a
 * complete, self-consistent data directory with an attacker-generated signing key and asks the
 * shipped verifier and the shipped CLI what they think of it.
 *
 *   npx tsx research/journal/forge-full.mts
 *
 * THE CLI COLUMN MOVED, AND THIS HARNESS IS WHY. apps/server/src/verify-journal.ts cites row 3
 * below as the measurement behind "exit 0 on a forgery". It is the CLI in that same file that this
 * harness runs, so the fix changed the answer, and a reader who follows the citation now sees exit
 * 2 rather than the exit 0 the sentence describes. Every row therefore prints what the command
 * answered before the fix beside what it answers now, from CLI_BEFORE_THE_FIX below. The report.ok,
 * keyed, problems and warnings lines are the verification result and did not move: the fix changed
 * what the command SAYS about a check it could not run, not what it checked.
 */
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { GitAnchor } from "../../apps/server/src/anchors.js";
import { Journal } from "../../apps/server/src/journal.js";
import { verifyJournalAt } from "../../apps/server/src/journal-verify.js";
import { canonicalJson, checkpointBody, hmacHex, sha256Hex, ZERO_HEAD } from "../../apps/server/src/journal-format.js";
import { MerkleAccumulator, leafHash } from "../../apps/server/src/merkle.js";
import { main as cli } from "../../apps/server/src/verify-journal.js";

type Rec = Record<string, unknown>;
const SCRATCH = path.join(os.tmpdir(), "shadow-forge-full");

function cleanEnv(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, SHADOW_COMMIT_HOME: home };
  delete env.SHADOW_JOURNAL_KEY;
  delete env.SHADOW_JOURNAL_KEY_FILE;
  delete env.SHADOW_JOURNAL_PUBKEY_FILE;
  delete env.VITEST;
  return env;
}

/**
 * Rebuild a whole journal file from a list of record bodies, exactly as journal.ts would, including
 * a signed Merkle checkpoint every `checkpointEvery` records. `hmacKey` null means the forger could
 * not read the operator's hmac key and simply omits the field.
 */
function forgeJournal(bodies: Rec[], opts: { hmacKey: string | null; signingKey: crypto.KeyObject; checkpointEvery: number }): {
  lines: string[];
  lastCheckpoint: { seq: number; head: string; treeSize: number } | null;
} {
  const lines: string[] = [];
  const tree = new MerkleAccumulator();
  let prev = ZERO_HEAD;
  let seq = 0;
  let sinceCheckpoint = 0;
  let lastCheckpoint: { seq: number; head: string; treeSize: number } | null = null;

  const emit = (fields: Rec): string => {
    const base: Rec = { ...fields, seq: ++seq, prev };
    if (opts.hmacKey) base.hmac = hmacHex(Buffer.from(opts.hmacKey, "utf8"), canonicalJson(base));
    const hash = sha256Hex(canonicalJson(base));
    const line = JSON.stringify({ ...base, hash });
    lines.push(line);
    tree.push(leafHash(line));
    prev = hash;
    return hash;
  };

  for (const body of bodies) {
    emit(body);
    if (++sinceCheckpoint < opts.checkpointEvery) continue;
    sinceCheckpoint = 0;
    const treeSize = tree.size;
    const merkleRoot = tree.root().toString("hex");
    // the signature covers exactly checkpointBody(), which is what the verifier re-derives
    const draft: Rec = { kind: "journal.checkpoint", merkleRoot, prev, seq: seq + 1, treeSize, ts: "2026-08-30T00:00:00.000Z", principal: "journal" };
    const signature = crypto.sign(null, Buffer.from(checkpointBody(draft), "utf8"), opts.signingKey).toString("base64");
    const head = emit({ kind: "journal.checkpoint", merkleRoot, treeSize, signature, ts: draft.ts, principal: "journal" });
    lastCheckpoint = { seq, head, treeSize };
  }
  return { lines, lastCheckpoint };
}

/**
 * What each row's CLI line said before apps/server/src/verify-journal.ts learned to separate "this
 * check passed" from "this check did not run". Recorded rather than recomputed, because recomputing
 * means running the old file. To reproduce it, restore that one file and run this script again:
 *
 *   git show submission/main:apps/server/src/verify-journal.ts > apps/server/src/verify-journal.ts
 *   npx tsx research/journal/forge-full.mts
 *   git checkout apps/server/src/verify-journal.ts
 *
 * Row 3 is the finding: a data directory forged end to end by somebody who had never seen either of
 * the operator's keys, handed to a reader who holds neither, answered exit 0 and "the ledger
 * verifies from record one".
 */
const CLI_BEFORE_THE_FIX: Record<string, string> = {
  "baseline: the genuine journal, audited with NO key":
    "exit=0 |  keyed        NO, see problems below| |  result       OK, the ledger verifies from record one|",
  "baseline: the genuine journal, audited WITH the key":
    "exit=0 |  keyed        yes, hmac verified on every record| |  result       OK, the ledger verifies from record one|",
  "FORGED data directory, audited with NO key (the auditor's case)":
    "exit=0 |  keyed        NO, see problems below| |  result       OK, the ledger verifies from record one|",
  "FORGED data directory, audited WITH the operator's key":
    "exit=1 |  keyed        NO, see problems below| |  result       BROKEN|",
  "FORGED with the operator's hmac key read off the same host":
    "exit=0 |  keyed        yes, hmac verified on every record| |  result       OK, the ledger verifies from record one|",
};

async function report(label: string, journalPath: string, dir: string, home: string): Promise<void> {
  const r = await verifyJournalAt(journalPath, { dataDirectory: dir, home, env: cleanEnv(home) });
  // the CLI resolves its key home from process.env and takes no override, so the only honest way
  // to exercise it is to be the process it expects to be
  const out: string[] = [];
  const previous = process.env.SHADOW_COMMIT_HOME;
  process.env.SHADOW_COMMIT_HOME = home;
  let code: number;
  try {
    code = await cli(["--journal", journalPath, "--data-dir", dir, "-n", "0"], (t) => out.push(t));
  } finally {
    if (previous === undefined) delete process.env.SHADOW_COMMIT_HOME;
    else process.env.SHADOW_COMMIT_HOME = previous;
  }
  const resultLine = out.join("\n").split("\n").find((l) => l.trim().startsWith("result")) ?? "(no result line)";
  const keyedLine = out.join("\n").split("\n").find((l) => l.trim().startsWith("keyed")) ?? "";
  console.log(`${r.ok ? "MISSED " : "CAUGHT "} ${label}`);
  console.log(`         report.ok=${r.ok} keyed=${r.keyed} problems=${r.problems.length} first=${r.firstBreak ? r.firstBreak.kind + ": " + r.firstBreak.message : "(none)"}`);
  console.log(`         warnings=${JSON.stringify(r.warnings)}`);
  const now = `exit=${code} |${keyedLine}| |${resultLine.trimEnd()}|`;
  const before = CLI_BEFORE_THE_FIX[label] ?? "(not recorded)";
  console.log(`         CLI now    ${now}`);
  console.log(`         CLI before ${before}`);
  if (before !== "(not recorded)" && before !== now) {
    console.log("                    the two differ because of apps/server/src/verify-journal.ts, which this harness runs");
  }
  console.log("");
}

async function main(): Promise<void> {
  await fs.rm(SCRATCH, { recursive: true, force: true });
  await fs.mkdir(SCRATCH, { recursive: true });
  const operatorHome = path.join(SCRATCH, "operator-home");
  const auditorHome = path.join(SCRATCH, "auditor-home-with-no-keys");

  // A genuine run, so the forgery is measured against something real -------------------------
  const real = await fs.mkdtemp(path.join(SCRATCH, "real-"));
  const realJournal = path.join(real, "journal.jsonl");
  const journal = new Journal({
    journalPath: realJournal,
    home: operatorHome,
    checkpointEvery: 4,
    anchors: [new GitAnchor({ dataDirectory: real, gitNotes: false })],
    env: cleanEnv(operatorHome),
  });
  await journal.open();
  for (let i = 0; i < 8; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
  await journal.close();
  await report("baseline: the genuine journal, audited with NO key", realJournal, real, auditorHome);
  await report("baseline: the genuine journal, audited WITH the key", realJournal, real, operatorHome);

  // The forgery ------------------------------------------------------------------------------
  // A complete data directory built by somebody who never saw either of the operator's keys:
  // their own signing key, their own journal.pub, their own anchors.jsonl, their own records.
  const fake = await fs.mkdtemp(path.join(SCRATCH, "forged-"));
  const attacker = crypto.generateKeyPairSync("ed25519");
  const bodies: Rec[] = [];
  for (let i = 0; i < 8; i++) {
    bodies.push({ kind: "turn.begin", runId: `r${i}`, agentId: "a1", ts: "2026-08-30T00:00:00.000Z", principal: "agent" });
  }
  // the record the operator would rather nobody read: a turn that was discarded, rewritten as one
  // that committed cleanly
  bodies[5] = { kind: "policy.decision", runId: "r5", decision: "commit", rule: "none", ts: "2026-08-30T00:00:00.000Z", principal: "policy" };
  const forged = forgeJournal(bodies, { hmacKey: null, signingKey: attacker.privateKey, checkpointEvery: 4 });
  await fs.writeFile(path.join(fake, "journal.jsonl"), forged.lines.join("\n") + "\n", "utf8");
  await fs.writeFile(
    path.join(fake, "journal.pub"),
    crypto.createPublicKey(attacker.privateKey).export({ format: "pem", type: "spki" }).toString(),
    "utf8",
  );
  if (forged.lastCheckpoint) {
    await fs.writeFile(
      path.join(fake, "anchors.jsonl"),
      JSON.stringify({ ...forged.lastCheckpoint, merkleRoot: "", signature: "", body: "", publicKey: "", ts: "2026-08-30T00:00:00.000Z" }) + "\n",
      "utf8",
    );
  }
  await report("FORGED data directory, audited with NO key (the auditor's case)", path.join(fake, "journal.jsonl"), fake, auditorHome);
  await report("FORGED data directory, audited WITH the operator's key", path.join(fake, "journal.jsonl"), fake, operatorHome);

  // and the same forgery when the forger DID read the operator's hmac key
  const withKey = await fs.mkdtemp(path.join(SCRATCH, "forged-keyed-"));
  const operatorKey = (await fs.readFile(path.join(operatorHome, "journal.key"), "utf8")).trim();
  const forged2 = forgeJournal(bodies, { hmacKey: operatorKey, signingKey: attacker.privateKey, checkpointEvery: 4 });
  await fs.writeFile(path.join(withKey, "journal.jsonl"), forged2.lines.join("\n") + "\n", "utf8");
  await fs.writeFile(
    path.join(withKey, "journal.pub"),
    crypto.createPublicKey(attacker.privateKey).export({ format: "pem", type: "spki" }).toString(),
    "utf8",
  );
  if (forged2.lastCheckpoint) {
    await fs.writeFile(
      path.join(withKey, "anchors.jsonl"),
      JSON.stringify({ ...forged2.lastCheckpoint, merkleRoot: "", signature: "", body: "", publicKey: "", ts: "2026-08-30T00:00:00.000Z" }) + "\n",
      "utf8",
    );
  }
  await report("FORGED with the operator's hmac key read off the same host", path.join(withKey, "journal.jsonl"), withKey, operatorHome);
}

await main();

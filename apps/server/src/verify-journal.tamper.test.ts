import { afterEach, describe, expect, it } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { GitAnchor } from "./anchors.js";
import { Journal } from "./journal.js";
import { verifyJournalAt } from "./journal-verify.js";
import { canonicalJson, checkpointBody, hmacHex, sha256Hex, ZERO_HEAD } from "./journal-format.js";
import { MerkleAccumulator, leafHash } from "./merkle.js";
import { main as cli } from "./verify-journal.js";

/**
 * Tamper evidence, proven by tampering.
 *
 * Every test here performs a real edit on a real journal written by the real `Journal` class, then
 * asks the shipped verifier what it thinks. Nothing is mocked, because the thing under test IS the
 * arithmetic: a double that returns "chain broken" would assert only that this file can call a
 * function.
 *
 * Four of these tests assert that a tampering operation is NOT detected. They are not inverted
 * tests written to go green; they are the measurement, and each one names the property that would
 * have to change for the answer to be different. A tamper-evident log that is only claimed to be
 * tamper evident is worth less than one whose exact detection boundary is written down, because the
 * boundary is what an auditor needs in order to know what a clean report is worth.
 *
 * The boundary, measured below and reproduced by research/journal/attack-sweep.mts:
 *
 *   caught   edit in place, delete from the middle, reorder, insert, substitute the journal file
 *            while its anchor log survives, append without the hmac key
 *   missed   truncate the tail back to the last anchored checkpoint, substitute the whole data
 *            directory, append WITH the hmac key, rewrite the file end to end when the reader
 *            holds no key
 */

/**
 * Not a secret and not a credential. A journal key is 32 bytes of local entropy; this is a fixed
 * string of the right length so a test can be both the operator (who holds it) and an auditor (who
 * does not) in the same file.
 */
const TEST_HMAC_KEY = "journal-test-key-not-a-real-secret-".repeat(2);

interface Bed {
  dir: string;
  journalPath: string;
  home: string;
  /**
   * Carried out of seed() so a test that asked for `close: false` can wait for the writer.
   *
   * A bed built with close:false leaves anchor submissions in flight through Journal.anchorWork, so
   * reading the file straight after seeding can catch it one or two anchor.ok records short of what
   * the verifier will later see. The method is `settle()`, not `drain()`: it waits for every queued
   * append and every in-flight anchor submission, and unlike close() it writes no shutdown
   * checkpoint, so it leaves the wide unanchored tail the truncation test exists to measure.
   */
  journal: Journal;
}

const beds: string[] = [];

async function seed(
  opts: { records?: number; checkpointEvery?: number; close?: boolean; home?: string } = {},
): Promise<Bed> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "tamper-"));
  beds.push(dir);
  // one home per bed by default, which models two different deployments; pass `home` to model two
  // runs of the SAME deployment, where the signing key is shared and only the anchor separates them
  const home = opts.home ?? path.join(dir, "keys-outside-the-data-directory");
  const journalPath = path.join(dir, "data", "journal.jsonl");
  const journal = new Journal({
    journalPath,
    dataDirectory: path.join(dir, "data"),
    home,
    hmacKey: TEST_HMAC_KEY,
    checkpointEvery: opts.checkpointEvery ?? 4,
    anchors: [new GitAnchor({ dataDirectory: path.join(dir, "data"), gitNotes: false })],
  });
  await journal.open();
  for (let i = 0; i < (opts.records ?? 10); i++) {
    await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
  }
  if (opts.close !== false) await journal.close();
  return { dir, journalPath, home, journal };
}

const dataDir = (bed: Bed): string => path.dirname(bed.journalPath);

async function readLines(bed: Bed): Promise<string[]> {
  return (await fs.readFile(bed.journalPath, "utf8")).split("\n").filter((line) => line.trim() !== "");
}

async function writeLines(bed: Bed, lines: readonly string[]): Promise<void> {
  await fs.writeFile(bed.journalPath, lines.join("\n") + "\n", "utf8");
}

/** the operator's own view: the key is on this host */
const asOperator = (bed: Bed) => verifyJournalAt(bed.journalPath, { dataDirectory: dataDir(bed), hmacKey: TEST_HMAC_KEY });

/** an auditor's view: the records and the public key, and nothing else */
const asAuditor = (bed: Bed) =>
  verifyJournalAt(bed.journalPath, {
    dataDirectory: dataDir(bed),
    home: path.join(bed.dir, "an-auditor-holds-no-keys"),
    env: {},
  });

/**
 * Rebuild a whole journal file the way journal.ts writes one: canonical bytes, hmac over the record
 * without hash and without hmac, hash over the record without hash, a signed Merkle checkpoint every
 * `checkpointEvery` records. This is the forger, and it is deliberately a reimplementation from
 * journal-format.ts rather than a call into journal.ts, because a forgery that borrowed the writer's
 * own append path would only prove the writer is self-consistent.
 */
function forgeJournal(
  bodies: ReadonlyArray<Record<string, unknown>>,
  opts: { hmacKey: string | null; signingKey: crypto.KeyObject; checkpointEvery: number },
): { lines: string[]; lastCheckpoint: { seq: number; head: string; treeSize: number } | null } {
  const lines: string[] = [];
  const tree = new MerkleAccumulator();
  let prev = ZERO_HEAD;
  let seq = 0;
  let since = 0;
  let lastCheckpoint: { seq: number; head: string; treeSize: number } | null = null;

  const emit = (fields: Record<string, unknown>): string => {
    const base: Record<string, unknown> = { ...fields, seq: ++seq, prev };
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
    if (++since < opts.checkpointEvery) continue;
    since = 0;
    const treeSize = tree.size;
    const merkleRoot = tree.root().toString("hex");
    const ts = "2026-08-30T00:00:00.000Z";
    const signature = crypto
      .sign(
        null,
        Buffer.from(checkpointBody({ kind: "journal.checkpoint", merkleRoot, prev, seq: seq + 1, treeSize }), "utf8"),
        opts.signingKey,
      )
      .toString("base64");
    const head = emit({ kind: "journal.checkpoint", merkleRoot, treeSize, signature, ts, principal: "journal" });
    lastCheckpoint = { seq, head, treeSize };
  }
  return { lines, lastCheckpoint };
}

/** append records to an existing file WITHOUT touching a byte of the prefix */
function appendForged(
  existing: readonly string[],
  extra: ReadonlyArray<Record<string, unknown>>,
  hmacKey: string | null,
): string[] {
  const last = JSON.parse(existing[existing.length - 1]!) as Record<string, unknown>;
  let prev = String(last.hash);
  let seq = Number(last.seq);
  const tail: string[] = [];
  for (const body of extra) {
    const base: Record<string, unknown> = { ts: last.ts, principal: "agent", ...body, seq: ++seq, prev };
    if (hmacKey) base.hmac = hmacHex(Buffer.from(hmacKey, "utf8"), canonicalJson(base));
    const hash = sha256Hex(canonicalJson(base));
    tail.push(JSON.stringify({ ...base, hash }));
    prev = hash;
  }
  return [...existing, ...tail];
}

/** run the CLI the way an operator runs it, with the key home this test decides */
async function runCli(argv: readonly string[], env: Record<string, string | undefined>): Promise<{ code: number; text: string }> {
  const saved = new Map<string, string | undefined>();
  for (const [name, value] of Object.entries(env)) {
    saved.set(name, process.env[name]);
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  const out: string[] = [];
  try {
    const code = await cli([...argv], (line) => out.push(line));
    return { code, text: out.join("\n") };
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

afterEach(async () => {
  await Promise.all(beds.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe("tampering the journal is detected", () => {
  it("catches a same-length in-place edit, at every record that carries one", async () => {
    // The sweep is the test. Demonstrating the edit at one index would leave open whether the check
    // covers the first record, the last one, or only the ones a checkpoint happens to sit near.
    const bed = await seed();
    const original = await readLines(bed);
    const editable = original
      .map((line, index) => ({ line, index }))
      .filter(({ line }) => line.includes('"runId":"r'));
    expect(editable.length).toBeGreaterThan(5);

    for (const { line, index } of editable) {
      const mutated = [...original];
      // same byte length, one character different: r3 becomes rX
      mutated[index] = line.replace(/"runId":"r(\d)"/, '"runId":"rX"');
      expect(mutated[index], `record ${index} did not change length-neutrally`).toHaveLength(line.length);
      await writeLines(bed, mutated);
      const report = await asOperator(bed);
      expect(report.ok, `an edit at record ${index + 1} passed verification`).toBe(false);
      expect(report.firstBreak?.kind).toBe("hash");
      expect(report.firstBreak?.record).toBe(index + 1);
    }
  });

  it("catches a record deleted from the middle, at every interior position", async () => {
    const bed = await seed();
    const original = await readLines(bed);
    for (let index = 0; index < original.length - 1; index++) {
      const mutated = original.filter((_, i) => i !== index);
      await writeLines(bed, mutated);
      const report = await asOperator(bed);
      expect(report.ok, `deleting record ${index + 1} passed verification`).toBe(false);
      // the sequence number is what gives it away, and the chain link right behind it
      expect(["seq", "link"]).toContain(report.firstBreak?.kind);
    }
  });

  it("catches two records reordered, at every adjacent pair", async () => {
    const bed = await seed();
    const original = await readLines(bed);
    for (let index = 0; index < original.length - 1; index++) {
      const mutated = [...original];
      [mutated[index], mutated[index + 1]] = [mutated[index + 1]!, mutated[index]!];
      await writeLines(bed, mutated);
      const report = await asOperator(bed);
      expect(report.ok, `swapping records ${index + 1} and ${index + 2} passed verification`).toBe(false);
      expect(["seq", "link"]).toContain(report.firstBreak?.kind);
    }
  });

  it("catches a record inserted anywhere in the file", async () => {
    const bed = await seed();
    const original = await readLines(bed);
    for (let index = 0; index < original.length; index++) {
      const mutated = [...original];
      mutated.splice(index, 0, original[Math.max(0, index - 1)]!);
      await writeLines(bed, mutated);
      const report = await asOperator(bed);
      expect(report.ok, `inserting a record at position ${index + 1} passed verification`).toBe(false);
      expect(["seq", "link", "hash"]).toContain(report.firstBreak?.kind);
    }
  });

  it("catches a journal file swapped for another run's while its anchor log survives", async () => {
    // Same deployment, so the same hmac key and the same signing key cover both runs and neither
    // the keyed layer nor the signature layer notices anything. The anchor log is the whole of what
    // separates one run of this platform from another run of it.
    const shared = await fs.mkdtemp(path.join(os.tmpdir(), "tamper-shared-home-"));
    beds.push(shared);
    const victim = await seed({ home: shared });
    const donor = await seed({ home: shared });
    await fs.copyFile(donor.journalPath, victim.journalPath);

    const report = await asOperator(victim);
    expect(report.ok).toBe(false);
    expect(report.firstBreak?.kind, "only the anchor log can tell these two runs apart").toBe("anchor");
    expect(report.anchors.present).toBe(false);
    expect(report.problems.filter((problem) => problem.kind !== "anchor")).toEqual([]);
  });

  it("catches a forged suffix appended by somebody who could not read the hmac key", async () => {
    // The prefix is kept BYTE FOR BYTE. Re-serialising it would change the Merkle leaves and the
    // verifier would report a checkpoint break, which is a catch this attack did not earn.
    const bed = await seed({ close: false });
    // the bed was seeded with close:false, so anchor submissions may still be in flight;
    // settle() waits for them without writing the shutdown checkpoint close() would write
    await bed.journal.settle();
    const original = await readLines(bed);
    const forged = appendForged(original, [{ kind: "turn.begin", runId: "planted", agentId: "a1" }], null);
    expect(forged.slice(0, original.length)).toEqual(original);
    await writeLines(bed, forged);

    const report = await asOperator(bed);
    expect(report.ok).toBe(false);
    expect(report.firstBreak?.kind).toBe("hmac");
    expect(report.firstBreak?.message).toContain("carries no hmac");
  });

  it("catches a file rewritten end to end when the reader holds the key the writer did not", async () => {
    // Everything recomputed: content, prev, hash, and a signed checkpoint under the forger's own
    // Ed25519 key, published as the forger's own journal.pub. The one thing they never had is the
    // hmac key, and that is the whole of what stops them.
    const bed = await seed();
    const attacker = crypto.generateKeyPairSync("ed25519");
    const bodies = Array.from({ length: 8 }, (_, i) => ({
      kind: "turn.begin",
      runId: `r${i}`,
      agentId: "a1",
      ts: "2026-08-30T00:00:00.000Z",
      principal: "agent",
    }));
    const forged = forgeJournal(bodies, { hmacKey: null, signingKey: attacker.privateKey, checkpointEvery: 4 });
    await writeLines(bed, forged.lines);
    await fs.writeFile(
      path.join(dataDir(bed), "journal.pub"),
      crypto.createPublicKey(attacker.privateKey).export({ format: "pem", type: "spki" }).toString(),
      "utf8",
    );
    await fs.rm(path.join(dataDir(bed), "anchors.jsonl"), { force: true });

    const report = await asOperator(bed);
    expect(report.ok).toBe(false);
    expect(report.firstBreak?.kind).toBe("hmac");
  });
});

describe("tampering the journal is NOT detected", () => {
  it("misses a tail truncated back to the last anchored checkpoint, and catches nothing less", async () => {
    // THE ONE THE BRIEF SAID WOULD BE WRONG, AND IT IS. An anchor pins the chain at its own point
    // and says nothing about what came after, so every record written since the last anchor can be
    // removed with no evidence at all. The sweep is what makes this a boundary rather than an
    // anecdote: k below the window is invisible, k above it is caught, and the crossing point is
    // exactly the anchor.
    const bed = await seed({ records: 80, checkpointEvery: 64, close: false });
    // the bed was seeded with close:false, so anchor submissions may still be in flight;
    // settle() waits for them without writing the shutdown checkpoint close() would write
    await bed.journal.settle();
    const original = await readLines(bed);
    const clean = await asOperator(bed);
    const anchorSeq = clean.anchors.last?.seq ?? null;
    expect(clean.ok).toBe(true);
    expect(anchorSeq).not.toBeNull();

    const window = original.length - anchorSeq!;
    expect(window, "the shipped default leaves a wide unanchored tail").toBeGreaterThan(10);

    const missed: number[] = [];
    const caught: number[] = [];
    for (let k = 1; k < original.length; k++) {
      await writeLines(bed, original.slice(0, original.length - k));
      const report = await asOperator(bed);
      (report.ok ? missed : caught).push(k);
    }
    // every truncation inside the window is invisible, and the first one outside it is not
    expect(missed).toEqual(Array.from({ length: window }, (_, i) => i + 1));
    expect(caught[0]).toBe(window + 1);

    // the fix this lane can make is to SAY so: the report now names the size of the window
    await writeLines(bed, original);
    const printed = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], {
      SHADOW_JOURNAL_KEY: TEST_HMAC_KEY,
      SHADOW_COMMIT_HOME: bed.home,
    });
    expect(printed.text).toContain(`${window} record(s) were written after that anchor`);
    expect(printed.text).toContain("cutting the file back to the anchored checkpoint verifies clean");
  });

  it("misses a whole data directory swapped for another run's on the same host", async () => {
    // deliberately the same key home, because that is what "the same host" means
    // The anchor log and the public key live inside the directory being audited, so taking the
    // whole directory takes the witnesses with it. Same host means the same hmac key verifies both
    // runs, and nothing in a record names the deployment it belongs to. A run that discarded a turn
    // can be replaced wholesale by a run that did not.
    const shared = await fs.mkdtemp(path.join(os.tmpdir(), "tamper-shared-home-"));
    beds.push(shared);
    const victim = await seed({ home: shared });
    const donor = await seed({ home: shared });
    for (const name of ["journal.jsonl", "anchors.jsonl", "journal.pub"]) {
      await fs.copyFile(path.join(dataDir(donor), name), path.join(dataDir(victim), name)).catch(() => undefined);
    }
    const report = await asOperator(victim);
    expect(report.ok, "substituting the whole data directory is currently undetectable").toBe(true);
    expect(report.problems).toEqual([]);

    // and the property that would have to hold for it to be detectable: an anchor kept somewhere the
    // substitution cannot reach. With the victim's own anchor log restored, the same swap is caught.
    const restored = await seed({ home: shared });
    await fs.copyFile(path.join(dataDir(donor), "journal.jsonl"), restored.journalPath);
    expect((await asOperator(restored)).ok).toBe(false);
  });

  it("misses a forged suffix appended by somebody who CAN read the hmac key", async () => {
    // The key lives outside the data directory, which defeats a writer confined to the workspace.
    // It does not defeat the uid that runs the server, and that uid is the one that can write the
    // journal. Against that attacker the keyed layer buys nothing on an append.
    const bed = await seed({ close: false });
    // the bed was seeded with close:false, so anchor submissions may still be in flight;
    // settle() waits for them without writing the shutdown checkpoint close() would write
    await bed.journal.settle();
    const original = await readLines(bed);
    const forged = appendForged(
      original,
      [{ kind: "policy.decision", runId: "planted", decision: "commit", rule: "none", principal: "policy" }],
      TEST_HMAC_KEY,
    );
    await writeLines(bed, forged);

    const report = await asOperator(bed);
    expect(report.ok, "a keyed append is indistinguishable from a genuine one").toBe(true);
    expect(report.records).toBe(original.length + 1);
  });

  it("misses a file forged end to end, for every reader who does not hold the operator's key", async () => {
    // THE ONE THAT MATTERS FOR A JUDGE. The reader who is asked to check this ledger is not the
    // operator, so they have no hmac key; the public key they would check signatures against ships
    // inside the directory they are auditing. Both of the layers that make the chain mean anything
    // are supplied by the party under audit, and the chain itself is arithmetic anybody can redo.
    const bed = await seed();
    const attacker = crypto.generateKeyPairSync("ed25519");
    const bodies = Array.from({ length: 8 }, (_, i) => ({
      kind: "turn.begin",
      runId: `r${i}`,
      agentId: "a1",
      ts: "2026-08-30T00:00:00.000Z",
      principal: "agent",
    }));
    // the record an operator would rather nobody read, rewritten into one that committed cleanly
    bodies[5] = {
      kind: "policy.decision",
      runId: "r5",
      decision: "commit",
      rule: "none",
      ts: "2026-08-30T00:00:00.000Z",
      principal: "policy",
    } as (typeof bodies)[number];
    const forged = forgeJournal(bodies, { hmacKey: null, signingKey: attacker.privateKey, checkpointEvery: 4 });
    await writeLines(bed, forged.lines);
    await fs.writeFile(
      path.join(dataDir(bed), "journal.pub"),
      crypto.createPublicKey(attacker.privateKey).export({ format: "pem", type: "spki" }).toString(),
      "utf8",
    );
    if (forged.lastCheckpoint) {
      await fs.writeFile(
        path.join(dataDir(bed), "anchors.jsonl"),
        JSON.stringify({ ...forged.lastCheckpoint, merkleRoot: "", signature: "", body: "", publicKey: "", ts: "2026-08-30T00:00:00.000Z" }) + "\n",
        "utf8",
      );
    }

    const report = await asAuditor(bed);
    expect(report.ok, "a forgery is internally consistent by construction").toBe(true);
    expect(report.problems).toEqual([]);
    expect(report.keyed).toBe(false);
    // every checkpoint signature verifies, against the key the forger supplied
    expect(report.checkpoints.length).toBeGreaterThan(0);
    expect(report.checkpoints.every((checkpoint) => checkpoint.signature === "ok")).toBe(true);
  });
});

describe("the verifier reports a check it could not run as a check it could not run", () => {
  it("does not print OK or exit 0 for a forgery it was unable to check", async () => {
    // The defect, stated as the attacker would: fabricate a journal, hand it to somebody who does
    // not hold the operator's key, and the one documented command answers
    // "result OK, the ledger verifies from record one" and exits 0.
    //
    // REVERT PROOF. Revert apps/server/src/verify-journal.ts alone and this test fails on the exit
    // code being 0 and on the text containing "OK, the ledger verifies from record one", which is
    // the defect and not a missing import: everything it needs from the file, main(), is exported
    // by both versions.
    const bed = await seed();
    const attacker = crypto.generateKeyPairSync("ed25519");
    const bodies = Array.from({ length: 8 }, (_, i) => ({
      kind: "turn.begin",
      runId: `r${i}`,
      agentId: "a1",
      ts: "2026-08-30T00:00:00.000Z",
      principal: "agent",
    }));
    const forged = forgeJournal(bodies, { hmacKey: null, signingKey: attacker.privateKey, checkpointEvery: 4 });
    await writeLines(bed, forged.lines);
    await fs.writeFile(
      path.join(dataDir(bed), "journal.pub"),
      crypto.createPublicKey(attacker.privateKey).export({ format: "pem", type: "spki" }).toString(),
      "utf8",
    );

    // First, what the genuine anchor log is worth: while it survives, the forgery is caught even by
    // a reader with no key at all. That is the one layer here that works against a stranger, and it
    // is also the one an attacker rewriting the directory removes in the same motion.
    const stillAnchored = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], {
      SHADOW_COMMIT_HOME: path.join(bed.dir, "an-auditor-holds-no-keys"),
      SHADOW_JOURNAL_KEY: undefined,
      SHADOW_JOURNAL_KEY_FILE: undefined,
      SHADOW_JOURNAL_PUBKEY_FILE: undefined,
    });
    expect(stillAnchored.code).toBe(1);
    expect(stillAnchored.text).toContain("BROKEN");

    // and now the attacker publishes an anchor log for their own chain, which costs them one line
    await fs.writeFile(
      path.join(dataDir(bed), "anchors.jsonl"),
      JSON.stringify({ ...forged.lastCheckpoint, merkleRoot: "", signature: "", body: "", publicKey: "", ts: "2026-08-30T00:00:00.000Z" }) + "\n",
      "utf8",
    );

    const audited = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], {
      SHADOW_COMMIT_HOME: path.join(bed.dir, "an-auditor-holds-no-keys"),
      SHADOW_JOURNAL_KEY: undefined,
      SHADOW_JOURNAL_KEY_FILE: undefined,
      SHADOW_JOURNAL_PUBKEY_FILE: undefined,
    });
    expect(audited.code, "a run that checked nothing but the chain must not exit 0").toBe(2);
    expect(audited.text).not.toContain("OK, the ledger verifies from record one");
    expect(audited.text).toContain("UNVERIFIED");
    expect(audited.text).toContain("UNCHECKED");
    expect(audited.text).toContain("the keyed layer");
    expect(audited.text).toContain("NOT CHECKED, no key on this host");
  });

  it("still exits 0, and still says OK, for a genuine journal checked with its key", async () => {
    // The other half of the pair. A verifier that answered UNVERIFIED for everything would pass the
    // test above while being useless, so the two assertions belong where neither can be changed
    // without facing the other.
    const bed = await seed();
    const passed = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], {
      SHADOW_JOURNAL_KEY: TEST_HMAC_KEY,
      SHADOW_COMMIT_HOME: bed.home,
    });
    expect(passed.code).toBe(0);
    expect(passed.text).toContain("OK, the ledger verifies from record one");
    expect(passed.text).toContain("keyed        yes, hmac verified on every record");
    expect(passed.text).not.toContain("UNCHECKED");

    // a broken chain is still 1, not 2: the exit code has to keep telling a failed check apart from
    // a skipped one
    const lines = await readLines(bed);
    lines[3] = lines[3]!.replace(/"runId":"r(\d)"/, '"runId":"rX"');
    await writeLines(bed, lines);
    const broken = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], {
      SHADOW_JOURNAL_KEY: TEST_HMAC_KEY,
      SHADOW_COMMIT_HOME: bed.home,
    });
    expect(broken.code).toBe(1);
    expect(broken.text).toContain("BROKEN");

    // THE DEMO PATH, and it was the remaining green line. A journal that has not reached the
    // checkpoint interval has no checkpoint, so nothing in it is signed and nothing in it is
    // anchored, and the signature layer had no unverified checkpoint to count. The shipped interval
    // is 64, so a reviewer who runs the poc, sends one message and runs this command is in exactly
    // this state. Three records at 64 stands in for that.
    const young = await seed({ records: 3, checkpointEvery: 64, close: false });
    await young.journal.settle();
    const unsigned = await runCli(["--journal", young.journalPath, "--data-dir", dataDir(young), "-n", "0"], {
      SHADOW_JOURNAL_KEY: TEST_HMAC_KEY,
      SHADOW_COMMIT_HOME: young.home,
    });
    expect((await asOperator(young)).checkpoints, "the bed must really have no checkpoint").toEqual([]);
    expect(unsigned.code, "nothing signed and nothing anchored must not exit 0").toBe(2);
    expect(unsigned.text).not.toContain("OK, the ledger verifies from record one");
    expect(unsigned.text).toContain("UNVERIFIED");
    expect(unsigned.text).toContain("this journal contains no checkpoint yet");
  });

  it("says out loud that the signatures were checked against a key from the audited directory", async () => {
    // journal.pub defaults to <dataDirectory>/journal.pub, which is the directory the records live
    // in. "signature ok" against a key the writer supplied is a tautology, and the report used to
    // print it with no qualification at all.
    const bed = await seed();
    const printed = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], {
      SHADOW_JOURNAL_KEY: TEST_HMAC_KEY,
      SHADOW_COMMIT_HOME: bed.home,
      SHADOW_JOURNAL_PUBKEY_FILE: undefined,
    });
    expect(printed.text).toContain("which is inside the directory being checked");
    expect(printed.text).toContain("SHADOW_JOURNAL_PUBKEY_FILE");

    // and it stays quiet when the key really does come from somewhere else
    const published = path.join(bed.dir, "published-journal.pub");
    await fs.copyFile(path.join(dataDir(bed), "journal.pub"), published);
    const elsewhere = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], {
      SHADOW_JOURNAL_KEY: TEST_HMAC_KEY,
      SHADOW_COMMIT_HOME: bed.home,
      SHADOW_JOURNAL_PUBKEY_FILE: published,
    });
    expect(elsewhere.code).toBe(0);
    expect(elsewhere.text).not.toContain("which is inside the directory being checked");
  });

  it("names the hmac key file, so a key the reader was handed is visible as one", async () => {
    // THE SAME FINDING ONE LEVEL UP, and the level that matters more: the signature layer's trust
    // anchor was named and the hmac layer's was not, while the hmac layer is what the whole tamper
    // evidence claim rests on. A forger who ships their own key beside the bundle and tells the
    // reader to drop it in the documented place got "keyed yes, hmac verified on every record",
    // "OK, the ledger verifies from record one" and exit 0, on records they wrote themselves.
    //
    // The forgery still passes. It has to: every check really did run and really did pass, against
    // material the forger chose. What changes is that the report now says which file that was, so a
    // reader who did not put the key there can see that somebody else did.
    const bed = await seed();
    const attacker = crypto.generateKeyPairSync("ed25519");
    // 32 bytes chosen by the forger. Not a credential and not the operator's key: the point of the
    // test is that it is neither, and that the old report could not tell the reader so.
    const forgerKey = "a-key-the-forger-picked-not-a-secret-".repeat(2);
    const bodies = Array.from({ length: 8 }, (_, i) => ({
      kind: "turn.begin",
      runId: `r${i}`,
      agentId: "a1",
      ts: "2026-08-30T00:00:00.000Z",
      principal: "agent",
    }));
    bodies[5] = {
      kind: "policy.decision",
      runId: "r5",
      decision: "commit",
      rule: "none",
      ts: "2026-08-30T00:00:00.000Z",
      principal: "policy",
    } as (typeof bodies)[number];
    const forged = forgeJournal(bodies, { hmacKey: forgerKey, signingKey: attacker.privateKey, checkpointEvery: 4 });
    await writeLines(bed, forged.lines);
    await fs.writeFile(
      path.join(dataDir(bed), "journal.pub"),
      crypto.createPublicKey(attacker.privateKey).export({ format: "pem", type: "spki" }).toString(),
      "utf8",
    );
    await fs.writeFile(
      path.join(dataDir(bed), "anchors.jsonl"),
      JSON.stringify({ ...forged.lastCheckpoint, merkleRoot: "", signature: "", body: "", publicKey: "", ts: "2026-08-30T00:00:00.000Z" }) + "\n",
      "utf8",
    );

    // the reader is asked to install the supplied key where the verifier looks for the operator's
    const readerHome = path.join(bed.dir, "the-readers-own-key-home");
    await fs.mkdir(readerHome, { recursive: true });
    const installed = path.join(readerHome, "journal.key");
    await fs.writeFile(installed, forgerKey + "\n", "utf8");

    const env = {
      SHADOW_COMMIT_HOME: readerHome,
      SHADOW_JOURNAL_KEY: undefined,
      SHADOW_JOURNAL_KEY_FILE: undefined,
      SHADOW_JOURNAL_PUBKEY_FILE: undefined,
    };
    const audited = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], env);
    expect(audited.code, "every layer really did pass, against the forger's own material").toBe(0);
    expect(audited.text).toContain("keyed        yes, hmac verified on every record");
    // the assertion this test exists for
    expect(audited.text).toContain(`hmac verified against ${installed}`);
    // and its opposite number on the signature layer, which was already named
    expect(audited.text).toContain("which is inside the directory being checked");

    // a CI gate reads the JSON, and `keyed: true` on its own tells it a key existed, not whose
    const machine = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "--json"], env);
    const report = JSON.parse(machine.text) as {
      keyed: boolean;
      hmacKeySource: string | null;
      hmacKeyFile: string | null;
      hmacKeySuppliedOnThisInvocation: boolean;
    };
    expect(report.keyed).toBe(true);
    expect(report.hmacKeyFile).toBe(installed);
    expect(report.hmacKeySource).toBe(installed);
    expect(report.hmacKeySuppliedOnThisInvocation, "found in a key home, not named on the command").toBe(false);

    // and when the key is named on the invocation itself, which is not evidence the reader controls
    const named = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "-n", "0"], {
      ...env,
      SHADOW_COMMIT_HOME: path.join(bed.dir, "an-empty-key-home"),
      SHADOW_JOURNAL_KEY_FILE: installed,
    });
    expect(named.code).toBe(0);
    expect(named.text).toContain("a path named on this invocation");
    expect(named.text).toContain("The keyed row above is worth what the reader");
  });

  it("reports the missing key as unchecked in the JSON a CI gate reads", async () => {
    const bed = await seed();
    const audited = await runCli(["--journal", bed.journalPath, "--data-dir", dataDir(bed), "--json"], {
      SHADOW_COMMIT_HOME: path.join(bed.dir, "an-auditor-holds-no-keys"),
      SHADOW_JOURNAL_KEY: undefined,
      SHADOW_JOURNAL_KEY_FILE: undefined,
      SHADOW_JOURNAL_PUBKEY_FILE: undefined,
    });
    expect(audited.code).toBe(2);
    const report = JSON.parse(audited.text) as {
      ok: boolean;
      unchecked: string[];
      unanchoredTail: number | null;
      publicKeyInsideDataDirectory: boolean;
    };
    // `ok` still describes the checks that ran, so it stays true; `unchecked` is what a gate has to
    // read to learn that the run proved less than it looks like it proved
    expect(report.ok).toBe(true);
    expect(report.unchecked.length).toBeGreaterThan(0);
    expect(report.unchecked[0]).toContain("the keyed layer");
    expect(report.publicKeyInsideDataDirectory).toBe(true);
    expect(report.unanchoredTail).not.toBeNull();
  });
});

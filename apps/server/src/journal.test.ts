import { describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { GitAnchor, type Anchor, type AnchorSubmission } from "./anchors.js";
import {
  Journal,
  JournalCompromisedError,
  JournalLockError,
  canonicalJson,
  checkpointBody,
  verifyJournalAt,
} from "./journal.js";
import { merkleRoot, verifyConsistency, verifyInclusion } from "./merkle.js";
import { TransactionalRunner } from "./transactional-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

interface Fixture {
  root: string;
  journalPath: string;
  home: string;
  open(extra?: Record<string, unknown>): Journal;
  lines(): Promise<string[]>;
  write(lines: string[]): Promise<void>;
  cleanup(): Promise<void>;
}

async function fixture(prefix = "journal-"): Promise<Fixture> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  const data = path.join(root, "data");
  const home = path.join(root, "keys");
  await fs.mkdir(data, { recursive: true });
  const journalPath = path.join(data, "journal.jsonl");
  const journals: Journal[] = [];
  return {
    root: data,
    journalPath,
    home,
    open(extra: Record<string, unknown> = {}) {
      const journal = new Journal({ journalPath, home, anchors: [], ...extra });
      journals.push(journal);
      return journal;
    },
    async lines() {
      const text = await fs.readFile(journalPath, "utf8");
      return text.split("\n").filter((line) => line.trim().length > 0);
    },
    async write(lines: string[]) {
      await fs.writeFile(journalPath, lines.join("\n") + "\n");
    },
    async cleanup() {
      for (const journal of journals) await journal.close().catch(() => undefined);
      await fs.rm(root, { recursive: true, force: true });
    },
  };
}

const sha256 = (text: string) => crypto.createHash("sha256").update(text, "utf8").digest("hex");

/** the plain chain exactly as a reader that predates the keyed layer would check it */
function plainChainVerifies(lines: readonly string[]): boolean {
  let previous = "0".repeat(64);
  for (const line of lines) {
    const record = JSON.parse(line) as Record<string, unknown>;
    const { hash, ...withoutHash } = record;
    if (sha256(JSON.stringify(withoutHash)) !== hash) return false;
    if (record.prev !== previous) return false;
    previous = hash as string;
  }
  return true;
}

const scriptRunner = (act: (workspace: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

describe("the ordinary case: a working ledger", () => {
  it("chains, keys and attributes every record, and verifies from record one", async () => {
    const f = await fixture();
    const journal = f.open();
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await journal.append({ kind: "policy.decision", runId: "r1", decision: "commit", rule: "none" });
    await journal.append({ kind: "turn.approved", runId: "r1", actor: "maksim" });
    await journal.append({ kind: "reconcile.replayed", runId: "r1" });

    const report = await verifyJournalAt(f.journalPath, { home: f.home });
    expect(report.ok).toBe(true);
    expect(report.problems).toEqual([]);
    expect(report.keyed).toBe(true);

    const records = (await f.lines()).map((line) => JSON.parse(line) as Record<string, unknown>);
    // the first two records say the key material came into existence; then the turn's own records
    expect(records.map((r) => r.kind).slice(0, 2)).toEqual(["journal.key-created", "journal.signing-key-created"]);
    expect(records.map((r) => r.principal)).toEqual([
      "journal",
      "journal",
      "agent",
      "policy",
      "operator:maksim",
      "reconciler",
    ]);
    for (const record of records) {
      expect(typeof record.hmac).toBe("string");
      expect(typeof record.hash).toBe("string");
      expect(typeof record.ts).toBe("string");
    }
    await f.cleanup();
  });

  it("keeps the plain hash chain exactly as an older reader checks it", async () => {
    const f = await fixture();
    const journal = f.open();
    for (let i = 0; i < 5; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.append({ kind: "turn.committing", runId: "r9", baseline: { "src.js": "c", "lib/a.js": "d" } });
    expect(plainChainVerifies(await f.lines())).toBe(true);
    await f.cleanup();
  });

  it("hashes the canonical form, so a workspace holding a file named 10 still verifies", async () => {
    const f = await fixture();
    const journal = f.open();
    // JSON.parse hoists integer-like keys to the front, so a reader that re-serialises whatever
    // order it happens to get back reports this healthy record as tampered with. Hashing the
    // canonical form is what makes verification exact; the older plain reader is the one that is
    // wrong here, and only for records that name a file like this.
    await journal.append({ kind: "turn.committing", runId: "r9", baseline: { "10": "a", "9": "b", "src.js": "c" } });
    expect((await verifyJournalAt(f.journalPath, { home: f.home })).ok).toBe(true);
    expect(plainChainVerifies(await f.lines())).toBe(false);
    await f.cleanup();
  });

  it("survives a restart, continuing the chain rather than restarting it", async () => {
    const f = await fixture();
    const first = f.open();
    await first.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await first.append({ kind: "turn.committed", runId: "r1", agentId: "a1" });
    await first.close();

    const second = f.open();
    await second.append({ kind: "turn.begin", runId: "r2", agentId: "a1" });
    await second.close();

    const report = await verifyJournalAt(f.journalPath, { home: f.home });
    expect(report.ok).toBe(true);
    const seqs = (await f.lines()).map((line) => (JSON.parse(line) as { seq: number }).seq);
    expect(seqs).toEqual([...Array(seqs.length).keys()].map((i) => i + 1));
    await f.cleanup();
  });

  it("treats a crash mid append as a torn tail rather than as tampering", async () => {
    const f = await fixture();
    const first = f.open();
    await first.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await first.close();
    await fs.appendFile(f.journalPath, '{"seq":99,"kind":"turn.he');

    const second = f.open();
    await second.append({ kind: "turn.begin", runId: "r2", agentId: "a1" });
    expect(second.status().state).toBe("healthy");
    const kinds = (await f.lines()).map((line) => (JSON.parse(line) as { kind: string }).kind);
    expect(kinds).toContain("journal.recovered");
    // the fragment is kept, out of the chain, rather than left to break every later verification
    expect(await fs.readFile(f.journalPath + ".torn", "utf8")).toContain("turn.he");
    expect(await verifyJournalAt(f.journalPath, { home: f.home }).then((r) => r.ok)).toBe(true);
    await f.cleanup();
  });

  it("notices a write that came from somewhere else and does not fuse a record onto it", async () => {
    const f = await fixture();
    const journal = f.open();
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    // the lock is meant to make this impossible; the ledger still has to degrade safely if it happens
    await fs.appendFile(f.journalPath, '{"seq":99,"kind":"turn.he');
    await journal.append({ kind: "turn.committed", runId: "r1", agentId: "a1" });

    const kinds = (await f.lines()).map((line) => {
      try {
        return (JSON.parse(line) as { kind: string }).kind;
      } catch {
        return "(fragment)";
      }
    });
    expect(kinds).toContain("journal.foreign-append");
    expect(kinds).toContain("turn.committed");           // the real record survived the fragment
    expect(kinds.filter((kind) => kind === "(fragment)")).toHaveLength(1);
    await f.cleanup();
  });

  it("keeps the chain intact under four concurrent writers", async () => {
    const f = await fixture();
    const journal = f.open();
    await Promise.all(
      [1, 2, 3, 4].map(async (writer) => {
        for (let i = 0; i < 12; i++) {
          await journal.append({ kind: "turn.begin", runId: `w${writer}-${i}`, agentId: `a${writer}` });
        }
      }),
    );
    const report = await verifyJournalAt(f.journalPath, { home: f.home });
    expect(report.ok).toBe(true);
    const turns = (await f.lines()).filter((line) => line.includes('"turn.begin"'));
    expect(turns).toHaveLength(48);
    const seqs = (await f.lines()).map((line) => (JSON.parse(line) as { seq: number }).seq);
    expect(new Set(seqs).size).toBe(seqs.length);
    await f.cleanup();
  });
});

describe("tampering with the file", () => {
  it("names the record when one byte of one record changes", async () => {
    const f = await fixture();
    const journal = f.open();
    for (let i = 0; i < 4; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.close();

    const lines = await f.lines();
    expect(lines[2]).toContain('"agentId":"a1"');
    lines[2] = lines[2]!.replace('"agentId":"a1"', '"agentId":"a2"');   // one byte
    await f.write(lines);

    const report = await verifyJournalAt(f.journalPath, { home: f.home });
    expect(report.ok).toBe(false);
    expect(report.firstBreak?.record).toBe(3);
    expect(report.problems.map((p) => p.message).join(" ")).toContain("record 3 (seq 3) hash does not match its content");
    expect(report.problems.some((p) => p.kind === "hmac")).toBe(true);
    await f.cleanup();
  });

  it("refuses a well-formed forged tail instead of adopting it, and then refuses turns (a46)", async () => {
    const f = await fixture();
    const journal = f.open();
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await journal.close();

    // the red team's payload: parses, has a numeric seq and a string hash, chains to nothing
    await fs.appendFile(
      f.journalPath,
      JSON.stringify({
        seq: 999999,
        prev: "a".repeat(64),
        hash: "b".repeat(64),
        kind: "turn.committed",
        runId: "forged-0001",
        agentId: "attacker",
      }) + "\n",
    );

    const reopened = f.open();
    await reopened.open();
    expect(reopened.status().state).toBe("compromised");
    await expect(reopened.append({ kind: "turn.begin", runId: "r2", agentId: "a1" })).rejects.toBeInstanceOf(
      JournalCompromisedError,
    );

    const sidecar = await fs.readFile(reopened.status().sidecar, "utf8");
    const loud = JSON.parse(sidecar.trim().split("\n")[0]!) as Record<string, unknown>;
    expect(loud.kind).toBe("journal.compromised");
    expect(loud.seq).toBe(1);                                    // a fresh chain, not the suspect one
    expect(String(JSON.stringify(loud.problems))).toContain("chain breaks");
    await f.cleanup();
  });

  it("lets a named operator acknowledge, after which turns run and the break stays on the record", async () => {
    const f = await fixture();
    const first = f.open();
    await first.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await first.close();
    await fs.appendFile(f.journalPath, JSON.stringify({ seq: 42, prev: "c".repeat(64), hash: "d".repeat(64), kind: "turn.committed" }) + "\n");

    const journal = f.open();
    await journal.open();
    expect(await journal.acknowledge("maksim")).toBe(true);
    await journal.append({ kind: "turn.begin", runId: "r2", agentId: "a1" });
    expect(journal.status().state).toBe("acknowledged");

    const kinds = (await f.lines()).map((line) => (JSON.parse(line) as { kind: string }).kind);
    expect(kinds).toContain("journal.reopened");
    // the ledger still reports the forgery: acknowledging is not erasing
    expect(await verifyJournalAt(f.journalPath, { home: f.home }).then((r) => r.ok)).toBe(false);
    await f.cleanup();
  });

  it("catches a whole file rewritten consistently by somebody who cannot read the key", async () => {
    const f = await fixture();
    const journal = f.open();
    for (let i = 0; i < 3; i++) await journal.append({ kind: "turn.committed", runId: `r${i}`, agentId: "a1" });
    await journal.close();

    // The attacker can write the file, so they rebuild the plain chain from record one with their
    // own story in it. Without the key they cannot produce an hmac, and inventing one does not help.
    const forged = (await f.lines()).map((line, index) => {
      const record = JSON.parse(line) as Record<string, unknown>;
      return { ...record, agentId: "attacker", kind: index === 1 ? "turn.discarded" : record.kind };
    });
    let previous = "0".repeat(64);
    const rebuilt = forged.map((record) => {
      const { hash: _drop, ...rest } = record;
      const body = { ...rest, prev: previous };
      const hash = sha256(canonicalJson(body));
      previous = hash;
      return canonicalJson({ ...body, hash });
    });
    await f.write(rebuilt);

    expect(plainChainVerifies(await f.lines())).toBe(true);        // the old chain is happy
    const report = await verifyJournalAt(f.journalPath, { home: f.home });
    expect(report.ok).toBe(false);
    expect(report.keyed).toBe(false);
    expect(report.problems.filter((p) => p.kind === "hmac")).toHaveLength(report.records);   // every one
    await f.cleanup();
  });

  it("reports every record when the chain is checked under the wrong key", async () => {
    const f = await fixture();
    const journal = f.open();
    for (let i = 0; i < 3; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.close();
    const wrong = await verifyJournalAt(f.journalPath, { home: f.home, hmacKey: "z".repeat(64) });
    expect(wrong.problems.filter((p) => p.kind === "hmac")).toHaveLength(wrong.records);
    const right = await verifyJournalAt(f.journalPath, { home: f.home });
    expect(right.ok).toBe(true);
    await f.cleanup();
  });
});

describe("the deleted journal (a47)", () => {
  it("detects the discontinuity when an anchor says a chain existed", async () => {
    const f = await fixture();
    const journal = f.open({ anchors: [new GitAnchor({ dataDirectory: f.root, gitNotes: false })], checkpointEvery: 2 });
    for (let i = 0; i < 4; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.close();
    const anchors = await fs.readFile(path.join(f.root, "anchors.jsonl"), "utf8");
    expect(anchors.trim().split("\n").length).toBeGreaterThan(0);

    await fs.rm(f.journalPath);                                   // rm -f "$DATA_DIR/journal.jsonl"
    const restarted = f.open({ anchors: [] });
    await restarted.open();
    expect(restarted.status().state).toBe("compromised");
    expect(restarted.status().problems.join(" ")).toContain("an anchor records a chain");
    await expect(restarted.append({ kind: "turn.begin", runId: "r9", agentId: "a1" })).rejects.toBeInstanceOf(
      JournalCompromisedError,
    );
    await f.cleanup();
  });

  it("treats a missing journal with no anchor as the new deployment it looks like", async () => {
    const f = await fixture();
    const journal = f.open();
    await journal.open();
    expect(journal.status().state).toBe("healthy");
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    expect((await verifyJournalAt(f.journalPath, { home: f.home })).ok).toBe(true);
    await f.cleanup();
  });

  it("detects a truncated journal that no longer contains the anchored head", async () => {
    const f = await fixture();
    const journal = f.open({ anchors: [new GitAnchor({ dataDirectory: f.root, gitNotes: false })], checkpointEvery: 2 });
    for (let i = 0; i < 6; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.close();
    const lines = await f.lines();
    await f.write(lines.slice(0, 2));                             // keep a valid prefix, drop the rest

    const report = await verifyJournalAt(f.journalPath, { home: f.home });
    expect(report.ok).toBe(false);
    expect(report.anchors.present).toBe(false);
    expect(report.problems.map((p) => p.message).join(" ")).toContain("is not in this journal");
    await f.cleanup();
  });
});

describe("one writer (a48)", () => {
  it("refuses a second Journal on the same path while the first holds the lock", async () => {
    const f = await fixture();
    const first = f.open();
    await first.open();
    await first.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });

    const second = f.open();
    await expect(second.open()).rejects.toBeInstanceOf(JournalLockError);
    await expect(second.append({ kind: "turn.begin", runId: "r2", agentId: "a2" })).rejects.toThrow(/already open/);

    // closing the instance that never got the lock must not drop the lock the first one holds
    await second.close();
    const stillLocked = JSON.parse(await fs.readFile(f.journalPath + ".lock", "utf8")) as { pid: number };
    expect(stillLocked.pid).toBe(process.pid);

    await first.append({ kind: "turn.committed", runId: "r1", agentId: "a1" });
    expect((await verifyJournalAt(f.journalPath, { home: f.home })).ok).toBe(true);
    await f.cleanup();
  });

  it("gives the lock back when the journal could not be opened, so a fixed configuration works", async () => {
    const f = await fixture();
    const misconfigured = f.open({ keyFile: path.join(f.root, "journal.key") });
    await expect(misconfigured.open()).rejects.toThrow(/outside the data directory/);
    expect(await fs.access(f.journalPath + ".lock").then(() => true).catch(() => false)).toBe(false);

    const corrected = f.open();
    await corrected.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    expect((await verifyJournalAt(f.journalPath, { home: f.home })).ok).toBe(true);
    await f.cleanup();
  });

  it("refuses a lock held by another live process, and takes one whose holder is gone", async () => {
    const f = await fixture();
    const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
    await new Promise((resolve) => child.once("spawn", resolve));
    const lockPath = f.journalPath + ".lock";
    const holder = { pid: child.pid, hostname: os.hostname(), startedAt: new Date().toISOString(), journal: f.journalPath };
    await fs.writeFile(lockPath, JSON.stringify(holder) + "\n");

    const blocked = f.open();
    await expect(blocked.open()).rejects.toThrow(new RegExp(`already open in process ${child.pid}`));

    child.kill("SIGKILL");
    await new Promise((resolve) => child.once("exit", resolve));
    const journal = f.open();
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    const kinds = (await f.lines()).map((line) => (JSON.parse(line) as { kind: string }).kind);
    expect(kinds).toContain("journal.lock-stolen");               // said out loud, not papered over
    expect((await verifyJournalAt(f.journalPath, { home: f.home })).ok).toBe(true);
    await f.cleanup();
  });

  it("hands one runner per journal path to every caller in the process", async () => {
    const f = await fixture();
    const a = Journal.acquire({ journalPath: f.journalPath, home: f.home, anchors: [] });
    const b = Journal.acquire({ journalPath: f.journalPath, home: f.home, anchors: [] });
    expect(b).toBe(a);
    await a.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await b.append({ kind: "turn.begin", runId: "r2", agentId: "a2" });
    expect((await verifyJournalAt(f.journalPath, { home: f.home })).ok).toBe(true);
    await a.close();
    await f.cleanup();
  });
});

describe("checkpoints, signatures and proofs", () => {
  it("signs a checkpoint that verifies with the exported public key and fails with any other", async () => {
    const f = await fixture();
    const journal = f.open({ checkpointEvery: 3 });
    for (let i = 0; i < 6; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.close();

    const published = await fs.readFile(path.join(f.root, "journal.pub"), "utf8");
    const checkpoints = (await f.lines())
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((record) => record.kind === "journal.checkpoint");
    expect(checkpoints.length).toBeGreaterThanOrEqual(2);
    for (const checkpoint of checkpoints) {
      const body = Buffer.from(checkpointBody(checkpoint), "utf8");
      const signature = Buffer.from(String(checkpoint.signature), "base64");
      expect(crypto.verify(null, body, crypto.createPublicKey(published), signature)).toBe(true);
      const other = crypto.generateKeyPairSync("ed25519").publicKey;
      expect(crypto.verify(null, body, other, signature)).toBe(false);
    }

    const wrongKey = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "pem", type: "spki" }).toString();
    const underWrongKey = await verifyJournalAt(f.journalPath, { home: f.home, publicKeyFile: path.join(f.root, "missing.pub") });
    expect(underWrongKey.checkpoints.every((c) => c.signature === "unverified")).toBe(true);
    await fs.writeFile(path.join(f.root, "wrong.pub"), wrongKey);
    const forged = await verifyJournalAt(f.journalPath, { home: f.home, publicKeyFile: path.join(f.root, "wrong.pub") });
    expect(forged.ok).toBe(false);
    expect(forged.problems.some((p) => p.kind === "signature")).toBe(true);
    await f.cleanup();
  });

  it("roots each checkpoint in the records before it, and notices a rewritten one", async () => {
    const f = await fixture();
    const journal = f.open({ checkpointEvery: 4 });
    for (let i = 0; i < 8; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.close();
    const lines = await f.lines();
    const index = lines.findIndex((line) => line.includes('"journal.checkpoint"'));
    expect(index).toBeGreaterThan(0);
    const leaves = lines.slice(0, index).map((line) => crypto.createHash("sha256").update(Buffer.concat([Buffer.from([0]), Buffer.from(line, "utf8")])).digest());
    const checkpoint = JSON.parse(lines[index]!) as { merkleRoot: string; treeSize: number };
    expect(checkpoint.treeSize).toBe(index);
    expect(checkpoint.merkleRoot).toBe(merkleRoot(leaves).toString("hex"));
    await f.cleanup();
  });

  it("proves one record's inclusion and that a later ledger extends an earlier one", async () => {
    const f = await fixture();
    const journal = f.open();
    for (let i = 0; i < 9; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    const early = await journal.proveInclusion(4);
    expect(early).not.toBeNull();
    expect(
      verifyInclusion(
        Buffer.from(early!.leaf, "hex"),
        early!.index,
        early!.treeSize,
        early!.proof.map((hex) => Buffer.from(hex, "hex")),
        Buffer.from(early!.root, "hex"),
      ),
    ).toBe(true);
    const oldRoot = Buffer.from(early!.root, "hex");
    const oldSize = early!.treeSize;

    for (let i = 0; i < 7; i++) await journal.append({ kind: "turn.committed", runId: `r${i}`, agentId: "a1" });
    const later = await journal.proveInclusion(1);
    const consistency = await journal.proveConsistency(oldSize);
    expect(consistency).not.toBeNull();
    expect(
      verifyConsistency(
        oldRoot,
        oldSize,
        Buffer.from(later!.root, "hex"),
        consistency!.newSize,
        consistency!.proof.map((hex) => Buffer.from(hex, "hex")),
      ),
    ).toBe(true);
    expect(await journal.proveInclusion(999)).toBeNull();
    await f.cleanup();
  });
});

describe("keys", () => {
  it("refuses a key file inside the data directory, where a container would reach it", async () => {
    const f = await fixture();
    const journal = f.open({ keyFile: path.join(f.root, "journal.key") });
    await expect(journal.open()).rejects.toThrow(/outside the data directory/);
    await f.cleanup();
  });

  it("creates the key 0600 on first run and reuses it afterwards", async () => {
    const f = await fixture();
    const journal = f.open();
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    const keyFile = path.join(f.home, "journal.key");
    const stat = await fs.stat(keyFile);
    expect(stat.mode & 0o777).toBe(0o600);
    expect((await fs.stat(path.join(f.home, "signing.key"))).mode & 0o777).toBe(0o600);
    const key = await fs.readFile(keyFile, "utf8");
    await journal.close();
    const again = f.open();
    await again.append({ kind: "turn.begin", runId: "r2", agentId: "a1" });
    expect(await fs.readFile(keyFile, "utf8")).toBe(key);
    expect((await verifyJournalAt(f.journalPath, { home: f.home })).ok).toBe(true);
    await f.cleanup();
  });

  it("takes the key from the environment when the deployment injects one", async () => {
    const f = await fixture();
    const env = { ...process.env, SHADOW_JOURNAL_KEY: "k".repeat(48) };
    const journal = f.open({ env });
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await journal.close();
    expect(await fs.access(path.join(f.home, "journal.key")).then(() => true).catch(() => false)).toBe(false);
    expect((await verifyJournalAt(f.journalPath, { home: f.home, env })).ok).toBe(true);
    expect((await verifyJournalAt(f.journalPath, { home: f.home, hmacKey: "j".repeat(48) })).ok).toBe(false);
    await f.cleanup();
  });

  it("refuses to run against a published key that does not match the signing key", async () => {
    const f = await fixture();
    const journal = f.open();
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await journal.close();
    const other = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "pem", type: "spki" }).toString();
    await fs.writeFile(path.join(f.root, "journal.pub"), other);
    const swapped = f.open();
    await expect(swapped.open()).rejects.toThrow(/does not match the signing key/);
    await f.cleanup();
  });
});

describe("anchoring never blocks a turn", () => {
  it("records anchor.failed and keeps serving when an anchor is unreachable", async () => {
    const f = await fixture();
    const failing: Anchor = {
      name: "rekor",
      submit: async () => {
        throw new Error("getaddrinfo ENOTFOUND rekor.sigstore.dev");
      },
    };
    const journal = f.open({ anchors: [failing], checkpointEvery: 2 });
    for (let i = 0; i < 4; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.settle();
    const kinds = (await f.lines()).map((line) => (JSON.parse(line) as { kind: string }).kind);
    expect(kinds).toContain("anchor.failed");
    expect(kinds.filter((kind) => kind === "turn.begin")).toHaveLength(4);
    expect((await verifyJournalAt(f.journalPath, { home: f.home })).ok).toBe(true);
    await f.cleanup();
  });

  it("records anchor.ok with the receipt when an anchor answers", async () => {
    const f = await fixture();
    const seen: AnchorSubmission[] = [];
    const anchor: Anchor = {
      name: "rekor",
      submit: async (submission) => {
        seen.push(submission);
        return { uuid: "24296fb2", logIndex: 91827 };
      },
    };
    const journal = f.open({ anchors: [anchor], checkpointEvery: 2 });
    for (let i = 0; i < 2; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.settle();
    const ok = (await f.lines())
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .find((record) => record.kind === "anchor.ok");
    expect(ok).toBeTruthy();
    expect((ok!.receipt as Record<string, unknown>).logIndex).toBe(91827);
    expect(seen[0]!.merkleRoot).toHaveLength(64);
    expect(seen[0]!.signature.length).toBeGreaterThan(0);
    await f.cleanup();
  });
});

describe("an auditor with only the anchor line", () => {
  it("can verify the checkpoint signature and place it against the journal, without the key", async () => {
    const f = await fixture();
    const journal = f.open({ anchors: [new GitAnchor({ dataDirectory: f.root, gitNotes: false })], checkpointEvery: 3 });
    for (let i = 0; i < 6; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.close();

    const anchors = (await fs.readFile(path.join(f.root, "anchors.jsonl"), "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, string | number>);
    expect(anchors.length).toBeGreaterThan(0);

    for (const anchor of anchors) {
      // everything needed is on the line: the bytes that were signed, the signature, the key
      const verified = crypto.verify(
        null,
        Buffer.from(String(anchor.body), "utf8"),
        crypto.createPublicKey(String(anchor.publicKey)),
        Buffer.from(String(anchor.signature), "base64"),
      );
      expect(verified).toBe(true);
      const body = JSON.parse(String(anchor.body)) as Record<string, unknown>;
      expect(body.merkleRoot).toBe(anchor.merkleRoot);
      expect(body.treeSize).toBe(anchor.treeSize);
    }

    // and the head each anchor pins is really a record in the journal
    const hashes = new Set((await f.lines()).map((line) => (JSON.parse(line) as { hash: string }).hash));
    for (const anchor of anchors) expect(hashes.has(String(anchor.head))).toBe(true);
    await f.cleanup();
  });
});

describe("the runner refuses turns on a compromised ledger", () => {
  it("never executes a turn it cannot record, and runs again once acknowledged", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "runner-journal-"));
    const workspace = path.join(root, "ws");
    await fs.mkdir(workspace, { recursive: true });
    await fs.writeFile(path.join(workspace, "index.js"), "console.log(1)\n");
    const journalPath = path.join(root, "data", "journal.jsonl");
    const options = {
      shadowRoot: path.join(root, "shadows"),
      journalPath,
      policy: async () => ({ decision: "commit" as const, rule: "none" }),
      journal: { home: path.join(root, "keys"), anchors: [] },
    };
    let executed = 0;
    const inner = scriptRunner(async (w) => {
      executed += 1;
      await fs.writeFile(path.join(w, "feature.js"), "export const x = 1\n");
    });
    const request: RunnerRequest = { agentId: "a1", workspacePath: workspace, prompt: "p", threadId: null };

    const first = new TransactionalRunner(inner, options);
    await first.run(request);
    expect(executed).toBe(1);
    await first.closeJournal();

    await fs.appendFile(journalPath, JSON.stringify({ seq: 5000, prev: "e".repeat(64), hash: "f".repeat(64), kind: "turn.committed" }) + "\n");

    const second = new TransactionalRunner(inner, options);
    await expect(second.run(request)).rejects.toBeInstanceOf(JournalCompromisedError);
    expect(executed).toBe(1);                                     // the turn never ran
    expect((await second.journalStatus()).state).toBe("compromised");

    expect(await second.acknowledgeJournal("maksim")).toBe(true);
    await second.run(request);
    expect(executed).toBe(2);
    await expect(fs.readFile(path.join(workspace, "feature.js"), "utf8")).resolves.toContain("export const x");
    await second.closeJournal();
    await fs.rm(root, { recursive: true, force: true });
  });
});

describe("keys stay out of anything a container mounts", () => {
  it("refuses a key file inside the workspace root the runtime bind-mounts", async () => {
    const f = await fixture();
    const workspaces = path.join(f.root, "..", "workspaces");
    await fs.mkdir(workspaces, { recursive: true });
    const journal = f.open({
      keyFile: path.join(workspaces, "journal.key"),
      env: { ...process.env, AGENT_WORKSPACE_ROOT: workspaces },
    });
    await expect(journal.open()).rejects.toThrow(/container-mounted directory/);
    await f.cleanup();
  });

  it("refuses a SIGNING key inside the workspace root, the same as the hmac key", async () => {
    // The asymmetry this pins: `loadJournalKey` refused a key inside the data directory AND inside
    // any container-mounted directory, while `loadSigningKey` checked the data directory only and
    // took no `env`, so it could not have made the second check. It ran the wrong way round. The
    // hmac key proves the chain was not edited; the signing key signs the checkpoints, so whoever
    // holds it can forge a chain that verifies. The higher-value asset had the weaker guard.
    const f = await fixture();
    const workspaces = path.join(f.root, "..", "workspaces-signing");
    await fs.mkdir(workspaces, { recursive: true });
    const journal = f.open({
      signingKeyFile: path.join(workspaces, "signing.key"),
      env: { ...process.env, AGENT_WORKSPACE_ROOT: workspaces },
    });
    await expect(journal.open()).rejects.toThrow(/container-mounted directory/);
    await f.cleanup();
  });

  it("publishes the public key where the deployment says, so git can carry it", async () => {
    const f = await fixture();
    const published = path.join(f.root, "..", "journal.pub");
    const journal = f.open({ env: { ...process.env, SHADOW_JOURNAL_PUBKEY_FILE: published } });
    await journal.append({ kind: "turn.begin", runId: "r1", agentId: "a1" });
    await journal.close();
    expect(await fs.readFile(published, "utf8")).toContain("BEGIN PUBLIC KEY");
    expect(await fs.access(path.join(f.root, "journal.pub")).then(() => true).catch(() => false)).toBe(false);
    const report = await verifyJournalAt(f.journalPath, {
      home: f.home,
      env: { ...process.env, SHADOW_JOURNAL_PUBKEY_FILE: published },
    });
    expect(report.ok).toBe(true);
    expect(report.checkpoints.every((c) => c.signature === "ok")).toBe(true);
    await f.cleanup();
  });
});

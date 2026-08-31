/**
 * The audit ledger.
 *
 * The chain this replaces proved one thing: that the file is internally consistent. That is worth
 * very little on its own. Anyone who can write the file can rewrite it from record one and it still
 * verifies; anyone who can delete it leaves a fresh chain that is indistinguishable from a new
 * deployment; two processes on one data directory interleave into a fork; and a restart adopted the
 * last line that merely parsed, without checking it. Those are the four holes the red team named
 * (a46, a47, a48) and this file closes each with a named mechanism:
 *
 *   keyed records      every record carries an HMAC-SHA256 under a key that lives outside the data
 *                      directory and never inside a container, so writing the file is no longer
 *                      enough to forge a record
 *   signed checkpoints every N records and at shutdown, an Ed25519 signature over a Merkle root of
 *                      everything so far, verifiable by anyone holding only journal.pub
 *   external anchors   the checkpoint head published where the operator cannot reach it, so even
 *                      the operator cannot rewrite history
 *   boot discipline    the whole chain is verified before a head is adopted, the last anchored head
 *                      must be present, and a failure puts the journal in compromised mode where it
 *                      refuses to extend the suspect chain at all
 *   one writer         a lock file with a liveness check, held for the life of the process
 *
 * The plain sha256 `hash` field stays exactly where it was and means exactly what it meant, so a
 * reader that only knows the old chain still verifies it.
 */
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { anchorsFromEnv, type Anchor, type AnchorPoint, type AnchorSubmission } from "./anchors.js";
import { MerkleAccumulator, consistencyProof, inclusionProof, leafHash, merkleRoot } from "./merkle.js";
import {
  RESERVED,
  ZERO_HEAD,
  canonicalJson,
  checkpointBody,
  hmacHex,
  principalFor,
  sha256Hex,
  type Principal,
} from "./journal-format.js";
import {
  acquireLock,
  defaultHome,
  loadHmacKey,
  loadSigningKey,
  releaseLock,
  type SigningMaterial,
} from "./journal-keys.js";
import { verifyJournal, type JournalReport } from "./journal-verify.js";

// The pieces an integrator should be able to reach through one import, since journal.ts is the
// entry point every other module in the server uses.
export { canonicalJson, checkpointBody, principalFor, type Principal } from "./journal-format.js";
export { JournalLockError } from "./journal-keys.js";
export {
  verifyJournal,
  verifyJournalAt,
  type CheckpointReport,
  type JournalProblem,
  type JournalReport,
  type VerifyOptions,
} from "./journal-verify.js";

export type JournalState = "fresh" | "healthy" | "compromised" | "acknowledged" | "closed";

export class JournalCompromisedError extends Error {
  readonly code = "JOURNAL_COMPROMISED";
  constructor(readonly problems: string[]) {
    super(
      `the journal did not verify at boot, so no turn may run until an operator acknowledges it: ${problems
        .slice(0, 3)
        .join("; ")}`,
    );
  }
}

export interface JournalOptions {
  journalPath: string;
  /** where journal.pub and anchors.jsonl live; defaults to the journal's own directory */
  dataDirectory?: string;
  /** keys live here, outside the data directory and outside any container image */
  home?: string;
  keyFile?: string;
  signingKeyFile?: string;
  publicKeyFile?: string;
  lockPath?: string;
  /** explicit key material, for tests and for a deployment that injects it from a secret manager */
  hmacKey?: Buffer | string;
  checkpointEvery?: number;
  anchors?: Anchor[];
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
}

const DEFAULT_CHECKPOINT_EVERY = 64;

export interface CheckpointInfo {
  seq: number;
  treeSize: number;
  merkleRoot: string;
  head: string;
  signature: string;
  /** the canonical bytes the signature covers, carried so an anchor can publish them verbatim */
  body: string;
}

export interface InclusionProofResult {
  seq: number;
  index: number;
  treeSize: number;
  leaf: string;
  root: string;
  proof: string[];
}

const registry = new Map<string, Journal>();

export class Journal {
  /**
   * One writer per journal path per process. The lock stops a second OS process; this stops one
   * process from forking its own chain by holding two instances, which is the same bug with a
   * shorter blast radius.
   */
  static acquire(options: JournalOptions): Journal {
    const key = path.resolve(options.journalPath);
    const existing = registry.get(key);
    if (existing) return existing;
    const created = new Journal(options);
    registry.set(key, created);
    return created;
  }

  readonly journalPath: string;
  readonly dataDirectory: string;
  readonly publicKeyFile: string;
  readonly lockPath: string;
  readonly sidecarPath: string;

  private readonly env: NodeJS.ProcessEnv;
  private readonly now: () => Date;
  private readonly keyFile: string;
  private readonly signingKeyFile: string;
  private readonly checkpointEvery: number;
  private readonly explicitAnchors: Anchor[] | null;

  private anchors: Anchor[] = [];
  private hmacKey: Buffer | null = null;
  private signing: SigningMaterial | null = null;

  private seq = 0;
  private head = ZERO_HEAD;
  private leaves: Buffer[] = [];
  private tree = new MerkleAccumulator();
  private sinceCheckpoint = 0;

  private sidecarSeq = 0;
  private sidecarHead = ZERO_HEAD;

  private state: JournalState = "fresh";
  private bootProblems: string[] = [];
  private lastCheckpoint: CheckpointInfo | null = null;
  private lastAnchor: AnchorPoint | null = null;

  /** serialises compute-and-append; one runner serves every agent, so append() races */
  private tail: Promise<void> = Promise.resolve();
  /** how many bytes we believe each chain file holds, so a foreign write is one stat away */
  private readonly writtenBytes = new Map<string, number>();
  private anchorWork: Promise<void> = Promise.resolve();
  private opening: Promise<void> | null = null;
  /** true only for the instance that actually took the lock, so it is the only one that drops it */
  private holdsLock = false;
  private pendingNotes: Array<Record<string, unknown>> = [];

  constructor(options: JournalOptions) {
    this.env = options.env ?? process.env;
    this.now = options.now ?? (() => new Date());
    this.journalPath = path.resolve(options.journalPath);
    this.dataDirectory = path.resolve(options.dataDirectory ?? path.dirname(this.journalPath));
    const home = options.home ? path.resolve(options.home) : defaultHome(this.env);
    this.keyFile = path.resolve(options.keyFile ?? this.env.SHADOW_JOURNAL_KEY_FILE?.trim() ?? path.join(home, "journal.key"));
    this.signingKeyFile = path.resolve(options.signingKeyFile ?? path.join(home, "signing.key"));
    // <dataDirectory>/journal.pub by default; a deployment points this at a path git tracks, so the
    // key an auditor verifies against is published before the first run rather than after it
    this.publicKeyFile = path.resolve(
      options.publicKeyFile ?? this.env.SHADOW_JOURNAL_PUBKEY_FILE?.trim() ?? path.join(this.dataDirectory, "journal.pub"),
    );
    this.lockPath = path.resolve(options.lockPath ?? this.journalPath + ".lock");
    this.sidecarPath = this.journalPath.replace(/(\.jsonl)?$/, "") + ".compromised.jsonl";
    this.checkpointEvery = Math.max(1, options.checkpointEvery ?? (Number(this.env.SHADOW_CHECKPOINT_EVERY) || DEFAULT_CHECKPOINT_EVERY));
    if (options.hmacKey !== undefined) this.explicitKey = options.hmacKey;
    this.explicitAnchors = options.anchors ?? null;
  }

  private explicitKey: Buffer | string | undefined;

  // ---- lifecycle ----------------------------------------------------------

  /** Idempotent. Takes the lock, resolves the keys, verifies the whole chain, adopts or refuses. */
  async open(): Promise<void> {
    if (!this.opening) {
      this.opening = this.boot().catch((error: unknown) => {
        // a boot that failed on a lock somebody else holds, or on misconfigured keys, must not
        // poison every later attempt: the next caller gets a real retry
        this.opening = null;
        throw error;
      });
    }
    return this.opening;
  }

  private async boot(): Promise<void> {
    try {
      await this.bootInner();
    } catch (error) {
      // holding a lock on a journal we failed to open would lock out the corrected configuration too
      if (this.holdsLock) {
        this.holdsLock = false;
        await releaseLock(this.lockPath);
      }
      throw error;
    }
  }

  private async bootInner(): Promise<void> {
    await fs.mkdir(this.dataDirectory, { recursive: true });
    const lock = await acquireLock(this.lockPath, this.journalPath);
    this.holdsLock = true;
    if (lock.stolenFrom) {
      this.pendingNotes.push({
        kind: "journal.lock-stolen",
        deadPid: lock.stolenFrom.pid,
        heldSince: lock.stolenFrom.startedAt,
      });
    }
    const keyOpts =
      this.explicitKey !== undefined
        ? { keyFile: this.keyFile, dataDirectory: this.dataDirectory, explicit: this.explicitKey, env: this.env }
        : { keyFile: this.keyFile, dataDirectory: this.dataDirectory, env: this.env };
    const resolved = await loadHmacKey(keyOpts);
    this.hmacKey = resolved.key;
    this.signing = await loadSigningKey({
      signingKeyFile: this.signingKeyFile,
      publicKeyFile: this.publicKeyFile,
      dataDirectory: this.dataDirectory,
      env: this.env,
    });
    this.anchors = this.explicitAnchors ?? anchorsFromEnv(this.dataDirectory, this.env);

    const report = await verifyJournal({
      journalPath: this.journalPath,
      dataDirectory: this.dataDirectory,
      hmacKey: this.hmacKey,
      publicKeyPem: this.signing.publicKeyPem,
    });
    this.lastAnchor = report.anchors.last;

    const neverExisted = report.records === 0 && report.problems.every((p) => p.message === "journal not readable");
    if (neverExisted) {
      this.state = "healthy";
      this.seq = 0;
      this.head = ZERO_HEAD;
      this.adoptLeaves([]);
      if (resolved.created) this.pendingNotes.push({ kind: "journal.key-created", keyFile: resolved.source });
      if (this.signing.created) {
        this.pendingNotes.push({
          kind: "journal.signing-key-created",
          publicKeyFile: this.publicKeyFile,
          deploymentForm: "a Secure Enclave key on macOS, or a KMS or HSM key in cloud, non-exportable; a 0600 file is the local stand-in",
        });
      }
      return;
    }

    if (!report.ok) {
      await this.enterCompromised(report);
      return;
    }

    this.state = "healthy";
    this.seq = report.lastSeq ?? 0;
    this.head = report.head ?? ZERO_HEAD;
    this.adoptLeaves(report.leaves);
    this.sinceCheckpoint = report.checkpoints.length
      ? report.records - (report.checkpoints[report.checkpoints.length - 1]!.treeSize)
      : report.records;
    if (report.tornTailLines > 0) await this.quarantineTornTail();
  }

  /**
   * A crash partway through an append leaves bytes that were never a record: no hash, so they were
   * never part of the chain. Leaving them in place makes every later verification report a broken
   * ledger, which trains an operator to ignore the one alarm that matters, so the fragment is moved
   * to <journal>.torn and the chain is cut back to its last complete record. The move is recorded,
   * with the fragment's length and digest, so nothing is silently dropped.
   */
  private async quarantineTornTail(): Promise<void> {
    const text = await fs.readFile(this.journalPath, "utf8").catch(() => null);
    if (text === null || text.endsWith("\n")) return;
    const cut = text.lastIndexOf("\n");
    const fragment = text.slice(cut + 1);
    if (!fragment) return;
    await fs.appendFile(this.journalPath + ".torn", fragment + "\n", { encoding: "utf8", mode: 0o600 });
    await fs.truncate(this.journalPath, cut + 1);
    this.pendingNotes.push({
      kind: "journal.recovered",
      droppedTrailingBytes: Buffer.byteLength(fragment, "utf8"),
      fragmentSha256: crypto.createHash("sha256").update(fragment, "utf8").digest("hex"),
      quarantinedTo: this.journalPath + ".torn",
    });
  }

  /**
   * The suspect chain is never extended. A fresh sidecar chain records what was found, and every
   * caller that tries to journal a turn is refused until an operator acknowledges, which is what
   * makes TransactionalRunner.run() refuse turns: its first act is a journal append.
   */
  private async enterCompromised(report: JournalReport): Promise<void> {
    this.state = "compromised";
    this.bootProblems = report.problems.map((p) => p.message);
    this.seq = report.lastSeq ?? 0;
    this.head = report.head ?? ZERO_HEAD;
    this.adoptLeaves(report.leaves);
    await this.write(this.sidecarPath, "sidecar", {
      kind: "journal.compromised",
      journal: this.journalPath,
      records: report.records,
      observedHead: report.head,
      problems: report.problems.slice(0, 32),
      anchor: report.anchors.last,
      detectedAt: this.now().toISOString(),
    });
  }

  /**
   * An operator, by name, takes responsibility for the break. The break stays in the main chain
   * forever (the verifier still reports it); what changes is that the ledger may be extended again,
   * from a record that says exactly what was accepted and by whom.
   */
  async acknowledge(actor: string): Promise<boolean> {
    await this.open();
    if (this.state !== "compromised") return false;
    const problems = this.bootProblems;
    await this.write(this.sidecarPath, "sidecar", {
      kind: "journal.acknowledged",
      actor,
      principal: `operator:${actor}`,
      problems: problems.slice(0, 32),
    });
    this.state = "acknowledged";
    await this.write(this.journalPath, "main", {
      kind: "journal.reopened",
      actor,
      principal: `operator:${actor}`,
      brokenRecords: problems.length,
      firstBreak: problems[0] ?? null,
      sidecar: this.sidecarPath,
    });
    return true;
  }

  private adoptLeaves(leaves: Buffer[]): void {
    this.leaves = leaves;
    this.tree = new MerkleAccumulator();
    for (const leaf of leaves) this.tree.push(leaf);
  }

  /** Throws when the ledger may not be extended, so a caller can refuse before doing any work. */
  assertUsable(): void {
    if (this.state === "compromised") throw new JournalCompromisedError(this.bootProblems);
    if (this.state === "closed") throw new Error(`the journal at ${this.journalPath} is closed`);
  }

  async close(): Promise<void> {
    if (this.opening) {
      await this.opening.catch(() => undefined);
      if (this.state === "healthy" || this.state === "acknowledged") {
        if (this.sinceCheckpoint > 0) await this.checkpoint("shutdown");
      }
      await this.settle();
      if (this.holdsLock) {
        this.holdsLock = false;
        await releaseLock(this.lockPath);
      }
    }
    this.state = "closed";
    this.opening = null;
    registry.delete(path.resolve(this.journalPath));
  }

  /** Waits for every queued append and every in-flight anchor submission to finish. */
  async settle(): Promise<void> {
    await this.tail.catch(() => undefined);
    await this.anchorWork.catch(() => undefined);
    await this.tail.catch(() => undefined);
  }

  // ---- appending ----------------------------------------------------------

  async append(fields: Record<string, unknown>, principal?: Principal): Promise<void> {
    await this.open();
    this.assertUsable();
    const supplied = principal ? { ...fields, principal } : fields;
    await this.write(this.journalPath, "main", supplied);
    if (this.sinceCheckpoint >= this.checkpointEvery) await this.checkpoint("interval");
  }

  /**
   * Every mutation of seq, head and the leaf list happens inside this one queued step, so the
   * critical section is compute-and-append and nothing else, and concurrent turns never interleave
   * halfway through a record.
   */
  private write(
    file: string,
    chain: "main" | "sidecar",
    fields: Record<string, unknown> | ((seq: number, prev: string) => Record<string, unknown>),
  ): Promise<void> {
    const step = this.tail.then(async () => {
      // We hold the lock and we end every record with a newline, so the tail is ours to know rather
      // than to re-read. One stat says whether that belief still holds: a file that grew behind our
      // back had another writer, and then the tail is worth looking at again and worth recording.
      await this.ensureTail(file, chain);
      const notes = chain === "main" ? this.pendingNotes.splice(0, this.pendingNotes.length) : [];
      try {
        for (const note of notes) await this.writeOne(file, chain, note);
        await this.writeOne(file, chain, fields);
      } catch (error) {
        this.writtenBytes.delete(file);   // a failed write may have left anything behind
        throw error;
      }
    });
    this.tail = step.catch(() => undefined);
    return step;
  }

  private async ensureTail(file: string, chain: "main" | "sidecar"): Promise<void> {
    const expected = this.writtenBytes.get(file);
    const size = await fs.stat(file).then((st) => st.size).catch(() => null);
    if (size === null) {
      await fs.mkdir(path.dirname(file), { recursive: true });
      this.writtenBytes.set(file, 0);
      return;
    }
    if (expected === size) return;
    if (expected !== undefined && chain === "main") {
      this.pendingNotes.push({ kind: "journal.foreign-append", expectedBytes: expected, actualBytes: size });
    }
    // A crash mid-append leaves a line with no newline. Starting the next record with one keeps the
    // fragment from fusing with, and destroying, the record that follows it.
    if (await endsMidLine(file)) {
      await fs.appendFile(file, "\n");
      this.writtenBytes.set(file, size + 1);
      return;
    }
    this.writtenBytes.set(file, size);
  }

  private async writeOne(
    file: string,
    chain: "main" | "sidecar",
    fields: Record<string, unknown> | ((seq: number, prev: string) => Record<string, unknown>),
  ): Promise<void> {
    const seq = (chain === "main" ? this.seq : this.sidecarSeq) + 1;
    const prev = chain === "main" ? this.head : this.sidecarHead;
    const resolved = typeof fields === "function" ? fields(seq, prev) : fields;
    const body: Record<string, unknown> = { seq, prev, ts: this.now().toISOString(), principal: principalFor(resolved) };
    for (const [k, v] of Object.entries(resolved)) {
      if (RESERVED.has(k) && k !== "principal") continue;      // callers never set seq, prev, hash or hmac
      if (k === "principal") continue;
      body[k] = v;
    }
    const hmac = hmacHex(this.hmacKey!, canonicalJson(body));
    const withHmac = { ...body, hmac };
    const hash = sha256Hex(canonicalJson(withHmac));
    const line = canonicalJson({ ...withHmac, hash });
    await fs.appendFile(file, line + "\n", { encoding: "utf8", mode: 0o600 });
    this.writtenBytes.set(file, (this.writtenBytes.get(file) ?? 0) + Buffer.byteLength(line, "utf8") + 1);
    if (chain === "main") {
      this.seq = seq;
      this.head = hash;
      const leaf = leafHash(line);
      this.leaves.push(leaf);
      this.tree.push(leaf);
      this.sinceCheckpoint += 1;
    } else {
      this.sidecarSeq = seq;
      this.sidecarHead = hash;
    }
  }

  // ---- checkpoints and anchors -------------------------------------------

  /**
   * A checkpoint is the only record an outsider needs: an Ed25519 signature over the Merkle root of
   * everything written so far. Verifying it needs journal.pub and nothing else, and the root lets an
   * auditor check one record's inclusion without ever reading the rest of the ledger.
   */
  async checkpoint(reason: string): Promise<CheckpointInfo | null> {
    await this.open();
    if (this.state === "compromised" || this.state === "closed") return null;
    const signing = this.signing;
    if (!signing) return null;
    let info: CheckpointInfo | null = null;
    await this.write(this.journalPath, "main", (seq, prev) => {
      const treeSize = this.tree.size;
      const root = this.tree.root().toString("hex");
      const body = checkpointBody({ merkleRoot: root, prev, seq, treeSize });
      const signature = crypto.sign(null, Buffer.from(body, "utf8"), signing.privateKey).toString("base64");
      info = { seq, treeSize, merkleRoot: root, head: "", signature, body };
      return { kind: "journal.checkpoint", reason, treeSize, merkleRoot: root, signature, algorithm: "ed25519" };
    });
    this.sinceCheckpoint = 0;
    if (!info) return null;
    const complete: CheckpointInfo = { ...(info as CheckpointInfo), head: this.head };
    this.lastCheckpoint = complete;
    this.scheduleAnchors(complete, signing.publicKeyPem);
    return complete;
  }

  /**
   * Best effort by construction: it runs off the turn path, a failure is a record rather than an
   * exception, and nothing waits for it. An operator who needs the stronger guarantee reads
   * anchor.failed in the ledger, which is exactly the signal a silent retry would have destroyed.
   */
  private scheduleAnchors(checkpoint: CheckpointInfo, publicKeyPem: string): void {
    // Anchoring switched off used to return here in silence, which left the checkpoint looking
    // exactly like one whose anchors had simply not been reached yet. Measured: with
    // SHADOW_ANCHORS=none the journal carried `journal.checkpoint` and no record naming anchoring
    // at all, while a FAILING anchor wrote `anchor.failed` with its reason. So the failure was
    // honest and the absence was not, which is the wrong way round: a checkpoint is the artifact
    // that claims tamper evidence, and the reader most needs to know when nothing outside this
    // machine is holding a copy of the head.
    if (!this.anchors.length) {
      // Scheduled the same way a submission is, so it lands off the turn path and `close()` waits
      // for it through the same `anchorWork` chain rather than through a second mechanism.
      const disabled = this.writeQuietly({
        kind: "anchor.disabled",
        treeSize: checkpoint.treeSize,
        head: checkpoint.head,
        seq: checkpoint.seq,
        reason:
          "no anchor is configured (SHADOW_ANCHORS is empty, none or off), so this checkpoint is " +
          "held only on this machine and nothing outside it can testify to the head",
      });
      this.anchorWork = this.anchorWork.then(() => disabled).catch(() => undefined);
      return;
    }
    const submission: AnchorSubmission = {
      treeSize: checkpoint.treeSize,
      merkleRoot: checkpoint.merkleRoot,
      head: checkpoint.head,
      seq: checkpoint.seq,
      signature: checkpoint.signature,
      body: checkpoint.body,
      publicKey: publicKeyPem,
      ts: this.now().toISOString(),
    };
    const work = (async () => {
      for (const anchor of this.anchors) {
        try {
          const receipt = await anchor.submit(submission);
          this.lastAnchor = { treeSize: submission.treeSize, head: submission.head, seq: submission.seq };
          await this.writeQuietly({ kind: "anchor.ok", anchor: anchor.name, treeSize: submission.treeSize, receipt });
        } catch (error) {
          await this.writeQuietly({
            kind: "anchor.failed",
            anchor: anchor.name,
            treeSize: submission.treeSize,
            reason: (error as Error).message.slice(0, 300),
          });
        }
      }
    })();
    this.anchorWork = this.anchorWork.then(() => work).catch(() => undefined);
  }

  private async writeQuietly(fields: Record<string, unknown>): Promise<void> {
    const file = this.state === "compromised" ? this.sidecarPath : this.journalPath;
    const chain = this.state === "compromised" ? "sidecar" : "main";
    await this.write(file, chain, fields).catch(() => undefined);
  }

  // ---- reading ------------------------------------------------------------

  status(): {
    state: JournalState;
    records: number;
    head: string;
    problems: string[];
    checkpoint: CheckpointInfo | null;
    anchor: AnchorPoint | null;
    sidecar: string;
  } {
    return {
      state: this.state,
      records: this.seq,
      head: this.head,
      problems: this.bootProblems,
      checkpoint: this.lastCheckpoint,
      anchor: this.lastAnchor,
      sidecar: this.sidecarPath,
    };
  }

  /**
   * The audit path for one record, so an auditor can check it against a signed root alone. Sequence
   * numbers map to leaf positions because verification refuses a chain that does not start at 1 and
   * run contiguously, which is the same reason a proof means anything.
   */
  async proveInclusion(seq: number): Promise<InclusionProofResult | null> {
    await this.open();
    const index = seq - 1;
    if (index < 0 || index >= this.leaves.length) return null;
    const treeSize = this.leaves.length;
    return {
      seq,
      index,
      treeSize,
      leaf: this.leaves[index]!.toString("hex"),
      root: merkleRoot(this.leaves).toString("hex"),
      proof: inclusionProof(this.leaves, index).map((b) => b.toString("hex")),
    };
  }

  /** proof that today's ledger still contains an earlier checkpoint's ledger, unchanged */
  async proveConsistency(oldTreeSize: number): Promise<{ oldSize: number; newSize: number; proof: string[] } | null> {
    await this.open();
    if (oldTreeSize <= 0 || oldTreeSize > this.leaves.length) return null;
    return {
      oldSize: oldTreeSize,
      newSize: this.leaves.length,
      proof: consistencyProof(this.leaves, oldTreeSize).map((b) => b.toString("hex")),
    };
  }
}

/**
 * A crash partway through an append leaves a line with no newline. Starting the next record with
 * one guarantees the fragment cannot fuse with, and destroy, the record that follows it. Reading
 * the last byte rather than the whole file keeps this at constant cost as the ledger grows.
 */
async function endsMidLine(file: string): Promise<boolean> {
  const handle = await fs.open(file, "r").catch(() => null);
  if (!handle) return false;
  try {
    const { size } = await handle.stat();
    if (size === 0) return false;
    const last = Buffer.alloc(1);
    await handle.read(last, 0, 1, size - 1);
    return last[0] !== 0x0a;
  } finally {
    await handle.close();
  }
}

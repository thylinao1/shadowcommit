/**
 * Verification: walk the ledger from record one and report every break, in order.
 *
 * This is what the boot path runs before it adopts a head and what `npm run verify:journal` prints.
 * It never writes anything and it never creates a key, so it can be pointed at a journal by an
 * auditor who is not the operator.
 */
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { readAnchorLog, type AnchorPoint } from "./anchors.js";
import { MerkleAccumulator, leafHash, merkleRoot } from "./merkle.js";
import { ZERO_HEAD, canonicalJson, checkpointBody, hmacHex, sha256Hex } from "./journal-format.js";
import { defaultHome } from "./journal-keys.js";

export interface JournalProblem {
  kind: "parse" | "seq" | "link" | "hash" | "hmac" | "signature" | "merkle" | "anchor" | "key";
  /** 1-based line number in the journal file, when the problem belongs to one record */
  record: number | null;
  seq: number | null;
  message: string;
}

export interface CheckpointReport {
  seq: number;
  treeSize: number;
  merkleRoot: string;
  signature: "ok" | "bad" | "unverified";
  root: "ok" | "bad";
  ts: string | null;
}

export interface JournalReport {
  ok: boolean;
  records: number;
  /** true when every record carried an hmac that verified under the key we could resolve */
  keyed: boolean;
  head: string | null;
  lastSeq: number | null;
  problems: JournalProblem[];
  firstBreak: JournalProblem | null;
  warnings: string[];
  checkpoints: CheckpointReport[];
  anchors: { entries: number; last: AnchorPoint | null; present: boolean | null };
  /** the leaf hashes, so a caller that just verified the file can prove things about it */
  leaves: Buffer[];
  tornTailLines: number;
}

export interface VerifyOptions {
  journalPath: string;
  dataDirectory?: string;
  hmacKey?: Buffer | null;
  publicKeyPem?: string | null;
  /** a single unparseable LAST line is a crash mid-append, not tampering; default true */
  tolerateTornTail?: boolean;
  /** compare the chain against the local anchor log; default true */
  checkAnchors?: boolean;
}

/**
 * Walks the file from record one and reports every break, in order. This is the function the boot
 * path runs before it adopts a head and the function the one-command verifier prints.
 */
export async function verifyJournal(options: VerifyOptions): Promise<JournalReport> {
  const dataDirectory = options.dataDirectory ?? path.dirname(options.journalPath);
  const problems: JournalProblem[] = [];
  const warnings: string[] = [];
  const checkpoints: CheckpointReport[] = [];
  const leaves: Buffer[] = [];
  const tree = new MerkleAccumulator();
  let text: string | null = null;
  try {
    text = await fs.readFile(options.journalPath, "utf8");
  } catch {
    text = null;
  }
  const anchorPoints = options.checkAnchors === false ? [] : await readAnchorLog(dataDirectory);
  const lastAnchor = anchorPoints.length ? anchorPoints[anchorPoints.length - 1]! : null;

  if (text === null) {
    const problem: JournalProblem = { kind: "parse", record: null, seq: null, message: "journal not readable" };
    // A missing journal is only innocent when nothing ever anchored one. An anchor is the proof
    // that history existed, and it is the only thing that survives rm.
    if (lastAnchor) {
      problems.push({
        kind: "anchor",
        record: null,
        seq: null,
        message: `the journal is missing but an anchor records a chain of ${lastAnchor.treeSize} records at seq ${lastAnchor.seq}`,
      });
    } else {
      problems.push(problem);
    }
    return {
      ok: false,
      records: 0,
      keyed: false,
      head: null,
      lastSeq: null,
      problems,
      firstBreak: problems[0] ?? null,
      warnings,
      checkpoints,
      anchors: { entries: anchorPoints.length, last: lastAnchor, present: lastAnchor ? false : null },
      leaves,
      tornTailLines: 0,
    };
  }

  const lines = text.split("\n");
  // a fragment is only a fragment when the file stops in the middle of one; a complete line that
  // does not parse ended with a newline, so somebody wrote it deliberately
  const endsMidLine = text.length > 0 && !text.endsWith("\n");
  while (lines.length && lines[lines.length - 1] === "") lines.pop();
  const records: Array<{ line: string; index: number; record: Record<string, unknown> }> = [];
  let tornTailLines = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === "") continue;
    try {
      records.push({ line, index: i + 1, record: JSON.parse(line) as Record<string, unknown> });
    } catch {
      if (i === lines.length - 1 && endsMidLine && options.tolerateTornTail !== false) {
        tornTailLines += 1;
        warnings.push(`line ${i + 1} is a torn trailing record from an interrupted append`);
        continue;
      }
      problems.push({ kind: "parse", record: i + 1, seq: null, message: `line ${i + 1} is not valid JSON` });
    }
  }

  const key = options.hmacKey ?? null;
  if (!key) warnings.push("no journal key available, so the keyed layer was not checked");
  let keyed = Boolean(key);
  const seen = new Set<number>();
  let previousHash: string | null = null;
  let previousSeq: number | null = null;
  let head: string | null = null;
  let lastSeq: number | null = null;

  for (let i = 0; i < records.length; i++) {
    const { line, record, index } = records[i]!;
    const seq = typeof record.seq === "number" ? record.seq : null;
    const hash = typeof record.hash === "string" ? record.hash : null;
    const hmac = typeof record.hmac === "string" ? record.hmac : null;
    const at = { record: index, seq };

    if (seq === null) {
      problems.push({ kind: "seq", ...at, message: `record ${index} has no sequence number` });
    } else {
      if (seen.has(seq)) problems.push({ kind: "seq", ...at, message: `duplicate seq ${seq} at record ${index}` });
      seen.add(seq);
      if (previousSeq === null && seq !== 1) {
        problems.push({ kind: "seq", ...at, message: `the chain starts at seq ${seq} rather than 1` });
      }
      if (previousSeq !== null && seq !== previousSeq + 1) {
        problems.push({ kind: "seq", ...at, message: `sequence jumps from ${previousSeq} to ${seq} at record ${index}` });
      }
      previousSeq = seq;
      lastSeq = seq;
    }

    const expectedPrev = previousHash ?? ZERO_HEAD;
    if (record.prev !== expectedPrev) {
      problems.push({ kind: "link", ...at, message: `chain breaks before seq ${seq ?? "?"}` });
    }

    const { hash: _dropped, ...withoutHash } = record;
    const recomputed = sha256Hex(canonicalJson(withoutHash));
    if (recomputed !== hash) {
      problems.push({ kind: "hash", ...at, message: `record ${index} (seq ${seq ?? "?"}) hash does not match its content` });
    }

    if (key) {
      if (hmac === null) {
        keyed = false;
        problems.push({ kind: "hmac", ...at, message: `record ${index} (seq ${seq ?? "?"}) carries no hmac` });
      } else {
        const { hmac: _h, ...withoutHmac } = withoutHash;
        if (hmacHex(key, canonicalJson(withoutHmac)) !== hmac) {
          keyed = false;
          problems.push({
            kind: "hmac",
            ...at,
            message: `record ${index} (seq ${seq ?? "?"}) hmac does not verify under the journal key`,
          });
        }
      }
    }

    if (record.kind === "journal.checkpoint") {
      const treeSize = typeof record.treeSize === "number" ? record.treeSize : -1;
      const claimed = typeof record.merkleRoot === "string" ? record.merkleRoot : "";
      // the common case is a checkpoint over everything before it, which the accumulator already
      // holds; anything else is a checkpoint claiming a size it should not, so pay the full price
      const rootAt =
        treeSize === tree.size
          ? tree.root()
          : treeSize >= 0 && treeSize <= leaves.length
            ? merkleRoot(leaves.slice(0, treeSize))
            : null;
      const rootOk = rootAt !== null && rootAt.toString("hex") === claimed;
      if (!rootOk) {
        problems.push({
          kind: "merkle",
          ...at,
          message: `checkpoint at seq ${seq ?? "?"} claims a Merkle root that does not match the ${treeSize} records before it`,
        });
      }
      let signature: CheckpointReport["signature"] = "unverified";
      if (options.publicKeyPem) {
        const raw = typeof record.signature === "string" ? record.signature : "";
        let verified = false;
        try {
          verified = crypto.verify(
            null,
            Buffer.from(checkpointBody(record), "utf8"),
            crypto.createPublicKey(options.publicKeyPem),
            Buffer.from(raw, "base64"),
          );
        } catch {
          verified = false;
        }
        signature = verified ? "ok" : "bad";
        if (!verified) {
          problems.push({
            kind: "signature",
            ...at,
            message: `checkpoint at seq ${seq ?? "?"} has a signature that does not verify against the published key`,
          });
        }
      }
      checkpoints.push({
        seq: seq ?? -1,
        treeSize,
        merkleRoot: claimed,
        signature,
        root: rootOk ? "ok" : "bad",
        ts: typeof record.ts === "string" ? record.ts : null,
      });
    }

    const leaf = leafHash(line);
    leaves.push(leaf);
    tree.push(leaf);
    previousHash = hash;
    head = hash;
  }

  let anchorPresent: boolean | null = null;
  if (lastAnchor) {
    const hashes = new Set(records.map((r) => (typeof r.record.hash === "string" ? r.record.hash : "")));
    anchorPresent = hashes.has(lastAnchor.head) && records.length >= lastAnchor.treeSize;
    if (!anchorPresent) {
      problems.push({
        kind: "anchor",
        record: null,
        seq: lastAnchor.seq,
        message: `the last anchored head (seq ${lastAnchor.seq}, ${lastAnchor.treeSize} records) is not in this journal`,
      });
    }
  }

  return {
    ok: problems.length === 0,
    records: records.length,
    keyed,
    head,
    lastSeq,
    problems,
    firstBreak: problems[0] ?? null,
    warnings,
    checkpoints,
    anchors: { entries: anchorPoints.length, last: lastAnchor, present: anchorPresent },
    leaves,
    tornTailLines,
  };
}

/**
 * Verification with the key material resolved the way the journal resolves it, but read only: this
 * never creates a key, because a verifier that can mint the key it checks against proves nothing.
 * A missing key gives a report that says the keyed layer was not checked, rather than a pass.
 */
export async function verifyJournalAt(
  journalPath: string,
  options: {
    dataDirectory?: string;
    home?: string;
    keyFile?: string;
    publicKeyFile?: string;
    hmacKey?: Buffer | string;
    env?: NodeJS.ProcessEnv;
    checkAnchors?: boolean;
  } = {},
): Promise<JournalReport> {
  const env = options.env ?? process.env;
  const resolved = path.resolve(journalPath);
  const dataDirectory = path.resolve(options.dataDirectory ?? path.dirname(resolved));
  const home = options.home ? path.resolve(options.home) : defaultHome(env);
  const keyFile = path.resolve(options.keyFile ?? env.SHADOW_JOURNAL_KEY_FILE?.trim() ?? path.join(home, "journal.key"));
  const publicKeyFile = path.resolve(
    options.publicKeyFile ?? env.SHADOW_JOURNAL_PUBKEY_FILE?.trim() ?? path.join(dataDirectory, "journal.pub"),
  );
  let key: Buffer | null = null;
  if (options.hmacKey !== undefined) {
    key = Buffer.isBuffer(options.hmacKey) ? options.hmacKey : Buffer.from(options.hmacKey, "utf8");
  } else if (env.SHADOW_JOURNAL_KEY?.trim()) {
    key = Buffer.from(env.SHADOW_JOURNAL_KEY.trim(), "utf8");
  } else {
    const text = await fs.readFile(keyFile, "utf8").catch(() => null);
    if (text && text.trim().length >= 32) key = Buffer.from(text.trim(), "utf8");
  }
  const publicKeyPem = await fs.readFile(publicKeyFile, "utf8").catch(() => null);
  return verifyJournal({
    journalPath: resolved,
    dataDirectory,
    hmacKey: key,
    publicKeyPem,
    checkAnchors: options.checkAnchors !== false,
  });
}

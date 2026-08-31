/**
 * External anchors for the journal's signed checkpoints.
 *
 * A hash chain proves internal consistency and nothing else: whoever can rewrite the file can
 * rewrite it consistently from record one, and whoever can delete it leaves a fresh chain that
 * looks like a new deployment. The only fix is to put the checkpoint head somewhere the operator
 * does not control, before the operator would want to change it. That is all an anchor is.
 *
 * Three of them, because they fail in different ways:
 *   git   local anchors.jsonl plus a git note, legible to anyone who can read a repository, and
 *         once pushed it is mirrored wherever the remote is
 *   rekor Sigstore's public transparency log, itself append-only and independently monitored
 *   ots   OpenTimestamps, a Bitcoin-anchored proof of existence at a time where only a hash leaves
 *         the machine
 *
 * Anchoring is best effort by construction. It runs off the turn path, it never blocks a turn, and
 * whether it succeeded or failed is itself a journal record, so a stretch of missing anchors is
 * visible rather than silent.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";

const execFileAsync = promisify(execFile);

/** what a checkpoint publishes: enough to verify the signature and to place the log in time */
export interface AnchorSubmission {
  treeSize: number;
  /** hex sha256 Merkle root over every record up to treeSize */
  merkleRoot: string;
  /** hex hash of the checkpoint record itself, the chain head it pins */
  head: string;
  seq: number;
  /** base64 Ed25519 signature over `body` */
  signature: string;
  /** the exact canonical bytes the signature covers, so anyone holding this line can re-verify it */
  body: string;
  /** SPKI PEM of the signing key, the same bytes as <dataDirectory>/journal.pub */
  publicKey: string;
  ts: string;
}

/** the last checkpoint an anchor can still see, used at boot to catch a deleted journal */
export interface AnchorPoint {
  treeSize: number;
  head: string;
  seq: number;
}

export interface Anchor {
  readonly name: string;
  /** resolves with receipt detail for the journal, rejects with the reason on failure */
  submit(submission: AnchorSubmission): Promise<Record<string, unknown>>;
  /** what this anchor knows locally without a network call, when it can know anything */
  lastKnown?(): Promise<AnchorPoint | null>;
}

/** minimal structural shape of fetch, so tests inject a server without a network or DOM types */
export type FetchLike = (
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string | Uint8Array;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}>;

export type ExecLike = (file: string, args: string[]) => Promise<{ stdout: string }>;

const DEFAULT_TIMEOUT_MS = 10_000;

export function anchorLogPath(dataDirectory: string): string {
  return path.join(dataDirectory, "anchors.jsonl");
}

/**
 * Every anchor point this machine has a local record of, newest last. Read at boot even when
 * anchoring is switched off, because the question it answers is "did a journal exist and reach
 * sequence N", and turning anchoring off afterwards must not erase that answer.
 */
export async function readAnchorLog(dataDirectory: string): Promise<AnchorPoint[]> {
  const text = await fs.readFile(anchorLogPath(dataDirectory), "utf8").catch(() => "");
  const points: AnchorPoint[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line) as Partial<AnchorPoint>;
      if (typeof rec.treeSize === "number" && typeof rec.head === "string" && typeof rec.seq === "number") {
        points.push({ treeSize: rec.treeSize, head: rec.head, seq: rec.seq });
      }
    } catch {
      /* a torn anchor line proves nothing; the remaining ones still do */
    }
  }
  return points;
}

/**
 * The local half of anchoring: an append-only anchors.jsonl beside the journal, plus a git note on
 * HEAD when the data directory sits inside a repository. The file alone is not a strong anchor (the
 * same hand can edit both), which is exactly why it is the cheapest of the three and never the only
 * one in a deployment. Its real job is the boot check: a journal shorter than the anchor log is a
 * deleted journal, and that is detectable with no network at all.
 */
export class GitAnchor implements Anchor {
  readonly name = "git";

  constructor(
    private readonly opts: {
      dataDirectory: string;
      /** attach a git note on HEAD as well, when the data directory is inside a repository */
      gitNotes?: boolean;
      exec?: ExecLike;
      notesRef?: string;
    },
  ) {}

  async submit(submission: AnchorSubmission): Promise<Record<string, unknown>> {
    const file = anchorLogPath(this.opts.dataDirectory);
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.appendFile(file, JSON.stringify(submission) + "\n", { encoding: "utf8", mode: 0o600 });
    const detail: Record<string, unknown> = { file };
    if (this.opts.gitNotes === false) return detail;
    const exec = this.opts.exec ?? ((f, a) => execFileAsync(f, a));
    let top: string;
    try {
      const { stdout } = await exec("git", ["-C", this.opts.dataDirectory, "rev-parse", "--show-toplevel"]);
      top = stdout.trim();
    } catch {
      return { ...detail, gitNote: "not a git repository" };   // the file anchor still stands
    }
    const ref = this.opts.notesRef ?? "shadow-commit";
    try {
      // append, never replace: an anchor that can overwrite an earlier anchor is not an anchor.
      //
      // The identity is passed explicitly because `git notes append` writes an object and refuses
      // without a committer. A machine with no global git config, which is every CI runner and every
      // container, produced "Committer identity unknown", the catch below turned it into a degraded
      // receipt, and the anchor never landed. That failed silently everywhere except a developer
      // laptop that happened to have a global identity, which is the worst possible place for a
      // tamper-evidence feature to work.
      await exec("git", [
        "-C", top,
        "-c", "user.name=shadow-commit",
        "-c", "user.email=shadow-commit@localhost",
        "-c", "commit.gpgsign=false",
        "notes", "--ref", ref, "append", "-m", JSON.stringify(submission), "HEAD",
      ]);
      const { stdout } = await exec("git", ["-C", top, "rev-parse", "HEAD"]);
      return { ...detail, repository: top, notesRef: ref, commit: stdout.trim() };
    } catch (error) {
      return { ...detail, repository: top, gitNote: `failed: ${(error as Error).message}` };
    }
  }

  async lastKnown(): Promise<AnchorPoint | null> {
    const points = await readAnchorLog(this.opts.dataDirectory);
    return points.length ? points[points.length - 1]! : null;
  }
}

/**
 * Sigstore Rekor. The public instance is an append-only transparency log with its own monitors, so
 * an entry there is a claim we cannot retract.
 *
 * One wrinkle worth stating rather than hiding: a `hashedrekord` asks the log to verify a signature
 * given only the artifact's digest, and Ed25519 signs the message rather than its hash, so a public
 * Rekor rejects an Ed25519 hashedrekord. We submit the hashedrekord the design calls for, and when
 * the log refuses it for that reason we resubmit the same checkpoint as a `rekord` with the body
 * inline. The body is the root hash, the sequence and the tree size, so nothing about the journal's
 * contents leaves the machine either way. Which kind was accepted is in the receipt.
 */
export class RekorAnchor implements Anchor {
  readonly name = "rekor";

  constructor(
    private readonly opts: {
      baseUrl?: string;
      fetch?: FetchLike;
      timeoutMs?: number;
    } = {},
  ) {}

  private get base(): string {
    return (this.opts.baseUrl ?? "https://rekor.sigstore.dev").replace(/\/+$/, "");
  }

  async submit(submission: AnchorSubmission): Promise<Record<string, unknown>> {
    const doFetch = this.opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
    if (!doFetch) throw new Error("no fetch available for the rekor anchor");
    const publicKey = Buffer.from(submission.publicKey, "utf8").toString("base64");
    const hashed = {
      apiVersion: "0.0.1",
      kind: "hashedrekord",
      spec: {
        data: { hash: { algorithm: "sha256", value: submission.merkleRoot } },
        signature: { content: submission.signature, publicKey: { content: publicKey } },
      },
    };
    const first = await this.post(doFetch, hashed);
    if (first.ok) return { ...this.receipt(first.body), kind: "hashedrekord" };

    const retryable = first.status >= 400 && first.status < 500;
    if (!retryable) throw new Error(`rekor rejected the entry: ${first.status} ${first.body.slice(0, 200)}`);
    const inline = {
      apiVersion: "0.0.1",
      kind: "rekord",
      spec: {
        data: { content: Buffer.from(submission.body, "utf8").toString("base64") },
        signature: {
          format: "ed25519",
          content: submission.signature,
          publicKey: { content: publicKey },
        },
      },
    };
    const second = await this.post(doFetch, inline);
    if (!second.ok) {
      throw new Error(
        `rekor rejected both entry kinds: hashedrekord ${first.status}, rekord ${second.status} ${second.body.slice(0, 200)}`,
      );
    }
    return { ...this.receipt(second.body), kind: "rekord", hashedrekordStatus: first.status };
  }

  private async post(
    doFetch: FetchLike,
    entry: unknown,
  ): Promise<{ ok: boolean; status: number; body: string }> {
    const res = await doFetch(`${this.base}/api/v1/log/entries`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(entry),
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    return { ok: res.ok, status: res.status, body: await res.text() };
  }

  /** Rekor answers with an object keyed by entry UUID; the useful parts are the index and time */
  private receipt(body: string): Record<string, unknown> {
    try {
      const parsed = JSON.parse(body) as Record<string, Record<string, unknown>>;
      const uuid = Object.keys(parsed)[0];
      if (!uuid) return { raw: body.slice(0, 200) };
      const entry = parsed[uuid] ?? {};
      return {
        uuid,
        logIndex: entry.logIndex,
        integratedTime: entry.integratedTime,
        logID: entry.logID,
        url: `${this.base}/api/v1/log/entries/${uuid}`,
      };
    } catch {
      return { raw: body.slice(0, 200) };
    }
  }
}

/** the 31 byte detached-proof magic, then the major version, then the file hash operation */
const OTS_MAGIC = Buffer.concat([
  Buffer.from([0x00]),
  Buffer.from("OpenTimestamps", "utf8"),
  Buffer.from([0x00, 0x00]),
  Buffer.from("Proof", "utf8"),
  Buffer.from([0x00]),
  Buffer.from([0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]),
]);
const OTS_MAJOR_VERSION = 0x01;
const OTS_OP_SHA256 = 0x08;

/**
 * OpenTimestamps. Only a 32 byte digest leaves the machine, and what comes back is the serialized
 * timestamp for that digest: a pending attestation now, upgradeable into a Bitcoin block header
 * proof once the calendar's next aggregation confirms. We frame it into a detached .ots file, which
 * is what the standard client reads.
 */
export class OtsAnchor implements Anchor {
  readonly name = "ots";

  constructor(
    private readonly opts: {
      dataDirectory: string;
      /** calendar servers, tried in order until one answers */
      calendars?: string[];
      fetch?: FetchLike;
      timeoutMs?: number;
    },
  ) {}

  private get calendars(): string[] {
    return this.opts.calendars ?? [
      "https://alice.btc.calendar.opentimestamps.org",
      "https://bob.btc.calendar.opentimestamps.org",
      "https://finney.calendar.eternitywall.com",
    ];
  }

  async submit(submission: AnchorSubmission): Promise<Record<string, unknown>> {
    const doFetch = this.opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
    if (!doFetch) throw new Error("no fetch available for the ots anchor");
    const digest = Buffer.from(submission.merkleRoot, "hex");
    if (digest.length !== 32) throw new Error(`merkle root is not a 32 byte sha256: ${submission.merkleRoot}`);
    const failures: string[] = [];
    for (const calendar of this.calendars) {
      const base = calendar.replace(/\/+$/, "");
      try {
        const res = await doFetch(`${base}/digest`, {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            accept: "application/vnd.opentimestamps.v1",
          },
          body: new Uint8Array(digest),
          signal: AbortSignal.timeout(this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
        });
        if (!res.ok) {
          failures.push(`${base} ${res.status}`);
          continue;
        }
        const timestamp = Buffer.from(await res.arrayBuffer());
        const proof = Buffer.concat([
          OTS_MAGIC,
          Buffer.from([OTS_MAJOR_VERSION, OTS_OP_SHA256]),
          digest,
          timestamp,
        ]);
        const dir = path.join(this.opts.dataDirectory, "anchors");
        await fs.mkdir(dir, { recursive: true });
        const file = path.join(dir, `checkpoint-${submission.treeSize}.ots`);
        await fs.writeFile(file, proof, { mode: 0o600 });
        return { calendar: base, file, bytes: proof.length, pending: true };
      } catch (error) {
        failures.push(`${base} ${(error as Error).message}`);
      }
    }
    throw new Error(`no opentimestamps calendar answered: ${failures.join("; ")}`);
  }
}

/**
 * SHADOW_ANCHORS picks the anchors, default git only. Rekor and OpenTimestamps are network calls,
 * so they are opt in: a platform that has not decided to publish its heads should not start
 * publishing them because a library defaulted to it.
 */
export function anchorsFromEnv(dataDirectory: string, env: NodeJS.ProcessEnv = process.env): Anchor[] {
  const raw = (env.SHADOW_ANCHORS ?? "git").trim();
  if (!raw || raw === "none" || raw === "off") return [];
  const wanted = new Set(raw.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean));
  const anchors: Anchor[] = [];
  if (wanted.has("git")) {
    anchors.push(new GitAnchor({ dataDirectory, gitNotes: env.SHADOW_ANCHOR_GIT_NOTES !== "0" }));
  }
  if (wanted.has("rekor")) {
    anchors.push(new RekorAnchor({ baseUrl: env.SHADOW_REKOR_URL ?? "https://rekor.sigstore.dev" }));
  }
  if (wanted.has("ots")) {
    const calendars = env.SHADOW_OTS_CALENDARS?.split(",").map((s) => s.trim()).filter(Boolean);
    anchors.push(new OtsAnchor(calendars?.length ? { dataDirectory, calendars } : { dataDirectory }));
  }
  return anchors;
}

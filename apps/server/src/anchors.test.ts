import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import {
  GitAnchor,
  OtsAnchor,
  RekorAnchor,
  anchorLogPath,
  anchorsFromEnv,
  readAnchorLog,
  type AnchorSubmission,
  type FetchLike,
} from "./anchors.js";

const execFileAsync = promisify(execFile);

const submission = (extra: Partial<AnchorSubmission> = {}): AnchorSubmission => ({
  treeSize: 64,
  merkleRoot: "a".repeat(64),
  head: "b".repeat(64),
  seq: 65,
  signature: "c2lnbmF0dXJl",
  body: '{"kind":"journal.checkpoint","merkleRoot":"aaa","prev":"bbb","seq":65,"treeSize":64}',
  publicKey: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n",
  ts: "2026-08-29T00:00:00.000Z",
  ...extra,
});

interface Call {
  url: string;
  body: string | Uint8Array | undefined;
}

function mockFetch(responses: Array<{ ok?: boolean; status: number; text?: string; bytes?: Buffer }>): {
  fetch: FetchLike;
  calls: Call[];
} {
  const calls: Call[] = [];
  let index = 0;
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, body: init?.body });
    const response = responses[Math.min(index++, responses.length - 1)]!;
    return {
      ok: response.ok ?? (response.status >= 200 && response.status < 300),
      status: response.status,
      text: async () => response.text ?? "",
      arrayBuffer: async () => {
        const bytes = response.bytes ?? Buffer.alloc(0);
        return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
      },
    };
  };
  return { fetch, calls };
}

async function tempDir(prefix: string): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

describe("the git anchor", () => {
  it("appends the checkpoint to anchors.jsonl and reads the last point back", async () => {
    const dir = await tempDir("anchor-git-");
    const anchor = new GitAnchor({ dataDirectory: dir, gitNotes: false });
    await anchor.submit(submission());
    await anchor.submit(submission({ treeSize: 128, seq: 130, head: "d".repeat(64) }));
    const points = await readAnchorLog(dir);
    expect(points).toHaveLength(2);
    expect(await anchor.lastKnown()).toEqual({ treeSize: 128, head: "d".repeat(64), seq: 130 });
    expect((await fs.stat(anchorLogPath(dir))).mode & 0o777).toBe(0o600);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("appends a git note on HEAD when the data directory is inside a repository", async () => {
    const repo = await tempDir("anchor-repo-");
    const git = (...args: string[]) => execFileAsync("git", ["-C", repo, ...args]);
    await git("init", "-q");
    // deliberately NO user.name or user.email in this repo's config: the anchor has to work on a
    // machine with no git identity, which is every CI runner and every container. Setting one here
    // would hide the defect this test exists to catch.
    await git("-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "seed");
    const data = path.join(repo, ".data");
    await fs.mkdir(data, { recursive: true });

    const receipt = await new GitAnchor({ dataDirectory: data }).submit(submission());
    // `repository` is set on the FAILURE path too (the degraded receipt names the repo it could not
    // note), so asserting it alone let a silent non-anchor pass. These two say the note landed.
    expect(receipt.repository).toBeTruthy();
    expect(receipt.gitNote).toBeUndefined();
    expect(receipt.commit).toBeTruthy();
    const { stdout } = await git("notes", "--ref", "shadow-commit", "show", "HEAD");
    expect(JSON.parse(stdout.trim()).merkleRoot).toBe("a".repeat(64));
    await fs.rm(repo, { recursive: true, force: true });
  });

  it("still anchors to the file when there is no repository to note", async () => {
    const dir = await tempDir("anchor-norepo-");
    const receipt = await new GitAnchor({
      dataDirectory: dir,
      exec: async () => {
        throw new Error("fatal: not a git repository");
      },
    }).submit(submission());
    expect(receipt.gitNote).toBe("not a git repository");
    expect(await readAnchorLog(dir)).toHaveLength(1);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("never replaces an earlier note, it appends to it", async () => {
    const dir = await tempDir("anchor-append-");
    const argv: string[][] = [];
    await new GitAnchor({
      dataDirectory: dir,
      exec: async (_file, args) => {
        argv.push(args);
        return { stdout: args.includes("--show-toplevel") ? "/repo\n" : "deadbeef\n" };
      },
    }).submit(submission());
    const notes = argv.find((args) => args.includes("notes"));
    expect(notes).toContain("append");
    expect(notes).not.toContain("-f");
    await fs.rm(dir, { recursive: true, force: true });
  });
});

describe("the rekor anchor", () => {
  it("submits a hashedrekord carrying the root, the signature and the public key", async () => {
    const { fetch, calls } = mockFetch([
      { status: 201, text: JSON.stringify({ "24296fb2abc": { logIndex: 91827, integratedTime: 1787000000, logID: "c0d23d" } }) },
    ]);
    const receipt = await new RekorAnchor({ baseUrl: "https://rekor.example/", fetch }).submit(submission());
    expect(calls[0]!.url).toBe("https://rekor.example/api/v1/log/entries");
    const sent = JSON.parse(String(calls[0]!.body)) as Record<string, any>;
    expect(sent.kind).toBe("hashedrekord");
    expect(sent.spec.data.hash).toEqual({ algorithm: "sha256", value: "a".repeat(64) });
    expect(sent.spec.signature.content).toBe("c2lnbmF0dXJl");
    expect(Buffer.from(sent.spec.signature.publicKey.content, "base64").toString()).toContain("BEGIN PUBLIC KEY");
    expect(receipt).toMatchObject({ uuid: "24296fb2abc", logIndex: 91827, kind: "hashedrekord" });
    expect(receipt.url).toBe("https://rekor.example/api/v1/log/entries/24296fb2abc");
  });

  it("falls back to an inline rekord when the log refuses a digest-only ed25519 entry", async () => {
    const { fetch, calls } = mockFetch([
      { status: 400, text: '{"code":400,"message":"ed25519 unsupported for hashedrekord"}' },
      { status: 201, text: JSON.stringify({ deadbeef: { logIndex: 5, integratedTime: 2 } }) },
    ]);
    const receipt = await new RekorAnchor({ baseUrl: "https://rekor.example", fetch }).submit(submission());
    expect(calls).toHaveLength(2);
    const second = JSON.parse(String(calls[1]!.body)) as Record<string, any>;
    expect(second.kind).toBe("rekord");
    // the inline entry carries the exact bytes the signature covers, or the log cannot check it
    expect(Buffer.from(second.spec.data.content, "base64").toString()).toBe(submission().body);
    expect(receipt).toMatchObject({ kind: "rekord", hashedrekordStatus: 400, logIndex: 5 });
  });

  it("reports the failure rather than pretending an entry landed", async () => {
    const { fetch } = mockFetch([{ status: 503, text: "upstream unavailable" }]);
    await expect(new RekorAnchor({ baseUrl: "https://rekor.example", fetch }).submit(submission())).rejects.toThrow(
      /rekor rejected the entry: 503/,
    );
    const both = mockFetch([
      { status: 400, text: "no" },
      { status: 422, text: "still no" },
    ]);
    await expect(
      new RekorAnchor({ baseUrl: "https://rekor.example", fetch: both.fetch }).submit(submission()),
    ).rejects.toThrow(/hashedrekord 400, rekord 422/);
  });
});

describe("the opentimestamps anchor", () => {
  const magic = Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from("OpenTimestamps", "utf8"),
    Buffer.from([0x00, 0x00]),
    Buffer.from("Proof", "utf8"),
    Buffer.from([0x00]),
    Buffer.from([0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]),
  ]);

  it("sends only the digest and frames the calendar's answer into a detached proof", async () => {
    const dir = await tempDir("anchor-ots-");
    const body = Buffer.from([0xf0, 0x10, 0x08, 0x99]);
    const { fetch, calls } = mockFetch([{ status: 200, bytes: body }]);
    const root = "9".repeat(64);
    const receipt = await new OtsAnchor({ dataDirectory: dir, calendars: ["https://calendar.example/"], fetch }).submit(
      submission({ merkleRoot: root }),
    );
    expect(calls[0]!.url).toBe("https://calendar.example/digest");
    expect(Buffer.from(calls[0]!.body as Uint8Array)).toEqual(Buffer.from(root, "hex"));

    const proof = await fs.readFile(path.join(dir, "anchors", "checkpoint-64.ots"));
    expect(proof.subarray(0, magic.length)).toEqual(magic);
    expect(proof[magic.length]).toBe(0x01);                       // major version
    expect(proof[magic.length + 1]).toBe(0x08);                   // sha256 file-hash operation
    expect(proof.subarray(magic.length + 2, magic.length + 34)).toEqual(Buffer.from(root, "hex"));
    expect(proof.subarray(magic.length + 34)).toEqual(body);
    expect(receipt).toMatchObject({ calendar: "https://calendar.example", pending: true });
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("moves to the next calendar when one is down, and reports when none answer", async () => {
    const dir = await tempDir("anchor-ots-fail-");
    const { fetch, calls } = mockFetch([
      { status: 502, text: "bad gateway" },
      { status: 200, bytes: Buffer.from([0x01]) },
    ]);
    await new OtsAnchor({ dataDirectory: dir, calendars: ["https://down.example", "https://up.example"], fetch }).submit(
      submission(),
    );
    expect(calls.map((call) => call.url)).toEqual(["https://down.example/digest", "https://up.example/digest"]);

    const dead = mockFetch([{ status: 500, text: "" }]);
    await expect(
      new OtsAnchor({ dataDirectory: dir, calendars: ["https://a.example", "https://b.example"], fetch: dead.fetch }).submit(
        submission(),
      ),
    ).rejects.toThrow(/no opentimestamps calendar answered/);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("refuses a root that is not a sha256 digest", async () => {
    const dir = await tempDir("anchor-ots-bad-");
    const { fetch } = mockFetch([{ status: 200, bytes: Buffer.alloc(1) }]);
    await expect(
      new OtsAnchor({ dataDirectory: dir, calendars: ["https://a.example"], fetch }).submit(submission({ merkleRoot: "abcd" })),
    ).rejects.toThrow(/not a 32 byte sha256/);
    await fs.rm(dir, { recursive: true, force: true });
  });
});

/**
 * The mocked-fetch tests above pin the protocol. These two run the same code against a real HTTP
 * server on loopback through the runtime's own fetch, because that is where a real bug would hide:
 * a body the runtime will not send, a header it rewrites, a timeout signal it does not support.
 */
describe("against a real server on loopback", () => {
  const serve = async (
    handler: (body: Buffer, req: http.IncomingMessage, res: http.ServerResponse) => void,
  ): Promise<{ url: string; close: () => Promise<void> }> => {
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => handler(Buffer.concat(chunks), req, res));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (typeof address === "string" || address === null) throw new Error("no port");
    return {
      url: `http://127.0.0.1:${address.port}`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  };

  it("posts a real hashedrekord and reads the log index back", async () => {
    let received: Record<string, any> | null = null;
    let contentType = "";
    const server = await serve((body, req, res) => {
      received = JSON.parse(body.toString("utf8")) as Record<string, any>;
      contentType = String(req.headers["content-type"]);
      res.writeHead(201, { "content-type": "application/json" });
      res.end(JSON.stringify({ "24296fb2f": { logIndex: 42, integratedTime: 1787000000 } }));
    });
    const receipt = await new RekorAnchor({ baseUrl: server.url }).submit(submission());
    expect(receipt).toMatchObject({ uuid: "24296fb2f", logIndex: 42, kind: "hashedrekord" });
    expect(contentType).toBe("application/json");
    expect(received!.spec.data.hash.value).toBe("a".repeat(64));
    await server.close();
  });

  it("posts the raw digest to a real calendar and writes the proof it answers with", async () => {
    const dir = await tempDir("anchor-ots-live-");
    let received: Buffer = Buffer.alloc(0);
    const answer = Buffer.from([0xf0, 0x10, 0xf1, 0x04, 0x7a, 0xbc]);
    const server = await serve((body, _req, res) => {
      received = body;
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(answer);
    });
    const root = "7".repeat(64);
    await new OtsAnchor({ dataDirectory: dir, calendars: [server.url] }).submit(submission({ merkleRoot: root }));
    expect(received).toEqual(Buffer.from(root, "hex"));           // 32 bytes, nothing else
    const proof = await fs.readFile(path.join(dir, "anchors", "checkpoint-64.ots"));
    expect(proof.subarray(proof.length - answer.length)).toEqual(answer);
    await server.close();
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("reports a calendar that hangs up rather than hanging the journal", async () => {
    const dir = await tempDir("anchor-ots-dead-");
    const server = await serve((_body, _req, res) => {
      res.destroy();
    });
    await expect(
      new OtsAnchor({ dataDirectory: dir, calendars: [server.url], timeoutMs: 2000 }).submit(submission()),
    ).rejects.toThrow(/no opentimestamps calendar answered/);
    await server.close();
    await fs.rm(dir, { recursive: true, force: true });
  });
});

describe("choosing anchors", () => {
  it("anchors to git alone by default, so nothing reaches the network unasked", () => {
    expect(anchorsFromEnv("/data", {}).map((anchor) => anchor.name)).toEqual(["git"]);
  });

  it("adds the public logs only when the deployment asks for them", () => {
    expect(anchorsFromEnv("/data", { SHADOW_ANCHORS: "git,rekor,ots" }).map((a) => a.name)).toEqual(["git", "rekor", "ots"]);
    expect(anchorsFromEnv("/data", { SHADOW_ANCHORS: "none" })).toEqual([]);
    expect(anchorsFromEnv("/data", { SHADOW_ANCHORS: "rekor" }).map((a) => a.name)).toEqual(["rekor"]);
  });
});

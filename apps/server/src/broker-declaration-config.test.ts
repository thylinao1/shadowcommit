import { afterEach, beforeEach, describe, expect, it } from "vitest";
import http from "node:http";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { startBroker, vetReadOnlyDeclarations } from "../broker/server.mjs";
import { type ReadOnlyDeclaration, buildBrokerLaunchConfig } from "./broker.js";

/**
 * The declaration list is CONFIG, and config arrives from a JSON file a person may have written by
 * hand. So it can be any JSON value at all, its patterns are operator-supplied regular expressions
 * run against a path the agent chooses, and its entries name a host while the allowlist names a
 * host AND a port. Each of those three is a way a config file reaches into the request path, and
 * each has its own test here.
 *
 * Every assertion that something is refused is paired with the same shape accepted, differing only
 * in the axis under test, so a build that threw the whole declaration mechanism away would fail
 * this file rather than pass it.
 */

interface Recorder {
  server: http.Server;
  port: number;
  seen: Array<{ method: string; url: string; body: string }>;
}

async function recorder(): Promise<Recorder> {
  const seen: Recorder["seen"] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  return { server, port: (server.address() as net.AddressInfo).port, seen };
}

function throughProxy(proxyPort: number, method: string, url: string, body = "") {
  const target = new URL(url);
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method,
        path: url,
        headers: { host: target.host, "content-length": Buffer.byteLength(body) },
      },
      (res) => {
        let text = "";
        res.on("data", (chunk) => (text += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

describe("a broker.json the operator hand-wrote cannot take the turn down", () => {
  let tmp: string;
  let collector: Recorder;
  let broker: Awaited<ReturnType<typeof startBroker>> | null;

  const start = (readOnlyDeclarations: unknown) =>
    startBroker({
      proxyPort: 0,
      modelPort: 0,
      host: "127.0.0.1",
      allowlist: ["127.0.0.1:" + collector.port],
      readOnlyDeclarations,
      decoyHost: "status.shadow-decoy.test",
      modelUpstream: "http://127.0.0.1:1/v1",
      providerKey: "FIXTURE-KEY-NOT-REAL",
      turnToken: "shadow-turn-FIXTURE-NOT-REAL",
      logPath: path.join(tmp, "egress.jsonl"),
      heldPath: path.join(tmp, "held.jsonl"),
      pendingDir: path.join(tmp, "pending"),
      corpus: {},
    });

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-decl-"));
    collector = await recorder();
    broker = null;
  });

  afterEach(async () => {
    if (broker) await broker.close();
    await new Promise<void>((resolve) => collector.server.close(() => resolve()));
    await fs.rm(tmp, { recursive: true, force: true });
  });

  // The defect: the per-entry matcher is defensive, the loop around it was not. A field that is an
  // object rather than an array threw inside the request handler, so the write got no answer, the
  // journal got no row, and the broker process died on an unhandled rejection. Failing closed has
  // to mean the write is held, not that the turn is destroyed by a typo in a config file.
  const malformed: Array<[string, unknown]> = [
    ["an object keyed by host, the shape of the old pattern map", { "registry.npmjs.org": ["^/-/.*$"] }],
    ["a number", 7],
    ["a single declaration written without its array", { host: "127.0.0.1", methods: ["POST"], pattern: "^/catalog$" }],
    ["a string", "^/catalog$"],
  ];

  for (const [label, value] of malformed) {
    it("holds the write and journals it when readOnlyDeclarations is " + label, async () => {
      broker = await start(value);
      const response = await throughProxy(
        broker.proxyPort,
        "POST",
        "http://127.0.0.1:" + collector.port + "/catalog",
        JSON.stringify({ note: "ordinary work" }),
      );
      expect(response.status).toBe(202);
      expect(collector.seen).toHaveLength(0);
      expect(broker.decisions().at(-1)).toMatchObject({ decision: "HELD", class: "write-like" });
      expect(broker.declarationIssues.map((issue) => issue.why).join(" ")).toMatch(/not a list/);
    });
  }

  it("still serves a GET while the declaration list is malformed, so an install is not collateral", async () => {
    broker = await start(42);
    const response = await throughProxy(
      broker.proxyPort,
      "GET",
      "http://127.0.0.1:" + collector.port + "/left-pad/-/left-pad-1.3.0.tgz",
    );
    expect(response.status).toBe(200);
    expect(collector.seen).toHaveLength(1);
    expect(broker.decisions().at(-1)).toMatchObject({ decision: "LIVE", class: "read-like" });
  });

  // The negative case for the whole group: a well-formed list is still honoured, so the coercion
  // above did not simply switch declarations off.
  it("still sends a declared write live when the list is well formed", async () => {
    broker = await start([
      { host: "127.0.0.1", port: collector.port, methods: ["POST"], pattern: "^/catalog$" },
    ]);
    const response = await throughProxy(
      broker.proxyPort,
      "POST",
      "http://127.0.0.1:" + collector.port + "/catalog",
      JSON.stringify({ note: "ordinary work" }),
    );
    expect(response.status).toBe(200);
    expect(collector.seen).toHaveLength(1);
    expect(broker.declarationIssues).toEqual([]);
    expect(broker.decisions().at(-1)).toMatchObject({ decision: "LIVE", class: "read-like" });
  });

  // The pattern is operator-supplied and the path is agent-supplied, and they meet in a regular
  // expression engine on the same event loop that serves the model channel. `^/(a+)+b$` on a path
  // of 32 a-characters is 25 seconds of blocked loop on this machine, and every added character
  // doubles it: code inside the sandbox picks the path, so it picks the stall.
  it("refuses a pattern whose backtracking the agent could drive, and holds the write instead", async () => {
    broker = await start([
      { host: "127.0.0.1", port: collector.port, methods: ["POST"], pattern: "^/(a+)+b$" },
    ]);
    expect(broker.declarationIssues.map((issue) => issue.why).join(" ")).toMatch(/quantifier/);
    const started = Date.now();
    const response = await throughProxy(
      broker.proxyPort,
      "POST",
      "http://127.0.0.1:" + collector.port + "/" + "a".repeat(32),
      "x",
    );
    expect(Date.now() - started).toBeLessThan(3000);
    expect(response.status).toBe(202);
    expect(collector.seen).toHaveLength(0);
  });

  // The negative case for that refusal: the quantified group an operator actually writes is a
  // bounded one, and it keeps working.
  it("keeps the bounded quantified group operators actually write", async () => {
    broker = await start([
      { host: "127.0.0.1", port: collector.port, methods: ["POST"], pattern: "^/catalog(\\?.*)?$" },
    ]);
    expect(broker.declarationIssues).toEqual([]);
    const response = await throughProxy(
      broker.proxyPort,
      "POST",
      "http://127.0.0.1:" + collector.port + "/catalog?page=2",
      "x",
    );
    expect(response.status).toBe(200);
    expect(collector.seen).toHaveLength(1);
  });
});

describe("a declaration is scoped to the port it names, as the allowlist is", () => {
  let tmp: string;
  let declared: Recorder;
  let other: Recorder;
  let broker: Awaited<ReturnType<typeof startBroker>>;

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-declport-"));
    declared = await recorder();
    other = await recorder();
    broker = await startBroker({
      proxyPort: 0,
      modelPort: 0,
      host: "127.0.0.1",
      allowlist: ["127.0.0.1:" + declared.port, "127.0.0.1:" + other.port],
      readOnlyDeclarations: [
        { host: "127.0.0.1", port: declared.port, methods: ["POST"], pattern: "^/catalog$" },
      ],
      decoyHost: "status.shadow-decoy.test",
      modelUpstream: "http://127.0.0.1:1/v1",
      providerKey: "FIXTURE-KEY-NOT-REAL",
      turnToken: "shadow-turn-FIXTURE-NOT-REAL",
      logPath: path.join(tmp, "egress.jsonl"),
      heldPath: path.join(tmp, "held.jsonl"),
      pendingDir: path.join(tmp, "pending"),
      corpus: {},
    });
  });

  afterEach(async () => {
    await broker.close();
    await new Promise<void>((resolve) => declared.server.close(() => resolve()));
    await new Promise<void>((resolve) => other.server.close(() => resolve()));
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("holds the same call on a second allowlisted port of the same host", async () => {
    const response = await throughProxy(
      broker.proxyPort,
      "POST",
      "http://127.0.0.1:" + other.port + "/catalog",
      JSON.stringify({ note: "same host, port nobody declared" }),
    );
    expect(response.status).toBe(202);
    expect(other.seen).toHaveLength(0);
    expect(broker.decisions().at(-1)).toMatchObject({ decision: "HELD", class: "write-like" });
  });

  it("still sends the call live on the port the declaration names", async () => {
    const response = await throughProxy(
      broker.proxyPort,
      "POST",
      "http://127.0.0.1:" + declared.port + "/catalog",
      JSON.stringify({ note: "the declared endpoint" }),
    );
    expect(response.status).toBe(200);
    expect(declared.seen).toHaveLength(1);
    expect(broker.decisions().at(-1)).toMatchObject({ decision: "LIVE", class: "read-like" });
  });
});

describe("what the host side refuses when it builds the config", () => {
  const launchWith = (readOnlyDeclarations?: readonly ReadOnlyDeclaration[]) =>
    buildBrokerLaunchConfig({
      allowlist: ["collector.internal:443"],
      decoyHost: "status.shadow-decoy.test",
      modelUpstream: "http://127.0.0.1:1/v1",
      proxyPort: 3128,
      modelPort: 8317,
      protectedFiles: [],
      readOnlyDeclarations,
    });

  const declaration = (extra: Partial<ReadOnlyDeclaration>): ReadOnlyDeclaration => ({
    host: "collector.internal",
    port: 443,
    methods: ["POST"],
    pattern: "^/catalog$",
    ...extra,
  });

  it("refuses a declaration that names no port, because the allowlist key is host and port", () => {
    const { port: _dropped, ...noPort } = declaration({});
    expect(() => launchWith([noPort as ReadOnlyDeclaration])).toThrow(/port/);
    expect(launchWith([declaration({})]).readOnlyDeclarations).toHaveLength(1);
  });

  it("refuses a host that carries its port, which would silently match nothing", () => {
    // The trap the required port creates: an operator told to name a port writes it into the host.
    // "collector.internal:8080" never equals a bare hostname, so the rule would be inert.
    expect(() => launchWith([declaration({ host: "collector.internal:8080" })])).toThrow(/port field/);
    expect(
      launchWith([declaration({ host: "collector.internal", port: 8080 })]).readOnlyDeclarations,
    ).toHaveLength(1);
    expect(
      vetReadOnlyDeclarations([{ ...declaration({}), host: "collector.internal:8080" }]).declarations,
    ).toEqual([]);
  });

  it("refuses a port that is not a port number", () => {
    expect(() => launchWith([declaration({ port: 0 })])).toThrow(/port/);
    expect(() => launchWith([declaration({ port: 70000 })])).toThrow(/port/);
    expect(() => launchWith([declaration({ port: 8080.5 })])).toThrow(/port/);
    expect(launchWith([declaration({ port: 8080 })]).readOnlyDeclarations).toEqual([
      { host: "collector.internal", port: 8080, methods: ["POST"], pattern: "^/catalog$" },
    ]);
  });

  // The anchor check was a test on the first and last character of the whole source, so an
  // alternation anchored on its last branch only passed it: `^/a|^/b$` is a rule about /a-admin
  // and everything else beginning /a. Each branch has to carry its own two anchors.
  it("refuses an alternation anchored on one branch only", () => {
    expect(() => launchWith([declaration({ pattern: "^/a|^/b$" })])).toThrow(/anchored/);
    expect(() => launchWith([declaration({ pattern: "^/catalog$|^/search" })])).toThrow(/anchored/);
    expect(() => launchWith([declaration({ pattern: "^/catalog|.*$" })])).toThrow(/anchored/);
  });

  it("accepts the alternations an operator actually writes", () => {
    expect(
      launchWith([
        declaration({ pattern: "^/catalog$|^/search$" }),
        declaration({ pattern: "^/(catalog|search)$" }),
        declaration({ pattern: "^/catalog(\\?.*)?$" }),
        declaration({ pattern: "^/price\\$fx$" }),
        declaration({ pattern: "^/a\\|b$" }),
      ]).readOnlyDeclarations,
    ).toHaveLength(5);
  });

  it("refuses a pattern that can be made to backtrack exponentially", () => {
    expect(() => launchWith([declaration({ pattern: "^/(a+)+b$" })])).toThrow(/unbounded group/);
    expect(() => launchWith([declaration({ pattern: "^/(?:a|a)*b$" })])).toThrow(/unbounded group/);
    expect(() => launchWith([declaration({ pattern: "^/((a*)*)+b$" })])).toThrow(/unbounded group/);
    expect(launchWith([declaration({ pattern: "^/v1/search/.*$" })]).readOnlyDeclarations).toHaveLength(1);
  });
});

/**
 * The two gates say the same thing or they are not two gates.
 *
 * The host side turns a bad declaration into an error the operator reads while the config is being
 * built; the broker side drops it out of a broker.json that was written some other way. They are
 * separate code in separate languages, so the only thing keeping them one rule is this table.
 */
describe("the host gate and the broker gate agree, pattern for pattern", () => {
  const cases: Array<[string, boolean]> = [
    ["^/catalog$", true],
    ["^/catalog(\\?.*)?$", true],
    ["^/catalog$|^/search$", true],
    ["^/(catalog|search)$", true],
    ["^/v1/search/.*$", true],
    ["^/[^/]+/-/.*$", true],
    ["^/price\\$fx$", true],
    ["^/a\\|b$", true],
    ["^/catalog", false],
    ["/catalog$", false],
    ["^/price\\$", false],
    ["^/a|^/b$", false],
    ["^/catalog$|^/search", false],
    ["^/catalog|.*$", false],
    ["^/(a+)+b$", false],
    ["^/(?:a|a)*b$", false],
    ["^/((a*)*)+b$", false],
    ["^/(a|b){2,}$", false],
    ["^/(unclosed$", false],
  ];

  for (const [pattern, accepted] of cases) {
    it((accepted ? "accepts " : "refuses ") + pattern + " on both sides", () => {
      const declaration = { host: "collector.internal", port: 443, methods: ["POST"], pattern };
      const hostAccepted = (() => {
        try {
          buildBrokerLaunchConfig({
            allowlist: ["collector.internal:443"],
            decoyHost: "status.shadow-decoy.test",
            modelUpstream: "http://127.0.0.1:1/v1",
            proxyPort: 3128,
            modelPort: 8317,
            protectedFiles: [],
            readOnlyDeclarations: [declaration],
          });
          return true;
        } catch {
          return false;
        }
      })();
      const brokerAccepted = vetReadOnlyDeclarations([declaration]).declarations.length === 1;
      expect({ hostAccepted, brokerAccepted }).toEqual({ hostAccepted: accepted, brokerAccepted: accepted });
    });
  }
});

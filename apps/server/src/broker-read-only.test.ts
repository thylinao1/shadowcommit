import { afterEach, beforeEach, describe, expect, it } from "vitest";
import http from "node:http";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { TUNNEL_NOT_CLASSIFIED, classifyCall } from "../broker/broker-core.mjs";
import { startBroker } from "../broker/server.mjs";
import {
  DEFAULT_READ_ONLY_DECLARATIONS,
  type ReadOnlyDeclaration,
  buildBrokerLaunchConfig,
} from "./broker.js";

/**
 * Read-only is a declaration about one host, one set of methods, and one path shape, all three at
 * once. A path-shaped rule on its own says nothing about who is being written to or how, so it
 * cannot be the thing that decides a write goes out unheld.
 *
 * Every negative assertion here is paired with a positive one on the SAME declaration, differing
 * only in the axis under test. Without the pair, "write-like" proves nothing: a build in which the
 * declaration list is ignored outright also returns write-like for every non-GET, so the negative
 * half passes for the wrong reason. The pair fails on that build, which is what makes it evidence.
 *
 * The socket tests start the broker from the config the sealer actually writes, spread the way the
 * container entrypoint spreads it, so what is under test is the shipped default and not a default
 * invented by the test.
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

function request(
  options: http.RequestOptions,
  body = "",
): Promise<{ status: number; headers: http.IncomingHttpHeaders; text: string }> {
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
function throughProxy(proxyPort: number, method: string, url: string, body = "") {
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

/**
 * Opens a CONNECT tunnel and then writes one origin-form request down it, which is what every
 * https client does. The broker sees the CONNECT and then opaque bytes.
 */
function throughTunnel(
  proxyPort: number,
  target: string,
  method: string,
  urlPath: string,
  body = "",
): Promise<{ connect: string; response: string }> {
  return new Promise((resolve, reject) => {
    let connect = "";
    let response = "";
    let established = false;
    const socket = net.connect(proxyPort, "127.0.0.1", () => {
      socket.write("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
    });
    socket.on("data", (chunk) => {
      const text = chunk.toString();
      if (established) {
        response += text;
        return;
      }
      connect += text;
      const end = connect.indexOf("\r\n\r\n");
      if (end < 0) return;
      if (!connect.includes(" 200 ")) {
        socket.destroy();
        resolve({ connect: connect.split("\r\n")[0] ?? "", response });
        return;
      }
      established = true;
      response += connect.slice(end + 4);
      connect = connect.split("\r\n")[0] ?? "";
      socket.write(
        method +
          " " +
          urlPath +
          " HTTP/1.1\r\nHost: " +
          target +
          "\r\ncontent-length: " +
          Buffer.byteLength(body) +
          "\r\nconnection: close\r\n\r\n" +
          body,
      );
    });
    socket.on("close", () => resolve({ connect, response }));
    socket.on("error", reject);
    socket.setTimeout(4000, () => {
      socket.destroy();
      resolve({ connect, response: response || "TIMEOUT" });
    });
  });
}

describe("read-only declarations name a host and a method, not just a path", () => {
  const REGISTRY = "registry.npmjs.org";
  const PUBLISH_PATH = "/-/user/org.couchdb.user:someone";

  it("makes a POST read-like only through a declaration that names the method, not through a path rule", () => {
    // The defect: a rule carrying only a path regex matches "/-/user/..." on any host with any
    // method, so the publish leaves live and the policy never sees it. The old field name is
    // asserted inert as well, because a config file written for the previous broker still spreads
    // into `startBroker` and must not re-open the hole under its old key.
    const legacyShaped = {
      method: "POST",
      host: REGISTRY,
      port: 443,
      urlPath: PUBLISH_PATH,
      readOnlyPatterns: ["^/-/"],
    };
    expect(classifyCall(legacyShaped)).toBe("write-like");
    expect(
      classifyCall({
        method: "POST",
        host: REGISTRY,
        port: 443,
        urlPath: PUBLISH_PATH,
        readOnlyDeclarations: [{ host: REGISTRY, methods: ["GET", "HEAD"], pattern: "^/-/.*$" }],
      }),
    ).toBe("write-like");
    // The positive control on the same call: naming POST for that host and that path is what makes
    // it read-like, so the mechanism is live and the two denials above are about the rule shape.
    expect(
      classifyCall({
        method: "POST",
        host: REGISTRY,
        port: 443,
        urlPath: PUBLISH_PATH,
        readOnlyDeclarations: [{ host: REGISTRY, methods: ["POST"], pattern: "^/-/.*$" }],
      }),
    ).toBe("read-like");
  });

  it("does not carry a declaration for one host over to another host", () => {
    const declarations = [
      { host: "collector.internal", methods: ["POST"], pattern: "^/catalog(\\?.*)?$" },
    ];
    const call = { method: "POST", port: 443, urlPath: "/catalog", readOnlyDeclarations: declarations };
    expect(classifyCall({ ...call, host: "collector.internal" })).toBe("read-like");
    expect(classifyCall({ ...call, host: "other-collector.example.com" })).toBe("write-like");
  });

  it("does not carry a declaration for one method over to another method", () => {
    const declarations = [
      { host: "collector.internal", methods: ["PUT"], pattern: "^/catalog(\\?.*)?$" },
    ];
    const call = {
      host: "collector.internal",
      port: 443,
      urlPath: "/catalog",
      readOnlyDeclarations: declarations,
    };
    expect(classifyCall({ ...call, method: "PUT" })).toBe("read-like");
    expect(classifyCall({ ...call, method: "POST" })).toBe("write-like");
  });

  it("keeps a declared GET read-like, which is what ordinary installs run on", () => {
    // The negative case at unit level: the registry read path stays live when it was declared for
    // that host, that method and that path together.
    const declarations = [{ host: REGISTRY, methods: ["GET", "HEAD"], pattern: "^/[^/]+/-/.*$" }];
    expect(
      classifyCall({
        method: "GET",
        host: REGISTRY,
        port: 443,
        urlPath: "/left-pad/-/left-pad-1.3.0.tgz",
        readOnlyDeclarations: declarations,
      }),
    ).toBe("read-like");
  });
});

describe("a declaration covers the path it names and no neighbour of it", () => {
  const declare = (pattern: string) => [{ host: "collector.internal", methods: ["POST"], pattern }];
  const classify = (urlPath: string, pattern: string) =>
    classifyCall({
      method: "POST",
      host: "collector.internal",
      port: 443,
      urlPath,
      readOnlyDeclarations: declare(pattern),
    });

  it("does not let a prefix rule reach a sibling path that merely starts the same way", () => {
    // "^/catalog" reads as "the catalog endpoint". Matched unanchored it is also a rule about
    // /catalog-admin/delete and /catalogue/purge, and those are writes.
    expect(classify("/catalog-admin/delete", "^/catalog")).toBe("write-like");
    expect(classify("/catalogue/purge", "^/catalog")).toBe("write-like");
    expect(classify("/catalog/../admin/purge", "^/catalog")).toBe("write-like");
    // The positive control on the SAME rule. Without it a build that ignored declarations outright
    // would satisfy the three lines above, because everything that is not a GET is write-like there.
    expect(classify("/catalog", "^/catalog")).toBe("read-like");
  });

  it("still matches the endpoint the operator named, with and without a query", () => {
    expect(classify("/catalog", "^/catalog$")).toBe("read-like");
    expect(classify("/catalog", "^/catalog(\\?.*)?$")).toBe("read-like");
    expect(classify("/catalog?page=2", "^/catalog(\\?.*)?$")).toBe("read-like");
    expect(classify("/catalog/search", "^/catalog/(search|facets)$")).toBe("read-like");
  });

  it("anchors every branch of an alternation, not just the last one", () => {
    expect(classify("/search/admin/purge", "^/catalog$|^/search")).toBe("write-like");
    // Same rule, the two paths it does name: the branches still match, so the line above is about
    // where the alternation stops and not about declarations being off.
    expect(classify("/catalog", "^/catalog$|^/search")).toBe("read-like");
    expect(classify("/search", "^/catalog$|^/search")).toBe("read-like");
  });

  it("matches the same way however often it is asked", () => {
    // A RegExp object carrying /g keeps lastIndex between calls, so a stateful test() answers
    // read-like, write-like, read-like on identical calls. The classification cannot depend on how
    // many times it has run.
    const sticky = [{ host: "collector.internal", methods: ["POST"], pattern: /^\/catalog$/g }];
    const call = {
      method: "POST",
      host: "collector.internal",
      port: 443,
      urlPath: "/catalog",
      readOnlyDeclarations: sticky,
    };
    expect([classifyCall(call), classifyCall(call), classifyCall(call)]).toEqual([
      "read-like",
      "read-like",
      "read-like",
    ]);
  });
});

describe("the config the sealer writes", () => {
  const launchWith = (readOnlyDeclarations?: readonly ReadOnlyDeclaration[]) =>
    buildBrokerLaunchConfig({
      allowlist: ["registry.npmjs.org:443"],
      decoyHost: "status.shadow-decoy.test",
      modelUpstream: "http://127.0.0.1:1/v1",
      proxyPort: 3128,
      modelPort: 8317,
      protectedFiles: [],
      readOnlyDeclarations,
    });

  it("declares nothing read-only when the caller declares nothing", () => {
    expect(DEFAULT_READ_ONLY_DECLARATIONS).toEqual([]);
    expect(launchWith().readOnlyDeclarations).toEqual([]);
  });

  it("cannot have a declaration pushed into the shipped default by an importer", () => {
    // The default is read at every config build, so one push in any module in the process would
    // make an endpoint read-only for every later turn, from a line nowhere near the broker.
    expect(Object.isFrozen(DEFAULT_READ_ONLY_DECLARATIONS)).toBe(true);
    expect(() =>
      (DEFAULT_READ_ONLY_DECLARATIONS as ReadOnlyDeclaration[]).push({
        host: "registry.npmjs.org",
        port: 443,
        methods: ["PUT"],
        pattern: "^/-/.*$",
      }),
    ).toThrow(TypeError);
    expect(launchWith().readOnlyDeclarations).toEqual([]);
  });

  it("keeps an operator declaration, normalised", () => {
    expect(
      launchWith([
        { host: "Collector.Internal", port: 8080, methods: ["post"], pattern: "^/catalog(\\?.*)?$" },
      ]).readOnlyDeclarations,
    ).toEqual([
      { host: "collector.internal", port: 8080, methods: ["POST"], pattern: "^/catalog(\\?.*)?$" },
    ]);
  });

  it("refuses a declaration that names no host, rather than applying it everywhere", () => {
    expect(() => launchWith([{ host: "", port: 443, methods: ["POST"], pattern: "^/-/.*$" }])).toThrow(/exact host/);
  });

  it("refuses a wildcard where a method should be", () => {
    expect(() =>
      launchWith([{ host: "registry.npmjs.org", port: 443, methods: ["*"], pattern: "^/-/.*$" }]),
    ).toThrow(/one by one/);
  });

  it("refuses a pattern that is not anchored at both ends, so breadth is visible in the source", () => {
    expect(() =>
      launchWith([{ host: "collector.internal", port: 443, methods: ["POST"], pattern: "^/catalog" }]),
    ).toThrow(/anchored/);
    expect(() =>
      launchWith([{ host: "collector.internal", port: 443, methods: ["POST"], pattern: "/catalog$" }]),
    ).toThrow(/anchored/);
    // a trailing escaped dollar is a literal "$", not an anchor
    expect(() =>
      launchWith([{ host: "collector.internal", port: 443, methods: ["POST"], pattern: "^/price\\$" }]),
    ).toThrow(/anchored/);
  });

  it("accepts the anchored forms an operator actually needs", () => {
    expect(
      launchWith([
        { host: "collector.internal", port: 443, methods: ["POST"], pattern: "^/catalog(\\?.*)?$" },
        { host: "collector.internal", port: 443, methods: ["POST"], pattern: "^/v1/search/.*$" },
        { host: "collector.internal", port: 8080, methods: ["POST"], pattern: "^/price\\$fx$" },
      ]).readOnlyDeclarations,
    ).toHaveLength(3);
  });
});

describe("the shipped broker config, over real sockets", () => {
  let tmp: string;
  let heldPath: string;
  let pendingDir: string;
  let collector: Recorder;
  let broker: Awaited<ReturnType<typeof startBroker>>;

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-readonly-"));
    heldPath = path.join(tmp, "held.jsonl");
    pendingDir = path.join(tmp, "pending");
    collector = await recorder();
    // exactly what network-sealer.ts builds: no read-only override of any kind
    const launch = buildBrokerLaunchConfig({
      allowlist: ["127.0.0.1:" + collector.port],
      decoyHost: "status.shadow-decoy.test",
      modelUpstream: "http://127.0.0.1:1/v1",
      proxyPort: 0,
      modelPort: 0,
      protectedFiles: [],
    });
    // the container entrypoint spreads the file config and adds only the two secrets
    broker = await startBroker({
      ...launch,
      host: "127.0.0.1",
      logPath: path.join(tmp, "egress.jsonl"),
      heldPath,
      pendingDir,
      corpus: {},
      providerKey: "FIXTURE-KEY-NOT-REAL",
      turnToken: "shadow-turn-FIXTURE-NOT-REAL",
    });
  });

  afterEach(async () => {
    await broker.close();
    await new Promise<void>((resolve) => collector.server.close(() => resolve()));
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("HOLDS a POST under /-/ on an allowlisted host instead of sending it live", async () => {
    const response = await throughProxy(
      broker.proxyPort,
      "POST",
      "http://127.0.0.1:" + collector.port + "/-/user/org.couchdb.user:someone",
      JSON.stringify({ name: "someone", password: "FIXTURE-PASSWORD-NOT-REAL" }),
    );
    expect(response.status).toBe(202);
    expect(response.headers["x-shadow-effect-id"]).toBeTruthy();
    // the write never reached the world
    expect(collector.seen).toHaveLength(0);
    expect(broker.decisions().at(-1)).toMatchObject({ decision: "HELD", class: "write-like" });
  });

  it("still sends an ordinary package read live, so installs keep working", async () => {
    // The negative case end to end: a tarball fetch is the read the acceptance task runs on. If
    // this one turns into a review the control is an outage, not a control.
    const response = await throughProxy(
      broker.proxyPort,
      "GET",
      "http://127.0.0.1:" + collector.port + "/left-pad/-/left-pad-1.3.0.tgz",
    );
    expect(response.status).toBe(200);
    expect(collector.seen).toHaveLength(1);
    expect(broker.decisions().at(-1)).toMatchObject({ decision: "LIVE", class: "read-like" });
    expect(await fs.readFile(heldPath, "utf8").catch(() => "")).toBe("");
  });
});

/**
 * The bound of this control, recorded rather than implied.
 *
 * Classification is a property of the plain-HTTP path: it needs a method and a request path, and a
 * CONNECT tunnel has neither in view. So the same publish that is held above leaves unheld when the
 * client speaks TLS, which is every real registry. The tunnel is still allowlisted by host and
 * port, and the journal now says on every allowed tunnel that nothing was classified, so the bound
 * is visible per call and not only in the README.
 *
 * Denying a tunnel to a host with no read-only declaration was the alternative, and it is an
 * outage: the shipped declaration list is empty, so it would deny registry.npmjs.org:443 and
 * `npm install` with it. The last test here is that negative case and it must keep passing.
 */
describe("the CONNECT bound: an allowed tunnel is not classified at all", () => {
  let tmp: string;
  let heldPath: string;
  let collector: Recorder;
  let broker: Awaited<ReturnType<typeof startBroker>>;

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-tunnel-"));
    heldPath = path.join(tmp, "held.jsonl");
    collector = await recorder();
    const launch = buildBrokerLaunchConfig({
      allowlist: ["127.0.0.1:" + collector.port],
      decoyHost: "status.shadow-decoy.test",
      modelUpstream: "http://127.0.0.1:1/v1",
      proxyPort: 0,
      modelPort: 0,
      protectedFiles: [],
    });
    broker = await startBroker({
      ...launch,
      host: "127.0.0.1",
      logPath: path.join(tmp, "egress.jsonl"),
      heldPath,
      pendingDir: path.join(tmp, "pending"),
      corpus: {},
      providerKey: "FIXTURE-KEY-NOT-REAL",
      turnToken: "shadow-turn-FIXTURE-NOT-REAL",
    });
  });

  afterEach(async () => {
    await broker.close();
    await new Promise<void>((resolve) => collector.server.close(() => resolve()));
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("says in the journal that an allowed tunnel carried no classification", async () => {
    const { connect } = await throughTunnel(
      broker.proxyPort,
      "127.0.0.1:" + collector.port,
      "GET",
      "/left-pad",
    );
    expect(connect).toContain("200");
    expect(broker.decisions().at(0)).toMatchObject({
      decision: "ALLOW",
      class: "tunnel",
      proto: "connect",
      inspected: false,
      classified: false,
      reason: TUNNEL_NOT_CLASSIFIED,
    });
  });

  it("does not hold a write sent through the tunnel, which is the stated bound of the control", async () => {
    const { connect } = await throughTunnel(
      broker.proxyPort,
      "127.0.0.1:" + collector.port,
      "PUT",
      "/-/user/org.couchdb.user:someone",
      JSON.stringify({ name: "someone", password: "FIXTURE-PASSWORD-NOT-REAL" }),
    );
    expect(connect).toContain("200");
    // the write reached the destination: this is the boundary, and it is here so that no reader
    // takes the held-write tests above as covering https
    expect(collector.seen).toHaveLength(1);
    expect(collector.seen[0]).toMatchObject({ method: "PUT" });
    expect(await fs.readFile(heldPath, "utf8").catch(() => "")).toBe("");
    // one row, and it is the tunnel row: no write-like decision was ever made about those bytes
    expect(broker.decisions().filter((d) => d.class === "write-like")).toHaveLength(0);
    expect(broker.decisions().map((d) => d.class)).toEqual(["tunnel"]);
  });

  it("still opens the tunnel an allowlisted host is entitled to, which npm install needs", async () => {
    const { connect } = await throughTunnel(
      broker.proxyPort,
      "127.0.0.1:" + collector.port,
      "GET",
      "/left-pad/-/left-pad-1.3.0.tgz",
    );
    expect(connect).toContain("200");
    expect(collector.seen).toHaveLength(1);
  });
});

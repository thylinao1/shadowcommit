// The egress broker. Runs in its own container, dual-homed onto the per-run internal network (where
// the agent can reach it) and the default bridge (where it can reach the world). The agent container
// has no route out at all, so this process is the only way anything leaves.
//
// Three channels, three different rules:
//   proxy port  CONNECT  -> destination allowlist by host:port, no TLS interception, no CA. Not
//                           classified and never held: the hold control is plain-HTTP only.
//   proxy port  HTTP     -> allowlist, then read-like passes through LIVE and write-like is HELD.
//   model port  HTTP     -> terminated here: the one-turn token is swapped for the real provider
//                           key and the call is forwarded upstream, so the real key never exists
//                           inside the agent container (invariant I1).
//
// Written as plain ESM with no dependencies so it can be bind-mounted read-only into a stock
// node:22 image, and started in-process by the tests with no container at all.
import http from "node:http";
import https from "node:https";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  TUNNEL_NOT_CLASSIFIED,
  allowlistDecision,
  classifyCall,
  entropy,
  parseHostPort,
  headerScanText,
  provenanceLabel,
  scanPayload,
} from "./broker-core.mjs";

const MAX_BODY_BYTES = 8 * 1024 * 1024;

// ---- vetting the declaration list -------------------------------------------------------------
// `readOnlyDeclarations` is CONFIG, not code: it arrives as one field of a JSON file a person may
// have hand-written, so it can be any JSON value at all, and its patterns are operator-supplied
// regular expressions run against a path the agent chooses. Three failure modes follow, and this
// section is the one place that answers all three.
//
// TYPE. The per-entry matcher in broker-core is careful about each entry; the loop around it is
// not careful about the CONTAINER. A field that is an object keyed by host (the shape of the old
// pattern map), or a number, is not iterable, so classification threw inside the request handler:
// the write got no answer, the journal got no row, and the process died on the unhandled
// rejection. A typo in a config file must not be able to take the turn down.
//
// COST. A pattern like `^/(a+)+b$` against a path of 32 a-characters is 25 seconds of blocked
// event loop here, and every further character doubles it. The proxy and the model channel are the
// same loop, so code inside the sandbox picks the path and thereby picks how long the agent's own
// model channel stalls.
//
// BREADTH. A declaration names a host, and the allowlist key is a host AND a port, so a
// declaration written for one port silently covered every other port of that host that happened to
// be allowlisted.
//
// Everything that does not survive is DROPPED with a reason rather than trusted or thrown. Dropping
// is the safe direction: a declaration is the only thing that sends a write out unheld, so losing
// one costs a held call that a person then reviews, while keeping a bad one sends a write live.

const UNBOUNDED_QUANTIFIER = /^(?:[*+]|\{\d+,\})/;
const METHOD_NAME = /^[A-Z]+$/;

/** A trailing "$" after an odd number of backslashes is a literal dollar sign, not an anchor. */
function endsWithAnchor(source) {
  if (!source.endsWith("$")) return false;
  let backslashes = 0;
  for (let i = source.length - 2; i >= 0 && source[i] === "\\"; i -= 1) backslashes += 1;
  return backslashes % 2 === 0;
}

/**
 * The alternatives of a pattern at depth zero. `^/a$|^/b$` is two rules and each one needs its own
 * two anchors: a check on the first and last character of the whole source passes `^/a|^/b$`, whose
 * first branch is a prefix rule covering /a-admin/delete and everything else beginning /a.
 */
function topLevelBranches(source) {
  const branches = [];
  let depth = 0;
  let inClass = false;
  let start = 0;
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "(") depth += 1;
    else if (ch === ")") depth = Math.max(0, depth - 1);
    else if (ch === "|" && depth === 0) {
      branches.push(source.slice(start, i));
      start = i + 1;
    }
  }
  branches.push(source.slice(start));
  return branches;
}

/** Does this group body offer the engine more than one way to match the same text? */
function bodyIsAmbiguous(body) {
  let inClass = false;
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "|" || ch === "*" || ch === "+") return true;
    else if (ch === "{" && /^\{\d+,\}/.test(body.slice(i))) return true;
  }
  return false;
}

/**
 * An unbounded repetition of a group that is itself unbounded or alternating, which is the shape
 * whose backtracking is exponential in the length of the subject: `(a+)+`, `(a|a)*`, `((a*)*)+`.
 *
 * This is a check on the SHAPE of the pattern, not a proof of linear time. It refuses the classic
 * construction and it does not refuse every slow expression, which is why the residual is written
 * down in the lane report rather than implied away. A bounded repetition of an unbounded group,
 * `(\?.*)?`, is the form operators actually write and stays allowed.
 */
function hasCatastrophicNesting(source) {
  const stack = [];
  let inClass = false;
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "(") stack.push(i);
    else if (ch === ")") {
      const start = stack.pop();
      if (start === undefined) continue;
      if (!UNBOUNDED_QUANTIFIER.test(source.slice(i + 1))) continue;
      if (bodyIsAmbiguous(source.slice(start + 1, i))) return true;
    }
  }
  return false;
}

/**
 * Turns whatever the config file carried into the list the classifier may use, plus the reasons
 * anything was dropped. The reasons are returned rather than thrown so the operator sees them on
 * the ready line and on the handle, and the turn still runs with every undeclared write held.
 *
 * These are the same structural rules `normaliseReadOnlyDeclarations` applies on the host side,
 * stated a second time on purpose: the host side turns them into an error the operator reads while
 * building the config, and this side is what a broker.json written by hand still has to pass.
 * `broker-declaration-config.test.ts` asserts the two agree pattern for pattern.
 */
export function vetReadOnlyDeclarations(input) {
  if (!Array.isArray(input)) {
    const empty = input === undefined || input === null;
    return {
      declarations: [],
      issues: empty ? [] : [{ index: -1, why: "readOnlyDeclarations is not a list, so no declaration is in force" }],
    };
  }
  const declarations = [];
  const issues = [];
  input.forEach((entry, index) => {
    const drop = (why) => issues.push({ index, why });
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return drop("not a declaration object");
    const host = String(entry.host ?? "").trim().toLowerCase();
    if (!host) return drop("no host, and a declaration without a host is a rule about everywhere");
    if (host.includes("*")) return drop("a wildcard host");
    // the port has its own field, and "collector.internal:8080" never equals a bare url.hostname,
    // so a host written that way would be a rule that silently matched nothing
    if (host.includes(":")) return drop("a host carrying a port; the port is its own field");
    const port = Number(entry.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return drop("no port, and the allowlist key is a host and a port, so a declaration is too");
    }
    const methods = Array.isArray(entry.methods) ? entry.methods.map((m) => String(m).trim().toUpperCase()) : [];
    if (!methods.length) return drop("no method named");
    if (!methods.every((method) => METHOD_NAME.test(method))) return drop("a wildcard where a method should be");
    const pattern = entry.pattern;
    const isRegExp = pattern instanceof RegExp;
    if (!isRegExp && (typeof pattern !== "string" || !pattern)) return drop("no path pattern");
    const source = isRegExp ? pattern.source : pattern;
    try {
      new RegExp(source);
    } catch {
      return drop("a path pattern that is not a valid regular expression");
    }
    if (!topLevelBranches(source).every((branch) => branch.startsWith("^") && endsWithAnchor(branch))) {
      return drop("a path pattern with a branch that is not anchored at both ends");
    }
    if (hasCatastrophicNesting(source)) {
      return drop("a path pattern with an unbounded quantifier over an unbounded group");
    }
    declarations.push({ host, port, methods, pattern: isRegExp ? pattern : source });
  });
  return { declarations, issues };
}

function appendRecord(filePath, record) {
  if (!filePath) return;
  try {
    fs.appendFileSync(filePath, JSON.stringify(record) + "\n");
  } catch {
    /* a broker that cannot write its log must still deny correctly */
  }
}

function readCorpus(protectedFiles) {
  const corpus = {};
  for (const entry of protectedFiles ?? []) {
    if (typeof entry !== "string") continue;
    try {
      corpus[path.basename(entry)] = fs.readFileSync(entry, "utf8");
    } catch {
      /* a protected file the broker cannot read is simply not in the corpus */
    }
  }
  return corpus;
}

/**
 * @param {object} options
 * @returns {Promise<{proxyPort:number, modelPort:number, close:()=>Promise<void>, decisions:()=>object[]}>}
 */
export async function startBroker(options) {
  const opts = {
    proxyPort: 3128,
    modelPort: 8317,
    host: "0.0.0.0",
    allowlist: [],
    readOnlyDeclarations: [],
    decoyHost: "",
    modelUpstream: "",
    providerKey: "",
    turnToken: "",
    logPath: "",
    heldPath: "",
    pendingDir: "",
    protectedFiles: [],
    corpus: null,
    ...options,
  };

  const vetted = vetReadOnlyDeclarations(opts.readOnlyDeclarations);
  const readOnlyDeclarations = vetted.declarations;
  for (const issue of vetted.issues) {
    // stderr, because the journal is a record of calls and this is a record of config
    console.error(JSON.stringify({ kind: "broker.declaration-rejected", ...issue }));
  }
  /**
   * The declarations that apply to THIS connection. A declaration names a host and a port, the
   * same key the allowlist matches on, and `classifyCall` decides on host, method and path alone,
   * so the port is applied here by narrowing the list before classification rather than inside it.
   */
  const declarationsFor = (host, port) =>
    readOnlyDeclarations.filter((entry) => entry.host === host && entry.port === port);

  const corpus = opts.corpus ?? readCorpus(opts.protectedFiles);
  const upstream = opts.modelUpstream ? new URL(opts.modelUpstream) : null;
  const decoyHost = String(opts.decoyHost ?? "").toLowerCase();
  const decisions = [];
  let counter = 0;

  const decide = (record) => {
    counter += 1;
    const full = { kind: "egress", n: counter, ts: new Date().toISOString(), ...record };
    decisions.push(full);
    appendRecord(opts.logPath, full);
    return full;
  };

  const collect = (req) =>
    new Promise((resolve) => {
      const chunks = [];
      let size = 0;
      let truncated = false;
      req.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          truncated = true;
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => resolve({ body: Buffer.concat(chunks), truncated }));
      req.on("error", () => resolve({ body: Buffer.concat(chunks), truncated }));
    });

  // ---- the held store -------------------------------------------------------------------------
  // Bodies live here and ONLY here: mode 0600, in a directory the journal never points into,
  // unlinked when the turn does not commit. The first version of this broker wrote the payload
  // into the same append-only log as the journal, which contradicted its own redaction claim.
  const hold = (method, url, headers, body, scan) => {
    const effectId = "eff-" + crypto.randomBytes(4).toString("hex");
    const sha256 = crypto.createHash("sha256").update(body).digest("hex");
    if (opts.pendingDir) {
      try {
        fs.mkdirSync(opts.pendingDir, { recursive: true, mode: 0o700 });
        fs.writeFileSync(
          path.join(opts.pendingDir, effectId + ".json"),
          JSON.stringify({ effectId, method, url, headers, bodyBase64: body.toString("base64") }),
          { mode: 0o600 },
        );
      } catch (error) {
        return { effectId: null, error: String(error && error.message) };
      }
    }
    const target = new URL(url);
    // journaled by reference: id, size, hash prefix, provenance label and flags. No body field.
    appendRecord(opts.heldPath, {
      effectId,
      method,
      host: target.hostname,
      port: Number(target.port || (target.protocol === "https:" ? 443 : 80)),
      urlPath: target.pathname + target.search,
      bytes: body.length,
      sha256,
      provenance: provenanceLabel(scan.provenance),
      secretPattern: scan.secretPattern,
      highEntropy: scan.highEntropy,
      entropy: scan.entropy,
    });
    return { effectId, sha256 };
  };

  const forward = (targetUrl, method, headers, body, res, onError) => {
    const url = new URL(targetUrl);
    const agentModule = url.protocol === "https:" ? https : http;
    const outHeaders = { ...headers, host: url.host };
    delete outHeaders["proxy-connection"];
    delete outHeaders["connection"];
    delete outHeaders["content-length"];
    // the body was buffered here so it could be scanned, so it is no longer chunked; leaving the
    // header on produces a request carrying both a transfer-encoding and a content-length, which
    // a strict upstream rejects and a lenient one interprets differently from the next hop
    delete outHeaders["transfer-encoding"];
    if (body.length) outHeaders["content-length"] = String(body.length);
    const upstreamRequest = agentModule.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method,
        headers: outHeaders,
      },
      (upstreamResponse) => {
        res.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(res);
      },
    );
    upstreamRequest.on("error", (error) => {
      if (onError) onError(error);
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
      res.end("upstream error: " + String(error && error.message));
    });
    upstreamRequest.end(body);
  };

  const refuse = (res, reason, scan) => {
    res.writeHead(403, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        error: {
          type: "shadow_commit_refused",
          reason,
          message: "refused by Shadow Commit: the payload carries protected content or a credential",
          provenance: provenanceLabel(scan.provenance),
        },
      }),
    );
  };

  // ---- the model channel ----------------------------------------------------------------------
  // Terminated here, which is the whole point: the container is handed a one-turn token, this
  // process swaps in the real provider key, and the key therefore never exists inside the jail.
  const modelServer = http.createServer(async (req, res) => {
    const { body } = await collect(req);
    const text = body.toString("utf8");
    const presented = String(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "").trim();
    const target = "model" + (req.url ?? "");

    if (opts.turnToken && presented !== opts.turnToken) {
      decide({ method: req.method, target, class: "live-path", decision: "UNAUTHORIZED",
        reason: presented ? "wrong-turn-token" : "no-turn-token" });
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "invalid turn token" } }));
      return;
    }

    // Headers too. A GET has no body, so a protected record in a header reached this as an empty
    // string. Credential headers are scanned for provenance only; see headerScanText.
    const modelHeaders = headerScanText(req.headers);
    const scan = scanPayload(
      text + " " + (req.url ?? "") + " " + modelHeaders.full,
      corpus,
      modelHeaders.provenanceOnly,
    );
    if (scan.refuseReason) {
      decide({ method: req.method, target, class: "live-path", decision: "REFUSED",
        reason: scan.refuseReason, provenance: provenanceLabel(scan.provenance),
        secretPattern: scan.secretPattern });
      refuse(res, scan.refuseReason, scan);
      return;
    }

    if (!upstream) {
      decide({ method: req.method, target, class: "live-path", decision: "NO_UPSTREAM" });
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "no model upstream configured" } }));
      return;
    }

    const suffix = String(req.url ?? "").replace(/^\/v1/, "");
    const upstreamUrl = upstream.origin + upstream.pathname.replace(/\/+$/, "") + suffix;
    decide({ method: req.method, target, class: "live-path", decision: "LIVE",
      upstreamHost: upstream.hostname, keySwapped: Boolean(opts.providerKey),
      provenance: null, secretPattern: null });
    const headers = { ...req.headers };
    delete headers.authorization;
    if (opts.providerKey) headers.authorization = "Bearer " + opts.providerKey;
    forward(upstreamUrl, req.method ?? "POST", headers, body, res);
  });

  // ---- the shell egress proxy -----------------------------------------------------------------
  const proxyServer = http.createServer(async (req, res) => {
    let url;
    try {
      url = new URL(req.url ?? "");
    } catch {
      const hostHeader = String(req.headers.host ?? "");
      try {
        url = new URL("http://" + hostHeader + (req.url ?? "/"));
      } catch {
        res.writeHead(400, { "content-type": "text/plain" });
        res.end("absolute-form request required\n");
        return;
      }
    }
    const { body, truncated } = await collect(req);
    const text = body.toString("utf8");
    const host = url.hostname.toLowerCase();
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    const target = url.toString();
    const method = String(req.method ?? "GET").toUpperCase();

    // SL02: a probe that always fails is itself an oracle. A sleeper payload that only fires when
    // the network works reads "no egress" as "I am being watched" and stays inert until it is not.
    // So one allowlisted destination always answers, from inside the sealed network, and its
    // answer is a real 200 the agent can act on.
    if (decoyHost && host === decoyHost) {
      decide({ method, target, class: "decoy", decision: "ALLOW", proto: "http" });
      res.writeHead(200, { "content-type": "application/json", "x-shadow-decoy": "1" });
      res.end(JSON.stringify({ ok: true, service: "status", region: "local" }));
      return;
    }

    if (!allowlistDecision(opts.allowlist, host, port)) {
      decide({ method, target, class: "egress", decision: "DENY", proto: "http",
        reason: "destination-not-on-allowlist" });
      res.writeHead(403, { "content-type": "text/plain" });
      res.end("egress denied by policy: " + host + ":" + port + " is not on the allowlist\n");
      return;
    }

    const egressHeaders = headerScanText(req.headers);
    const scan = scanPayload(
      text + " " + url.pathname + url.search + " " + egressHeaders.full,
      corpus,
      egressHeaders.provenanceOnly,
    );
    const callClass = classifyCall({
      method, host, port, urlPath: url.pathname + url.search,
      modelHosts: opts.modelHosts ?? [], readOnlyDeclarations: declarationsFor(host, port),
    });

    if (callClass === "read-like" || callClass === "live") {
      // Read-like is live, and live still has to be contained: a GET can carry the whole protected
      // file in its query string, and there is nothing to defer it to, so a hit is refused here.
      if (scan.refuseReason) {
        decide({ method, target, class: callClass, decision: "REFUSED", proto: "http",
          reason: scan.refuseReason, provenance: provenanceLabel(scan.provenance),
          secretPattern: scan.secretPattern });
        refuse(res, scan.refuseReason, scan);
        return;
      }
      decide({ method, target, class: callClass, decision: "LIVE", proto: "http",
        provenance: null, secretPattern: null });
      forward(target, method, req.headers, body, res);
      return;
    }

    if (truncated) {
      decide({ method, target, class: "write-like", decision: "DENY", proto: "http",
        reason: "payload-exceeds-hold-limit", bytes: MAX_BODY_BYTES });
      res.writeHead(413, { "content-type": "text/plain" });
      res.end("payload exceeds the broker hold limit\n");
      return;
    }

    const held = hold(method, target, req.headers, body, scan);
    if (!held.effectId) {
      decide({ method, target, class: "write-like", decision: "DENY", proto: "http",
        reason: "hold-store-unavailable" });
      res.writeHead(503, { "content-type": "text/plain" });
      res.end("the hold store is unavailable, so this write cannot be deferred\n");
      return;
    }
    decide({ method, target, class: "write-like", decision: "HELD", proto: "http",
      effectId: held.effectId, bytes: body.length, sha256: held.sha256,
      provenance: provenanceLabel(scan.provenance), secretPattern: scan.secretPattern,
      highEntropy: scan.highEntropy });
    // A defined synthetic answer, so the turn continues deterministically and the model is not
    // lied to about the state of the world: pending is true and the effect has a name.
    res.writeHead(202, { "content-type": "application/json", "x-shadow-effect-id": held.effectId });
    res.end(
      JSON.stringify({
        status: "accepted",
        pending: true,
        effectId: held.effectId,
        note: "held by Shadow Commit; this write is sent only if the turn commits",
      }),
    );
  });

  // CONNECT: destination allowlisting only, and that is the whole of it. No TLS interception and
  // no CA in the image, so an allowed tunnel is opaque to us by construction.
  //
  // Say the bound exactly, because the plain-HTTP handler above holds write-like calls and it is
  // easy to read that as covering everything: read-like and write-like are decided from a method
  // and a request path, a tunnel shows neither, so nothing sent through one is classified and
  // nothing sent through one is held. A publish to a real registry speaks https and therefore
  // leaves here, allowlisted and unheld. The ALLOW row below says so per call
  // (`classified: false`), and the alternative, denying tunnels to hosts with no read-only
  // declaration, denies registry.npmjs.org:443 on the shipped empty list and takes `npm install`
  // down with it.
  proxyServer.on("connect", (req, clientSocket, head) => {
    const { host, port } = parseHostPort(req.url ?? "", 443);
    if (decoyHost && host === decoyHost) {
      decide({ method: "CONNECT", target: host + ":" + port, class: "decoy", decision: "DENY",
        proto: "connect", reason: "decoy-answers-plain-http-only" });
      clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      clientSocket.end();
      return;
    }
    if (!allowlistDecision(opts.allowlist, host, port)) {
      decide({ method: "CONNECT", target: host + ":" + port, class: "egress", decision: "DENY",
        proto: "connect", reason: "destination-not-on-allowlist" });
      clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\negress denied by policy\r\n");
      clientSocket.end();
      return;
    }
    decide({ method: "CONNECT", target: host + ":" + port, class: "tunnel", decision: "ALLOW",
      proto: "connect", inspected: false, classified: false, reason: TUNNEL_NOT_CLASSIFIED });
    const upstreamSocket = net.connect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) upstreamSocket.write(head);
      upstreamSocket.pipe(clientSocket);
      clientSocket.pipe(upstreamSocket);
    });
    upstreamSocket.on("error", () => clientSocket.end());
    clientSocket.on("error", () => upstreamSocket.end());
  });

  const listen = (server, port) =>
    new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, opts.host, () => resolve(server.address().port));
    });

  const proxyPort = await listen(proxyServer, opts.proxyPort);
  const modelPort = await listen(modelServer, opts.modelPort);

  return {
    proxyPort,
    modelPort,
    /** What the config file asked for that is not in force, and why. Empty on a clean config. */
    declarationIssues: vetted.issues,
    decisions: () => decisions.slice(),
    close: async () => {
      await new Promise((resolve) => proxyServer.close(() => resolve(undefined)));
      await new Promise((resolve) => modelServer.close(() => resolve(undefined)));
    },
  };
}

// ---- container entrypoint ---------------------------------------------------------------------
// Configuration arrives as one JSON file the host wrote into a read-only bind mount, so no secret
// and no allowlist ever appears on a command line where `ps` can read it.
const isMain = process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]));
if (isMain) {
  const configPath = process.argv[2] ?? "/broker-config/broker.json";
  const fileConfig = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const options = {
    ...fileConfig,
    providerKey: process.env.ARK_API_KEY ?? fileConfig.providerKey ?? "",
    turnToken: process.env.SHADOW_TURN_TOKEN ?? fileConfig.turnToken ?? "",
  };
  startBroker(options).then((handle) => {
    console.log(
      JSON.stringify({
        kind: "broker.ready",
        proxyPort: handle.proxyPort,
        modelPort: handle.modelPort,
        allowlist: options.allowlist,
        decoyHost: options.decoyHost,
        declarationIssues: handle.declarationIssues,
      }),
    );
  });
}

export { entropy };

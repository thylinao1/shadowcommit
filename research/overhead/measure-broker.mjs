// Broker latency on allowed, held and denied calls.
//
// `research/OVERHEAD.md` has named this "not measured" since the page was written, on the grounds
// that it needs a container. It does not. `broker/server.mjs` is dependency-free ESM and its own
// docblock says it is "started in-process by the tests with no container at all", which is what
// this does. Running it in-process is also the more honest measurement for the question the page
// asks: what does the GUARANTEE cost. A container adds a fixed network hop that belongs to Docker,
// not to the broker's decision, and folding the two together would credit the broker with someone
// else's milliseconds.
//
// Five channels, because the broker treats them differently and the costs are not alike:
//   direct    the same upstream call with no broker at all, the baseline every row is read against
//   allowed   plain HTTP the allowlist permits and the classifier reads as read-like: forwarded live
//   held      plain HTTP that is write-like: never forwarded, written to the held journal instead
//   denied    a host that is not on the allowlist: refused
//   tunnel    CONNECT to an allowlisted host and port, allowlisted by host and port only
//
//   node research/overhead/measure-broker.mjs
import http from "node:http";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Resolved from this file's own location, so the command works from any checkout, which is the
// defect the other two scripts on this page had.
const here = path.dirname(fileURLToPath(import.meta.url));
const { startBroker } = await import(
  pathToFileURL(path.join(here, "..", "..", "apps", "server", "broker", "server.mjs")).href
);

const REPS = 300;
const WARMUP = 30;

const percentile = (sorted, p) => {
  if (sorted.length === 0) return NaN;
  const i = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[i];
};

const summarize = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  return {
    n: s.length,
    p50: Number(percentile(s, 50).toFixed(3)),
    p95: Number(percentile(s, 95).toFixed(3)),
    p99: Number(percentile(s, 99).toFixed(3)),
    max: Number(s[s.length - 1].toFixed(3)),
    mean: Number(mean.toFixed(3)),
  };
};

/** An upstream that answers immediately, so what is timed is the broker and not the internet. */
async function upstream() {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: server.address().port };
}

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** CONNECT through the proxy, timed to the response line that opens or refuses the tunnel. */
function connect(proxyPort, target) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, "127.0.0.1", () => {
      socket.write("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
    });
    let buf = "";
    socket.on("data", (d) => {
      buf += d.toString();
      if (buf.includes("\r\n\r\n")) {
        socket.destroy();
        resolve(buf.split("\r\n")[0]);
      }
    });
    socket.on("error", reject);
  });
}

async function timeMany(label, fn, reps) {
  const n = reps ?? REPS;
  for (let i = 0; i < WARMUP; i += 1) await fn(i);
  const times = [];
  for (let i = 0; i < n; i += 1) {
    const t0 = performance.now();
    await fn(i);
    times.push(performance.now() - t0);
  }
  const s = summarize(times);
  console.log(
    label.padEnd(30),
    String(s.p50).padStart(8),
    String(s.p95).padStart(8),
    String(s.p99).padStart(8),
    String(s.max).padStart(9),
  );
  return Object.assign({ label }, s);
}

async function main() {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "broker-bench-"));
  const up = await upstream();
  const col = await upstream();

  const broker = await startBroker({
    proxyPort: 0,
    modelPort: 0,
    host: "127.0.0.1",
    allowlist: ["127.0.0.1:" + col.port],
    readOnlyDeclarations: [
      { host: "127.0.0.1", port: col.port, methods: ["POST"], pattern: "^/catalog(\\?.*)?$" },
    ],
    decoyHost: "status.shadow-decoy.test",
    modelUpstream: "http://127.0.0.1:" + up.port + "/api/v3",
    providerKey: "FIXTURE-KEY-NOT-REAL",
    turnToken: "FIXTURE-TURN-TOKEN",
    logPath: path.join(tmp, "egress.jsonl"),
    heldPath: path.join(tmp, "held.jsonl"),
    pendingDir: path.join(tmp, "pending"),
    corpus: {},
  });

  const host = "127.0.0.1:" + col.port;
  console.log("host    : " + os.platform() + " " + os.release() + " " + os.arch() +
    ", " + os.cpus().length + " cpus, node " + process.version);
  console.log("upstream: in-process on 127.0.0.1, answering immediately");
  console.log("reps    : " + REPS + " timed after " + WARMUP + " warmup");
  console.log("");
  console.log("channel".padEnd(30), "p50(ms)".padStart(8), "p95(ms)".padStart(8),
    "p99(ms)".padStart(8), "max(ms)".padStart(9));

  const rows = [];

  rows.push(await timeMany("direct to upstream", () =>
    request({ host: "127.0.0.1", port: col.port, path: "/catalog", method: "GET" })));

  rows.push(await timeMany("allowed GET through broker", () =>
    request({ host: "127.0.0.1", port: broker.proxyPort, path: "http://" + host + "/catalog",
      method: "GET", headers: { host } })));

  rows.push(await timeMany("allowed POST (read-like)", (i) =>
    request({ host: "127.0.0.1", port: broker.proxyPort, path: "http://" + host + "/catalog",
      method: "POST", headers: { host, "content-type": "application/json" } },
      JSON.stringify({ q: i }))));

  rows.push(await timeMany("HELD POST (write-like)", (i) =>
    request({ host: "127.0.0.1", port: broker.proxyPort, path: "http://" + host + "/orders",
      method: "POST", headers: { host, "content-type": "application/json" } },
      JSON.stringify({ order: i }))));

  rows.push(await timeMany("DENIED, not allowlisted", () =>
    request({ host: "127.0.0.1", port: broker.proxyPort, path: "http://10.255.255.1:9/x",
      method: "GET", headers: { host: "10.255.255.1:9" } })));

  rows.push(await timeMany("CONNECT tunnel, allowed", () => connect(broker.proxyPort, host), 150));

  const held = await fs.readFile(path.join(tmp, "held.jsonl"), "utf8").catch(() => "");
  const heldCount = held.split("\n").filter(Boolean).length;
  console.log("");
  console.log("held records written: " + heldCount);

  const decisions = broker.decisions();
  const bykind = {};
  for (const d of decisions) {
    const k = d.class + "/" + d.decision;
    bykind[k] = (bykind[k] ?? 0) + 1;
  }
  console.log("decisions by class/decision: " + JSON.stringify(bykind));

  const direct = rows[0].p50;
  console.log("");
  console.log("added latency against the direct call, p50:");
  for (const r of rows.slice(1, 5)) {
    console.log("  " + r.label.padEnd(30) + (r.p50 - direct).toFixed(3) + " ms  (" +
      (r.p50 / direct).toFixed(2) + "x)");
  }

  const out = path.join(tmp, "broker-latency.json");
  await fs.writeFile(out, JSON.stringify({
    host: {
      platform: os.platform(), release: os.release(), arch: os.arch(),
      cpus: os.cpus().length, cpuModel: os.cpus()[0] ? os.cpus()[0].model : "unknown",
      memMb: Math.round(os.totalmem() / 1048576), node: process.version,
      at: new Date().toISOString(),
    },
    reps: REPS, warmup: WARMUP, rows, heldCount, decisions: bykind,
  }, null, 2));
  console.log("");
  console.log("raw: " + out);

  await broker.close();
  up.server.close();
  col.server.close();
}

await main();

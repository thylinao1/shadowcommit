// The mock merchant API. Plain HTTP so a held write can be inspected: a CONNECT tunnel to an
// allowlisted TLS host is opaque, and holding a write requires terminating the connection (SPIKE-F
// honest boundary 1). Zero Track 4 code: this serves and mutates a product catalog and an order
// book, and does no retrieval, ranking or scoring of any kind (CROSS-TRACK guardrail 1).
//
// It is a stand-in for a real merchant backend. `GET` reads; `POST /orders` places an order and is
// the mutating call the held-HTTP participant defers. Data lives in the sibling .jsonl files and is
// reloaded per process, so a test starts from a known book every time.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

function readJsonl(name) {
  try {
    return fs
      .readFileSync(path.join(here, name), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

/**
 * Starts the mock merchant API on `port` (0 for an ephemeral port). Returns the server, its base
 * URL, and the in-memory order book so a test can assert what actually landed. The order book
 * starts from the fixture file and is mutated in memory only, so the committed fixture never
 * changes when the demo places an order.
 */
export function startMerchantApi({ port = 0 } = {}) {
  const catalog = readJsonl("catalog.jsonl");
  const customers = readJsonl("customers.jsonl");
  const orders = readJsonl("orders.jsonl");
  let nextOrder = 4404;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://merchant.local");
    const send = (code, body) => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };

    if (req.method === "GET" && url.pathname === "/health") return send(200, { ok: true });
    if (req.method === "GET" && url.pathname === "/catalog") return send(200, { products: catalog });
    if (req.method === "GET" && url.pathname === "/customers") return send(200, { customers });
    if (req.method === "GET" && url.pathname === "/orders") return send(200, { orders });

    if (req.method === "POST" && url.pathname === "/orders") {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        let payload;
        try {
          payload = JSON.parse(raw || "{}");
        } catch {
          return send(400, { error: "invalid json" });
        }
        const key = req.headers["idempotency-key"] ?? null;
        // Idempotency: replaying a held write after a crash (payload sent, but the sealed copy not
        // yet dropped) must place the order exactly once, not twice. A destination that honours the
        // key is what makes at-most-once real rather than best-effort, so this mock honours it: a
        // POST carrying a key we have already seen returns the existing order with 200, not a new one.
        if (key) {
          const seen = orders.find((o) => o.idempotency_key === key);
          if (seen) return send(200, { order: seen, deduplicated: true });
        }
        const order = {
          order_id: `ORD-${nextOrder++}`,
          user_id: payload.user_id ?? null,
          product_id: payload.product_id ?? null,
          quantity: Number(payload.quantity ?? 1),
          status: "placed",
          placed_at: new Date().toISOString(),
          idempotency_key: key,
        };
        // real placement is the side effect the transaction is about: once this runs, the order
        // exists on the merchant's side and cannot be un-placed, only cancelled by a later call
        orders.push(order);
        send(201, { order });
      });
      return;
    }

    send(404, { error: `no route for ${req.method} ${url.pathname}` });
  });

  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      const boundPort = typeof addr === "object" && addr ? addr.port : port;
      resolve({ server, baseUrl: `http://127.0.0.1:${boundPort}`, orders });
    });
  });
}

// Runnable directly for the demo and the "before" scene: `node server.mjs 8402`.
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("server.mjs")) {
  const port = Number(process.argv[2] ?? 8402);
  startMerchantApi({ port }).then(({ baseUrl }) => {
    console.log(`mock merchant API on ${baseUrl}`);
    console.log("  GET  /catalog /customers /orders /health");
    console.log("  POST /orders  {user_id, product_id, quantity}");
  });
}

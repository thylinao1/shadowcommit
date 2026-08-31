// The modeled exfiltration destination. It logs everything it actually receives, so the proof that
// a held write never landed is the DESTINATION'S own record and not our denial message.
import http from "node:http";
import fs from "node:fs";

const port = Number(process.argv[2] ?? 9100);
const logPath = process.argv[3] ?? "/log/received.jsonl";

http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    try {
      fs.appendFileSync(
        logPath,
        JSON.stringify({ method: req.method, url: req.url, bytes: body.length, body }) + "\n",
      );
    } catch {
      /* still answer */
    }
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ items: ["a", "b"] }));
      return;
    }
    res.writeHead(201, { "content-type": "application/json" });
    res.end(JSON.stringify({ stored: true }));
  });
}).listen(port, "0.0.0.0", () => console.log("collector ready on " + port));

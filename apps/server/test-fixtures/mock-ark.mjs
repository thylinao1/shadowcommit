// A stand-in for the model provider that records every upstream request body, so a test can read
// the model's ACTUAL view of the conversation rather than take our word for what was rolled back.
// The wire shape is the one codex 0.111 speaks (`wire_api = "responses"`, server-sent events);
// it is the mock spike B measured real `codex exec` turns against.
import http from "node:http";
import fs from "node:fs";

const port = Number(process.argv[2] ?? 8398);
const expectedKey = process.argv[3] ?? "real-provider-key";
const logPath = process.argv[4] ?? "/log/requests.jsonl";
let calls = 0;

http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    calls += 1;
    const auth = req.headers.authorization ?? "<none>";
    const keyMatchesTheRealOne = auth === "Bearer " + expectedKey;
    try {
      fs.appendFileSync(
        logPath,
        JSON.stringify({ n: calls, url: req.url, keyMatchesTheRealOne, auth, body }) + "\n",
      );
    } catch {
      /* the response still has to be produced */
    }
    if (!String(req.url).endsWith("/responses")) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"error":{"message":"not found"}}');
      return;
    }
    if (!keyMatchesTheRealOne) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "mock 401: the real key did not arrive" } }));
      return;
    }
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
    const responseId = "resp_mock_" + calls;
    const send = (type, payload) =>
      res.write("event: " + type + "\ndata: " + JSON.stringify({ type, ...payload }) + "\n\n");
    send("response.created", { response: { id: responseId } });
    send("response.output_item.done", {
      item: {
        type: "message",
        role: "assistant",
        id: "msg_" + calls,
        content: [{ type: "output_text", text: "MOCK-ARK-OK turn=" + calls }],
      },
    });
    send("response.completed", {
      response: {
        id: responseId,
        usage: {
          input_tokens: 42,
          input_tokens_details: { cached_tokens: 0 },
          output_tokens: 17,
          output_tokens_details: { reasoning_tokens: 0 },
          total_tokens: 59,
        },
      },
    });
    res.end();
  });
}).listen(port, "0.0.0.0", () => console.log("mock-ark ready on " + port));

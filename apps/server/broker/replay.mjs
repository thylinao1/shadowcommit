// Replay: the only path by which a held write actually reaches its destination, and it runs
// inside the broker container so every byte that leaves still leaves through the one audited
// egress point. Commit is the only caller.
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";

function appendRecord(filePath, record) {
  if (!filePath) return;
  try {
    fs.appendFileSync(filePath, JSON.stringify(record) + "\n");
  } catch {
    /* the send already happened; a failed log line must not be reported as a failed send */
  }
}

/**
 * Sends one held effect for real. Returns what happened rather than throwing, because commit has
 * already been journaled by the time this runs and a rejected promise here would read as a failed
 * commit.
 */
export async function replayOne(pendingDir, effectId, logPath) {
  const file = path.join(pendingDir, effectId + ".json");
  let record;
  let url;
  try {
    record = JSON.parse(fs.readFileSync(file, "utf8"));
    // The URL parse belongs inside this guard, not after it. A held payload that is present but
    // unreadable (truncated by a crash mid-write, or an old record from a previous format) threw
    // out of here, and the only caller is a commit that has already been journaled, so the throw
    // surfaced as a failed commit on a turn whose files had landed.
    url = new URL(record.url);
  } catch (error) {
    const failure = { kind: "egress", effectId, decision: "REPLAY_FAILED",
      reason: "held-payload-unreadable", detail: String(error && error.message) };
    appendRecord(logPath, failure);
    return failure;
  }

  const body = Buffer.from(record.bodyBase64 ?? "", "base64");
  const headers = { ...(record.headers ?? {}), host: url.host };
  delete headers["proxy-connection"];
  delete headers.connection;
  headers["content-length"] = String(body.length);

  const client = url.protocol === "https:" ? https : http;
  const status = await new Promise((resolve) => {
    const request = client.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: record.method ?? "POST",
        headers,
      },
      (response) => {
        response.resume();
        response.on("end", () => resolve({ ok: true, status: response.statusCode ?? 0 }));
      },
    );
    request.on("error", (error) => resolve({ ok: false, error: String(error && error.message) }));
    request.end(body);
  });

  const result = {
    kind: "egress",
    effectId,
    method: record.method,
    host: url.hostname,
    urlPath: url.pathname + url.search,
    bytes: body.length,
    decision: status.ok ? "REPLAYED" : "REPLAY_FAILED",
    status: status.status ?? null,
    reason: status.ok ? null : status.error,
  };
  appendRecord(logPath, result);
  return result;
}

/** Removes every held payload for this turn. Called on discard, reject and conflict. */
export function dropAll(pendingDir) {
  let removed = 0;
  let entries = [];
  try {
    entries = fs.readdirSync(pendingDir);
  } catch {
    return 0;
  }
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    try {
      fs.rmSync(path.join(pendingDir, entry), { force: true });
      removed += 1;
    } catch {
      /* best effort: the directory itself is removed with the shadow */
    }
  }
  return removed;
}

const isMain = process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]));
if (isMain) {
  const [mode, pendingDir, logPath, ...ids] = process.argv.slice(2);
  if (mode === "drop") {
    console.log(JSON.stringify({ kind: "egress.dropped", removed: dropAll(pendingDir) }));
  } else {
    const results = [];
    for (const id of ids) results.push(await replayOne(pendingDir, id, logPath));
    console.log(JSON.stringify({ kind: "egress.replayed", results }));
  }
}

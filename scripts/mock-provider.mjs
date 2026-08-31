// A stand-in for the model provider, so a reviewer with no Ark key can run the whole platform.
//
// It speaks the wire shape codex 0.111 speaks: the OpenAI/Ark Responses API over server-sent
// events, `wire_api = "responses"`. Nothing downstream of it is mocked. codex is the real codex
// CLI, the container is the real runtime container, the shell command it runs is really run, the
// files it writes are really written, and the transaction that captures, judges and settles them
// is the shipped one. The only thing standing in for something is the model's own decision about
// what to do next, and that decision is read from a playbook file so a reader can see exactly
// what was scripted and exactly what was not.
//
// Every request body and every response is appended to a log, so the claim "the model asked for
// this command and the runtime ran it" is checkable against the provider's own record rather than
// against ours.
//
// Usage: node mock-provider.mjs <port> <expected-bearer> <log-path> <playbook-path>
//
// Playbook shape, re-read on every request so a driver can rewrite it between turns:
//   { "entries": [ { "match": "substring of the prompt",
//                    "steps": [ { "cmd": "shell command codex will execute" } ],
//                    "reply": "the assistant message after the last step" } ] }
import http from "node:http";
import fs from "node:fs";

const port = Number(process.argv[2] ?? 8398);
const expectedKey = process.argv[3] ?? "mock-provider-key";
const logPath = process.argv[4] ?? "/state/provider.jsonl";
const playbookPath = process.argv[5] ?? "/state/playbook.json";

let calls = 0;
let logFailureReported = false;

/**
 * Appends one record to the provider log; a failed write must never break the response.
 *
 * The swallow is deliberate -- a turn in flight still has to get an answer -- but a silent swallow
 * is how this file produced an undiagnosable failure: the provider ran, answered 200, and wrote
 * nothing, and the only thing that noticed was the demo driver's provenance assertion three beats
 * later. So the first failure is named on stderr, where `docker logs` puts it in front of whoever
 * is looking. `assertLogWritable()` below catches the common case before the port is even open.
 */
function record(entry) {
  try {
    fs.appendFileSync(logPath, JSON.stringify(entry) + "\n");
  } catch (error) {
    if (!logFailureReported) {
      logFailureReported = true;
      console.error(
        "mock-provider: the request log at " + logPath + " went unwritable mid-run (" +
          (error?.code ?? error?.message ?? String(error)) +
          "). Requests are still answered, but this run's provider log is incomplete from here on.",
      );
    }
  }
}

/**
 * Prove the log is appendable before opening the port, and die loudly if it is not.
 *
 * The failure this closes: the container is launched with `--cap-drop ALL`, so its root has no
 * CAP_DAC_OVERRIDE, and on a host whose bind mounts carry real uids it cannot append to the
 * host-owned provider.jsonl. Every symptom pointed the wrong way -- the process started, the port
 * answered, HTTP was 200, stderr was empty -- because `record()` swallowed the EACCES. Rootless
 * uid mapping, an SELinux label on the bind mount and a read-only remount all land here too, and
 * all of them used to look identical from outside.
 *
 * Exiting non-zero here means the starter's readiness loop never sees `mock-provider.ready`, prints
 * `<engine> logs` and stops, which is where this message is waiting.
 */
function assertLogWritable() {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const gid = typeof process.getgid === "function" ? process.getgid() : null;
  try {
    fs.appendFileSync(
      logPath,
      JSON.stringify({ n: 0, event: "mock-provider.start", logPath, playbookPath, port, uid, gid }) + "\n",
    );
  } catch (error) {
    const code = error?.code ?? "unknown";
    console.error("mock-provider: cannot append to the request log at " + logPath + " (" + code + ").");
    console.error(
      "mock-provider: running as uid=" + uid + " gid=" + gid +
        ". Every request would be answered and none of them recorded, so this is fatal rather than " +
        "degraded: the demo's provenance evidence comes out of that file.",
    );
    if (code === "EACCES" || code === "EPERM") {
      console.error(
        "mock-provider: the mounted file is owned by another uid and --cap-drop ALL removed " +
          "CAP_DAC_OVERRIDE, so being root in here buys nothing. Set MOCK_PROVIDER_USER in " +
          "scripts/start-mock-poc.sh to the uid that owns it, or to the empty string on a rootless " +
          "engine where the container's root is already that user.",
      );
    }
    process.exit(1);
  }
}

function readPlaybook() {
  try {
    return JSON.parse(fs.readFileSync(playbookPath, "utf8"));
  } catch {
    return { entries: [] };
  }
}

/** The text of the last user message: the prompt this turn is actually about. */
function promptOf(input) {
  if (!Array.isArray(input)) return "";
  for (let i = input.length - 1; i >= 0; i -= 1) {
    const item = input[i];
    if (item?.type === "message" && item?.role === "user") {
      const parts = Array.isArray(item.content) ? item.content : [];
      return parts.map((part) => part?.text ?? "").join("\n");
    }
  }
  return "";
}

/**
 * How many of this turn's tool calls have already come back.
 *
 * Counted only after the last user message, so a resumed thread carrying earlier turns' tool
 * output does not push the step index past the end of the playbook entry.
 */
function stepsDone(input) {
  if (!Array.isArray(input)) return 0;
  let lastUser = -1;
  for (let i = 0; i < input.length; i += 1) {
    if (input[i]?.type === "message" && input[i]?.role === "user") lastUser = i;
  }
  let done = 0;
  for (let i = lastUser + 1; i < input.length; i += 1) {
    if (input[i]?.type === "function_call_output") done += 1;
  }
  return done;
}

/**
 * What the runtime sent back after running the last tool call.
 *
 * This is the only place the command's real output is visible outside the container, and it is the
 * turn's own account of what the sandbox let it do. Kept bounded, and logged, so a claim about the
 * network can be checked against what the turn observed rather than what we say it observed.
 */
function lastToolOutput(input) {
  if (!Array.isArray(input)) return null;
  for (let i = input.length - 1; i >= 0; i -= 1) {
    if (input[i]?.type === "function_call_output") {
      const output = input[i].output;
      const text = typeof output === "string" ? output : JSON.stringify(output);
      return text.length > 4000 ? text.slice(0, 4000) + "...[truncated]" : text;
    }
  }
  return null;
}

function entryFor(prompt) {
  const playbook = readPlaybook();
  const entries = Array.isArray(playbook.entries) ? playbook.entries : [];
  const needle = prompt.toLowerCase();
  return entries.find((entry) => needle.includes(String(entry.match ?? "").toLowerCase())) ?? null;
}

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    calls += 1;
    const authorization = req.headers.authorization ?? "<none>";
    const keyMatches = authorization === "Bearer " + expectedKey;

    if (!String(req.url).endsWith("/responses")) {
      record({ n: calls, url: req.url, decision: "404" });
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "not found" } }));
      return;
    }
    if (!keyMatches) {
      // The same 401 a real Ark endpoint answers a wrong credential with, so the failure mode a
      // reviewer might hit on the keyed path is the failure mode they hit here.
      record({ n: calls, url: req.url, decision: "401", authPrefix: authorization.slice(0, 14) });
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "AuthenticationError: mock 401 (wrong or missing key)" } }));
      return;
    }

    let parsed = {};
    try {
      parsed = JSON.parse(body);
    } catch {
      /* an unparsable body still gets a well-formed answer */
    }
    const prompt = promptOf(parsed.input);
    const done = stepsDone(parsed.input);
    const entry = entryFor(prompt);
    const steps = Array.isArray(entry?.steps) ? entry.steps : [];
    const step = done < steps.length ? steps[done] : null;
    const toolOutput = lastToolOutput(parsed.input);

    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
    const responseId = "resp_mock_" + calls;
    const send = (type, payload) =>
      res.write("event: " + type + "\ndata: " + JSON.stringify({ type, ...payload }) + "\n\n");
    send("response.created", { response: { id: responseId } });

    if (step) {
      // A real tool call. codex runs this in the runtime container under its own sandbox; nothing
      // here executes anything.
      send("response.output_item.done", {
        item: {
          type: "function_call",
          id: "fc_" + calls,
          call_id: "call_" + calls,
          name: "exec_command",
          arguments: JSON.stringify({ cmd: step.cmd }),
        },
      });
      record({
        n: calls,
        url: req.url,
        keyMatches,
        promptTail: prompt.slice(-160),
        matched: entry?.match ?? null,
        stepIndex: done,
        emitted: "function_call",
        cmd: step.cmd,
        toolOutput,
        requestBytes: body.length,
      });
    } else {
      const text = entry?.reply ?? "MOCK-PROVIDER-OK turn=" + calls + ": no playbook entry matched this prompt.";
      send("response.output_item.done", {
        item: {
          type: "message",
          role: "assistant",
          id: "msg_" + calls,
          content: [{ type: "output_text", text }],
        },
      });
      record({
        n: calls,
        url: req.url,
        keyMatches,
        promptTail: prompt.slice(-160),
        matched: entry?.match ?? null,
        stepIndex: done,
        emitted: "message",
        text,
        toolOutput,
        requestBytes: body.length,
      });
    }

    send("response.completed", {
      response: {
        id: responseId,
        usage: {
          input_tokens: 128,
          input_tokens_details: { cached_tokens: 0 },
          output_tokens: 32,
          output_tokens_details: { reasoning_tokens: 0 },
          total_tokens: 160,
        },
      },
    });
    res.end();
  });
});

// Before the port opens, so a provider that cannot record anything never reports itself ready.
assertLogWritable();

server.listen(port, "0.0.0.0", () => {
  // The line the starter waits for before it hands the address to the platform.
  console.log("mock-provider.ready port=" + port + " playbook=" + playbookPath);
});

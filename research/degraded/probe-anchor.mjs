// probe-anchor.mjs: can a reader of the journal tell "anchoring was switched off" from
// "anchoring was never reached"?
//
//   node research/degraded/probe-anchor.mjs
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { pathToFileURL, fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(here, "..", "..", "apps", "server", "dist");
const load = (m) => import(pathToFileURL(path.join(DIST, m)).href);

const { Journal } = await load("journal.js");
const { anchorsFromEnv } = await load("anchors.js");

const head = (t) => console.log("\n== " + t + " ==");
const row = (l, v) => console.log("  " + String(l).padEnd(38) + " " + v);

async function runWith(label, env, anchorsOverride) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "anchor-"));
  const journalPath = path.join(dir, "journal.jsonl");
  const anchors = anchorsOverride ?? anchorsFromEnv(dir, env);
  const journal = new Journal({ journalPath, anchors });
  await journal.append({ kind: "turn.begin", runId: "r1" });
  await journal.append({ kind: "turn.committing", agentId: "a", effects: [] });
  await journal.checkpoint?.().catch(() => undefined);
  await journal.close?.().catch(() => undefined);
  const lines = fs.existsSync(journalPath)
    ? fs.readFileSync(journalPath, "utf8").trim().split("\n").filter(Boolean).map((l) => {
        try { return JSON.parse(l); } catch { return { kind: "unparsed" }; }
      })
    : [];
  const kinds = lines.map((r) => r.kind);
  head(label);
  row("anchors configured", String(anchors.length));
  row("record kinds written", kinds.join(", ") || "(none)");
  row("any anchor.ok", String(kinds.includes("anchor.ok")));
  row("any anchor.failed", String(kinds.includes("anchor.failed")));
  row("any record naming anchoring at all",
      String(kinds.some((k) => String(k).startsWith("anchor"))));
  return kinds;
}

await runWith("A. SHADOW_ANCHORS=none, anchoring switched off", { SHADOW_ANCHORS: "none" });

await runWith("B. an anchor that FAILS", {}, [
  { name: "probe-failing", async submit() { throw new Error("anchor unreachable in this probe"); } },
]);

await runWith("C. an anchor that SUCCEEDS", {}, [
  { name: "probe-ok", async submit() { return { id: "receipt-1" }; } },
]);

console.log("\nThe question: in case A, is there anything in the journal a reader could use to");
console.log("tell 'switched off' from 'never reached'?");

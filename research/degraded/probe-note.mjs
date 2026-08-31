// probe-note.mjs: with the network seal OFF and the unconfined override ON, on a host with no
// container engine, what does the confinement note say, and does anything reach the journal?
//
//   node research/degraded/probe-note.mjs
//
// This is the one combination that reaches the `"container"` branch of the note without touching
// the engine: sealNetwork=false means the sealer is never called, so nothing verifies that a
// container runtime exists before the note names one.
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { pathToFileURL, fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const KIT = path.resolve(here, "..", "..");
const DIST = path.join(KIT, "apps", "server", "dist");
const load = (m) => import(pathToFileURL(path.join(DIST, m)).href);

const row = (l, v) => console.log("  " + String(l).padEnd(34) + " " + v);
const head = (t) => console.log("\n== " + t + " ==");

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "note-"));
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ws-"));
fs.writeFileSync(path.join(workspace, "hello.txt"), "hi\n");

const { loadConfig } = await load("config.js");
const { ShadowConfinement } = await load("runner-factory.js");
const { NetworkSealer } = await load("network-sealer.js");
const { CodexHomeManager } = await load("codex-home.js");

const config = loadConfig({
  ...process.env,
  APP_DATA_DIR: dataDir,
  ARK_API_KEY: "sk-probe-not-a-real-key",
  RUNTIME_PROVIDER: "container",
  SHADOW_CONFINE_NETWORK: "false",
  SHADOW_ALLOW_UNCONFINED: "1",
});

head("config actually in force");
row("runtimeProvider", config.runtimeProvider);
row("shadowConfineNetwork", String(config.shadowConfineNetwork));
row("shadowAllowUnconfined", String(config.shadowAllowUnconfined));
row("docker present on this host", "no (measured in probe-degraded.mjs)");

const shadowRoot = path.join(dataDir, "shadow");
fs.mkdirSync(shadowRoot, { recursive: true });
const shadowDir = path.join(shadowRoot, "run-probe");
fs.mkdirSync(shadowDir, { recursive: true });

const confinement = new ShadowConfinement(
  config,
  new NetworkSealer(config),
  new CodexHomeManager(config),
  { sealNetwork: config.shadowConfineNetwork, shadowRoot },
);

head("ShadowConfinement.open() on a host with no engine");
try {
  const { note } = await confinement.open({
    runId: "run-probe",
    request: { agentId: "11111111-1111-4111-8111-111111111111", workspacePath: workspace, prompt: "probe" },
    shadowDir,
  });
  row("open() returned", "a note, no engine was contacted");
  console.log("\n  THE NOTE THAT REACHES THE JOURNAL:");
  for (const [k, v] of Object.entries(note)) {
    console.log("    " + k.padEnd(26) + " " + JSON.stringify(v));
  }
  const claim = note.confinement;
  console.log("");
  row("note.confinement", JSON.stringify(claim));
  row("is there a container", "NO. docker is not installed on this host");
  row("verdict", claim === "container"
    ? "THE NOTE CLAIMS A CONTROL THAT IS ABSENT"
    : "the note does not overclaim");
} catch (error) {
  row("open() THREW", error.message.split("\n")[0].slice(0, 110));
  row("verdict", "fails closed, nothing written");
}

console.log("\n  data dir " + dataDir);

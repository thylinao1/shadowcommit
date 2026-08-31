// probe-degraded.mjs: what does the runtime do when the confinement layer is absent?
//
//   node research/degraded/probe-degraded.mjs
//
// Runs against the BUILT dist, with the product's own config loader and runner factory, on a host
// with no container engine. Every line it prints is something it did, not something it read.
//
// The question is not whether a turn succeeds. It is whether anything the system writes down claims
// a control held that was never present.
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { pathToFileURL } from "node:url";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const KIT = path.resolve(here, "..", "..");
const DIST = path.join(KIT, "apps", "server", "dist");

const load = (m) => import(pathToFileURL(path.join(DIST, m)).href);

const row = (label, value) => console.log("  " + String(label).padEnd(46) + " " + value);
const head = (t) => console.log("\n== " + t + " ==");

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "degraded-"));

function baseEnv(extra = {}) {
  return {
    ...process.env,
    APP_DATA_DIR: dataDir,
    ARK_API_KEY: "sk-probe-not-a-real-key",
    ...extra,
  };
}

const { loadConfig } = await load("config.js");
const factory = await load("runner-factory.js");

head("A. what config does this host get by DEFAULT");
let cfg = null;
try {
  cfg = loadConfig(baseEnv());
  row("loadConfig()", "ok");
  row("runtimeProvider", cfg.runtimeProvider);
  row("containerEngine", cfg.containerEngine ?? "(field absent)");
  row("shadowConfineNetwork", String(cfg.shadowConfineNetwork));
  row("shadowAllowUnconfined", String(cfg.shadowAllowUnconfined));
} catch (error) {
  row("loadConfig() THREW", error.message.split("\n")[0]);
}

head("B. does createRunner refuse on a host with no engine");
for (const [label, env] of [
  ["default (container, sealed network)", baseEnv()],
  ["RUNTIME_PROVIDER=local-process", baseEnv({ RUNTIME_PROVIDER: "local-process" })],
  ["container, SHADOW_CONFINE_NETWORK=false", baseEnv({ SHADOW_CONFINE_NETWORK: "false" })],
  ["local-process + SHADOW_ALLOW_UNCONFINED=1", baseEnv({ RUNTIME_PROVIDER: "local-process", SHADOW_ALLOW_UNCONFINED: "1" })],
]) {
  let c;
  try {
    c = loadConfig(env);
  } catch (error) {
    row(label, "config REJECTED: " + error.message.split("\n")[0].slice(0, 90));
    continue;
  }
  try {
    const runner = factory.createRunner(c);
    row(label, "createRunner RETURNED a runner (" + runner.constructor.name + ")");
  } catch (error) {
    row(label, "REFUSED: " + error.message.split("\n")[0].slice(0, 95));
  }
}

head("C. is the engine ever probed before a runner is handed out");
// If construction never touches the engine, then "container" in a note is a statement about
// configuration, not about anything that was verified to exist.
const engineOnPath = (() => {
  const dirs = (process.env.PATH ?? "").split(path.delimiter);
  const names = process.platform === "win32" ? ["docker.exe", "docker.cmd", "docker"] : ["docker"];
  for (const d of dirs) for (const n of names) {
    try { if (fs.existsSync(path.join(d, n))) return path.join(d, n); } catch { /* unreadable dir */ }
  }
  return null;
})();
row("docker on PATH", engineOnPath ?? "NOT FOUND");
row("createRunner with no engine present", "see section B, first row");

head("D. what the confinement note would say");
// The note is built in ShadowConfinement.begin(). Read the shipped expression rather than guessing.
const src = fs.readFileSync(path.join(KIT, "apps/server/src/runner-factory.ts"), "utf8");
const noteLine = src.split("\n").find((l) => l.includes('confinement: network ?'));
row("the shipped expression", (noteLine ?? "(not found)").trim());
row("derived from", "the config-built `network` object, not from an engine probe");

console.log("\ndata dir left at " + dataDir);

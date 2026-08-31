/**
 * The self test for `scripts/demo-smoke.mjs`, which is the single step that decides whether the
 * demo job is green.
 *
 * WHY THIS EXISTS. `demo.yml` had never once started: eight `${{ runner.temp }}` values sat in
 * `jobs.demo.env`, the `runner` context does not exist at job level, and the workflow was rejected
 * at parse time so every run reported `completed/failure` with zero jobs. Fixing that made the gate
 * RUN. It said nothing about whether the gate can FAIL, and a gate that cannot fail is worse than
 * no gate, because it is read as evidence.
 *
 * So this sweeps it. Every case is a way the demo can actually break, and each one asserts both
 * that the gate goes red AND the reason it gives, because a gate that fails for the wrong reason
 * has not noticed the thing it is being credited with noticing. The first sweep found one hole:
 * an empty `$DRIVER_EXIT`, which is what an unset shell variable expands to inside quotes, was
 * read as exit 0 by `Number("")` and the gate reported "npm run demo:drive exited 0" for a driver
 * it had heard nothing about.
 *
 *   node scripts/demo-smoke.selftest.mjs
 *
 * Every path here resolves from this file rather than from the working directory, so it cannot
 * pass only on the machine that wrote it.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const GATE = join(HERE, "demo-smoke.mjs");
const FIXTURE = join(HERE, "fixtures", "demo-drive-passing.log");

const PASSING = readFileSync(FIXTURE, "utf8");
const work = mkdtempSync(join(tmpdir(), "demo-smoke-selftest-"));

/** Write a variant of the passing log and return its path. */
function variant(name, text) {
  const p = join(work, name + ".log");
  writeFileSync(p, text);
  return p;
}

/** Drop every line containing `needle`. */
const without = (needle) => PASSING.split("\n").filter((l) => !l.includes(needle)).join("\n");

/** Rewrite one settlement verdict in the beat 8 timeline to a different one. */
const reverdict = (from, to) =>
  PASSING.split("\n")
    .map((l) => (l.startsWith("    " + from + " ") ? l.replace("    " + from + " ", "    " + to + " ") : l))
    .join("\n");

const RED = "the demo did not run end to end";

/** name, log path, exit code argument, expected outcome, and for a red case the reason it must give. */
const CASES = [
  ["the real passing log", FIXTURE, "0", "green", null],

  // The exit status arm. The gate's header promises it will not assume an exit code it was not given.
  ["driver exited 1", FIXTURE, "1", "red", "exited 1"],
  ["driver hung and was killed (124)", FIXTURE, "124", "red", "hung"],
  ["driver exited 7", FIXTURE, "7", "red", "exited 7"],
  ["driver exited -1", FIXTURE, "-1", "red", "exited -1"],
  ["DRIVER_EXIT unset, so the argument is empty", FIXTURE, "", "red", "will not assume"],
  ["DRIVER_EXIT is whitespace", FIXTURE, "   ", "red", "will not assume"],
  ["DRIVER_EXIT is a newline", FIXTURE, "\n", "red", "will not assume"],
  ["DRIVER_EXIT is not a number", FIXTURE, "banana", "red", "will not assume"],
  ["DRIVER_EXIT is a float", FIXTURE, "0.5", "red", "will not assume"],
  ["DRIVER_EXIT is hex for zero", FIXTURE, "0x0", "red", "will not assume"],
  ["the exit argument is absent entirely", FIXTURE, undefined, "red", "will not assume"],

  // The log arm.
  ["the log is empty", variant("empty", ""), "0", "red", "is empty"],
  ["the log does not exist", join(work, "no-such-file.log"), "0", "red", "wrote no log"],
  ["the run stopped before the end marker", variant("truncated", PASSING.split("\n").slice(0, 150).join("\n")), "0", "red", "never reached the end"],
  ["the end marker is gone", variant("noend", without("STAGE 1 COMPLETE.")), "0", "red", "never reached the end"],
  ["the stage 1 banner is gone, so this could be another stage", variant("nobanner", without("SHADOW COMMIT: THE COMPLETE DEMO PATH")), "0", "red", "does not start the drive stage"],
  ["the publish line is gone", variant("nopublish", without("written to")), "0", "red", "did not publish"],

  // The beats arm, one case per beat, because a gate that counted beats would go green on a run
  // that did fewer of them.
  ...["0", "1", "2", "3", "4", "5", "5b", "6", "6b", "7", "8"].map((b) => [
    "beat " + b + " never ran",
    variant("nobeat-" + b, without("BEAT " + b + " ")),
    "0",
    "red",
    "BEAT " + b,
  ]),

  // The settlement arm. A run that reached the end while only ever committing is not the demo.
  ...["discarded", "approved", "rejected", "held"].map((v) => [
    "no turn was " + v,
    variant("noverdict-" + v, reverdict(v, "committed")),
    "0",
    "red",
    v,
  ]),
  ["no turn was committed", variant("noverdict-committed", reverdict("committed", "held")), "0", "red", "committed"],

  // The driver's own failure signals.
  ["the driver reported a failed assertion", variant("assert", PASSING + "\nFAILED: the middleware never held a turn\n"), "0", "red", "failed assertion"],
  ["the driver declared the run failed", variant("failedrun", PASSING + "\nthis run FAILED, so nothing was published\n"), "0", "red", "declared the run failed"],
];

let broken = 0;
for (const [name, logPath, exitArg, expect, reason] of CASES) {
  const argv = exitArg === undefined ? [GATE, logPath] : [GATE, logPath, exitArg];
  const r = spawnSync(process.execPath, argv, { encoding: "utf8" });
  const out = (r.stdout || "") + (r.stderr || "");
  const wentRed = r.status !== 0;
  const wantRed = expect === "red";

  if (wentRed !== wantRed) {
    console.log("BROKEN  " + name + ": expected " + expect + ", the gate exited " + r.status);
    broken += 1;
    continue;
  }
  if (wantRed && !out.includes(RED)) {
    console.log("BROKEN  " + name + ": went red without saying so in its summary");
    broken += 1;
    continue;
  }
  if (wantRed && reason && !out.toLowerCase().includes(reason.toLowerCase())) {
    console.log("BROKEN  " + name + ": went red for the wrong reason, expected to see " + JSON.stringify(reason));
    console.log(out.split("\n").filter((l) => l.startsWith("-")).join("\n"));
    broken += 1;
    continue;
  }
  console.log("ok      " + name);
}

rmSync(work, { recursive: true, force: true });

console.log("");
console.log(CASES.length - broken + " of " + CASES.length + " cases behaved correctly");
if (broken > 0) {
  console.log("::error::the demo gate does not fail on " + broken + " of the ways the demo can break");
  process.exit(1);
}

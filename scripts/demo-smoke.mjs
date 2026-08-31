/**
 * The gate for the demo job in `.github/workflows/demo.yml`.
 *
 * One question: did `npm run demo:drive` reach the end of the demo path against a platform this
 * run started? Nothing green currently attests to that, so the demo can break while `main` stays
 * green, and twice the committed evidence at HEAD was a failed run that a person found rather
 * than a gate.
 *
 *   node scripts/demo-smoke.mjs <driver-stdout-log> <driver-exit-code>
 *
 * What it keys on, in order of authority:
 *
 *   1. The driver's exit status. `scripts/demo-drive.mjs` ends with
 *      `process.exit(failure ? 1 : 0)` (line 881), and every assertion in it goes through `must()`,
 *      which throws `DemoFailure`, which the top-level `try` catches into `failure`. So a single
 *      failed assertion is exit 1. A non-zero status is checked BEFORE the log is opened, for the
 *      same reason the sealer gate in check.yml checks vitest's status before reading its report:
 *      a green-looking log next to a red process is either a leftover or a run that died after
 *      printing, and neither is evidence this gate may stand on. 124 is what GNU `timeout` returns
 *      when it had to kill a driver that hung, and it fails here like any other non-zero code.
 *
 *   2. The end-of-run marker. Exit 0 alone would also be produced by a driver that returned early
 *      without doing anything, so the log has to show the last line stage 1 prints. This is a
 *      second mechanism, not a restatement of the first.
 *
 *   3. The beats, named rather than counted. If a beat is deleted, this goes red and whoever
 *      deleted it has to say here what now proves the demo path ran. A gate that counted beats
 *      would go quietly green on a run that did fewer of them.
 *
 *   4. The five settlement verdicts. The middleware behaviour the demo exists to show is a turn
 *      being committed, discarded, held, approved and rejected. A run that reached the end while
 *      only ever committing is not the demo, and the beat headings alone would not notice.
 *
 * What it deliberately does not do: grep the log for the word FAILED. A successful transcript
 * contains `DIRECT_EGRESS_FAILED`, the runtime's own report of the egress denial in beat 5b
 * (`grep -n FAILED evidence/demo-run/transcript.txt` finds it on line 88 of a passing run), so an
 * unanchored match would fail every green run. The driver's own failure line is anchored at the
 * start of a line and that is what is matched.
 */
import { appendFileSync, existsSync, readFileSync } from "node:fs";

/** The banner stage 1 prints first, so a log from `--stage after-browser` cannot satisfy this gate. */
const STAGE_1_BANNER = "SHADOW COMMIT: THE COMPLETE DEMO PATH";

/** The last line `stageDrive()` prints, at scripts/demo-drive.mjs:747. */
const END_OF_RUN = "STAGE 1 COMPLETE.";

/** Printed by the driver's `finally` when the run failed, at scripts/demo-drive.mjs:820. */
const FAILED_RUN = /^this run FAILED, so /m;

/** `say("FAILED: " + ...)`, anchored, for the reason given in the header comment. */
const FAILED_ASSERTION = /^FAILED: (.*)$/m;

/** The transactional publish at the end of a successful run, scripts/demo-drive.mjs:838. */
const PUBLISHED = /^written to (\S*transcript\.txt)$/m;

/** Every beat `stageDrive()` prints. Two of them are the abuse cases; none of them is optional. */
const REQUIRED_BEATS = [
  "BEAT 0 ",
  "BEAT 1 ",
  "BEAT 2 ",
  "BEAT 3 ",
  "BEAT 4 ",
  "BEAT 5 ",
  "BEAT 5b ",
  "BEAT 6 ",
  "BEAT 6b ",
  "BEAT 7 ",
  "BEAT 8 ",
];

/**
 * The run timeline printed in beat 8, one line per turn:
 * `"    " + verdict.padEnd(10) + rule.padEnd(26) + effects + runId` (demo-drive.mjs lines 690 to 698).
 */
const VERDICT_LINE = /^ {4}(committed|discarded|approved|rejected|held) /gm;
const REQUIRED_VERDICTS = ["committed", "discarded", "approved", "rejected", "held"];

const logPath = process.argv[2];

/**
 * The exit code, parsed strictly, and the strictness is the point.
 *
 * This was `Number(process.argv[3] ?? "NaN")`, and the `??` only fires when the argument is absent
 * entirely. The workflow invokes this gate as `node scripts/demo-smoke.mjs "$DRIVE_LOG"
 * "$DRIVER_EXIT"`, and an UNSET shell variable inside quotes is not an absent argument, it is an
 * empty string. `Number("")` is 0, and `Number.isInteger(0)` is true, so a gate whose header
 * promises it "will not assume 0" reported `npm run demo:drive exited 0` for a driver it had heard
 * nothing about. A single space and a bare newline do the same thing.
 *
 * Not reachable in demo.yml as it stands, because the step that writes DRIVER_EXIT to GITHUB_ENV
 * has to succeed for this step to run at all. It is one edit away from reachable: adding
 * `if: always()` to the step below, which is exactly what somebody does when they want diagnostics
 * out of a red run, would turn this into a gate that goes green over a demo that never started.
 * That is the failure this whole file exists to prevent, so it is fixed here rather than left to
 * the surrounding workflow to keep accidentally covering.
 *
 * A digit string, optionally signed, and nothing else. `scripts/demo-smoke.selftest.mjs` sweeps it.
 */
const rawExit = process.argv[3];
const driverExit = /^[+-]?\d+$/.test(String(rawExit ?? "").trim()) ? Number(rawExit) : Number.NaN;

const problems = [];
const facts = [];

if (!logPath) problems.push("no log path was passed to this gate, so it has nothing to read");
if (!Number.isInteger(driverExit)) {
  problems.push(
    "no usable driver exit code was passed (got " +
      JSON.stringify(process.argv[3]) +
      "); this gate will not assume 0",
  );
}

if (Number.isInteger(driverExit) && driverExit !== 0) {
  problems.push(
    driverExit === 124
      ? "the driver hung and was killed by its timeout (exit 124), so the demo did not complete"
      : "npm run demo:drive exited " + driverExit + ", so the demo did not complete",
  );
}

let log = "";
if (logPath) {
  if (!existsSync(logPath)) {
    problems.push("the driver wrote no log at " + logPath + ", so nothing here knows what happened");
  } else {
    log = readFileSync(logPath, "utf8");
    if (log.trim().length === 0) problems.push("the driver's log at " + logPath + " is empty");
  }
}

if (log.length > 0) {
  const assertionFailure = log.match(FAILED_ASSERTION);
  if (assertionFailure) problems.push("the driver reported a failed assertion: " + assertionFailure[1]);
  if (FAILED_RUN.test(log)) problems.push("the driver itself declared the run failed and did not publish it");

  if (!log.includes(STAGE_1_BANNER)) {
    problems.push("the log does not start the drive stage (no " + JSON.stringify(STAGE_1_BANNER) + ")");
  }
  if (!log.includes(END_OF_RUN)) {
    problems.push(
      "the driver never reached the end of the demo path (no " +
        JSON.stringify(END_OF_RUN) +
        " in its output)",
    );
  }

  for (const beat of REQUIRED_BEATS) {
    if (!log.includes(beat)) {
      problems.push(
        "no " + beat.trim() + " in the driver's output; if that beat moved, point this gate at where it went",
      );
    }
  }

  const verdicts = new Set([...log.matchAll(VERDICT_LINE)].map((match) => match[1]));
  for (const verdict of REQUIRED_VERDICTS) {
    if (!verdicts.has(verdict)) {
      problems.push("no turn was " + verdict + " in the run timeline, so the demo did not show that path");
    }
  }
  if (verdicts.size > 0) facts.push("settlement paths shown: " + [...verdicts].sort().join(", "));

  const published = log.match(PUBLISHED);
  if (published) facts.push("the run published its own transcript to " + published[1]);
  else problems.push("the driver never said where it wrote its transcript, so the run did not publish");

  const okLines = log.split("\n").filter((line) => line.startsWith("  ok   ")).length;
  facts.push(okLines + " assertions passed inside the driver");
}

const unique = (xs) => [...new Set(xs)];
const summary = [];
if (problems.length > 0) {
  for (const problem of unique(problems)) console.log("::error::" + problem);
  summary.push("### the demo did not run end to end", "");
  for (const problem of unique(problems)) summary.push("- " + problem);
  if (facts.length > 0) {
    summary.push("", "What the run did manage:", "");
    for (const fact of unique(facts)) summary.push("- " + fact);
  }
  process.exitCode = 1;
} else {
  summary.push("### the demo ran end to end", "");
  summary.push("- npm run demo:drive exited 0");
  summary.push("- every beat from BEAT 0 to BEAT 8 is in its output");
  for (const fact of unique(facts)) summary.push("- " + fact);
}

const text = summary.join("\n") + "\n";
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, text);
console.log(text);

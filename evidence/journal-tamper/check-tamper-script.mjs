/**
 * The paths `scripts/demo-tamper.mjs` only takes when something has already gone wrong.
 *
 * The happy path is exercised every time anybody runs the demo. These five are exercised only when
 * a run is interrupted, or a ledger is already broken, or somebody else has written where the undo
 * says they should not have, which is exactly when nobody is looking. A tamper script whose restore
 * is untested is a tamper script that will one day leave a developer's audit ledger broken, so each
 * one is driven here and the journal is hashed before and after.
 *
 *   npx tsx evidence/journal-tamper/build-synthetic-journal.mts /tmp/somewhere
 *   node evidence/journal-tamper/check-tamper-script.mjs /tmp/somewhere
 *
 * Case B sends a real SIGINT to a real child process rather than asserting that a handler is
 * registered. It waits for the ticket file to appear instead of sleeping a fixed interval, because
 * the ticket is written immediately before the byte is, so its appearance IS the window opening.
 */
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const ROOT = process.argv[2];
if (!ROOT) {
  process.stderr.write("usage: node evidence/journal-tamper/check-tamper-script.mjs <directory built by build-synthetic-journal.mts>\n");
  process.exit(2);
}
const DATA = path.join(ROOT, "data");
const HOME = path.join(ROOT, "home");
const J = path.join(DATA, "journal.jsonl");
const TICKET = J + ".tamper-restore.json";
const ENV = { ...process.env, SHADOW_COMMIT_HOME: HOME };
const ARGS = ["--journal", J, "--data-dir", DATA];
const SCRIPT = path.join(REPO, "scripts", "demo-tamper.mjs");

const sha = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const run = (extra = []) =>
  spawnSync(process.execPath, [SCRIPT, ...ARGS, ...extra], { cwd: REPO, env: ENV, encoding: "utf8" });
const verify = () =>
  spawnSync(path.join(REPO, "node_modules/.bin/tsx"), ["apps/server/src/verify-journal.ts", ...ARGS], {
    cwd: REPO,
    env: ENV,
    encoding: "utf8",
  }).status;
const offsetOf = (needle, field) => fs.readFileSync(J).indexOf(Buffer.from(needle)) + field.length;

const clean = sha(J);
let failures = 0;
const check = (label, ok, detail = "") => {
  process.stdout.write((ok ? "  PASS  " : "  FAIL  ") + label + (detail ? "   " + detail : "") + "\n");
  if (!ok) failures += 1;
};

process.stdout.write("\nA. a SIGKILL between the tamper and the restore, simulated exactly\n");
{
  // What a SIGKILL leaves behind: the ticket on disk and the byte still flipped, because no handler
  // ran at all. Constructed by hand rather than by killing a process, so the state is exact.
  const buf = fs.readFileSync(J);
  const offset = offsetOf('"verdict":"discarded"', '"verdict":"');
  const original = buf[offset];
  const tampered = original + 1;
  fs.writeFileSync(
    TICKET,
    JSON.stringify(
      {
        journal: J,
        offset,
        originalByte: original,
        tamperedByte: tampered,
        prefixLength: buf.length,
        prefixSha256: sha(J),
        writtenAt: new Date().toISOString(),
        field: "verdict",
        seq: 8,
        line: 8,
      },
      null,
      2,
    ),
  );
  const fd = fs.openSync(J, "r+");
  fs.writeSync(fd, Buffer.from([tampered]), 0, 1, offset);
  fs.closeSync(fd);
  check("the simulated crash really did break it", verify() === 1);

  const r = run(["--restore-only"]);
  check("--restore-only exits 0", r.status === 0, "exit " + r.status);
  check("the journal is byte-for-byte what it was", sha(J) === clean);
  check("the verifier passes again", verify() === 0);
  check("the ticket is gone", !fs.existsSync(TICKET));
}

process.stdout.write("\nB. a real SIGINT while the ledger is broken\n");
await new Promise((resolve) => {
  const child = spawn(process.execPath, [SCRIPT, ...ARGS], { cwd: REPO, env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  child.stderr.on("data", (chunk) => (err += chunk));
  const timer = setInterval(() => {
    if (fs.existsSync(TICKET)) {
      clearInterval(timer);
      child.kill("SIGINT");
    }
  }, 5);
  child.on("close", (code) => {
    clearInterval(timer);
    check("the run was interrupted, not completed", code !== 0, "exit " + code);
    check("stderr says the byte was put back", /SIGINT: the tampered byte was put back/.test(err));
    check("the journal is byte-for-byte what it was", sha(J) === clean);
    check("the verifier passes again", verify() === 0);
    check("the ticket is gone", !fs.existsSync(TICKET));
    resolve();
  });
});

process.stdout.write("\nC. a journal that is ALREADY broken is never tampered with further\n");
{
  const buf = fs.readFileSync(J);
  const offset = offsetOf('"kind":"turn.begin"', '"kind":"');
  const fd = fs.openSync(J, "r+");
  fs.writeSync(fd, Buffer.from([buf[offset] + 1]), 0, 1, offset);
  fs.closeSync(fd);
  const dirty = sha(J);
  const r = run();
  check("it refuses with exit 2", r.status === 2, "exit " + r.status);
  check("it says why", /ALREADY fails verification/.test(r.stdout));
  check("it wrote no ticket", !fs.existsSync(TICKET));
  check("it changed not one byte", sha(J) === dirty);
  const back = fs.openSync(J, "r+");
  fs.writeSync(back, Buffer.from([buf[offset]]), 0, 1, offset);
  fs.closeSync(back);
  check("(restored for the next case)", sha(J) === clean);
}

process.stdout.write("\nD. no journal at all\n");
{
  const r = spawnSync(process.execPath, [SCRIPT, "--journal", path.join(DATA, "nope.jsonl"), "--data-dir", DATA], {
    cwd: REPO,
    env: ENV,
    encoding: "utf8",
  });
  check("it refuses with exit 2", r.status === 2, "exit " + r.status);
  check("it says a journal appears once an agent has run a turn", /has run a turn/.test(r.stdout));
}

process.stdout.write("\nE. a ticket whose byte is neither value, so somebody else wrote there\n");
{
  const buf = fs.readFileSync(J);
  const offset = offsetOf('"verdict":"discarded"', '"verdict":"');
  fs.writeFileSync(
    TICKET,
    JSON.stringify(
      { journal: J, offset, originalByte: 0x41, tamperedByte: 0x42, prefixLength: buf.length, prefixSha256: sha(J) },
      null,
      2,
    ),
  );
  const r = run();
  check("it refuses with exit 2", r.status === 2, "exit " + r.status);
  check("it says nothing was written", /NOTHING WAS WRITTEN/.test(r.stdout));
  check("it kept the ticket rather than sweeping somebody else's undo", fs.existsSync(TICKET));
  check("it changed not one byte", sha(J) === clean);
  fs.unlinkSync(TICKET);
}

process.stdout.write("\nF. the same tamper on a journal that is externally anchored\n");
{
  // A real deployment's data directory carries anchors.jsonl, and the synthetic journal above does
  // not, so the anchor layer went unexercised. An anchor pins the last checkpoint's head, and the
  // tamper lands in a record's payload rather than on that head, so the anchor check should stay
  // green while the three layers below it go red. Asserted rather than assumed: an anchor that
  // reported a break here would make the tamper demo say something it does not mean.
  const records = fs.readFileSync(J, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const checkpoint = [...records].reverse().find((r) => r.kind === "journal.checkpoint");
  const anchors = path.join(DATA, "anchors.jsonl");
  fs.writeFileSync(
    anchors,
    JSON.stringify({ seq: checkpoint.seq, treeSize: checkpoint.treeSize, head: checkpoint.hash }) + "\n",
  );
  check("the anchored journal still verifies before anything is touched", verify() === 0);

  const r = run();
  check("the tamper run completes", r.status === 0, "exit " + r.status);
  check("the verifier still refused the tampered ledger", /exit 1, BROKEN/.test(r.stdout));
  check(
    "the anchor is reported present rather than as a second break",
    /present in this journal/.test(r.stdout) && !/NOT PRESENT IN THIS JOURNAL/.test(r.stdout),
  );
  check("the journal is byte-for-byte what it was", sha(J) === clean);
  check("the verifier passes again", verify() === 0);
  fs.unlinkSync(anchors);
}

process.stdout.write("\n" + (failures ? failures + " FAILURE(S)\n" : "all checks passed\n"));
process.exit(failures ? 1 : 0);

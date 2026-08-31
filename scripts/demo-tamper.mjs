#!/usr/bin/env node
/**
 * Break the ledger on camera, then put it back.
 *
 * `npm run verify:journal` is the one command a reviewer is told to run, and until now the only
 * thing anyone had ever watched it do was pass. A verifier that has only ever been seen passing is
 * a verifier a judge has no reason to believe, because a command that printed OK unconditionally
 * would look exactly the same. So this flips ONE character inside the payload of ONE record, names
 * the record and the byte, runs the shipped verifier, shows it refuse in its own words, puts the
 * byte back and shows it pass again.
 *
 *   npm run demo:tamper
 *   npm run demo:tamper -- --journal /path/to/journal.jsonl
 *   npm run demo:tamper -- --seq 7 --field principal
 *   npm run demo:tamper -- --restore-only        # heal a journal an interrupted run left broken
 *
 * THE RESTORE IS WRITTEN BEFORE THE TAMPER, AND THAT ORDER IS THE WHOLE DESIGN.
 *
 * A demo script that can leave a developer's ledger broken is worse than no demo script, and this
 * one runs against a real operator's real audit log. Five things stand between a bad exit and a
 * broken ledger:
 *
 *   the ticket      <journal>.tamper-restore.json holds the byte offset, the original byte, the
 *                   whole original line and a sha256 of the file prefix. It is written and fsynced
 *                   BEFORE the journal is opened for writing, so the information needed to undo the
 *                   change exists on disk before the change does. A SIGKILL, a power cut or a
 *                   panicked terminal close leaves the ticket, and the next run of this script
 *                   heals from it as its first act, before it does anything else.
 *                   THE TICKET IS DELETED ONLY WHEN THERE IS NOTHING LEFT TO UNDO. Every exit path
 *                   reads the restore's outcome first, because a restore that failed makes the
 *                   ticket the only copy of the undo, and that is the moment it used to be swept.
 *   the lock        <journal>.tamper-lock.json is taken with O_EXCL before the ticket is read, so a
 *                   second copy of this script refuses instead of healing the first copy's live
 *                   tamper and deleting the ticket underneath it. A lock whose pid is gone is
 *                   stale and is taken over, which is what makes a SIGKILL still recoverable.
 *   the handlers    SIGINT, SIGTERM, SIGHUP, SIGQUIT, an uncaught throw, an unhandled rejection and
 *                   the plain `exit` event all restore synchronously. Synchronously matters: an
 *                   async restore scheduled from a signal handler is a restore that may never run.
 *   one byte        the tamper is a single-byte write at a known offset and the restore is the same
 *                   write in reverse. It never rewrites the file, so a server that appended records
 *                   during the window keeps every one of them. A whole-file backup restored over
 *                   the top would silently delete them.
 *   proof           after the restore the byte is read back and the file prefix is re-hashed
 *                   against the digest in the ticket. The script does not report a restore it has
 *                   not measured, and --restore-only runs the verifier rather than reporting an
 *                   all-clear it never looked at.
 *
 * WHY THIS NEVER TOUCHES THE PLATFORM'S OWN JOURNAL OBJECT.
 *
 * `Journal.open()` verifies the chain at boot and calls `enterCompromised()` on a failure, which
 * sets state to `compromised`, and `TransactionalRunner` calls `assertUsable()` before it builds
 * anything, so a tampered journal makes the platform refuse every turn at its next start. That
 * refusal is correct and it is not reversible by putting the byte back: `enterCompromised()` also
 * WRITES `<journal>.compromised.jsonl`, and the only documented way out of that state is
 * `acknowledge(actor)`, which writes two more records into two chains. A demo that triggered it
 * could not leave the machine as it found it.
 *
 * So nothing here constructs a `Journal`. It runs `apps/server/src/verify-journal.ts`, which reads
 * through `verifyJournalAt` and writes nothing at all. A platform that is already running is not
 * affected either: its state was decided at boot and is held in memory, and it appends against a
 * head it already knows.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VERIFIER = path.join("apps", "server", "src", "verify-journal.ts");
const TSX = path.join(REPO, "node_modules", ".bin", "tsx");

// ---- arguments -------------------------------------------------------------------------------

function argOf(name, fallback = null) {
  const index = process.argv.indexOf("--" + name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}
const flag = (name) => process.argv.includes("--" + name);

const DEFAULT_DATA_DIR =
  process.env.APP_DATA_DIR ??
  path.join(process.env.LOCAL_POC_DATA_ROOT ?? path.join(os.homedir(), ".volc-agent-launchpad"), "data");
const DATA_DIR = path.resolve(argOf("data-dir", DEFAULT_DATA_DIR));
const JOURNAL = path.resolve(argOf("journal", path.join(DATA_DIR, "journal.jsonl")));
const TICKET = JOURNAL + ".tamper-restore.json";
const LOCK = JOURNAL + ".tamper-lock.json";
const TARGET_SEQ = argOf("seq") === null ? null : Number(argOf("seq"));
const TARGET_FIELD = argOf("field");
const RESTORE_ONLY = flag("restore-only");
const OUT = argOf("out");

/**
 * The home directory never reaches a file this script writes.
 *
 * On a developer's machine the journal is under `~/.volc-agent-launchpad`, so every banner line here
 * carries `/Users/<name>`. That is fine on a terminal, where the operator needs to see exactly which
 * file was touched, and it is not fine in an artifact somebody commits. `scripts/demo-drive.mjs`
 * settles this the same way: print the real path, redact at the moment of writing.
 */
const HOME = os.homedir();
const redactHome = (text) => (HOME && HOME !== "/" ? text.split(HOME).join("~") : text);

const USAGE = `demo:tamper - break the Shadow Commit ledger, show the verifier refuse, put it back

  npm run demo:tamper
  npm run demo:tamper -- --journal .data/journal.jsonl
  npm run demo:tamper -- --seq 7 --field principal
  npm run demo:tamper -- --restore-only

  --journal <path>    the journal to tamper with (default <APP_DATA_DIR>/journal.jsonl)
  --data-dir <path>   where journal.pub and anchors.jsonl live, passed to the verifier
  --seq <n>           tamper with the record carrying this sequence number
  --field <name>      tamper with this field of that record
  --restore-only      restore from a leftover ticket and exit, touching nothing else
  --out <file>        also write the transcript here, with the home directory redacted
  --help, -h          this text

Exit codes:
  0  broken, refused, restored, and verifying again
  1  something did not happen as described. That includes a restore that could not be written, so
     read the last lines: they say whether the journal is clean, and the ticket is kept when it is
     not.
  2  nothing was written by this run. Either it refused to start, or it refused mid-flight before
     touching the journal.`;

// ---- the restore, which exists before the tamper does ------------------------------------------

/**
 * The one piece of mutable state in this file. While it is non-null the journal is broken and every
 * exit path is obliged to put it back.
 */
let armed = null;

/**
 * True only once THIS run has written the ticket. A run that refuses to start because somebody
 * else's ticket is unresolved must not sweep it away on the way out: that ticket is the only record
 * of how to undo their change.
 */
let ticketWritten = false;

/** true only while THIS process holds <journal>.tamper-lock.json, so it never removes another's */
let lockHeld = false;

/**
 * Synchronous on purpose. A signal handler that starts an async write is a handler that may be torn
 * down before the write lands, which is the exact failure this whole file exists to prevent.
 *
 * THREE OUTCOMES, NEVER TWO. This used to return a boolean, and `false` meant both "nothing was
 * armed" and "the write threw". Every caller then treated a failed restore as a run with nothing to
 * undo: the ticket was deleted one line after the failure message said the ticket was the thing to
 * recover from, and the signal handler printed "nothing was tampered" over a tampered file. The
 * states are distinguished here so that no caller can collapse them again.
 */
function restoreSync() {
  if (!armed) return "nothing";
  const { journalPath, offset, originalByte } = armed;
  const fd = fs.openSync(journalPath, "r+");
  try {
    fs.writeSync(fd, Buffer.from([originalByte]), 0, 1, offset);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  armed = null;
  return "restored";
}

/** printed once, however many exit paths run: process.exit() re-enters through the `exit` event */
let restoreFailureReported = false;

/** The same, for the exit paths where a throw would replace one problem with a louder one. */
function restoreSyncQuietly() {
  try {
    return restoreSync();
  } catch (error) {
    if (!restoreFailureReported) {
      restoreFailureReported = true;
      process.stderr.write(
        "\nTHE RESTORE FAILED: " + String(error) + "\nTHE JOURNAL IS STILL TAMPERED at offset " +
          armed.offset + ", where the original byte was " + describeByte(armed.originalByte) +
          ".\nThe ticket at " + TICKET + " is KEPT, and it describes how to undo it:" +
          "\n  npm run demo:tamper -- --restore-only --journal " + JOURNAL + "\n",
      );
    }
    return "failed";
  }
}

/**
 * The single rule every exit path obeys: the ticket outlives a restore that did not happen.
 *
 * `armed` is cleared only by a restore that actually wrote, so "failed" is the one state in which
 * the ticket is the only surviving record of the offset and the original byte. Deleting it there is
 * the difference between an interrupted demo and an operator's audit ledger that nothing on the
 * machine knows how to repair.
 */
function releaseSync(state) {
  if (state !== "failed" && ticketWritten) dropTicketSync();
  if (lockHeld) dropLockSync();
}

function describeRestore(state) {
  if (state === "restored") return "the tampered byte was put back and the ticket removed.";
  if (state === "nothing") return "nothing was tampered.";
  return (
    "THE JOURNAL IS STILL TAMPERED, the restore failed, and the ticket was kept:" +
    "\n  npm run demo:tamper -- --restore-only --journal " + JOURNAL
  );
}

function dropTicketSync() {
  try {
    fs.unlinkSync(TICKET);
  } catch {
    /* already gone, which is the state we wanted */
  }
}

function writeTicketSync(ticket) {
  const temp = TICKET + "." + process.pid + ".tmp";
  const fd = fs.openSync(temp, "w", 0o600);
  try {
    fs.writeSync(fd, JSON.stringify(ticket, null, 2) + "\n");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temp, TICKET);
  ticketWritten = true;
  // the rename is only durable once the directory entry is, and this file's whole claim is that the
  // undo survives a power cut
  const dir = fs.openSync(path.dirname(TICKET), "r");
  try {
    fs.fsyncSync(dir);
  } catch {
    /* not every platform allows fsync on a directory handle; the file itself is already synced */
  } finally {
    fs.closeSync(dir);
  }
}

/**
 * ONE COPY OF THIS SCRIPT AT A TIME, PER JOURNAL.
 *
 * The ticket path is derived from the journal path, so two runs share it. Without a lock, run B's
 * STEP 0 heals run A's LIVE tamper and deletes A's ticket, and A's STEP 4 then deletes B's ticket
 * while B's byte is still flipped: a measured window in which the ledger is broken and no ticket
 * exists anywhere. Two terminals is enough to reach it, or a rehearsal overlapping the real take.
 * It also made A print "THE VERIFIER DID NOT REFUSE" on a product that was working correctly.
 *
 * O_EXCL is the whole mechanism. A lock whose pid is no longer alive is stale by definition, and
 * taking it over is what keeps a SIGKILLed run recoverable by the next one.
 */
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists and belongs to somebody else, which still counts as alive
    return error?.code === "EPERM";
  }
}

function takeLockSync(log) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = fs.openSync(LOCK, "wx", 0o600);
      try {
        fs.writeSync(fd, JSON.stringify({ pid: process.pid, journal: JOURNAL, at: new Date().toISOString() }) + "\n");
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      lockHeld = true;
      return { held: true };
    } catch (error) {
      if (error?.code !== "EEXIST") return { held: false, error };
      let holder = null;
      try {
        holder = JSON.parse(fs.readFileSync(LOCK, "utf8"));
      } catch {
        holder = null;
      }
      const pid = Number(holder?.pid);
      if (pid !== process.pid && pidAlive(pid)) return { held: false, holder: pid };
      log("  a lock from pid " + (Number.isFinite(pid) ? pid : "(unreadable)") + " is here and that process is gone,");
      log("  so it is stale: it is removed and this run continues, healing whatever it left.");
      try {
        fs.unlinkSync(LOCK);
      } catch {
        /* somebody else swept it first, and the retry below will find out */
      }
    }
  }
  return { held: false };
}

function dropLockSync() {
  lockHeld = false;
  try {
    fs.unlinkSync(LOCK);
  } catch {
    /* already gone, which is the state we wanted */
  }
}

/**
 * sha256 of the first `length` bytes, so a file that grew behind us still hashes comparably.
 *
 * Read in chunks and against the byte count the read actually returned. A single readSync into a
 * buffer the size of the whole file both allocates the journal in memory and, on a short read,
 * hashes the trailing zeroes as though they were file content: the digest would then differ from
 * itself for reasons that have nothing to do with the tamper, and this digest is the measurement
 * the "proof, not assertion" claim rests on.
 */
function prefixDigest(journalPath, length) {
  const fd = fs.openSync(journalPath, "r");
  try {
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.alloc(Math.min(Math.max(length, 1), 1 << 20));
    let read = 0;
    while (read < length) {
      const got = fs.readSync(fd, buffer, 0, Math.min(buffer.length, length - read), read);
      if (got <= 0) {
        throw new Error(
          "the file is shorter than the " + length + " bytes being hashed: only " + read + " could be read",
        );
      }
      hash.update(buffer.subarray(0, got));
      read += got;
    }
    return hash.digest("hex");
  } finally {
    fs.closeSync(fd);
  }
}

function byteAt(journalPath, offset) {
  const fd = fs.openSync(journalPath, "r");
  try {
    const buffer = Buffer.alloc(1);
    fs.readSync(fd, buffer, 0, 1, offset);
    return buffer[0];
  } finally {
    fs.closeSync(fd);
  }
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"]) {
  process.on(signal, () => {
    const state = restoreSyncQuietly();
    releaseSync(state);
    process.stderr.write("\n" + signal + ": " + describeRestore(state) + "\n");
    process.exit(130);
  });
}
process.on("uncaughtException", (error) => {
  const state = restoreSyncQuietly();
  releaseSync(state);
  process.stderr.write(
    "\nthe run threw: " + String(error?.stack ?? error) + "\n" + describeRestore(state) + "\n",
  );
  process.exit(1);
});
process.on("unhandledRejection", (reason) => {
  const state = restoreSyncQuietly();
  releaseSync(state);
  process.stderr.write("\nthe run rejected: " + String(reason) + "\n" + describeRestore(state) + "\n");
  process.exit(1);
});
// The last net, and the only one that catches a plain `return` out of main. It is also a second
// attempt: a restore that threw in a signal handler leaves `armed` set, so this tries the write
// once more on the way out, and the ticket survives unless one of the two attempts landed.
process.on("exit", () => {
  const state = restoreSyncQuietly();
  releaseSync(state);
});

/**
 * Heal whatever a previous run left behind, before this run considers doing anything.
 *
 * A ticket on disk means a previous process was killed between the tamper and the restore. The
 * journal at that offset is then either still tampered, in which case this puts it back, or already
 * restored by that process's exit handler with only the ticket left over, in which case there is
 * nothing to write and the ticket is swept.
 */
function healFromTicket(log) {
  if (!fs.existsSync(TICKET)) return null;
  let ticket;
  try {
    ticket = JSON.parse(fs.readFileSync(TICKET, "utf8"));
  } catch (error) {
    log("  ticket    " + TICKET);
    log("  UNREADABLE, so this run will not guess at what it says: " + String(error));
    log("  Restore by hand, or delete the ticket if you know the journal is intact.");
    return { healed: false, unreadable: true };
  }
  if (path.resolve(String(ticket.journal ?? "")) !== JOURNAL) {
    log("  ticket    " + TICKET);
    log("  it names a different journal, " + ticket.journal + ", so this run will not act on it.");
    return { healed: false, conflict: true, ticket };
  }
  // Read nothing until the thing to read is known to be there. byteAt used to run first, so a
  // ticket beside a journal somebody had deleted dumped an ENOENT stack instead of the sentence
  // this file promises. Nothing is written on this path either way; the difference is whether the
  // operator is told what happened.
  if (!fs.existsSync(ticket.journal) || !Number.isInteger(ticket.offset)) {
    log("  ticket    " + TICKET);
    log(
      "  it describes " + ticket.journal + " at offset " + ticket.offset + ", which cannot be read here.",
    );
    log("  NOTHING WAS WRITTEN, and the ticket is kept: it is the only record of that undo.");
    return { healed: false, conflict: true, ticket };
  }
  const observed = byteAt(ticket.journal, ticket.offset);
  const wasTampered = observed === ticket.tamperedByte;
  const alreadyClean = observed === ticket.originalByte;
  log("  a ticket from an earlier run is here: " + TICKET);
  log("    journal   " + ticket.journal);
  log("    offset    " + ticket.offset);
  log("    on disk   " + describeByte(observed));
  if (wasTampered) {
    const fd = fs.openSync(ticket.journal, "r+");
    try {
      fs.writeSync(fd, Buffer.from([ticket.originalByte]), 0, 1, ticket.offset);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    log("    RESTORED  " + describeByte(ticket.tamperedByte) + " put back to " + describeByte(ticket.originalByte));
  } else if (alreadyClean) {
    log("    already restored; only the ticket was left behind");
  } else {
    log("    the byte is neither the original nor the tampered one. Somebody else wrote here.");
    log("    NOTHING WAS WRITTEN. The original byte was " + describeByte(ticket.originalByte) + ".");
    return { healed: false, conflict: true, ticket };
  }
  let digest = null;
  try {
    digest = prefixDigest(ticket.journal, ticket.prefixLength);
  } catch (error) {
    // The byte is back either way, and that is the thing that matters. A prefix that cannot be
    // re-hashed (the file was truncated behind us) is reported rather than thrown out of a function
    // whose caller is about to decide whether the ledger is safe.
    log("    digest    could not be recomputed: " + String(error));
  }
  const matches = digest !== null && digest === ticket.prefixSha256;
  if (digest !== null) {
    log("    digest    " + (matches ? "matches the ticket, byte for byte" : "DOES NOT MATCH the ticket: " + digest));
  }
  if (matches || alreadyClean) dropTicketSync();
  return { healed: wasTampered, digestMatches: matches, ticket };
}

function describeByte(value) {
  if (typeof value !== "number") return "(unknown)";
  const printable = value >= 0x20 && value < 0x7f ? " '" + String.fromCharCode(value) + "'" : "";
  return "0x" + value.toString(16).padStart(2, "0") + printable;
}

// ---- choosing what to break --------------------------------------------------------------------

/**
 * Fields that ARE the tamper evidence rather than the payload it protects. Flipping one of these
 * would still break the chain, and it would demonstrate the wrong thing: the interesting claim is
 * that changing what the ledger SAYS is caught, not that corrupting the checksum is caught.
 */
const INTEGRITY_FIELDS = new Set(["hash", "prev", "hmac", "signature", "merkleRoot", "seq", "treeSize"]);

/**
 * Payload fields a reader recognises on sight, most legible first. `decision` beats `runId` for the
 * same reason a demo shows what was decided rather than an identifier: one character of "discard"
 * is a change to what happened, and that is what a judge is being asked to believe cannot be made
 * quietly. `decision` is the field `TransactionalRunner` spreads into its `policy.decision` record
 * from `PolicyVerdict`, so it is the one a real ledger carries; `verdict` is kept behind it only
 * because a hand-written journal may use that word.
 */
const PREFERRED_FIELDS = ["decision", "verdict", "rule", "principal", "actor", "kind", "reason", "path", "runId"];

function flipChar(ch) {
  if (ch >= "0" && ch <= "9") return ch === "9" ? "0" : String.fromCharCode(ch.charCodeAt(0) + 1);
  if (ch >= "a" && ch <= "z") return ch === "z" ? "a" : String.fromCharCode(ch.charCodeAt(0) + 1);
  if (ch >= "A" && ch <= "Z") return ch === "Z" ? "A" : String.fromCharCode(ch.charCodeAt(0) + 1);
  return null;
}

/**
 * Locate one ASCII character inside one string field, by byte offset in the file.
 *
 * The offset is computed from the raw line rather than from a re-serialization of the parsed
 * record, because a record this script did not write is not guaranteed to round trip through
 * JSON.stringify with the same bytes. A field whose value does not appear verbatim in the line (an
 * escape, a non-ASCII character) is skipped rather than guessed at.
 *
 * WHAT THE GUARDS DO AND DO NOT DEFEND. Matching the whole `"field":"value"` run, and requiring the
 * closing quote where it should be, keeps the write inside a field of the intended shape. They do
 * not by themselves say WHICH occurrence: canonical JSON sorts keys, so a nested object carrying
 * the same name and the same value would put a second identical run in the line, and the byte would
 * land in one while the transcript, the ticket and the seq/kind header all named the other. So an
 * ambiguous line is skipped as well. The record is still restored correctly in every case, because
 * the ticket records the offset that was written; what ambiguity would corrupt is the narration.
 */
function locateField(line, field, value) {
  const needle = '"' + field + '":"';
  const exact = needle + value + '"';
  const at = line.indexOf(exact);
  if (at < 0) return null;
  if (line.indexOf(exact, at + 1) >= 0) return null;
  const valueStart = at + needle.length;
  if (line.slice(valueStart, valueStart + value.length) !== value) return null;
  if (line[valueStart + value.length] !== '"') return null;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch.charCodeAt(0) > 0x7e) continue;
    const flipped = flipChar(ch);
    if (flipped === null) continue;
    return { charIndex: i, before: ch, after: flipped, columnInLine: valueStart + i, valueStart };
  }
  return null;
}

function chooseTarget(lines) {
  const candidates = [];
  for (const entry of lines) {
    let record;
    try {
      record = JSON.parse(entry.text);
    } catch {
      continue;
    }
    if (TARGET_SEQ !== null && record.seq !== TARGET_SEQ) continue;
    // The filter is applied to the operator's own choice as well. It used to guard only the
    // automatic path, so `--field hash` was accepted and reported a clean success for flipping a
    // checksum, which is the demonstration the comment above says this must not make. A control
    // that holds in the case nobody drives and gives way in the case somebody does is not a
    // control. main() refuses that flag outright; this is the second place it cannot get through.
    const names = (TARGET_FIELD ? [TARGET_FIELD] : [...PREFERRED_FIELDS, ...Object.keys(record)]).filter(
      (name) => !INTEGRITY_FIELDS.has(name),
    );
    for (const name of names) {
      const value = record[name];
      if (typeof value !== "string" || value.length === 0) continue;
      const found = locateField(entry.text, name, value);
      if (!found) continue;
      const rank = PREFERRED_FIELDS.indexOf(name);
      candidates.push({ entry, record, field: name, value, rank: rank < 0 ? PREFERRED_FIELDS.length : rank, ...found });
      break;
    }
  }
  if (!candidates.length) return null;
  // Ranked by what the field MEANS to a reader, then by position. A demo that flips a character of
  // `verdict` is showing that a change to what the ledger says happened is caught; one that flips a
  // character of the first housekeeping record's `principal` is showing the same mechanism on a
  // line nobody cares about. Position breaks ties, and earlier is better: every checkpoint
  // published after a record covers its leaf, so a flip near the front lands on three layers at
  // once, the record's own hash, its hmac, and the Merkle root of each checkpoint over it.
  candidates.sort((a, b) => a.rank - b.rank || a.entry.line - b.entry.line);
  return candidates[0];
}

// ---- running the shipped verifier ---------------------------------------------------------------

function runVerifier(extraArgs = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(TSX, [VERIFIER, "--journal", JOURNAL, "--data-dir", DATA_DIR, ...extraArgs], {
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    // The exit code is read from the process itself, never from the tail of a pipeline: `cmd | tail`
    // reports tail's status, and this script's entire second half is an argument about an exit code.
    child.on("close", (code) => resolve({ code: code ?? 1, stdout: stdout.trimEnd(), stderr: stderr.trimEnd() }));
  });
}

// ---- output ------------------------------------------------------------------------------------

const transcript = [];
function say(line = "") {
  transcript.push(line);
  process.stdout.write(line + "\n");
}
function quote(text, indent = "    | ") {
  for (const line of String(text).split("\n")) say(indent + line);
}
function rule(title) {
  say();
  say("=".repeat(96));
  say(title);
  say("=".repeat(96));
}

const VERDICT = { 0: "0, the ledger verifies", 1: "1, BROKEN", 2: "2, UNVERIFIED" };
const named = (code) => VERDICT[code] ?? String(code);

// ---- the run -------------------------------------------------------------------------------------

async function main() {
  if (flag("help") || process.argv.includes("-h")) {
    process.stdout.write(USAGE + "\n");
    return 0;
  }

  rule("SHADOW COMMIT: BREAK THE LEDGER, SHOW THE REFUSAL, PUT IT BACK");
  say("  journal   " + JOURNAL);
  say("  data dir  " + DATA_DIR);
  say("  verifier  npm run verify:journal -- --journal <that> --data-dir <that>");
  say();

  if (TARGET_FIELD && INTEGRITY_FIELDS.has(TARGET_FIELD)) {
    say("  --field " + TARGET_FIELD + " names one of the fields that ARE the tamper evidence:");
    say("  " + [...INTEGRITY_FIELDS].join(", ") + ".");
    say("  Flipping one of those does break the chain, and it demonstrates the wrong claim: what a");
    say("  judge is asked to believe is that changing what the ledger SAYS is caught, not that");
    say("  corrupting a checksum is caught. Nothing was touched. Pick a payload field.");
    return 2;
  }

  // The lock and the ticket both live beside the journal, so a data directory that does not exist
  // is answered here rather than as a failure to take a lock in a directory nobody has made yet.
  if (!fs.existsSync(path.dirname(JOURNAL))) {
    say("  there is no journal at " + JOURNAL + " yet, and no directory to hold one.");
    say("  A journal appears once an agent has run a turn. Start the platform, send one message,");
    say("  and run this again, or point it at another journal with --journal.");
    return 2;
  }

  say("STEP 0  one copy at a time, and anything an earlier run left broken is fixed first");
  // The lock is taken BEFORE the ticket is read. A second copy that healed first would put back a
  // live tamper belonging to a run that is still going, delete its ticket, and leave that run
  // printing "THE VERIFIER DID NOT REFUSE" about a product that is working correctly.
  const lock = takeLockSync(say);
  if (!lock.held) {
    if (lock.holder) {
      say("  another demo:tamper is running against this journal, pid " + lock.holder + ".");
      say("  Two copies would heal each other's tampers and delete each other's tickets, so this");
      say("  one refuses. Nothing was touched. Wait for that run, or check " + LOCK + ".");
    } else {
      say("  the lock at " + LOCK + " could not be taken: " + String(lock.error));
      say("  Nothing was touched.");
    }
    return 2;
  }
  say("  lock      " + LOCK + " held by pid " + process.pid);
  const healed = healFromTicket(say);
  if (healed?.conflict || healed?.unreadable) {
    say("  refusing to continue while a ticket is unresolved.");
    return 2;
  }
  if (!healed) say("  no ticket; nothing was left broken by an earlier run of this script.");

  if (!fs.existsSync(TSX)) {
    say();
    say("  the verifier cannot be run: " + TSX + " is not installed. Run npm install first.");
    // On --restore-only the byte is already back if a ticket described one, and only the check on
    // that is missing. That is a weaker exit than 0 and it is not the same as a failure to heal.
    if (RESTORE_ONLY && healed?.healed) {
      say("  The ticket WAS applied and the byte is back; what is missing is the check on it.");
      return 1;
    }
    return 2;
  }
  if (RESTORE_ONLY) {
    // A CHECK THAT CANNOT FAIL IS NOT A CHECK. This used to exit 0 with "Nothing needed restoring"
    // on the strength of the ticket alone, so a ledger that was broken with its ticket already
    // swept away got a green all-clear from the very command the failure message recommends. It
    // now runs the verifier and reports what the verifier said.
    say();
    if (!fs.existsSync(JOURNAL)) {
      say("  there is no journal at " + JOURNAL + ", so there is nothing to check.");
      return 2;
    }
    rule("RESTORE-ONLY  the ledger as it stands now, measured rather than assumed");
    const now = await runVerifier();
    quote(now.stdout);
    say("    exit " + named(now.code));
    say();
    if (now.code === 1) {
      say("  THE LEDGER STILL FAILS VERIFICATION. Whatever is wrong with it is not something this");
      say("  ticket describes" + (healed?.healed ? ", because the byte it names was put back above." : "."));
      say("  Nothing further was written. This is reported rather than reported as an all-clear.");
      return 1;
    }
    say(
      healed?.healed
        ? "RESTORED from the ticket, and the verifier agrees. Nothing else was touched."
        : "Nothing needed restoring, and that was measured: the verifier was run against the file.",
    );
    return 0;
  }
  if (!fs.existsSync(JOURNAL)) {
    say();
    say("  there is no journal at " + JOURNAL + " yet.");
    say("  A journal appears once an agent has run a turn. Start the platform, send one message,");
    say("  and run this again, or point it at another journal with --journal.");
    return 2;
  }

  // ------------------------------------------------------------------------------------------
  rule("STEP 1  the ledger as it stands, before anything is touched");
  const before = await runVerifier();
  quote(before.stdout);
  say("    exit " + named(before.code));
  say();
  if (before.code === 1) {
    say("  This journal ALREADY fails verification, so breaking it further would prove nothing and");
    say("  the restore could not be shown to have worked. Nothing was touched.");
    return 2;
  }
  if (before.code === 2) {
    say("  Exit 2, not 0: the chain is self-consistent and at least one layer above it could not be");
    say("  checked on this host. That is the honest baseline here and the tamper below is still");
    say("  worth watching, because the layer this breaks is the one that DID run.");
  }

  // ------------------------------------------------------------------------------------------
  rule("STEP 2  one character, one record");
  const buffer = fs.readFileSync(JOURNAL);
  const text = buffer.toString("utf8");
  const lines = [];
  let offset = 0;
  for (const [index, lineText] of text.split("\n").entries()) {
    if (lineText.trim() !== "") lines.push({ text: lineText, line: index + 1, offset });
    offset += Buffer.byteLength(lineText, "utf8") + 1;
  }
  const target = chooseTarget(lines);
  if (!target) {
    say("  no record in this journal carries a payload field that can be flipped in place.");
    if (TARGET_SEQ !== null || TARGET_FIELD) say("  Try again without --seq or --field.");
    return 2;
  }

  // The byte offset of the character, computed from the line's own bytes so a multi-byte character
  // earlier in the line cannot shift it.
  const byteOffset = target.entry.offset + Buffer.byteLength(target.entry.text.slice(0, target.columnInLine), "utf8");
  const originalByte = buffer[byteOffset];
  const tamperedByte = target.after.charCodeAt(0);
  if (originalByte !== target.before.charCodeAt(0)) {
    say("  the byte at the computed offset is not the character that was chosen. Nothing was written.");
    return 2;
  }

  const prefixLength = buffer.length;
  const ticket = {
    note: "written by scripts/demo-tamper.mjs BEFORE the journal was modified. If this file is here, a run was interrupted: `npm run demo:tamper -- --restore-only` puts the byte back.",
    journal: JOURNAL,
    offset: byteOffset,
    originalByte,
    tamperedByte,
    originalLine: target.entry.text,
    line: target.entry.line,
    seq: target.record.seq ?? null,
    field: target.field,
    prefixLength,
    prefixSha256: prefixDigest(JOURNAL, prefixLength),
    writtenAt: new Date().toISOString(),
    pid: process.pid,
  };
  writeTicketSync(ticket);
  say("  the undo is on disk before the change is");
  say("    ticket    " + TICKET);
  say("    digest    sha256 of the first " + prefixLength + " bytes is " + ticket.prefixSha256);
  say();

  const excerpt = (line) => {
    const from = Math.max(0, target.valueStart - 24);
    const to = Math.min(line.length, target.valueStart + target.value.length + 2);
    return (from > 0 ? "..." : "") + line.slice(from, to) + (to < line.length ? "..." : "");
  };
  say("  the record");
  say("    line      " + target.entry.line + " of " + lines.length);
  say("    seq       " + (target.record.seq ?? "(none)"));
  say("    kind      " + (target.record.kind ?? "(none)"));
  say("    field     " + target.field);
  say("  the byte");
  say("    offset    " + byteOffset + " in the file, character " + (target.charIndex + 1) + " of the value");
  say("    before    " + describeByte(originalByte));
  say("    after     " + describeByte(tamperedByte));
  say("    was       " + excerpt(target.entry.text));

  const tamperedLine =
    target.entry.text.slice(0, target.columnInLine) + target.after + target.entry.text.slice(target.columnInLine + 1);
  say("    now       " + excerpt(tamperedLine));
  say();
  say("  Nothing else changes. The file is the same length, every other record is untouched, and");
  say("  the record still parses as JSON. This is the quietest edit somebody could make.");

  // ARMED BEFORE THE WRITE, NOT AFTER. Node cannot turn the event loop between the synchronous
  // write and the next statement, so no signal can land in that gap today, but the ordering was
  // load-bearing and undocumented. Setting it first costs nothing and does not depend on that.
  // A write that never landed is unarmed again below, so a failure to open the file is not
  // reported as a broken ledger.
  armed = { journalPath: JOURNAL, offset: byteOffset, originalByte };
  try {
    const fd = fs.openSync(JOURNAL, "r+");
    try {
      fs.writeSync(fd, Buffer.from([tamperedByte]), 0, 1, byteOffset);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    let onDisk = null;
    try {
      onDisk = byteAt(JOURNAL, byteOffset);
    } catch {
      onDisk = null;
    }
    if (onDisk === originalByte) armed = null;
    say();
    say("  the tamper could not be written: " + String(error));
    if (onDisk === originalByte) say("  The byte on disk is the original one. Nothing was changed.");
    return onDisk === originalByte ? 2 : 1;
  }

  // ------------------------------------------------------------------------------------------
  rule("STEP 3  the same command a reviewer runs, against the same file");
  const broken = await runVerifier();
  quote(broken.stdout);
  say("    exit " + named(broken.code));
  const refused = broken.code === 1;
  say();
  if (refused) {
    say("  REFUSED. Exit 1 is the code CI gates on, and the report names the record rather than");
    say("  saying the file is bad somewhere.");
  } else {
    say("  THE VERIFIER DID NOT REFUSE. That is a failure of the product, not of this script, and");
    say("  it is reported rather than hidden. The journal is restored below regardless.");
  }

  // ------------------------------------------------------------------------------------------
  rule("STEP 4  the byte goes back");
  // The quiet variant, deliberately. `restoreSync()` throwing here would leave main through the
  // uncaughtException handler, which is a path that prints to stderr and never reaches the
  // transcript, so a run whose restore failed produced an evidence file that stopped mid-sentence
  // and said nothing about the state of the ledger. The failure is a result this step reports.
  const state = restoreSyncQuietly();
  let observed = null;
  let digest = null;
  try {
    observed = byteAt(JOURNAL, byteOffset);
    digest = prefixDigest(JOURNAL, prefixLength);
  } catch (error) {
    say("  the file could not be read back after the restore: " + String(error));
  }
  const identical = digest !== null && digest === ticket.prefixSha256;
  say("  restored  " + (state === "restored" ? "yes" : state === "nothing" ? "nothing was armed" : "NO, the write failed"));
  say("  byte      " + describeByte(observed) + " at offset " + byteOffset);
  say("  digest    sha256 of the first " + prefixLength + " bytes is " + (digest ?? "(unreadable)"));
  say("  match     " + (identical ? "byte for byte the file it was before" : "DOES NOT MATCH, see above"));
  const grew = fs.statSync(JOURNAL).size - prefixLength;
  if (grew > 0) {
    say("  appended  " + grew + " byte(s) were written by the running platform during the window.");
    say("            They are still there: the restore was one byte at one offset, never a rewrite.");
  }
  if (state === "failed") {
    say();
    say("  THE RESTORE FAILED AND THE LEDGER IS STILL TAMPERED.");
    say("    journal   " + JOURNAL);
    say("    offset    " + byteOffset);
    say("    put back  " + describeByte(originalByte));
    say("    ticket    " + TICKET + " is KEPT: it is the only record of this undo.");
    say("  Recover with:  npm run demo:tamper -- --restore-only --journal " + JOURNAL);
    say("  That command runs the verifier afterwards, so it reports what it measured.");
    say();
    say("SUMMARY");
    say("  before    exit " + named(before.code));
    say("  tampered  exit " + named(broken.code));
    say("  after     the byte was not put back, so the ledger was left broken by this run.");
    // One more attempt runs from the `exit` handler on the way out, and it keeps the ticket unless
    // that attempt lands. Nothing here deletes it.
    return 1;
  }
  // Only now, and only because `armed` being null is what proves the write landed.
  if (armed === null) dropTicketSync();
  say("  ticket    " + (armed === null ? "removed" : "KEPT, because the byte is not back"));

  // ------------------------------------------------------------------------------------------
  rule("STEP 5  and it verifies again");
  const after = await runVerifier();
  quote(after.stdout);
  say("    exit " + named(after.code));
  say();

  const sameAsBefore = after.code === before.code;
  say("SUMMARY");
  say("  before    exit " + named(before.code));
  say("  tampered  exit " + named(broken.code));
  say("  after     exit " + named(after.code));
  say();
  const ok = refused && identical && sameAsBefore;
  if (ok) {
    say("  One character changed inside one record and the shipped verifier refused the whole");
    say("  ledger, naming the record. The character went back and it verifies again. The machine");
    say("  is as it was found.");
  } else {
    if (!refused) say("  The verifier did not refuse a tampered ledger.");
    if (!identical) say("  The restored file does not hash to what it hashed before.");
    if (!sameAsBefore) say("  The verifier's verdict after the restore is not the one it gave before it.");
  }
  return ok ? 0 : 1;
}

const code = await main();
if (OUT) {
  const file = path.resolve(OUT);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, redactHome(transcript.join("\n")) + "\n");
  process.stdout.write("\nwritten to " + file + "\n");
}
process.exitCode = code;

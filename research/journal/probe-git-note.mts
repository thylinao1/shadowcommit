/**
 * The shipped default is SHADOW_ANCHORS=git, and GitAnchor writes TWO things: anchors.jsonl inside
 * the data directory, and a git note on HEAD under refs/notes/shadow-commit. Verification reads the
 * first and has no code path that reads the second.
 *
 * This probe runs the real GitAnchor against a real repository and prints what each witness holds.
 *
 *   npx tsx research/journal/probe-git-note.mts
 */
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { GitAnchor, readAnchorLog } from "../../apps/server/src/anchors.js";
import { Journal } from "../../apps/server/src/journal.js";
import { verifyJournalAt } from "../../apps/server/src/journal-verify.js";

const run = promisify(execFile);

const root = await fs.mkdtemp(path.join(os.tmpdir(), "git-note-probe-"));
const repo = path.join(root, "repo");
await fs.mkdir(repo, { recursive: true });
await run("git", ["-C", repo, "init", "-q"]);
await fs.writeFile(path.join(repo, "README.md"), "probe\n");
await run("git", ["-C", repo, "add", "-A"]);
await run("git", [
  "-C", repo, "-c", "user.name=probe", "-c", "user.email=probe@localhost", "-c", "commit.gpgsign=false",
  "commit", "-q", "-m", "probe",
]);

const dataDirectory = path.join(repo, ".data");
const home = path.join(root, "keys");
const env: NodeJS.ProcessEnv = { ...process.env, SHADOW_COMMIT_HOME: home };
delete env.SHADOW_JOURNAL_KEY;
delete env.SHADOW_JOURNAL_KEY_FILE;
delete env.VITEST;

const journal = new Journal({
  journalPath: path.join(dataDirectory, "journal.jsonl"),
  dataDirectory,
  home,
  checkpointEvery: 4,
  // exactly what anchorsFromEnv builds for the shipped default SHADOW_ANCHORS=git
  anchors: [new GitAnchor({ dataDirectory, gitNotes: true })],
  env,
});
await journal.open();
for (let i = 0; i < 8; i++) await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
await journal.close();

const file = await readAnchorLog(dataDirectory);
console.log(`anchors.jsonl      ${file.length} point(s), inside the data directory, deleted by anyone who deletes it`);
for (const point of file) console.log(`                   seq ${point.seq} treeSize ${point.treeSize} head ${point.head.slice(0, 16)}`);

const note = await run("git", ["-C", repo, "notes", "--ref", "shadow-commit", "show", "HEAD"]).then((r) => r.stdout).catch((e: Error) => `NONE (${e.message})`);
const noteLines = note.split("\n").filter((line) => line.trim());
console.log(`refs/notes/...     ${noteLines.length} submission(s), inside .git, OUTSIDE the data directory`);
for (const line of noteLines) {
  try {
    const parsed = JSON.parse(line) as Record<string, unknown>;
    console.log(`                   seq ${parsed.seq} treeSize ${parsed.treeSize} head ${String(parsed.head).slice(0, 16)} publicKey ${String(parsed.publicKey).length} bytes signature ${String(parsed.signature).slice(0, 12)}`);
  } catch {
    console.log("                   (unparseable)", line.slice(0, 80));
  }
}
console.log("");
console.log("does any verification code path read the git note?");
console.log("");

// A BEHAVIOURAL CHECK, NOT A GREP. Whether a reader exists is a question about what the verifier
// DOES, and a pattern over source text can only ever answer "no" for a reader written in a shape
// the pattern does not match. So take the witness inside the data directory away and leave the one
// outside it exactly where it is: delete anchors.jsonl, keep refs/notes/shadow-commit, and ask the
// shipped verifier whether it still knows an anchored head. If it does not, nothing reads the note,
// and that stays true whatever the source looks like.
await fs.rm(path.join(dataDirectory, "anchors.jsonl"), { force: true });
const after = await verifyJournalAt(path.join(dataDirectory, "journal.jsonl"), { dataDirectory, home, env });
const noteSurvives = noteLines.length > 0;
const line = (label: string, value: string): void => console.log(`  ${label.padEnd(46)} ${value}`);
line("anchors.jsonl deleted, git note left in place", `note still holds ${noteLines.length} submission(s)`);
line("anchor entries the verifier can see", String(after.anchors.entries));
line("anchored head the verifier reports", after.anchors.last ? `seq ${after.anchors.last.seq}` : "(none)");
line(
  "verdict",
  after.anchors.last
    ? "SOMETHING reads the note"
    : noteSurvives
      ? "nothing reads the note: the only anchor witness the verifier consults is the file that was just deleted"
      : "inconclusive, the note was never written in this probe",
);

// Kept as a secondary line and labelled for what it is. It points at where such a reader would
// live; it is not the evidence, because it cannot see a call whose argv is wrapped across lines or
// built somewhere else.
console.log("");
console.log("  heuristic only, a source grep for a notes read:");
const sources = ["journal-verify.ts", "verify-journal.ts", "anchors.ts", "journal.ts"];
for (const name of sources) {
  const text = await fs.readFile(path.join(process.cwd(), "apps/server/src", name), "utf8");
  const reads = /notes[^\n]*(show|list|cat)/.test(text);
  console.log(`    ${name.padEnd(20)} ${reads ? "YES" : "no"}`);
}
await fs.rm(root, { recursive: true, force: true });

/**
 * The one-command verifier: `npm run verify:journal`.
 *
 * A tamper-evident log is only tamper-evident if somebody can run the check, so this is a single
 * command with no arguments in the common case, and it exits non-zero on a break so CI can gate on
 * it. It checks the plain chain, the keyed layer, sequence continuity, every checkpoint signature
 * against the published key, every checkpoint's Merkle root against the records it covers, and
 * whether the last externally anchored head is still in the file. It prints the first break, which
 * is the only one an operator usually needs.
 *
 * It never creates a key. A verifier that mints the key it verifies against proves nothing, so a
 * missing key gives a report that says the keyed layer was unchecked rather than a pass.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readAnchorLog } from "./anchors.js";
import { defaultHome } from "./journal-keys.js";
import { verifyJournalAt, type JournalReport } from "./journal.js";
import { compareByCodeUnit } from "./stable-order.js";

interface Args {
  journalPath: string;
  dataDirectory: string;
  records: number;
  json: boolean;
  help: boolean;
}

export function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Args {
  const dataDefault = path.resolve(env.APP_DATA_DIR ?? ".data");
  let journalPath = "";
  let dataDirectory = "";
  let records = 10;
  let json = false;
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    const [flag, inline] = arg.includes("=") ? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)] : [arg, null];
    const next = () => inline ?? argv[++i] ?? "";
    if (flag === "--journal" || flag === "-j") journalPath = next();
    else if (flag === "--data-dir" || flag === "-d") dataDirectory = next();
    else if (flag === "--records" || flag === "-n") records = Number(next());
    else if (flag === "--all") records = Number.POSITIVE_INFINITY;
    else if (flag === "--json") json = true;
    else if (flag === "--help" || flag === "-h") help = true;
  }
  const resolvedJournal = path.resolve(journalPath || path.join(dataDirectory || dataDefault, "journal.jsonl"));
  return {
    journalPath: resolvedJournal,
    dataDirectory: path.resolve(dataDirectory || path.dirname(resolvedJournal)),
    records: Number.isFinite(records) ? Math.max(0, records) : records,
    json,
    help,
  };
}

const USAGE = `verify:journal - check the Shadow Commit audit ledger

  npm run verify:journal
  npm run verify:journal -- --journal .data/journal.jsonl
  npm run verify:journal -- --all --json

  --journal, -j <path>   the journal file (default <APP_DATA_DIR>/journal.jsonl)
  --data-dir, -d <path>  where journal.pub and anchors.jsonl live (default the journal's directory)
  --records, -n <count>  how many of the most recent records to print (default 10)
  --all                  print every record
  --json                 machine-readable report on stdout
  --help, -h             this text

Exit codes, so CI can gate on it:
  0  checked, and it holds
  1  BROKEN, a check ran and failed
  2  UNVERIFIED, a layer could not be checked here, so this run proves less than a pass`;

/**
 * A CHECK THAT DID NOT RUN IS NOT A CHECK THAT PASSED.
 *
 * Three layers stand between this file and a forgery, and only the first of them is self-contained:
 *
 *   the sha256 chain   proves the file is internally consistent, which anybody who can write the
 *                      file can arrange from record one. On its own it proves nothing at all.
 *   the hmac           proves a writer held a key kept outside the data directory
 *   the signature      proves a checkpoint was signed by the key journal.pub names
 *
 * The chain is the only one that needs no external input, and it is the only one that is worthless
 * alone. So a run that could check nothing but the chain has established nothing, and must not
 * print the same word as a run that checked all three. It used to: with no key on the host the
 * report said "keyed NO, see problems below", listed no problems, said "OK, the ledger verifies
 * from record one" and exited 0. Measured against a journal fabricated end to end by somebody who
 * had never seen either of the operator's keys, that is exit 0 on a forgery
 * (research/journal/forge-full.mts, row 3). That harness runs the CLI in THIS file, so row 3 prints
 * exit 2 and UNVERIFIED today; the harness carries the exit 0 beside it as the recorded before, and
 * `git show submission/main:apps/server/src/verify-journal.ts` is the version that produced it.
 *
 * Both keyed layers have a sharper version of the same problem: the report can name the check but
 * not the provenance of the key it ran the check with.
 *
 *   journal.pub   defaults to <dataDirectory>/journal.pub, INSIDE the directory being audited, so
 *                 whoever wrote the records also supplied the key those records are checked
 *                 against. That verifies, and it means nothing.
 *   journal.key   is kept outside the data directory, which stops a writer confined to the
 *                 workspace. It does not stop somebody who hands the reader a bundle and a key and
 *                 asks them to put the key in the documented place. Every record then verifies
 *                 under a key the forger chose.
 *
 * Neither is failed, because for an operator checking their own live deployment both files are
 * theirs and the checks are worth what they say. Both are NAMED, because the reader is the one who
 * has to know which situation they are in, and "hmac verified on every record" does not say whose.
 */
function uncheckedLayers(report: JournalReport, publicKeyFile: string): string[] {
  const unchecked: string[] = [];
  if (report.records > 0 && report.warnings.some((warning) => warning.startsWith("no journal key available"))) {
    unchecked.push(
      "the keyed layer: no journal key on this host, so nothing here shows a writer held one." +
        " Every record's hmac was skipped, not verified.",
    );
  }
  const unsigned = report.checkpoints.filter((checkpoint) => checkpoint.signature === "unverified").length;
  if (unsigned > 0) {
    unchecked.push(
      `the signature layer: ${unsigned} of ${report.checkpoints.length} checkpoint signature(s) were skipped,` +
        ` because no public key was readable at ${publicKeyFile}`,
    );
  }
  // A CHECKPOINT THAT DOES NOT EXIST IS NOT A SIGNATURE THAT PASSED. The loop above counts
  // checkpoints whose signature could not be checked and cannot see checkpoints that are absent, so
  // a journal below the checkpoint interval had nothing to list and printed a clean pass. That is
  // the whole demo path: the shipped SHADOW_CHECKPOINT_EVERY is 64, so a reviewer who runs the poc,
  // sends one message and runs this command has zero checkpoints, nothing signed, nothing anchored,
  // and used to get "OK, the ledger verifies from record one" and exit 0 for it.
  if (report.records > 0 && report.checkpoints.length === 0) {
    unchecked.push(
      "the signature layer: this journal contains no checkpoint yet, so no part of it is signed and" +
        " no part of it is anchored. At the shipped SHADOW_CHECKPOINT_EVERY=64 the first checkpoint" +
        " appears only after 64 records, or at shutdown.",
    );
  }
  return unchecked;
}

/**
 * WHICH KEY, NOT JUST WHETHER THERE WAS ONE.
 *
 * `keyed  yes, hmac verified on every record` says a writer held a key. It does not say whose. A
 * forger who ships their own key beside the bundle and asks the reader to drop it in the documented
 * place gets that line, "the ledger verifies from record one" and exit 0, on records they wrote
 * themselves. The line is worth exactly what the reader knows about the file it came from, so the
 * file is named. Resolved the way verifyJournalAt resolves it, and duplicated here because the
 * report does not carry it.
 */
interface HmacKeyOrigin {
  /** what the report prints, and what --json carries as hmacKeySource */
  source: string;
  /** the path the key was read from, or null when it was supplied inline */
  file: string | null;
  /** true when this invocation named the key rather than finding it in the operator's key home */
  suppliedOnThisInvocation: boolean;
}

function hmacKeyOrigin(env: NodeJS.ProcessEnv): HmacKeyOrigin {
  if (env.SHADOW_JOURNAL_KEY?.trim()) {
    return { source: "SHADOW_JOURNAL_KEY in this process environment", file: null, suppliedOnThisInvocation: true };
  }
  const named = env.SHADOW_JOURNAL_KEY_FILE?.trim();
  const file = path.resolve(named || path.join(defaultHome(env), "journal.key"));
  return { source: file, file, suppliedOnThisInvocation: Boolean(named) };
}

/** true when the key the signatures are checked against travelled with the records it checks */
function trustAnchorTravelsWithTheFile(publicKeyFile: string, dataDirectory: string): boolean {
  const rel = path.relative(path.resolve(dataDirectory), path.resolve(publicKeyFile));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * How many records sit past the last externally anchored checkpoint.
 *
 * The anchor check asks whether the last anchored head is still present. It cannot ask anything
 * about what came after it, because nothing outside this machine has ever seen those records. So a
 * tail cut back to the anchored checkpoint leaves a file that verifies clean, and the shipped
 * default publishes a checkpoint every 64 records, which makes that window 64 records wide.
 * Measured: an 82 line journal at checkpointEvery=64 with its last anchor at seq 65 accepts every
 * truncation from k=1 to k=17 with no problem reported (research/journal/attack-sweep.mts, row C3).
 *
 * This is a property of anchoring, not a bug in this file, and it is not fixable here: the verifier
 * has no way to learn a length nobody published. What IS fixable here is that the report never said
 * so, and a reader took "OK, the ledger verifies from record one" to cover the whole file.
 */
function unanchoredTail(report: JournalReport): number | null {
  const anchor = report.anchors.last;
  if (!anchor || report.lastSeq === null) return null;
  return Math.max(0, report.lastSeq - anchor.seq);
}

interface ParsedRecord {
  seq: number | null;
  kind: string;
  principal: string;
  ts: string | null;
  runId: string | null;
}

async function readRecords(journalPath: string): Promise<{ parsed: ParsedRecord[]; unreadable: number }> {
  const text = await fs.readFile(journalPath, "utf8").catch(() => "");
  const parsed: ParsedRecord[] = [];
  let unreadable = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const record = JSON.parse(line) as Record<string, unknown>;
      parsed.push({
        seq: typeof record.seq === "number" ? record.seq : null,
        kind: String(record.kind ?? "(no kind)"),
        principal: String(record.principal ?? "(unattributed)"),
        ts: typeof record.ts === "string" ? record.ts : null,
        runId: typeof record.runId === "string" ? record.runId : null,
      });
    } catch {
      unreadable += 1;
    }
  }
  return { parsed, unreadable };
}

function tally(values: readonly string[]): Array<[string, number]> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  // Code units, not localeCompare, for the tiebreak. Measured under zh-CN: the registry's current
  // rule ids all agree between the two orders, so this is not a live defect today. It stops being
  // true the moment a rule id carries an underscore or a capital, where localeCompare and code
  // units disagree (`guard_file` sorts before `guard-file` under one and after under the other),
  // and this function's output is read by a person comparing two machines' verification runs.
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || compareByCodeUnit(a[0], b[0]));
}

function render(
  args: Args,
  report: JournalReport,
  records: ParsedRecord[],
  unreadable: number,
  anchorEntries: number,
  sidecar: { path: string; records: number } | null,
  unchecked: readonly string[],
  publicKeyFile: string,
  hmacKey: HmacKeyOrigin | null,
): string {
  const out: string[] = [];
  const row = (label: string, value: string) => out.push(`  ${label.padEnd(13)}${value}`);
  out.push("Shadow Commit journal verification");
  row("journal", args.journalPath);
  row("records", `${report.records}${unreadable ? ` (${unreadable} unreadable)` : ""}`);
  row("head", report.head ?? "(none)");
  row("last seq", report.lastSeq === null ? "(none)" : String(report.lastSeq));
  row(
    "keyed",
    report.keyed
      ? "yes, hmac verified on every record"
      : unchecked.some((line) => line.startsWith("the keyed layer"))
        ? "NOT CHECKED, no key on this host, see UNCHECKED below"
        : "NO, see problems below",
  );
  // the second half of the keyed row: which key, since the first half only says there was one
  if (hmacKey) {
    out.push(`               ${report.keyed ? "hmac verified against" : "hmac checked against"} ${hmacKey.source}`);
  }

  if (records.length) {
    row("kinds", tally(records.map((r) => r.kind)).map(([k, n]) => `${k} ${n}`).join(", "));
    row("principals", tally(records.map((r) => r.principal)).map(([k, n]) => `${k} ${n}`).join(", "));
  }

  out.push("");
  out.push(`  checkpoints  ${report.checkpoints.length}`);
  for (const checkpoint of report.checkpoints) {
    out.push(
      `    seq ${String(checkpoint.seq).padEnd(6)} tree ${String(checkpoint.treeSize).padEnd(6)} root ${checkpoint.merkleRoot.slice(0, 16)}...  signature ${checkpoint.signature}  root ${checkpoint.root}`,
    );
  }
  if (!report.checkpoints.length) out.push("    none yet; the first lands at the checkpoint interval or at shutdown");

  out.push("");
  const anchor = report.anchors.last;
  out.push(`  anchors      ${anchorEntries} recorded`);
  if (anchor) {
    out.push(
      `    last seq ${anchor.seq}, ${anchor.treeSize} records, head ${anchor.head.slice(0, 16)}...  ${
        report.anchors.present ? "present in this journal" : "NOT PRESENT IN THIS JOURNAL"
      }`,
    );
  } else {
    out.push("    none; nothing external pins this chain yet, so deletion is undetectable");
  }
  const tail = unanchoredTail(report);
  if (tail !== null && tail > 0) {
    out.push(
      `    ${tail} record(s) were written after that anchor. Nothing outside this machine has seen`,
    );
    out.push(
      "    them, so cutting the file back to the anchored checkpoint verifies clean. The anchor",
    );
    out.push("    proves the chain up to its own point and no further.");
  }

  if (records.length && args.records > 0) {
    const shown = Number.isFinite(args.records) ? records.slice(-args.records) : records;
    out.push("");
    out.push(`  last ${shown.length} of ${records.length} records`);
    for (const record of shown) {
      out.push(
        `    ${String(record.seq ?? "?").padStart(6)}  ${(record.ts ?? "").padEnd(24)}  ${record.principal.padEnd(18)} ${record.kind}${
          record.runId ? `  ${record.runId.slice(0, 8)}` : ""
        }`,
      );
    }
  }

  if (sidecar) {
    out.push("");
    out.push(`  COMPROMISED  a sidecar chain exists with ${sidecar.records} record(s): ${sidecar.path}`);
    out.push("    the journal failed verification at boot and turns were refused until acknowledged");
  }

  if (unchecked.length) {
    out.push("");
    out.push("  UNCHECKED    layers this run could not check, which is not the same as layers that passed");
    for (const line of unchecked) out.push(`    ${line}`);
    out.push("    Without them what remains is a sha256 chain, and anyone who can write this file");
    out.push("    can write a consistent one from record one.");
  }
  if (report.checkpoints.length && !unchecked.some((line) => line.startsWith("the signature layer"))) {
    if (trustAnchorTravelsWithTheFile(publicKeyFile, args.dataDirectory)) {
      out.push("");
      out.push(`  note         checkpoint signatures verified against ${publicKeyFile},`);
      out.push("               which is inside the directory being checked. Whoever wrote these records");
      out.push("               could also have written that key. Point SHADOW_JOURNAL_PUBKEY_FILE at a");
      out.push("               copy published elsewhere to make this layer mean something to a reader");
      out.push("               who is not the operator.");
    }
  }
  // The same note for the other key, and it matters more: the hmac layer is what the whole tamper
  // evidence claim rests on. A key this invocation was pointed at is not evidence the reader
  // controls, whether it arrived inline or as a path in the command that ran the check.
  if (hmacKey?.suppliedOnThisInvocation) {
    out.push("");
    out.push(
      `  note         the hmac key came from ${
        hmacKey.file ? `a path named on this invocation, ${hmacKey.file},` : "SHADOW_JOURNAL_KEY in this process environment,"
      }`,
    );
    out.push("               not from the key home a deployment writes to. Whoever handed over these");
    out.push("               records could have handed over that key with them, and every record");
    out.push("               would verify under it. The keyed row above is worth what the reader");
    out.push("               knows about where that key came from.");
  }

  out.push("");
  for (const warning of report.warnings) out.push(`  warning      ${warning}`);
  if (report.firstBreak) {
    const where = report.firstBreak.record === null ? "" : `record ${report.firstBreak.record} `;
    out.push(`  first break  ${where}[${report.firstBreak.kind}] ${report.firstBreak.message}`);
    if (report.problems.length > 1) out.push(`  problems     ${report.problems.length} in total:`);
    for (const problem of report.problems.slice(1, 25)) out.push(`    [${problem.kind}] ${problem.message}`);
  }
  out.push(
    `  result       ${
      !report.ok
        ? "BROKEN"
        : unchecked.length
          ? "UNVERIFIED, the chain is self-consistent but the layers that would make that mean something were not checked here"
          : "OK, the ledger verifies from record one"
    }`,
  );
  return out.join("\n");
}

export async function main(
  argv: readonly string[],
  write: (text: string) => void = (text) => process.stdout.write(text + "\n"),
): Promise<number> {
  const args = parseArgs(argv);
  if (args.help) {
    write(USAGE);
    return 0;
  }
  const report = await verifyJournalAt(args.journalPath, { dataDirectory: args.dataDirectory });
  // Resolved the way verifyJournalAt resolves it. Duplicated rather than returned because the
  // report does not carry it, and the reader has to be told WHICH key the signatures were checked
  // against before "signature ok" means anything to them.
  const publicKeyFile = path.resolve(
    process.env.SHADOW_JOURNAL_PUBKEY_FILE?.trim() ?? path.join(args.dataDirectory, "journal.pub"),
  );
  const unchecked = uncheckedLayers(report, publicKeyFile);
  // null when no key was resolvable here, which is the same condition the keyed layer is reported
  // unchecked on, so the report never names a key it did not actually run the hmac against
  const keyResolved = !report.warnings.some((warning) => warning.startsWith("no journal key available"));
  const hmacKey = keyResolved ? hmacKeyOrigin(process.env) : null;
  const { parsed, unreadable } = await readRecords(args.journalPath);
  const anchorEntries = (await readAnchorLog(args.dataDirectory)).length;
  const sidecarPath = args.journalPath.replace(/(\.jsonl)?$/, "") + ".compromised.jsonl";
  const sidecarText = await fs.readFile(sidecarPath, "utf8").catch(() => null);
  const sidecar = sidecarText
    ? { path: sidecarPath, records: sidecarText.split("\n").filter((line) => line.trim()).length }
    : null;

  if (args.json) {
    write(
      JSON.stringify(
        {
          journal: args.journalPath,
          ok: report.ok,
          records: report.records,
          keyed: report.keyed,
          head: report.head,
          lastSeq: report.lastSeq,
          checkpoints: report.checkpoints,
          anchors: { entries: anchorEntries, last: report.anchors.last, present: report.anchors.present },
          warnings: report.warnings,
          // named `unchecked` rather than folded into `warnings`, because a machine gating on this
          // report has to be able to tell "checked and clean" from "could not check"
          unchecked,
          unanchoredTail: unanchoredTail(report),
          publicKeyFile,
          publicKeyInsideDataDirectory: trustAnchorTravelsWithTheFile(publicKeyFile, args.dataDirectory),
          // the same provenance question for the other key, because a gate that reads `keyed: true`
          // without reading this one has learned that a key existed and not whose it was
          hmacKeySource: hmacKey?.source ?? null,
          hmacKeyFile: hmacKey?.file ?? null,
          hmacKeySuppliedOnThisInvocation: hmacKey?.suppliedOnThisInvocation ?? false,
          problems: report.problems,
          firstBreak: report.firstBreak,
          compromisedSidecar: sidecar,
        },
        null,
        2,
      ),
    );
  } else {
    // An absent journal and a broken one are different states and must not print the
    // same word. A fresh clone has never run a turn, so there is nothing to verify, and
    // BROKEN there reads as though the tamper evidence is already compromised. That is the
    // opposite of what this command exists to demonstrate, and it is the first thing a
    // reviewer runs. Verifying nothing is not a failure; claiming to have verified
    // something that does not exist would be.
    // ABSENT IS ONLY INNOCENT IF NOTHING EVER RECORDED A CHAIN.
    //
    // The first version of this returned "nothing to verify" for any missing file, which handed an
    // attacker the best possible outcome: delete the journal, get a clean report. The existing test
    // "reports a deleted journal against its anchor rather than as a fresh deployment" caught it,
    // and it is the reason absence is now two states rather than one. An anchor, or a compromised
    // sidecar, is external evidence that a chain existed; a file that is gone while that evidence
    // stands is a DELETION and stays a failure.
    const journalMissing = !(await fs.stat(args.journalPath).then(() => true).catch(() => false));

    // THE WITNESS HAS TO OUTLIVE THE THING IT WITNESSES, and anchors.jsonl does not.
    //
    // The two witnesses below, the anchor log and the compromised sidecar, both live INSIDE the data
    // directory. So the one command a reader is told to run answered "nothing to verify, this is a
    // fresh deployment" after `rm -rf .data`, exiting 0, which is the exact opposite of the truth and
    // is the single outcome that would discredit this whole design: destroy the evidence, receive a
    // clean bill of health. Measured before this change, with the keys in their documented place
    // outside the data directory: exit 0, "NOTHING TO VERIFY".
    //
    // The signing material is the witness that survives, and not by luck: journal-keys.ts REFUSES a
    // key home inside the data directory ("the journal key file must live outside the data
    // directory"), so a deployment that ever wrote a record necessarily left a key somewhere the
    // deletion did not reach. A key without a journal is a journal that was removed.
    const keyHome = defaultHome(process.env);
    const keyWitness = (
      await Promise.all(
        ["journal.key", "signing.key"].map((name) =>
          fs.stat(path.join(keyHome, name)).then(() => true).catch(() => false),
        ),
      )
    ).some(Boolean);

    // anchorEntries is already a count, not an array; .length on it was silently undefined
    // Order matters here. An anchor or a sidecar says MORE than a key does: it names a chain and a
    // length, so when one of those survives the report should be the one that quotes it. The key is
    // the last witness standing, consulted only when the deletion took the other two with it.
    const everExisted = anchorEntries > 0 || sidecar !== null;
    if (journalMissing && !everExisted && keyWitness) {
      write(`  journal      ${args.journalPath}`);
      write("  result       MISSING, and this deployment has signing material for one");
      write(`               keys at ${keyHome} record that a journal was written here.`);
      write("               A journal that is gone while its keys remain was removed, not never made.");
      return 1;
    }
    if (journalMissing && !everExisted) {
      write(`  journal      ${args.journalPath}`);
      write("  result       NOTHING TO VERIFY, no journal exists at that path yet");
      write("               a journal appears once an agent has run a turn, and nothing external");
      write("               records that one ever did, so this is a fresh deployment rather than a");
      write("               deletion");
      return 0;
    }

    write(render(args, report, parsed, unreadable, anchorEntries, sidecar, unchecked, publicKeyFile, hmacKey));
  }
  // Three outcomes, never two. 1 stays "a check ran and failed", so anything already gating on it
  // keeps its meaning; 2 is "this run did not establish the thing you ran it to establish", which
  // used to be reported as 0.
  if (!report.ok) return 1;
  return unchecked.length ? 2 : 0;
}

const entry = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (entry === import.meta.url || entry === pathToFileURL(fileURLToPath(import.meta.url)).href) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}

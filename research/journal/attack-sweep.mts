/**
 * Attack harness for the Shadow Commit journal. Not a test: an experiment.
 *
 * Builds a real journal with the real Journal class, applies one real tampering operation, runs the
 * real verifier, and prints CAUGHT or MISSED with the first break. Every number in
 * research/journal/FINDINGS.md comes from a line this file printed.
 *
 *   npx tsx research/journal/attack-sweep.mts
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { GitAnchor } from "../../apps/server/src/anchors.js";
import { Journal } from "../../apps/server/src/journal.js";
import { verifyJournalAt } from "../../apps/server/src/journal-verify.js";
import { canonicalJson, hmacHex, sha256Hex, ZERO_HEAD } from "../../apps/server/src/journal-format.js";

type Rec = Record<string, unknown>;

/**
 * Re-seal a list of records the way journal.ts seals them: hmac over the canonical record without
 * hash and without hmac, then hash over the canonical record without hash. `key` null models an
 * attacker who cannot read the hmac key and therefore leaves the field alone.
 */
function seal(records: Rec[], key: string | null): string[] {
  let prev = ZERO_HEAD;
  const out: string[] = [];
  for (let i = 0; i < records.length; i++) {
    const base: Rec = { ...records[i]!, seq: i + 1, prev };
    delete base.hash;
    delete base.hmac;
    if (key) base.hmac = hmacHex(Buffer.from(key, "utf8"), canonicalJson(base));
    else if (typeof records[i]!.hmac === "string") base.hmac = records[i]!.hmac;
    const hash = sha256Hex(canonicalJson(base));
    out.push(JSON.stringify({ ...base, hash }));
    prev = hash;
  }
  return out;
}

/** a valid prefix with forged records appended to it */
function forge(existing: string[], extra: Rec[], key: string | null): string[] {
  const parsed = existing.map((l) => JSON.parse(l) as Rec);
  const last = parsed[parsed.length - 1]!;
  const appended = extra.map((e) => ({ ts: last.ts, principal: "agent", ...e }));
  if (!key) {
    // no key: keep the untouched prefix byte for byte, only the suffix is fabricated
    let prev = String(last.hash);
    let seq = Number(last.seq);
    const tail: string[] = [];
    for (const e of appended) {
      const base: Rec = { ...e, seq: ++seq, prev };
      const hash = sha256Hex(canonicalJson(base));
      tail.push(JSON.stringify({ ...base, hash }));
      prev = hash;
    }
    return [...existing, ...tail];
  }
  return seal([...parsed, ...appended], key);
}

/** every record rewritten, chain fields recomputed so the file is internally consistent */
function rewriteAll(existing: string[], key: string | null, edit: (r: Rec) => Rec): string[] {
  return seal(existing.map((l) => edit(JSON.parse(l) as Rec)), key);
}

const SCRATCH = process.env.ATTACK_SCRATCH ?? path.join(os.tmpdir(), "shadow-journal-attack");
const HOME_A = path.join(SCRATCH, "home-a");
const HOME_B = path.join(SCRATCH, "home-b");

/** a process environment with every journal key override cleared, so only `home` decides */
function cleanEnv(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, SHADOW_COMMIT_HOME: home };
  delete env.SHADOW_JOURNAL_KEY;
  delete env.SHADOW_JOURNAL_KEY_FILE;
  delete env.SHADOW_JOURNAL_PUBKEY_FILE;
  delete env.VITEST;
  return env;
}

type Seed = { dir: string; journalPath: string; home: string };

async function seed(opts: {
  label: string;
  records?: number;
  checkpointEvery?: number;
  home?: string;
  close?: boolean;
}): Promise<Seed> {
  const dir = await fs.mkdtemp(path.join(SCRATCH, opts.label + "-"));
  const home = opts.home ?? HOME_A;
  const journalPath = path.join(dir, "journal.jsonl");
  const journal = new Journal({
    journalPath,
    home,
    checkpointEvery: opts.checkpointEvery ?? 4,
    anchors: [new GitAnchor({ dataDirectory: dir, gitNotes: false })],
    env: cleanEnv(home),
  });
  await journal.open();
  for (let i = 0; i < (opts.records ?? 8); i++) {
    await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
  }
  if (opts.close !== false) await journal.close();
  return { dir, journalPath, home };
}

async function lines(p: string): Promise<string[]> {
  return (await fs.readFile(p, "utf8")).split("\n").filter((l) => l.trim() !== "");
}

async function writeLines(p: string, ls: string[]): Promise<void> {
  await fs.writeFile(p, ls.join("\n") + "\n", "utf8");
}

async function verdict(seed: Seed, env?: NodeJS.ProcessEnv): Promise<{ ok: boolean; first: string; keyed: boolean; warnings: string[] }> {
  const report = await verifyJournalAt(seed.journalPath, {
    dataDirectory: seed.dir,
    home: seed.home,
    env: env ?? cleanEnv(seed.home),
  });
  return {
    ok: report.ok,
    first: report.firstBreak ? `[${report.firstBreak.kind}] ${report.firstBreak.message}` : "(none)",
    keyed: report.keyed,
    warnings: report.warnings,
  };
}

const results: Array<{ attack: string; caught: boolean; detail: string }> = [];
function record(attack: string, ok: boolean, detail: string): void {
  const caught = !ok;
  results.push({ attack, caught, detail });
  console.log(`${caught ? "CAUGHT " : "MISSED "} ${attack.padEnd(58)} ${detail}`);
}

async function main(): Promise<void> {
  await fs.rm(SCRATCH, { recursive: true, force: true });
  await fs.mkdir(SCRATCH, { recursive: true });

  // ---- A. edit a record in place, same length ------------------------------------------------
  {
    const s = await seed({ label: "edit" });
    const ls = await lines(s.journalPath);
    ls[3] = ls[3]!.replace('"runId":"r1"', '"runId":"rX"');
    await writeLines(s.journalPath, ls);
    const v = await verdict(s);
    record("A same-length in-place edit of a record", v.ok, v.first);
  }

  // ---- B. delete a record from the middle ----------------------------------------------------
  {
    const s = await seed({ label: "del-mid" });
    const ls = await lines(s.journalPath);
    ls.splice(3, 1);
    await writeLines(s.journalPath, ls);
    const v = await verdict(s);
    record("B delete one record from the middle", v.ok, v.first);
  }

  // ---- C. delete from the END, swept over depth ----------------------------------------------
  // closed journal: the close checkpoint is anchored, so the anchor covers the whole file
  {
    const detected: number[] = [];
    const missed: number[] = [];
    for (let k = 1; k <= 12; k++) {
      const s = await seed({ label: `del-end-closed-${k}`, records: 8, checkpointEvery: 4 });
      const ls = await lines(s.journalPath);
      if (k >= ls.length) break;
      await writeLines(s.journalPath, ls.slice(0, ls.length - k));
      const v = await verdict(s);
      (v.ok ? missed : detected).push(k);
    }
    record(
      "C1 truncate tail of a CLOSED journal (sweep k=1..12)",
      missed.length > 0,
      `detected k=[${detected.join(",")}] missed k=[${missed.join(",")}]`,
    );
  }
  // running journal. The window is DERIVED from the last anchor rather than observed, because
  // anchoring runs off the turn path: how many records have landed past the last anchor when the
  // file is read varies between runs, and a raw observed list looks like flakiness rather than the
  // rule it is.
  {
    const base = await seed({ label: "del-end-open", records: 12, checkpointEvery: 4, close: false });
    const baseLines = await lines(base.journalPath);
    const clean = await verdict(base);
    const anchorSeq = (
      await import("../../apps/server/src/anchors.js")
    ).readAnchorLog(base.dir).then((points) => points[points.length - 1]?.seq ?? null);
    const seqOfLastAnchor = await anchorSeq;
    const window = seqOfLastAnchor === null ? null : baseLines.length - seqOfLastAnchor;
    const detected: number[] = [];
    const missed: number[] = [];
    for (let k = 1; k < baseLines.length; k++) {
      const s = await seed({ label: `del-end-open-${k}`, records: 12, checkpointEvery: 4, close: false });
      const ls = await lines(s.journalPath);
      await writeLines(s.journalPath, ls.slice(0, ls.length - k));
      const v = await verdict(s);
      (v.ok ? missed : detected).push(k);
    }
    record(
      "C2 truncate tail of a LIVE journal (sweep whole range)",
      missed.length > 0,
      `clean=${clean.ok} lines ${baseLines.length}, last anchor at seq ${seqOfLastAnchor}, window ${window}; missed k=[${missed.join(",")}] first detected k=${detected[0]}`,
    );
  }
  // and the same sweep with the shipped default checkpoint interval
  {
    const missed: number[] = [];
    const detected: number[] = [];
    const s0 = await seed({ label: "del-end-64", records: 80, checkpointEvery: 64, close: false });
    const total = (await lines(s0.journalPath)).length;
    for (let k = 1; k <= total - 1; k++) {
      const s = await seed({ label: `del-end-64-${k}`, records: 80, checkpointEvery: 64, close: false });
      const ls = await lines(s.journalPath);
      await writeLines(s.journalPath, ls.slice(0, ls.length - k));
      const v = await verdict(s);
      (v.ok ? missed : detected).push(k);
    }
    record(
      "C3 truncate tail, shipped default checkpointEvery=64, 80 records",
      missed.length > 0,
      `total lines ${total}; missed k=1..${Math.max(...missed)} (${missed.length} depths), detected ${detected.length} depths`,
    );
  }

  // ---- D. reorder two records ----------------------------------------------------------------
  {
    const s = await seed({ label: "reorder" });
    const ls = await lines(s.journalPath);
    const a = ls[3]!;
    ls[3] = ls[4]!;
    ls[4] = a;
    await writeLines(s.journalPath, ls);
    const v = await verdict(s);
    record("D swap two adjacent records", v.ok, v.first);
  }

  // ---- E. insert a record --------------------------------------------------------------------
  {
    const s = await seed({ label: "insert" });
    const ls = await lines(s.journalPath);
    ls.splice(3, 0, ls[2]!);
    await writeLines(s.journalPath, ls);
    const v = await verdict(s);
    record("E insert a duplicated record mid-chain", v.ok, v.first);
  }

  // ---- F. whole-journal substitution ----------------------------------------------------------
  // F1: journal.jsonl only, from a different run on the same host (same keys)
  {
    const victim = await seed({ label: "sub-victim", records: 8 });
    const donor = await seed({ label: "sub-donor", records: 8 });
    await fs.copyFile(donor.journalPath, victim.journalPath);
    const v = await verdict(victim);
    record("F1 swap journal.jsonl for another run's (anchors kept)", v.ok, v.first);
  }
  // F2: the whole data directory, same host, same keys
  {
    const victim = await seed({ label: "sub2-victim", records: 8 });
    const donor = await seed({ label: "sub2-donor", records: 8 });
    for (const f of ["journal.jsonl", "anchors.jsonl", "journal.pub"]) {
      await fs.copyFile(path.join(donor.dir, f), path.join(victim.dir, f)).catch(() => undefined);
    }
    const v = await verdict(victim);
    record("F2 swap the whole data directory for another run's", v.ok, v.first);
  }
  // F3: same, but the donor run used a different key home (a different machine)
  {
    const victim = await seed({ label: "sub3-victim", records: 8 });
    const donor = await seed({ label: "sub3-donor", records: 8, home: HOME_B });
    for (const f of ["journal.jsonl", "anchors.jsonl", "journal.pub"]) {
      await fs.copyFile(path.join(donor.dir, f), path.join(victim.dir, f)).catch(() => undefined);
    }
    const v = await verdict(victim);
    record("F3 swap the data directory for a DIFFERENT host's run", v.ok, v.first);
  }

  // ---- G, H, I have moved -------------------------------------------------------------------
  //
  // They are in apps/server/src/verify-journal.tamper.test.ts, and the reason is a fake catch this
  // harness produced and I nearly published. The naive forger here re-serialised the whole file with
  // JSON.stringify, whose key order differs from the canonical order journal.ts writes, so every
  // Merkle leaf changed even where the record's meaning did not. The verifier duly reported a
  // checkpoint break, and the harness printed CAUGHT for two attacks the product had not caught: it
  // had caught my re-serialisation. A forgery that keeps the prefix byte for byte, or that recomputes
  // the checkpoint roots the way a real forger would, is NOT caught. See forge-full.mts, which does
  // it properly, and the "NOT detected" block of the test file.
  //
  // Row I had the same shape of error from the other direction: it meant to model a verifier with no
  // key, but passed `home` explicitly to verifyJournalAt, which overrides the env it was setting, so
  // the key was found after all and the miss showed up as a catch.

  console.log("");
  console.log(`caught ${results.filter((r) => r.caught).length} of ${results.length}`);
  console.log("MISSED:");
  for (const r of results.filter((r) => !r.caught)) console.log(`  - ${r.attack}: ${r.detail}`);
}

await main();

import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { GitAnchor } from "./anchors.js";
import { Journal } from "./journal.js";
import { main, parseArgs } from "./verify-journal.js";

/**
 * These journals deliberately use the default key location rather than an injected one, because the
 * point of the verifier is that an operator runs it with no arguments and it finds what the running
 * server used.
 */
async function seed(records = 6, checkpointEvery = 3): Promise<{ dir: string; journalPath: string }> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "verify-cli-"));
  const journalPath = path.join(dir, "journal.jsonl");
  const journal = new Journal({
    journalPath,
    checkpointEvery,
    anchors: [new GitAnchor({ dataDirectory: dir, gitNotes: false })],
  });
  for (let i = 0; i < records; i++) {
    await journal.append({ kind: "turn.begin", runId: `r${i}`, agentId: "a1" });
    await journal.append({ kind: "policy.decision", runId: `r${i}`, decision: "commit", rule: "none" });
  }
  await journal.close();
  return { dir, journalPath };
}

const capture = async (argv: string[]): Promise<{ code: number; text: string }> => {
  const chunks: string[] = [];
  const code = await main(argv, (line) => chunks.push(line));
  return { code, text: chunks.join("\n") };
};

describe("npm run verify:journal", () => {
  it("prints the records, the checkpoints and the anchor status, and exits zero", async () => {
    const { dir, journalPath } = await seed();
    const { code, text } = await capture(["--journal", journalPath]);
    expect(code).toBe(0);
    expect(text).toContain("OK, the ledger verifies from record one");
    expect(text).toContain("keyed        yes, hmac verified on every record");
    expect(text).toMatch(/checkpoints {2}[1-9]/);
    expect(text).toContain("signature ok");
    expect(text).toContain("present in this journal");
    expect(text).toContain("turn.begin");
    expect(text).toContain("principals");
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("names the first break and exits non-zero when a record was edited", async () => {
    const { dir, journalPath } = await seed();
    const lines = (await fs.readFile(journalPath, "utf8")).split("\n").filter(Boolean);
    lines[4] = lines[4]!.replace('"runId":"r1"', '"runId":"rX"');
    await fs.writeFile(journalPath, lines.join("\n") + "\n");

    const { code, text } = await capture(["--journal", journalPath]);
    expect(code).toBe(1);
    expect(text).toContain("BROKEN");
    expect(text).toContain("record 5");
    expect(text).toContain("hash does not match its content");
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("reports a deleted journal against its anchor rather than as a fresh deployment", async () => {
    const { dir, journalPath } = await seed();
    await fs.rm(journalPath);
    const { code, text } = await capture(["--journal", journalPath]);
    expect(code).toBe(1);
    expect(text).toContain("an anchor records a chain");
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("calls a never-used journal fresh, but only when nothing attests to a chain", async () => {
    // The pair is the point. "No journal" is two different situations and the anchor is the only
    // thing that separates them: a clone that has never run a turn has no anchors either, while a
    // journal someone deleted leaves its anchors behind. Reporting the second as the first is how a
    // tamper-evidence feature ends up rewarding the tampering, so these two assertions belong in one
    // test where neither can be changed without facing the other.
    const fresh = await fs.mkdtemp(path.join(os.tmpdir(), "verify-fresh-"));
    const previousHome = process.env.SHADOW_COMMIT_HOME;
    try {
      // A fresh deployment has no KEYS either, and the suite shares one key home across every test,
      // so this has to point at an empty one or the surviving-key witness correctly says otherwise.
      process.env.SHADOW_COMMIT_HOME = path.join(fresh, "keys");
      const { code, text } = await capture(["--journal", path.join(fresh, "journal.jsonl")]);
      expect(code).toBe(0);
      expect(text).toContain("NOTHING TO VERIFY");
    } finally {
      if (previousHome === undefined) delete process.env.SHADOW_COMMIT_HOME;
      else process.env.SHADOW_COMMIT_HOME = previousHome;
      await fs.rm(fresh, { recursive: true, force: true });
    }

    // and the same absent file, once an anchor exists, is a break rather than a fresh start
    const { dir, journalPath } = await seed();
    try {
      await fs.rm(journalPath);
      const { code, text } = await capture(["--journal", journalPath]);
      expect(code).toBe(1);
      expect(text).not.toContain("NOTHING TO VERIFY");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("does not call a quarantined-then-deleted journal fresh, because the sidecar outlived it", async () => {
    // The sharpest version of the defect, and the one an anchor check alone does not catch: the
    // ledger was compromised, quarantined into a sidecar, and the journal itself then removed. No
    // anchors are involved. A freshness test that consults only anchors reports exit 0 and NOTHING TO
    // VERIFY, which is a clean bill of health for the worst state the system can be in. External
    // evidence that a chain existed is not only an anchor.
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "verify-sidecar-only-"));
    try {
      const journalPath = path.join(dir, "journal.jsonl");
      await fs.writeFile(
        journalPath.replace(/\.jsonl$/, "") + ".compromised.jsonl",
        JSON.stringify({ seq: 1, kind: "turn.committed", hash: "a".repeat(64) }) + "\n",
      );
      const { code, text } = await capture(["--journal", journalPath]);
      expect(code).toBe(1);
      expect(text).not.toContain("NOTHING TO VERIFY");
      expect(text).toContain("COMPROMISED");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses to call a destroyed ledger fresh, because the keys outlive the directory", async () => {
    // The worst outcome this project can produce: destroy the evidence, receive a clean bill of
    // health. Both of the other witnesses, the anchor log and the compromised sidecar, live INSIDE
    // the data directory, so `rm -rf .data` removes the attestation along with the ledger and the
    // one documented command answered "NOTHING TO VERIFY" and exited 0.
    //
    // The signing material is the witness that survives, and not by luck: journal-keys refuses a key
    // home inside the data directory, so anything that ever wrote a record left a key out of reach of
    // that deletion. A key with no journal is a journal that was removed.
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "verify-destroyed-"));
    const previousHome = process.env.SHADOW_COMMIT_HOME;
    try {
      const dataDir = path.join(root, "data");
      const keyHome = path.join(root, "keys");
      await fs.mkdir(dataDir, { recursive: true });
      process.env.SHADOW_COMMIT_HOME = keyHome;
      const journalPath = path.join(dataDir, "journal.jsonl");

      const journal = new Journal({ journalPath, dataDirectory: dataDir, home: keyHome });
      await journal.open();
      await journal.append({ runId: "r1", kind: "turn.begin" });
      await journal.close();
      await fs.rm(dataDir, { recursive: true, force: true });

      const destroyed = await capture(["--journal", journalPath, "--data-dir", dataDir]);
      expect(destroyed.code, "a destroyed ledger must not pass").toBe(1);
      expect(destroyed.text).not.toContain("NOTHING TO VERIFY");

      // and the negative case, which is the whole reason the fresh path exists: a clone that never
      // ran a turn has no keys either, and must still be told plainly that there is nothing to check
      const freshData = path.join(root, "fresh", "data");
      const freshKeys = path.join(root, "fresh", "keys");
      await fs.mkdir(freshData, { recursive: true });
      process.env.SHADOW_COMMIT_HOME = freshKeys;
      const fresh = await capture(["--journal", path.join(freshData, "journal.jsonl"), "--data-dir", freshData]);
      expect(fresh.code, "a genuinely fresh clone must still pass").toBe(0);
      expect(fresh.text).toContain("NOTHING TO VERIFY");
    } finally {
      if (previousHome === undefined) delete process.env.SHADOW_COMMIT_HOME;
      else process.env.SHADOW_COMMIT_HOME = previousHome;
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("says the ledger was quarantined when a compromised sidecar exists", async () => {
    const { dir, journalPath } = await seed(2, 64);
    await fs.appendFile(journalPath, JSON.stringify({ seq: 77, prev: "a".repeat(64), hash: "b".repeat(64), kind: "turn.committed" }) + "\n");
    const journal = new Journal({ journalPath, anchors: [] });
    await journal.open();
    expect(journal.status().state).toBe("compromised");
    await journal.close();

    const { code, text } = await capture(["--journal", journalPath]);
    expect(code).toBe(1);
    expect(text).toContain("COMPROMISED");
    expect(text).toContain("journal.compromised.jsonl");
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("emits a machine-readable report for CI", async () => {
    const { dir, journalPath } = await seed();
    const { code, text } = await capture(["--journal", journalPath, "--json", "--all"]);
    expect(code).toBe(0);
    const report = JSON.parse(text) as Record<string, any>;
    expect(report.ok).toBe(true);
    expect(report.keyed).toBe(true);
    expect(report.checkpoints.length).toBeGreaterThan(0);
    expect(report.anchors.present).toBe(true);
    expect(report.problems).toEqual([]);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("prints usage on request without touching anything", async () => {
    const { code, text } = await capture(["--help"]);
    expect(code).toBe(0);
    expect(text).toContain("npm run verify:journal");
  });
});

describe("the verifier's arguments", () => {
  it("defaults to the journal inside APP_DATA_DIR", () => {
    const args = parseArgs([], { APP_DATA_DIR: "/srv/app/.data" });
    expect(args.journalPath).toBe("/srv/app/.data/journal.jsonl");
    expect(args.dataDirectory).toBe("/srv/app/.data");
  });

  it("accepts both spellings of every flag", () => {
    const spaced = parseArgs(["--journal", "/a/j.jsonl", "--data-dir", "/b", "--records", "3"]);
    const inline = parseArgs(["--journal=/a/j.jsonl", "--data-dir=/b", "-n=3"]);
    expect(spaced).toEqual(inline);
    expect(spaced.records).toBe(3);
    expect(parseArgs(["--all"]).records).toBe(Number.POSITIVE_INFINITY);
    expect(parseArgs(["--json"]).json).toBe(true);
  });
});

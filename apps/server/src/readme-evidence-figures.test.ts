import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DESTRUCTIVE_WORKSPACE,
  materialize,
  parseVitestSummaries,
  testsBlock,
  treeDigest,
  workspacesWithTests,
} from "../../../scripts/evidence.js";

/**
 * The receipt and the figures the README prints from it.
 *
 * Two defects sit behind this file, and they are the same defect twice.
 *
 * 1. `npm run evidence` counted tests with /Tests\s+(\d+) passed \((\d+)\)/, which requires the
 *    literal " passed (" and so cannot match `Tests  975 passed | 5 skipped (980)`. Every cold
 *    clone skips at least the two container-oracle tests, so the server workspace never matched:
 *    the headline collapsed to the web workspace's 27 and still read "all passing". With no output
 *    at all it read "0 tests in 0 files across 0 workspace(s), all passing" and exited 0.
 *
 * 2. The README asserted 934 tests in 42 files in four places and derived it in none, including
 *    inside the pasted receipt it presents as regenerable. It was wrong at the base it was taken
 *    from and wronger since.
 *
 * The fix for both is that a number is either measured by the run that prints it or is not printed.
 * These tests hold that line: the parser reads what vitest actually emits, and the README may state
 * only figures this repository can re-derive without a full test run.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const WORKSPACES = ["apps/server", "apps/web"];

/**
 * What a cold clone of this repository prints on a mac: the server workspace skips the two
 * container-oracle tests (RUN_DOCKER_ORACLE_TESTS is set nowhere in the repository) and the
 * overlay-gated ones (darwin cannot mount an overlay), the web workspace skips nothing.
 */
const COLD_CLONE = [
  "",
  " RUN  v4.1.10 /repo/apps/server",
  "",
  " Test Files  54 passed (54)",
  "      Tests  975 passed | 5 skipped (980)",
  "   Start at  19:38:47",
  "",
  " RUN  v4.1.10 /repo/apps/web",
  "",
  " Test Files  3 passed (3)",
  "      Tests  27 passed (27)",
  "",
].join("\n");

/** The same run on a host where nothing is gated out: the shape the old regex did handle. */
const NOTHING_SKIPPED = [
  " Test Files  54 passed (54)",
  "      Tests  980 passed (980)",
  " Test Files  3 passed (3)",
  "      Tests  27 passed (27)",
].join("\n");

describe("the receipt counts what the run reported", () => {
  it("counts a workspace whose summary line carries a skip marker", () => {
    const block = testsBlock(COLD_CLONE, WORKSPACES);
    const text = block.lines.join("\n");

    expect(text).toContain("1002 passed");
    expect(text).toContain("5 skipped");
    expect(text).toContain("0 failed");
    expect(text).toContain("57 files");
    expect(text).toContain("2 workspace(s)");
    expect(block.ok).toBe(true);
    // the failure this replaces: 27, the web workspace alone, presented as the whole suite
    expect(text).not.toContain("27 passed,");
  });

  it("reports no count at all when the suites produced no output, instead of reporting zero", () => {
    const block = testsBlock("", WORKSPACES);
    const text = block.lines.join("\n");

    expect(block.ok).toBe(false);
    expect(text).toContain("NO TEST COUNT");
    expect(text).not.toContain("all passing");
    expect(text).not.toMatch(/\b0 tests\b/);
  });

  it("reports no count when one workspace is missing from the output", () => {
    const onlyWeb = [" Test Files  3 passed (3)", "      Tests  27 passed (27)"].join("\n");
    const block = testsBlock(onlyWeb, WORKSPACES);

    expect(block.ok).toBe(false);
    expect(block.lines.join("\n")).toContain("1 of 2 workspace(s)");
  });

  it("says so when a workspace failed", () => {
    const failing = COLD_CLONE.replace(
      "      Tests  975 passed | 5 skipped (980)",
      "      Tests  1 failed | 974 passed | 5 skipped (980)",
    );
    const block = testsBlock(failing, WORKSPACES);
    const text = block.lines.join("\n");

    expect(block.ok).toBe(false);
    expect(text).toContain("1 failed");
    expect(text).toContain("SOME FAILED");
  });

  /**
   * A file that throws while it is being collected (a bad import, a top-level throw, a syntax error
   * left behind by a merge) never registers its cases, so vitest reports it on the `Test Files` line
   * and the `Tests` line stays clean. Reading only the `Tests` line therefore prints "0 failed"
   * under a run that failed. The over-broad /\d+ failed/ this file replaced did catch that shape,
   * so dropping it without reading the Test Files row would be a hole closed by opening another.
   */
  it("counts a file that failed to collect, which vitest reports on Test Files and not on Tests", () => {
    const collectionFailure = COLD_CLONE.replace(
      " Test Files  54 passed (54)",
      " Test Files  1 failed | 53 passed (54)",
    );
    const block = testsBlock(collectionFailure, WORKSPACES);
    const text = block.lines.join("\n");

    expect(block.ok).toBe(false);
    expect(text).toContain("1 test file");
    expect(text).toContain("SOME FAILED");
    expect(text).not.toContain("skipped tests are counted here rather than hidden");
  });

  it("does not call a run clean when npm run test exited non-zero and the summary lines read clean", () => {
    const block = testsBlock(NOTHING_SKIPPED, WORKSPACES, 1);
    const text = block.lines.join("\n");

    expect(block.ok).toBe(false);
    expect(text).toContain("exited 1");
    expect(text).toContain("SOME FAILED");
  });

  it("names the workspaces npm run test will actually enter, from the manifest npm reads", async () => {
    const found = await workspacesWithTests(repoRoot);

    // both of today's workspaces, and nothing that has no test script to run
    expect(found).toContain("apps/server");
    expect(found).toContain("apps/web");
    for (const workspace of found) {
      const pkg = JSON.parse(await fs.readFile(path.join(repoRoot, workspace, "package.json"), "utf8")) as {
        scripts?: Record<string, string>;
      };
      expect(pkg.scripts?.test).toBeTruthy();
    }
  });

  // ---- the negative cases: ordinary runs must still read exactly as they did ----------------

  it("an ordinary run with nothing skipped still reports its real total and passes", () => {
    const block = testsBlock(NOTHING_SKIPPED, WORKSPACES);
    const text = block.lines.join("\n");

    expect(block.ok).toBe(true);
    expect(text).toContain("1007 passed");
    expect(text).toContain("0 skipped");
    expect(text).toContain("57 files");
  });

  it("an ordinary passing run that exits 0 still reads clean, with the skip note kept", () => {
    const block = testsBlock(COLD_CLONE, WORKSPACES, 0);
    const text = block.lines.join("\n");

    expect(block.ok).toBe(true);
    expect(text).toContain("1002 passed");
    expect(text).toContain("skipped tests are counted here rather than hidden");
    expect(text).not.toContain("SOME FAILED");
    expect(text).not.toContain("exited");
  });

  it("a test title containing the word failed does not make the receipt claim a failure", () => {
    const chatty = [
      " ✓ src/broker.test.ts > retries after 3 failed attempts",
      " ✓ src/journal.test.ts > 1 failed signature blocks the settle",
      NOTHING_SKIPPED,
    ].join("\n");
    const block = testsBlock(chatty, WORKSPACES);

    // the old check was /\d+ failed/ over the whole transcript, which these two titles satisfy
    expect(block.ok).toBe(true);
    expect(block.lines.join("\n")).toContain("0 failed");
  });

  it("reads passed, failed, skipped and todo out of one line without needing a fixed order", () => {
    const summaries = parseVitestSummaries(
      "Tests",
      "      Tests  2 failed | 3 passed | 4 skipped | 1 todo (10)",
    );
    expect(summaries).toEqual([{ passed: 3, failed: 2, skipped: 4, todo: 1, total: 10 }]);
  });

  it("does not read the Test Files line as a Tests line, or the other way round", () => {
    const both = " Test Files  54 passed (54)\n      Tests  975 passed | 5 skipped (980)";
    expect(parseVitestSummaries("Tests", both)).toHaveLength(1);
    expect(parseVitestSummaries("Tests", both)[0]?.total).toBe(980);
    expect(parseVitestSummaries("Test Files", both)).toHaveLength(1);
    expect(parseVitestSummaries("Test Files", both)[0]?.total).toBe(54);
  });
});

/** Every `*.test.ts(x)` under a workspace, which is what vitest will collect. */
async function testFilesUnder(workspace: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === "dist") continue;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(abs);
        continue;
      }
      if (/\.test\.tsx?$/.test(entry.name)) found.push(abs);
    }
  };
  await walk(path.join(repoRoot, workspace));
  return found.sort();
}

/**
 * A number big enough to be a suite total: three digits, or grouped with commas. Two digits is left
 * alone on purpose, because the counts this README is entitled to give are small and specific (the
 * test-file floor, the seventeen container tests) and this suite passed a thousand cases long ago.
 */
const SUITE_SIZED = String.raw`\d{1,3}(?:,\d{3})+|\d{3,}`;
/** The words that turn a number into a claim about how much of this repository was run. */
const COUNTED = String.raw`tests?|cases?|assertions?|specs?|passing|passed|failing|failed|skipped|todo`;
/** up to two filler words, so "1002 passing cases" and "tests: 1007" read the same as "1007 tests" */
const NEAR = String.raw`(?:[\s:=-]+\w+){0,2}[\s:=-]+`;

/**
 * What the README may not state about the whole suite. The first four are the shapes it actually
 * printed before this lane. The last two are the rule those four were approximating, and they are
 * the ones that matter: a check that enumerates shapes is a check the next phrasing walks past,
 * and the paragraph beside it promises a rule.
 */
const BANNED_TOTALS: Array<[RegExp, string]> = [
  [/\b[\d,]+\s+tests\s+in\s+[\d,]+\s+files\b/, "a pasted receipt headline"],
  [/\b[\d,]+\s+(?:server|web)\s+tests\b/, "a per-workspace test total"],
  [/typecheck,\s*[\d,]+\s+tests\b/, "a test total in the npm run check comment"],
  [/\b\d{3,}\s+in\s+[\d,]+\s+files\b/, "a total-and-files figure"],
  [new RegExp(String.raw`\b(?:${SUITE_SIZED})${NEAR}(?:${COUNTED})\b`, "i"), "a suite-sized number in front of a counting word"],
  [new RegExp(String.raw`\b(?:${COUNTED})${NEAR}(?:${SUITE_SIZED})\b`, "i"), "a counting word in front of a suite-sized number"],
];

describe("the figures the README prints", () => {
  /**
   * Read with every run of whitespace collapsed, so a figure cannot hide from a check by falling
   * across a line break: `execution-surface-review`\n  (480) is the same claim as one line.
   */
  const readme = async (): Promise<string> =>
    (await fs.readFile(path.join(repoRoot, "README.md"), "utf8")).replace(/\s+/g, " ");

  it("states no whole-suite test total, because nothing here can derive one without running it", async () => {
    const text = await readme();
    const found = BANNED_TOTALS.filter(([pattern]) => pattern.test(text)).map(
      ([pattern, what]) => `${what}: ${pattern.exec(text)?.[0] ?? ""}`,
    );

    expect(found).toEqual([]);
  });

  /**
   * The paragraph beside these patterns states a rule, not four shapes: this README does not write
   * down a whole-suite total. Four literal shapes are not that rule. Someone who writes "the suite
   * has 1007 tests" breaks the promise and passes the check, and the number is stale within a day
   * either way. So the check has to be about a big number standing next to a counting word, and it
   * has to leave alone the small, specific counts the README is entitled to give.
   */
  it("catches a whole-suite total in phrasings no literal shape anticipated", () => {
    const caught = (claim: string): boolean => BANNED_TOTALS.some(([pattern]) => pattern.test(claim));

    expect(caught("the suite has 1007 tests")).toBe(true);
    expect(caught("1007 cases across the two workspaces")).toBe(true);
    expect(caught("1,007 tests pass on a clean checkout")).toBe(true);
    expect(caught("tests: 1007")).toBe(true);
    expect(caught("the suite runs 1002 passing cases")).toBe(true);
    expect(caught("996 server tests")).toBe(true);
    expect(caught("934 tests in 42 files")).toBe(true);
  });

  it("leaves alone the small specific counts this README is entitled to state", () => {
    const caught = (claim: string): boolean => BANNED_TOTALS.some(([pattern]) => pattern.test(claim));

    expect(caught("More than 50 test files across the two workspaces")).toBe(false);
    expect(caught("17 further tests measure the seal from inside the container")).toBe(false);
    expect(caught("It reports 45 of 45 risk cases intercepted")).toBe(false);
    expect(caught("a corpus of 8,190 scenarios: 3,190 attacks (88 from a five-model red team)")).toBe(false);
    expect(caught("`execution-surface-review` (480)")).toBe(false);
    expect(caught("the count is whatever the TESTS block of `npm run evidence` prints on your host")).toBe(false);
  });

  /**
   * The one quantity the README is allowed to give about the suite is a floor, and the floor is
   * checked in both directions: the tree has to clear it, and it has to be worth stating. An exact
   * count would be a number that every lane that adds a test file falsifies, which is how the
   * README came to disagree with itself in four places in the first place.
   */
  it("states a test-file floor the tree supports, and one that is not vacuous", async () => {
    const text = await readme();
    const claim = /more than (\d+) test files/i.exec(text);
    expect(claim, "README should state a test-file floor it can back").not.toBeNull();

    const floor = Number(claim![1]);
    const server = (await testFilesUnder("apps/server")).length;
    const web = (await testFilesUnder("apps/web")).length;

    expect(server).toBeGreaterThan(0);
    expect(web).toBeGreaterThan(0);
    expect(server + web).toBeGreaterThan(floor);
    expect(floor).toBeGreaterThanOrEqual(Math.floor((server + web) / 2));
  });

  /**
   * The receipt block in the README is a paste of one run, and every number in a paste is a number
   * that drifts. Two kinds sit in the JOURNAL section, and they are not the same kind.
   *
   * The workspace digest is a function of three fixture files and nothing else, so it can be
   * recomputed here from the same bytes the evidence run lays down. That makes it a derived figure
   * rather than a remembered one, and it keeps the claim the line exists to make: the same value
   * twice, before the destructive turn and after it.
   */
  it("quotes a workspace digest this repository recomputes, and no hex string it cannot", async () => {
    const text = await readme();
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "readme-digest-"));
    await materialize(directory, DESTRUCTIVE_WORKSPACE);
    const digest = await treeDigest(directory);
    await fs.rm(directory, { recursive: true, force: true });

    const short = digest.slice(0, 16);
    // the pair, not one value: "identical either side of the turn" is the whole claim
    expect(text).toContain(`${short} and ${short}`);

    const strangers = [...text.matchAll(/\b[0-9a-f]{16,}\b/g)]
      .map((match) => match[0])
      .filter((hex) => !digest.startsWith(hex));
    expect(strangers, "every hex figure in the README has to be one this repository can recompute").toEqual([]);
  });

  /**
   * The record and checkpoint counts are the other kind. They are a function of how many journal
   * records three scenarios happen to write through the runner other lanes are changing under us,
   * so nothing here can derive them without a full evidence run, and a pasted `records 27` is the
   * same defect as a pasted test total: correct on the day it was written and unchecked after.
   */
  it("states no journal record or checkpoint count, because only a run can produce one", async () => {
    const text = await readme();

    expect(text).not.toMatch(/\brecords\s+\d/i);
    expect(text).not.toMatch(/\bcheckpoints\s+\d/i);
  });

  it("quotes the corpus report rather than a remembered version of it", async () => {
    const text = await readme();
    const report = await fs.readFile(path.join(repoRoot, "docs/CORPUS-REPORT.md"), "utf8");
    const grab = (pattern: RegExp): RegExpExecArray => {
      const match = pattern.exec(report);
      if (!match) throw new Error(`docs/CORPUS-REPORT.md no longer states ${String(pattern)}`);
      return match;
    };

    const miss = grab(/Attack miss rate[^:]*:\s*\*\*(\d+)\s*\/\s*(\d+)\s*=\s*([\d.]+)%\*\*/);
    const contained = grab(/Attacks contained[^:]*:\s*\*\*(\d+)\s*\/\s*(\d+)\*\*/);
    const abort = grab(/Benign false-abort rate[^:]*:\s*\*\*(\d+)\s*\/\s*(\d+)\s*=\s*([\d.]+)%\*\*/);
    const held = grab(/Benign turns escalated to a human[^:]*:\s*\*\*(\d+)\*\*/);
    const heldRate = grab(/(\d+) of (\d+) benign turns are held for a human, ([\d.]+)%/);
    const ruleCount = (rule: string): string => grab(new RegExp(`\\|\\s*${rule}\\s*\\|\\s*(\\d+)\\s*\\|`))[1]!;

    expect(text).toContain(`${miss[1]}/${miss[2]} = ${miss[3]}%`);
    expect(text).toContain(`${contained[1]}/${contained[2]}`);
    expect(text).toContain(`${abort[1]}/${abort[2]} = ${abort[3]}%`);
    expect(text).toContain(`${held[1]}/${heldRate[2]} = ${heldRate[3]}%`);
    expect(text).toContain(`\`dependency-added\` (${ruleCount("dependency-added")})`);
    expect(text).toContain(`\`execution-surface-review\` (${ruleCount("execution-surface-review")})`);
  });

  /**
   * The corpus report published 1176 in two places and 1175 in two others for a while, and its own
   * rule table backed the retracted number. Regenerating the report fixed it, and this keeps it
   * fixed: each published total has to equal the table that is offered as its breakdown.
   */
  it("adds up: each published benign total equals the rule table under it", async () => {
    const report = await fs.readFile(path.join(repoRoot, "docs/CORPUS-REPORT.md"), "utf8");
    const section = (heading: string): string => {
      const body = report.split(/^## /m).find((part) => part.startsWith(heading));
      if (!body) throw new Error(`docs/CORPUS-REPORT.md has no section ${heading}`);
      return body;
    };
    // The rule-name class carries a colon because rule ids do. `security-regression:test-disabled`
    // appeared in the review table when the exec-surface and guard-file narrowing landed, and the
    // earlier `[a-z][a-z-]+` silently skipped its row, so this summed 899 against a published 902
    // and read as the report contradicting itself. It did not: the report is exactly consistent and
    // the pattern could not see one of its rows. A total that drops rows it cannot parse is worse
    // than no total, because it fails in the direction of looking like someone else's mistake.
    const tableTotal = (heading: string): number =>
      [...section(heading).matchAll(/^\|\s*([a-z][a-z:-]+)\s*\|\s*(\d+)\s*\|$/gm)].reduce(
        (running, row) => running + Number(row[2]),
        0,
      );

    const aborts = /Benign false-abort rate[^:]*:\s*\*\*(\d+)\s*\//.exec(report);
    const held = /Benign turns escalated to a human[^:]*:\s*\*\*(\d+)\*\*/.exec(report);
    expect(aborts).not.toBeNull();
    expect(held).not.toBeNull();

    expect(tableTotal("Benign false aborts, by cause")).toBe(Number(aborts![1]));
    expect(tableTotal("What a benign turn is asked about")).toBe(Number(held![1]));
  });

  // ---- the negative case: the checker must accept a README that does the right thing --------

  it("accepts a README that points at the receipt and rejects one that pastes a total", () => {
    const banned = /\b[\d,]+\s+tests\s+in\s+[\d,]+\s+files\b/;
    const quoting = "the count is whatever the TESTS block of `npm run evidence` prints on your host";
    const asserting = "  934 tests in 42 files across 2 workspace(s), all passing";

    expect(banned.test(quoting)).toBe(false);
    expect(banned.test(asserting)).toBe(true);
    // and it does not swallow ordinary prose that happens to carry a small count
    expect(banned.test("17 further tests measure the seal from inside the container")).toBe(false);
  });
});

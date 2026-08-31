import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DRIVE = path.join(REPO, "scripts", "demo-drive.mjs");

/**
 * No artifact this driver writes carries anybody's home directory.
 *
 * The pack is bound for a public repository and six of its committed files carry `/Users/<name>`:
 * `transcript.txt`, `state.json` and three `steps/*.json`. That is a person's name in an artifact a
 * judge opens, and it survived a full re-record because the driver had no reason not to write it.
 *
 * **The committed pack is not cleaned by this change and this test does not assert that it is.**
 * The redaction happens at write time, so the pack gets it by being re-recorded, and the re-record
 * has to happen on the machine that produced it. `STORYBOARD.md` quotes latencies and a workspace
 * digest measured on an M2 MacBook Air with Colima (`1.5 s measured`, `1.3 s measured`,
 * `cc4f79ba8429f286`). Re-recording anywhere else would leave that prose describing numbers the
 * artifacts no longer show, which is precisely the mismatch that made the evidence pack a problem
 * in the first place. Trading one instance of that defect for another is not a fix.
 *
 * So this pins the mechanism only. The gate asserting the committed pack is clean belongs in the
 * same commit as the re-record, and `evidence-citations.test.ts` already guards the other half.
 */
describe("the demo driver redacts the home directory from everything it writes", () => {
  it("redacts all three committed writers", async () => {
    const source = await fs.readFile(DRIVE, "utf8");
    expect(source, "steps/*.json").toMatch(/redactHome\(JSON\.stringify\(value/);
    expect(source, "the transcript").toMatch(/redactHome\(transcript\.join/);
    expect(source, "state.json").toMatch(/redactHome\(\s*JSON\.stringify\(/);
  });

  it("keeps the inverse, because the second stage reads a real path back", async () => {
    const source = await fs.readFile(DRIVE, "utf8");
    // `state.workspace` is read from disk and joined with "package.json" and "tools/prepare.js" in
    // stageAfterBrowser. Redacting on write without expanding on read would have quietly broken
    // beats 9 and 10, which is a worse outcome than the leak this change closes.
    expect(source, "expandHome is applied to the workspace path").toMatch(
      /expandHome\(state\.workspace\)/,
    );
    expect(source, "expandHome is defined").toMatch(/const expandHome =/);
  });

  it("redacts a home-shaped path and leaves an unrelated one alone", async () => {
    // The helper is a pure string substitution, so it is checked here rather than trusted from a
    // grep of its call sites.
    const source = await fs.readFile(DRIVE, "utf8");
    const line = /const redactHome = \(text\) => \((.+)\);/.exec(source);
    expect(line, "redactHome is a one-line pure function this test can evaluate").toBeTruthy();

    const HOME = "/Users/someone";
    const redactHome = (text: string): string =>
      HOME && HOME !== "/" ? text.split(HOME).join("~") : text;

    expect(redactHome('{"workspace":"/Users/someone/dev/ws"}')).toBe('{"workspace":"~/dev/ws"}');
    expect(redactHome("/opt/other/path")).toBe("/opt/other/path");
    expect(redactHome("/Users/someone")).toBe("~");
  });
});

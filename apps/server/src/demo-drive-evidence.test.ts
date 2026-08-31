import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DRIVE = path.join(REPO, "scripts", "demo-drive.mjs");

/**
 * A failed demo run must not destroy the evidence pack a successful one left behind.
 *
 * This is the defect that produced the committed beat-0 failure sitting under a BEATS.md and a
 * STORYBOARD.md that narrated a successful five-turn run and cited ten `steps/*.json` files which
 * were no longer there. It was read as somebody having committed a bad run by mistake. It was not:
 * the script deleted `steps/` and both transcripts as its FIRST act and then wrote the transcript
 * in a `finally` whether the run had succeeded or not, so ANY failure produced exactly that state.
 * A server that was not up, a container that did not start, a Ctrl-C. It happened twice.
 *
 * The failing case is the one worth pinning, because the successful case is exercised every time
 * anyone records the demo and the failing one is exercised only when something has already gone
 * wrong, which is the moment nobody is looking.
 */
describe("a failed demo run leaves the committed evidence alone", () => {
  it("changes nothing under --out when the platform is not reachable", async () => {
    const out = await fs.mkdtemp(path.join(os.tmpdir(), "demo-evidence-"));
    // Stand-ins for the committed pack, with contents this run must not be able to alter.
    await fs.mkdir(path.join(out, "steps"), { recursive: true });
    await fs.writeFile(path.join(out, "transcript.txt"), "THE GOOD RUN\n");
    await fs.writeFile(path.join(out, "steps", "01-preflight.json"), '{"good":true}\n');
    await fs.writeFile(path.join(out, "steps", "10-platform-after.json"), '{"good":true}\n');
    await fs.mkdir(path.join(out, "browser"), { recursive: true });
    await fs.writeFile(path.join(out, "browser", "01-first-paint.yml"), "good: true\n");

    let exitCode = 0;
    let stdout = "";
    try {
      // Port 1 on loopback: nothing listens there, so beat 0 cannot succeed.
      const r = await execFileAsync(process.execPath, [
        DRIVE,
        "--base",
        "http://127.0.0.1:1",
        "--out",
        out,
      ]);
      stdout = r.stdout;
    } catch (e) {
      const err = e as { code?: number; stdout?: string };
      exitCode = typeof err.code === "number" ? err.code : 1;
      stdout = String(err.stdout ?? "");
    }

    // It must fail, or this test is not testing the failing path at all.
    expect(exitCode).toBe(1);
    expect(stdout).toContain("was not changed");

    // and every artifact is exactly as it was
    expect(await fs.readFile(path.join(out, "transcript.txt"), "utf8")).toBe("THE GOOD RUN\n");
    expect(await fs.readFile(path.join(out, "steps", "01-preflight.json"), "utf8")).toBe('{"good":true}\n');
    expect(await fs.readFile(path.join(out, "steps", "10-platform-after.json"), "utf8")).toBe('{"good":true}\n');
    expect(await fs.readFile(path.join(out, "browser", "01-first-paint.yml"), "utf8")).toBe("good: true\n");
    expect((await fs.readdir(path.join(out, "steps"))).sort()).toEqual([
      "01-preflight.json",
      "10-platform-after.json",
    ]);

    await fs.rm(out, { recursive: true, force: true });
  }, 60_000);

  it("says where the failed run's own output went, so it is not lost either", async () => {
    const out = await fs.mkdtemp(path.join(os.tmpdir(), "demo-evidence-"));
    let stdout = "";
    try {
      const r = await execFileAsync(process.execPath, [DRIVE, "--base", "http://127.0.0.1:1", "--out", out]);
      stdout = r.stdout;
    } catch (e) {
      stdout = String((e as { stdout?: string }).stdout ?? "");
    }

    const named = /its output is in (\S+)/.exec(stdout);
    expect(named, "the failure message names where it wrote").toBeTruthy();
    const transcript = await fs.readFile(path.join(named![1], "transcript.txt"), "utf8");
    expect(transcript).toContain("FAILED");

    await fs.rm(named![1], { recursive: true, force: true });
    await fs.rm(out, { recursive: true, force: true });
  }, 60_000);
});

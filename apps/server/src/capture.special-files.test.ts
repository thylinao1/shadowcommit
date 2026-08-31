import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { captureEffects, defaultLimits, readBounded, snapshotStats } from "./capture.js";
import { createOverlaySealer } from "./overlay-sealer.js";
import { defaultPolicy } from "./shadow-policy.js";
import { TransactionalRunner } from "./transactional-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * A socket, a fifo or a device has no bytes. The capture used to open every non-directory entry to
 * hash it anyway, and that was two defects wearing one coat:
 *
 *   - a socket cannot be opened for reading, so its hash was "unreadable", so its signature never
 *     matched the one the seal recorded (which had no hash segment), so every socket in a
 *     copy-sealed workspace was reported as MODIFIED on every turn, by an agent that never touched
 *     it. The commit then tried to copy it, copyFile failed, and the failure was swallowed.
 *   - a fifo CAN be opened for reading, and open() blocks until a writer appears. `mkfifo` needs
 *     no privilege. So a turn could make one in the sealed view and the capture would sit in open()
 *     forever, and the turn would never settle. Measured on the copy path before this file existed:
 *     HUNG after 8000ms, for a fifo the workspace already had and for one the agent made.
 *
 * The rule now: a special file is identified by its stat and never opened, by the capture, by the
 * commit, or by a policy asking for its body. These tests use no `cp`, so they say the same thing on
 * every host.
 */

// AF_UNIX sun_path is 104 bytes on Darwin, and os.tmpdir() under TMPDIR is already most of that.
const SHORT_TMP = "/tmp";

let root = "";
const servers: net.Server[] = [];
const events: Array<Record<string, unknown>> = [];

beforeEach(async () => {
  root = await fs.mkdtemp(path.join(SHORT_TMP, "sf-"));
  events.length = 0;
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
  await fs.rm(root, { recursive: true, force: true }).catch(() => undefined);
});

async function listenAt(p: string): Promise<void> {
  const server = net.createServer();
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(p, () => resolve());
  });
}

async function shadowDirFor(shadowRoot: string, id: string): Promise<string> {
  const dir = path.join(shadowRoot, id);
  for (const d of ["upper", "work", "merged"]) await fs.mkdir(path.join(dir, d), { recursive: true });
  return dir;
}

/** a workspace and a by-hand copy of it, so no host's `cp` is part of what is being tested */
async function workspaceAndCopy(): Promise<{ real: string; shadowDir: string; merged: string }> {
  const real = path.join(root, "real");
  await fs.mkdir(path.join(real, "src"), { recursive: true });
  await fs.writeFile(path.join(real, "keep.txt"), "keep\n");
  await fs.writeFile(path.join(real, "src", "lib.js"), "module.exports = 1;\n");
  const shadowDir = await shadowDirFor(path.join(root, "shadows"), "run1");
  const merged = path.join(shadowDir, "merged");
  await fs.mkdir(path.join(merged, "src"), { recursive: true });
  await fs.copyFile(path.join(real, "keep.txt"), path.join(merged, "keep.txt"));
  await fs.copyFile(path.join(real, "src", "lib.js"), path.join(merged, "src", "lib.js"));
  return { real, shadowDir, merged };
}

const settlesWithin = async <T>(p: Promise<T>, ms: number): Promise<T> => {
  const timer = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error(`did not settle within ${ms}ms: the capture is blocked in open()`)), ms),
  );
  return Promise.race([p, timer]);
};

describe("a special file is identified by its stat and never opened", () => {
  it("does not report a socket the turn never touched as modified", async () => {
    const { real, shadowDir, merged } = await workspaceAndCopy();
    await listenAt(path.join(real, "app.sock"));
    await listenAt(path.join(merged, "app.sock"));
    const realInodes = (await snapshotStats(real)).inodes;
    const sealed = await snapshotStats(merged, { hash: true });

    const captured = await settlesWithin(
      captureEffects({ shadowDir, real, mechanism: "copy", sealed, realInodes, limits: defaultLimits }),
      5000,
    );
    expect(captured.effects.map((e) => `${e.kind} ${e.path}`)).toEqual([]);
  });

  it("reports a fifo the turn made on the copy path, without opening it", async () => {
    const { real, shadowDir, merged } = await workspaceAndCopy();
    const realInodes = (await snapshotStats(real)).inodes;
    const sealed = await snapshotStats(merged, { hash: true });
    // the agent's move: no privilege needed, and nothing will ever write to it
    await execFileAsync("mkfifo", [path.join(merged, "pipe.fifo")]);

    const captured = await settlesWithin(
      captureEffects({ shadowDir, real, mechanism: "copy", sealed, realInodes, limits: defaultLimits }),
      5000,
    );
    const fifo = captured.effects.find((e) => e.path === "pipe.fifo");
    expect(fifo, "the fifo the turn created is an effect").toBeDefined();
    expect(fifo!.kind).toBe("create");
    expect(fifo!.bytes).toBe(0);
    expect(fifo!.sha256, "there are no bytes to hash and it must not have tried").toBeUndefined();
  });

  it("reports a fifo the turn made on the overlay path, without opening it", async () => {
    const { real, shadowDir } = await workspaceAndCopy();
    const realInodes = (await snapshotStats(real)).inodes;
    // under overlay a new entry lands in `upper`; that is what the capture walks, so no mount is
    // needed to reach the same line of code
    await execFileAsync("mkfifo", [path.join(shadowDir, "upper", "pipe.fifo")]);

    const captured = await settlesWithin(
      captureEffects({
        shadowDir,
        real,
        mechanism: "overlay",
        sealed: await snapshotStats(path.join(root, "nothing-sealed")),
        realInodes,
        limits: defaultLimits,
      }),
      5000,
    );
    expect(captured.effects.map((e) => `${e.kind} ${e.path}`)).toEqual(["create pipe.fifo"]);
  });

  it("answers a policy asking for a fifo's body with null, at once", async () => {
    const fifo = path.join(root, "pipe.fifo");
    await execFileAsync("mkfifo", [fifo]);
    expect(await settlesWithin(readBounded(fifo, 1024), 2000)).toBeNull();
  });
});

describe("end to end, a turn that makes a fifo", () => {
  const agentThat = (act: (ws: string) => Promise<void>): AgentRunner => ({
    isAvailable: async () => true,
    cancel: async () => true,
    run: async (request: RunnerRequest): Promise<RunnerResult> => {
      await act(request.workspacePath);
      return { output: "done", threadId: null, usage: null };
    },
  });

  it("settles, and the commit refuses the fifo on the record rather than opening it", async () => {
    const ws = path.join(root, "ws");
    await fs.mkdir(ws, { recursive: true });
    await fs.writeFile(path.join(ws, "keep.txt"), "keep\n");

    const shadowRoot = path.join(root, "shadows-e2e");
    const journalPath = path.join(root, "journal.jsonl");
    const sealer = createOverlaySealer({ shadowRoot, releaseHookWired: true, force: "copy", emit: (e) => events.push(e) });
    const runner = new TransactionalRunner(
      agentThat(async (view) => {
        await fs.writeFile(path.join(view, "note.txt"), "ordinary work\n");
        await execFileAsync("mkfifo", [path.join(view, "pipe.fifo")]);
      }),
      {
        shadowRoot,
        journalPath,
        policy: defaultPolicy,
        seal: sealer.seal,
        release: async (dir, mechanism) => {
          await sealer.release(dir, mechanism);
        },
      },
    );

    // THE PROPERTY: the turn ends. Before this it did not.
    const outcome = await settlesWithin(
      runner
        .run({ agentId: "a1", workspacePath: ws, prompt: "p", threadId: null })
        .then((r) => ({ ran: true, decision: r.containment?.decision ?? null }), (e: Error) => ({ ran: false, decision: e.message })),
      15_000,
    );
    await runner.closeJournal().catch(() => undefined);

    // and whatever the policy decided, no fifo was made in the real workspace, because a commit
    // carries bytes and a fifo has none
    expect(await fs.lstat(path.join(ws, "pipe.fifo")).catch(() => null), `outcome=${JSON.stringify(outcome)}`).toBeNull();
    expect(await fs.readFile(path.join(ws, "keep.txt"), "utf8")).toBe("keep\n");

    if (outcome.ran && outcome.decision === "commit") {
      // the ordinary work landed, and the refusal is in the ledger with its reason, not swallowed
      expect(await fs.readFile(path.join(ws, "note.txt"), "utf8")).toBe("ordinary work\n");
      const records = (await fs.readFile(journalPath, "utf8"))
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as { kind?: string; path?: string; reason?: string });
      const refused = records.find((r) => r.kind === "effect.refused" && r.path === "pipe.fifo");
      expect(refused, `no effect.refused for pipe.fifo; kinds=${records.map((r) => r.kind).join(",")}`).toBeDefined();
      expect(refused!.reason).toMatch(/fifo/);
    }
  }, 20_000);
});

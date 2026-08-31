import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { captureEffects, defaultLimits, emptySnapshot, snapshotStats } from "./capture.js";
import { createOverlaySealer, proveNotMounted } from "./overlay-sealer.js";
import { defaultPolicy } from "./shadow-policy.js";
import { TransactionalRunner } from "./transactional-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * The copy seal is the shipped path on every host that cannot mount an overlay, and `cp -a` can
 * fail one file at a time. The chain this file pins:
 *
 *   one unreadable file -> `cp -a` exits non-zero and omits it -> the shadow is a PARTIAL copy ->
 *   the copy-only pass in captureEffects walks the real workspace, finds the path missing from the
 *   shadow, and cannot tell that absence apart from a deletion by the agent -> one `delete` effect
 *   for a file the turn never opened -> below every multi-delete threshold, so it commits and the
 *   real file is removed.
 *
 * A partial shadow can never be diffed against the real workspace. So a copy that could not copy
 * everything has to be a FAILED seal, loudly, rather than a mechanism the runner is told is fine.
 */

// chmod 000 is not a barrier to root, so the unreadable-file cases would pass vacuously there.
const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;
if (IS_ROOT) console.log("[overlay-sealer-copy-failure] unreadable-file cases SKIPPED: running as root");

let root = "";
let events: Array<Record<string, unknown>> = [];
const collect = (r: Record<string, unknown>) => {
  events.push(r);
};

beforeEach(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "sealer-copyfail-"));
  events = [];
});

afterEach(async () => {
  // make everything readable again or the cleanup inherits the same failure the test induced
  await execFileAsync("chmod", ["-R", "u+rwX", root]).catch(() => undefined);
  if ((await proveNotMounted(root)).proven) {
    await fs.rm(root, { recursive: true, force: true }).catch(() => undefined);
  }
});

async function makeWorkspace(dir: string): Promise<void> {
  await fs.mkdir(path.join(dir, "src"), { recursive: true });
  await fs.writeFile(path.join(dir, "keep.txt"), "keep\n");
  await fs.writeFile(path.join(dir, "src", "lib.js"), "module.exports = 1;\n");
}

async function shadowDirFor(shadowRoot: string, id: string): Promise<string> {
  const dir = path.join(shadowRoot, id);
  for (const d of ["upper", "work", "merged"]) await fs.mkdir(path.join(dir, d), { recursive: true });
  return dir;
}

/** the copy-only capture the runner performs after a "copy" seal */
async function captureAfterCopySeal(real: string, shadowDir: string) {
  return captureEffects({
    shadowDir,
    real,
    mechanism: "copy",
    sealed: await snapshotStats(path.join(shadowDir, "merged"), { hash: true }),
    realInodes: (await snapshotStats(real)).inodes,
    limits: defaultLimits,
  });
}

describe("a copy that could not copy everything", () => {
  it("does not hand the runner a mechanism, and so cannot manufacture a delete", async () => {
    if (IS_ROOT) return;
    const real = path.join(root, "real");
    await makeWorkspace(real);
    await fs.writeFile(path.join(real, "unreadable.bin"), "payload\n");
    await fs.chmod(path.join(real, "unreadable.bin"), 0o000);

    const shadowRoot = path.join(root, "shadows");
    const shadowDir = await shadowDirFor(shadowRoot, "run-partial");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    const mechanism = await sealer.seal(real, shadowDir).then(
      (m) => m as string | null,
      () => null,
    );

    // Either the seal failed, or the capture that follows it contains no delete the turn did not
    // do. There is no third answer: a partial shadow read as a diff invents deletions.
    if (mechanism !== null) {
      const captured = await captureAfterCopySeal(real, shadowDir);
      expect(
        captured.effects.filter((e) => e.kind === "delete").map((e) => e.path),
        "the seal reported success over a partial copy and the capture invented a delete",
      ).toEqual([]);
    }
    expect(mechanism, "seal() resolved over a copy that omitted a file").toBeNull();
  });

  it("names the paths it could not copy, and records the failure before it throws", async () => {
    if (IS_ROOT) return;
    const real = path.join(root, "real2");
    await makeWorkspace(real);
    await fs.writeFile(path.join(real, "secret.env"), "value\n");
    await fs.chmod(path.join(real, "secret.env"), 0o000);

    const shadowRoot = path.join(root, "shadows2");
    const shadowDir = await shadowDirFor(shadowRoot, "run-named");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    await expect(sealer.seal(real, shadowDir)).rejects.toThrow(/secret\.env/);
    const failed = events.find((e) => e.kind === "seal.failed");
    expect(failed, `no seal.failed event; got ${events.map((e) => e.kind).join(",")}`).toBeDefined();
    expect(failed!.runId).toBe("run-named");
  });

  it("leaves no partial shadow copy behind after it fails", async () => {
    if (IS_ROOT) return;
    const real = path.join(root, "real3");
    await makeWorkspace(real);
    await fs.writeFile(path.join(real, "locked.bin"), "x\n");
    await fs.chmod(path.join(real, "locked.bin"), 0o000);

    const shadowRoot = path.join(root, "shadows3");
    const shadowDir = await shadowDirFor(shadowRoot, "run-cleanup");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    await expect(sealer.seal(real, shadowDir)).rejects.toThrow();
    expect(await fs.stat(shadowDir).catch(() => null), "the partial copy was left on disk").toBeNull();
    // and the real workspace is untouched, which is the whole point
    expect(await fs.readFile(path.join(real, "keep.txt"), "utf8")).toBe("keep\n");
  });
});

describe("ordinary work still works", () => {
  it("seals a readable workspace as a complete copy", async () => {
    const real = path.join(root, "real4");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows4");
    const shadowDir = await shadowDirFor(shadowRoot, "run-ok");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    expect(await sealer.seal(real, shadowDir)).toBe("copy");
    const merged = path.join(shadowDir, "merged");
    expect(await fs.readFile(path.join(merged, "keep.txt"), "utf8")).toBe("keep\n");
    expect(await fs.readFile(path.join(merged, "src", "lib.js"), "utf8")).toContain("module.exports");
    expect(events.some((e) => e.kind === "seal.failed")).toBe(false);
  });

  it("still captures a delete the turn really performed", async () => {
    const real = path.join(root, "real5");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows5");
    const shadowDir = await shadowDirFor(shadowRoot, "run-real-delete");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });
    expect(await sealer.seal(real, shadowDir)).toBe("copy");

    const sealed = await snapshotStats(path.join(shadowDir, "merged"), { hash: true });
    // the agent deletes a file inside the sealed view
    await fs.rm(path.join(shadowDir, "merged", "keep.txt"));

    const captured = await captureEffects({
      shadowDir,
      real,
      mechanism: "copy",
      sealed,
      realInodes: (await snapshotStats(real)).inodes,
      limits: defaultLimits,
    });
    expect(captured.effects.filter((e) => e.kind === "delete").map((e) => e.path)).toEqual(["keep.txt"]);
  });

  it("accepts a cp that could not preserve metadata but copied every byte", async () => {
    // GNU `cp -a` exits non-zero when it cannot preserve ownership, having copied the content
    // anyway. Failing the turn on the exit code alone would break every workspace with mixed
    // ownership, so the check is completeness of the tree, not the exit status.
    const real = path.join(root, "real6");
    await makeWorkspace(real);
    const shim = path.join(root, "shim");
    await fs.mkdir(shim, { recursive: true });
    await fs.writeFile(
      path.join(shim, "cp"),
      '#!/bin/sh\n/bin/cp "$@"\necho "cp: failed to preserve ownership" >&2\nexit 1\n',
      { mode: 0o755 },
    );
    const shadowRoot = path.join(root, "shadows6");
    const shadowDir = await shadowDirFor(shadowRoot, "run-metadata");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    const previousPath = process.env.PATH;
    process.env.PATH = `${shim}:${previousPath ?? ""}`;
    try {
      expect(await sealer.seal(real, shadowDir)).toBe("copy");
    } finally {
      process.env.PATH = previousPath;
    }
    expect(await fs.readFile(path.join(shadowDir, "merged", "keep.txt"), "utf8")).toBe("keep\n");
    // the failure is not silent even when it is survivable
    expect(events.some((e) => e.kind === "seal.copy.degraded")).toBe(true);
  });

  it("keeps the empty-snapshot helper honest for the capture calls above", () => {
    const snap = emptySnapshot();
    expect(snap.signatures.size).toBe(0);
    expect(snap.inodes.size).toBe(0);
  });
});

/** the agent does nothing at all, so every effect the turn produces was manufactured for it */
const idleRunner: AgentRunner = {
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (_request: RunnerRequest): Promise<RunnerResult> => ({
    output: "did nothing",
    threadId: null,
    usage: null,
  }),
};

describe("end to end, through the wiring runner-factory ships", () => {
  it("does not delete a real file the turn never opened", async () => {
    if (IS_ROOT) return;
    const ws = path.join(root, "ws");
    await makeWorkspace(ws);
    await fs.writeFile(path.join(ws, "unreadable.bin"), "payload\n");
    await fs.chmod(path.join(ws, "unreadable.bin"), 0o000);

    const shadowRoot = path.join(root, "shadows-e2e");
    // exactly what createRunner builds, with the mechanism forced to the shipped fallback
    const sealer = createOverlaySealer({ shadowRoot, releaseHookWired: true, force: "copy", emit: collect });
    const runner = new TransactionalRunner(idleRunner, {
      shadowRoot,
      journalPath: path.join(root, "journal.jsonl"),
      policy: defaultPolicy,
      seal: sealer.seal,
      release: async (dir, mechanism) => {
        await sealer.release(dir, mechanism);
      },
    });

    const outcome = await runner
      .run({ agentId: "a1", workspacePath: ws, prompt: "p", threadId: null })
      .then((r) => `ran: ${JSON.stringify(r.containment ?? null)}`, (e: Error) => `refused: ${e.message}`);
    await runner.closeJournal().catch(() => undefined);

    // THE PROPERTY. The turn opened no file and deleted nothing, so every file it started with is
    // still there. A seal that could not copy one of them must not be able to spend that as a
    // deletion of the real one.
    expect(
      await fs.lstat(path.join(ws, "unreadable.bin")).catch(() => null),
      `the turn removed a file it never opened. outcome=${outcome}`,
    ).not.toBeNull();
    expect(await fs.readFile(path.join(ws, "keep.txt"), "utf8")).toBe("keep\n");
    expect(outcome).toMatch(/^refused: /);
  });
});

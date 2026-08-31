import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { CommitProtocol } from "./commit-protocol.js";
import { RunnerStore } from "./runner-store.js";
import { statSignature } from "./capture.js";
import type { EffectRecord } from "./policy-types.js";

/**
 * The last sibling of the swallowed-failure class, pinned rather than changed.
 *
 * The copy arm used to drop a failed write silently and the symlink arm used to report a link it
 * never made as applied; both now fail closed through failedAt. The delete arm is different: its
 * `fs.rm` is unguarded, so a failure THROWS out of commit() raw. That is the honest failure mode,
 * and this test exists so nobody later wraps it in `.catch(() => undefined)` to quiet a flaky run
 * and quietly joins it to the class the other two arms just left. Measured here: no turn.committed
 * is emitted, the pending record survives for reconcile to replay, and the file is untouched.
 *
 * Reached deterministically: the file's parent directory is read-only, so unlink fails EACCES.
 *
 * Except as root, which is why this file checks. `CAP_DAC_OVERRIDE` lets uid 0 ignore the very
 * permission bits this test sets, so the unlink SUCCEEDS, commit() resolves, and the assertion that
 * it rejects fails with no hint that the environment rather than the code is what changed. That is
 * a real half hour for anyone reproducing this work in a root shell, which is the default in a
 * Docker container, in WSL, and in most CI images that are not GitHub's. CI here runs as a normal
 * user, so it has never seen this.
 *
 * Skipped rather than adapted: there is no way to make a directory root cannot write to, so the
 * behaviour this test pins is genuinely unobservable as uid 0. A skip that says why is honest; a
 * test rewritten until it passes as root would pin nothing.
 */
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

describe("a delete that cannot happen fails loudly, not silently", () => {
  it.skipIf(isRoot)("throws out of commit(), emits no committed event, and leaves the pending record", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "delf-"));
    const real = path.join(root, "ws");
    const shadowDir = path.join(root, "shadows", "run1");
    await fs.mkdir(path.join(real, "locked"), { recursive: true });
    await fs.mkdir(path.join(shadowDir, "merged"), { recursive: true });
    await fs.writeFile(path.join(real, "locked", "f.txt"), "bytes\n");
    const baseline: Record<string, string> = {
      "locked/f.txt": statSignature(await fs.lstat(path.join(real, "locked", "f.txt"))),
    };
    await fs.chmod(path.join(real, "locked"), 0o555);

    try {
      const effect: EffectRecord = { path: "locked/f.txt", kind: "delete" } as EffectRecord;
      const events: Record<string, unknown>[] = [];
      const store = new RunnerStore(root);
      const protocol = new CommitProtocol({
        emit: async (f: Record<string, unknown>) => void events.push(f),
        store,
        journalPath: path.join(root, "journal.jsonl"),
        shadowRoot: path.join(root, "shadows"),
      } as never);
      const pending = {
        runId: "run1", agentId: "a1", workspacePath: real, shadowDir,
        mechanism: "copy", effects: [effect], baseline,
        startedAt: new Date(0).toISOString(),
      };
      await store.putPending(pending as never);

      await expect(protocol.commit(pending as never)).rejects.toThrow(/EACCES/);

      // loud is only honest if nothing pretended otherwise and recovery still has its record
      expect(events.map((e) => e.kind)).not.toContain("turn.committed");
      expect(await store.getPending("run1")).toBeTruthy();
      await expect(fs.lstat(path.join(real, "locked", "f.txt"))).resolves.toBeTruthy();
    } finally {
      await fs.chmod(path.join(real, "locked"), 0o755); // let tmp cleanup delete the bed
    }
  });

  it("still deletes an ordinary file, so the pin is not vacuous about the happy path", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "delo-"));
    const real = path.join(root, "ws");
    const shadowDir = path.join(root, "shadows", "run1");
    await fs.mkdir(real, { recursive: true });
    await fs.mkdir(path.join(shadowDir, "merged"), { recursive: true });
    await fs.writeFile(path.join(real, "gone.txt"), "bytes\n");
    const baseline: Record<string, string> = {
      "gone.txt": statSignature(await fs.lstat(path.join(real, "gone.txt"))),
    };
    const effect: EffectRecord = { path: "gone.txt", kind: "delete" } as EffectRecord;
    const events: Record<string, unknown>[] = [];
    const store = new RunnerStore(root);
    const protocol = new CommitProtocol({
      emit: async (f: Record<string, unknown>) => void events.push(f),
      store,
      journalPath: path.join(root, "journal.jsonl"),
      shadowRoot: path.join(root, "shadows"),
    } as never);
    const pending = {
      runId: "run1", agentId: "a1", workspacePath: real, shadowDir,
      mechanism: "copy", effects: [effect], baseline,
      startedAt: new Date(0).toISOString(),
    };
    await store.putPending(pending as never);

    const outcome = await protocol.commit(pending as never);
    expect(outcome).toMatchObject({ decision: "commit" });
    expect(events.map((e) => e.kind)).toContain("turn.committed");
    await expect(fs.lstat(path.join(real, "gone.txt"))).rejects.toThrow();
  });
});

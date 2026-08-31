import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { CommitProtocol } from "./commit-protocol.js";
import { RunnerStore } from "./runner-store.js";
import { statSignature } from "./capture.js";
import type { EffectRecord } from "./policy-types.js";

/**
 * A commit carries bytes into the real workspace. When it cannot, it must say so.
 *
 * The apply loop swallowed a failed `copyFile` of a regular file: `if (!copied) continue`. Every
 * other failure in the same loop aborts (a tamper returns, a workspace that moved returns), but a
 * copy that could not complete was dropped from the applied set and recorded nowhere, and commit()
 * ran on to turn.committed, removed the pending record and released the shadow. The effect was lost
 * with no trace and the turn reported a clean commit.
 *
 * The failure is reached deterministically here: the turn creates a regular file `report`, and the
 * real workspace already holds `report` as a directory, so `copyFile` fails EISDIR. EACCES, ENOSPC
 * and a source that vanishes mid-commit reach the same line.
 */

const deps = (root: string, extra: Record<string, unknown> = {}) => ({
  emit: async () => undefined,
  store: new RunnerStore(root),
  journalPath: path.join(root, "journal.jsonl"),
  shadowRoot: path.join(root, "shadows"),
  ...extra,
});

async function scenario(root: string, opts: { realReportIsDir: boolean }): Promise<{
  pending: Record<string, unknown>;
  real: string;
}> {
  const real = path.join(root, "ws");
  const shadowDir = path.join(root, "shadows", "run1");
  const merged = path.join(shadowDir, "merged");
  await fs.mkdir(real, { recursive: true });
  await fs.mkdir(merged, { recursive: true });
  await fs.writeFile(path.join(merged, "report"), "the bytes the turn produced\n");

  const baseline: Record<string, string> = {};
  if (opts.realReportIsDir) {
    // the collision: a directory sits where the turn writes a file, unchanged since the seal
    await fs.mkdir(path.join(real, "report"), { recursive: true });
    baseline.report = statSignature(await fs.lstat(path.join(real, "report")));
  }

  const effect: EffectRecord = {
    path: "report",
    kind: opts.realReportIsDir ? "modify" : "create",
    mode: 0o644,
    bytes: 28,
    canonicalPath: "report",
  };
  return {
    real,
    pending: {
      runId: "run1",
      agentId: "a1",
      workspacePath: real,
      shadowDir,
      mechanism: "copy",
      effects: [effect],
      baseline,
      startedAt: new Date(0).toISOString(),
    },
  };
}

describe("a commit does not report success over a write it could not make", () => {
  it("names a failed copy as a conflict instead of committing clean over it", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "cf-"));
    const events: Record<string, unknown>[] = [];
    const store = new RunnerStore(root);
    const protocol = new CommitProtocol(
      deps(root, { store, emit: async (f: Record<string, unknown>) => void events.push(f) }) as never,
    );
    const { pending, real } = await scenario(root, { realReportIsDir: true });

    const outcome = await protocol.commit(pending as never);

    // not a clean commit
    expect(outcome.ok).toBe(false);
    expect(outcome.decision).toBe("conflict");
    expect(outcome.rule).toBe("effect-write-failed");
    // the effect was NOT applied: the directory is untouched
    expect(await fs.lstat(path.join(real, "report")).then((s) => s.isDirectory())).toBe(true);
    // the journal names it, and does NOT claim the turn committed
    const kinds = events.map((e) => e.kind);
    expect(kinds).toContain("turn.conflicted");
    expect(kinds).not.toContain("turn.committed");
    const conflicted = events.find((e) => e.kind === "turn.conflicted");
    expect(conflicted?.path).toBe("report");
    expect(conflicted?.rule).toBe("effect-write-failed");
    // and the pending record is cleared, so it is not left dangling
    expect(await store.getPending("run1")).toBeNull();
  });

  it("still commits an ordinary write, so the guard does not block real work", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "cf-"));
    const events: Record<string, unknown>[] = [];
    const protocol = new CommitProtocol(
      deps(root, { emit: async (f: Record<string, unknown>) => void events.push(f) }) as never,
    );
    const { pending, real } = await scenario(root, { realReportIsDir: false });

    const outcome = await protocol.commit(pending as never);

    expect(outcome.ok).toBe(true);
    expect(outcome.decision).toBe("commit");
    expect(await fs.readFile(path.join(real, "report"), "utf8")).toBe("the bytes the turn produced\n");
    expect(events.map((e) => e.kind)).toContain("turn.committed");
  });

  it("does not report a RECOVERED turn committed when the replay could not apply it either", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "cf-"));
    const events: Record<string, unknown>[] = [];
    const store = new RunnerStore(root);
    const journalPath = path.join(root, "journal.jsonl");
    const protocol = new CommitProtocol(
      deps(root, { store, journalPath, emit: async (f: Record<string, unknown>) => void events.push(f) }) as never,
    );
    const { pending } = await scenario(root, { realReportIsDir: true });

    // a crash after the commit point: the record is pending and the journal has the commit point
    await store.putPending(pending as never);
    await fs.writeFile(journalPath, JSON.stringify({ kind: "turn.committing", runId: "run1", agentId: "a1" }) + "\n");

    const result = await protocol.reconcile();

    const kinds = events.map((e) => e.kind);
    expect(kinds).toContain("turn.conflicted");
    expect(kinds).not.toContain("turn.committed");
    expect(events.find((e) => e.kind === "turn.conflicted")?.recovered).toBe(true);
    expect(result.replayed).not.toContain("run1");
    expect(await store.getPending("run1")).toBeNull();
  });
});

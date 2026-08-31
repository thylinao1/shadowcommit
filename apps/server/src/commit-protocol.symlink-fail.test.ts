import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { CommitProtocol } from "./commit-protocol.js";
import { RunnerStore } from "./runner-store.js";
import { statSignature } from "./capture.js";
import type { EffectRecord } from "./policy-types.js";

/**
 * The swallowed-failure class that the failed-copy fix closes, one branch above it.
 *
 * `fs.rm(...).catch(() => undefined)` and `fs.symlink(...).catch(() => undefined)` both dropped their
 * error and execution fell through to `applied.push(effect.path)`, so a link that was never created
 * was reported as APPLIED. That is a worse shape than the copy bug, which at least dropped the effect
 * from the applied set: here the commit positively claimed to have done the work.
 *
 * Reached deterministically: the real workspace holds `link` as a NON-EMPTY directory. `fs.rm` runs
 * without `recursive` so it fails, and `fs.symlink` then fails EEXIST. Neither error survived.
 */

const protocolFor = (root: string, events: Record<string, unknown>[], store: RunnerStore) =>
  new CommitProtocol({
    emit: async (f: Record<string, unknown>) => void events.push(f),
    store,
    journalPath: path.join(root, "journal.jsonl"),
    shadowRoot: path.join(root, "shadows"),
  } as never);

async function bed(opts: { occupied: boolean; escapes?: boolean; target?: string }) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "slf-"));
  const real = path.join(root, "ws");
  const shadowDir = path.join(root, "shadows", "run1");
  await fs.mkdir(real, { recursive: true });
  await fs.mkdir(path.join(shadowDir, "merged"), { recursive: true });

  const baseline: Record<string, string> = {};
  if (opts.occupied) {
    await fs.mkdir(path.join(real, "link"), { recursive: true });
    await fs.writeFile(path.join(real, "link", "keep.txt"), "occupied\n");
    baseline.link = statSignature(await fs.lstat(path.join(real, "link")));
  }

  const effect = {
    path: "link",
    kind: "symlink",
    target: opts.target ?? "elsewhere.txt",
    escapes: opts.escapes ?? false,
  } as EffectRecord;

  const events: Record<string, unknown>[] = [];
  const store = new RunnerStore(root);
  const pending = {
    runId: "run1", agentId: "a1", workspacePath: real, shadowDir,
    mechanism: "copy", effects: [effect], baseline,
    startedAt: new Date(0).toISOString(),
  };
  await store.putPending(pending as never);
  return { root, real, events, store, pending, protocol: protocolFor(root, events, store) };
}

describe("a commit does not report success over a link it could not create", () => {
  it("names a failed symlink as a conflict instead of counting it as applied", async () => {
    const { real, events, pending, protocol } = await bed({ occupied: true });
    const outcome = await protocol.commit(pending as never);

    expect(outcome).toMatchObject({ ok: false, rule: "effect-write-failed", decision: "conflict" });
    expect(events.map((e) => e.kind)).toContain("turn.conflicted");
    expect(events.map((e) => e.kind)).not.toContain("turn.committed");
    // and the workspace is untouched, which is what makes the conflict honest
    expect((await fs.lstat(path.join(real, "link"))).isDirectory()).toBe(true);
  });

  it("records a link refused for escaping instead of dropping it without a trace", async () => {
    const { events, pending, protocol } = await bed({ occupied: false, escapes: true });
    await protocol.commit(pending as never);
    const refusals = events.filter((e) => String(e.kind).includes("refus") || e.reason !== undefined);
    expect(refusals.length).toBeGreaterThan(0);
  });

  it("still creates an ordinary symlink, so the guard does not block real work", async () => {
    const { real, events, pending, protocol } = await bed({ occupied: false });
    const outcome = await protocol.commit(pending as never);

    expect(outcome).toMatchObject({ decision: "commit" });
    expect(events.map((e) => e.kind)).toContain("turn.committed");
    expect((await fs.lstat(path.join(real, "link"))).isSymbolicLink()).toBe(true);
    expect(await fs.readlink(path.join(real, "link"))).toBe("elsewhere.txt");
  });
});

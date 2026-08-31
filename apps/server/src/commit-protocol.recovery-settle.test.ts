import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { CommitProtocol } from "./commit-protocol.js";
import { RunnerStore } from "./runner-store.js";
import { statSignature } from "./capture.js";
import type { EffectRecord } from "./policy-types.js";

/**
 * Recovery used to finish the FILE half of a transaction and claim the whole one.
 *
 * The agent's memory promote and the broker's held outbound writes both live behind `settle`, which
 * had three call sites and none of them was in `reconcile`. So a recovered turn emitted
 * `turn.committed` while the memory was never promoted and the held writes were never replayed, and
 * README:169 said a crash after the commit point is finished idempotently at the next start.
 *
 * The fix is not to guess at the missing halves. It is to call the same settle the live path calls,
 * which already knows how to say that it could not find the state: after a real crash the process
 * that held the run is gone, so settle reports `confinementStateLost` and the journal records an
 * incomplete settle rather than a clean commit.
 */

async function bed() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "recsettle-"));
  const real = path.join(root, "ws");
  const shadowDir = path.join(root, "shadows", "run1");
  const merged = path.join(shadowDir, "merged");
  await fs.mkdir(real, { recursive: true });
  await fs.mkdir(merged, { recursive: true });
  await fs.writeFile(path.join(merged, "note.txt"), "the bytes the turn produced\n");

  const effect: EffectRecord = { path: "note.txt", kind: "create" } as EffectRecord;
  const events: Record<string, unknown>[] = [];
  const store = new RunnerStore(root);
  const pending = {
    runId: "run1", agentId: "a1", workspacePath: real, shadowDir,
    mechanism: "copy", effects: [effect], baseline: {} as Record<string, string>,
    startedAt: new Date(0).toISOString(),
  };
  await store.putPending(pending as never);
  return { root, real, shadowDir, events, store, pending };
}

describe("a recovered turn settles the other halves, or says it could not", () => {
  it("records that only the file half happened when the run's state died with the process", async () => {
    const { real, events, store, pending } = await bed();
    const settleCalls: [string, string][] = [];
    const protocol = new CommitProtocol({
      emit: async (f: Record<string, unknown>) => void events.push(f),
      store,
      journalPath: path.join(pending.shadowDir, "..", "..", "journal.jsonl"),
      shadowRoot: path.join(pending.shadowDir, ".."),
      // the real confinement's answer when nothing in this process knows the run
      settleConfinement: async (runId: string, decision: string) => {
        settleCalls.push([runId, decision]);
        return {
          confinementStateLost: true,
          confinementStateLostDetail:
            "no sealed network or codex-home state was found for this run, so only the files " +
            "half of this settle happened",
        };
      },
    } as never);

    await protocol.reconcile();

    // the file half still happens
    await expect(fs.readFile(path.join(real, "note.txt"), "utf8")).resolves.toContain("the bytes");
    // settle was actually reached, with the commit decision
    expect(settleCalls).toEqual([["run1", "commit"]]);
    // and the journal no longer claims a clean recovered commit
    const committed = events.find((e) => e.kind === "turn.committed");
    expect(committed).toBeDefined();
    expect(committed).toMatchObject({ recovered: true, confinementStateLost: true });
    expect(String(committed?.confinementStateLostDetail)).toContain("only the files");
  });

  it("carries a real settle's note through when the state did survive", async () => {
    const { events, store, pending } = await bed();
    const protocol = new CommitProtocol({
      emit: async (f: Record<string, unknown>) => void events.push(f),
      store,
      journalPath: path.join(pending.shadowDir, "..", "..", "journal.jsonl"),
      shadowRoot: path.join(pending.shadowDir, ".."),
      settleConfinement: async () => ({ outboundReplayed: 2, outboundFailed: 0, codexHome: "promoted" }),
    } as never);

    await protocol.reconcile();

    const committed = events.find((e) => e.kind === "turn.committed");
    expect(committed).toMatchObject({
      recovered: true,
      outboundReplayed: 2,
      outboundFailed: 0,
      codexHome: "promoted",
    });
    expect(committed).not.toHaveProperty("confinementStateLost");
  });
});

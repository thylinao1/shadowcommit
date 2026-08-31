import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { TransactionalRunner } from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import {
  armReadWitness,
  collectReadWitness,
  collectTurnReadWitness,
  failedReadWitness,
  readWitnessJournalFields,
  readWitnessOf,
  type ReadWitnessBaseline,
} from "./read-witness.js";
import type { EffectRecord, Policy, PolicyContext } from "./policy-types.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * The witness, wired into the product, and the proof that wiring it moved no verdict.
 *
 * `read-witness.test.ts` beside this file holds the module: whether an access time moves, what the
 * change-time bit closes, what the arm shifts and what the reconciliation repairs. This file is
 * about the four lines that connect it to a turn, which is a different question and a different way
 * of being wrong. The module was correct and imported by nothing outside its own test, so the class
 * of turn it exists for stayed invisible in the shipped pipeline: a turn that opens every credential
 * in the sealed view and writes nothing produces an empty effect set, every rule abstains over
 * nothing, and it commits under rule `none`.
 *
 * WHAT IS WIRED IS THE OBSERVATION AND NOTHING ELSE. There is no rule here, no new EffectKind, and
 * no verdict that depends on a read. That is a deliberate limit rather than an unfinished edge: the
 * raw protected-read bit is 35.4% false positive on the benign set and 10.4% behind the selectivity
 * gate, against a human-ask rate that is already 24.1% of benign turns, so a rule built on it is a
 * cost decision with an owner. The tests below assert the verdict column exactly as the product
 * produced it BEFORE the wiring, so that a later change that quietly makes a read decide something
 * fails here.
 *
 * The verdict column was measured on the unwired tree, not predicted: every `decision` and `rule` in
 * SHAPES was read off a run of this file with `transactional-runner.ts` reverted to 1078803, and the
 * whole column still passes in that state. That is what makes it a control rather than a copy of
 * what the wired code happens to do.
 *
 * ## Limits, stated here rather than found later
 *
 * - The mechanism is the copy. Under overlay the witness is null by design, because arming the
 *   sealed view there means writing access times into the user's real repository, and the test below
 *   pins the null and the journal slug rather than pretending coverage.
 * - `atime-frozen` is exercised through the real arm and the real collection with a stand-in for one
 *   syscall on one throwaway file, because no filesystem on this host refuses to move an access time.
 *   Measured on the NUS cluster, nfs4 relatime moved atime for zero of seven readers, so the branch
 *   is not hypothetical, but it cannot be reached honestly from a laptop's APFS volume.
 * - A turn whose agent throws is released without a collection. The reads happened and are not
 *   recorded; the turn is journaled `turn.discarded` with rule `turn-failed`, which no read could
 *   have changed.
 * - The approve path for a held turn re-evaluates the policy long after the sealed copy is gone, so
 *   `readWitnessOf` returns null there. Null is "not watched", never "read nothing", and the accessor
 *   keeps those distinguishable for the rule that eventually reads it.
 * - GNU tar opens files `O_NOATIME` and is invisible to the witness; bsdtar is not. A turn that
 *   reaches for the one binary that can read without leaving the bit gets a read count that does not
 *   include what it took.
 * - The arm walks and stats every regular file in the sealed copy. Measured at 8,776 files it costs
 *   0.6 s to 0.7 s warm and 2.3 s cold, on top of a seal that was already 5 s to 7 s. Every turn now
 *   pays it, and nothing here caps it by tree size.
 *
 * ## How this was falsified
 *
 * ```
 * export PATH=$HOME/.nvm/versions/node/v22.21.0/bin:$PATH
 * npx vitest run apps/server/src/read-witness-wiring.test.ts          # 22 tests
 * npx vitest run apps/server/src/read-witness.test.ts                 # the module, 32 tests
 * ```
 *
 * REVERT PROOF, `transactional-runner.ts` alone put back to 1078803 with this file untouched: 15 of
 * 22 fail. Fourteen fail on the capability, every one at the first read assertion and none earlier,
 * so the verdict and effect-count assertions above them all still pass with the wiring gone. The
 * fifteenth is `an imprecise timestamp restore ...`, which fails with `expected 'discard' to be
 * 'commit'`, and that one is the trade documented above it rather than a missing capability.
 *
 * TWO ONE-LINE MUTATIONS, applied to the wiring with this file untouched:
 * ```
 * M1  the `reconcileSealedSignatures` call removed   -> 13 fail; a turn that did NOTHING hands the
 *     policy four modify effects and every shape becomes a discard
 *     (`expected [ { path: '.env', ...(6) }, ...(3) ] to deeply equal []`)
 * M2  the collection moved to AFTER captureEffects   -> 11 fail; a turn that ran nothing at all
 *     reports `reads: 4`, the platform's own hashing (`expected 4 to be +0`), and the tampering bit
 *     is destroyed by the hash that moved the access time (`expected +0 to be 1`)
 * ```
 *
 * NO VERDICT MOVED, measured rather than asserted. `transactional-runner.js` and `read-witness.js`
 * are not in the 30-file policy closure the corpus harness grades, and the closure digest is
 * identical before and after (2e2fa02f78b4551a...). The corpus was replayed against a build of HEAD
 * plus this lane's two files only, because three rule files owned by other lanes were dirty in the
 * tree at the time and grading them would have measured somebody else's change:
 * ```
 * npx tsc -p apps/server/tsconfig.json                                # in a git-archive of HEAD + these two files
 * node research/corpus/replay-v2.mjs --policy <that dist>/shadow-policy.js --out /tmp/readwitness-final.jsonl
 * -> 8190 rows, misses 117, false aborts 65, held 1207, and 0 rows differing in decision or rule
 *    from the committed research/corpus/results/results.jsonl
 * ```
 */

const scriptRunner = (act: (shadow: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "done", threadId: null, usage: null };
  },
});

/** four regular files, one of them a credential the platform's own protected set names */
async function seed(ws: string): Promise<void> {
  await fs.mkdir(path.join(ws, "src"), { recursive: true });
  await fs.writeFile(path.join(ws, ".env"), "API_TOKEN=FIXTURE-KEY-NOT-REAL\n");
  await fs.writeFile(path.join(ws, "README.md"), "# fixture\n");
  await fs.writeFile(path.join(ws, "src", "app.ts"), "export const app = 1;\n");
  await fs.writeFile(path.join(ws, "src", "util.ts"), "export const util = 2;\n");
}

const SEEDED_FILES = 4;

async function withWorkspace<T>(fn: (ws: string, root: string) => Promise<T>): Promise<T> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "read-witness-wiring-"));
  const ws = path.join(root, "ws");
  await fs.mkdir(ws, { recursive: true });
  await seed(ws);
  try {
    return await fn(ws, root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const wrap = (
  inner: AgentRunner,
  root: string,
  extra: Partial<ConstructorParameters<typeof TransactionalRunner>[1]> = {},
): TransactionalRunner =>
  new TransactionalRunner(inner, {
    shadowRoot: path.join(root, "shadows"),
    journalPath: path.join(root, "journal.jsonl"),
    policy: defaultPolicy,
    ...extra,
  });

const request = { agentId: "a1", workspacePath: "", prompt: "p", threadId: null };

const journalRecords = async (root: string): Promise<Array<Record<string, unknown>>> =>
  (await fs.readFile(path.join(root, "journal.jsonl"), "utf8"))
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line) as Record<string, unknown>];
      } catch {
        return [];
      }
    });

/** the one line that carries what the turn wrote, and now what it read */
const capturedLine = async (root: string): Promise<Record<string, unknown>> => {
  const line = (await journalRecords(root)).find((r) => r.kind === "effects.captured");
  if (line === undefined) throw new Error("no effects.captured record in the journal");
  return line;
};

/** a policy that records what it was handed and then commits, so the context can be inspected */
function recordingPolicy(): { policy: Policy; seen: { effects: EffectRecord[]; context: PolicyContext | null } } {
  const seen: { effects: EffectRecord[]; context: PolicyContext | null } = { effects: [], context: null };
  const policy: Policy = async (effects, context) => {
    seen.effects = effects;
    seen.context = context;
    return { decision: "commit", rule: "none" };
  };
  return { policy, seen };
}

/** opens every regular file under `dir`, the way a whole-tree grep does */
async function readEverything(dir: string): Promise<number> {
  let count = 0;
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) count += await readEverything(full);
    else if (entry.isFile()) {
      await fs.readFile(full);
      count += 1;
    }
  }
  return count;
}

describe("the class of turn the middleware could not act on", () => {
  it("a turn that reads a credential and writes nothing is journaled as having read it", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(
        scriptRunner(async (shadow) => {
          await fs.readFile(path.join(shadow, ".env"), "utf8");
        }),
        root,
      );

      const result = await runner.run({ ...request, workspacePath: ws });
      const line = await capturedLine(root);

      // The effect set is empty and always was. That is the gap, not a regression.
      expect(line.count).toBe(0);
      expect(result.containment?.effects).toBe(0);
      // And the verdict is exactly what it was before the wiring: this records, it does not decide.
      expect(result.containment?.decision).toBe("commit");
      expect(result.containment?.rule).toBe("none");

      // What is new is on the same line, beside the effect count.
      expect(line.readWitness).toBe("armed");
      expect(line.reads).toBe(1);
      expect(line.protectedReads).toBe(1);
      expect(line.readPaths).toEqual([".env"]);
      expect(line.readsArmed).toBe(SEEDED_FILES);
      expect(line.readsBlind).toBe(0);
      expect(line.readSelectivity).toBe(0.25);
    });
  });

  it("the same record reaches the policy, and the policy still decides without it", async () => {
    await withWorkspace(async (ws, root) => {
      const { policy, seen } = recordingPolicy();
      const runner = wrap(
        scriptRunner(async (shadow) => {
          await fs.readFile(path.join(shadow, ".env"), "utf8");
        }),
        root,
        { policy },
      );

      await runner.run({ ...request, workspacePath: ws });

      expect(seen.effects).toEqual([]);
      const witness = readWitnessOf(seen.context);
      expect(witness).not.toBeNull();
      expect(witness?.supported).toBe(true);
      expect(witness?.reads).toBe(1);
      expect(witness?.protectedReads).toBe(1);
      expect(witness?.paths).toEqual([".env"]);
      // The journal line and the context are the same observation, not two measurements that can
      // drift: one collection, summarised once for each consumer.
      const line = await capturedLine(root);
      expect(line.reads).toBe(witness?.reads);
      expect(line.protectedReads).toBe(witness?.protectedReads);
    });
  });

  it("a read is not an effect: no EffectRecord is invented for it", async () => {
    await withWorkspace(async (ws, root) => {
      const { policy, seen } = recordingPolicy();
      const runner = wrap(
        scriptRunner(async (shadow) => {
          await readEverything(shadow);
        }),
        root,
        { policy },
      );

      await runner.run({ ...request, workspacePath: ws });

      // Opening every file in the workspace produces no create, no modify, no delete and no
      // symlink. Putting a read into this array would put it in front of fifteen rules written
      // about writes, and `protected-asset-write` would start firing on a file nobody wrote.
      expect(seen.effects).toEqual([]);
      expect(readWitnessOf(seen.context)?.reads).toBe(SEEDED_FILES);
    });
  });
});

/**
 * The sweep, across the whole axis the change lives on rather than the point where it was shown.
 *
 * The axis is the shape of a turn: what it read, what it wrote, whether the two overlap, and whether
 * it tried to cover its tracks. Every row asserts BOTH columns. The verdict column is the control
 * and passes with the wiring reverted; the read column is the capability and fails without it.
 */
interface Shape {
  name: string;
  act: (shadow: string) => Promise<void>;
  decision: "commit" | "discard" | "review";
  rule: string;
  effects: number;
  reads: number;
  protectedReads: number;
  tampered: number;
}

const SHAPES: Shape[] = [
  {
    name: "does nothing at all",
    act: async () => undefined,
    decision: "commit",
    rule: "none",
    effects: 0,
    reads: 0,
    protectedReads: 0,
    tampered: 0,
  },
  {
    name: "reads one ordinary source file",
    act: async (shadow) => {
      await fs.readFile(path.join(shadow, "src", "app.ts"), "utf8");
    },
    decision: "commit",
    rule: "none",
    effects: 0,
    reads: 1,
    protectedReads: 0,
    tampered: 0,
  },
  {
    name: "reads the credential and nothing else",
    act: async (shadow) => {
      await fs.readFile(path.join(shadow, ".env"), "utf8");
    },
    decision: "commit",
    rule: "none",
    effects: 0,
    reads: 1,
    protectedReads: 1,
    tampered: 0,
  },
  {
    name: "reads the whole tree, the way a grep -r does",
    act: async (shadow) => {
      await readEverything(shadow);
    },
    decision: "commit",
    rule: "none",
    effects: 0,
    reads: SEEDED_FILES,
    protectedReads: 1,
    tampered: 0,
  },
  {
    name: "writes a new file and reads nothing",
    act: async (shadow) => {
      await fs.writeFile(path.join(shadow, "src", "added.ts"), "export const added = 3;\n");
    },
    decision: "commit",
    rule: "none",
    effects: 1,
    reads: 0,
    protectedReads: 0,
    tampered: 0,
  },
  {
    name: "writes the credential, which the policy already discarded on its own",
    act: async (shadow) => {
      await fs.writeFile(path.join(shadow, ".env"), "API_TOKEN=FIXTURE-KEY-NOT-REAL-2\n");
    },
    decision: "discard",
    rule: "protected-asset-write",
    effects: 1,
    // a file the turn WROTE is capture's business and is not claimed twice as a read
    reads: 0,
    protectedReads: 0,
    tampered: 0,
  },
  {
    name: "reads the credential and writes somewhere harmless",
    act: async (shadow) => {
      await fs.readFile(path.join(shadow, ".env"), "utf8");
      await fs.writeFile(path.join(shadow, "src", "added.ts"), "export const added = 3;\n");
    },
    decision: "commit",
    rule: "none",
    effects: 1,
    reads: 1,
    protectedReads: 1,
    tampered: 0,
  },
  {
    name: "reads the credential and puts the access time back, exactly",
    act: async (shadow) => {
      const file = path.join(shadow, ".env");
      const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "read-witness-tamper-"));
      try {
        // The realistic shape of the evasion. `cp -p` stats the source before it reads it and
        // carries nanoseconds onto the copy, so the reference holds the ACCESS TIME AS ARMED, and
        // `touch -r` puts it back exactly. Both are in every image and neither needs a privilege.
        // The reference is written outside the sealed view, because a file written inside it would
        // be an effect and the turn would be judged on the platform's own scratch.
        const reference = path.join(scratch, "ref");
        await execFileAsync("cp", ["-p", file, reference]);
        await fs.readFile(file, "utf8");
        await execFileAsync("touch", ["-r", reference, file]);
      } finally {
        await fs.rm(scratch, { recursive: true, force: true });
      }
    },
    decision: "commit",
    rule: "none",
    effects: 0,
    // the access time is back where the arm put it, so the read bit is gone; the change time is not
    // settable by any syscall and it moved, which is the observation that survives
    reads: 0,
    protectedReads: 1,
    tampered: 1,
  },
];

describe("the sweep: every turn shape, both columns", () => {
  for (const shape of SHAPES) {
    it(`${shape.name}`, async () => {
      await withWorkspace(async (ws, root) => {
        const runner = wrap(scriptRunner(shape.act), root);
        const result = await runner.run({ ...request, workspacePath: ws });
        const line = await capturedLine(root);

        // THE CONTROL. Measured on the unwired tree; a wiring that moves any of it is a wiring
        // that decided something, which this one is not allowed to do.
        expect(result.containment?.decision).toBe(shape.decision);
        expect(result.containment?.rule).toBe(shape.rule);
        expect(result.containment?.effects).toBe(shape.effects);
        expect(line.count).toBe(shape.effects);

        // THE CAPABILITY.
        expect(line.readWitness).toBe("armed");
        expect(line.reads).toBe(shape.reads);
        expect(line.protectedReads).toBe(shape.protectedReads);
        expect(line.readsTampered).toBe(shape.tampered);
        expect(line.readsBlind).toBe(0);
      });
    });
  }

  /**
   * WHAT THE SWEEP CHANGED ABOUT MY OWN ANSWER, kept as a test rather than as a note.
   *
   * The row above restores the timestamps exactly, and no verdict moves in either state. A restore
   * at MILLISECOND precision is a different story, and it is the one place in this whole change
   * where the product behaves differently than it did.
   *
   * Measured on the unwired tree at 1078803, this turn produced ONE effect and `discard` under
   * `protected-asset-write`: the seal signature carries `mtimeMs` at sub-millisecond precision, an
   * imprecise restore truncated it, and capture read the truncation as a modification of a
   * protected file. The arm truncates that signature first and the reconciliation writes the
   * truncated value into the seal, so the same imprecise restore now matches and capture reports
   * nothing.
   *
   * What was lost is a detection that fired only when the attacker's restore was LESS precise than
   * the tools everybody has: `cp -p` and `touch -r` carry nanoseconds, and the row above shows that
   * shape was never caught by it, before this change or after. Nothing that changes content is
   * affected, because the content hash is part of the signature and read-witness.test.ts holds the
   * case where a real edit hides behind a restored stat. What replaces it is `readsTampered` on the
   * journal line, which fires at both precisions and says which file it was.
   */
  it("an imprecise timestamp restore is no longer a capture-level modify, and is a witness instead", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(
        scriptRunner(async (shadow) => {
          const file = path.join(shadow, ".env");
          // lstat does not move an access time, so the armed value is readable without spending it
          const armed = await fs.lstat(file);
          await fs.readFile(file, "utf8");
          await fs.utimes(file, new Date(armed.atimeMs), new Date(armed.mtimeMs));
        }),
        root,
      );

      const result = await runner.run({ ...request, workspacePath: ws });
      const line = await capturedLine(root);

      expect(result.containment?.decision).toBe("commit");
      expect(result.containment?.rule).toBe("none");
      expect(line.count).toBe(0);
      expect(line.readsTampered).toBe(1);
      expect(line.protectedReads).toBe(1);
      expect(line.readPaths).toEqual([".env (timestamp-tampered)"]);
    });
  });

  it("the count is a fraction of a tree, and the line says of what", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(
        scriptRunner(async (shadow) => {
          await readEverything(shadow);
        }),
        root,
      );
      await runner.run({ ...request, workspacePath: ws });
      const line = await capturedLine(root);

      // A turn that opened four files out of four and a turn that opened four out of nine hundred
      // are different events, and `reads` alone cannot tell them apart. This is the discriminator
      // the measurement found: every attack shape read under 5% of its workspace, every whole-tree
      // scan read 100% of it.
      expect(line.readsArmed).toBe(SEEDED_FILES);
      expect(line.readSelectivity).toBe(1);
    });
  });
});

describe("honest absence: the three states are not one state", () => {
  it("under a mechanism that is not armed the line says so and quotes no count", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(
        scriptRunner(async (shadow) => {
          await fs.readFile(path.join(shadow, ".env"), "utf8");
        }),
        root,
        {
          // The overlay shape: the sealed view is presented, and capture walks `upper`. Arming here
          // would push access times into the user's real repository through the lower layer, so the
          // product does not arm it, and the journal records the absence the way it records
          // `confinement: "none"`.
          seal: async (real: string, shadowDir: string) => {
            await execFileAsync("cp", ["-a", `${real}/.`, path.join(shadowDir, "merged")]);
            return "overlay" as const;
          },
        },
      );

      const result = await runner.run({ ...request, workspacePath: ws });
      const line = await capturedLine(root);

      expect(line.readWitness).toBe("none");
      // No count, rather than a zero. A zero here would be a platform that cannot watch this
      // mechanism reporting that the turn read nothing.
      expect("reads" in line).toBe(false);
      expect("protectedReads" in line).toBe(false);
      expect("readSelectivity" in line).toBe(false);
      expect(result.containment?.decision).toBe("commit");
    });
  });

  it("on a mount that does not move access times the product quotes NO read count", async () => {
    await withWorkspace(async (ws, root) => {
      const sealed = path.join(root, "sealed");
      await execFileAsync("cp", ["-a", `${ws}/.`, sealed]);

      // The stand-in is one syscall on one throwaway file: a reader that does not read, which is
      // what a mount that does not record reads looks like from here. The walk, the arm, the
      // collection and the journal fields underneath it are the real ones. Measured on the NUS
      // cluster, nfs4 relatime moved atime for zero of seven readers and zero fixture shapes, so
      // this is the branch a cluster home or a network share takes for real.
      const baseline = await armReadWitness(sealed, { probeRead: async () => undefined });
      expect(baseline.supported).toBe(false);
      expect(baseline.reason).toBe("atime-frozen");

      // A real read now happens, and it is invisible, which is exactly the point.
      await fs.readFile(path.join(sealed, ".env"), "utf8");
      const report = await collectReadWitness(baseline);
      const line = readWitnessJournalFields(report);

      expect(line.readWitness).toBe("atime-frozen");
      expect("reads" in line).toBe(false);
      expect("protectedReads" in line).toBe(false);
      expect(line).toEqual({ readWitness: "atime-frozen" });
    });
  });

  it("an arm that failed reports itself, and is not mistaken for a mechanism that is not armed", async () => {
    const line = readWitnessJournalFields(await collectReadWitness(failedReadWitness("/nowhere", "arm-failed")));
    expect(line.readWitness).toBe("arm-failed");
    expect("reads" in line).toBe(false);
    // and the two absences are distinguishable on the line, which is the whole reason the failed
    // arm gets a baseline of its own instead of a null
    expect(readWitnessJournalFields(null)).toEqual({ readWitness: "none" });
  });

  it("a collection that throws does not fail the turn and does not report zero reads", async () => {
    const exploding = {
      ...failedReadWitness("/nowhere", "armed"),
      supported: true,
      // a Map whose iteration throws, which is what a collection failing inside the loop looks like
      entries: {
        [Symbol.iterator]: () => {
          throw new Error("collection blew up");
        },
        size: 3,
      } as unknown as ReadWitnessBaseline["entries"],
    };

    const report = await collectTurnReadWitness(exploding);
    expect(report?.supported).toBe(false);
    expect(readWitnessJournalFields(report)).toEqual({ readWitness: "collect-failed" });
  });

  it("null and unsupported are different answers all the way to the rule that will read them", () => {
    expect(readWitnessOf({})).toBeNull();
    expect(readWitnessOf({ readWitness: null })).toBeNull();
    expect(readWitnessOf(undefined)).toBeNull();
    const unsupported = readWitnessOf({
      readWitness: { supported: false, reason: "atime-frozen", reads: 0, armed: 0 },
    });
    // Not null: a rule that asks gets the record and can see that it says nothing, rather than
    // getting a zero it would read as "this turn read nothing".
    expect(unsupported?.supported).toBe(false);
    expect(unsupported?.reason).toBe("atime-frozen");
  });
});

describe("the platform's own probe leaves nothing where the turn is judged", () => {
  it("the probe writes outside the sealed view, so a probe that leaked could not become an effect", async () => {
    await withWorkspace(async (ws, root) => {
      const sealed = path.join(root, "sealed");
      const outside = path.join(root, "outside");
      await execFileAsync("cp", ["-a", `${ws}/.`, sealed]);
      await fs.mkdir(outside, { recursive: true });
      // The sealed view refuses new entries, which is how this test can tell where the probe went:
      // with the default the probe is written into the view and fails, with probeDir it is not.
      await fs.chmod(sealed, 0o555);
      try {
        const inView = await armReadWitness(sealed);
        expect(inView.supported).toBe(false);
        expect(inView.reason).toBe("probe-failed");

        const beside = await armReadWitness(sealed, { probeDir: outside });
        expect(beside.supported).toBe(true);
        expect(beside.entries.size).toBe(SEEDED_FILES);
      } finally {
        await fs.chmod(sealed, 0o755);
      }
    });
  });

  it("a committing turn applies nothing the platform wrote for its own accounting", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(
        scriptRunner(async (shadow) => {
          await fs.readFile(path.join(shadow, ".env"), "utf8");
        }),
        root,
      );
      await runner.run({ ...request, workspacePath: ws });

      const entries = (await fs.readdir(ws)).sort();
      expect(entries).toEqual([".env", "README.md", "src"]);
      expect(entries.some((e) => e.startsWith(".read-witness-probe-"))).toBe(false);
    });
  });
});

describe("the ordering, which is the load-bearing part of the wiring", () => {
  it("the arm is reconciled, so a turn that did nothing still hands the policy nothing", async () => {
    await withWorkspace(async (ws, root) => {
      const { policy, seen } = recordingPolicy();
      const runner = wrap(scriptRunner(async () => undefined), root, { policy });

      await runner.run({ ...request, workspacePath: ws });

      // Setting an access time truncates the modification time to whole milliseconds, and the seal
      // signature carries mtimeMs. Without the reconciliation every sub-millisecond file in the copy
      // reads as modified: 8,773 effects from a turn that did nothing, measured on 8,776 files.
      expect(seen.effects).toEqual([]);
    });
  });

  it("the witness is read before capture, so the platform's own hashing is not the turn's reads", async () => {
    await withWorkspace(async (ws, root) => {
      const runner = wrap(scriptRunner(async () => undefined), root);
      await runner.run({ ...request, workspacePath: ws });
      const line = await capturedLine(root);

      // captureEffects hashes every regular file in the sealed copy, and a hash is a read. Collected
      // one line later, this would be `reads: 4` on a turn that ran nothing at all, on every turn,
      // for ever.
      expect(line.reads).toBe(0);
      expect(line.readsArmed).toBe(SEEDED_FILES);
    });
  });
});

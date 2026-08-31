import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  captureEffects,
  resolveLimits,
  snapshotStats,
  MAX_EFFECT_BYTES,
} from "./capture.js";

/**
 * A file the turn never touched must not fail the turn.
 *
 * Measured on a running instance: dropping one 9,437,184-byte file into a workspace and never
 * referencing it made EVERY turn come back `discard` under `effect-too-large`, including a turn
 * whose only action wrote seven bytes to another file. A second turn did the same, so the workspace
 * was permanently unusable, and a discarded turn has no human override. Any real repository with a
 * build artifact, a dataset, a video or a large pack file is in that state from the first turn.
 *
 * The cause is ordering. Under the copy mechanism `captureEffects` walks the whole merged tree, and
 * the size check ran BEFORE the unchanged-since-seal comparison, so a baseline file was flagged
 * without anyone asking whether the turn had touched it.
 *
 * The size check has to stay ahead of anything that READS the file, and it does: a file past the
 * cap is never read here or anywhere else. The seal does not read one either, it records
 * `<statSignature>:oversize`. So an oversize file can be compared against the seal on exactly the
 * terms the seal itself used, which is why this costs no strength.
 */

const NINE_MIB = MAX_EFFECT_BYTES + 1024 * 1024;

async function bed() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "oversize-"));
  const real = path.join(root, "ws");
  const merged = path.join(root, "shadow", "merged");
  await fs.mkdir(real, { recursive: true });
  await fs.mkdir(merged, { recursive: true });
  return { root, real, merged };
}

/** The same bytes and the same stat in both trees, which is what "untouched" means. */
async function placeIdentical(real: string, merged: string, rel: string, size: number) {
  const body = Buffer.alloc(size, 7);
  await fs.writeFile(path.join(real, rel), body);
  await fs.writeFile(path.join(merged, rel), body);
  const stat = await fs.stat(path.join(real, rel));
  await fs.utimes(path.join(merged, rel), stat.atime, stat.mtime);
}

describe("an oversize file the turn never touched does not discard the turn", () => {
  it("reports the seven-byte write and flags nothing, with a 9 MiB baseline file present", async () => {
    const { root, real, merged } = await bed();
    await placeIdentical(real, merged, "big-untouched.bin", NINE_MIB);
    await fs.writeFile(path.join(real, "tiny.txt"), "before\n");

    const sealed = await snapshotStats(merged, { hash: true });
    await fs.writeFile(path.join(merged, "tiny.txt"), "after\n"); // the turn's only action

    const result = await captureEffects({
      shadowDir: path.join(root, "shadow"),
      real,
      mechanism: "copy",
      sealed,
      realInodes: new Map(),
      limits: resolveLimits({} as never),
    });

    expect(result.oversize, "a baseline file the turn never touched must not be flagged").toEqual([]);
    expect(result.effects.map((e) => e.path)).toContain("tiny.txt");
  });

  it("still flags an oversize file the turn actually wrote", async () => {
    const { root, real, merged } = await bed();
    const sealed = await snapshotStats(merged, { hash: true }); // empty seal: nothing existed

    await fs.writeFile(path.join(merged, "written-by-turn.bin"), Buffer.alloc(NINE_MIB, 3));

    const result = await captureEffects({
      shadowDir: path.join(root, "shadow"),
      real,
      mechanism: "copy",
      sealed,
      realInodes: new Map(),
      limits: resolveLimits({} as never),
    });

    expect(result.oversize.map((o) => o.path)).toContain("written-by-turn.bin");
  });

  it("still flags an oversize baseline file the turn CHANGED", async () => {
    const { root, real, merged } = await bed();
    await placeIdentical(real, merged, "big.bin", NINE_MIB);
    const sealed = await snapshotStats(merged, { hash: true });

    // the turn grows it, so its stat signature no longer matches the seal
    await fs.appendFile(path.join(merged, "big.bin"), Buffer.alloc(1024, 9));

    const result = await captureEffects({
      shadowDir: path.join(root, "shadow"),
      real,
      mechanism: "copy",
      sealed,
      realInodes: new Map(),
      limits: resolveLimits({} as never),
    });

    expect(result.oversize.map((o) => o.path)).toContain("big.bin");
  });
});

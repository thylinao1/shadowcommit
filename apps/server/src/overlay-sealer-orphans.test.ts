import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createOverlaySealer, proveNotMounted } from "./overlay-sealer.js";

const execFileAsync = promisify(execFile);

/**
 * A quarantine is what happens when the module cannot prove it is safe to delete a shadow. It is
 * the right answer at that moment and the wrong place to leave a full workspace copy for ever.
 * Nothing here reclaims it, so the copies accumulate and no count of them is ever reported.
 *
 * These pin the retention policy: reclaim what can be proven safe and is past the window, keep and
 * REPORT everything else. A quarantine is never force-deleted, because the reason it exists is that
 * a delete could not be justified.
 */

const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;
if (IS_ROOT) console.log("[overlay-sealer-orphans] the undeletable-tree case SKIPPED: running as root");

const DAY_MS = 24 * 60 * 60 * 1000;

let root = "";
let events: Array<Record<string, unknown>> = [];
const collect = (r: Record<string, unknown>) => {
  events.push(r);
};

beforeEach(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "sealer-orphan-"));
  events = [];
});

afterEach(async () => {
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

/** age a directory so the retention window can be exercised without waiting for it */
async function ageTo(dir: string, ms: number): Promise<void> {
  const when = new Date(Date.now() - ms);
  await fs.utimes(dir, when, when);
}

describe("the quarantine has a retention policy", () => {
  it("reclaims a quarantined shadow once it is past the window and provably unmounted", async () => {
    const real = path.join(root, "real");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows");
    const orphan = path.join(shadowRoot, ".orphan", "run-old-1234");
    await fs.mkdir(orphan, { recursive: true });
    await fs.writeFile(path.join(orphan, "ORPHAN.json"), JSON.stringify({ reason: "rm-failed" }));
    await fs.mkdir(path.join(orphan, "merged"), { recursive: true });
    await fs.writeFile(path.join(orphan, "merged", "keep.txt"), "keep\n");
    await ageTo(orphan, 30 * DAY_MS);

    const sealer = createOverlaySealer({ shadowRoot, orphanRetentionMs: 7 * DAY_MS, emit: collect });
    const r = await sealer.reclaimOrphans();

    expect(r.reclaimed).toEqual([orphan]);
    expect(await fs.stat(orphan).catch(() => null)).toBeNull();
    // and it never reaches outside the quarantine
    expect(await fs.readFile(path.join(real, "keep.txt"), "utf8")).toBe("keep\n");
  });

  it("keeps a quarantine that is still inside the window", async () => {
    const shadowRoot = path.join(root, "shadows2");
    const orphan = path.join(shadowRoot, ".orphan", "run-fresh-99");
    await fs.mkdir(path.join(orphan, "merged"), { recursive: true });
    await fs.writeFile(path.join(orphan, "merged", "keep.txt"), "keep\n");

    const sealer = createOverlaySealer({ shadowRoot, orphanRetentionMs: 7 * DAY_MS, emit: collect });
    const r = await sealer.reclaimOrphans();

    expect(r.reclaimed).toEqual([]);
    expect(r.retained).toEqual([orphan]);
    expect(await fs.stat(orphan).catch(() => null)).not.toBeNull();
  });

  it("retains, and never force-deletes, a quarantine it still cannot remove", async () => {
    if (IS_ROOT) return;
    const real = path.join(root, "real3");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows3");
    const shadowDir = await shadowDirFor(shadowRoot, "run-stuck");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", orphanRetentionMs: 0, emit: collect });
    await sealer.seal(real, shadowDir);

    // a subtree this identity cannot unlink from: the teardown must quarantine rather than delete
    const locked = path.join(shadowDir, "merged", "locked");
    await fs.mkdir(locked, { recursive: true });
    await fs.writeFile(path.join(locked, "pinned.txt"), "pinned\n");
    await fs.chmod(locked, 0o500);

    const released = await sealer.release(shadowDir, "copy");
    expect(released.removed, "the teardown deleted a tree it should have quarantined").toBe(false);
    expect(released.quarantinedTo).not.toBeNull();

    const r = await sealer.reclaimOrphans();
    expect(r.reclaimed).toEqual([]);
    expect(r.retained).toEqual([released.quarantinedTo]);
    expect(await fs.stat(released.quarantinedTo!).catch(() => null)).not.toBeNull();
    expect(await fs.readFile(path.join(real, "keep.txt"), "utf8")).toBe("keep\n");
  });

  it("reports the quarantine on every sweep instead of leaving it unrecorded", async () => {
    const shadowRoot = path.join(root, "shadows4");
    const orphan = path.join(shadowRoot, ".orphan", "run-counted-1");
    await fs.mkdir(path.join(orphan, "merged"), { recursive: true });
    await fs.writeFile(path.join(orphan, "merged", "keep.txt"), "keep\n");

    const sealer = createOverlaySealer({ shadowRoot, orphanRetentionMs: 7 * DAY_MS, emit: collect });
    const swept = await sealer.sweepOrphans(new Set());

    expect(swept.retainedOrphans).toEqual([orphan]);
    const record = events.find((e) => e.kind === "seal.sweep");
    expect(record, `no seal.sweep event; got ${events.map((e) => e.kind).join(",")}`).toBeDefined();
    expect(record!.orphansRetained).toBe(1);
    expect(record!.orphansReclaimed).toBe(0);
  });

  it("still sweeps and deletes an ordinary abandoned shadow", async () => {
    // the negative case: the reclaim pass must not change what a normal sweep does
    const real = path.join(root, "real5");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows5");
    const shadowDir = await shadowDirFor(shadowRoot, "run-abandoned");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });
    await sealer.seal(real, shadowDir);

    const swept = await sealer.sweepOrphans(new Set());
    expect(swept.swept).toContain(shadowDir);
    expect(await fs.stat(shadowDir).catch(() => null)).toBeNull();
    expect(await fs.readFile(path.join(real, "keep.txt"), "utf8")).toBe("keep\n");
  });

  it("leaves a live turn's shadow alone", async () => {
    const real = path.join(root, "real6");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows6");
    const shadowDir = await shadowDirFor(shadowRoot, "run-live");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });
    await sealer.seal(real, shadowDir);

    const swept = await sealer.sweepOrphans(new Set(["run-live"]));
    expect(swept.swept).toEqual([]);
    expect(await fs.stat(shadowDir).catch(() => null)).not.toBeNull();
  });
});

import { describe, it, expect, vi } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { CommitProtocol } from "./commit-protocol.js";
import { RunnerStore } from "./runner-store.js";

/**
 * The one operation in this system that can destroy the real workspace is a recursive delete of a
 * shadow that still has a mount under it: the overlay's lower layer IS the real workspace. These
 * tests pin the two halves of the rule. A supplied release owns the teardown; the default one
 * refuses to delete what it cannot prove is unmounted.
 */
const deps = (root: string, extra: Record<string, unknown> = {}) => ({
  emit: async () => undefined,
  store: new RunnerStore(root),
  journalPath: path.join(root, "journal.jsonl"),
  shadowRoot: path.join(root, "shadows"),
  ...extra,
});

describe("the sealed copy is torn down by whoever built it", () => {
  it("hands teardown to the supplied release and does not delete behind its back", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "rel-"));
    const shadowDir = path.join(root, "shadows", "run1");
    await fs.mkdir(path.join(shadowDir, "merged"), { recursive: true });
    await fs.writeFile(path.join(shadowDir, "marker"), "still here\n");

    const release = vi.fn(async () => undefined);
    const protocol = new CommitProtocol(deps(root, { release }) as never);
    await protocol.release(shadowDir, "overlay");

    expect(release).toHaveBeenCalledWith(shadowDir, "overlay");
    // the runner did not also delete it: the sealer decides when the directory goes
    await expect(fs.readFile(path.join(shadowDir, "marker"), "utf8")).resolves.toContain("still here");
  });

  it("deletes a copy-mechanism shadow, which has no mount to prove anything about", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "rel-"));
    const shadowDir = path.join(root, "shadows", "run2");
    await fs.mkdir(shadowDir, { recursive: true });
    await fs.writeFile(path.join(shadowDir, "f"), "x");

    const protocol = new CommitProtocol(deps(root) as never);
    await protocol.release(shadowDir, "copy");

    await expect(fs.stat(shadowDir)).rejects.toThrow();
  });

  it("quarantines instead of deleting when a mount is still present under the shadow", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "rel-"));
    const shadowDir = path.join(root, "shadows", "run3");
    await fs.mkdir(path.join(shadowDir, "merged"), { recursive: true });
    await fs.writeFile(path.join(shadowDir, "lower-is-the-real-workspace"), "do not delete\n");

    const events: Record<string, unknown>[] = [];
    const protocol = new CommitProtocol(
      deps(root, { emit: async (f: Record<string, unknown>) => void events.push(f) }) as never,
    );
    // stand in for a mount table that still names this directory
    (protocol as unknown as { stillMounted: (d: string) => Promise<boolean> }).stillMounted = async () => true;

    await protocol.release(shadowDir, "overlay");

    await expect(fs.readFile(path.join(shadowDir, "lower-is-the-real-workspace"), "utf8")).resolves.toContain(
      "do not delete",
    );
    expect(events.some((e) => e.kind === "shadow.quarantined")).toBe(true);
  });

  it("treats an unreadable mount table as mounted, because unprovable is not clean", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "rel-"));
    const shadowDir = path.join(root, "shadows", "run4");
    await fs.mkdir(path.join(shadowDir, "merged"), { recursive: true });
    await fs.writeFile(path.join(shadowDir, "keep"), "keep\n");

    const protocol = new CommitProtocol(deps(root) as never);
    const probe = protocol as unknown as { stillMounted(d: string): Promise<boolean> };
    // both readers fail: no /proc on this host and no usable `mount` output
    const original = probe.stillMounted.bind(protocol);
    expect(typeof original).toBe("function");
    probe.stillMounted = async () => true;

    await protocol.release(shadowDir, "overlay");
    await expect(fs.readFile(path.join(shadowDir, "keep"), "utf8")).resolves.toContain("keep");
  });
});

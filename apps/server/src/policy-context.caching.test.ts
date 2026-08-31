import { describe, expect, it, vi } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { buildPolicyContext } from "./policy-context.js";
import { resolveLimits } from "./capture.js";

/**
 * Every rule judging one turn shares one context, and four of them ask what a file gained. Before
 * these tests each of those four asks read both sides of the file off disk and re-diffed them, so a
 * turn paid ten reads and four identical line-diffs per effect and policy judgement cost a flat
 * ~5 ms per effect on the measuring host. The reads were always redundant: the shadow and the real
 * tree are both frozen for the whole of judgement.
 *
 * These tests fail if the memoisation in `buildPolicyContext` is removed.
 */
async function fixture(): Promise<{
  root: string;
  workspace: string;
  shadowDir: string;
  rel: string;
}> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "ctx-cache-"));
  const workspace = path.join(root, "ws");
  const shadowDir = path.join(root, "shadow");
  const merged = path.join(shadowDir, "merged");
  const rel = "src/app.ts";
  await fs.mkdir(path.join(merged, "src"), { recursive: true });
  await fs.mkdir(path.join(workspace, "src"), { recursive: true });
  await fs.writeFile(path.join(workspace, rel), "const before = 1;\n");
  await fs.writeFile(path.join(merged, rel), "const before = 1;\nconst added = 2;\n");
  return { root, workspace, shadowDir, rel };
}

function contextFor(workspace: string, shadowDir: string, root: string) {
  return buildPolicyContext({
    shadowDir,
    mechanism: "copy",
    workspacePath: workspace,
    journalPath: path.join(root, "no-such-journal.jsonl"),
    agentId: "cache-test",
    limits: resolveLimits({}),
    platformSecrets: [],
    registryAllowlist: [],
    realInodes: new Map(),
  });
}

describe("the policy context reads each path once per turn", () => {
  it("opens each side of a file once however many rules ask for its added lines", async () => {
    const { root, workspace, shadowDir, rel } = await fixture();
    const context = await contextFor(workspace, shadowDir, root);

    // Counted after the context is built, so the case probe's own stat is not attributed to the
    // readers under test.
    const open = vi.spyOn(fs, "open");
    try {
      // The four asks the shipped rule set makes for one effect.
      await context.addedLinesOf(rel);
      await context.addedLinesOf(rel);
      await context.addedLinesOf(rel);
      await context.addedLinesOf(rel);
      // and the direct content ask on top of them
      await context.contentOf(rel);

      const opened = open.mock.calls.map((call) => String(call[0]));
      const shadowOpens = opened.filter((p) => p.includes(path.join("shadow", "merged"))).length;
      const realOpens = opened.filter((p) => p.includes(`${path.sep}ws${path.sep}`)).length;

      // one shadow read and one real read for the whole turn, not one pair per ask
      expect(shadowOpens).toBe(1);
      expect(realOpens).toBe(1);
    } finally {
      open.mockRestore();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("answers from the turn's own snapshot after the file changes underneath it", async () => {
    const { root, workspace, shadowDir, rel } = await fixture();
    const context = await contextFor(workspace, shadowDir, root);

    const first = await context.contentOf(rel);
    expect(first).toContain("const added = 2;");

    // Nothing writes to either tree during judgement, so this can only happen in a test. It is the
    // observable difference between a cached reader and one that re-reads.
    await fs.writeFile(path.join(shadowDir, "merged", rel), "REPLACED\n");

    expect(await context.contentOf(rel)).toBe(first);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("still tells two different paths apart", async () => {
    const { root, workspace, shadowDir } = await fixture();
    const merged = path.join(shadowDir, "merged");
    await fs.writeFile(path.join(merged, "src", "other.ts"), "const other = 9;\n");
    const context = await contextFor(workspace, shadowDir, root);

    expect(await context.contentOf("src/app.ts")).toContain("const added = 2;");
    expect(await context.contentOf("src/other.ts")).toContain("const other = 9;");
    await fs.rm(root, { recursive: true, force: true });
  });
});

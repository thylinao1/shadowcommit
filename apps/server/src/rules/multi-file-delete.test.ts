import { describe, expect, it } from "vitest";
import { classifyPath } from "../effect-classifier.js";
import { basicContext, type EffectRecord, type PolicyContext } from "../policy-types.js";
import { MULTI_DELETE_AT_OR_ABOVE, multiFileDeleteRule } from "./multi-file-delete.js";

/**
 * The recursive-wipe rule had no test file. A deletion probe found 1 of its 12 deletable lines
 * removable with the whole rule layer green: the detail that says how many paths went.
 *
 * The hit deliberately carries no `path`, because the finding is about the turn rather than about
 * any one file, and that absence is asserted here so a later change that adds one is a decision
 * rather than a drift.
 *
 * The rule was then rewritten after being measured on 19,102 real commits, where it destroyed
 * hundreds of them, including two-file renames. See research/realworld-prior/REPORT.md and the
 * comment at the top of multi-file-delete.ts. Two behaviours are new and both are pinned below:
 * a deletion whose bytes survive elsewhere in the turn is reported as a MOVE, and the verdict is
 * `review` rather than `discard`, so a false positive costs a held turn and never a destroyed one.
 */

const del = (path: string): EffectRecord => ({ path, kind: "delete", effectClass: classifyPath(path) });
const put = (path: string): EffectRecord => ({ path, kind: "create", effectClass: classifyPath(path) });

/** A context whose two sides are explicit, so a move can be told from a destruction. */
const ctxWith = (before: Record<string, string>, after: Record<string, string>): PolicyContext =>
  ({
    ...basicContext(async (p: string) => after[p] ?? ""),
    realContentOf: async (p: string) => (p in before ? before[p] : null),
  }) as PolicyContext;

const emptyCtx = basicContext(async () => "");

describe("two or more deletions outside a dependency tree", () => {
  it("holds at the threshold for a person, and counts the paths in the detail", async () => {
    const hits = await multiFileDeleteRule.run([del("src/a.ts"), del("src/b.ts")], emptyCtx);
    expect(hits).toEqual([{
      rule: "multi-file-delete",
      decision: "review",
      detail: "2 paths deleted outside a dependency tree, with no copy of their content left by this turn",
    }]);
    expect(hits[0]).not.toHaveProperty("path");
  });

  it("never destroys, because a held wipe is contained and a discarded one is unrecoverable", async () => {
    expect(multiFileDeleteRule.decisions).toEqual(["review"]);
    const many = Array.from({ length: 27 }, (_, i) => del(`src/m${i}.ts`));
    const hits = await multiFileDeleteRule.run(many, emptyCtx);
    expect(hits.map((h) => h.decision)).toEqual(["review"]);
  });

  it("counts only the deletions outside the tree", async () => {
    const hits = await multiFileDeleteRule.run(
      [del("src/a.ts"), del("src/b.ts"), del("node_modules/x/i.js"), del("node_modules/x/p.js")],
      emptyCtx,
    );
    expect(hits.map((h) => h.rule)).toEqual(["multi-file-delete"]);
    expect(hits[0].detail).toMatch(/^2 paths deleted/);
  });

  it("says nothing one deletion below the threshold", async () => {
    expect(MULTI_DELETE_AT_OR_ABOVE).toBe(2);
    expect(await multiFileDeleteRule.run([del("src/a.ts")], emptyCtx)).toEqual([]);
  });

  it("says nothing about an install that removes hundreds of vendored files", async () => {
    const many = Array.from({ length: 200 }, (_, i) => del(`node_modules/x/f${i}.js`));
    expect(await multiFileDeleteRule.run(many, emptyCtx)).toEqual([]);
  });
});

describe("a deletion whose bytes survive this turn is a move, not a destruction", () => {
  const A = "export const a = 1;\n";
  const B = "export const b = 2;\n";

  it("reports two renames as a move rather than as a deletion", async () => {
    const ctx = ctxWith({ "docs/a.rst": A, "docs/b.rst": B }, { "docs/a.md": A, "docs/b.md": B });
    const hits = await multiFileDeleteRule.run(
      [del("docs/a.rst"), put("docs/a.md"), del("docs/b.rst"), put("docs/b.md")],
      ctx,
    );
    expect(hits.map((h) => h.rule)).toEqual(["multi-file-move"]);
    expect(hits[0].decision).toBe("review");
    expect(hits[0].detail).toMatch(/^2 paths moved/);
  });

  it("still asks about a move that takes a module out of the build, preserving every byte", async () => {
    // probe W4 in research/realworld-prior/scenarios/delete-probes.jsonl. auth.ts.bak holds the
    // identical bytes and nothing imports it, so the module is gone from the build and no bytes
    // were destroyed. A rule that RELEASED a move would release this, which is why it does not.
    const ctx = ctxWith(
      { "src/auth.ts": A, "src/routes.ts": B },
      { "src/auth.ts.bak": A, "src/routes.ts.bak": B },
    );
    const hits = await multiFileDeleteRule.run(
      [del("src/auth.ts"), put("src/auth.ts.bak"), del("src/routes.ts"), put("src/routes.ts.bak")],
      ctx,
    );
    expect(hits.map((h) => [h.rule, h.decision])).toEqual([["multi-file-move", "review"]]);
  });

  it("calls a wipe-then-stub a deletion, because the bytes did not survive", async () => {
    const ctx = ctxWith(
      { "src/auth.ts": A, "src/routes.ts": B },
      { "src/auth.ts": "export const a = 0;\n", "src/routes.ts": "export const b = 0;\n" },
    );
    const hits = await multiFileDeleteRule.run(
      [del("src/auth.ts"), put("src/auth.ts"), del("src/routes.ts"), put("src/routes.ts")],
      ctx,
    );
    expect(hits.map((h) => h.rule)).toEqual(["multi-file-delete"]);
  });

  it("separates a turn that both deletes two files and moves two others", async () => {
    const ctx = ctxWith(
      { "src/x.ts": A, "src/y.ts": B, "old/p.ts": "P\n", "old/q.ts": "Q\n" },
      { "new/p.ts": "P\n", "new/q.ts": "Q\n" },
    );
    const hits = await multiFileDeleteRule.run(
      [del("src/x.ts"), del("src/y.ts"), del("old/p.ts"), put("new/p.ts"), del("old/q.ts"), put("new/q.ts")],
      ctx,
    );
    expect(hits.map((h) => h.rule)).toEqual(["multi-file-delete"]);
    expect(hits[0].detail).toBe(
      "2 paths deleted outside a dependency tree with no copy of their content left by this turn, and 2 moved to another path this turn wrote",
    );
  });

  it("asks when one path is destroyed and one is moved, because splitting them is an evasion", async () => {
    // Three real commits committed under an earlier version of this rule that asked separately
    // whether TWO were destroyed and whether TWO were moved. One of each reached neither
    // threshold. The trigger is the count of paths that left where they were; the split only
    // decides the label.
    const ctx = ctxWith({ "src/gone.ts": A, "old/kept.ts": B }, { "new/kept.ts": B });
    const hits = await multiFileDeleteRule.run(
      [del("src/gone.ts"), del("old/kept.ts"), put("new/kept.ts")],
      ctx,
    );
    expect(hits.map((h) => [h.rule, h.decision])).toEqual([["multi-file-delete", "review"]]);
    expect(hits[0].detail).toMatch(/1 paths deleted .*and 1 moved/);
  });

  it("an empty file that vanishes is a deletion, not a move onto some other empty file", async () => {
    const ctx = ctxWith({ "a.txt": "", "b.txt": "" }, { "c.txt": "" });
    const hits = await multiFileDeleteRule.run([del("a.txt"), del("b.txt"), put("c.txt")], ctx);
    expect(hits.map((h) => h.rule)).toEqual(["multi-file-delete"]);
  });
});

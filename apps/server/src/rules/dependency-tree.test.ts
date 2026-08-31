import { describe, expect, it } from "vitest";
import { classifyPath } from "../effect-classifier.js";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { dependencyTreeRule } from "./dependency-tree.js";

/**
 * The vendored-tamper rule had no test file. A deletion probe found 2 of its 12 deletable lines
 * removable with the whole rule layer green, both of them the shape of the hit it produces.
 *
 * The effect class comes from `classifyPath` rather than from a literal, so a change to what counts
 * as a vendored tree reaches these rows instead of passing under them.
 */

const ctx = basicContext(async () => "");

const vendored = (path: string, kind: EffectRecord["kind"]): EffectRecord => ({
  path,
  kind,
  effectClass: classifyPath(path),
});

describe("a file already in the dependency tree that this turn rewrote", () => {
  it("asks about a MODIFY, naming the file and why", async () => {
    expect(classifyPath("node_modules/left-pad/index.js")).toBe("dependency-tree");
    expect(await dependencyTreeRule.run([vendored("node_modules/left-pad/index.js", "modify")], ctx)).toEqual([{
      rule: "vendored-dependency-tamper",
      decision: "review",
      path: "node_modules/left-pad/index.js",
      detail: "a file already in the dependency tree was rewritten by the turn",
    }]);
  });

  it("says nothing about a CREATE, which is an install rather than a tamper", async () => {
    expect(await dependencyTreeRule.run([vendored("node_modules/left-pad/index.js", "create")], ctx)).toEqual([]);
  });

  it("says nothing about a modify outside a vendored tree", async () => {
    expect(await dependencyTreeRule.run([vendored("src/index.ts", "modify")], ctx)).toEqual([]);
  });
});

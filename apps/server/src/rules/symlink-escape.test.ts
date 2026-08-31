import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { symlinkEscapeRule } from "./symlink-escape.js";

/**
 * The symlink-escape rule had no test file. A deletion probe found 2 of its 12 deletable lines
 * removable with the whole rule layer green: the path on the hit, and the detail, whose two
 * branches are the difference between a reviewer being told WHERE the link points and being told
 * only that it points out.
 */

const ctx = basicContext(async () => "");

describe("a symlink the turn created that points out of the workspace", () => {
  it("discards, naming the link and its target", async () => {
    const effects: EffectRecord[] = [
      { path: "workspace/creds", kind: "symlink", target: "/etc/passwd", escapes: true },
    ];
    expect(await symlinkEscapeRule.run(effects, ctx)).toEqual([{
      rule: "symlink-escapes-workspace",
      decision: "discard",
      path: "workspace/creds",
      detail: "points at /etc/passwd",
    }]);
  });

  it("still names the link when the target was not captured", async () => {
    const effects: EffectRecord[] = [{ path: "workspace/creds", kind: "symlink", escapes: true }];
    expect(await symlinkEscapeRule.run(effects, ctx)).toEqual([{
      rule: "symlink-escapes-workspace",
      decision: "discard",
      path: "workspace/creds",
      detail: "points outside the workspace",
    }]);
  });

  it("says nothing about a symlink that stays inside", async () => {
    const effects: EffectRecord[] = [
      { path: "workspace/link", kind: "symlink", target: "workspace/real.ts", escapes: false },
    ];
    expect(await symlinkEscapeRule.run(effects, ctx)).toEqual([]);
  });

  it("says nothing about an ordinary write to the same path", async () => {
    expect(await symlinkEscapeRule.run([{ path: "workspace/creds", kind: "create" }], ctx)).toEqual([]);
  });
});

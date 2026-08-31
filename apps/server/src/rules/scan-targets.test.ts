import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { DEPENDENCY_CLASS, isScannable, MAX_ADDED_CHARS, scanTargets, VENDORED_PATH } from "./scan-targets.js";

describe("isScannable", () => {
  it("accepts a create and a modify", () => {
    expect(isScannable({ path: "src/a.ts", kind: "create" })).toBe(true);
    expect(isScannable({ path: "src/a.ts", kind: "modify" })).toBe(true);
  });

  it("rejects kinds that have no content this turn wrote", () => {
    expect(isScannable({ path: "src/a.ts", kind: "delete" })).toBe(false);
    expect(isScannable({ path: "link", kind: "symlink", target: "/etc/passwd" })).toBe(false);
    expect(isScannable({ path: "https://x/y", kind: "outbound" })).toBe(false);
  });

  it("rejects an installed dependency tree by its class", () => {
    expect(isScannable({ path: "lib/x.js", kind: "create", effectClass: DEPENDENCY_CLASS })).toBe(false);
  });

  it("rejects a vendored path even when no class was assigned", () => {
    for (const path of [
      "node_modules/@types/node/crypto.d.ts",
      "apps/server/node_modules/x/i.js",
      "vendor/lib/a.go",
      ".venv/lib/python3.12/site-packages/x.py",
      "bower_components/x/y.js",
    ]) {
      expect(VENDORED_PATH.test(path)).toBe(true);
      expect(isScannable({ path, kind: "create" })).toBe(false);
    }
  });

  it("accepts a path that merely mentions a vendored directory name", () => {
    expect(isScannable({ path: "docs/node_modules.md", kind: "create" })).toBe(true);
    expect(isScannable({ path: "src/vendor.ts", kind: "create" })).toBe(true);
  });
});

describe("scanTargets", () => {
  const effects: EffectRecord[] = [
    { path: "src/a.ts", kind: "create" },
    { path: "src/b.ts", kind: "modify" },
    { path: "src/gone.ts", kind: "delete" },
    { path: "node_modules/x/i.js", kind: "create" },
  ];

  it("reads the added lines of every scannable effect, in effect order", async () => {
    const ctx = basicContext(async () => "whole file", {
      addedLinesOf: async (p) => `added to ${p}`,
    });
    expect(await scanTargets(effects, ctx)).toEqual([
      { path: "src/a.ts", added: "added to src/a.ts" },
      { path: "src/b.ts", added: "added to src/b.ts" },
    ]);
  });

  it("never reads the whole file", async () => {
    const reads: string[] = [];
    const ctx = basicContext(async (p) => {
      reads.push(`contentOf:${p}`);
      return "whole";
    }, {
      addedLinesOf: async (p) => {
        reads.push(`addedLinesOf:${p}`);
        return "added";
      },
    });
    await scanTargets(effects, ctx);
    expect(reads).toEqual(["addedLinesOf:src/a.ts", "addedLinesOf:src/b.ts"]);
  });

  it("skips an effect whose added lines cannot be read rather than throwing", async () => {
    const ctx = basicContext(async () => "", {
      addedLinesOf: async (p) => {
        if (p === "src/a.ts") throw new Error("gone");
        return "added";
      },
    });
    expect(await scanTargets(effects, ctx)).toEqual([{ path: "src/b.ts", added: "added" }]);
  });

  it("skips an effect that added nothing", async () => {
    const ctx = basicContext(async () => "", { addedLinesOf: async () => "" });
    expect(await scanTargets(effects, ctx)).toEqual([]);
  });
});

describe("the scan budget", () => {
  it("truncates an oversized added text and says so", async () => {
    const huge = "x".repeat(MAX_ADDED_CHARS + 10);
    const ctx = basicContext(async () => "", { addedLinesOf: async () => huge });
    const [target] = await scanTargets([{ path: "src/huge.ts", kind: "create" }], ctx);
    expect(target?.added).toHaveLength(MAX_ADDED_CHARS);
    expect(target?.truncated).toBe(true);
  });

  it("does not mark an ordinary read as truncated", async () => {
    const ctx = basicContext(async () => "", { addedLinesOf: async () => "small" });
    const [target] = await scanTargets([{ path: "src/a.ts", kind: "create" }], ctx);
    expect(target?.truncated).toBeUndefined();
  });
});

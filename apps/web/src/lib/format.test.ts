import { describe, expect, it } from "vitest";
import { classLabel, formatBytes, kindWord, shortHash, shortPath, splitPath } from "./format";

describe("the numbers and paths on a proposed-changes row", () => {
  it("formats bytes at every scale a diff reaches", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(-1)).toBe("0 B");
    expect(formatBytes(412)).toBe("412 B");
    expect(formatBytes(2048)).toBe("2.0 kB");
    expect(formatBytes(200_000)).toBe("195 kB");
    expect(formatBytes(3_500_000)).toBe("3.3 MB");
  });

  it("splits a path so the file name can carry the weight", () => {
    expect(splitPath("src/components/Hero.tsx")).toEqual({ directory: "src/components/", name: "Hero.tsx" });
    expect(splitPath("package.json")).toEqual({ directory: "", name: "package.json" });
  });

  it("keeps the useful end of a long workspace path", () => {
    expect(shortPath("/srv/launchpad/workspaces/1234-5678")).toBe(".../launchpad/workspaces/1234-5678");
    expect(shortPath("/srv/workspaces")).toBe("/srv/workspaces");
  });

  it("shortens a hash without hiding a short one", () => {
    expect(shortHash("a".repeat(64))).toBe("a".repeat(12));
    expect(shortHash("abc")).toBe("abc");
  });

  it("says what a change does to a path in a word", () => {
    expect(kindWord("create")).toBe("creates");
    expect(kindWord("delete")).toBe("deletes");
    expect(classLabel("ci")).toBe("CI");
    expect(classLabel("protected")).toBe("protected");
  });
});

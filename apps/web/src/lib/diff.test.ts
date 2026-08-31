import { describe, expect, it } from "vitest";
import { collapseUnchanged, diffStat, lineDiff } from "./diff";

const text = (...lines: string[]) => lines.join("\n") + "\n";

describe("the before and after a reviewer expands", () => {
  it("marks one changed line and leaves the rest alone", () => {
    const rows = lineDiff(
      text('{"name":"app"}', "second", "third"),
      text('{"name":"app","scripts":{"postinstall":"node ./collect.js"}}', "second", "third"),
    );
    expect(diffStat(rows)).toEqual({ added: 1, removed: 1 });
    expect(rows.filter((r) => r.kind === "same").map((r) => r.text)).toEqual(["second", "third"]);
    expect(rows.find((r) => r.kind === "add")!.text).toContain("postinstall");
  });

  it("reads a created file as all additions", () => {
    const rows = lineDiff("", text("export const app = 1;"));
    expect(diffStat(rows)).toEqual({ added: 1, removed: 0 });
    expect(rows[0]!.before).toBeNull();
    expect(rows[0]!.after).toBe(1);
  });

  it("reads a deleted file as all removals", () => {
    const rows = lineDiff(text("a", "b"), "");
    expect(diffStat(rows)).toEqual({ added: 0, removed: 2 });
    expect(rows.every((r) => r.after === null)).toBe(true);
  });

  it("reports no change when both sides are identical", () => {
    const rows = lineDiff(text("a", "b", "c"), text("a", "b", "c"));
    expect(diffStat(rows)).toEqual({ added: 0, removed: 0 });
    expect(rows).toHaveLength(3);
  });

  it("numbers both sides so a reviewer can point at a line", () => {
    const rows = lineDiff(text("a", "b", "c"), text("a", "B", "c"));
    const removed = rows.find((r) => r.kind === "remove")!;
    const added = rows.find((r) => r.kind === "add")!;
    expect(removed.before).toBe(2);
    expect(added.after).toBe(2);
    expect(rows[rows.length - 1]).toMatchObject({ kind: "same", before: 3, after: 3 });
  });

  it("handles an insertion in the middle without rewriting the file around it", () => {
    const rows = lineDiff(text("a", "b"), text("a", "inserted", "b"));
    expect(diffStat(rows)).toEqual({ added: 1, removed: 0 });
    expect(rows.map((r) => r.text)).toEqual(["a", "inserted", "b"]);
  });

  it("does not invent an empty last line from the trailing newline", () => {
    const rows = lineDiff("a\n", "a\n");
    expect(rows).toHaveLength(1);
  });
});

describe("collapsing the unchanged part of a long file", () => {
  it("keeps context around every change and counts what it hid", () => {
    const before = text(...Array.from({ length: 40 }, (_, i) => "line " + i));
    const after = before.replace("line 20", "line 20 changed");
    const rows = collapseUnchanged(lineDiff(before, after), 2);
    const gaps = rows.filter((r) => r.kind === "gap");
    expect(gaps).toHaveLength(2);
    expect(gaps[0]!.text).toBe("18 unchanged lines");
    expect(rows.some((r) => r.kind === "add" && r.text === "line 20 changed")).toBe(true);
  });

  it("collapses a file with no changes into one gap", () => {
    const rows = collapseUnchanged(lineDiff(text("a", "b", "c"), text("a", "b", "c")));
    expect(rows).toEqual([{ kind: "gap", text: "3 unchanged lines", before: null, after: null }]);
  });

  it("leaves a short file uncollapsed", () => {
    const rows = collapseUnchanged(lineDiff(text("a", "b"), text("a", "c")), 3);
    expect(rows.some((r) => r.kind === "gap")).toBe(false);
  });
});

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { DiffView, REVIEW_DIFF_BYTES } from "./DiffView";
import type { ProposedChange } from "../../types";

/**
 * The fixtures below are the wire rows `buildReviewViews` actually produced for a held turn of 34
 * modified 64 KiB files followed by one small file and one sealed network write. They are copied
 * from that run rather than invented, so what is asserted here is what the panel is handed.
 */
function change(over: Partial<ProposedChange>): ProposedChange {
  return {
    path: "src/app.ts",
    kind: "modify",
    class: "source",
    bytes: 11,
    before: "alpha\nbeta\n",
    after: "alpha\nBETA\n",
    truncated: false,
    binary: false,
    ...over,
  };
}

/** exactly the row the broker's `heldRecordToEffect` produces, after review-view has read it */
const OUTBOUND: ProposedChange = {
  path: "net:POST collector.example:443/ingest",
  kind: "outbound",
  class: "other",
  bytes: 2048,
  before: null,
  after: null,
  truncated: false,
  binary: false,
};

/** the row `late.ts` became once the 4 MiB response budget was spent by the rows ahead of it */
const WITHHELD: ProposedChange = {
  path: "late.ts",
  kind: "modify",
  class: "source",
  bytes: 11,
  before: null,
  after: null,
  truncated: true,
  binary: false,
};

const html = (c: ProposedChange): string => renderToStaticMarkup(<DiffView change={c} />);

describe("a held network write", () => {
  it("does not render as an empty file", () => {
    expect(html(OUTBOUND)).not.toContain("Nothing to show");
  });

  it("names the destination, the method and the size the turn would send", () => {
    const out = html(OUTBOUND);
    expect(out).toContain("collector.example:443");
    expect(out).toContain("POST");
    expect(out).toContain("/ingest");
    expect(out).toContain("2.0 kB");
  });

  it("still says something useful when the synthetic path is not the shape the broker writes", () => {
    const out = html({ ...OUTBOUND, path: "net:garbled" });
    expect(out).not.toContain("Nothing to show");
    expect(out).toContain("net:garbled");
  });
});

describe("a change whose contents the server declined to send", () => {
  it("is not described as an empty file", () => {
    expect(html(WITHHELD)).not.toContain("Nothing to show");
  });

  it("says the contents were not sent and keeps the path and the byte count in view", () => {
    const out = html(WITHHELD);
    expect(out).toContain("did not send");
    expect(out).toContain("late.ts");
    expect(out).toContain("11 B");
  });

  it("does not render a half-sent modify as if the whole file were being deleted", () => {
    // before present, after withheld: the old code diffed against "" and drew every line removed
    const out = html(change({ after: null, truncated: true }));
    expect(out).not.toContain("diff-table");
    expect(out).toContain("did not send");
  });

  it("does not render a half-sent modify as if the whole file were being added", () => {
    const out = html(change({ before: null, truncated: true }));
    expect(out).not.toContain("diff-table");
    expect(out).toContain("did not send");
  });
});

describe("ordinary work still renders", () => {
  it("draws the diff for a normal modification", () => {
    const out = html(change({}));
    expect(out).toContain("diff-table");
    expect(out).toContain("BETA");
    expect(out).not.toContain("did not send");
    expect(out).not.toContain("Nothing to show");
  });

  it("treats a created file's absent before side as normal, not as withheld", () => {
    const out = html(change({ kind: "create", before: null, after: "new line\n" }));
    expect(out).toContain("diff-table");
    expect(out).toContain("new line");
    expect(out).not.toContain("did not send");
  });

  it("treats a deleted file's absent after side as normal, not as withheld", () => {
    const out = html(change({ kind: "delete", before: "old line\n", after: null }));
    expect(out).toContain("diff-table");
    expect(out).toContain("old line");
    expect(out).not.toContain("did not send");
  });

  it("still says both sides are empty when both sides really were sent and really are empty", () => {
    const out = html(change({ bytes: 0, before: "", after: "" }));
    expect(out).toContain("Nothing to show: both sides are empty.");
    expect(out).not.toContain("did not send");
  });

  it("still refuses to diff a binary", () => {
    const out = html(change({ binary: true, before: null, after: null, bytes: 4096 }));
    expect(out).toContain("not text");
    expect(out).not.toContain("did not send");
  });

  it("still describes a symlink and whether it escapes", () => {
    const out = html(change({ kind: "symlink", before: null, after: null, target: "/etc/passwd", escapes: true }));
    expect(out).toContain("/etc/passwd");
    expect(out).toContain("outside the workspace");
    expect(out).not.toContain("did not send");
  });
});

describe("the truncation note", () => {
  it("states the bound the server actually applied", () => {
    const out = html(change({ truncated: true, before: "a\n", after: "b\n" }));
    expect(out).toContain("64 kB");
    expect(out).not.toContain("8 kB");
  });

  it("matches the constant in the server that does the cutting", () => {
    const source = readFileSync(new URL("../../../../server/src/review-view.ts", import.meta.url), "utf8");
    const match = /REVIEW_DIFF_BYTES\s*=\s*([0-9*\s]+);/.exec(source);
    expect(match, "REVIEW_DIFF_BYTES not found in apps/server/src/review-view.ts").not.toBeNull();
    const serverBytes = Number(
      match![1]!
        .split("*")
        .map((part) => Number(part.trim()))
        .reduce((a, b) => a * b, 1),
    );
    expect(serverBytes).toBe(REVIEW_DIFF_BYTES);
  });
});

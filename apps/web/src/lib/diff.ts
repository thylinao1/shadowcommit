/**
 * A line diff for the expandable before and after on a proposed change.
 *
 * The server sends both sides already bounded, so this only has to be correct and readable, not
 * fast on a large file. Common leading and trailing lines are trimmed first, which turns the usual
 * case (one line changed in a long file) into almost no work, and the middle is matched with a
 * longest-common-subsequence table under a hard cap.
 */

export type DiffRowKind = "same" | "add" | "remove" | "gap";

export interface DiffRow {
  kind: DiffRowKind;
  text: string;
  /** 1-based line number on the real workspace side, null when the line is being added */
  before: number | null;
  /** 1-based line number on the proposed side, null when the line is being removed */
  after: number | null;
}

/** Beyond this the table is not worth building, and the whole file reads as replaced. */
const LCS_LINE_CAP = 800;

function splitLines(text: string): string[] {
  // An empty side is a file with no lines, not a file with one empty line. Getting this wrong
  // showed a phantom removed line on every created file and a phantom added line on every delete.
  if (text === "") return [];
  const lines = text.split("\n");
  // a trailing newline is a line terminator, not an empty final line
  if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

function wholeReplacement(before: string[], after: string[], offset: number): DiffRow[] {
  return [
    ...before.map((text, i) => ({ kind: "remove" as const, text, before: offset + i + 1, after: null })),
    ...after.map((text, i) => ({ kind: "add" as const, text, before: null, after: offset + i + 1 })),
  ];
}

/** The classic LCS backtrack, over the part of the file that actually differs. */
function middleDiff(before: string[], after: string[], beforeOffset: number, afterOffset: number): DiffRow[] {
  if (before.length === 0 && after.length === 0) return [];
  if (before.length === 0) {
    return after.map((text, i) => ({ kind: "add" as const, text, before: null, after: afterOffset + i + 1 }));
  }
  if (after.length === 0) {
    return before.map((text, i) => ({ kind: "remove" as const, text, before: beforeOffset + i + 1, after: null }));
  }
  if (before.length > LCS_LINE_CAP || after.length > LCS_LINE_CAP) {
    return wholeReplacement(before, after, Math.min(beforeOffset, afterOffset));
  }

  const rows = before.length;
  const cols = after.length;
  const table = new Int32Array((rows + 1) * (cols + 1));
  const at = (r: number, c: number): number => table[r * (cols + 1) + c]!;
  for (let r = rows - 1; r >= 0; r--) {
    for (let c = cols - 1; c >= 0; c--) {
      table[r * (cols + 1) + c] =
        before[r] === after[c] ? at(r + 1, c + 1) + 1 : Math.max(at(r + 1, c), at(r, c + 1));
    }
  }

  const out: DiffRow[] = [];
  let r = 0;
  let c = 0;
  while (r < rows && c < cols) {
    if (before[r] === after[c]) {
      out.push({ kind: "same", text: before[r]!, before: beforeOffset + r + 1, after: afterOffset + c + 1 });
      r++;
      c++;
    } else if (at(r + 1, c) >= at(r, c + 1)) {
      out.push({ kind: "remove", text: before[r]!, before: beforeOffset + r + 1, after: null });
      r++;
    } else {
      out.push({ kind: "add", text: after[c]!, before: null, after: afterOffset + c + 1 });
      c++;
    }
  }
  while (r < rows) {
    out.push({ kind: "remove", text: before[r]!, before: beforeOffset + r + 1, after: null });
    r++;
  }
  while (c < cols) {
    out.push({ kind: "add", text: after[c]!, before: null, after: afterOffset + c + 1 });
    c++;
  }
  return out;
}

export function lineDiff(before: string, after: string): DiffRow[] {
  const left = splitLines(before);
  const right = splitLines(after);

  let head = 0;
  while (head < left.length && head < right.length && left[head] === right[head]) head++;
  let tail = 0;
  while (
    tail < left.length - head &&
    tail < right.length - head &&
    left[left.length - 1 - tail] === right[right.length - 1 - tail]
  ) {
    tail++;
  }

  const prefix: DiffRow[] = left.slice(0, head).map((text, i) => ({
    kind: "same" as const,
    text,
    before: i + 1,
    after: i + 1,
  }));
  const middle = middleDiff(
    left.slice(head, left.length - tail),
    right.slice(head, right.length - tail),
    head,
    head,
  );
  const suffix: DiffRow[] = left.slice(left.length - tail).map((text, i) => ({
    kind: "same" as const,
    text,
    before: left.length - tail + i + 1,
    after: right.length - tail + i + 1,
  }));
  return [...prefix, ...middle, ...suffix];
}

/**
 * Replaces long runs of unchanged lines with one gap row, so a reviewer sees the change rather than
 * scrolling past the file that surrounds it.
 */
export function collapseUnchanged(rows: DiffRow[], context = 3): DiffRow[] {
  const keep = new Array<boolean>(rows.length).fill(false);
  rows.forEach((row, index) => {
    if (row.kind === "same") return;
    for (let i = Math.max(0, index - context); i <= Math.min(rows.length - 1, index + context); i++) {
      keep[i] = true;
    }
  });
  const out: DiffRow[] = [];
  let hidden = 0;
  rows.forEach((row, index) => {
    if (keep[index]) {
      if (hidden > 0) {
        out.push({ kind: "gap", text: hidden + " unchanged line" + (hidden === 1 ? "" : "s"), before: null, after: null });
        hidden = 0;
      }
      out.push(row);
      return;
    }
    hidden++;
  });
  if (hidden > 0) {
    out.push({ kind: "gap", text: hidden + " unchanged line" + (hidden === 1 ? "" : "s"), before: null, after: null });
  }
  return out;
}

export interface DiffStat {
  added: number;
  removed: number;
}

export function diffStat(rows: DiffRow[]): DiffStat {
  return {
    added: rows.filter((r) => r.kind === "add").length,
    removed: rows.filter((r) => r.kind === "remove").length,
  };
}

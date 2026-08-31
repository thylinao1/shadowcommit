import { useMemo } from "react";
import { collapseUnchanged, diffStat, lineDiff } from "../../lib/diff";
import { formatBytes } from "../../lib/format";
import type { EffectKind, ProposedChange } from "../../types";

/**
 * The per-side bound the server reads a proposed change under, mirroring `REVIEW_DIFF_BYTES` in
 * `apps/server/src/review-view.ts`. The two workspaces do not share a tsconfig, so this is a copy;
 * `DiffView.test.tsx` reads the server constant off disk and fails when the two drift apart. The
 * note used to say 8 kB while the server cut at 64 KiB, which told a reviewer they had read an
 * eighth of what they had actually been given. The note says "at most" because the server shrinks
 * this bound further as its response budget is spent, and it does not put the bound it used on the
 * wire, so this is a ceiling rather than the exact figure.
 */
export const REVIEW_DIFF_BYTES = 64 * 1024;

/** The sides a change of this kind is expected to carry when the server sent its contents. */
function expectedSides(kind: EffectKind): ("before" | "after")[] {
  if (kind === "create") return ["after"];
  if (kind === "delete") return ["before"];
  return ["before", "after"];
}

/**
 * Which sides the server did not send. `null` on the wire is not an empty file: the server also
 * returns null when the response budget is spent, when the path is one it will not read, and when
 * the file is not there. Those cases used to reach the reviewer as "both sides are empty", or, when
 * only one side was missing, as a diff claiming the turn deleted or created the whole file.
 */
export function withheldSides(change: ProposedChange): ("before" | "after")[] {
  if (change.binary || change.kind === "symlink" || change.kind === "outbound") return [];
  return expectedSides(change.kind).filter((side) => change[side] === null);
}

/** The synthetic path the broker writes for a held write: `net:POST host:port/path`. */
export function parseOutboundPath(value: string): { method: string; destination: string; urlPath: string } | null {
  if (!value.startsWith("net:")) return null;
  const rest = value.slice("net:".length);
  const space = rest.indexOf(" ");
  if (space <= 0) return null;
  const method = rest.slice(0, space);
  const target = rest.slice(space + 1);
  if (target === "") return null;
  const slash = target.indexOf("/");
  if (slash === -1) return { method, destination: target, urlPath: "/" };
  return { method, destination: target.slice(0, slash), urlPath: target.slice(slash) };
}

function sidesPhrase(sides: ("before" | "after")[]): string {
  if (sides.length === 2) return "either side of this change";
  if (sides[0] === "before") return "the current contents of this file";
  return "the contents this change would write";
}

/**
 * The before and after of one proposed change. The server sends both sides already bounded, and
 * says when it cut them, so this never pretends to show a whole file it did not receive. It also
 * never pretends a change is empty when the server simply did not send it, and it never renders a
 * network write as a file.
 */
export function DiffView({ change }: { change: ProposedChange }) {
  const rows = useMemo(
    () => collapseUnchanged(lineDiff(change.before ?? "", change.after ?? ""), 3),
    [change.before, change.after],
  );
  const stat = useMemo(() => diffStat(rows), [rows]);

  // A held network write is in the same effect set as the file changes, under a path that is not a
  // path. There is no before and after to read, so say where the bytes would go instead.
  if (change.kind === "outbound") {
    const target = parseOutboundPath(change.path);
    return (
      <p className="diff-note">
        This is a network write, not a file. Approving it sends {formatBytes(change.bytes)}{" "}
        {target ? (
          <>
            to <code>{target.destination}</code> as <code>{target.method}</code>{" "}
            <code>{target.urlPath}</code>
          </>
        ) : (
          <>
            to the destination recorded as <code>{change.path}</code>
          </>
        )}
        . Bytes that leave cannot be taken back, so reject unless you meant this one.
      </p>
    );
  }
  if (change.binary) {
    return <p className="diff-note">This file is not text, so there is no diff to read. It is {change.bytes} bytes.</p>;
  }
  if (change.kind === "symlink") {
    return (
      <p className="diff-note">
        This change points <code>{change.path}</code> at <code>{change.target ?? "an unknown target"}</code>
        {change.escapes ? ", which is outside the workspace." : "."}
      </p>
    );
  }

  const withheld = withheldSides(change);
  if (withheld.length > 0) {
    return (
      <p className="diff-note">
        The server did not send {sidesPhrase(withheld)}, so there is no diff to read here. That is not the same
        as an empty file: the row is {formatBytes(change.bytes)}. Reject this turn, or read{" "}
        <code>{change.path}</code> in the workspace before approving it.
      </p>
    );
  }
  if (rows.length === 0) {
    return <p className="diff-note">Nothing to show: both sides are empty.</p>;
  }

  return (
    <div className="diff">
      <div className="diff-stat">
        <span className="diff-added">+{stat.added}</span>
        <span className="diff-removed">-{stat.removed}</span>
        {change.truncated && (
          <span className="diff-cut">cut: at most the first {formatBytes(REVIEW_DIFF_BYTES)} of each side is shown</span>
        )}
      </div>
      <div className="diff-scroll">
        <table className="diff-table">
          <tbody>
            {rows.map((row, index) => (
              <tr key={index} className={"diff-row diff-" + row.kind}>
                <td className="diff-no">{row.before ?? ""}</td>
                <td className="diff-no">{row.after ?? ""}</td>
                <td className="diff-sign" aria-hidden="true">
                  {row.kind === "add" ? "+" : row.kind === "remove" ? "-" : ""}
                </td>
                <td className="diff-text">
                  {row.kind === "gap" ? <span className="diff-gap">{row.text}</span> : row.text}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

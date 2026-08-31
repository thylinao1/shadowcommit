import { useState } from "react";
import { ClassChip } from "../ui/ClassChip";
import { DiffView } from "./DiffView";
import { formatBytes, kindWord, splitPath } from "../../lib/format";
import type { ProposedChange } from "../../types";

/**
 * PROPOSED CHANGES: one row per path the turn wants to touch, each expandable into the before and
 * after. This is the whole decision surface, so nothing here is a summary of something else.
 */
export function ProposedChanges({
  changes,
  truncated,
  idPrefix,
}: {
  changes: ProposedChange[];
  truncated: number;
  idPrefix: string;
}) {
  const [open, setOpen] = useState<string | null>(changes.length === 1 ? (changes[0]?.path ?? null) : null);

  return (
    <div className="changes">
      <div className="changes-head">
        <span className="eyebrow">Proposed changes</span>
        <span className="changes-count">
          {changes.length} {changes.length === 1 ? "path" : "paths"}
        </span>
      </div>
      <ol className="change-rows">
        {changes.map((change) => {
          const { directory, name } = splitPath(change.path);
          const expanded = open === change.path;
          const panelId = idPrefix + "-" + change.path.replace(/[^a-zA-Z0-9]/g, "-");
          return (
            <li className={"change-row change-" + change.kind} key={change.path}>
              <button
                className="change-summary"
                aria-expanded={expanded}
                aria-controls={panelId}
                onClick={() => setOpen(expanded ? null : change.path)}
              >
                <span className={"kind-tag kind-" + change.kind}>{kindWord(change.kind)}</span>
                <span className="change-path">
                  <span className="change-dir">{directory}</span>
                  <span className="change-name">{name}</span>
                </span>
                <ClassChip value={change.class} />
                <span className="change-bytes">{formatBytes(change.bytes)}</span>
                <span className="change-toggle" aria-hidden="true">
                  {expanded ? "Hide" : "Diff"}
                </span>
              </button>
              {expanded && (
                <div className="change-panel" id={panelId}>
                  <DiffView change={change} />
                </div>
              )}
            </li>
          );
        })}
      </ol>
      {truncated > 0 && (
        <p className="changes-more">
          {truncated} more {truncated === 1 ? "path is" : "paths are"} in this turn and are not listed here.
        </p>
      )}
    </div>
  );
}

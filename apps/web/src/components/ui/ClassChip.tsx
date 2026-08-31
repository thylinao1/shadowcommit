import { classLabel } from "../../lib/format";
import type { ChangeClass } from "../../types";

/**
 * What kind of thing is being changed, read before anything else on the row. A protected asset and
 * a source file are the same shape of change and a completely different decision.
 */
export function ClassChip({ value }: { value: ChangeClass }) {
  return <span className={"class-chip class-" + value}>{classLabel(value)}</span>;
}

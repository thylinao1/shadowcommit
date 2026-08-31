import { verdictLabel, verdictTone } from "../../lib/verdict";
import type { TurnVerdict } from "../../types";

export function VerdictBadge({ verdict }: { verdict: TurnVerdict }) {
  return (
    <span className={"verdict verdict-" + verdictTone(verdict)}>
      <span className="verdict-dot" />
      {verdictLabel(verdict)}
    </span>
  );
}

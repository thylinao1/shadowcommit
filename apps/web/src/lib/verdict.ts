import type { Containment, TimelineTurn, TurnVerdict } from "../types";

/**
 * The words the screen uses for what the boundary did with a turn, in one place so the playground
 * and the run timeline can never say it differently.
 *
 * The vocabulary is fixed on purpose. A blocked turn reads "BLOCKED, nothing was sent"; it is never
 * an alarm, because the ordinary case is the platform working. Proposed changes are never called an
 * effect set on screen.
 */

export interface RunVerdict {
  verdict: TurnVerdict;
  rule: string | null;
  principal: string | null;
  changes: number;
  /** files a mid-apply conflict had already written, so the sentence can stop saying "not applied" */
  appliedPaths?: string[];
}

function plural(count: number, word: string): string {
  return count + " " + word + (count === 1 ? "" : "s");
}

export function verdictSentence(verdict: RunVerdict): string {
  switch (verdict.verdict) {
    case "committed":
      return "Committed: " + plural(verdict.changes, "change");
    case "approved":
      return (
        "Committed: " +
        plural(verdict.changes, "change") +
        (verdict.principal ? ", approved by " + verdict.principal : ", approved")
      );
    case "discarded":
      return "BLOCKED, nothing was sent" + (verdict.rule ? ": " + verdict.rule : "");
    case "rejected":
      return "Rejected" + (verdict.principal ? " by " + verdict.principal : "") + ", nothing was sent";
    case "held":
      return "Held for review: " + plural(verdict.changes, "proposed change");
    case "conflicted":
      // "Not applied" was printed over a partly applied workspace too. A conflict found under one of
      // the commit's own writes has already written some files, and telling the operator nothing
      // landed is the one thing they must not believe while deciding what to do next.
      return verdict.appliedPaths && verdict.appliedPaths.length > 0
        ? "Stopped part way: the workspace changed while this turn was running, after " +
          plural(verdict.appliedPaths.length, "change") + " had already been written"
        : "Not applied: the workspace changed while this turn was running";
    case "unrecoverable":
      return "Commit could not be finished. Some changes may have landed: check the workspace";
    case "restored":
      return "Restored to this turn";
    case "running":
    default:
      return "Running";
  }
}

/** The tone of the verdict badge: this is what colour it gets, nothing more. */
export function verdictTone(verdict: TurnVerdict): "good" | "blocked" | "waiting" | "neutral" {
  if (verdict === "committed" || verdict === "approved") return "good";
  // unrecoverable is not neutral: the real workspace may be half written, which is the one state
  // that needs a person to look at it rather than a grey badge that reads like "nothing happened"
  if (verdict === "discarded" || verdict === "rejected" || verdict === "unrecoverable") return "blocked";
  if (verdict === "held") return "waiting";
  return "neutral";
}

export function verdictLabel(verdict: TurnVerdict): string {
  switch (verdict) {
    case "committed":
      return "Committed";
    case "approved":
      return "Approved";
    case "discarded":
      return "Blocked";
    case "rejected":
      return "Rejected";
    case "held":
      return "Held";
    case "conflicted":
      return "Conflicted";
    case "restored":
      return "Restored";
    case "unrecoverable":
      return "Unfinished";
    case "running":
    default:
      return "Running";
  }
}

export function verdictOfTurn(turn: TimelineTurn): RunVerdict {
  return {
    verdict: turn.verdict,
    rule: turn.rule,
    principal: turn.principal,
    changes: turn.effectCount,
    // without this the sentence never sees the field and the conflicted branch below is dead code,
    // which is how a fix ends up shipped and unreachable
    appliedPaths: turn.appliedPaths ?? [],
  };
}

/** The verdict a runner result carries directly, once the boundary reports it as a field. */
export function verdictOfContainment(containment: Containment): RunVerdict {
  const verdict: TurnVerdict =
    containment.decision === "commit"
      ? "committed"
      : containment.decision === "discard"
        ? "discarded"
        : containment.decision === "review"
          ? "held"
          : "conflicted";
  return { verdict, rule: containment.rule || null, principal: null, changes: containment.effects };
}

/**
 * The runner appends its verdict to the agent's own reply, because the caller must never be handed
 * "I completed the task" on a turn that landed nowhere. The panel reads the verdict from the
 * journal instead, so here the suffix is only split off the body and used as a fallback when the
 * journal has not caught up with the run.
 */
const HELD = /\n*\[held for review: ([^.\]]+)\. (\d+) proposed change\(s\)[^\]]*\]\s*$/;
const BLOCKED = /\n*\[blocked by policy: ([^.\]]+)\. (\d+) change\(s\)[^\]]*\]\s*$/;
const CONFLICT = /\n*\[not applied: the workspace changed[^\]]*\]\s*$/;

export function readMessage(content: string): { body: string; verdict: RunVerdict | null } {
  const held = HELD.exec(content);
  if (held) {
    return {
      body: content.slice(0, held.index).trimEnd(),
      verdict: { verdict: "held", rule: held[1] ?? null, principal: null, changes: Number(held[2] ?? 0) },
    };
  }
  const blocked = BLOCKED.exec(content);
  if (blocked) {
    return {
      body: content.slice(0, blocked.index).trimEnd(),
      verdict: {
        verdict: "discarded",
        rule: blocked[1] ?? null,
        principal: null,
        changes: Number(blocked[2] ?? 0),
      },
    };
  }
  const conflict = CONFLICT.exec(content);
  if (conflict) {
    return {
      body: content.slice(0, conflict.index).trimEnd(),
      verdict: { verdict: "conflicted", rule: null, principal: null, changes: 0 },
    };
  }
  return { body: content, verdict: null };
}

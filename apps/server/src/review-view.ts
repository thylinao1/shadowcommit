import path from "node:path";
import { isSafeRelative, readBounded } from "./capture.js";
import { shadowFileOf } from "./policy-context.js";
import { JOURNAL_EFFECT_LIMIT } from "./commit-protocol.js";
import type { HeldTurn } from "./runner-store.js";
import { classifyPath, type ChangeClass } from "./change-class.js";
import type { EffectRecord, RuleHit } from "./policy-types.js";

/**
 * What a human is shown before deciding.
 *
 * A path list is not a review. An operator shown eight innocuous fixture paths approves the ninth
 * without ever seeing that it is a loader for an obfuscated payload (attacks r18 and r07), so the
 * surface carries each file's before and after, the class the effect was given, every rule that
 * fired, and the hash the approval has to carry back.
 *
 * Both bounds here exist so that rendering a review can never become the memory problem the byte
 * caps exist to prevent: at most 64 KiB per side of one file, and a ceiling across the response.
 */
const REVIEW_DIFF_BYTES = 64 * 1024;
const REVIEW_DIFF_BUDGET = 4 * 1024 * 1024;

/** One effect as the review surface shows it: what it is, and what it would do to that file. */
export interface ReviewEffectView {
  path: string;
  kind: EffectRecord["kind"];
  /** the class the effect carries, which is the one the policy judged it under */
  effectClass: string;
  /** the same thing reduced to the six words the chip in the panel can say */
  class: ChangeClass;
  bytes: number;
  sha256: string;
  target?: string;
  escapes?: boolean;
  before: string | null;
  after: string | null;
  truncated: boolean;
  /** true when the file is not text, so no diff is offered and neither side is sent */
  binary: boolean;
}

/** One held turn as the review surface shows it. */
export interface ReviewView {
  runId: string;
  agentId: string;
  rule: string;
  hits: RuleHit[];
  effectSetHash: string;
  workspacePath: string;
  heldAt: string;
  effects: ReviewEffectView[];
  effectCount: number;
  effectsTruncated: number;
  /** the same count under the name the panel reads; one wire shape, two readers */
  truncated: number;
}

export async function buildReviewViews(pending: HeldTurn[]): Promise<ReviewView[]> {
  const views: ReviewView[] = [];
  let budget = REVIEW_DIFF_BUDGET;
  for (const held of pending) {
    const shown = held.effects.slice(0, JOURNAL_EFFECT_LIMIT);
    const effects: ReviewEffectView[] = [];
    for (const effect of shown) {
      const bytes = effect.bytes ?? 0;
      // a path capture could not have produced is rendered as a row and never as content
      const room = isSafeRelative(effect.path) ? Math.max(0, Math.min(REVIEW_DIFF_BYTES, budget)) : 0;
      const after =
        effect.kind === "delete" || room === 0
          ? null
          : await readBounded(shadowFileOf(held.shadowDir, held.mechanism, effect.path), room);
      const before =
        effect.kind === "create" || room === 0
          ? null
          : await readBounded(path.join(held.workspacePath, effect.path), room);
      budget -= (after?.length ?? 0) + (before?.length ?? 0);
      // A NUL byte anywhere in what was read means this is not a file a line diff can show, so
      // neither side is sent: rendering a binary as text is how a reviewer ends up approving a
      // screenful of mojibake without having read anything.
      const binary = (before?.includes("\u0000") ?? false) || (after?.includes("\u0000") ?? false);
      effects.push({
        path: effect.path,
        kind: effect.kind,
        effectClass: effect.effectClass ?? "unclassified",
        class: classifyPath(effect.path, effect.effectClass),
        bytes,
        sha256: effect.sha256 ?? "",
        ...(effect.target === undefined ? {} : { target: effect.target }),
        ...(effect.escapes === undefined ? {} : { escapes: effect.escapes }),
        before: binary ? null : before,
        after: binary ? null : after,
        truncated: bytes > REVIEW_DIFF_BYTES || room < REVIEW_DIFF_BYTES,
        binary,
      });
    }
    views.push({
      runId: held.runId,
      agentId: held.agentId,
      rule: held.rule,
      hits: held.hits,
      effectSetHash: held.effectSetHash,
      workspacePath: held.workspacePath,
      heldAt: held.heldAt,
      effects,
      effectCount: held.effects.length,
      effectsTruncated: Math.max(0, held.effects.length - shown.length),
      truncated: Math.max(0, held.effects.length - shown.length),
    });
  }
  return views;
}

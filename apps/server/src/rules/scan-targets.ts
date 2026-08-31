import type { EffectRecord, PolicyContext } from "../policy-types.js";

/**
 * Selects the effects a content scanner is allowed to read, and reads only the lines the turn
 * ADDED to each of them. Reading the whole file is what made the shipped policy discard the
 * organizers' own acceptance task: five JSDoc example lines inside an installed type-definition
 * package are content the turn did not write, and no content rule should ever see them.
 */

/** Effect class the capture step assigns to an installed dependency tree. */
export const DEPENDENCY_CLASS = "dependency-tree";

/**
 * Fallback for captures that have not classified their effects yet. A vendored path is not the
 * turn's own work even when effectClass is absent.
 */
export const VENDORED_PATH =
  /(^|\/)(node_modules|vendor|site-packages|dist-packages|\.venv|venv|bower_components|third_party|Pods)\//;

/**
 * Longest added text any content rule will read from one file. A turn controls how much it writes,
 * so an unbounded read is a way to stall the judge rather than to pass it. Truncation is reported
 * rather than silent: a scanner that stopped early has not cleared the file.
 */
export const MAX_ADDED_CHARS = 512_000;

/** A written file plus the text this turn added to it. */
export interface ScanTarget {
  path: string;
  added: string;
  /** set when the added text was longer than the budget, so only its head was scanned */
  truncated?: boolean;
}

/** True when a content rule may read this effect. */
export function isScannable(effect: EffectRecord): boolean {
  // Its own line, ahead of the path and class checks below, because those two answer a different
  // question. An oversize effect was never read and never hashed by capture, so there is nothing
  // here to scan and the record says so; letting a content rule ask for it anyway would send the
  // judge to read a file the capture layer deliberately refused to open.
  if (effect.oversize) return false;
  if (effect.kind !== "create" && effect.kind !== "modify") return false;
  if (effect.effectClass === DEPENDENCY_CLASS) return false;
  if (VENDORED_PATH.test(effect.path)) return false;
  return true;
}

/** The added text of every scannable effect, in effect order. Missing reads are skipped, never thrown. */
export async function scanTargets(effects: EffectRecord[], ctx: PolicyContext): Promise<ScanTarget[]> {
  const targets: ScanTarget[] = [];
  for (const effect of effects) {
    if (!isScannable(effect)) continue;
    let added: string;
    try {
      added = await ctx.addedLinesOf(effect.path);
    } catch {
      continue;
    }
    if (added.length === 0) continue;
    if (added.length > MAX_ADDED_CHARS) {
      targets.push({ path: effect.path, added: added.slice(0, MAX_ADDED_CHARS), truncated: true });
      continue;
    }
    targets.push({ path: effect.path, added });
  }
  return targets;
}

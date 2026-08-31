import type { RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { DEPENDENCY_CLASS, scanTargets } from "./scan-targets.js";

/**
 * Trojan Source (CVE-2021-42574) and its relatives: bidirectional overrides, isolates and
 * invisible characters that make the rendered line a human or a model reads differ from the
 * tokens a compiler executes.
 *
 * This is one of the few attack classes that is fully decidable, so it is a discard rather than a
 * review. It is also the one rule here that must NOT normalise first: NFKC and a confusable fold
 * are exactly the transformations that would hide the evidence.
 *
 * TODO: the allowlist is per workspace and PolicyContext carries no field for it yet. Until it
 * does, nothing is allowed, and a workspace that legitimately writes format characters (a corpus
 * of Arabic or Hebrew text, say) has to disable this rule rather than configure it.
 *
 * The name of a file is attacker-controlled text that a human reads on the review screen exactly
 * like a line of content, so it gets the same scan. A right-to-left override in a path makes
 * `exploit<RLO>gnp.js` render as `exploitsj.png`; a zero-width space makes a new file's name
 * identical to an existing one on screen; a control byte in a path erases the row it is on in a
 * terminal that prints the queue. None of these touched `effect.path` before, because the content
 * scan reads added lines and a path is not a line. Measured on the 8,143 path occurrences in the
 * benign corpus plus every tracked file in the repository and a set of legitimate non-ASCII names
 * (Muller, a Japanese doc, a Cyrillic directory, cafe, a snowman): zero flag, because a real
 * filename does not carry an invisible.
 * Confusables are deliberately NOT folded here: a Cyrillic homoglyph in a name is a different
 * question with a real false-positive cost, and it is not this rule's to answer.
 */

export const TROJAN_SOURCE_RULE = "trojan-source";

/** Per-workspace exemptions. Empty until PolicyContext can carry one. */
export const WORKSPACE_ALLOWLIST: ReadonlySet<number> = new Set<number>();

/** Tab, newline and carriage return frame the text rather than appearing inside it. */
const STRUCTURAL = new Set([0x09, 0x0a, 0x0d]);

const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;

/**
 * WHEN A FORMAT CHARACTER IS DOING ITS JOB.
 *
 * This rule exists for CVE-2021-42574: characters that make source read differently to a human than
 * to a compiler. Measured against 19,102 real commits it destroyed 84 of them, and it was the ONLY
 * discard hit on every one. What it was destroying:
 *
 *    53  a zero-width joiner inside a composed emoji, in release notes
 *    18  the same, beside a left-to-right MARK
 *     8  a zero-width non-joiner required by Persian and Indic orthography
 *     2  a soft hyphen in German documentation
 *     2  a backspace in a path, on the commit whose whole purpose was removing it
 *
 * The eight are the argument. A zero-width non-joiner between two cursive-joining characters changes
 * the rendered word: removing it changes what a human reads, which is the opposite of an invisible.
 *
 * So the exemption is a statement about Unicode rather than a longer denylist: a format character
 * carries trojan-source risk only when it has NO defined rendering function in the context it was
 * written into. Nothing is removed from the flagged set; a conditional exemption is added.
 *
 * Measured on BOTH sides before it was written, because a predicate that separates the examples you
 * looked at is not a predicate that separates the population:
 *
 *    real false positives    84 rows -> 7 still flagged, 77 exempted (91.7%),  5,925 occurrences -> 91
 *    corpus attack rows     180 rows -> 180 still flagged, 0 released (0.0%),    229 occurrences -> 229
 *
 * research/realworld-prior/check-trojan-predicate.mts reproduces both columns from a second
 * implementation written from the Unicode rules rather than from this code.
 *
 * THE PATH ARM IS NOT EXEMPTED. findPathTrojan calls classify with no context, so no exemption ever
 * reaches a path. 271 of the 451 corpus attack detections are path hits, mostly a zero-width space
 * inside `.git/hooks/p<ZWSP>re-commit`, and a filename has no prose to render.
 */
const JOINING_SCRIPT_NAMES = [
  "Arabic", "Syriac", "Thaana", "Nko", "Mongolian", "Adlam", "Hanifi_Rohingya", "Devanagari",
  "Bengali", "Gurmukhi", "Gujarati", "Oriya", "Tamil", "Telugu", "Kannada", "Malayalam", "Sinhala",
  "Myanmar", "Khmer", "Tibetan", "Javanese", "Balinese", "Chakma", "Mandaic", "Phags_Pa",
];
const JOINING_SCRIPT = new RegExp(
  "[" + JOINING_SCRIPT_NAMES.map((n) => "\\p{Script_Extensions=" + n + "}").join("") + "]", "u",
);
const EXTENDED_PICTOGRAPHIC = /\p{Extended_Pictographic}/u;
/** Skin tones, variation selectors and the keycap combiner ride inside an emoji sequence. */
const EMOJI_RIDER = /[\u{1F3FB}-\u{1F3FF}\u{FE0F}\u{FE0E}\u{20E3}]/u;
/**
 * Strong right-to-left characters. With none present, UAX #9 reorders nothing.
 *
 * The explicit code points at the end are load-bearing and were missing from the first cut of this
 * change, which an adversarial reviewer refuted with a running bidi implementation. U+200F RIGHT-TO
 * -LEFT MARK is Bidi_Class=R, a STRONG right-to-left character, but its Script is Common, so a
 * Script-only test cannot see it. An RLM in an otherwise pure-ASCII file supplies its own opposing
 * strong run, and a guard that asks "is there strong RTL in scope" while being blind to the very
 * character it is about to exempt answers no and exempts it. Same for U+061C ALM and for the RTL
 * embedding, override and isolate initiators.
 */
const STRONG_RTL =
  /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}\p{Script=Samaritan}\p{Script=Mandaic}\p{Script=Adlam}\u200F\u061C\u202B\u202E\u2067]/u;

/** Where a code point sits, so a rendering function can be decided rather than guessed. */
export interface TextContext {
  /** code point immediately before, or null at start of line */
  previous: number | null;
  /** code point immediately after, or null at end of line */
  next: number | null;
  /** the whole added text, because a directional paragraph spans lines */
  scope: string;
}

const asChar = (cp: number | null): string => (cp === null ? "" : String.fromCodePoint(cp));
const isPictographic = (cp: number | null): boolean => cp !== null && EXTENDED_PICTOGRAPHIC.test(asChar(cp));
const ridesInEmoji = (cp: number | null): boolean => cp !== null && EMOJI_RIDER.test(asChar(cp));
const joinsCursively = (cp: number | null): boolean => cp !== null && JOINING_SCRIPT.test(asChar(cp));

export function hasRenderingFunction(codePoint: number, at: TextContext): boolean {
  // ZWNJ and ZWJ are Join_Control. They control cursive joining and conjunct formation and they
  // build emoji sequences. Between two Latin characters they render nothing at all, which is
  // precisely why an attacker puts one there.
  if (codePoint === 0x200c || codePoint === 0x200d) {
    const left = at.previous, right = at.next;
    const insideEmojiSequence =
      (isPictographic(left) || ridesInEmoji(left)) &&
      (isPictographic(right) || ridesInEmoji(right)) &&
      (isPictographic(left) || isPictographic(right)); // a rider alone is not a base
    if (insideEmojiSequence) return true;
    return joinsCursively(left) && joinsCursively(right);
  }
  // LEFT-TO-RIGHT MARK only, and only in a scope with nothing strong and right-to-left in it.
  //
  // U+200E is Bidi_Class=L. In an all-left-to-right scope it is inert: there is no opposing run for
  // it to resolve a neutral against, so the reordering is the identity and removing it changes
  // nothing a human sees.
  //
  // U+200F and U+061C are NOT included, and the first cut of this change included them. They are
  // Bidi_Class=R, so each supplies the very opposing strong run the exemption is checking for. That
  // costs nothing here: all 51 mark occurrences across the 84 real commits this change was measured
  // on are U+200E.
  if (codePoint === 0x200e) {
    return !STRONG_RTL.test(at.scope);
  }
  return false;
}

const MAX_FINDINGS_PER_FILE = 32;

export interface TrojanFinding {
  path: string;
  /** 1-based line in the added text */
  line: number;
  /** 1-based code point offset within that line */
  column: number;
  codePoint: number;
  label: string;
}

/** The name of the class a code point falls in, or null when it is ordinary text. */
export function classify(codePoint: number, atStartOfText: boolean, at?: TextContext): string | null {
  if (STRUCTURAL.has(codePoint)) return null;
  // The only new line. Absent a context, which is how findPathTrojan calls this, nothing is exempted.
  if (at !== undefined && hasRenderingFunction(codePoint, at)) return null;
  if (codePoint >= 0x202a && codePoint <= 0x202e) return "bidi-control";
  if (codePoint >= 0x2066 && codePoint <= 0x2069) return "bidi-isolate";
  if (codePoint >= 0x200b && codePoint <= 0x200d) return "zero-width";
  if (codePoint === 0x2060) return "word-joiner";
  if (codePoint === 0xfeff) return atStartOfText ? null : "byte-order-mark";
  if (!CONTROL_OR_FORMAT.test(String.fromCodePoint(codePoint))) return null;
  const isControl = codePoint < 0x20 || (codePoint >= 0x7f && codePoint <= 0x9f);
  return isControl ? "control-character" : "format-character";
}

/** `U+202E` for a code point, so a hit names the character rather than describing it. */
export function formatCodePoint(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * Pure. One finding per line and code point, so a file padded with a thousand zero-width spaces
 * produces a readable verdict rather than a thousand hits.
 */
export function findTrojanSource(added: string, path: string): TrojanFinding[] {
  const findings: TrojanFinding[] = [];
  const seen = new Set<string>();
  const lines = added.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    // Indexed rather than for-of so a character's neighbours are reachable. Column still counts
    // code points, exactly as before.
    const chars = [...(lines[index] ?? "")];
    for (let offset = 0; offset < chars.length; offset += 1) {
      const column = offset + 1;
      const codePoint = chars[offset]?.codePointAt(0) ?? 0;
      const label = classify(codePoint, index === 0 && column === 1, {
        previous: offset > 0 ? (chars[offset - 1]?.codePointAt(0) ?? null) : null,
        next: offset + 1 < chars.length ? (chars[offset + 1]?.codePointAt(0) ?? null) : null,
        scope: added,
      });
      if (label === null) continue;
      if (WORKSPACE_ALLOWLIST.has(codePoint)) continue;
      const key = `${index}:${codePoint}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ path, line: index + 1, column, codePoint, label });
      if (findings.length >= MAX_FINDINGS_PER_FILE) return findings;
    }
  }
  return findings;
}

/**
 * The same classes as the content scan, over one path as a single unit rather than as lines.
 *
 * A path legitimately has no newline, so there is no line dimension; a finding names the code
 * point and its 1-based position. Tab, newline and carriage return are scanned here rather than
 * delegated: `isSafeRelative` refuses an absolute path, `..`, `.` and an empty segment, and none
 * of those three is any of them, so a filename carrying one is accepted everywhere downstream.
 */
/**
 * Tab, newline and carriage return frame text but never appear inside a real filename, so the path
 * scan owns them where the content scan deliberately does not. A carriage return is the worst of the
 * three: `evil.sh<CR>safe.txt` returns the cursor to column 0 in any terminal that prints the review
 * queue, so the second half overwrites the first and the row reads `safe.txt`. That is the same
 * deception as a right-to-left override, reached without a single format character. A space is NOT
 * here: `My Document.txt` is an ordinary name.
 */
const PATH_STRUCTURAL: ReadonlyMap<number, string> = new Map([
  [0x09, "tab"],
  [0x0a, "newline"],
  [0x0d, "carriage-return"],
]);

export function findPathTrojan(effectPath: string): { column: number; codePoint: number; label: string }[] {
  const findings: { column: number; codePoint: number; label: string }[] = [];
  const seen = new Set<number>();
  let column = 0;
  for (const ch of effectPath) {
    column += 1;
    const codePoint = ch.codePointAt(0) ?? 0;
    // a BOM anywhere in a PATH is an anomaly, including at position 1, so no start-of-text exemption
    const label = PATH_STRUCTURAL.get(codePoint) ?? classify(codePoint, false);
    if (label === null) continue;
    if (WORKSPACE_ALLOWLIST.has(codePoint)) continue;
    if (seen.has(codePoint)) continue;
    seen.add(codePoint);
    findings.push({ column, codePoint, label });
    if (findings.length >= MAX_FINDINGS_PER_FILE) return findings;
  }
  return findings;
}

export const rule: Rule = {
  name: TROJAN_SOURCE_RULE,
  summary:
    "Bidirectional overrides, isolates and invisible characters in added lines and in the effect's own path, read before any normalising step can erase the evidence.",
  decisions: ["discard"],
  hitIds: ["trojan-source"],
  async run(effects, ctx) {
    const hits: RuleHit[] = [];

    // The path first, over the turn's own effects: a delete or a symlink has no added content to
    // scan but its name is still rendered to the reviewer, and a spoofed name on a delete is as
    // deceptive as one on a create, so scanTargets (content only) cannot carry this. Vendored and
    // outbound effects are skipped for the same reason the content scan skips them: an install is
    // one reviewable unit, not a per-file judgement, and an outbound path is not a filename.
    for (const effect of effects) {
      if (effect.effectClass === DEPENDENCY_CLASS || effect.kind === "outbound") continue;
      for (const found of findPathTrojan(effect.path)) {
        hits.push({
          rule: TROJAN_SOURCE_RULE,
          decision: "discard",
          path: effect.path,
          detail: `${formatCodePoint(found.codePoint)} (${found.label}) in the path at position ${found.column}`,
        });
      }
    }

    const targets = await scanTargets(effects, ctx);
    for (const target of targets) {
      for (const found of findTrojanSource(target.added, target.path)) {
        hits.push({
          rule: TROJAN_SOURCE_RULE,
          decision: "discard",
          path: found.path,
          detail: `${formatCodePoint(found.codePoint)} (${found.label}) at line ${found.line} column ${found.column}`,
        });
      }
    }
    return hits;
  },
};

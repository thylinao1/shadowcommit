import fs from "node:fs/promises";
import path from "node:path";
import type { PolicyContext } from "./policy-types.js";
import { canonicalPath, readBounded, type CaptureLimits } from "./capture.js";
import { isProtectedPath } from "./effect-classifier.js";
import type { ReadWitnessCarrier, ReadWitnessRecord } from "./read-witness.js";

/**
 * Everything the policy is allowed to know, assembled by the side of the boundary that is trusted.
 *
 * The policy is a pure function of an effect set and this context. That split is deliberate: the
 * policy never opens a file, never reads the journal and never probes the host, so every rule can
 * be tested as a function and every bound on what it may read is enforced in one place, here.
 */

/**
 * The protected set every workspace starts with.
 *
 * Written against canonical paths (NFC, case folded), matched with segment-anywhere semantics, so
 * `Customers.jsonl`, `data/customers.jsonl` and a decomposed-accent variant all land on the same
 * rule. `.shadow-commit` is in the list because that directory is where a workspace declares its
 * own protected set: an agent that could edit it could disarm the rule that guards it.
 */
export const DEFAULT_PROTECTED_PATHS: RegExp[] = [
  /(^|\/)customers\.jsonl$/,
  /(^|\/)\.env(\.[\w.-]+)?$/,
  /(^|\/)secrets?(\/|$)/,
  // The hyphen is not load-bearing and must not be. The real directory is `.shadow-commit`
  // (journal-keys.ts:23), and a held-out attack aimed at `.shadowcommit/audit.jsonl` walked past a
  // pattern that demanded the hyphen. The attack named a directory this product does not use, so it
  // is not a live hole, but a protected-path rule that a one-character respelling defeats is a rule
  // that has learned a string rather than a thing. Both spellings, and the audit file whatever it is
  // called inside them.
  /(^|\/)\.shadow-?commit(\/|$)/,
  // The product's own audit trail, and the key that signs it.
  //
  // The claim this platform makes is a tamper-evident record of what every agent did. A turn that
  // rewrites the journal, forges an anchor, or takes the signing key does not merely damage a file:
  // it attacks the evidence that any of the rest of this worked, and it was the one thing the
  // protected set did not defend. `.shadow-commit` was listed and the journal beside it was not.
  //
  // Found by the rule-blind held-out attack set, which is the point of holding attacks out: nobody
  // who wrote the protected list thought to protect the list's own author.
  //
  // The runner keeps these under `dataDirectory` rather than in the workspace, so a turn usually
  // cannot reach them at all. Usually is not a control. This makes the reach a discard wherever a
  // deployment puts the data directory somewhere a turn can see, which the compose file does by
  // mounting ./data into the repository.
  /(^|\/)journal(-[\w.-]+)?\.jsonl$/,
  /(^|\/)anchors\.jsonl$/,
  /(^|\/)(journal|signing)\.key$/,
];

/** Package hosts a manifest or a lockfile may point at without that being an exfiltration route. */
export const DEFAULT_REGISTRY_ALLOWLIST = [
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "static.crates.io",
  "proxy.golang.org",
  "sum.golang.org",
  "repo.maven.apache.org",
  "rubygems.org",
];

/** Where a workspace declares its own protected paths, read from the real side, never the shadow. */
export const PROTECTED_DECLARATION = ".shadow-commit/protected.json";
const MAX_DECLARED_PATTERNS = 200;
const MAX_PATTERN_LENGTH = 200;
/** How far back cumulative-footprint rules may look. */
export const RECENT_TURNS = 10;
export const RECENT_HOURS = 24;
const MAX_RECENT_TOUCHES = 2_000;

/**
 * Reads a workspace's own protected list.
 *
 * Taken from the real workspace, not the sealed copy, so it is the pre-turn declaration: a turn
 * cannot widen or narrow its own guard, because its edit to that file is an effect like any other
 * and lands only if it commits. A pattern that does not compile is skipped rather than fatal, so a
 * typo in one line cannot disable the whole file.
 */
export async function readDeclaredProtectedPaths(workspacePath: string): Promise<RegExp[]> {
  const file = path.join(workspacePath, PROTECTED_DECLARATION);
  const raw = await fs.readFile(file, "utf8").catch(() => null);
  if (raw === null) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  const list = Array.isArray(parsed)
    ? parsed
    : Array.isArray((parsed as { paths?: unknown })?.paths)
      ? (parsed as { paths: unknown[] }).paths
      : [];
  const out: RegExp[] = [];
  for (const entry of list.slice(0, MAX_DECLARED_PATTERNS)) {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > MAX_PATTERN_LENGTH) continue;
    try {
      out.push(new RegExp(entry));
    } catch {
      /* an unparseable pattern is skipped, not fatal */
    }
  }
  return out;
}

const caseProbeCache = new Map<string, boolean>();

/** flips the case of the first cased letter, or null when the name has none to flip */
function caseVariant(name: string): string | null {
  for (let i = 0; i < name.length; i++) {
    const character = name[i]!;
    const flipped = character === character.toLowerCase() ? character.toUpperCase() : character.toLowerCase();
    if (flipped !== character) return name.slice(0, i) + flipped + name.slice(i + 1);
  }
  return null;
}

/**
 * Asks the filesystem, rather than the platform name, whether two spellings are one file.
 *
 * `process.platform === "darwin"` is a guess: APFS can be created case-sensitive, and a Linux host
 * can mount a case-insensitive volume. The answer decides whether a write to `Customers.jsonl`
 * lands on `customers.jsonl`, so it is worth asking the actual mount.
 *
 * The probe prefers a file that is already there, comparing the inode reached by a case variant of
 * its name, because that costs a stat and writes nothing. Only an empty workspace falls back to
 * creating a temporary file, and this runs at seal time, before the baseline snapshot, so a probe
 * file can never be mistaken for something a turn did. One answer per workspace per process.
 */
export async function probeCaseInsensitive(workspacePath: string): Promise<boolean> {
  const cached = caseProbeCache.get(workspacePath);
  if (cached !== undefined) return cached;
  let answer = process.platform === "darwin" || process.platform === "win32";

  const sameFileUnderVariant = async (name: string): Promise<boolean | null> => {
    const variant = caseVariant(name);
    if (!variant) return null;
    const original = await fs.lstat(path.join(workspacePath, name)).catch(() => null);
    if (!original) return null;
    const alias = await fs.stat(path.join(workspacePath, variant)).catch(() => null);
    return alias !== null && alias.dev === original.dev && alias.ino === original.ino;
  };

  const entries = await fs.readdir(workspacePath, { withFileTypes: true }).catch(() => []);
  let decided = false;
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const result = await sameFileUnderVariant(entry.name);
    if (result === null) continue;
    answer = result;
    decided = true;
    break;
  }

  if (!decided) {
    const name = `.shadow-commit-case-probe-${process.pid}-${Date.now()}`;
    try {
      await fs.writeFile(path.join(workspacePath, name), "");
      answer = (await sameFileUnderVariant(name)) ?? answer;
    } catch {
      /* an unwritable workspace falls back to the platform guess */
    } finally {
      await fs.rm(path.join(workspacePath, name), { force: true }).catch(() => undefined);
    }
  }

  caseProbeCache.set(workspacePath, answer);
  return answer;
}

interface CommittingRecord {
  seq?: number;
  kind?: string;
  agentId?: string;
  at?: string;
  effects?: Array<{ path?: string }>;
}

/**
 * The paths this agent committed recently, so a change sliced across turns can be judged on its
 * cumulative footprint rather than on each slice.
 *
 * Read from `turn.committing` records, which are the only journal records that name what actually
 * landed. This is the one place the journal is read for policy input, and it is read as evidence
 * about the past, never as an instruction: the worst a forged line can do is widen the set of paths
 * the policy already treats as touched, which tightens the verdict rather than loosening it.
 */
export async function recentTouchesFor(
  journalPath: string,
  agentId: string,
  now: number = Date.now(),
): Promise<string[]> {
  const text = await fs.readFile(journalPath, "utf8").catch(() => "");
  if (!text) return [];
  const mine: CommittingRecord[] = [];
  for (const line of text.split("\n")) {
    if (!line || !line.includes("turn.committing")) continue;
    try {
      const record = JSON.parse(line) as CommittingRecord;
      if (record.kind === "turn.committing" && record.agentId === agentId) mine.push(record);
    } catch {
      /* torn line, skipped */
    }
  }
  const window = now - RECENT_HOURS * 60 * 60 * 1000;
  const recent = mine
    .slice(-RECENT_TURNS)
    .filter((record) => !record.at || Date.parse(record.at) >= window);
  const paths = new Set<string>();
  for (const record of recent) {
    for (const effect of record.effects ?? []) {
      if (typeof effect.path === "string") paths.add(effect.path);
      if (paths.size >= MAX_RECENT_TOUCHES) return [...paths];
    }
  }
  return [...paths];
}

/**
 * The largest exact line diff this module will run, counted in cells of the comparison table.
 *
 * The reads feeding the diff are already capped at `limits.maxScanBytes` (1 MiB by default), and a
 * megabyte of one-character lines is half a million lines a side, so the byte cap alone does not
 * bound the work: an exact diff is quadratic in the lines it compares. This is the second bound.
 * 250,000 cells is one Int32Array of 1 MB and a few milliseconds of work, and the reductions above
 * the table (a common prefix and suffix, then dropping every line with no counterpart at all) put
 * every one of the 6,711 benign corpus effects below it, the largest table any of them would need
 * being one cell. Past the cap the problem is split on unambiguous lines instead (`matchByAnchors`)
 * and only a stretch with no unambiguous line in it reaches the linear pass.
 *
 * This comment used to end "a file at the read cap therefore costs false positives rather than a
 * hole". That was wrong, and it is worth saying so where the constant is defined rather than
 * anywhere else. Crossing this cap did not degrade the answer, it INVERTED it: finding F-01c put a
 * unique payload line inside repeated boilerplate, which made the payload the only line the anchor
 * pass would pair, so the payload was declared unchanged and the boilerplate was reported in its
 * place. Measured on that shape, 498 boilerplate lines a side is 250,000 cells and the verdict is
 * `discard`; 499 lines is 251,001 cells and the verdict is `commit`. Ninety-nine lines of padding,
 * chosen by the attacker, was the whole of the bypass. The cap is a work bound and nothing else:
 * what makes every path across it safe is `unmovedMatches`, not the cap's position.
 *
 * Cost at the cap, measured on an Apple M2 MacBook Air (8 GB, fanless), node v20, median of the
 * repetitions named in each row, comparing the shipped diff before this change against it after:
 *
 *     unchanged 1 MiB file                                     0.0 ms ->   0.0 ms
 *     one line appended                                        2.6 ms ->   2.5 ms
 *     wholly rewritten                                        13.4 ms ->  12.8 ms
 *     41,184 distinct lines, every line shuffled              74.2 ms -> 106.1 ms
 *     349,525 short lines, every line shuffled               102.7 ms -> 136.6 ms
 *     144,960 max-distinct short lines, every line shuffled  258.8 ms -> 326.9 ms
 *
 * The last row is the worst shape found at the cap and 326.9 ms is the number to plan against, not
 * the 24.6 ms this comment used to carry.
 */
const MAX_DIFF_AREA = 250_000;

/**
 * Which lines of `after` this turn added, as indexes into `after`.
 *
 * "Added" has to mean added AT A POSITION. The first version of this asked whether a line existed
 * anywhere in the pre-turn file, which is set membership, and red team round five walked through
 * it (finding F-01): a turn that moved a `fetch(...).then((t) => new Function(t)())` line out of a
 * dead function and into the live one produced an EMPTY added set, because the line already
 * existed in the dead copy. `scanTargets` skips a file whose added text is empty, so secret-scan,
 * net-to-exec, trojan-source and the idiom scanner all skipped the file and the turn committed.
 * The same bytes in a file with no dead copy were discarded. One set lookup defeated four rules.
 *
 * The version that replaced it computed a MINIMAL EDIT SCRIPT, and that is a different wrong
 * answer. A minimal edit script is obliged to report the CHEAPER of two swapped blocks, so an
 * attacker who makes the payload block the LARGER of the two gets the payload MATCHED and the
 * untouched live code reported in its place (finding F-01b). At a payload of 8 lines against a
 * live block of 5 this is not a tie-break the walk-back can win: every optimal alignment hides the
 * payload, the best alignment that reports it scoring 45 against an optimal 48. A minimal edit
 * script is the right objective for showing a human a patch and the wrong one for deciding what a
 * scanner may look at.
 *
 * What the scanner needs is ANY LINE AT A NEW POSITION IS ADDED, which is strictly stronger. The
 * implementable reading of "new position" is new RELATIVE TO THE LINES THAT SURVIVED AROUND IT:
 * absolute position cannot be it, because one line inserted at the top would then make every line
 * below it added. Two things follow from that reading, and both are enforced in `unmovedMatches`
 * below, on the matcher's output rather than inside any one matcher, so that changing or replacing
 * a matcher cannot quietly reopen either hole:
 *
 *   1. a matched line that some other line relocated ACROSS is reported, which is what makes a
 *      swap report BOTH blocks instead of whichever one the alignment found cheaper
 *   2. a matched line standing ALONE at a shifted position is reported, because one line agreeing
 *      across a gap is the weakest evidence a diff has and it is exactly what the anchor pass
 *      believed in finding F-01c
 *
 * Over-reporting is the safe direction and it is a real cost, not a free one: a line wrongly called
 * added costs a scan and possibly a false abort, a line wrongly called unchanged costs the whole
 * control. The cost is measured in the test file beside this one and in the report of the change.
 *
 * Four steps, cheapest first, each one shrinking what the next has to look at:
 *
 *   1. the common prefix and suffix, which is the part of the file the turn did not touch
 *   2. every remaining line with no counterpart at all on the other side, which can never match
 *   3. an exact longest-common-subsequence over what is left, or a bounded pass when that is too big
 *   4. the displacement audit above, which takes matches back off the matcher
 */
function addedLineIndexes(before: readonly string[], after: readonly string[]): number[] {
  const shorter = Math.min(before.length, after.length);
  let head = 0;
  while (head < shorter && before[head] === after[head]) head++;
  let tail = 0;
  while (
    tail < shorter - head &&
    before[before.length - 1 - tail] === after[after.length - 1 - tail]
  ) {
    tail++;
  }

  const midBefore = before.slice(head, before.length - tail);
  const midAfter = after.slice(head, after.length - tail);
  if (midAfter.length === 0) return [];
  if (midBefore.length === 0) return midAfter.map((_, index) => head + index);

  // Start from "every changed line is added" and let the matcher take lines back out. A matcher
  // that gives up part way therefore leaves lines marked added, which is the direction that costs
  // a false alarm instead of a miss.
  const isAdded = new Uint8Array(midAfter.length).fill(1);

  // A line that appears nowhere on the other side cannot be part of any match, so it never needs
  // to enter the table. On a normal edit this alone empties the table: the lines a turn wrote are
  // new text, and the lines it deleted are gone.
  //
  // Both sides keep their positions, because the displacement audit needs to know where a
  // candidate sat in the file and not merely where it sat among the other candidates. A line
  // dropped here can never be shared content: it exists on one side only, so it cannot be a line
  // that relocated, and leaving it out of the audit costs nothing.
  const beforeLines = new Set(midBefore);
  const afterLines = new Set(midAfter);
  const candidateAfterAt: number[] = [];
  const candidateAfter: string[] = [];
  for (let index = 0; index < midAfter.length; index++) {
    const line = midAfter[index]!;
    if (!beforeLines.has(line)) continue;
    candidateAfterAt.push(index);
    candidateAfter.push(line);
  }
  const candidateBeforeAt: number[] = [];
  const candidateBefore: string[] = [];
  for (let index = 0; index < midBefore.length; index++) {
    const line = midBefore[index]!;
    if (!afterLines.has(line)) continue;
    candidateBeforeAt.push(index);
    candidateBefore.push(line);
  }

  if (candidateAfter.length > 0 && candidateBefore.length > 0) {
    const alignment = matchLines(candidateBefore, candidateAfter, 0);
    const unmoved = unmovedMatches(
      alignment,
      candidateBefore,
      candidateAfter,
      candidateBeforeAt,
      candidateAfterAt,
    );
    for (let pair = 0; pair < unmoved.length; pair++) {
      if (unmoved[pair] === 1) isAdded[candidateAfterAt[alignment.after[pair]!]!] = 0;
    }
  }

  const added: number[] = [];
  for (let index = 0; index < isAdded.length; index++) {
    if (isAdded[index] === 1) added.push(head + index);
  }
  return added;
}

/**
 * A matcher's answer: `before[k]` is the line `after[k]` was matched to. Both are strictly
 * increasing, because every matcher here aligns rather than pairs arbitrarily.
 *
 * The matchers used to return the `after` indexes alone. The displacement audit needs the pairing,
 * because "did this line move" is a question about the two positions and not about either one.
 */
interface Alignment {
  before: number[];
  after: number[];
}

/**
 * Take back every match the alignment made that does not survive "a line at a new position is
 * added". Returns 1 for a pair to keep, 0 for a pair whose `after` line goes back to being added.
 *
 * This runs on the matcher's OUTPUT, not inside a matcher, and that placement is the point. The
 * two bypasses this closes arrived through two different matchers (the exact table hid a swapped
 * block, the anchor pass hid a lone unique line) and a third matcher, `matchGreedily`, hides the
 * same lone line the anchor pass did, so a fix inside either one of them would have left the hole
 * open through the other two. Anything that can produce a pairing is audited here.
 *
 * CHECK ONE, a line that something relocated across. If a line's content sits ABOVE this pair on
 * one side and BELOW it on the other, that content crossed this pair, so this pair moved relative
 * to it. Requiring the content to be IDENTICAL rather than merely counting deletions above and
 * insertions below is what keeps this affordable: deleting a line at the top of a file and adding
 * a different one at the bottom is an ordinary edit and reports nothing extra, while a genuine
 * reorder reports both of its sides. It is also what makes a swap safe at every ratio, since
 * whichever block the alignment matched, the other one is the content that crossed it.
 *
 * CHECK TWO, a match standing alone at a shifted position. A pair whose two indexes are equal is
 * at the same place it was and is kept whatever else happened in the file. A pair at a shifted
 * position is kept only if an immediately adjacent line matched at the same shift, so a run of two
 * or more carries itself and a single line agreeing across a gap does not. This is the anchor
 * hardening the review asked for, generalised off the anchor pass: applied only to anchors it
 * would have moved F-01c from `matchByAnchors` to `matchGreedily`, which reproduces it exactly.
 *
 * Neither check subsumes the other. A swapped block of eight lines is a run, so check two keeps it
 * and check one reports it; a lone relocated line across a wholly rewritten span has no content
 * crossing it, so check one keeps it and check two reports it.
 */
function unmovedMatches(
  alignment: Alignment,
  before: readonly string[],
  after: readonly string[],
  beforeAt: readonly number[],
  afterAt: readonly number[],
): Uint8Array {
  const pairs = alignment.before.length;
  const unmoved = new Uint8Array(pairs).fill(1);
  if (pairs === 0) return unmoved;

  const matchedBefore = new Uint8Array(before.length);
  const matchedAfter = new Uint8Array(after.length);
  for (let pair = 0; pair < pairs; pair++) {
    matchedBefore[alignment.before[pair]!] = 1;
    matchedAfter[alignment.after[pair]!] = 1;
  }

  // Check one, both ways round: content deleted above a pair and re-inserted below it, and content
  // inserted above a pair that was deleted below it. One direction alone would catch a block that
  // moved up and miss the same block moving down.
  markCrossed(unmoved, before, matchedBefore, alignment.before, after, matchedAfter, alignment.after);
  markCrossed(unmoved, after, matchedAfter, alignment.after, before, matchedBefore, alignment.before);

  // Check two. `beforeAt`/`afterAt` put a candidate back where it sits in the file, which is what
  // "the same position" and "immediately adjacent" have to be measured in: two candidates can be
  // neighbours in the candidate list with fifty dropped lines between them in the file.
  const lineOfBefore = (pair: number): number => beforeAt[alignment.before[pair]!]!;
  const lineOfAfter = (pair: number): number => afterAt[alignment.after[pair]!]!;
  const runsWith = (pair: number, neighbour: number): boolean =>
    neighbour >= 0 &&
    neighbour < pairs &&
    Math.abs(lineOfBefore(neighbour) - lineOfBefore(pair)) === 1 &&
    Math.abs(lineOfAfter(neighbour) - lineOfAfter(pair)) === 1;
  for (let pair = 0; pair < pairs; pair++) {
    if (lineOfAfter(pair) === lineOfBefore(pair)) continue;
    if (runsWith(pair, pair - 1) || runsWith(pair, pair + 1)) continue;
    unmoved[pair] = 0;
  }

  return unmoved;
}

/**
 * Check one, in one direction: unreport every pair that a line crossed going from the `above` side
 * to the `below` side.
 *
 * Two multisets swept in one pass, which is what keeps this linear rather than quadratic in the
 * pairs. `above` accumulates the unmatched lines of one side as the sweep descends past them;
 * `below` starts holding every unmatched line of the other side and gives them up as the sweep
 * passes them. `shared` counts the values currently in both, so the test at each pair is a
 * comparison against zero rather than a set intersection.
 */
function markCrossed(
  unmoved: Uint8Array,
  aboveLines: readonly string[],
  aboveMatched: Uint8Array,
  abovePairIndexes: readonly number[],
  belowLines: readonly string[],
  belowMatched: Uint8Array,
  belowPairIndexes: readonly number[],
): void {
  const above = new Map<string, number>();
  const below = new Map<string, number>();
  for (let index = 0; index < belowLines.length; index++) {
    if (belowMatched[index] === 1) continue;
    const line = belowLines[index]!;
    below.set(line, (below.get(line) ?? 0) + 1);
  }

  let shared = 0;
  let aboveCursor = 0;
  let belowCursor = 0;
  for (let pair = 0; pair < unmoved.length; pair++) {
    for (; aboveCursor < abovePairIndexes[pair]!; aboveCursor++) {
      if (aboveMatched[aboveCursor] === 1) continue;
      const line = aboveLines[aboveCursor]!;
      const held = above.get(line) ?? 0;
      above.set(line, held + 1);
      if (held === 0 && (below.get(line) ?? 0) > 0) shared++;
    }
    for (; belowCursor <= belowPairIndexes[pair]!; belowCursor++) {
      if (belowMatched[belowCursor] === 1) continue;
      const line = belowLines[belowCursor]!;
      const left = (below.get(line) ?? 0) - 1;
      below.set(line, left);
      if (left === 0 && (above.get(line) ?? 0) > 0) shared--;
    }
    if (shared > 0) unmoved[pair] = 0;
  }
}

/** Anchor passes before the linear pass takes over, so a pathological file still terminates. */
const MAX_ANCHOR_DEPTH = 16;

/**
 * Match two line sequences, picking the method the size of the problem can afford.
 *
 * Exact while the comparison table fits the bound. Past it, split the problem on the lines that
 * appear exactly once on each side, which are the only pairings no diff could disagree about, and
 * solve the gaps between them, which are small. Only a stretch with no unambiguous line anywhere
 * in it, and only after `MAX_ANCHOR_DEPTH` splits, falls through to the linear pass.
 *
 * None of the three is trusted to have got the answer right. Whatever comes back is audited by
 * `unmovedMatches`, which is where the security property lives; this function only decides how
 * much work to spend looking for matches in the first place.
 */
function matchLines(before: readonly string[], after: readonly string[], depth: number): Alignment {
  if (before.length === 0 || after.length === 0) return { before: [], after: [] };
  if ((before.length + 1) * (after.length + 1) <= MAX_DIFF_AREA) {
    return matchByLongestSubsequence(before, after);
  }
  if (depth >= MAX_ANCHOR_DEPTH) return matchGreedily(before, after);
  return matchByAnchors(before, after, depth);
}

/**
 * Split a large diff on the lines that occur exactly once on each side.
 *
 * Without this the fallback for a large file was one forward pass that took the earliest occurrence
 * of each line, and that pass is directional. Measured on an 8,000 line file of unique lines, a
 * five line block moved FORWARD reported 5 lines added and the same block moved BACKWARD reported
 * 4,800: the pass consumed the whole span it had been moved over and called every line of it new.
 * A rule set fed 4,800 lines of untouched code is a false alarm generator, so the fallback had to
 * align rather than guess.
 *
 * A line appearing once on each side is the one pairing no diff can argue with. Taking the longest
 * increasing run of those pairings gives an alignment in O(n log n), and the stretches between the
 * anchors are small enough for the exact table.
 *
 * "The one pairing no diff can argue with" is true of a diff and false of a scanner, which is
 * finding F-01c: a payload line that is unique inside repeated boilerplate is the ONLY line here
 * eligible to anchor, so it anchors across the whole file and is declared unchanged while the
 * boilerplate is reported in its place. The pairing is not wrong, it is just not evidence that the
 * line stayed put, and `unmovedMatches` is what decides that question now.
 */
function matchByAnchors(before: readonly string[], after: readonly string[], depth: number): Alignment {
  const unique = (lines: readonly string[]): Map<string, number> => {
    const at = new Map<string, number>();
    const seen = new Set<string>();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (seen.has(line)) at.delete(line);
      else {
        seen.add(line);
        at.set(line, i);
      }
    }
    return at;
  };
  const beforeAt = unique(before);
  const afterAt = unique(after);
  const pairs: Array<{ before: number; after: number }> = [];
  for (const [line, afterIndex] of afterAt) {
    const beforeIndex = beforeAt.get(line);
    if (beforeIndex !== undefined) pairs.push({ before: beforeIndex, after: afterIndex });
  }
  pairs.sort((one, other) => one.after - other.after);
  const keep = longestIncreasingRun(pairs.map((pair) => pair.before));
  if (keep.length === 0) return matchGreedily(before, after);

  const matched: Alignment = { before: [], after: [] };
  const gap = (beforeLo: number, beforeHi: number, afterLo: number, afterHi: number): void => {
    if (beforeHi <= beforeLo || afterHi <= afterLo) return;
    const inner = matchLines(
      before.slice(beforeLo, beforeHi),
      after.slice(afterLo, afterHi),
      depth + 1,
    );
    for (let i = 0; i < inner.after.length; i++) {
      matched.before.push(beforeLo + inner.before[i]!);
      matched.after.push(afterLo + inner.after[i]!);
    }
  };
  let beforeLo = 0;
  let afterLo = 0;
  for (const index of keep) {
    const pair = pairs[index]!;
    gap(beforeLo, pair.before, afterLo, pair.after);
    matched.before.push(pair.before);
    matched.after.push(pair.after);
    beforeLo = pair.before + 1;
    afterLo = pair.after + 1;
  }
  gap(beforeLo, before.length, afterLo, after.length);
  return matched;
}

/** Indexes of a longest strictly increasing subsequence, by patience sorting. */
function longestIncreasingRun(values: readonly number[]): number[] {
  const tails: number[] = [];
  const previous = new Int32Array(values.length).fill(-1);
  for (let i = 0; i < values.length; i++) {
    let low = 0;
    let high = tails.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (values[tails[middle]!]! < values[i]!) low = middle + 1;
      else high = middle;
    }
    if (low > 0) previous[i] = tails[low - 1]!;
    if (low === tails.length) tails.push(i);
    else tails[low] = i;
  }
  const out: number[] = [];
  let at = tails.length === 0 ? -1 : tails[tails.length - 1]!;
  while (at !== -1) {
    out.push(at);
    at = previous[at]!;
  }
  return out.reverse();
}

/**
 * Exact longest common subsequence, returning the pairs a match covers.
 *
 * Bounded by its caller at `MAX_DIFF_AREA` cells, which is what makes an O(n*m) table safe here.
 * The table is filled from the end so the walk back out of it runs forward, which keeps the
 * matched indexes in ascending order without a sort.
 *
 * Exact here means exact about the EDIT SCRIPT, which is not the same as right about what moved,
 * and the difference is finding F-01b. Nothing downstream may assume this answer is safe on its
 * own; `unmovedMatches` is what makes it safe.
 */
function matchByLongestSubsequence(before: readonly string[], after: readonly string[]): Alignment {
  const rows = before.length;
  const columns = after.length;
  const width = columns + 1;
  const table = new Int32Array((rows + 1) * width);
  for (let i = rows - 1; i >= 0; i--) {
    const row = i * width;
    const next = row + width;
    for (let j = columns - 1; j >= 0; j--) {
      table[row + j] =
        before[i] === after[j]
          ? table[next + j + 1]! + 1
          : Math.max(table[next + j]!, table[row + j + 1]!);
    }
  }
  const matched: Alignment = { before: [], after: [] };
  let i = 0;
  let j = 0;
  while (i < rows && j < columns) {
    if (before[i] === after[j]) {
      matched.before.push(i);
      matched.after.push(j);
      i++;
      j++;
    } else if (table[(i + 1) * width + j]! >= table[i * width + j + 1]!) {
      i++;
    } else {
      j++;
    }
  }
  return matched;
}

/**
 * The bound's fallback: one forward pass that matches each line of `after` to the earliest
 * still-unused occurrence of it in `before`.
 *
 * What it returns is a common subsequence, not the longest one, so it never matches more lines
 * than the exact diff and therefore never reports fewer lines as added. That asymmetry is the whole
 * reason it is the fallback: the shape it cannot align gets scanned too eagerly, not too little.
 * Every per-line cursor only moves forward, so the pass is linear in the two inputs.
 *
 * Fewer matches is not the same as safer matches. This pass will happily pair a lone line across
 * the whole file, which is F-01c under a different matcher, so its output is audited like the rest.
 */
function matchGreedily(before: readonly string[], after: readonly string[]): Alignment {
  const positions = new Map<string, number[]>();
  for (let i = 0; i < before.length; i++) {
    const line = before[i]!;
    const list = positions.get(line);
    if (list === undefined) positions.set(line, [i]);
    else list.push(i);
  }
  const consumed = new Map<string, number>();
  const matched: Alignment = { before: [], after: [] };
  let cursor = 0;
  for (let j = 0; j < after.length; j++) {
    const line = after[j]!;
    const list = positions.get(line);
    if (list === undefined) continue;
    let at = consumed.get(line) ?? 0;
    while (at < list.length && list[at]! < cursor) at++;
    consumed.set(line, at);
    if (at >= list.length) continue;
    matched.before.push(list[at]!);
    matched.after.push(j);
    cursor = list[at]! + 1;
    consumed.set(line, at + 1);
  }
  return matched;
}

/**
 * The text a turn added to one file: the post-turn body when there is no pre-turn file, otherwise
 * the lines of the post-turn body that a positional diff calls insertions, joined back together.
 *
 * Exported because it is the whole of the decision. A closure inside `buildPolicyContext` can only
 * be tested through a temporary directory, and this is the function four rules depend on for
 * knowing what they are allowed to look at.
 */
export function addedLinesBetween(before: string | null, after: string): string {
  if (after.length === 0) return "";
  if (before === null) return after;
  if (before === after) return "";
  const afterLines = after.split("\n");
  const indexes = addedLineIndexes(before.split("\n"), afterLines);
  let out = "";
  for (let i = 0; i < indexes.length; i++) {
    if (i > 0) out += "\n";
    out += afterLines[indexes[i]!]!;
  }
  return out;
}

export interface ContextInput {
  shadowDir: string;
  mechanism: "overlay" | "copy";
  workspacePath: string;
  journalPath: string;
  agentId: string;
  taskPrompt?: string | undefined;
  limits: CaptureLimits;
  platformSecrets: string[];
  registryAllowlist: string[];
  /** dev:ino of every real path at seal, so protected identity survives a rename or a case variant */
  realInodes: Map<string, string>;
  /**
   * What the turn OPENED, when the mechanism could be watched.
   *
   * The effect set is a comparison of two end states, so a read leaves no trace in it: a turn that
   * opens every credential in the sealed view and writes nothing hands the policy an empty array.
   * `read-witness.ts` records the reads on the trusted side instead, off the access times of the
   * sealed copy, and `rules/read-exposure.ts` is the one rule that judges them.
   *
   * It is a context field and NOT an `EffectRecord`, which is the same decision `read-witness.ts`
   * documents at `attachReadWitness`: putting a read into the effect array would put it in front of
   * sixteen rules written about writes, and `protected-asset-write` would start discarding turns
   * over a file nobody wrote.
   *
   * Three states, kept apart all the way to the rule. Absent or null is "this turn produced no
   * witness", which is what the overlay mechanism produces and what every caller that does not arm
   * anything produces. A record with `supported: false` is "this mount cannot show reads". Only a
   * supported record with `reads: 0` says the turn read nothing.
   *
   * `transactional-runner.ts` collects the report AFTER the agent and BEFORE capture (capture hashes
   * every file, and a hash is a read), so on the live path it attaches the summary itself once it
   * has one. This input is for every other caller of this builder: a harness, a test, or a future
   * settle path that already holds the record when it builds the context.
   */
  readWitness?: ReadWitnessRecord | null | undefined;
}

/** The directory holding this turn's version of a file: `upper` under overlay, `merged` under a copy. */
export function shadowFileOf(shadowDir: string, mechanism: "overlay" | "copy", rel: string): string {
  return path.join(shadowDir, mechanism === "overlay" ? "upper" : "merged", rel);
}

export async function buildPolicyContext(
  input: ContextInput,
): Promise<PolicyContext & ReadWitnessCarrier> {
  const {
    shadowDir,
    mechanism,
    workspacePath,
    journalPath,
    agentId,
    limits,
    platformSecrets,
    registryAllowlist,
    realInodes,
  } = input;

  const declared = await readDeclaredProtectedPaths(workspacePath);
  const protectedPaths = [...DEFAULT_PROTECTED_PATHS, ...declared];

  // Identity, not spelling: every real path that matches the protected set contributes its inode,
  // so a modify or delete reached under a different name is still recognisably the same file.
  const protectedInodes = new Set<string>();
  for (const [rel, ino] of realInodes) {
    if (isProtectedPath(canonicalPath(rel), protectedPaths)) protectedInodes.add(ino);
  }

  const shadowOf = (rel: string) => shadowFileOf(shadowDir, mechanism, rel);
  const realOf = (rel: string) => path.join(workspacePath, rel);

  /**
   * One read per path per turn, for each of the three readers below.
   *
   * A context is built once per turn (`transactional-runner.ts` at turn open, at settle and on the
   * held path) and every rule judging that turn shares it. The shadow tree and the real tree are
   * both frozen for the whole of judgement: the agent has already finished, and nothing writes to
   * either until the commit or discard that follows. So a second read of the same path in the same
   * turn cannot return anything different from the first, and caching it changes no decision.
   *
   * Measured before caching, on a ten-effect turn: `addedLinesOf` was called four times for every
   * effect, once by each rule that asks what a file gained, and each call read BOTH sides off disk
   * and re-split them. That is ten file reads and four identical line-diffs per effect, and it made
   * policy judgement cost a flat ~5 ms per effect on the measuring host, growing without bound in
   * the size of the effect set. The work was always redundant; nothing needed the repetition.
   *
   * The promise is cached rather than its value, so two rules asking for the same path at the same
   * time share one read instead of racing to start two.
   */
  const once = <T>(fn: (rel: string) => Promise<T>): ((rel: string) => Promise<T>) => {
    const cache = new Map<string, Promise<T>>();
    return (rel: string): Promise<T> => {
      const hit = cache.get(rel);
      if (hit !== undefined) return hit;
      const started = fn(rel);
      cache.set(rel, started);
      return started;
    };
  };

  const contentOf = once(
    async (rel: string): Promise<string> =>
      (await readBounded(shadowOf(rel), limits.maxScanBytes)) ?? "",
  );

  const realContentOf = once(
    async (rel: string): Promise<string | null> => readBounded(realOf(rel), limits.maxScanBytes),
  );

  /**
   * The lines this turn added: present in the shadow copy, absent from the real file. For a file
   * the turn created there is no real side, so the whole (bounded) body is added. Scanning added
   * lines rather than whole files is what stops a pre-existing example credential in a vendored
   * dependency from reading as this turn's secret.
   */
  const addedLinesOf = once(async (rel: string): Promise<string> =>
    addedLinesBetween(await realContentOf(rel), await contentOf(rel)),
  );

  return {
    contentOf,
    addedLinesOf,
    realContentOf,
    // Authorization asks "was this agent allowed to touch this", which is a question about the
    // agent, not about the bytes. Without this the capability rule cannot tell one agent's grant
    // from another's and fails closed on every non-empty effect set.
    agentId,
    recentTouches: await recentTouchesFor(journalPath, agentId),
    ...(input.taskPrompt === undefined ? {} : { taskPrompt: input.taskPrompt }),
    protectedPaths,
    protectedInodes,
    caseInsensitiveHost: await probeCaseInsensitive(workspacePath),
    platformSecrets: platformSecrets.filter((value) => value.length > 0),
    registryAllowlist,
    // Always present, never undefined. `readWitnessOf` treats absent and null alike, but a field
    // that is sometimes missing is a field a reader has to guess about, and the three states this
    // carries are exactly the ones nobody may guess at.
    readWitness: input.readWitness ?? null,
  };
}

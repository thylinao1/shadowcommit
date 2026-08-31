#!/usr/bin/env node
/**
 * check-figures.mjs: every published figure still matches the measurement.
 *
 *   node research/corpus/check-figures.mjs            # the gate: report and exit non-zero on drift
 *   node research/corpus/check-figures.mjs --list     # what is guarded, what is not, and why
 *   node research/corpus/check-figures.mjs --audit    # every figure this finds, match by match
 *   node research/corpus/check-figures.mjs --sweep    # mutate every published figure in memory and
 *                                                     # report what this gate catches and misses
 *   node research/corpus/check-figures.mjs --floors   # print the FLOORS table this file should carry
 *
 * WHY THIS EXISTS. When the corpus moved from 165 misses to 149, the only two documents that ended
 * up correct were the two `check.sh` stage 9 already guarded: `docs/CORPUS-REPORT.md` and
 * `research/corpus/REPORT.md`. Every unguarded document was stale, and one of them, `README.md`,
 * contradicted itself seventeen lines apart. An internal review record documented the same
 * drift one batch earlier, at 1175 held against today's 1207. A figure is only as fresh as the gate
 * that reads it, so this reads them all against one source of truth.
 *
 * THE SOURCE OF TRUTH is `results/report-metrics.json`, written by `report.mjs` from the raw
 * `results/results.jsonl` rows. Nothing here is hardcoded from a document: the miss count, the
 * denominators, the held count and both macro-averages are all derived below, so when the corpus
 * moves this script re-targets itself and every guarded document is re-read against the new truth.
 *
 * IT REPORTS AND FAILS. IT NEVER WRITES. There is no `fs.write` in this file and there must never
 * be one, `--sweep` included: the sweep mutates a copy of a document in memory and throws it away.
 * `check.sh` stage 9 learned this the expensive way: it used to `cp REPORT.md` over the shipped page
 * inside its own failure branch, so the first run repaired the thing it was comparing against and
 * the second run passed whether or not a human had looked at what changed. A gate that repairs what
 * it checks certifies itself. Updating a document is a deliberate act by somebody who read the diff.
 *
 * WHY AN ALLOWLIST AND NOT A MARKER LINE. The alternative was a marker line ("HISTORICAL, pinned at
 * <commit>") carried by every document that is a record rather than a claim. It was rejected for
 * three reasons. (1) It fails open: a new live document that forgets the marker is guarded, which is
 * right, but a new live document that copies a nearby header wholesale inherits the marker and is
 * silently exempt, which is the same self-certification defect wearing a different hat. (2) It puts
 * the decision in files this gate does not own, so getting a document guarded means editing that
 * document, and commit-pinned internal records of what was
 * true at a past commit, where editing anything at all is falsifying the record. (3) The allowlist
 * fails closed and fails visibly: a document is guarded because a line here names it, and adding the
 * next one is that one line, below, with a reason beside it.
 *
 * HOW A GUARDED PAGE QUOTES A FIGURE IT HAS RETIRED. A live page often needs to state an old number
 * on purpose. `research/METRICS.md` keeps the macro sentence it retracted; `README.md` says in so
 * many words that the paragraph used to read 9.7% against a 5.2% headline; `research/LEAKAGE-PROOF.md`
 * says the regeneration moved the headline from 5.22 percent to 4.71 percent. A gate that cannot
 * tell a retired figure from a live one either fires on all three or gets switched off, so there are
 * exactly two fences, and BOTH ARE COUNTED AND PRINTED rather than applied in silence:
 *
 *   quoted     the figure sits inside double quotes, so the sentence is reproducing somebody's words.
 *   retracted  the figure's own sentence carries an explicit retraction cue from the closed list in
 *              RETRACTION_CUES below ("used to", "previously", "at 165 misses", "moved from X to Y").
 *
 * The cue must be in the same sentence as the figure, not merely the same paragraph, because a
 * paragraph-wide cue would exempt the live figure sitting next to the retired one. Every fenced
 * figure is counted in the pass line and listed by `--audit`, which is the part that matters: a
 * silent exemption is an exemption nobody audits, and the count going up is the thing a reviewer
 * notices. Both fences can be abused by a writer who wraps a live stale figure in false history.
 * That is a deliberate misstatement rather than drift, this is a drift gate, and the counting is
 * what makes the abuse visible.
 *
 * DECLARED SITES, AND THE SPRING ON THEM. Documents drift in files a given lane may not edit. Those
 * sites are declared one by one in DECLARED below, with the file, the stale value, the sentence they
 * live in and the reason. They print in full on every run and do not fail the build. The spring is
 * that a declaration whose sentence has gone FAILS, demanding the declaration be deleted, so the
 * waiting room drains itself and cannot become a permanent exemption. The same spring runs over
 * PENDING files: an entry there carries the full list of its known stale sentences, including the
 * ones no rule here matches, and the file may only be promoted to GUARDED when every one of them is
 * gone. Without that list a lane could fix the two sites the regexes see, be told "no drift left,
 * promote this", and certify five stale sentences nobody looked at.
 *
 * WHAT IT CATCHES AND WHAT IT DOES NOT. Measured, not asserted, by `--sweep`: it rewrites every
 * published figure in every guarded document, one token at a time, twice. Once to the value that
 * figure held in the previous corpus batch, which is the drift this repository actually produces,
 * and once to an arbitrary wrong value, which is harder because no list of retired numbers can see
 * it. Re-measured on 2026-08-31 with research/RED-TEAM-ROUND-5.md promoted out of PENDING, over 203
 * swept sites in the eight guarded documents, against the same run over the seven guarded before it:
 *
 *   rollback   153 caught, 50 missed      (140 caught, 41 missed over 181 sites, seven documents)
 *   arbitrary  140 caught, 63 missed      (131 caught, 50 missed over the same 181)
 *
 * The percentage falls and the gate still got stronger, so read the counts and not the rate. The
 * promotion added 22 swept sites; a rollback catches 13 of them and misses 9, which is below the
 * standing average, so the overall rate goes 77 percent to 75 while 13 more real drift sites are
 * caught than were caught an hour earlier. A page that publishes bare counts drags the rate down by
 * arriving, and refusing to guard it to protect the number would be the gate grading itself.
 *
 * That measurement covered eight documents and the guarded set is ten as this is written:
 * docs/DESIGN-CASE.md and research/queue/NARROWING.md were guarded after the sweep was taken, so
 * the two rows above are pinned to the eight and do not describe today's set. Re-run --sweep.
 *
 * Both rows move whenever any guarded document is corrected, so this is a snapshot and not a
 * standing property. research/LEAKAGE-PROOF.md carries open drift as this is written and belongs to
 * another lane; re-run `--sweep` once that lands rather than trusting this tally.
 *
 * The 50 missed on a rollback are three figures and five leftovers. `5000` and `5,000` account for
 * 28, `3161` and `3,161` for 10, `63` for 7, which is 45 of the 50: the two denominators written in
 * a shape no rule can anchor, and the false-abort count, the one published figure too short to clear
 * the three-digit bar every count rule needs. Six of those 28 are a coincidence rather than a gap:
 * research/RED-TEAM-ROUND-5.md writes `MAX_LINES = 5000` and "past line 5000" about a scanner's cut,
 * so rewriting them states nothing false, the same case as research/METRICS.md:178 in class 5 below.
 * The last 5 are single sites: `3.64` twice in unanchored prose, and `1.3`, `17.3` and `17.26` where
 * the sentence names them as a pair or as points of false alarm rather than as a rate. The classes
 * below are the reasoning behind those decisions and still stand; their per-class counts are from
 * the 2026-08-30 measurement, so read them as the shape rather than as the tally.
 *
 * One thing besides the corrections moved the rate up over this stretch: `afterWrapped` let the
 * reversed rules survive a hard wrap, which had been silently un-guarding sentences depending on
 * where the line happened to break.
 *
 * The first version of this file scored 65 caught on both, measured the same way, over the 210
 * sites that existed at that time. The classes it misses on a rollback, largest first.
 * Each is a decision, not an oversight:
 *
 *   1. COLUMN CONSTANTS IN THE SWEEP TABLES (29 sites, all in research/METRICS.md). The knee and
 *      per-organisation tables repeat 1.30, 1207 and 24.14 down a column, one row per rule set. A
 *      regex reads one cell and cannot tell a column constant from a coincidence. Those tables are
 *      output from research/overhead/measure-metrics.mjs, and the fix is to guard that generator's
 *      own hardcoded expectations, which is a file another lane owns this run.
 *   2. THE FALSE-ABORT COUNT IS TWO DIGITS (20 sites). Every count rule here needs three digits or
 *      a thousands comma, because a two-digit rule fires on every column of every table in these
 *      pages. 65 is the one published figure that cannot clear that bar, so it is caught only where
 *      it is written over its denominator, as 65/5000.
 *   3. A DENOMINATOR IN A SHAPE WITH NO ANCHOR (9 sites). "and 5,000 benign", "benign 5000" as a
 *      row label, "3161 rows are 14 families". An anchor on "rows" would read "8190 rows" as the
 *      attack denominator, and "<count> benign turns" is how the held count is written too, so the
 *      total is only recognisable behind "all" or "of the".
 *   4. A BARE PERCENT IN UNANCHORED PROSE (about 12 sites, mostly research/LEAKAGE-PROOF.md). The
 *      anchored rules need a phrase naming the quantity within 40 characters and superseded-value
 *      needs a corpus word within the same distance. "The honest statement of the same result is
 *      4.7 percent" has neither. Widening the window was measured and rejected: at 80 characters an
 *      anchored rule reached across a clause and graded an unrelated 95.3 percent as the headline.
 *      A rollback here is caught by superseded-value; an invented number is not, which is most of
 *      the gap between the two sweep rows above.
 *   5. FENCED SITES (4) and one coincidence. The fences cost coverage on purpose, and one is worth
 *      naming: apps/server/src/bench/RESULTS.md:125 says "this section previously offered ... as
 *      proof that large-blast-radius fires in none of the 5,000 benign scenarios", so the sentence
 *      retracts a claim while its numbers stay live and the cue fences them. The repository's own
 *      <!-- retracted:BEGIN --> regions are deliberately NOT fences for the mirror-image reason:
 *      RESULTS.md:168 states the live 24.1% inside one. The coincidence is research/METRICS.md:178,
 *      where a per-rule count happens to equal 149; rewriting it states nothing false.
 *
 * RELATIONAL SENTENCES are outside all of this and always will be. "Nearly double the headline",
 * "the worst family is X", "one family is a third of the denominator": no regex here reads English
 * arithmetic, and each of those survives a correct digit swap while staying false. The failure text
 * says so on every failure, because that is the one place a person is guaranteed to read it.
 *
 * The FLOORS table is what stops classes 3 and 4 growing unnoticed. It records how many times each
 * rule currently matches in each guarded document and fails when a count drops. Rewording a figure
 * into a shape no rule reads, deleting it, or corrupting a denominator so the ratio rule stops
 * matching all read as a drop, so the gate cannot be quietened by making it match less.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");
const METRICS_JSON = path.join(HERE, "results", "report-metrics.json");

/* ------------------------------------------------------------------ the truth */

function loadTruth() {
  if (!fs.existsSync(METRICS_JSON)) {
    fail(`${rel(METRICS_JSON)} is missing. Run: node research/corpus/report.mjs --label after`);
  }
  const m = JSON.parse(fs.readFileSync(METRICS_JSON, "utf8"));
  const ratio = (s, what) => {
    const hit = /^(\d+)\/(\d+)$/.exec(String(s ?? ""));
    if (!hit) fail(`report-metrics.json headline.${what} is ${JSON.stringify(s)}, expected "k/n".`);
    return { k: Number(hit[1]), n: Number(hit[2]) };
  };

  const miss = ratio(m.headline?.attack_miss, "attack_miss");
  const contained = ratio(m.headline?.attack_contained, "attack_contained");
  const abort = ratio(m.headline?.benign_false_abort, "benign_false_abort");
  const held = Number(m.headline?.benign_human_ask);
  const families = Array.isArray(m.families) ? m.families : [];

  // A gate comparing documents against an incoherent source of truth is worse than no gate: it
  // reports PASS on numbers that do not add up. These are the arithmetic the JSON owes itself.
  const bad = [];
  if (miss.n !== m.corpus?.attacks_policy_decidable) {
    bad.push(`headline denominator ${miss.n} != corpus.attacks_policy_decidable ${m.corpus?.attacks_policy_decidable}`);
  }
  if (abort.n !== m.corpus?.benign) bad.push(`benign denominator ${abort.n} != corpus.benign ${m.corpus?.benign}`);
  if (miss.n !== contained.n) bad.push(`miss denominator ${miss.n} != contained denominator ${contained.n}`);
  if (miss.k + contained.k !== miss.n) bad.push(`miss ${miss.k} + contained ${contained.k} != ${miss.n}`);
  if (!Number.isFinite(held)) bad.push(`headline.benign_human_ask is ${JSON.stringify(m.headline?.benign_human_ask)}`);
  if (families.length === 0) bad.push("families[] is empty");
  const famN = families.reduce((a, f) => a + f.n, 0);
  const famMiss = families.reduce((a, f) => a + f.misses, 0);
  if (famN !== miss.n) bad.push(`families n sum ${famN} != ${miss.n}`);
  if (famMiss !== miss.k) bad.push(`families miss sum ${famMiss} != ${miss.k}`);
  if (bad.length) fail(`report-metrics.json does not agree with itself:\n  - ${bad.join("\n  - ")}`);

  const mean = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
  const big = families.filter((f) => f.n >= 50);
  return {
    missK: miss.k,
    missN: miss.n,
    containedK: contained.k,
    abortK: abort.k,
    benignN: abort.n,
    held,
    missPct: (100 * miss.k) / miss.n,
    containedPct: (100 * contained.k) / miss.n,
    abortPct: (100 * abort.k) / abort.n,
    heldPct: (100 * held) / abort.n,
    macroPct: 100 * mean(families.map((f) => f.misses / f.n)),
    macroBigPct: 100 * mean(big.map((f) => f.misses / f.n)),
    familyCount: families.length,
    bigFamilyCount: big.length,
  };
}

/* ----------------------------------------------------------- what is guarded */

/**
 * Guarded: a document that states these figures as current fact. Drift here FAILS.
 * To guard the next one, add a line. That is the whole cost, by design.
 */
const GUARDED = [
  {
    file: "PROJECT.md",
    why: "the document the project hands a reader first, and until this entry it was in neither list: not guarded, and not in the deliberate exclusions either, so nothing checked the four headline figures on the one page that states all four together. That is the same defect docs/DESIGN-CASE.md carried until 31 August, one level up, and it is worse here only because the exclusion list at least put that one on the record.",
  },
  {
    file: "README.md",
    why: "the front door. It is the file that contradicted itself: a table reading 149/3161 seventeen lines above a bullet reading '165 attacks still commit'. That bullet is what the miss-count rule exists for.",
  },
  {
    file: "docs/DESIGN-CASE.md",
    why: "the most judge-facing design document, and it sat outside this gate until 31 August, which is how it came to carry three readings of one quantity: the human-ask rate as 24.1 percent in two places and 17.3 percent in a third, plus a benign split whose two halves did not add up (4,074 commit unattended, 'those 3,728'). It ARGUES from the figures rather than restating them, so drift there breaks a claim and not only a cell: the sentence at the read-witness hole compares a 35.4 percent false positive against the human-ask rate, and that comparison changes direction when the rate moves. Guarding it does not make every number on the page checked, and the same refresh proves it: the read-witness sentence was rewritten to read \"35.4 percent ... which is 1,770 of the 5,000 benign scenarios\", a count that exists nowhere, back-computed from a rate that was measured on 48 turns and not on the benign corpus. No rule here would ever have seen it. This gate checks the figures it knows the true value of; a fabricated denominator swap still needs a reader.",
  },
  {
    file: "docs/CORPUS-REPORT.md",
    why: "the published report a reader is pointed at. check.sh stage 9 proves it equals the run's REPORT.md; this proves that pair equals the metrics JSON, which stage 9 cannot, since a report.mjs that formatted a figure wrongly would write the same wrong figure into both copies stage 9 compares.",
  },
  {
    file: "research/corpus/REPORT.md",
    why: "the run's own output, same reason as above, and it is what gets copied over the published page.",
  },
  {
    file: "research/METRICS.md",
    why: "carries the micro, both macro-averages and the held count in prose, and it went stale wholesale on the last corpus move. Four of its sentences are stale again today and are declared below.",
  },
  {
    file: "research/LEAKAGE-PROOF.md",
    why: "quotes the headline and the macro to argue the headline is not an artifact; a stale headline there discredits the argument built on it. It states the headline in prose more than twenty times, which is why the superseded-value rule matters most here.",
  },
  {
    file: "apps/server/src/bench/RESULTS.md",
    why: "cites docs/CORPUS-REPORT.md's benign cost as live fact ('publishes ... 1207 of 5000 ... 24.1%') and again as 'the rate this repository does publish'. The run it records is pinned to a date, but those citations are not: they become false the moment the report moves.",
  },
  {
    file: "research/corpus-v2/TWINS-REPORT.md",
    why: "published into this repository so the README's citation resolves, and it opens with a 'shipped today' table of the headline, the contained count and both benign figures. It was in PENDING earlier in this same session with a stale benign split; it was refreshed while this gate was being written, the empty-PENDING rule below demanded promotion, and this line is that promotion.",
  },
  {
    file: "research/RED-TEAM-ROUND-5.md",
    why: "the round 5 write-up, and its conclusion is a comparison against the published miss rate rather than a restatement of it: none of its eleven findings sits inside that miss count, so it argues the true rate against an attacker who has not read `research/corpus/` is higher than the published one by an amount the round cannot size. An argument of that shape is only as good as the figure it is measured from, and the page states the headline four separate times and then reproduces the raw counts, the review queue split and the per-family misses in a block. Its header claims every corpus figure in it was refreshed against report-metrics.json on 31 August, and this line is what holds it to that claim. It was in PENDING with seven recorded stale sentences arguing from 165 of 3161 and 5.2%; all seven are gone, so this is that promotion.",
  },
  {
    file: "research/queue/NARROWING.md",
    why: "the standing answer to whether `dependency-added` can be narrowed, and the page a reader is sent to when they ask why one rule owns most of the review queue. It does not restate the held count, it takes a SHARE of it: 712 of the 863 benign turns held, 82.50%, more than four in five of every question this system asks a person. Move the held count and that share is wrong while every digit on the page stays where it is, which is the failure a reader cannot see and this gate can. The page already states 902 and 751 as retired and names 863 beside them, so guarding it holds it to what it already claims.",
  },
];

/**
 * Pending: stale today, in files this lane does not own, and stale in more places than the rules
 * here can see. `sites` is the full list of stale sentences, taken by reading the file. Promotion to
 * GUARDED is allowed only when every one of them is gone, not when the regexes stop firing: a lane
 * that fixed the two visible sites and left five would otherwise be told the file was clean.
 */
const PENDING = [
  // EMPTY, and that is the spring working rather than the waiting room being unused. Its one entry
  // was research/RED-TEAM-ROUND-5.md, held here with seven recorded stale sentences citing "the
  // published 165 of 3161" and "5.2%" as current. All seven are gone, the page was refreshed
  // against report-metrics.json, the empty-PENDING rule demanded promotion, and the file now sits
  // in GUARDED above. A file arrives here only when it is stale in more places than the rules can
  // see, and it leaves only upward.
];

/**
 * Declared: a single stale sentence in a guarded document, named and reasoned. It prints on every
 * run and does not fail. `where` is a literal substring of the line; when it stops appearing the
 * declaration itself fails, so a fixed sentence cannot leave a stale exemption behind it.
 */
const DECLARED = [
  {
    file: "PROJECT.md",
    where: "36/5000 -> 24/5000, held 890 -> 902",
    why: "not a claim, it is the OUTPUT of a deliberately misleading command, printed so a reader recognises the wrong answer when they type the command that produces it. The block's own label on that line is WRONG HERE, and the correct invocation sits two lines below it. Rewriting 36 to 24 here would destroy the demonstration and leave a block that teaches nothing, and a reader running the named command really does get 36.",
  },
  // The six research/METRICS.md entries that stood here are GONE, because the sentences they
  // excused are fixed. The tables and the two concentration sentences were recomputed from a fresh
  // `node research/overhead/measure-metrics.mjs` against the corpus at 117 misses, not edited by
  // hand, which is what their own `why` asked for.
  //
  // The spring is what forced it. Fixing the sentences made this gate FAIL with "a declared stale
  // sentence is no longer in the file, so its declaration must go", which is the correct and
  // uncomfortable behaviour: a declaration outliving the sentence it excuses is an exemption
  // nobody is looking at, and it would have sat here quietly forever.
  // The three lines below the blank line in LEAKAGE-PROOF's dispersion block. That page says of
  // them, in its own prose immediately afterwards: "Nothing below the blank line was recomputed.
  // The standard errors, the design effect, the effective count and both intervals were computed at
  // policy 58fa2bce, where the micro rate was 4.71 percent, and restating them needs a re-run of the
  // script that this pass did not do."
  //
  // Adding the outbound family moved the denominator to 3251, so the gate reads these as stale, and
  // they are. Rewriting the n to 3251 while leaving a standard error and two intervals that were
  // computed on a different corpus at a different policy would make them worse than stale: it would
  // make them look current. They are declared instead, until somebody re-runs that script.
  {
    file: "research/LEAKAGE-PROOF.md",
    where: "binomial standard error on n=3161",
    why: "part of the dispersion block that page declares was not recomputed. The n belongs with the standard error beside it, and both were taken at policy 58fa2bce on the 3161-scenario corpus.",
  },
  {
    file: "research/LEAKAGE-PROOF.md",
    where: "effective independent observations          220   (nominal 3161)",
    why: "same block. The effective count came from a cluster bootstrap over the 3161-scenario corpus; the nominal figure beside it is what that bootstrap divided, not a live denominator.",
  },
  {
    file: "research/LEAKAGE-PROOF.md",
    where: "published Wilson 95% on n=3161",
    why: "same block. This interval is [4%, 5.5%], which is the 4.71 percent run's, not today's 3.60 percent. Restating the n without recomputing the interval would attach today's denominator to another run's spread.",
  },
  {
    file: "research/corpus-v2/TWINS-REPORT.md",
    where: "discard 65 / review 1175 / commit 3760",
    why: "not the shipped held count. It is the twins run's own replay of the ordinary benign corpus at policy build adb73a81, where review was 1175 against today's 1207. The staleness note this report now opens with covers it, and rewriting it would falsify what that run measured.",
  },
];
/**
 * Not guarded, on purpose. Stated here so the exclusion is a decision on the record rather than
 * an omission nobody notices.
 */
const EXCLUDED = [
  ["docs/CORPUS-REPORT-BEFORE.md", "the before run, graded against a different policy build. Its k/3161 numerators are supposed to differ from the after run; guarding it against the after metrics would fail permanently and for the wrong reason."],
  ["research/OVERHEAD.md", "timing and memory only. It carries no corpus figure, checked; nothing here would ever match."],
  ["research/corpus/lib/*.mjs, apps/server/src/*.test.ts", "code, and the figures in them are comments recording past defects (165 at d4cd9b4, the 66/1102 near-miss). The live expectations in research/overhead/measure-metrics.mjs are a different matter and SHOULD be guarded, but that file is owned by another lane this run; see the report."],
];

/* ------------------------------------------------------------------- the rules */

// A number that is either written with a decimal point, or written as an integer immediately
// followed by a percent sign. Requiring one of the two is what stops the lazy gap in an anchored
// rule from capturing the "149" in "miss rate: **149 / 3161 = 4.7%**" instead of the 4.7.
const NUM = String.raw`(?<![\d.])((?:\d+\.\d+)|(?:\d+(?=\s*(?:%|percent\b))))(?![\d])`;
// Up to 40 characters of anything, never crossing a blank line. Prose here hard-wraps, so a
// line-scoped gap would miss "held for a human,\n24.1%", which is exactly how one guarded document
// writes it. 40 rather than 80 because every widening of this window bought a false positive: at
// 80, "The report should lead with containment and the miss rate" reached across a clause and
// graded an unrelated 95.3 percent as the headline.
const GAP = String.raw`(?:(?!\n\s*\n)[\s\S]){0,40}?`;
// A bare count: three digits or more, so a "0" column or the "24" of a nearby "24.1%" is not
// mistaken for one, and never part of a decimal. It may carry thousands commas inside it but never
// a trailing one: "attacks 3190, policy-decidable 3161" reads as 3190 for the decidable count if
// the capture is allowed to swallow the comma between the two.
const INT = String.raw`(?<![\d.,])(\d{1,3}(?:,\d{3})+|\d{3,})(?![\d.])`;
const PCT = NUM + String.raw`\s*(?:%|percent\b)`;
const near = (anchor, tail = NUM) => new RegExp(`(?:${anchor})${GAP}${tail}`, "gi");
// The reversed form (figure first, name after) allows NO WORDS in between. "5.2% miss rate" is a
// claim about the miss rate; "95.3 percent. The report should lead with ... the miss rate" is not,
// and only adjacency tells them apart.
//
const after = (tail, anchor) => new RegExp(`${tail}[ \\t]*(?:${anchor})`, "gi");

// `after`, but tolerating the one hard wrap that prose here puts between a figure and the noun it
// names. Whether "902 benign turns held for a human" lands on one line is decided by where the wrap
// fell at 98 characters, not by what the sentence claims, and `research/LEAKAGE-PROOF.md` sat in
// GUARDED with a stale 902 invisible for exactly that reason. A lane rewrapping research/METRICS.md
// the same night silently un-guarded a site it had just corrected, from the other direction.
//
// USE IT SPARINGLY AND NEVER FOR A TABLE. Applying it to every reversed rule was tried first and
// cost more than it bought: in `research/LEAKAGE-PROOF.md`'s results block, "pooled (micro) miss
// rate 3.70%" is followed on the next line by a row beginning "macro", so crossing the newline let
// the macro rule claim the micro figure, and the micro rule then dropped below its floor. Inside a
// table the next line is the next claim, not the rest of this one.
//
// `notAfterOf` exists for the same reason in the other dimension. "863 of 5000 benign turns held
// for a human" puts the DENOMINATOR immediately before the noun, so a reversed rule anchored on
// "benign turns held" reads 5000 as the held count. Requiring that the integer is not preceded by
// "of " separates the two readings, and nothing else did.
const afterWrapped = (tail, anchor) => new RegExp(`${tail}[ \\t]*(?:\\n[ \\t]*)?(?:${anchor})`, "gi");
const notAfterOf = String.raw`(?<!of )` + INT;

// A denominator written in prose carries thousands commas ("115 of 3,161"); the same denominator in
// a table does not ("115/3161"). The two ratio rules were written against the table form, so every
// prose site in docs/DESIGN-CASE.md was invisible to them on the day that file was guarded: 115 of
// 3,161, 1,848 of 3,161 and 863 of 5,000 all read as no ratio at all. Accepting the comma at each
// thousands boundary is the fix, rather than asking prose to write 3161. It can only match more,
// never less, so no floor below can drop because of it.
const denom = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",?");

// The words that make a number in these pages a corpus figure rather than a timing, a version or a
// section number. Used only by the superseded-value rule, which needs to know that "1175" beside
// "review" is a claim and "1175" beside "ms" is not.
const CORPUS_WORDS = String.raw`miss(?:es|ed)?|headline|macro|micro|abort|discard|held|hold|escalat|contain|benign|attack|corpus|policy|denominator|graded|family|families|queue|turns|percent|rate\b|ratio`;

function buildRules(t) {
  const dec = (s) => (String(s).includes(".") ? String(s).split(".")[1].length : 0);
  // 4.7, 4.71 and 4.714 are all the same figure written to different precision. Compare at the
  // precision the document chose, so a rounding is a pass and a different number is a failure.
  const pctMatches = (found, truth) => Number(found) === Number(truth.toFixed(dec(found)));

  return [
    {
      id: "attack-ratio",
      rank: 5,
      what: `a count over the ${t.missN} policy-decidable attacks`,
      re: new RegExp(String.raw`(?<![\d.])(\d[\d,]*)\s*(?:\/|\s+of\s+)\s*${denom(t.missN)}\b`, "g"),
      check: (found) => ATTACK_NUMERATORS(t).some((a) => a.value === Number(found.replace(/,/g, ""))),
      expected: (found) => describe(ATTACK_NUMERATORS(t), found),
    },
    {
      id: "benign-ratio",
      rank: 5,
      what: `a count over the ${t.benignN} benign turns`,
      re: new RegExp(String.raw`(?<![\d.])(\d[\d,]*)\s*(?:\/|\s+of\s+)\s*${denom(t.benignN)}\b`, "g"),
      check: (found) => BENIGN_NUMERATORS(t).some((a) => a.value === Number(found.replace(/,/g, ""))),
      expected: (found) => describe(BENIGN_NUMERATORS(t), found),
    },
    {
      // Self-anchoring and needs no configuration: whatever k, n and p are, p must be 100k/n.
      // This is the half-updated line, where somebody swapped the count and left the rate.
      id: "ratio-pct-arithmetic",
      rank: 0,
      what: "a written k/n = p% that must agree with its own arithmetic",
      re: /(?<![\d.])(\d[\d,]*)\s*\/\s*(\d[\d,]*)\s*=\s*(\d+(?:\.\d+)?)\s*(?:%|percent\b)/g,
      pick: (m) => `${m[1]}/${m[2]} = ${m[3]}%`,
      check: (_found, m) => {
        const k = Number(m[1].replace(/,/g, ""));
        const n = Number(m[2].replace(/,/g, ""));
        return n !== 0 && pctMatches(m[3], (100 * k) / n);
      },
      expected: (_found, m) => {
        const k = Number(m[1].replace(/,/g, ""));
        const n = Number(m[2].replace(/,/g, ""));
        return `${m[1]}/${m[2]} is ${((100 * k) / n).toFixed(2)}%, not ${m[3]}%`;
      },
    },
    {
      id: "miss-pct",
      rank: 3,
      what: "the attack miss rate (micro)",
      // Deliberately narrow. A bare "miss rate" or "headline" anchor as a PREFIX matched a
      // per-family rate, a Wilson level, a design effect and a 634.9x speedup verdict in the
      // guarded set alone. As a SUFFIX, with no gap allowed, the same words are safe: "5.2 percent
      // headline" is a claim about the headline and nothing else parses that way. A figure the gate
      // cannot identify with confidence is better left to the ratio rules, which cannot be wrong
      // about which quantity they read, because the denominator says so.
      res: [
        near(String.raw`pooled \(micro\)|micro \(published headline\)|published headline|headline miss rate|headline of|micro miss rate|miss rate \(micro\)`),
        after(PCT, String.raw`miss rate\b|headline\b`),
        // "117 misses of 3251 policy-decidable attacks, 3.60 percent". The rate is the miss rate BY
        // CONSTRUCTION here: the sentence has already named both the numerator and the denominator,
        // so the percentage after them cannot be anything else. None of the anchors above appear in
        // it, so the gate walked straight past a lane that updated 3161 to 3251 and left 3.70
        // beside it. It flagged two other stale sites in the same file on the same run and exited 0.
        //
        // The anchor deliberately spans BOTH the word "misses" and the denominator phrase rather
        // than keying on "policy-decidable attacks" alone, which appears in table rows and in
        // sentences like "the 3251 policy-decidable attacks are 15 families" where a nearby
        // percentage would belong to something else.
        near(String.raw`misses of[\s\S]{0,24}?policy-decidable attacks`),
      ],
      check: (found) => pctMatches(found, t.missPct),
      expected: () => `${t.missPct.toFixed(2)}% (${t.missK}/${t.missN})`,
    },
    {
      // The bullet the README contradicted itself with: a bare count of misses, no denominator
      // beside it, seventeen lines under a table that already said 149. Nothing caught it until
      // this rule existed.
      id: "miss-count",
      rank: 3,
      what: "the count of attacks the policy still commits (the miss count)",
      res: [
        after(INT, String.raw`attacks still commit|attacks that still commit|attacks commit|are counted as misses|counted as misses|misses is\b`),
      ],
      check: (found) => Number(found.replace(/,/g, "")) === t.missK,
      expected: () => `${t.missK} (attacks the policy commits, of ${t.missN} policy-decidable)`,
    },
    {
      id: "macro-pct",
      rank: 2,
      what: `the macro-average miss rate over all ${t.familyCount} families`,
      res: [
        near(String.raw`macro-average|macro average|macro over all families|every family counted once|each family counted once|every family equally|each family equally`),
        after(PCT, String.raw`macro\b`),
      ],
      check: (found) => pctMatches(found, t.macroPct),
      expected: () => `${t.macroPct.toFixed(2)}% (unweighted mean over ${t.familyCount} families)`,
    },
    {
      id: "macro-n50-pct",
      rank: 1,
      what: `the macro-average over the ${t.bigFamilyCount} families with n >= 50`,
      res: [new RegExp(String.raw`macro${GAP}n\s*>=?\s*50${GAP}${NUM}`, "gi")],
      check: (found) => pctMatches(found, t.macroBigPct),
      expected: () => `${t.macroBigPct.toFixed(2)}% (unweighted mean over ${t.bigFamilyCount} families with n >= 50)`,
    },
    {
      id: "abort-pct",
      rank: 3,
      what: "the benign false-abort rate",
      res: [
        near(String.raw`false[- ]abort rate|benign false[- ]abort|falseAbort\W|hard-discard(?:s|ed)?`),
        after(PCT, String.raw`\*{0,2}[ \t]*(?:\[[\d.,\s]*\][ \t]*)?on (?:the )?ordinary\b|benign baseline`),
      ],
      check: (found) => pctMatches(found, t.abortPct),
      expected: () => `${t.abortPct.toFixed(2)}% (${t.abortK}/${t.benignN})`,
    },
    {
      // The one guarded figure published as a bare integer with no denominator beside it: "Benign
      // turns escalated to a human (review, not an abort): **1207**". Rolling that bullet back to
      // 1175 was caught by nothing until this rule existed.
      id: "held-count",
      rank: 3,
      what: "the count of benign turns held for a human",
      res: [
        near(String.raw`escalated to a human|benign turns held for a human|held for a human|benign human asks`, INT),
        after(INT, String.raw`(?:more|additional|destroyed|held) benign turns|benign turns that were held`),
        // "902 benign turns held for a human" is the reversed form of the first `near` anchor and
        // was matched by neither arm: `near` needs the words first, and the list above has every
        // phrasing except the plain one. Wrapped, because that is how LEAKAGE-PROOF.md wrote it,
        // and `notAfterOf` because "863 of 5000 benign turns held" must not read as 5000.
        afterWrapped(notAfterOf, String.raw`benign turns held\b`),
      ],
      check: (found) => Number(found.replace(/,/g, "")) === t.held,
      expected: () => `${t.held} (of ${t.benignN} benign turns)`,
    },
    {
      id: "held-pct",
      rank: 3,
      what: "the share of benign turns held for a human",
      res: [
        near(String.raw`held for a human|escalated to a human|benign hold rate|turns are held|does publish`),
        after(PCT, String.raw`benign hold rate|of benign turns now ask a human|of benign turns are held`),
      ],
      check: (found) => pctMatches(found, t.heldPct),
      expected: () => `${t.heldPct.toFixed(2)}% (${t.held}/${t.benignN})`,
    },
    {
      id: "contained-count",
      rank: 3,
      what: "the count of attacks contained (discarded or held)",
      res: [after(INT, String.raw`attacks discarded or held|attacks contained|contained attacks`)],
      check: (found) => Number(found.replace(/,/g, "")) === t.containedK,
      expected: () => `${t.containedK} (of ${t.missN} policy-decidable attacks)`,
    },
    {
      id: "contained-pct",
      rank: 3,
      what: "the share of policy-decidable attacks contained",
      res: [
        near(String.raw`discarded or held|attacks contained|containment rate|contained \(discard or review\)`),
        after(PCT, String.raw`of attacks are contained|contained\b`),
      ],
      check: (found) => pctMatches(found, t.containedPct),
      expected: () => `${t.containedPct.toFixed(2)}% (${t.containedK}/${t.missN})`,
    },
    {
      // A denominator written on its own, with no k over it, so neither ratio rule sees it. Both
      // anchor sets are deliberately literal: "n=" alone reads "-- all attacks (n=3190)" and calls
      // the whole-attack denominator a stale decidable one.
      id: "attack-denominator",
      rank: 4,
      what: `the count of policy-decidable attacks (the miss denominator)`,
      res: [
        after(INT, String.raw`(?:are |of them )?policy-decidable|graded attacks|decidable attacks|minus`),
        near(String.raw`policy-decidable attacks only \(n=|error on n=|Wilson 95% on n=|nominal|of which, policy-decidable`, INT),
      ],
      check: (found) => Number(found.replace(/,/g, "")) === t.missN,
      expected: () => `${t.missN} (policy-decidable attacks)`,
    },
    {
      // "the 1,207 benign turns that were held" is also "<count> benign turns", so the total is
      // only recognisable by the determiner in front of it: all of them, or every one of them.
      id: "benign-denominator",
      rank: 4,
      what: `the count of benign turns (the false-abort denominator)`,
      res: [
        new RegExp(String.raw`(?:\ball\b|\bof the\b|\bevery one of the\b)\s+${INT}\s+benign\b`, "gi"),
        after(INT, String.raw`benign scenarios|benign rows`),
        near(String.raw`\|\s*Benign\s*\|`, INT),
      ],
      check: (found) => Number(found.replace(/,/g, "")) === t.benignN,
      expected: () => `${t.benignN} (benign turns in the corpus)`,
    },
    {
      // The rule that does not need to know which quantity a sentence is about. Drift in this
      // repository has always been a rollback: a page keeps the value the last batch published.
      // So the values this repository has retired are listed once, each with what it was, and any
      // of them appearing in a guarded page beside a corpus word is drift unless it is fenced.
      // This is what covers the prose the anchored rules cannot identify, and it is the reason
      // LEAKAGE-PROOF is guarded in more than name.
      id: "superseded-value",
      rank: 9,
      what: "a value this repository has retired, restated as current",
      res: [
        new RegExp(String.raw`(?:${CORPUS_WORDS})${GAP}${SUPERSEDED_TOKENS}`, "gi"),
        new RegExp(`${SUPERSEDED_TOKENS}${GAP}(?:${CORPUS_WORDS})`, "gi"),
      ],
      check: () => false,
      expected: (found) => {
        const s = SUPERSEDED.find((x) => x.token === String(found));
        return `${s.was}. It is ${s.now} today. Quote it or say it is retired, or restate the live figure`;
      },
    },
  ];
}

// The values this repository has published and retired. Each is matched only as a whole token, and
// only beside one of CORPUS_WORDS, so a section number "5.2" and a "65 ms" column are not figures.
// A value that is still legal somewhere (1848 and 1313 are the before run's, and stay) is not here.
const SUPERSEDED = [
  { token: "165", was: "the miss count of the batch before this one", now: "149" },
  { token: "5.22", was: "the miss rate before the corpus was regenerated", now: "4.71%" },
  { token: "5.2", was: "the miss rate before the corpus was regenerated", now: "4.7%" },
  { token: "9.73", was: "the macro-average before the misses spread out", now: "5.12%" },
  { token: "9.7", was: "the macro-average before the misses spread out", now: "5.1%" },
  { token: "1175", was: "the benign held count one batch earlier, the drift bench-truth.md records", now: "1207" },
  { token: "23.5", was: "the benign hold rate one batch earlier", now: "24.1%" },
  { token: "2996", was: "the contained count at 165 misses", now: "3012" },
];
const SUPERSEDED_TOKENS = `(?<![\\d.,])(${SUPERSEDED.map((s) => s.token.replace(".", "\\.")).join("|")})(?![\\d.,%]*\\d)`;

// The numerators that may legitimately sit over each denominator, each with what it means.
// The two "before" values are the pre-integration policy run published in docs/CORPUS-REPORT-BEFORE.md.
// They do not move when the after run moves. They do become meaningless if the corpus itself is
// resized, but so does the denominator, and then these rules stop matching and the floors below fire.
const ATTACK_NUMERATORS = (t) => [
  { value: t.missK, means: "attacks the policy committed (the miss count)" },
  { value: t.containedK, means: "attacks contained, discard or review" },
  { value: t.missN, means: "the denominator itself" },
  { value: 1848, means: "the BEFORE run's miss count, docs/CORPUS-REPORT-BEFORE.md" },
  { value: 1313, means: "the BEFORE run's contained count, docs/CORPUS-REPORT-BEFORE.md" },
];
const BENIGN_NUMERATORS = (t) => [
  { value: t.abortK, means: "benign turns hard-discarded (the false aborts)" },
  { value: t.held, means: "benign turns held for a human" },
  { value: t.benignN, means: "the denominator itself" },
  { value: 232, means: "the BEFORE run's hard-discard count, docs/CORPUS-REPORT-BEFORE.md" },
];
const describe = (allowed, found) =>
  `one of ${allowed.map((a) => `${a.value} (${a.means})`).join(", ")}; found ${found}`;

/**
 * Floors: how many times each rule currently matches in each guarded document. A count that drops
 * FAILS. This is what stops the gate being silenced by making it match less: rewording a figure into
 * a shape no rule reads, deleting the sentence, or breaking the denominator so the ratio rule stops
 * matching all show up here as a drop rather than as a quiet green run. Regenerate with --floors
 * after a deliberate rewrite, and read the diff before pasting it.
 */
const FLOORS = {
  // Written when PROJECT.md was guarded, from --floors against that page alone, for the reason the
  // note further down this table gives: --floors reads whatever is on disk now, so pasting the whole
  // regenerated table would ratchet every other row down to its current state. A missing row is not
  // a neutral default here, it is no floor at all (FLOORS[entry.file] ?? {}), which is how a page can
  // sit in GUARDED and still be silenced by deleting the figure rather than by correcting it.
  "PROJECT.md": { "attack-denominator": 1, "attack-ratio": 2, "benign-ratio": 2, "held-pct": 1, "macro-pct": 1, "ratio-pct-arithmetic": 5 },
  "README.md": { "abort-pct": 1, "attack-denominator": 1, "attack-ratio": 4, "benign-denominator": 2, "benign-ratio": 2, "held-count": 1, "held-pct": 1, "macro-pct": 1, "miss-count": 1, "ratio-pct-arithmetic": 5 },
  "docs/CORPUS-REPORT.md": { "attack-denominator": 2, "attack-ratio": 3, "benign-denominator": 1, "benign-ratio": 2, "held-count": 1, "held-pct": 1, "macro-pct": 1, "ratio-pct-arithmetic": 3 },
  "research/corpus/REPORT.md": { "attack-denominator": 2, "attack-ratio": 3, "benign-denominator": 1, "benign-ratio": 2, "held-count": 1, "held-pct": 1, "macro-pct": 1, "ratio-pct-arithmetic": 3 },
  "research/METRICS.md": { "attack-denominator": 1, "attack-ratio": 2, "benign-denominator": 1, "benign-ratio": 1, "held-count": 4, "held-pct": 1, "macro-n50-pct": 2, "macro-pct": 2, "miss-count": 1, "miss-pct": 3 },
  "research/LEAKAGE-PROOF.md": { "abort-pct": 2, "attack-denominator": 5, "benign-denominator": 1, "contained-pct": 1, "macro-pct": 1, "miss-count": 1, "miss-pct": 1 },
  "apps/server/src/bench/RESULTS.md": { "benign-ratio": 1, "held-pct": 2 },
  "research/corpus-v2/TWINS-REPORT.md": { "abort-pct": 2, "attack-denominator": 2, "attack-ratio": 2, "benign-ratio": 4, "held-count": 1, "ratio-pct-arithmetic": 13 },
  // Written when this file was promoted out of PENDING, from --floors against the refreshed page.
  // Only this row was regenerated. The rows above are left at the counts they already carried,
  // because --floors reads whatever is on disk right now and pasting the whole table while another
  // lane has a guarded document open would quietly ratchet that document's floor down to its
  // half-corrected state, which is the exact silencing this table exists to prevent.
  "research/RED-TEAM-ROUND-5.md": { "abort-pct": 1, "attack-ratio": 2, "contained-count": 1, "contained-pct": 1, "held-count": 2, "miss-pct": 1 },
  // Written when research/queue/NARROWING.md was guarded, from --floors against that page alone.
  // One rule matches there: the page states the held count once and spends the rest of itself
  // taking a share of it. That is the whole point of the floor here. Reword the one sentence that
  // says 863 into a shape no rule reads and the page keeps arguing from a number nothing checks.
  "research/queue/NARROWING.md": { "held-count": 1 },
  // Written when docs/DESIGN-CASE.md was guarded, from --floors against that page alone. It was
  // guarded with no floor row at all, which left the guard half-built: the page ARGUES from the
  // figures, so the cheapest way to break it is to reword one into a shape no rule reads, and that
  // is precisely what this table is for. Two of these eight cost a prose edit to earn. held-count
  // and held-pct were zero while the page said "holds **863** for a human", because the rule reads
  // "benign turns held" and the bold markers broke the adjacency; attack-ratio was zero because the
  // live 115 of 3,161 shared one sentence with the retired 1,848 of 3,161 and the "earlier build"
  // cue fenced both, which is the case the fence comment above says a sentence scope exists to
  // avoid. Splitting that sentence is what put the live figure back under the gate.
  "docs/DESIGN-CASE.md": { "abort-pct": 2, "attack-ratio": 1, "benign-denominator": 1, "benign-ratio": 1, "held-count": 1, "held-pct": 1, "macro-n50-pct": 1, "macro-pct": 1 },
};

/* --------------------------------------------------------------------- machinery */

function fail(msg) {
  console.error(`check-figures: ${msg}`);
  process.exit(1);
}
const rel = (p) => path.relative(ROOT, p) || p;

function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, start: starts[lo], end: starts[lo + 1] ?? text.length };
  };
}

/* ------------------------------------------------------------------ the fences */

// A figure inside straight or curly double quotes is a verbatim quotation, and this gate does not
// grade quotations. It is how a live page preserves a sentence it has retracted.
function insideQuotes(line, column) {
  const before = line.slice(0, Math.max(0, column));
  const straight = (before.match(/"/g) ?? []).length;
  if (straight % 2 === 1) return true;
  const openCurly = before.lastIndexOf("“");
  const closeCurly = before.lastIndexOf("”");
  return openCurly > closeCurly && line.indexOf("”", column) !== -1;
}

// A closed list, kept short on purpose. Each of these says in words that the figure beside it is
// not the current one. "no longer" and "has since" were tried and removed: README's live sentence
// "At 4.7% and 5.1% it no longer does" carries the first, so they fence live figures.
// Every space here is \s+ because this prose hard-wraps: "an earlier\nbuild of the policy" is the
// same cue as "an earlier build of the policy" and a literal space would miss half of them.
const RETRACTION_CUES = [
  [/\bused\s+to\b/i, "used to"],
  [/\bpreviously\b/i, "previously"],
  [/\bformerly\b/i, "formerly"],
  [/\bsupersed(?:ed|es|ing)\b/i, "superseded"],
  [/\bretract(?:ed|s|ion)\b/i, "retracted"],
  [/\bat\s+\d[\d,]*\s+misses\b/i, "at N misses"],
  [/\bearlier\s+(?:build|run|batch|policy|corpus)\b/i, "earlier build"],
  [/\bthis\s+(?:page|paragraph|report|document|table)\s+(?:read|said|named|carried|showed)\b/i, "this page read"],
  [/\bat\s+[0-9a-f]{7,40}\b/, "at <commit>"],
];

// The block a figure lives in: never across a blank line, and never across a structural line start
// (a table row, a list item, a heading, a fence), because those are separate statements that happen
// to be adjacent. Then the sentence within that block. A cue has to share the figure's sentence:
// a cue anywhere in the paragraph would exempt the live figure sitting beside the retired one.
const STRUCTURAL = /^\s*(?:\||[-*+]\s|\d+\.\s|#{1,6}\s|```|>\s)/;
const SENTENCE_END = /[.!?][)"'”*_\]]*(?:\s|$)/g;

function sentenceAround(text, offset) {
  let blockStart = text.lastIndexOf("\n\n", Math.max(0, offset - 1));
  blockStart = blockStart === -1 ? 0 : blockStart + 2;
  let blockEnd = text.indexOf("\n\n", offset);
  blockEnd = blockEnd === -1 ? text.length : blockEnd;
  // Walk the block's lines and keep only the run of lines around the offset that no structural
  // line start interrupts.
  let cursor = blockStart;
  let start = blockStart;
  let end = blockEnd;
  let seen = false;
  while (cursor < blockEnd) {
    let nl = text.indexOf("\n", cursor);
    if (nl === -1 || nl > blockEnd) nl = blockEnd;
    const line = text.slice(cursor, nl);
    if (STRUCTURAL.test(line)) {
      if (seen) {
        end = cursor;
        break;
      }
      start = cursor;
    }
    if (offset >= cursor && offset <= nl) seen = true;
    cursor = nl + 1;
  }
  const chunk = text.slice(start, end);
  const relOff = offset - start;
  let sentStart = 0;
  let m;
  SENTENCE_END.lastIndex = 0;
  while ((m = SENTENCE_END.exec(chunk)) !== null) {
    if (m.index + m[0].length <= relOff) sentStart = m.index + m[0].length;
    else break;
  }
  SENTENCE_END.lastIndex = relOff;
  const tail = SENTENCE_END.exec(chunk);
  const sentEnd = tail ? tail.index + tail[0].length : chunk.length;
  return { text: chunk.slice(sentStart, sentEnd), offset: relOff - sentStart };
}

// A figure inside a single-backtick code span is program output being reproduced, the same act as
// a quotation: research/METRICS.md carries `DRIFT: miss=true is 164, the published report says 165.`
// as the evidence that its own guard fires. Fenced code blocks are NOT covered, because the tables
// this repository publishes live in them and they are exactly what has to stay fresh.
function insideCodeSpan(line, column) {
  const before = line.slice(0, Math.max(0, column));
  return (before.match(/`/g) ?? []).length % 2 === 1;
}

function fenceFor(text, offset, line, column) {
  if (insideQuotes(line, column)) return "quoted";
  if (insideCodeSpan(line, column)) return "code span";
  const s = sentenceAround(text, offset);
  // The cue may sit either side of the figure inside its own sentence. "The 18.41 percent headline
  // describes an earlier build" puts it after, and reading only backwards would fire on it. A cue
  // one sentence away does not count: that is the case where a live figure sits beside a retired
  // one, and the paragraph-wide reading would exempt both.
  for (const [re, name] of RETRACTION_CUES) {
    re.lastIndex = 0;
    if (re.test(s.text)) return `retracted, "${name}"`;
  }
  // "moved the headline from 5.22 percent to 4.71 percent": the first arm of a stated change is the
  // old value by construction, and the second arm is not fenced by it.
  const before = s.text.slice(0, s.offset);
  if (/\bfrom\b(?:(?!\bto\b)[\s\S]){0,40}$/.test(before) && /^(?:(?!\.\s)[\s\S]){0,60}?\bto\b/.test(s.text.slice(s.offset))) {
    return 'retracted, "from X to Y"';
  }
  return null;
}

/* -------------------------------------------------------------------- scanning */

function scan(file, text, rules) {
  const at = lineIndex(text);
  const raw = [];
  for (const rule of rules) {
    for (const re of rule.res ?? [rule.re]) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) {
          re.lastIndex++;
          continue;
        }
        const hit = m;
        // Report the line the FIGURE is on, not the line the anchor started on.
        const figureOffset = hit.index + Math.max(0, hit[0].lastIndexOf(String(hit[1])));
        const loc = at(rule.pick ? hit.index : figureOffset);
        const source = text.slice(loc.start, loc.end).replace(/\s+$/, "");
        // A percent that is the tail of a written "k/n = p%" is already checked, harder, by
        // ratio-pct-arithmetic (against its own k and n) and by the ratio rule (against the allowed
        // numerators). Checking it a second time here would ask which quantity it is, and in a
        // before/after table the answer is often "the other column": the anchored rule reads
        // "Attack miss rate ... 1848/3161 = 58.5%" and calls the BEFORE rate a stale miss rate.
        if (!rule.pick && /\d\s*\/\s*\d[\d,]*\s*=\s*$/.test(text.slice(Math.max(0, figureOffset - 40), figureOffset))) {
          continue;
        }
        const found = rule.pick ? rule.pick(hit) : hit[1];
        raw.push({
          file,
          rule,
          key: rule.pick ? `p${hit.index}` : `f${figureOffset}`,
          offset: figureOffset,
          line: loc.line,
          column: figureOffset - loc.start,
          source,
          found,
          ok: rule.check(found, hit),
          expected: () => rule.expected(found, hit),
        });
      }
    }
  }
  // One figure, one grader. When two rules read the same token the more specific one owns it, so
  // "the macro-average is 5.12 percent against a headline of 4.71" grades 5.12 as the macro and
  // 4.71 as the micro instead of the whole line being dropped because it says "macro" somewhere.
  const byKey = new Map();
  for (const h of raw) {
    const prev = byKey.get(h.key);
    if (!prev || h.rule.rank < prev.rule.rank) byKey.set(h.key, h);
  }
  const hits = [];
  for (const h of byKey.values()) {
    const f = fenceFor(text, h.offset, h.source, h.column);
    if (f) hits.push({ ...h, fenced: f });
    else hits.push(h);
  }
  return hits.sort((a, b) => a.line - b.line || a.rule.id.localeCompare(b.rule.id));
}

function readFile(file) {
  const abs = path.join(ROOT, file);
  return fs.existsSync(abs) ? fs.readFileSync(abs, "utf8") : null;
}

function printViolation(v) {
  console.log(`  ${v.file}:${v.line}`);
  console.log(`      figure:   ${v.rule.what}`);
  console.log(`      found:    ${v.found}`);
  console.log(`      expected: ${v.expected()}`);
  console.log(`      line:     ${v.source.trim().slice(0, 160)}`);
  console.log("");
}

/* ------------------------------------------------------------------ evaluation */

/**
 * One pass over the guarded set. `override` substitutes a document's text without touching the
 * disk, which is how --sweep mutates a figure: nothing here writes, ever.
 */
function evaluate(rules, override = null) {
  const out = { violations: [], missingFiles: [], floorDrops: [], declaredHits: [], fenced: [], pending: [], pendingClean: [], deadDeclarations: [] };
  const textOf = (file) => (override && override.file === file ? override.text : readFile(file));

  const declaredFor = (file) => DECLARED.filter((d) => d.file === file);

  for (const entry of GUARDED) {
    const text = textOf(entry.file);
    if (text === null) {
      out.missingFiles.push(entry.file);
      continue;
    }
    const decls = declaredFor(entry.file);
    for (const d of decls) if (!text.includes(d.where)) out.deadDeclarations.push(d);
    const hits = scan(entry.file, text, rules);
    const counts = {};
    for (const h of hits) {
      if (h.fenced) {
        out.fenced.push(h);
        continue;
      }
      // Not superseded-value: every match of that rule IS drift, so a floor on it would be a
      // standing order to keep the stale number.
      if (h.rule.id !== "superseded-value") counts[h.rule.id] = (counts[h.rule.id] ?? 0) + 1;
      if (h.ok) continue;
      const covered = decls.find((d) => h.source.includes(d.where));
      if (covered) out.declaredHits.push({ ...h, why: covered.why });
      else out.violations.push(h);
    }
    for (const [id, floor] of Object.entries(FLOORS[entry.file] ?? {})) {
      const seen = counts[id] ?? 0;
      if (seen < floor) out.floorDrops.push({ file: entry.file, id, seen, floor });
    }
  }

  for (const entry of PENDING) {
    const text = textOf(entry.file);
    if (text === null) {
      out.missingFiles.push(entry.file);
      continue;
    }
    const bad = scan(entry.file, text, rules).filter((h) => !h.ok && !h.fenced);
    const left = (entry.sites ?? []).filter((s) => text.includes(s));
    if (left.length === 0 && bad.length === 0) out.pendingClean.push(entry);
    else out.pending.push({ entry, bad, left });
  }
  return out;
}

function failed(r) {
  return (
    r.violations.length > 0 ||
    r.floorDrops.length > 0 ||
    r.missingFiles.length > 0 ||
    r.pendingClean.length > 0 ||
    r.deadDeclarations.length > 0
  );
}

/* -------------------------------------------------------------------- the modes */

const argv = process.argv.slice(2);
const truth = loadTruth();
const rules = buildRules(truth);

if (argv.includes("--list")) {
  console.log("Source of truth: research/corpus/results/report-metrics.json");
  console.log(`  attack miss        ${truth.missK}/${truth.missN} = ${truth.missPct.toFixed(2)}%`);
  console.log(`  attacks contained  ${truth.containedK}/${truth.missN} = ${truth.containedPct.toFixed(2)}%`);
  console.log(`  macro (${truth.familyCount} families) ${truth.macroPct.toFixed(2)}%`);
  console.log(`  macro (n>=50, ${truth.bigFamilyCount})  ${truth.macroBigPct.toFixed(2)}%`);
  console.log(`  benign false abort ${truth.abortK}/${truth.benignN} = ${truth.abortPct.toFixed(2)}%`);
  console.log(`  benign held        ${truth.held}/${truth.benignN} = ${truth.heldPct.toFixed(2)}%`);
  console.log("\nGUARDED (drift here fails the build):");
  for (const g of GUARDED) console.log(`  ${g.file}\n      ${g.why}`);
  console.log("\nDECLARED (a stale sentence in a guarded file, printed every run, does not fail):");
  for (const d of DECLARED) console.log(`  ${d.file}\n      "${d.where}"\n      ${d.why}`);
  console.log("\nPENDING (a whole file, stale; may be promoted only when every site below is gone):");
  if (PENDING.length === 0) console.log("  none. Every file that was held here has been refreshed and promoted to GUARDED.");
  for (const p of PENDING) {
    console.log(`  ${p.file}\n      ${p.why}`);
    for (const s of p.sites ?? []) console.log(`        site: ${s}`);
  }
  console.log("\nNOT GUARDED, deliberately:");
  for (const [f, why] of EXCLUDED) console.log(`  ${f}\n      ${why}`);
  process.exit(0);
}

if (argv.includes("--audit")) {
  for (const entry of [...GUARDED, ...PENDING]) {
    const text = readFile(entry.file);
    if (text === null) {
      console.log(`${entry.file}  (missing)`);
      continue;
    }
    console.log(`\n=== ${entry.file}`);
    for (const h of scan(entry.file, text, rules)) {
      const mark = h.fenced ? "fence" : h.ok ? "ok   " : "DRIFT";
      console.log(`  ${mark} ${String(h.line).padStart(4)}  ${h.rule.id.padEnd(18)} ${String(h.found).padEnd(18)} ${h.fenced ?? ""}`);
      if (!h.ok && !h.fenced) console.log(`         expected ${h.expected()}`);
    }
  }
  process.exit(0);
}

if (argv.includes("--floors")) {
  for (const entry of GUARDED) {
    const text = readFile(entry.file);
    if (text === null) continue;
    const counts = {};
    for (const h of scan(entry.file, text, rules)) {
      if (h.fenced || h.rule.id === "superseded-value") continue;
      counts[h.rule.id] = (counts[h.rule.id] ?? 0) + 1;
    }
    const body = Object.keys(counts)
      .sort()
      .map((k) => `"${k}": ${counts[k]}`)
      .join(", ");
    console.log(`  ${JSON.stringify(entry.file)}: { ${body} },`);
  }
  process.exit(0);
}

if (argv.includes("--sweep")) {
  runSweep();
  process.exit(0);
}

const result = evaluate(rules);

if (result.declaredHits.length) {
  console.log("KNOWN STALE, declared site by site, not failing this build:");
  console.log("");
  for (const v of result.declaredHits) {
    printViolation(v);
    console.log(`      declared: ${v.why}`);
    console.log("");
  }
}

if (result.pending.length) {
  console.log("KNOWN STALE, whole file in PENDING, not failing this build:");
  console.log("");
  for (const p of result.pending) {
    for (const v of p.bad) printViolation(v);
    console.log(`      ${p.entry.file}: ${p.left.length} of ${(p.entry.sites ?? []).length} recorded stale sentences remain.`);
    for (const s of p.left) console.log(`        still there: ${s}`);
    console.log("");
  }
}

if (result.violations.length) {
  console.log(`FAIL: ${result.violations.length} published figure(s) disagree with research/corpus/results/report-metrics.json.`);
  console.log("");
  for (const v of result.violations) printViolation(v);
  console.log("      Fix the documents, not this gate, and rewrite the sentence rather than the digits:");
  console.log("      a relational claim (\"nearly double the headline\", \"the worst family is X\") survives a");
  console.log("      number swap and stays false. This gate will not edit a document for you, because a gate");
  console.log("      that repairs what it checks passes next run whether or not anybody looked.");
  console.log("");
}

if (result.floorDrops.length) {
  console.log("FAIL: a guarded document states a figure fewer times than it used to.");
  for (const { file, id, seen, floor } of result.floorDrops) {
    const rule = rules.find((r) => r.id === id);
    console.log(`  ${file}: ${id} matched ${seen} time(s), floor is ${floor} (${rule.what}).`);
  }
  console.log("      Either the figure was dropped, or it was reworded into a shape no rule matches, or a");
  console.log("      denominator was changed so the rule that read it no longer fires. A rewording needs a");
  console.log("      pattern added here; a deletion needs a decision; then regenerate with --floors.");
  console.log("");
}

if (result.missingFiles.length) {
  console.log("FAIL: a declared document does not exist.");
  for (const f of result.missingFiles) console.log(`  ${f}`);
  console.log("      If it was renamed or deleted, update the GUARDED/PENDING list in check-figures.mjs.");
  console.log("");
}

if (result.pendingClean.length) {
  console.log("FAIL: a PENDING document has no recorded drift left and must be promoted to GUARDED.");
  for (const e of result.pendingClean) console.log(`  ${e.file}`);
  console.log("      Move its entry from PENDING to GUARDED in check-figures.mjs. PENDING exists to hold");
  console.log("      drift this lane could not fix, not to exempt a document from the gate for good.");
  console.log("");
}

if (result.deadDeclarations.length) {
  console.log("FAIL: a declared stale sentence is no longer in the file, so its declaration must go.");
  for (const d of result.deadDeclarations) console.log(`  ${d.file}: "${d.where}"`);
  console.log("      Delete that entry from DECLARED in check-figures.mjs. A declaration outliving the");
  console.log("      sentence it excuses is an exemption nobody is looking at.");
  console.log("");
}

if (failed(result)) process.exit(1);

const declaredCount = result.declaredHits.length;
const pendingSites = result.pending.reduce((a, p) => a + p.left.length, 0);
// Deliberately not "every guarded document publishes the numbers this run measured". Eight sites do
// not, they are declared and printed above, and a pass line that rounded them away would be the
// same self-certification this gate exists to stop.
console.log(
  `  ok   no undeclared drift in ${GUARDED.length} guarded document(s) against report-metrics.json ` +
    `(miss ${truth.missK}/${truth.missN}, macro ${truth.macroPct.toFixed(2)}%, ` +
    `abort ${truth.abortK}/${truth.benignN}, held ${truth.held}, contained ${truth.containedK}/${truth.missN})`
);
if (declaredCount) {
  const files = [...new Set(result.declaredHits.map((h) => h.file))].length;
  console.log(`       ${declaredCount} declared stale site(s) in ${files} file(s), printed above, still to be fixed.`);
}
console.log(`       ${result.fenced.length} figure(s) fenced as quoted or retracted; --audit lists them with the cue.`);
if (pendingSites) {
  console.log(`       ${PENDING.length} document(s) in PENDING with ${pendingSites} recorded stale sentence(s).`);
}

/* ---------------------------------------------------------------- the sweep */

/**
 * Rewrite every published figure in every guarded document, one token at a time, and report what
 * this gate catches. Two mutations per site: a ROLLBACK to the value that figure held in the
 * previous corpus batch, which is the drift this repository actually produces, and an ARBITRARY
 * wrong value, which is the harder case because no list of retired numbers can see it.
 *
 * A site is skipped when the token is not a figure at all: part of a hex digest, a section number,
 * a millisecond column. Those are listed under "not a figure" so the exclusions are visible rather
 * than quietly shrinking the denominator.
 */
function runSweep() {
  const t = truth;
  const p1 = (x) => x.toFixed(1);
  const p2 = (x) => x.toFixed(2);
  const catalogue = [
    { token: String(t.missK), roll: "165", arb: "137" },
    { token: String(t.missN), roll: "3082", arb: "3164" },
    { token: String(t.containedK), roll: "2996", arb: "3021" },
    { token: String(t.held), roll: "1175", arb: "1290" },
    { token: String(t.abortK), roll: "67", arb: "71" },
    { token: String(t.benignN), roll: "4900", arb: "5300" },
    { token: p2(t.missPct), roll: "5.22", arb: "4.13" },
    { token: p1(t.missPct), roll: "5.2", arb: "4.1" },
    { token: p2(t.macroPct), roll: "9.73", arb: "6.34" },
    { token: p1(t.macroPct), roll: "9.7", arb: "6.3" },
    { token: p2(t.macroBigPct), roll: "5.44", arb: "6.20" },
    { token: p2(t.abortPct), roll: "1.52", arb: "1.71" },
    { token: p1(t.abortPct), roll: "1.5", arb: "1.7" },
    { token: p2(t.heldPct), roll: "23.50", arb: "26.83" },
    { token: p1(t.heldPct), roll: "23.5", arb: "26.8" },
    { token: p1(t.containedPct), roll: "94.8", arb: "93.1" },
  ];
  const comma = (s) => (s.length > 3 && !s.includes(".") ? `${s.slice(0, -3)},${s.slice(-3)}` : null);
  // Occurrences that are not figures. Each is a measured coincidence, named so the denominator is
  // not quietly trimmed. A digit inside a sha256 needs no rule here: the lookarounds below already
  // refuse a token with a letter on either side of it.
  const NOT_A_FIGURE = [
    [/\bms\b/, "a milliseconds column"],
    [/\d-file\b/, "the size of a synthetic file tree"],
    [/\bsection\b/i, "a cross-reference to a section number"],
  ];
  // "## 7. Does 4.7 percent mean anything" is a heading whose 7 is a section number and whose 4.7
  // is the headline, so this asks where the token sits rather than what kind of line it is on.
  const isSectionNumber = (line, index) => {
    const head = /^\s*#{1,6}\s*/.exec(line);
    return head !== null && index === head[0].length;
  };

  const sites = [];
  for (const entry of GUARDED) {
    const text = readFile(entry.file);
    if (text === null) continue;
    const lines = text.split("\n");
    let base = 0;
    lines.forEach((line, i) => {
      for (const c of catalogue) {
        for (const form of [c.token, comma(c.token)].filter(Boolean)) {
          const re = new RegExp(`(?<![\\d.,A-Za-z])${form.replace(".", "\\.")}(?![\\d.,A-Za-z])`, "g");
          let m;
          while ((m = re.exec(line)) !== null) {
            const window = line.slice(Math.max(0, m.index - 24), m.index + 24);
            const excuse = isSectionNumber(line, m.index)
              ? [null, "a heading's section number"]
              : NOT_A_FIGURE.find(([r]) => r.test(window));
            const rollForm = comma(c.token) === form ? comma(c.roll) ?? c.roll : c.roll;
            const arbForm = comma(c.token) === form ? comma(c.arb) ?? c.arb : c.arb;
            sites.push({
              file: entry.file,
              line: i + 1,
              at: base + m.index,
              len: form.length,
              token: form,
              roll: rollForm,
              arb: arbForm,
              skip: excuse ? excuse[1] : null,
              src: line.trim().slice(0, 110),
            });
          }
        }
      }
      base += line.length + 1;
    });
  }

  const live = sites.filter((s) => !s.skip);
  const results = { rollback: { caught: [], missed: [] }, arbitrary: { caught: [], missed: [] } };
  const cache = new Map();
  const base = evaluate(rules);
  for (const kind of ["rollback", "arbitrary"]) {
    for (const s of live) {
      const text = cache.get(s.file) ?? readFile(s.file);
      cache.set(s.file, text);
      const to = kind === "rollback" ? s.roll : s.arb;
      const mutated = text.slice(0, s.at) + to + text.slice(s.at + s.len);
      const r = evaluate(rules, { file: s.file, text: mutated });
      // Caught means this mutation made the gate fail for a reason the untouched tree does not
      // already carry, so a document that is already declared stale cannot lend its failure here.
      const newViolations = r.violations.length > base.violations.length;
      const newDrops = r.floorDrops.length > base.floorDrops.length;
      (newViolations || newDrops ? results[kind].caught : results[kind].missed).push({ ...s, to });
    }
  }

  const total = live.length;
  console.log("MUTATION SWEEP. Every published figure in every guarded document, one token at a time.");
  console.log(`  sites found     ${sites.length}`);
  console.log(`  not a figure    ${sites.length - total}  (hex digests, section numbers, timing columns)`);
  console.log(`  sites swept     ${total}`);
  console.log("");
  for (const kind of ["rollback", "arbitrary"]) {
    const c = results[kind].caught.length;
    console.log(`  ${kind.padEnd(10)} caught ${String(c).padStart(3)} of ${total}   missed ${total - c}`);
  }
  console.log("");
  for (const kind of ["rollback", "arbitrary"]) {
    if (!results[kind].missed.length) continue;
    console.log(`MISSED, ${kind}:`);
    for (const m of results[kind].missed) {
      console.log(`  ${m.file}:${m.line}  ${m.token} -> ${m.to}`);
      console.log(`      ${m.src}`);
    }
    console.log("");
  }
  if (sites.length - total) {
    console.log("NOT A FIGURE, skipped:");
    for (const s of sites.filter((x) => x.skip)) console.log(`  ${s.file}:${s.line}  ${s.token}  (${s.skip})`);
  }
}

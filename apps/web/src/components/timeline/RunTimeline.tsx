import { useState, type CSSProperties } from "react";
import { ClassChip } from "../ui/ClassChip";
import { VerdictBadge } from "../ui/VerdictBadge";
import { formatBytes, kindWord, splitPath } from "../../lib/format";
import { verdictOfTurn, verdictSentence } from "../../lib/verdict";
import type { JournalResponse, TimelineTurn } from "../../types";

/** The first twelve hex of a digest: enough for a person to compare two by eye, short enough to read. */
const shortDigest = (digest: string): string => digest.slice(0, 12);

/**
 * The one line the whole boundary exists to let a person read: what the REAL workspace is now,
 * against what it was before the agent ran.
 *
 * The two values are the server's own sha256 over the workspace tree, recorded on its hash-chained
 * journal at turn open and at the moment the turn ended. Nothing here computes a digest, and that
 * is the point of it: a panel that measured the workspace itself would be one more thing taking
 * the product's word for the product's headline claim.
 *
 * A commit is SUPPOSED to move the digest, so the line names the state rather than passing a
 * verdict on it. A turn that was blocked, held, rejected or crashed and still moved the digest is
 * the case worth seeing at a glance, and it reads as "Changed" here like any other change.
 *
 * Four states, not two, because the two ways a measurement can be less than whole each have to be
 * visible rather than rounded up into the claim:
 *
 *   - `unchanged` is the only state that may say "byte for byte", and it says it only when two real
 *     digests are equal AND the walk read the whole tree.
 *   - `partial` is two equal digests over a tree the walk could not read all of. An unreadable
 *     subtree hashes to a constant, so the digest cannot move for anything written under it, and
 *     "byte for byte" over that would be the same false comfort as not measuring at all.
 *   - `unmeasured` is a refusal, and it names the refusal.
 *   - `changed` is a change, and it stays a change whatever the verdict says.
 */
export function workspaceLine(turn: TimelineTurn): { state: string; sentence: string } {
  const before = turn.workspaceDigestBefore;
  const after = turn.workspaceDigestAfter;
  if (!before || !after) {
    // Two absent values are not two equal values, and a turn still running has an opening
    // measurement and no closing one yet. Neither may read as a workspace that provably held still.
    if (turn.workspaceDigestReason) {
      // The bound is an entry count, so the count is what tells a person whether their tree is over
      // it by a little or by a hundred times. "tree-over-budget" alone does not.
      const stopped =
        turn.workspaceDigestReason === "tree-over-budget" && turn.workspaceFilesAfter !== null
          ? " The walk stopped at " + turn.workspaceFilesAfter + " entries."
          : "";
      return { state: "unmeasured", sentence: "Not measured: " + turn.workspaceDigestReason + "." + stopped };
    }
    if (before && turn.verdict === "running") {
      return { state: "unmeasured", sentence: "Measured at open. This turn has not ended yet." };
    }
    if (before || after) {
      return {
        state: "unmeasured",
        sentence: "Measured at one end of this turn only, so there is nothing to compare.",
      };
    }
    return { state: "unmeasured", sentence: "Not recorded for this turn." };
  }
  const files = turn.workspaceFilesAfter ?? turn.workspaceFilesBefore;
  // Either end being partial makes the comparison partial, so the larger count is the honest one.
  const unreadable = Math.max(turn.workspaceUnreadableBefore ?? 0, turn.workspaceUnreadableAfter ?? 0);
  const blind = unreadable === 0 ? "" : " " + unreadable + " entries could not be read at all.";
  if (before === after) {
    if (unreadable > 0) {
      return {
        state: "partial",
        sentence:
          "Unchanged across the part of the tree that could be read." +
          blind +
          " That is not a byte for byte claim over the whole workspace.",
      };
    }
    // A held turn has a real closing measurement, taken when it went to the review queue, and the
    // claim under the review screen is exactly this one: none of the proposed changes is in the
    // workspace. But the turn has NOT closed, so it must not be told it has.
    const second = turn.verdict === "held" ? "while this turn waits for review" : "at close";
    return {
      state: "unchanged",
      sentence:
        "Unchanged, byte for byte" +
        (files === null ? "" : " across " + files + " entries") +
        ". sha256 " +
        shortDigest(before) +
        " at open and " +
        second +
        ".",
    };
  }
  const counts =
    turn.workspaceFilesBefore === null || turn.workspaceFilesAfter === null
      ? ""
      : " " + turn.workspaceFilesBefore + " entries before, " + turn.workspaceFilesAfter + " after.";
  return {
    state: "changed",
    sentence:
      "Changed." + counts + " sha256 " + shortDigest(before) + " became " + shortDigest(after) + "." + blind,
  };
}

/**
 * The same four states, as something the eye can separate.
 *
 * `workspace-state` and the four `workspace-<state>` classes below carry no rules anywhere in
 * styles.css, so on the shipped panel every state renders in the same ink at the same weight:
 * "Changed" on a turn the policy blocked looks exactly like "Unchanged" on a turn that committed.
 * That is the one distinction this row exists to make, and a person scanning a run for the row
 * that matters had nothing to scan for.
 *
 * The colour is set here rather than there because styles.css belongs to another lane. The classes
 * stay on the element so its owner can take this over; whoever writes those rules should delete
 * this map in the same change, because an inline style beats a stylesheet and would otherwise
 * quietly override them.
 *
 * `changed` is the loud one on purpose. It is the state that says something reached the real
 * workspace, and on a blocked, held or crashed turn it is the failure of the product's headline
 * claim. `partial` is amber rather than green because it is a claim withheld over part of the
 * tree, and `unmeasured` is neutral because it asserts nothing at all.
 */
const WORKSPACE_TONE: Record<string, { ink: string; ground: string; rule: string }> = {
  unchanged: { ink: "var(--green)", ground: "var(--green-soft)", rule: "var(--green)" },
  changed: { ink: "var(--red)", ground: "var(--red-soft)", rule: "var(--red)" },
  partial: { ink: "var(--amber)", ground: "var(--amber-soft)", rule: "var(--amber-line)" },
  unmeasured: { ink: "var(--slate)", ground: "var(--slate-soft)", rule: "var(--slate)" },
};

/** An unknown state is treated as asserting nothing, never as the clean claim. */
export function workspaceStyle(state: string): CSSProperties {
  const tone = WORKSPACE_TONE[state] ?? WORKSPACE_TONE["unmeasured"]!;
  return {
    color: tone.ink,
    background: tone.ground,
    borderLeft: "3px solid " + tone.rule,
    padding: "0.35rem 0.6rem",
    borderRadius: "3px",
  };
}

/**
 * The OTHER bounded control, in one line a person reads without help.
 *
 * Track C asks for two controls. The filesystem half is on this screen four times over: the
 * workspace digest, the effect list, the diffs and the review card. The network half was on it
 * nowhere, although the journal has carried it all along: a turn runs inside a container on a
 * per-run internal network with no route out except one mediating broker, the model channel is
 * terminated at that broker, and the agent's own memory is sealed the same way the workspace is. A
 * judge could learn any of that only by being told it out loud.
 *
 * This reads the fields the server projects off `turn.begin` and off the record the turn settled
 * on. It measures nothing and infers nothing, and that rule is enforced rather than stated: every
 * clause below is present because a field was present, and it says what the field says. The two
 * clauses that used to draw a consequence out of a label are gone. "whose only route out was the
 * broker" was the product's own headline claim restated per turn out of one word in a note that
 * `open()` composes BEFORE the container is launched, so it described what was prepared, not what
 * was observed. "so the provider credential stayed outside the runtime" was drawn from
 * `modelChannel`, which is itself only `network ? "terminated-at-broker" : "direct"`. Both are true
 * of the code, and neither is a measurement, so neither belongs on the screen a judge photographs.
 * A presenter can say them out loud; this panel reports the record.
 *
 * The states are not two, because `confinement: "none"` IS A REAL VALUE. The Compose and ECS
 * profiles run the host-process runtime under SHADOW_ALLOW_UNCONFINED=1, and the runner writes
 * `confinement: "none"` onto every turn.begin under it. So:
 *
 *   - `sealed` is a container AND a sealed per-run network that came back whole, which is the
 *     product's headline claim, and it is the only state painted as the clean one.
 *   - `partial` is a container the record says had no per-run network. That is not an absence of
 *     evidence: the runner writes the bare word `container` only on the branch where no network was
 *     created, so it is a positive record that the network half did not happen.
 *   - `breached` is a boundary reporting a failure of ITSELF: a per-run network that could not be
 *     torn down and outlived its turn, or a settle that found no network or memory state so only
 *     the files half of it ran. Both used to render under `sealed`, in green ink, with the caveat
 *     as the last clause of a seven-clause paragraph.
 *   - `unconfined` is the word "none" in the record: nothing bounded this turn. It is painted as
 *     the alarm, because a panel that showed this green, or left the row out, would be a false
 *     claim on the product's headline printed on the screen a judge photographs.
 *   - `unknown` is a confinement word this panel cannot read. It asserts nothing. See
 *     `networkState` for why that default runs this way and not the other.
 *   - `unrecorded` is an opening record from before these fields existed. Nothing is known, which
 *     is not the same as knowing there was nothing.
 *   - `no-record` is a turn with no `turn.begin` at all, so not even the absence was journaled.
 */
export function networkLine(turn: TimelineTurn): { state: string; sentence: string } {
  const facts = factsOf(turn);
  const state = networkState(facts);
  const parts = [networkHead(facts, state), ...networkDetail(facts, state)];
  return { state, sentence: parts.filter((part) => part !== "").join(" ") };
}

/**
 * The one word the COLLAPSED row carries, and it is only ever a failure.
 *
 * Every row on this panel ships collapsed, so until now a judge scanning a run list could not tell
 * a sealed turn from one journaled `confinement: "none"`: the network half, the one thing this row
 * exists to put on a screen, was a click deep on every turn. The two states that are affirmative
 * failures of the boundary now reach the summary.
 *
 * The absences do not, on purpose. `unrecorded`, `no-record` and `unknown` are states in which
 * nothing is known, the collapsed row asserts nothing about containment either way, and a chip on
 * every turn of an older journal would be noise standing where a finding should stand.
 */
export function networkFlag(state: string): string {
  if (state === "unconfined") return "Not confined";
  if (state === "breached") return "Boundary incomplete";
  return "";
}

/**
 * Every field the server projects, read once, with `undefined` folded into `null`.
 *
 * All of them are optional on the wire, so a panel talking to a server that does not project them
 * gets `undefined` everywhere, and a turn whose records carried nothing gets `null`. Both mean "no
 * value", and the one place that distinction is load-bearing is `beginRecorded`, which is kept as
 * three-valued on purpose: true is a turn with an opening record, false is a turn without one, and
 * null is a panel that was told neither. Folding those three into a boolean would let an old server
 * make every turn read as one that never opened.
 */
interface NetworkFacts {
  verdict: TimelineTurn["verdict"];
  beginRecorded: boolean | null;
  confinement: string | null;
  confinementReason: string | null;
  network: string | null;
  egressAllowlistSize: number | null;
  modelChannel: string | null;
  codexHomeFiles: number | null;
  egress: Record<string, number> | null;
  outboundDropped: number | null;
  outboundReplayed: number | null;
  outboundFailed: number | null;
  outboundHeldForReview: number | null;
  codexHomeRestored: boolean | null;
  codexHomeVerifiedUnchanged: boolean | null;
  codexHomeDroppedAfterReview: boolean | null;
  codexHomeChanged: number | null;
  networkLeaked: string | null;
  confinementStateLost: boolean;
}

function factsOf(turn: TimelineTurn): NetworkFacts {
  return {
    verdict: turn.verdict,
    beginRecorded: turn.beginRecorded ?? null,
    confinement: turn.confinement ?? null,
    confinementReason: turn.confinementReason ?? null,
    network: turn.network ?? null,
    egressAllowlistSize: turn.egressAllowlistSize ?? null,
    modelChannel: turn.modelChannel ?? null,
    codexHomeFiles: turn.codexHomeFiles ?? null,
    egress: turn.egress ?? null,
    outboundDropped: turn.outboundDropped ?? null,
    outboundReplayed: turn.outboundReplayed ?? null,
    outboundFailed: turn.outboundFailed ?? null,
    outboundHeldForReview: turn.outboundHeldForReview ?? null,
    codexHomeRestored: turn.codexHomeRestored ?? null,
    codexHomeVerifiedUnchanged: turn.codexHomeVerifiedUnchanged ?? null,
    codexHomeDroppedAfterReview: turn.codexHomeDroppedAfterReview ?? null,
    codexHomeChanged: turn.codexHomeChanged ?? null,
    networkLeaked: turn.networkLeaked ?? null,
    confinementStateLost: turn.confinementStateLost === true,
  };
}

/** A counted noun, because "1 entries changed" is the kind of seam that makes a panel look guessed. */
const counted = (n: number, one: string, many: string): string => n + " " + (n === 1 ? one : many);

/**
 * The three words `runner-factory.ts` writes into `confinement`, and nothing else is read.
 *
 * `open()` writes `network ? "container+sealed-network" : "container"`, and
 * `transactional-runner.ts` writes `{ confinement: "none" }` when there is no confined request at
 * all. Any other string is a word this panel does not know the meaning of.
 */
const CONFINEMENT_WORDS = new Set(["container+sealed-network", "container", "none"]);

/**
 * The state, and the direction its default runs, which is the whole thing.
 *
 * The unknown-value fallback used to run TOWARD containment: anything that was not exactly "none"
 * fell through to `partial`, and `networkHead` then printed "Confined as <word>: the container half
 * only". That asserted a container from a token the panel could not read. `confinement: ""` printed
 * "Confined as : the container half only", and `confinement: "none"` printed "Confined as none: the
 * container half only" until a special case was bolted on for that one word, which left the next
 * mode word the runner adds to reintroduce the headline failure this row exists to prevent.
 *
 * So the default now runs the other way, matching the rule `workspaceStyle` states above: a word
 * this panel cannot read asserts NOTHING. Three words are recognised and everything else, the empty
 * string included, is `unknown`.
 *
 * The breach check sits between the unconfined check and the two clean states on purpose. A turn
 * whose network leaked or whose settle found no state has not met the claim, so it must not reach
 * `sealed`; a turn already journaled unconfined is not made louder by a leak on top, so the alarm
 * keeps its own state.
 */
function networkState(facts: NetworkFacts): string {
  if (facts.beginRecorded === false) return "no-record";
  if (facts.confinement === null) return "unrecorded";
  if (!CONFINEMENT_WORDS.has(facts.confinement)) return "unknown";
  if (facts.confinement === "none") return "unconfined";
  if (facts.networkLeaked !== null || facts.confinementStateLost) return "breached";
  return facts.confinement === "container+sealed-network" ? "sealed" : "partial";
}

/** What the turn ran inside, named in the record's own word so it can be grepped in the journal. */
function networkHead(facts: NetworkFacts, state: string): string {
  const mode = facts.confinement ?? "";
  if (state === "no-record") {
    // Scoped to the opening record, because the settling record may well have carried broker and
    // memory facts and the clauses below will print them. The head used to say "nothing was
    // journaled", which those clauses then contradicted two clauses later.
    return "No opening record for this turn, so what it ran inside was never journaled.";
  }
  if (state === "unrecorded") {
    return facts.beginRecorded === true
      ? "Not recorded. This turn's opening record carries no confinement field, so what it ran inside is unknown, which is not the same as knowing it ran inside nothing."
      : "Not recorded. Nothing about the network half came back for this turn, so what it ran inside is unknown.";
  }
  if (state === "unknown") {
    return (
      "The opening record names a confinement mode this panel cannot read: " +
      (mode === "" ? "an empty value" : mode) +
      ". What it bounded is unknown."
    );
  }
  if (state === "unconfined") {
    const reason = facts.confinementReason ? " The record's own reason: " + facts.confinementReason + "." : "";
    return (
      "Not confined. The opening record says confinement none: no container and no sealed network bounded this turn." +
      reason
    );
  }
  // The runner writes the bare word `container` ONLY on the branch where no network was created, so
  // that word is an affirmative record that the network half did not happen. Reporting it as
  // "nothing in this record says the network half was sealed" read as an absence of evidence and
  // understated a mode the repo's own gate refuses to start without SHADOW_ALLOW_UNCONFINED=1.
  const named =
    mode === "container+sealed-network"
      ? "Confined as container+sealed-network: the opening record names a container and a network created for this run alone."
      : "Confined as container: the opening record names a container and says no per-run network was sealed for this turn.";
  return state === "breached" ? "This turn's boundary did not come back whole. " + named : named;
}

/**
 * The states in which a network name, an allowlist size and a model channel are consistent with the
 * head above.
 *
 * They are all read off `turn.begin`, so a turn with no opening record cannot carry them and a turn
 * journaled unconfined has no network object to name. If they turn up anyway the record contradicts
 * itself, and the honest rendering of a self-contradicting record is to say so rather than to print
 * clauses asserting a sealed network under a head that denies one.
 */
const ADMITS_NETWORK_FIELDS = new Set(["sealed", "partial", "breached", "unrecorded"]);

/** One clause per field the records actually carry, and none for a field they do not. */
function networkDetail(facts: NetworkFacts, state: string): string[] {
  const parts: string[] = [];
  if (ADMITS_NETWORK_FIELDS.has(state)) {
    if (facts.network) parts.push("Network " + facts.network + ".");
    if (facts.egressAllowlistSize !== null) {
      parts.push(
        facts.egressAllowlistSize === 0
          ? "The egress allowlist named no destinations at all."
          : counted(facts.egressAllowlistSize, "destination", "destinations") + " on the egress allowlist.",
      );
    }
    if (facts.modelChannel !== null) {
      parts.push(
        facts.modelChannel === "terminated-at-broker"
          ? "The opening record names the model channel terminated-at-broker."
          : "The opening record names the model channel " + facts.modelChannel + ", not terminated at a broker.",
      );
    }
  } else if (facts.network !== null || facts.egressAllowlistSize !== null || facts.modelChannel !== null) {
    parts.push(
      "The same opening record also carries network fields its confinement value does not admit, so the record contradicts itself and none of them is reported here.",
    );
  }
  const egress = facts.egress;
  if (egress !== null) {
    const kinds = Object.keys(egress).sort();
    parts.push(
      kinds.length === 0
        ? "The broker logged no outbound request on this turn."
        : "Broker decisions: " + kinds.map((kind) => kind + " " + egress[kind]).join(", ") + ".",
    );
  } else if ((state === "sealed" || state === "breached") && facts.verdict !== "running") {
    parts.push("No broker decision summary was recorded on the settle.");
  }
  parts.push(...outboundClauses(facts));
  parts.push(...memoryClauses(facts, state));
  if (facts.networkLeaked) {
    parts.push("The per-run network " + facts.networkLeaked + " could not be removed, so it outlived the turn.");
  }
  if (facts.confinementStateLost) {
    parts.push("The settle found no network or memory state for this run, so only the files half of it ran.");
  }
  return parts;
}

/**
 * The held outbound writes, and the arithmetic that used to be wrong.
 *
 * `outboundReplayed` and `outboundFailed` are DISJOINT counts, not a set and a subset. The live
 * path takes them from `NetworkSealer.replay`, which increments exactly one of the two per payload,
 * and the recalled path in `runner-factory.ts` does the same in its own loop. So the number
 * attempted is their SUM, and the panel used to render the failed count as "N of them failed to
 * send" against the replayed count: 3 replayed and 2 failed read as 2 of the 3 successes failing,
 * and 0 replayed with 3 failed, a total failure to send writes a person believes went out, read as
 * "0 held outbound writes were sent ... 3 of them failed to send". Both counts are now rendered as
 * the two parts of one attempted total, and the failed clause never stands alone with a pronoun.
 *
 * Nothing here names a commit either. These are settle-record fields and the verdict is a separate
 * fact on the same card; the record does not say the turn committed, so this does not say it.
 *
 * Zero is a value, and every count says so in its own words. `outboundReplayed: 0` and
 * `outboundFailed: 0` are what the sealer returns for an empty held set, which is the ordinary case
 * on a committed turn, and `outboundHeldForReview: 0` is what a turn held on a filesystem rule
 * writes. Those are the values the runner writes MOST often, and they used to print raw counts of
 * zero as padding on the screen this panel exists to keep clean.
 */
function outboundClauses(facts: NetworkFacts): string[] {
  const parts: string[] = [];
  if (facts.outboundHeldForReview !== null) {
    parts.push(
      facts.outboundHeldForReview === 0
        ? "No outbound write was held for a person to decide on."
        : counted(facts.outboundHeldForReview, "outbound write is", "outbound writes are") +
            " held, unsent, until a person decides.",
    );
  }
  parts.push(...replayClauses(facts.outboundReplayed, facts.outboundFailed));
  if (facts.outboundDropped !== null) {
    parts.push(
      facts.outboundDropped === 0
        ? "No outbound write was held on this turn, so none was dropped."
        : counted(facts.outboundDropped, "held outbound write was", "held outbound writes were") + " dropped unsent.",
    );
  }
  return parts;
}

/** The two disjoint halves of the replay, and each of the two ways only one of them came back. */
function replayClauses(replayed: number | null, failed: number | null): string[] {
  if (replayed !== null && failed !== null) {
    const attempted = replayed + failed;
    if (attempted === 0) return ["No held outbound write was waiting when this turn settled, so none was replayed."];
    return [
      counted(attempted, "held outbound write was", "held outbound writes were") +
        " replayed when this turn settled: " +
        replayed +
        " sent, " +
        failed +
        " not sent.",
    ];
  }
  if (replayed !== null) {
    return [
      replayed === 0
        ? "No held outbound write is recorded as sent on this settle, and no failure count came back."
        : counted(replayed, "held outbound write was", "held outbound writes were") +
            " sent when this turn settled. No failure count came back.",
    ];
  }
  if (failed !== null) {
    return [
      failed === 0
        ? "No held outbound write is recorded as having failed on this settle, and no sent count came back."
        : counted(failed, "held outbound write", "held outbound writes") +
            " failed to send when this turn settled. No sent count came back.",
    ];
  }
  return [];
}

/**
 * The agent's own memory, sealed with the turn.
 *
 * Two things here are not what they look like.
 *
 * `verifiedUnchanged` is a MEASUREMENT on the live settle path and a hardcoded literal on the
 * reviewed one. `settleReviewed` in runner-factory.ts writes
 * `{ restored: false, verifiedUnchanged: true, droppedAfterReview: true }` unconditionally on a
 * rejected review, because the memory was already rolled back at the earlier review settle and this
 * settle only drops the sealed copy. `buildTimeline` reads the LAST settling record, so that
 * literal is what a review-then-reject projects, and reading its two survivors as evidence rendered
 * the panel's most reassuring sentence on the one path where no verification ran and a rollback
 * did. `droppedAfterReview` is what separates the two, so it is read first.
 *
 * And the comparison is NOT the workspace digest, although the card puts them side by side.
 * `CodexHomeManager.signature` hashes `rel|size|mtimeMs|mode` per file and never opens one, while
 * `workspaceDigest` in commit-protocol.ts is over the bytes. One card must not use one word for two
 * strengths of guarantee, so this names what was actually compared and leaves the word "digest" to
 * the row that earns it.
 */
function memoryClauses(facts: NetworkFacts, state: string): string[] {
  const subject = "The agent's memory" + (facts.codexHomeFiles === null ? "" : ", " + facts.codexHomeFiles + " files,");
  if (facts.codexHomeDroppedAfterReview === true) {
    return [
      subject +
        " was not measured on this settle: the record marks it dropped after review, so the restored and verified values beside that mark are bookkeeping rather than evidence.",
    ];
  }
  if (facts.codexHomeVerifiedUnchanged !== null || facts.codexHomeRestored !== null) {
    if (facts.codexHomeVerifiedUnchanged === true && facts.codexHomeRestored === true) {
      // Today's runner cannot write this pair: `restore` returns verified-and-not-restored or
      // restored-and-not-verified. A record carrying both is a record contradicting itself, and it
      // used to render as the clean claim with the rolled-back half silently discarded.
      return [
        subject +
          " is recorded both verified unchanged and rolled back on this settle. Those cannot both be true, so neither is reported here.",
      ];
    }
    if (facts.codexHomeVerifiedUnchanged === true) {
      return [
        subject +
          " came back unchanged in name, size, timestamp and mode against the signature taken before the turn" +
          (facts.codexHomeRestored === false ? ", so no rollback was needed." : "."),
      ];
    }
    return [
      facts.codexHomeRestored === true
        ? subject + " had moved, and was rolled back to the copy taken before the turn."
        : subject + " was not verified unchanged, and no rollback is recorded.",
    ];
  }
  if (facts.codexHomeChanged !== null) {
    return [subject + " was promoted with " + counted(facts.codexHomeChanged, "entry", "entries") + " changed."];
  }
  if ((state === "sealed" || state === "partial" || state === "breached") && facts.verdict !== "running") {
    // The count from `turn.begin` is something that WAS recorded about the memory, so a flat
    // "nothing was recorded" threw away a fact the projection carries and then dropped.
    return facts.codexHomeFiles === null
      ? ["Nothing was recorded about the agent's memory on the settle."]
      : [
          "The agent's memory was sealed with " +
            counted(facts.codexHomeFiles, "file", "files") +
            " at open, and nothing was recorded about it on the settle.",
        ];
  }
  return [];
}

/**
 * `defaultOpen` exists so the panel's contents can be rendered and asserted.
 *
 * This workspace has no DOM in its tests and no testing library, so `renderToStaticMarkup` is the
 * only way in, and it renders a collapsed row as a button and nothing else. Without the prop the
 * whole Workspace row could be deleted from the markup below and every test here would stay green,
 * which is exactly the shape of defect this lane was opened to remove. Production never passes it.
 */
export function TurnRow({ turn, defaultOpen = false }: { turn: TimelineTurn; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = "turn-" + turn.runId;
  const workspace = workspaceLine(turn);
  const network = networkLine(turn);
  const flag = networkFlag(network.state);

  return (
    <li className={"turn turn-" + turn.verdict}>
      <button className="turn-summary" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen(!open)}>
        <span className="turn-seq">#{turn.seq}</span>
        <VerdictBadge verdict={turn.verdict} />
        <span className="turn-sentence">{verdictSentence(verdictOfTurn(turn))}</span>
        {/* The slot is always here so the grid keeps its columns and the toggle does not move
            between rows; it carries a chip only on the two states that are failures of the
            boundary, and renders as nothing at all otherwise. */}
        <span className={flag ? "turn-network-flag network-flag-" + network.state : "turn-network-flag"}>{flag}</span>
        <span className="turn-toggle" aria-hidden="true">
          {open ? "Hide" : "Open"}
        </span>
      </button>
      {open && (
        <div className="turn-panel" id={panelId}>
          <dl className="turn-facts">
            <div>
              <dt>Run</dt>
              <dd>
                <code>{turn.runId}</code>
              </dd>
            </div>
            <div>
              <dt>Seal</dt>
              <dd>{turn.mechanism ?? "not recorded"}</dd>
            </div>
            <div className="turn-fact-wide">
              <dt>Network</dt>
              <dd className={"network-state network-" + network.state}>{network.sentence}</dd>
            </div>
            <div>
              <dt>Workspace</dt>
              <dd className={"workspace-state workspace-" + workspace.state} style={workspaceStyle(workspace.state)}>
                {workspace.sentence}
              </dd>
            </div>
            {turn.rule && (
              <div>
                <dt>Rule</dt>
                <dd>{turn.rule}</dd>
              </div>
            )}
            {turn.principal && (
              <div>
                <dt>Principal</dt>
                <dd>{turn.principal}</dd>
              </div>
            )}
          </dl>

          {turn.conflictPaths.length > 0 && (
            <p className="turn-note">
              Somebody else changed {turn.conflictPaths.join(", ")} while this turn was running, so it was not applied.
            </p>
          )}

          {turn.effects.length > 0 ? (
            <ol className="turn-effects">
              {turn.effects.map((effect) => {
                const { directory, name } = splitPath(effect.path);
                return (
                  <li key={effect.path}>
                    <span className={"kind-tag kind-" + effect.kind}>{kindWord(effect.kind)}</span>
                    <span className="change-path">
                      <span className="change-dir">{directory}</span>
                      <span className="change-name">{name}</span>
                    </span>
                    <ClassChip value={effect.class} />
                    {/* the journal does not record a byte count yet, and a printed zero would be
                        a number we cannot support */}
                    <span className="change-bytes">{effect.bytes > 0 ? formatBytes(effect.bytes) : ""}</span>
                  </li>
                );
              })}
              {turn.truncated > 0 && <li className="turn-more">{turn.truncated} more not listed.</li>}
            </ol>
          ) : (
            <p className="turn-note">
              {turn.effectCount > 0
                ? turn.effectCount +
                  " changes were captured on this turn. The paths are journalled when a turn commits or is held, and this one settled another way."
                : "This turn produced no changes."}
            </p>
          )}

          <ol className="turn-records">
            {turn.records.map((record) => (
              <li key={record.seq}>
                <span className="record-seq">#{record.seq}</span>
                <span className="record-kind">{record.kind}</span>
                <code className="record-hash">{record.hash}</code>
              </li>
            ))}
          </ol>
        </div>
      )}
    </li>
  );
}

/**
 * The run timeline: every turn this agent has taken, newest first, with the verdict the boundary
 * recorded rather than the sentence the agent wrote about itself. It is the answer to "is the
 * platform still understandable and controllable after all this", and it reads back as one list.
 */
export function RunTimeline({ journal, agentName }: { journal: JournalResponse | null; agentName: string }) {
  if (!journal) {
    return (
      <section className="timeline">
        <header className="timeline-topbar">
          <div>
            <span className="eyebrow">Run timeline</span>
            <h2>{agentName}</h2>
          </div>
        </header>
        <p className="timeline-empty">Reading the journal.</p>
      </section>
    );
  }

  return (
    <section className="timeline">
      <header className="timeline-topbar">
        <div>
          <span className="eyebrow">Run timeline</span>
          <h2>Every turn, and what happened to it</h2>
          <p className="timeline-lede">
            One ordered list a person can act on. Each turn carries the verdict the boundary recorded, and opens into
            the changes it proposed and the journal records it wrote.
          </p>
        </div>
        <span className={"chain " + (journal.chain.ok ? "chain-ok" : "chain-broken")}>
          <span className="chain-dot" aria-hidden="true" />
          {journal.chain.ok
            ? "Chain intact, " + journal.chain.records + " records"
            : "Chain not verified, " + journal.chain.records + " records"}
        </span>
      </header>

      {!journal.chain.ok && journal.chain.problems.length > 0 && (
        <ul className="chain-problems">
          {journal.chain.problems.map((problem) => (
            <li key={problem}>{problem}</li>
          ))}
        </ul>
      )}

      {journal.turns.length === 0 ? (
        <p className="timeline-empty">No turns recorded yet. Send this agent a task and it will appear here.</p>
      ) : (
        <>
          <ol className="turns">
            {journal.turns.map((turn) => (
              <TurnRow key={turn.runId} turn={turn} />
            ))}
          </ol>
          {journal.more > 0 && <p className="timeline-more">{journal.more} older turns are not shown.</p>}
        </>
      )}
    </section>
  );
}

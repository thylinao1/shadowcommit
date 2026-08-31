import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { canonicalise, isProtectedPath } from "../effect-classifier.js";
import { readWitnessOf, type ReadWitnessRecord } from "../read-witness.js";

/**
 * The one rule that judges what a turn OPENED rather than what it wrote.
 *
 * `EffectKind` is create, modify, delete, symlink, outbound. A turn that opens every credential in
 * the sealed view and writes nothing produces an empty effect set, so every other rule in this
 * directory abstains over nothing and the turn commits under rule `none`. `read-witness.ts` has
 * recorded that turn's reads since it was wired, and until this file nothing consumed the record.
 *
 * ## Why the raw record is not the rule
 *
 * `docs/READ-WITNESS.md` measured the raw protected-read bit over 96 real turns on
 * four real workspaces: 48 of 48 read-only attack turns carry one, and so do 17 of 48 benign turns,
 * a 35.4% false positive rate. A rule at that rate is not a control, it is a second queue. Twelve
 * of the seventeen are whole-tree sweeps (`grep -rn router .`, `find . -type f -exec wc -l {} +`),
 * which a coding agent runs all day and which pull the credential files up with everything else.
 *
 * So three narrowings stand between the bit and a hold, and each one is measured rather than
 * guessed.
 *
 * ### 1. Selectivity, which separates a theft from a sweep
 *
 * `reads / armed`. The same 96 turns:
 *
 * ```
 * attack   n=48 min 0.0000 median 0.0139 max 0.0435
 * benign   n=17 min 0.0046 median 1.0000 max 1.0000
 *   selectivity <= 0.05  catches 48/48 of attacks, fires on 5/48 = 10.4% of benign
 * ```
 *
 * Every attack read under 5% of the workspace and every sweep read 100% of it, so the cut is taken
 * at 0.05: the lowest value that costs nothing in detection, in the middle of a gap between 0.0435
 * and 1.0000 that is wide enough that the threshold is not being tuned to the sample.
 *
 * ### 2. A denominator large enough for that fraction to mean anything
 *
 * `selectivity <= 0.05` with at least one read requires `armed >= 20`. Below that, NO turn that
 * read a file can pass the gate, and the only turns that still can are the ones with `reads == 0`,
 * which is the tamper shape. That is not the behaviour the numbers above describe: on a small tree
 * the gate silently stops selecting "a targeted read" and starts selecting "a read that left no
 * read bit". `MIN_ARMED_FILES` keeps the rule inside the regime it was measured in. The four
 * measured workspaces carried 69, 70, 169 and 216 armed files. A workspace under twenty files is
 * not judged by this rule at all, and that is a stated hole rather than a silent one.
 *
 * ### 3. Reading alone is ordinary, so the read has to be joined to something
 *
 * Opening a credential and then writing application code is what an agent asked to wire up a
 * database does. Two shapes are not that:
 *
 *   - the turn wrote NOTHING. Nothing was proposed, nothing can be rolled back, and what the turn
 *     learned has already left through the model channel, which the broker allowlists.
 *   - the turn made an OUTBOUND request. The broker held the body and `outbound-provenance` judges
 *     what is in it; this says the same turn also opened a protected file, which is the pairing the
 *     content of one held body cannot show on its own.
 *
 * ## What is left, said here rather than found later
 *
 * The residue is not tunable. Four of the five benign turns that survive every threshold are
 * `grep PORT .env` on four different workspaces, and that is byte for byte the same filesystem
 * event as a theft of the same file. The difference is intent and intent is not on the disk. The
 * fifth was a read of `.env.example`, a checked-in template with no credential in it that the
 * shipped protected pattern matches anyway, and this rule drops template spellings from its own
 * protected set for that reason. It does not touch `isProtectedPath`, because the same name as a
 * WRITE target is a different question and belongs to whoever owns that predicate.
 *
 * The decision is `review` and only `review`. A false positive here costs a person one look at a
 * held turn; it can never destroy work. That asymmetry is the whole reason this rule is allowed to
 * run on a signal with a measured floor under its false positive rate.
 */

export const READ_EXPOSURE_RULE = "protected-read-exposure";

/**
 * The fraction of the armed tree a turn may open and still be treated as targeted.
 *
 * Measured: attacks max 0.0435, benign sweeps 1.0000. See the lane report table above.
 */
export const SELECTIVITY_CEILING = 0.05;

/**
 * The smallest armed tree on which `SELECTIVITY_CEILING` can be reached by a turn that read one
 * file, which is `ceil(1 / SELECTIVITY_CEILING)`. Below it the gate selects the wrong thing.
 */
export const MIN_ARMED_FILES = 20;

/** what `summariseReadWitness` appends to an observation that is not a plain read */
const TAMPERED_MARKER = " (timestamp-tampered)";

/**
 * Checked-in stand-ins for a credential file, which the shipped protected pattern matches and which
 * carry nothing to steal. `.env.example` was one of the five benign turns that fired at every
 * selectivity threshold in the lane measurement.
 */
const TEMPLATE_SUFFIX = /\.(example|sample|template|dist|default)$/;

/** the path a summary line names, with the kind marker taken back off */
export function observedPath(entry: string): string {
  return entry.endsWith(TAMPERED_MARKER) ? entry.slice(0, -TAMPERED_MARKER.length) : entry;
}

/**
 * The protected files this turn opened, named.
 *
 * Derived from the summary's own path list rather than from the `protectedReads` COUNT, for two
 * reasons that both matter to an operator. A hold has to say which file, and a count cannot. And
 * the template exclusion above is a decision about a name, which a count has already thrown away.
 *
 * `summariseReadWitness` ranks protected observations first and truncates after, so a bounded list
 * keeps every protected path it had unless there were more than the bound, which is 64 by default.
 */
export function protectedReadsIn(
  record: ReadWitnessRecord,
  protectedPaths: readonly RegExp[],
): string[] {
  const found: string[] = [];
  for (const entry of record.paths) {
    const observed = observedPath(entry);
    const canonical = canonicalise(observed);
    if (TEMPLATE_SUFFIX.test(canonical)) continue;
    if (!isProtectedPath(canonical, protectedPaths)) continue;
    found.push(observed);
  }
  return found;
}

/** why this turn is not judgeable on its reads, or null when it is */
export type ReadExposureAbstention =
  | "no-witness"
  | "unsupported"
  | "tree-too-small"
  | "no-protected-read"
  | "swept-the-tree"
  | "ordinary-work";

export interface ReadExposure {
  /** "silent" when the turn wrote nothing, "outbound" when it also sent something */
  shape: "silent" | "outbound";
  paths: string[];
  selectivity: number;
  armed: number;
}

/**
 * The whole decision, as a function, so every gate can be exercised without a rule harness.
 *
 * Returns the abstention slug rather than a bare null, because "this mechanism was not watched",
 * "this mount cannot see reads" and "this turn opened nothing protected" are three different
 * answers and a caller that collapses them is quoting a silence as if it were evidence.
 */
export function readExposureOf(
  effects: readonly EffectRecord[],
  ctx: PolicyContext,
): ReadExposure | ReadExposureAbstention {
  const record = readWitnessOf(ctx);
  // Null is "not watched": the overlay mechanism, or any caller that built a context without one.
  if (record === null) return "no-witness";
  // `supported: false` is "this mount cannot show reads". Neither of these is "read nothing", and
  // only a supported record with reads of zero says that.
  if (!record.supported) return "unsupported";
  if (record.selectivity === null || record.armed < MIN_ARMED_FILES) return "tree-too-small";

  const paths = protectedReadsIn(record, ctx.protectedPaths);
  if (paths.length === 0) return "no-protected-read";
  if (record.selectivity > SELECTIVITY_CEILING) return "swept-the-tree";

  const outbound = effects.some((effect) => effect.kind === "outbound");
  if (!outbound && effects.length > 0) return "ordinary-work";
  return {
    shape: outbound ? "outbound" : "silent",
    paths,
    selectivity: record.selectivity,
    armed: record.armed,
  };
}

/** the files, bounded, so a hold names its evidence without printing a directory listing */
const NAMED_PATHS = 5;

function detailFor(exposure: ReadExposure): string {
  const named = exposure.paths.slice(0, NAMED_PATHS).join(", ");
  const rest = exposure.paths.length - Math.min(exposure.paths.length, NAMED_PATHS);
  const files = rest > 0 ? `${named} and ${rest} more` : named;
  const fraction = `${exposure.paths.length} of ${exposure.armed} watched files, selectivity ${exposure.selectivity.toFixed(4)}`;
  return exposure.shape === "outbound"
    ? `the turn opened ${files} and then made an outbound request (${fraction})`
    : `the turn opened ${files} and wrote nothing, so there is no effect to roll back (${fraction})`;
}

export const readExposureRule: Rule = {
  name: READ_EXPOSURE_RULE,
  summary:
    "A turn that opened a protected file selectively and either wrote nothing at all or made an outbound request, read off the access-time witness rather than the effect set.",
  decisions: ["review"],
  hitIds: ["protected-read-exposure"],
  async run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> {
    const exposure = readExposureOf(effects, ctx);
    if (typeof exposure === "string") return [];
    // `paths` is non-empty by construction, and the hit names the first of them: the summary ranks
    // protected observations first, so the first is the one an operator needs on the review card.
    const first = exposure.paths[0];
    return [
      {
        rule: READ_EXPOSURE_RULE,
        decision: "review",
        ...(first === undefined ? {} : { path: first }),
        detail: detailFor(exposure),
      },
    ];
  },
};

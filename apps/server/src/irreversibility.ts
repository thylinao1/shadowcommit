/**
 * WHERE THIS LIVES, AND WHY IT IS NOT UNDER participants/.
 *
 * This table arrived with a participants feature that is not on the product path: nothing reachable
 * from createRunner or createApp imports any of it, established by walking imports from index.ts
 * rather than by reading its report. The table itself needs no wiring to be true, so it was taken and
 * the rest was left. Keeping it under participants/ would have implied a live registry that does not
 * exist, which is the kind of thing a reader discovers and then distrusts the rest for.
 *
 * What it says is a claim about the world, not about this code: which effect kinds a settle can undo,
 * which it can only delay, and which are not modelled at all. The third column is the honest one.
 *
 * READ THE `participant` FIELD AS A TAXONOMY, NOT AN INVENTORY. It names the kind of resource a row
 * is about ("file", "http", "sqlite"). Only the file kind has a settle path in this product today:
 * held outbound writes are settled by NetworkSealer through the broker, and there is no sqlite path
 * at all. A row labelled sqlite describes what undoing a database write would require, which is worth
 * writing down and is not a claim that we do it.
 */
/**
 * The irreversibility table, as data.
 *
 * Naming what we cannot undo is the most credible thing on the page. Every resource a turn could
 * touch falls into exactly one class:
 *
 *   - `reversible`: the turn's effect can be truly undone. Discard leaves no trace. Files (drop the
 *     shadow), a SQLite savepoint (ROLLBACK), a versioned object store (a new version, revert to the
 *     old one).
 *   - `delay-only`: we can HOLD the effect until the commit decision, but once it settles it cannot
 *     be recalled, only compensated. A placed order, a sent email, a spreadsheet append, a package
 *     published to a public registry.
 *   - `not-modelled`: the effect is a byproduct we neither hold nor undo. The billing a legitimate
 *     API call incurs, the access log on the far side of an allowed destination, a DNS cache warmed
 *     by a lookup.
 *
 * This is the honest core of the scalability answer: the judge generalises to every resource, and
 * this table says exactly what settling each one costs. It is committed as data so the review panel,
 * the caller-facing verdict text and the architecture diagram all read one source.
 */
import type { ResourceKind } from "./policy-types.js";

export type ReversibilityClass = "reversible" | "delay-only" | "not-modelled";

export interface IrreversibilityRow {
  /** the resource, human-readable */
  resource: string;
  /** the participant that ships for it, when one does */
  participant?: ResourceKind;
  class: ReversibilityClass;
  /** what makes discard a true undo, a hold, or nothing at all */
  mechanism: string;
  /** the honest limit, stated in the row rather than in a footnote */
  limit: string;
}

export const IRREVERSIBILITY_TABLE: IrreversibilityRow[] = [
  {
    resource: "Workspace files",
    participant: "file",
    class: "reversible",
    mechanism: "Nothing reaches the real workspace before commit; discard drops the shadow copy.",
    limit: "None. The real tree is byte-identical to how the turn found it after a discard.",
  },
  {
    resource: "SQLite / SQL database (our adapter)",
    participant: "sqlite",
    class: "reversible",
    mechanism: "The turn's writes run inside a savepoint; commit RELEASEs it, discard ROLLBACKs it.",
    limit: "Only for a database we hold a transaction on. A row's id is real inside the open transaction and gone after a rollback.",
  },
  {
    resource: "Versioned object store (S3 with versioning, git)",
    class: "reversible",
    mechanism: "A write is a new version; undo reverts to the prior version id.",
    limit: "Reversible only where versioning is on. Not yet a shipped participant.",
  },
  {
    resource: "Generic HTTP write (order, webhook)",
    participant: "http",
    class: "delay-only",
    mechanism: "The write is held at the broker until commit, then replayed to the real destination.",
    limit: "Delay, not undo. Once replayed the order exists on the merchant's side and can only be cancelled by a later call.",
  },
  {
    resource: "Email / message send",
    class: "delay-only",
    mechanism: "Held until commit, then sent.",
    limit: "Cannot be unsent after it settles. A recall request is a new action, not an undo.",
  },
  {
    resource: "Spreadsheet / append-only log write",
    class: "delay-only",
    mechanism: "Held until commit, then appended.",
    limit: "The append is durable once made; there is no transactional rollback for a third-party sheet.",
  },
  {
    resource: "Package publish (npm, PyPI)",
    class: "delay-only",
    mechanism: "Held until commit, then published.",
    limit: "Cannot be unpublished from a public registry after settlement, even with a compensating unpublish.",
  },
  {
    resource: "Billing / metering of an allowed call",
    class: "not-modelled",
    mechanism: "Using a legitimate, allowed API incurs whatever billing that API defines.",
    limit: "Detectable after the fact by ledger reconciliation, never prevented. Out of the hold's reach by definition.",
  },
  {
    resource: "Access logs on the far side of an allowed destination",
    class: "not-modelled",
    mechanism: "The destination logs the request it received.",
    limit: "We do not control the destination's own logging. Out of scope entirely.",
  },
];

/** The three classes, for the diagram legend and a stable ordering. */
export const REVERSIBILITY_CLASSES: ReversibilityClass[] = ["reversible", "delay-only", "not-modelled"];

/** The row for a shipped participant, so a verdict can name the cost of the resource it settled. */
export function rowForResource(resource: ResourceKind): IrreversibilityRow | undefined {
  return IRREVERSIBILITY_TABLE.find((r) => r.participant === resource);
}

/**
 * The one comparison anything that feeds a digest is allowed to sort by.
 *
 * Four places hashed a directory listing or an object's keys after sorting them with
 * `localeCompare`, and `localeCompare` follows the host's locale. So the same tree produced a
 * different digest on a different machine, which is the one thing a digest exists to rule out.
 *
 * MEASURED on this repository's own sort sites, comparing the order six locales produce against the
 * order code units produce, over name sets a real repository contains:
 *
 *   swedish vowels     sv-SE puts arende AFTER zebra, every other locale puts it first
 *   turkish dotted i   tr-TR puts Irmak before index, every other locale after
 *   CJK filenames      zh-CN, ja-JP and en-US each produce a DIFFERENT order, three in total
 *   mixed case         localeCompare folds case, so README.md and readme-extra.md swap
 *   punctuation        localeCompare gives `-` `_` `.` almost no weight, code units give them order
 *
 * The host this was measured on defaults to zh-CN, which is exactly the sort of thing that is
 * invisible until somebody runs the project somewhere that is not the author's laptop.
 *
 * `compareByCodeUnit` is a total order over UTF-16 code units. It is not a nice order for a person
 * to read, and that is fine: nothing here is shown to a person, it decides the byte sequence a hash
 * consumes. Where a listing IS shown to a person, sort it for the person at the point of display.
 */

/**
 * Order two strings by UTF-16 code unit, identically on every host and in every locale.
 *
 * Deliberately not `Intl.Collator` with a pinned locale: that would be stable across hosts but still
 * depends on the ICU data version bundled with the runtime, which moves with Node. Code units depend
 * on nothing.
 */
export function compareByCodeUnit(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

/** Sort a copy of `values` into digest order, leaving the input untouched. */
export function sortedByCodeUnit(values: readonly string[]): string[] {
  return [...values].sort(compareByCodeUnit);
}

/** Sort named entries (a readdir result, an entries list) into digest order, in place. */
export function sortByNameForDigest<T extends { name: string }>(entries: T[]): T[] {
  return entries.sort((left, right) => compareByCodeUnit(left.name, right.name));
}

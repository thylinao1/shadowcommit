// Wilson score intervals and the sample-size arithmetic behind the section 8 table.
//
// The normal-approximation interval is wrong at the rates this corpus reports: at 0 successes in
// 400 it returns [0, 0], which would let us publish a zero miss rate with no uncertainty at all.
// Wilson does not, which is the whole reason section 8 uses it.

/** Two-sided z for a given confidence. 95 percent is the only level this corpus publishes. */
export const Z95 = 1.959963984540054;

/**
 * Wilson score interval for k successes in n trials.
 * Returns fractions in [0, 1]; n = 0 returns the whole interval, because no data means no bound.
 */
export function wilson(k, n, z = Z95) {
  if (n === 0) return { point: 0, low: 0, high: 1 };
  const p = k / n;
  const d = 1 + (z * z) / n;
  const centre = (p + (z * z) / (2 * n)) / d;
  const half = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return { point: p, low: Math.max(0, centre - half), high: Math.min(1, centre + half) };
}

/** The interval as percentages rounded to one decimal, the form the report prints. */
export function wilsonPct(k, n, z = Z95) {
  const w = wilson(k, n, z);
  const r = (x) => Math.round(x * 1000) / 10;
  return { point: r(w.point), low: r(w.low), high: r(w.high) };
}

/**
 * The smallest n for which observing `misses` misses puts the whole 95 percent Wilson upper bound
 * below `target`. This is the arithmetic that produced the section 8 table, recomputed rather than
 * copied, so the table in REPORT.md is checkable.
 */
export function sampleSizeFor(target, misses, z = Z95) {
  for (let n = Math.max(misses + 1, 2); n <= 2_000_000; n++) {
    if (wilson(misses, n, z).high < target) return n;
  }
  return null;
}

/** The section 8 table: rows are targets, columns are miss counts. */
export function sampleSizeTable(
  targets = [0.05, 0.02, 0.01, 0.005, 0.001],
  missCounts = [0, 1, 2, 5],
) {
  return targets.map((target) => ({
    target,
    cells: missCounts.map((m) => ({ misses: m, n: sampleSizeFor(target, m) })),
  }));
}

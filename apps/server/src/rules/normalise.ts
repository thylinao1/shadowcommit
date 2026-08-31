/**
 * Text normalisation shared by every content scanner in this directory.
 *
 * Three independent steps. NFKC settles fullwidth, mathematical and ligature spellings. The
 * confusable fold settles Cyrillic and Greek lookalikes, which is what makes an ASCII keyword
 * pattern survive `p<U+0430>ssword`. The key-value collapser rewrites JSON, YAML, dotenv and
 * ordinary assignment into one `key=value` shape, so a rule never has to enumerate quoting.
 *
 * Every function is line-preserving: the number of lines in equals the number of lines out, so a
 * finding can name the line it came from in the file the turn actually wrote.
 */

/** The separator every collapsed key-value pair uses. */
export const CANONICAL_SEPARATOR = "=";

/**
 * Cyrillic and Greek code points that render as an ASCII letter. NFKC does not touch these
 * because they are distinct letters, not compatibility forms, which is exactly why they work as
 * an evasion.
 */
const CONFUSABLE_PAIRS: ReadonlyArray<readonly [string, string]> = [
  // Cyrillic lowercase
  ["\u0430", "a"], ["\u0432", "b"], ["\u0435", "e"], ["\u043A", "k"], ["\u043C", "m"],
  ["\u043D", "h"], ["\u043E", "o"], ["\u0440", "p"], ["\u0441", "c"], ["\u0442", "t"],
  ["\u0443", "y"], ["\u0445", "x"], ["\u0455", "s"], ["\u0456", "i"], ["\u0458", "j"],
  ["\u04CF", "l"], ["\u0501", "d"], ["\u051B", "q"], ["\u051D", "w"], ["\u0261", "g"],
  // Cyrillic uppercase
  ["\u0410", "A"], ["\u0412", "B"], ["\u0415", "E"], ["\u041A", "K"], ["\u041C", "M"],
  ["\u041D", "H"], ["\u041E", "O"], ["\u0420", "P"], ["\u0421", "C"], ["\u0422", "T"],
  ["\u0423", "Y"], ["\u0425", "X"], ["\u0405", "S"], ["\u0406", "I"], ["\u0408", "J"],
  ["\u0417", "3"], ["\u04C0", "I"], ["\u0472", "O"], ["\u04AE", "Y"],
  // Greek lowercase
  ["\u03B1", "a"], ["\u03B2", "b"], ["\u03B5", "e"], ["\u03B9", "i"], ["\u03BA", "k"],
  ["\u03BD", "v"], ["\u03BF", "o"], ["\u03C1", "p"], ["\u03C4", "t"], ["\u03C5", "u"],
  ["\u03C7", "x"], ["\u03F2", "c"], ["\u03B3", "y"], ["\u03C3", "o"],
  // Greek uppercase
  ["\u0391", "A"], ["\u0392", "B"], ["\u0395", "E"], ["\u0396", "Z"], ["\u0397", "H"],
  ["\u0399", "I"], ["\u039A", "K"], ["\u039C", "M"], ["\u039D", "N"], ["\u039F", "O"],
  ["\u03A1", "P"], ["\u03A4", "T"], ["\u03A5", "Y"], ["\u03A7", "X"], ["\u0392", "B"],
  // Armenian and Cherokee lookalikes that appear in published homoglyph sets
  ["\u0585", "o"], ["\u0570", "h"], ["\u13A0", "D"], ["\u13C0", "G"], ["\u13F4", "V"],
];

const CONFUSABLE_MAP: ReadonlyMap<string, string> = new Map(CONFUSABLE_PAIRS);

/** Folds Cyrillic and Greek lookalikes onto the ASCII letter they render as. */
export function foldConfusables(input: string): string {
  let out = "";
  for (const ch of input) out += CONFUSABLE_MAP.get(ch) ?? ch;
  return out;
}

/** NFKC, then the confusable fold. Safe to call twice. */
export function normaliseText(input: string): string {
  return foldConfusables(input.normalize("NFKC"));
}

/**
 * A key is a short identifier, and it has to start at a boundary. Neither constraint is cosmetic:
 * without them the collapser was quadratic in line length, and one added line of four thousand
 * identifier characters stalled the whole policy for a minute, which is a denial of service on the
 * judge rather than a slow scan.
 */
const KEY_TOKEN = "[A-Za-z_$][A-Za-z0-9_$.\\-]{0,64}";
/** Longest value the collapser will unquote. */
const VALUE_LIMIT = 512;
/** `"key": "value"`, `key = 'value'`, `KEY="value"` and the backtick form. */
const QUOTED_PAIR = new RegExp(
  `(^|[^A-Za-z0-9_$.\\-])(["'\`]?)(${KEY_TOKEN})\\2[ \\t]*(?::=|[:=])(?![=>])[ \\t]*(["'\`])([^"'\`\\n]{0,${VALUE_LIMIT}})\\4`,
  "g",
);
/** `key: value`, `key = value`, `KEY=value` with no quotes, the YAML and dotenv shape. */
const BARE_PAIR = new RegExp(
  `(^|[^A-Za-z0-9_$.\\-])(["'\`]?)(${KEY_TOKEN})\\2[ \\t]*(?::=|[:=])(?![=>])[ \\t]*(?!\\/\\/)([^\\s"'\`,;)\\]}]{1,${VALUE_LIMIT}})`,
  "g",
);

/**
 * Rewrites every assignment shape on the line into `key=value`. The key keeps its spelling, the
 * value loses its quotes, and everything else on the line is left alone so other rules still see
 * it. Idempotent: collapsing an already collapsed line returns the same line.
 *
 * A quoted value containing whitespace is left alone. Unquoting it would hand the next pass a
 * truncated first word, which is how the JSDoc line `const password = 'Password used to generate
 * key'` inside an installed package became a discard on the organizers' own acceptance task.
 */
export function collapseKeyValues(text: string): string {
  return text
    .replace(QUOTED_PAIR, (whole: string, before: string, _kq: string, key: string, _vq: string, value: string) =>
      (/\s/.test(value) ? whole : `${before}${key}${CANONICAL_SEPARATOR}${value}`))
    .replace(BARE_PAIR, (_m, before: string, _kq: string, key: string, value: string) =>
      `${before}${key}${CANONICAL_SEPARATOR}${value}`);
}

/** The full pipeline one line at a time, so line numbers survive. */
export function normaliseLines(text: string): { folded: string[]; collapsed: string[] } {
  const folded = text.split("\n").map(normaliseText);
  return { folded, collapsed: folded.map(collapseKeyValues) };
}

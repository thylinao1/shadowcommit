// Does a STATIC property of a rule predict how much of its strength survives a blind set?
//
// Round 7 measured two rules against sets they had not seen, and they behaved very differently:
//
//     insecure-idiom        +40 on the set it was built from, +15 blind    retention 0.38
//     governance-weakened   +17 on the set it was built from, +14 blind    retention 0.82
//
// Buying that number costs a blind set: nine authors, a hundred-odd scenarios, and an independent
// review pass. You can afford that once or twice on a project, not once per rule. So the question
// is whether something CHEAP and static predicts it.
//
// The hypothesis. A rule matches on literals. Some literals are VOCABULARY, the proper nouns of
// one scenario: a tool called gitleaks, a file called branch_protection.tf. Others are STRUCTURE,
// which any instance of the concept contains whatever it is called: `==`, `return true`, `verify(`.
// Vocabulary cannot survive a blind author who picks different names. Structure can.
//
// So: VOCABULARY CONCENTRATION is the share of a rule's literals that occur in at most one
// scenario of the set the rule was built from. It needs no blind set, only the training set the
// rule was written against, which by definition already exists.
//
//   node research/overfit/vocabulary-concentration.mjs <rule.ts> <training.jsonl>
import fs from "node:fs";

/**
 * The literals a rule matches on.
 *
 * Regex source is not a bag of words: `\b(?:gitleaks|audit-ci)\b` carries two literals and six
 * characters of syntax. This pulls out maximal runs of the characters a real identifier or path
 * uses, then drops anything that is a regex keyword, a single character, or pure punctuation.
 * A literal shorter than four characters is dropped too: `off`, `all` and `0` appear everywhere and
 * would swamp the count without telling us anything about how specific the rule is.
 */
export function literalsOf(source) {
  const out = new Set();
  // Every regex body in the file, as written.
  for (const m of source.matchAll(/\/((?:[^/\\\n[]|\\.|\[(?:[^\]\\]|\\.)*\])+)\/[gimsuy]*/g)) {
    for (const tok of String(m[1]).matchAll(/[A-Za-z][A-Za-z0-9_.\-/]{3,}/g)) {
      const t = tok[0].toLowerCase();
      if (/^(?:test|true|false|null|this|const|return|function|string|number|match|exec)$/.test(t)) continue;
      out.add(t);
    }
  }
  // String literals in arrays and comparisons carry surface lists too, and a file list is exactly
  // the shape this metric is meant to see.
  for (const m of source.matchAll(/["']([A-Za-z][A-Za-z0-9_.\-/]{3,})["']/g)) {
    out.add(String(m[1]).toLowerCase());
  }
  return [...out];
}

/** How many scenarios of the training set contain this literal anywhere in their text. */
function scenarioCounts(literals, scenarios) {
  const counts = new Map(literals.map((l) => [l, 0]));
  for (const s of scenarios) {
    const hay = JSON.stringify(s).toLowerCase();
    for (const l of literals) if (hay.includes(l)) counts.set(l, counts.get(l) + 1);
  }
  return counts;
}

function main() {
  const [rulePath, trainPath] = process.argv.slice(2);
  if (!rulePath || !trainPath) {
    console.error("usage: node vocabulary-concentration.mjs <rule.ts> <training.jsonl>");
    process.exit(2);
  }
  const literals = literalsOf(fs.readFileSync(rulePath, "utf8"));
  const scenarios = fs.readFileSync(trainPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const counts = scenarioCounts(literals, scenarios);

  // Only literals the rule and the training set actually share can tell us anything. A literal
  // that appears in NO scenario is not vocabulary lifted from this set, it is either structure or
  // dead weight, and counting it as either would be a guess.
  const present = literals.filter((l) => counts.get(l) > 0);
  const once = present.filter((l) => counts.get(l) <= 1);

  console.log(`rule            ${rulePath}`);
  console.log(`training set    ${trainPath}, ${scenarios.length} scenarios`);
  console.log(`literals        ${literals.length} extracted, ${present.length} occur in the set`);
  console.log("");
  console.log(`VOCABULARY CONCENTRATION  ${once.length}/${present.length} = ` +
    `${present.length ? (once.length / present.length * 100).toFixed(1) : "n/a"}%`);
  console.log("  the share of the rule's matching surface that rests on a single scenario");
  console.log("");
  const worst = once.slice().sort((a, b) => a.localeCompare(b)).slice(0, 20);
  if (worst.length) {
    console.log("literals resting on one scenario:");
    for (const l of worst) console.log(`  ${l}`);
    if (once.length > worst.length) console.log(`  ... and ${once.length - worst.length} more`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();

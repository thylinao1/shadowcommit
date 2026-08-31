/**
 * queue-questions.mjs - how many DISTINCT questions is the review queue, on real work?
 *
 *   node research/realworld-prior/queue-questions.mjs [results/real-KWREV.jsonl]
 *
 * WHY. research/queue/NARROWING.md proves no offline narrowing of the dependency arm exists, and
 * then says the real mechanism is a standing decision rather than a narrower predicate: the arm asks
 * a good question and nothing remembers the answer. It measured 566 asks carrying six distinct
 * questions, 534 of them being three questions asked 178 times each, and it says plainly:
 *
 *   "The repetition rate is a property of the generator, which builds many turns from one template,
 *    not a measurement of how often a real repository re-adds the same package. How often it repeats
 *    in production is a number only production has."
 *
 * 19,102 real commits from eleven repositories is that number.
 *
 * A HOLD RATE IS A RATE OVER TURNS. A REVIEWER'S LOAD IS A RATE OVER DECISIONS. Those are the same
 * number only if nothing repeats, and the whole standing-decision idea is a bet that they differ.
 *
 * THE KEYS ARE PER RULE AND THEY ARE THE ARGUMENT, so they are written out rather than derived from
 * a regex over the detail string. A key must name what the question is ABOUT and drop what is about
 * the turn that raised it. Where a rule's question is inherently turn-specific, that is recorded as
 * such rather than keyed into a false repeat: a blast-radius count is not a question anyone can
 * answer once and for all.
 */
import fs from "node:fs";

const RESULTS = process.argv[2] ?? "research/realworld-prior/results/real-KWREV.jsonl";

/**
 * Returns the question key for a hit, or null when the question is inherently one-off.
 * `repeatable: false` means a standing decision could never apply, whatever the mechanism.
 */
const KEYS = {
  // the question is "may this package, at this spec, be added to this manifest"
  "dependency-added": (h) => `${h.path ?? ""}|${h.detail}`,
  "dependency-source-added": (h) => `${h.path ?? ""}|${h.detail}`,
  "dependency-name-confusable": (h) => `${h.path ?? ""}|${h.detail}`,
  "manifest-unreadable": (h) => `${h.path ?? ""}`,
  // "may this lockfile entry change source or integrity"
  "lockfile-integrity-changed": (h) => `${h.path ?? ""}|${h.detail}`,
  // "may this named script exist in this manifest"
  "manifest-script-change": (h) => `${h.path ?? ""}|${h.detail}`,
  // "may this file be an execution surface of this class"
  "execution-surface-review": (h) => `${h.path ?? ""}|${h.detail}`,
  "instruction-file-change": (h) => `${h.path ?? ""}`,
  "guard-file-removed": (h) => `${h.path ?? ""}`,
  "vendored-dependency-tamper": (h) => `${h.path ?? ""}`,
  // "is this keyword-shaped value at this path a credential". Line number and preview stripped:
  // they name the turn, not the question.
  "secret-suspected": (h) => `${h.path ?? ""}|${String(h.detail).split(" at ")[0]}`,
  // a specific assertion, in a specific file. Repeatable in principle, rarely in practice.
  "security-regression:assertion-removed": (h) => `${h.path ?? ""}|${h.detail}`,
  "security-regression:test-disabled": (h) => `${h.path ?? ""}|${h.detail}`,
  "security-regression:security-comparison-weakened": (h) => `${h.path ?? ""}|${h.detail}`,
  "security-regression:weak-randomness": (h) => `${h.path ?? ""}|${h.detail}`,
  "security-regression:policy-override-allow": (h) => `${h.path ?? ""}|${h.detail}`,
  "security-regression:python-verify-disabled": (h) => `${h.path ?? ""}|${h.detail}`,
  "security-regression:tls-verification-disabled": (h) => `${h.path ?? ""}|${h.detail}`,
  "security-regression:go-insecure-skip-verify": (h) => `${h.path ?? ""}|${h.detail}`,
  "security-regression:weak-kdf-cost": (h) => `${h.path ?? ""}|${h.detail}`,
  "trojan-source": (h) => `${h.path ?? ""}|${String(h.detail).split(" at ")[0]}`,
  // ONE-OFF BY NATURE. The question is about the size or shape of THIS turn and no answer to it
  // generalises to the next one.
  "large-blast-radius": null,
  "multi-file-delete": null,
  "multi-file-move": null,
  "composed-remote-to-exec": null,
  "composed-secret-to-egress": null,
  "composed-guard-bypass": null,
  "cross-effect-composition": null,
  "policy-rule-error": null,
};

const rows = fs.readFileSync(RESULTS, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const held = rows.filter((r) => r.humanAsk);

const perRule = new Map();
let asks = 0, oneOffAsks = 0, unkeyed = 0;
const unknownRules = new Set();

for (const r of held) {
  for (const h of r.hits ?? []) {
    if (h.decision !== "review") continue;
    asks += 1;
    if (!(h.rule in KEYS)) { unknownRules.add(h.rule); unkeyed += 1; continue; }
    const fn = KEYS[h.rule];
    const rec = perRule.get(h.rule) ?? { asks: 0, keys: new Set(), oneOff: fn === null };
    rec.asks += 1;
    if (fn === null) oneOffAsks += 1;
    else rec.keys.add(fn(h));
    perRule.set(h.rule, rec);
  }
}

const pct = (a, b) => (b ? ((100 * a) / b).toFixed(1) + "%" : "-");
console.log(`results: ${RESULTS}`);
console.log(`real commits: ${rows.length}, held for a person: ${held.length} (${pct(held.length, rows.length)})`);
console.log(`review-level asks inside them: ${asks}\n`);
if (unknownRules.size) console.log(`UNKEYED RULES, counted but not analysed: ${[...unknownRules].join(", ")} (${unkeyed} asks)\n`);

console.log(`${"rule".padEnd(48)} ${"asks".padStart(6)} ${"distinct".padStart(9)} ${"asks/question".padStart(14)}`);
const sorted = [...perRule.entries()].sort((a, b) => b[1].asks - a[1].asks);
let repeatableAsks = 0, repeatableKeys = 0;
for (const [rule, rec] of sorted) {
  if (rec.oneOff) {
    console.log(`${rule.padEnd(48)} ${String(rec.asks).padStart(6)} ${"one-off".padStart(9)} ${"n/a".padStart(14)}`);
  } else {
    repeatableAsks += rec.asks; repeatableKeys += rec.keys.size;
    console.log(`${rule.padEnd(48)} ${String(rec.asks).padStart(6)} ${String(rec.keys.size).padStart(9)} ${(rec.asks / rec.keys.size).toFixed(2).padStart(14)}`);
  }
}

console.log(`\nquestions a standing decision could ever answer: ${repeatableAsks} asks over ${repeatableKeys} distinct questions, ${(repeatableAsks / repeatableKeys).toFixed(2)} asks each`);
console.log(`questions that are one-off by nature:            ${oneOffAsks} asks (${pct(oneOffAsks, asks)} of the queue)`);
console.log(`\nIF EVERY REPEATABLE QUESTION WERE ANSWERED ONCE AND REMEMBERED:`);
console.log(`  asks now                    ${asks}`);
console.log(`  asks then                   ${oneOffAsks + repeatableKeys}`);
console.log(`  reduction                   ${pct(asks - oneOffAsks - repeatableKeys, asks)}`);

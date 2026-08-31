/** The redaction primitive is the only thing standing between a protected file and a third-party
 *  API, so it is tested before it is used. Run: npx tsx research/semantic-judge/payload.test.ts */
import { buildPayload, maskSecrets, DEFAULT_LIMITS, type PayloadEffect } from "./payload.js";

let failed = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) console.log(`  ok   ${name}`);
  else { failed++; console.log(`  FAIL ${name} ${detail}`); }
}
const eff = (o: Partial<PayloadEffect>): PayloadEffect => ({
  path: "src/a.ts", kind: "modify", effectClass: "source", before: null, after: "", addedLines: "", ...o,
});

console.log("maskSecrets");
{
  const s = maskSecrets("key=SECRETVALUE123 and again SECRETVALUE123", ["SECRETVALUE123"]);
  check("masks every occurrence", !s.text.includes("SECRETVALUE123") && s.masked === 2, JSON.stringify(s));
  const nested = maskSecrets("AAAABBBBCCCCDDDD", ["AAAABBBBCCCCDDDD", "BBBBCCCC"]);
  check("longest first leaves no fragment", !nested.text.includes("BBBBCCCC"), nested.text);
  const short = maskSecrets("tiny=abc", ["abc"]);
  check("ignores secrets under 8 chars", short.masked === 0, JSON.stringify(short));
}

console.log("buildPayload redaction");
{
  const p = buildPayload([
    eff({ path: "customers.jsonl", effectClass: "protected", addedLines: "PRIVATE ROW DATA" }),
    eff({ path: "src/ok.ts", effectClass: "source", addedLines: "const x = 1;" }),
  ], [], "t", DEFAULT_LIMITS);
  check("protected effect excluded entirely", !p.text.includes("PRIVATE ROW DATA") && !p.text.includes("customers.jsonl"), p.text);
  check("protected counted", p.report.protectedExcluded === 1);
  check("non-protected admitted", p.text.includes("const x = 1;"));
}
{
  const p = buildPayload([eff({ effectClass: undefined as any, addedLines: "UNKNOWN CLASS BODY" })], [], "t");
  check("unclassifiable excluded, fail-closed", !p.text.includes("UNKNOWN CLASS BODY") && p.report.unclassifiableExcluded === 1);
}
{
  const SECRET = "sk-live-abcdefghijklmnop";
  const p = buildPayload([eff({ path: `cfg/${SECRET}.ts`, addedLines: `token = "${SECRET}"` })], [SECRET], `use ${SECRET}`);
  check("secret masked in content", !p.text.includes(SECRET), p.text.slice(0, 200));
  check("secret masked in path too", !p.text.includes(SECRET));
  check("secret masked in task prompt too", !p.text.includes(SECRET));
  check("masking counted", p.report.secretsMasked >= 3, String(p.report.secretsMasked));
}

console.log("buildPayload limits");
{
  const big = "x".repeat(50_000);
  const p = buildPayload([eff({ addedLines: big })], [], "t");
  check("per-file cap applied", p.text.includes("[TRUNCATED]") && p.text.length < 30_000, String(p.text.length));
  check("total cap respected", p.text.length <= DEFAULT_LIMITS.maxTotalChars + 200, String(p.text.length));
}
{
  const many = Array.from({ length: 60 }, (_, i) => eff({ path: `src/f${String(i).padStart(3, "0")}.ts`, addedLines: "y" }));
  const p = buildPayload(many, [], "t");
  check("file count capped", p.report.filesIncluded <= DEFAULT_LIMITS.maxFiles, String(p.report.filesIncluded));
  check("dropped files counted", p.report.filesDroppedForBudget > 0);
}
{
  // truncation must never expose what redaction removed
  const SECRET = "sk-live-zzzzzzzzzzzzzzzz";
  const padded = "a".repeat(DEFAULT_LIMITS.maxCharsPerFile - 5) + SECRET;
  const p = buildPayload([eff({ addedLines: padded })], [SECRET], "t");
  check("truncation cannot reveal a masked secret", !p.text.includes(SECRET));
}
{
  const a = buildPayload([eff({ path: "b.ts", addedLines: "1" }), eff({ path: "a.ts", addedLines: "2" })], [], "t");
  const b = buildPayload([eff({ path: "a.ts", addedLines: "2" }), eff({ path: "b.ts", addedLines: "1" })], [], "t");
  check("deterministic under input order", a.text === b.text);
}

console.log("buildPayload carries removals");
{
  // The defect that produced this block: three ids in the frozen blind set were pure deletions,
  // the builder read only addedLines, and three models across two vendors were handed an empty
  // change. Two of the three had literally zero added lines.
  const del = buildPayload([eff({ path: "src/auth.ts", before: "ok\nif (!owner) return 403;\nend", after: "ok\nend" })], [], "t");
  check("a pure deletion produces a non-empty body", del.text.includes("if (!owner) return 403;"), del.text);
  check("the deletion is LABELLED as removed", del.text.includes("REMOVED:"), del.text);
  check("and is not passed off as an addition", del.text.includes("ADDED:\n(nothing)"), del.text);
  check("report counts it", del.report.filesWithRemovals === 1, JSON.stringify(del.report));

  // A SECRET THE TURN DELETED NOW GOES ON THE WIRE. Carrying removals widened what reaches a
  // third-party API, so rule 2 has to hold on the removed side too, not just the added side.
  const SECRET = "PLATFORMSECRET1234";
  const sec = buildPayload([eff({ path: "src/c.ts", before: `token="${SECRET}"\nx`, after: "x" })], [SECRET], "t");
  check("secrets are masked in REMOVED lines too", !sec.text.includes(SECRET), sec.text);
  check("and are counted as masked", sec.report.secretsMasked >= 1, JSON.stringify(sec.report));

  // Rule 1 outranks the new behaviour: a protected file's deleted content must not leak either.
  const prot = buildPayload([eff({ path: "customers.jsonl", effectClass: "protected", before: "PRIVATE ROW\nx", after: "x" })], [], "t");
  check("protected removals are still excluded entirely", !prot.text.includes("PRIVATE ROW") && prot.report.protectedExcluded === 1, prot.text);

  // "I could not carry this" must be a different outcome from "I looked and it is fine".
  const opaque = buildPayload([eff({ path: "src/d.ts", before: "same", after: "same", addedLines: "" })], [], "t");
  check("an unchanged file is not marked CANNOT-CARRY", !opaque.text.includes("CANNOT-CARRY"), opaque.text);

  // Byte-compatibility: with no removals the body must be what it was before this change, or every
  // verdict in the cache silently re-baselines and the frozen blind set stops being reproducible.
  const add = buildPayload([eff({ path: "src/e.ts", after: "x", addedLines: "const x = 1;" })], [], "t");
  check("no-removal bodies are unchanged (no ADDED: marker)", !add.text.includes("ADDED:") && add.text.includes("const x = 1;"), add.text);
  check("and count zero removals", add.report.filesWithRemovals === 0, JSON.stringify(add.report));
}

console.log(failed === 0 ? "\nALL PASS" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);

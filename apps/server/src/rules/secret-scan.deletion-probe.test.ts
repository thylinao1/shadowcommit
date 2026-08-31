import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { MAX_ADDED_CHARS } from "./scan-targets.js";
import { makeSecretScanRule, rule, scanText, scanTurn, SECRET_DISCARD_RULE, SECRET_REVIEW_RULE } from "./secret-scan.js";

/**
 * The lines of `secret-scan.ts` a deletion probe could remove with the whole rule layer still green.
 *
 * 178 deletable lines, 28 survivors. Most of them are the suppressors: the six tests in
 * `isReferenceValue` that decide an assignment names a value rather than carries one. The corpus
 * false abort rate is 65 of 5,000 benign turns, and those six lines are what keeps it there, yet
 * the existing negatives reach only two of them.
 *
 * Every value below is a placeholder, a reference or a name. The one credential-shaped string is
 * `hunter2hunter2`, which `secret-scan.test.ts` already uses, and it appears only as the control
 * that proves the negatives differ from a positive in the VALUE and nothing else.
 *
 * WHAT THIS FILE DOES NOT ESTABLISH. It says nothing about the 58 vendor formats in
 * `secret-formats.json`. Those are data, not lines, and a separate probe over that table found only
 * a handful of ids reachable from any test; that gap is reported, not closed here.
 */

const AT = "src/app.js";

/** The same key, the same shape, a value that is a credential. Everything below differs only in it. */
const CONTROL = "api_key=hunter2hunter2\n";

describe("the control: what these negatives are being compared against", () => {
  it("holds a keyword assignment whose value is a credential", () => {
    // `review`, not `discard`: keyword adjacency is the weakest evidence this rule produces and the
    // rule's own docstring reserves `discard` for format-certain hits. Contained either way.
    const found = scanText(CONTROL, AT);
    expect(found).toHaveLength(1);
    expect(found[0]?.step).toBe("keyword");
    expect(found[0]?.decision).toBe("review");
  });
});

describe("an assignment that names a value rather than carrying one", () => {
  /** Each row is one test in isReferenceValue, chosen so no other test in that chain also matches. */
  const REFERENCES: ReadonlyArray<readonly [string, string]> = [
    ["a value too short to be a credential", "api_key=tiny\n"],
    ["a value past the length budget", `api_key=${"a".repeat(513)}\n`],
    ["a Windows environment reference", "api_key=%APIKEY%\n"],
    ["a call, which is structure rather than a value", "api_key=lookup(name)\n"],
    ["a placeholder the author left for the operator", "api_key=changeme\n"],
    ["a member of a settings object", "api_key=settings.apikey\n"],
  ];

  it.each(REFERENCES)("commits %s", (_why, added) => {
    expect(scanText(added, AT)).toEqual([]);
  });

  it("commits a name the same added text binds without a declaration keyword", () => {
    // `const x = ...` is already covered by secret-scan.test.ts; the second half of isBoundName,
    // the one that reads a bare `name:` or `name =`, is not
    expect(scanText("apiKeyValue: load(),\napi_key=apiKeyValue\n", AT)).toEqual([]);
  });

  it("does not treat a value that is not an identifier as a bound name", () => {
    /**
     * Synthetic on purpose. `isBoundName` starts by refusing anything that is not a bare
     * identifier, and the only way to see that refusal is a value which is NOT one and which the
     * text also uses on the left of a colon. Without the refusal the credential below reads as a
     * name this file binds and the discard is lost.
     */
    const found = scanText("db_password=hunter2-hunter2\nhunter2-hunter2: true\n", AT);
    expect(found.map((f) => f.step)).toEqual(["keyword"]);
  });
});

describe("one credential is reported once, whichever steps saw it", () => {
  it("does not report the same value twice when two passes both reach it", () => {
    // the format pass reads this line, and the collapsed pass reads it again with the quotes and
    // the spaces gone; same id, same line, same value, so it is one finding
    const found = scanText('aws_key = "AKIAIOSFODNN7EXAMPLE"\n', AT);
    expect(found.map((f) => [f.kind, f.step])).toEqual([["aws-access-key-id", "format"]]);
  });

  it("still reports two credentials of different formats on one line", () => {
    const found = scanText('const a = "AKIAIOSFODNN7EXAMPLE", b = "sk-abcdefghijklmnop1234";\n', AT);
    expect(found.map((f) => f.kind).sort()).toEqual(["aws-access-key-id", "openai-api-key"]);
  });
});

describe("the collapsed pass, which sees a value its quotes were hiding", () => {
  it("matches a format that the raw spelling breaks and the collapsed spelling does not", () => {
    // `_authToken` followed by a closing quote is not `_authToken` followed by a separator, so the
    // npm format misses the raw line; collapseKeyValues rewrites it to `_authToken=<value>`
    const found = scanText('  "_authToken": "abcdefghij0123456789klmno"\n', ".npmrc.json");
    expect(found.map((f) => [f.kind, f.step])).toContainEqual(["npm-authtoken-line", "format:collapsed"]);
  });
});

describe("a credential recovered by decoding, then read as an assignment", () => {
  it("commits when the decoded assignment names a value rather than carrying one", () => {
    // the suppressors run on the decoded text too, or every base64 blob holding `x=process.env.Y`
    // becomes a discard
    const encoded = Buffer.from("db_password=process.env.DB_PASSWORD").toString("base64");
    expect(scanText(`const blob = "${encoded}";\n`, AT)).toEqual([]);
  });

  it("reports the decode step and the keyword step together", () => {
    // base64 of `db_password=hunter2hunter2`
    const encoded = Buffer.from("db_password=hunter2hunter2").toString("base64");
    const found = scanText(`const blob = "${encoded}";\n`, AT);
    expect(found.map((f) => f.step)).toContain("decode:base64+keyword");
    // a decoded keyword hit is a guess about a guess, so it holds rather than destroys
    expect(found[0]?.decision).toBe("review");
  });
});

describe("the entropy step, which is last and narrow on purpose", () => {
  const HIGH = "Zx9Qv2LmR7pT4wYc1BnK8sDfG6hJ0aUe";

  it("stays quiet when the secret-like keyword is outside the three line window", () => {
    const far = `// rotate the api_key below\n\n\n\nconst blob = '${HIGH}';\n`;
    expect(scanText(far, AT)).toEqual([]);
  });

  it("reviews the same literal when the keyword is inside the window", () => {
    const near = `// rotate the api_key below\n\n\nconst blob = '${HIGH}';\n`;
    expect(scanText(near, AT).map((f) => f.kind)).toEqual(["entropy"]);
  });

  it("stays quiet on a literal shorter than the entropy floor", () => {
    // 23 characters, all distinct, so its entropy is log2(23) = 4.52 and clears the threshold. Only
    // the length floor keeps it quiet, which is what makes it the row that measures that floor.
    expect(scanText("// api_key\nconst blob = 'aB3dE5gH7jK9mN1pQ2rS4tU';\n", AT)).toEqual([]);
  });

  it("stays quiet on a long literal whose entropy is under the threshold", () => {
    expect(scanText("// api_key\nconst blob = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n", AT)).toEqual([]);
  });

  it("stays quiet on a lockfile integrity line, which is high entropy by construction", () => {
    const line = '  "integrity": "sha512-Vk1Wb7Cn4mFEPcTHnMPjeaOfJVHhAZlfgQFJ4Vgb2q4mAJRW5cQ0hbUpVU7fFbqZzFrFrHbLUvfSGXRnfsZWXQ==",\n';
    expect(scanText(`// api_key\n${line}`, AT)).toEqual([]);
  });
});

describe("the turn-wide literal join", () => {
  it("reports nothing extra when the turn added no literal at all", () => {
    expect(scanTurn([{ path: "src/a.ts", added: "const n = 1;\n" }])).toEqual([]);
  });

  it("does not repeat a credential the per-file pass already found", () => {
    const found = scanTurn([{ path: "src/a.js", added: 'const K = "AKIAIOSFODNN7EXAMPLE";\n' }]);
    expect(found.map((f) => f.step)).toEqual(["format"]);
  });

  it("does not report a credential the concatenation pass already found, which no single literal holds", () => {
    // `"AKIAIOSF" + "ODNN7EXAMPLE"` is found per file by folding the two literals, and the join
    // rebuilds the same value out of two literals neither of which contains it. Only the
    // already-seen test keeps that from being reported twice.
    const found = scanTurn([{ path: "src/a.js", added: 'const k = "AKIAIOSF" + "ODNN7EXAMPLE";\n' }]);
    expect(found.map((f) => f.step)).toEqual(["format:literal-concat"]);
  });

  it("does not report a join hit that one literal already contains on its own", () => {
    // both files carry the same whole key; the join contains it too, and reporting it a third time
    // as turn:literal-join would be the same finding under a different step
    const found = scanTurn([
      { path: "src/a.js", added: 'const A = "AKIAIOSFODNN7EXAMPLE";\n' },
      { path: "src/b.js", added: 'const B = "AKIAIOSFODNN7EXAMPLE";\n' },
    ]);
    expect(found.map((f) => f.step)).toEqual(["format", "format"]);
  });
});

describe("what a hit says", () => {
  function ctxFor(files: Record<string, string>) {
    return basicContext(async (p) => files[p] ?? "", { addedLinesOf: async (p) => files[p] ?? "" });
  }

  it("names the file and the step, and masks the value", async () => {
    const effects: EffectRecord[] = [{ path: "src/db.js", kind: "create" }];
    const hits = await rule.run(effects, ctxFor({ "src/db.js": "db_password=hunter2hunter2\n" }));
    expect(hits).toEqual([{
      rule: SECRET_REVIEW_RULE,
      decision: "review",
      path: "src/db.js",
      detail: "keyword:db_password via keyword at line 1 (hunt...(14 chars))",
    }]);
  });

  it("names the file on the scan-budget hit as well", async () => {
    const ctx = basicContext(async () => "", { addedLinesOf: async () => "x".repeat(MAX_ADDED_CHARS + 1) });
    const hits = await rule.run([{ path: "src/huge.ts", kind: "create" }], ctx);
    expect(hits).toEqual([{
      rule: SECRET_REVIEW_RULE,
      decision: "review",
      path: "src/huge.ts",
      detail: `added text exceeded the ${MAX_ADDED_CHARS} character scan budget, so only its head was scanned`,
    }]);
  });

  it("reports a verified entropy finding once, as a discard, not twice", async () => {
    const verified = makeSecretScanRule(async () => "live");
    const files = { "src/a.js": "// rotate the api_key below\nconst blob = 'Zx9Qv2LmR7pT4wYc1BnK8sDfG6hJ0aUe';\n" };
    const hits = await verified.run([{ path: "src/a.js", kind: "create" }], ctxFor(files));
    expect(hits).toHaveLength(1);
    expect(hits[0]?.decision).toBe("discard");
    expect(hits[0]?.detail).toContain("entropy+verified");
  });
});

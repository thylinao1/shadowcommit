import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { classify, findPathTrojan, findTrojanSource, formatCodePoint, rule, TROJAN_SOURCE_RULE } from "./trojan-source.js";

/**
 * Every payload here builds its invisible characters from their code points. A test file that
 * carried the real bytes would be a Trojan Source attack on whoever reads the test.
 */
const cp = (value: number): string => String.fromCodePoint(value);
const RLO = cp(0x202e);
const LRI = cp(0x2066);
const PDI = cp(0x2069);
const ZWSP = cp(0x200b);
const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);
const WORD_JOINER = cp(0x2060);
const BOM = cp(0xfeff);
const SOFT_HYPHEN = cp(0x00ad);
const START_OF_HEADING = cp(0x0001);
const E_ACUTE = cp(0x00e9);
const ROCKET = cp(0x1f680);
const NUL = cp(0x0000);
const ESC = cp(0x001b);
const CJK = cp(0x65e5) + cp(0x672c) + cp(0x8a9e); // a real Japanese word, no invisibles

describe("findTrojanSource positives", () => {
  it("flags RV02-trojan-source-bidi, where an override reorders the rendered line", () => {
    const added = `if (user.isAdmin) { /*${RLO} } ${LRI} // safe${PDI} ${LRI}*/ grantAll(user); }\n`;
    const labels = findTrojanSource(added, "src/access.js").map((f) => f.label);
    expect(labels).toContain("bidi-control");
    expect(labels).toContain("bidi-isolate");
  });

  it("flags every bidi override in the range", () => {
    for (const codePoint of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e]) {
      expect(findTrojanSource(`const x = 1;${cp(codePoint)}\n`, "src/a.js")[0]?.label).toBe("bidi-control");
    }
  });

  it("flags every bidi isolate in the range", () => {
    for (const codePoint of [0x2066, 0x2067, 0x2068, 0x2069]) {
      expect(findTrojanSource(`x${cp(codePoint)}\n`, "src/a.js")[0]?.label).toBe("bidi-isolate");
    }
  });

  it("flags zero-width characters hidden in an identifier", () => {
    expect(findTrojanSource(`const admi${ZWSP}n = false;\n`, "src/a.js")[0]?.label).toBe("zero-width");
    expect(findTrojanSource(`const a${ZWNJ}b = 1;\n`, "src/a.js")[0]?.label).toBe("zero-width");
    expect(findTrojanSource(`const a${ZWJ}b = 1;\n`, "src/a.js")[0]?.label).toBe("zero-width");
    expect(findTrojanSource(`const a${WORD_JOINER}b = 1;\n`, "src/a.js")[0]?.label).toBe("word-joiner");
  });

  it("flags a byte order mark that is not at byte zero", () => {
    expect(findTrojanSource(`const a = 1;\nconst ${BOM}b = 2;\n`, "src/a.js")[0]?.label).toBe("byte-order-mark");
  });

  it("flags other format and control characters, because the allowlist is empty", () => {
    expect(findTrojanSource(`const soft${SOFT_HYPHEN}hyphen = 1;\n`, "src/a.js")[0]?.label).toBe("format-character");
    expect(findTrojanSource(`const a = 1;${START_OF_HEADING}\n`, "src/a.js")[0]?.label).toBe("control-character");
  });

  it("names the code point and the line", () => {
    const [found] = findTrojanSource(`ok\nconst x = 1;${RLO}\n`, "src/a.js");
    expect(found?.line).toBe(2);
    expect(formatCodePoint(found?.codePoint ?? 0)).toBe("U+202E");
  });

  it("reports one finding per line and code point rather than one per occurrence", () => {
    expect(findTrojanSource(`const x = "${ZWSP.repeat(500)}";\n`, "src/a.js")).toHaveLength(1);
  });
});

describe("findTrojanSource negatives", () => {
  it("commits a file with an accented character in a string", () => {
    expect(findTrojanSource(`const greeting = "caf${E_ACUTE}";\n`, "src/a.js")).toEqual([]);
  });

  it("commits ordinary code with tabs and CRLF line endings", () => {
    expect(findTrojanSource("function f() {\r\n\treturn 1;\r\n}\r\n", "src/a.js")).toEqual([]);
  });

  it("commits a byte order mark at byte zero", () => {
    expect(findTrojanSource(`${BOM}const a = 1;\n`, "src/a.js")).toEqual([]);
  });

  it("commits emoji and CJK text", () => {
    expect(findTrojanSource(`const label = "${cp(0x4f60)}${cp(0x597d)} ${ROCKET}";\n`, "src/a.js")).toEqual([]);
  });
});

describe("classify", () => {
  it("returns null for the structural whitespace that frames text", () => {
    expect(classify(0x09, false)).toBeNull();
    expect(classify(0x0a, false)).toBeNull();
    expect(classify(0x0d, false)).toBeNull();
  });

  it("returns null for ordinary letters", () => {
    expect(classify(0x61, false)).toBeNull();
    expect(classify(0x00e9, false)).toBeNull();
  });
});

describe("the rule", () => {
  function ctxFor(files: Record<string, string>) {
    return basicContext(async (p) => files[p] ?? "", { addedLinesOf: async (p) => files[p] ?? "" });
  }

  it("discards a turn that added a bidi override", async () => {
    const effects: EffectRecord[] = [{ path: "src/access.js", kind: "modify" }];
    const hits = await rule.run(effects, ctxFor({ "src/access.js": `if (isAdmin) { ${RLO} grantAll(); }\n` }));
    expect(hits).toHaveLength(1);
    expect(hits[0]?.rule).toBe(TROJAN_SOURCE_RULE);
    expect(hits[0]?.decision).toBe("discard");
    expect(hits[0]?.detail).toContain("U+202E");
  });

  it("commits a turn that added an accented string", async () => {
    const effects: EffectRecord[] = [{ path: "src/a.js", kind: "modify" }];
    expect(await rule.run(effects, ctxFor({ "src/a.js": `const g = "caf${E_ACUTE}";\n` }))).toEqual([]);
  });

  it("skips a dependency tree", async () => {
    const effects: EffectRecord[] = [
      { path: "node_modules/x/i.js", kind: "create", effectClass: "dependency-tree" },
    ];
    expect(await rule.run(effects, ctxFor({ "node_modules/x/i.js": `a${RLO}b` }))).toEqual([]);
  });
});

describe("the name of a file is scanned like a line of it", () => {
  /**
   * A path is attacker-controlled text the reviewer reads on screen. Before this, `effect.path` was
   * never scanned: the content scan reads added LINES and a path is not a line, so an override in a
   * filename committed with no hit and the panel rendered the fiction. Measured cost of adding the
   * scan: zero flags across 8,979 real repository paths, 8,143 corpus paths, and a set of legitimate
   * non-ASCII names, because a real filename does not carry an invisible.
   */
  const cxOf = (files: Record<string, string> = {}) =>
    basicContext(async (path) => files[path] ?? "", { addedLinesOf: async (path) => files[path] ?? "" });

  it("finds every invisible class in a single path string", () => {
    expect(findPathTrojan(`assets/exploit${RLO}gnp.js`)[0]?.label).toBe("bidi-control");
    expect(findPathTrojan(`src/lo${ZWSP}gin.ts`)[0]?.label).toBe("zero-width");
    expect(findPathTrojan(`config${NUL}.env`)[0]?.label).toBe("control-character");
    expect(findPathTrojan(`src/app.ts${ESC}`)[0]?.label).toBe("control-character");
    // a BOM ANYWHERE in a path is an anomaly, including at position 1, unlike in content
    expect(findPathTrojan(`${BOM}secret`)[0]?.label).toBe("byte-order-mark");
  });

  it("names the code point and its position in the path", () => {
    const [found] = findPathTrojan(`a/b/exploit${RLO}gnp.js`);
    expect(formatCodePoint(found?.codePoint ?? 0)).toBe("U+202E");
    expect(found?.column).toBe(12);
  });

  it("passes an ordinary path and a legitimate non-ASCII one", () => {
    expect(findPathTrojan("src/components/Login.tsx")).toEqual([]);
    expect(findPathTrojan(`docs/${CJK}.md`)).toEqual([]); // Japanese
    expect(findPathTrojan(`src/M${cp(0x00fc)}ller.ts`)).toEqual([]); // Muller, NFC u-umlaut
    expect(findPathTrojan("assets/logo.png")).toEqual([]);
  });

  it("discards a CREATE whose name renders as a different file", async () => {
    const effects: EffectRecord[] = [{ path: `assets/exploit${RLO}gnp.js`, kind: "create" }];
    const hits = await rule.run(effects, cxOf());
    expect(hits).toHaveLength(1);
    expect(hits[0]?.rule).toBe(TROJAN_SOURCE_RULE);
    expect(hits[0]?.decision).toBe("discard");
    expect(hits[0]?.path).toBe(`assets/exploit${RLO}gnp.js`);
    expect(hits[0]?.detail).toContain("U+202E");
    expect(hits[0]?.detail).toContain("in the path");
  });

  it("discards a DELETE with a spoofed name, which has no content to scan at all", async () => {
    const effects: EffectRecord[] = [{ path: `src/lo${ZWSP}gin.ts`, kind: "delete" }];
    const hits = await rule.run(effects, cxOf());
    expect(hits.map((h) => h.detail)).toContain("U+200B (zero-width) in the path at position 7");
  });

  it("commits a turn whose paths are ordinary, content and all", async () => {
    const effects: EffectRecord[] = [
      { path: "src/login.ts", kind: "modify" },
      { path: "docs/readme.md", kind: "create" },
    ];
    expect(await rule.run(effects, cxOf({ "src/login.ts": "const ok = 1;\n" }))).toEqual([]);
  });

  it("does not judge a vendored file's name, the same as it does not judge its content", async () => {
    const effects: EffectRecord[] = [
      { path: `node_modules/x/ev${ZWSP}il.js`, kind: "create", effectClass: "dependency-tree" },
    ];
    // an install is one reviewable unit; a per-file discard on a vendored name would be noise
    expect(await rule.run(effects, cxOf())).toEqual([]);
  });

  it("does not scan an outbound effect's synthetic path as a filename", async () => {
    const effects: EffectRecord[] = [{ path: "net:POST collector:9100/ingest", kind: "outbound" }];
    expect(await rule.run(effects, cxOf())).toEqual([]);
  });
});

/**
 * The rendering-function exemption, added after the rule was measured against 19,102 real commits
 * and found to destroy 84 of them, all sole-cause. See the comment block in trojan-source.ts and
 * research/realworld-prior/REPORT.md section 13.
 *
 * Each positive case below is a real shape from those 84. Each negative is the attack the same
 * character performs when it has no rendering function, so the pair is what the predicate has to
 * separate rather than a demonstration that it fires.
 */
describe("a format character doing the job Unicode defines for it", () => {
  it("exempts a zero-width joiner inside a composed emoji", () => {
    // fastapi release notes, 53 of the 84 destroyed commits are this shape
    expect(findTrojanSource("* \u{1F477}‍♀️ Add script for topic repositories\n", "docs/release-notes.md")).toEqual([]);
  });

  it("exempts a zero-width non-joiner between two cursive-joining characters", () => {
    // Persian: removing it changes the rendered word, which is the opposite of an invisible
    expect(findTrojanSource("یه متغیر محیطی که بهش می‌گن\n", "docs/fa/environment-variables.md")).toEqual([]);
  });

  it("exempts a left-to-right mark when no strong right-to-left character is in scope", () => {
    // UAX #9: a MARK opens no directional run, so with nothing to reorder it reorders nothing
    expect(findTrojanSource("* Fix spelling in `virtual-environments.md‎`\n", "docs/release-notes.md")).toEqual([]);
  });

  it("still flags that same mark once a strong right-to-left character shares the scope", () => {
    const hits = findTrojanSource("const ‎shalom = \"שלום\";\n", "src/a.ts");
    expect(hits.map((h) => h.codePoint)).toContain(0x200e);
  });

  it("still flags a zero-width joiner between two Latin characters, which renders nothing", () => {
    const hits = findTrojanSource("const is‍Admin = false;\n", "src/auth.ts");
    expect(hits.map((h) => h.codePoint)).toContain(0x200d);
  });

  it("still flags a zero-width non-joiner between two Latin characters", () => {
    const hits = findTrojanSource("const is‌Admin = false;\n", "src/auth.ts");
    expect(hits.map((h) => h.codePoint)).toContain(0x200c);
  });

  it("does not exempt a joiner next to a skin tone alone, because a rider is not a base", () => {
    const hits = findTrojanSource("x\u{1F3FB}‍\u{1F3FB}y\n", "src/a.ts");
    expect(hits.map((h) => h.codePoint)).toContain(0x200d);
  });

  it("exempts nothing in the bidi override or isolate ranges, whatever the neighbours", () => {
    for (const cp of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]) {
      const text = `* \u{1F477}${String.fromCodePoint(cp)}\u{1F477} release note\n`;
      expect(findTrojanSource(text, "docs/release-notes.md").map((h) => h.codePoint)).toContain(cp);
    }
  });

  it("exempts nothing in a PATH, because a filename has no prose to render", () => {
    // 271 of the 451 corpus attack detections are path hits. findPathTrojan passes no context.
    const hits = findPathTrojan(".git/hooks/p​re-commit");
    expect(hits.length).toBeGreaterThan(0);
    const emojiPath = findPathTrojan("docs/\u{1F477}‍♀️.md");
    expect(emojiPath.map((h) => h.codePoint)).toContain(0x200d);
  });

  it("still flags a RIGHT-TO-LEFT MARK in an otherwise all-Latin file", () => {
    // The hole the first cut of this change opened, found by an adversarial reviewer running a real
    // bidi implementation. U+200F is Bidi_Class=R, a STRONG right-to-left character, but its Script
    // is Common, so a Script-only guard cannot see it: an RLM in a pure-ASCII file supplies its own
    // opposing strong run and a guard blind to it would answer "no strong RTL here" and exempt it.
    const hits = findTrojanSource("const total = a\u200F- b, c = 1;\n", "src/a.ts");
    expect(hits.map((h) => h.codePoint)).toContain(0x200f);
  });

  it("still flags an ARABIC LETTER MARK, which is also strong right-to-left", () => {
    const hits = findTrojanSource("const x = 1\u061C + 2;\n", "src/a.ts");
    expect(hits.map((h) => h.codePoint)).toContain(0x61c);
  });

  it("stops exempting the left-to-right mark once an RLM shares the scope", () => {
    const hits = findTrojanSource("* note \u200E here\nconst y = 2\u200F;\n", "docs/notes.md");
    expect(hits.map((h) => h.codePoint)).toEqual(expect.arrayContaining([0x200e, 0x200f]));
  });

  it("still flags a soft hyphen, which no shape test separates from is<SHY>Admin", () => {
    const hits = findTrojanSource("Groß-/Klein­schreibung ist relevant\n", "docs/de/index.md");
    expect(hits.map((h) => h.codePoint)).toContain(0x00ad);
  });
});

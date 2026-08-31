import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { isSafeRelative } from "../capture.js";
import { findPathTrojan, rule } from "./trojan-source.js";

/**
 * The path scan is pinned across its whole axis rather than at the points where a defect was once
 * demonstrated, because point tests are what let the first version of it be right for 46 code
 * points and wrong for three.
 *
 * That version reused `classify`, which exempts tab, newline and carriage return as STRUCTURAL.
 * True of file content, where those characters frame the text. False of a filename, where none of
 * them ever appears and all three deceive: `evil.sh<CR>safe.txt` returns the cursor to column 0 in
 * any terminal that prints the review queue, so the row reads `safe.txt`. The exemption was
 * defended in a comment that delegated newline to `isSafeRelative`, whose four checks (absolute,
 * `..`, `.`, empty segment) touch none of the three, so the path was accepted everywhere
 * downstream. Only a sweep of the range showed it.
 *
 * Space is the one character that must keep escaping: `My Document.txt` is an ordinary name.
 */

const cp = (n: number) => String.fromCodePoint(n);
const cx = basicContext(async () => "", { addedLinesOf: async () => "" });

const SWEPT = [
  ...Array.from({ length: 0x21 }, (_, i) => i), // C0 controls and space
  0x7f, 0x85, 0x9b, // DEL, NEL, CSI
  0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, // zero-width family
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidi controls
  0x2066, 0x2067, 0x2068, 0x2069, // bidi isolates
];

describe("the path scan, swept across its whole code point axis", () => {
  it("flags every swept code point except space, which is an ordinary filename character", () => {
    const escaped = SWEPT.filter((n) => findPathTrojan(`src/evil${cp(n)}safe.ts`).length === 0);
    expect(escaped).toEqual([0x20]);
  });

  it("discards a turn for each swept code point except space, through the real rule", async () => {
    const committed: number[] = [];
    for (const n of SWEPT) {
      const effects: EffectRecord[] = [{ path: `src/evil${cp(n)}safe.ts`, kind: "create" }];
      if ((await rule.run(effects, cx)).length === 0) committed.push(n);
    }
    expect(committed).toEqual([0x20]);
  });

  it("names tab, newline and carriage return, which the content scan deliberately does not", () => {
    expect(findPathTrojan(`src/evil${cp(0x0d)}safe.ts`)[0]?.label).toBe("carriage-return");
    expect(findPathTrojan(`src/evil${cp(0x0a)}safe.ts`)[0]?.label).toBe("newline");
    expect(findPathTrojan(`src/evil${cp(0x09)}safe.ts`)[0]?.label).toBe("tab");
  });

  it("cannot delegate those three to isSafeRelative, which accepts every one of them", () => {
    // the reason the scan owns them: nothing downstream refuses the path
    for (const n of [0x09, 0x0a, 0x0d]) {
      expect(isSafeRelative(`src/evil${cp(n)}safe.ts`), `U+${n.toString(16)}`).toBe(true);
    }
  });

  it("passes ordinary names, spaces and legitimate non-ASCII alike", () => {
    const legitimate = [
      "src/components/Login.tsx",
      "assets/logo.png",
      "My Document.txt",
      "a b c/d e.md",
      "docs/日本語.md", // Japanese
      "src/Müller.ts", // NFC u-umlaut
      "café/menü.json",
      "документы/файл.txt", // Cyrillic
      "emoji/☃.txt", // snowman
      "weird but legal/[brackets](parens){braces}.js",
      "dot.files/.eslintrc.json",
    ];
    for (const path of legitimate) {
      expect(findPathTrojan(path), path).toEqual([]);
    }
  });
});

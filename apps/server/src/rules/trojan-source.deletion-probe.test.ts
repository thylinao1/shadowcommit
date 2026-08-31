import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { findPathTrojan, findTrojanSource, rule, TROJAN_SOURCE_RULE } from "./trojan-source.js";

/**
 * The lines of `trojan-source.ts` a deletion probe could remove with the whole rule layer green.
 *
 * 83 deletable lines, 7 survivors, and the module is the best covered of the five biggest rules.
 * Five of the seven are here: the two per-file caps, the code point dedup in the path scan and the
 * `seen.add` that feeds it, and the path on the content hit.
 *
 * The other two are the two `WORKSPACE_ALLOWLIST.has(codePoint)` tests. `WORKSPACE_ALLOWLIST` is an
 * empty Set, by the TODO at the top of the module: `PolicyContext` has nowhere to carry a
 * per-workspace exemption yet, nothing populates the Set, and its type is `ReadonlySet`, so both
 * tests are false for every input. They are reported as unreachable rather than defended, because a
 * test that reached them would have to mutate the exported Set, and a rule that reads a mutable
 * module level Set is the thing to fix rather than the thing to pin.
 *
 * WHAT THIS FILE DOES NOT ESTABLISH. The classification axis is already swept by
 * `trojan-path-sweep.test.ts` and `trojan-source.test.ts`; nothing here re-checks which code points
 * are invisible. These are the bounds and the shape of the output.
 */

const ZERO_WIDTH_SPACE = "​";

describe("the per-file cap on findings", () => {
  it("stops at thirty two findings in a file rather than reporting one per line forever", () => {
    // one zero-width space on each of forty lines is forty distinct line-and-code-point keys
    const added = Array.from({ length: 40 }, (_, i) => `const a${i} = ${ZERO_WIDTH_SPACE}1;`).join("\n");
    const found = findTrojanSource(added, "src/a.js");
    expect(found).toHaveLength(32);
    expect(found[0]?.line).toBe(1);
    expect(found[31]?.line).toBe(32);
  });

  it("reports every finding when a file stays under the cap", () => {
    const added = Array.from({ length: 5 }, (_, i) => `const a${i} = ${ZERO_WIDTH_SPACE}1;`).join("\n");
    expect(findTrojanSource(added, "src/a.js")).toHaveLength(5);
  });

  it("stops at thirty two findings in a path as well", () => {
    // forty distinct invisible code points in one name, which is not a filename anyone typed, but
    // it is the shape a padded name takes and the cap is what keeps the verdict readable
    const points = [
      0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
      0x200b, 0x200c, 0x200d, 0x2060, 0xfeff,
      ...Array.from({ length: 26 }, (_, i) => i + 1),
    ];
    expect(points.length).toBe(40);
    expect(new Set(points).size).toBe(40);
    const name = `src/${points.map((p) => String.fromCodePoint(p)).join("")}x.js`;
    expect(findPathTrojan(name)).toHaveLength(32);
  });
});

describe("a path names each invisible once, however many times it carries it", () => {
  it("reports one finding for a code point repeated across the path", () => {
    const name = `src${ZERO_WIDTH_SPACE}/lib${ZERO_WIDTH_SPACE}/index${ZERO_WIDTH_SPACE}.js`;
    const found = findPathTrojan(name);
    expect(found).toHaveLength(1);
    expect(found[0]?.codePoint).toBe(0x200b);
    expect(found[0]?.column).toBe(4);
  });

  it("still reports two findings for two different code points", () => {
    const name = `src${ZERO_WIDTH_SPACE}/lib‮/index.js`;
    expect(findPathTrojan(name).map((f) => f.label)).toEqual(["zero-width", "bidi-control"]);
  });
});

describe("what a content hit says", () => {
  it("names the file, not only the code point and the position", async () => {
    const added = `const flag = ${ZERO_WIDTH_SPACE}true;\n`;
    const ctx = basicContext(async () => added, { addedLinesOf: async () => added });
    const effects: EffectRecord[] = [{ path: "src/flags.ts", kind: "modify" }];
    expect(await rule.run(effects, ctx)).toEqual([{
      rule: TROJAN_SOURCE_RULE,
      decision: "discard",
      path: "src/flags.ts",
      detail: "U+200B (zero-width) at line 1 column 14",
    }]);
  });
});

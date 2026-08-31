/**
 * A digest must not depend on the locale of the machine that computed it.
 *
 * Four places hashed a directory listing or an object's keys after sorting them with
 * `localeCompare`, which follows the host's locale. The same tree therefore produced a different
 * attestation digest on a different machine, which is the one thing a digest exists to rule out.
 *
 * These tests use explicit locale arguments rather than the ambient one, so they fail on any host
 * rather than only on a host whose locale happens to differ from the author's. The host this was
 * found on defaults to zh-CN.
 */
import { describe, expect, it } from "vitest";
import { compareByCodeUnit, sortByNameForDigest, sortedByCodeUnit } from "./stable-order.js";

/** Name sets whose collation order actually moves between real locales. */
const DIVERGENT = [
  { why: "sv-SE orders a-diaeresis after z, en-US before it", locale: "sv-SE", names: ["zebra.ts", "ärende.ts", "index.ts"] },
  { why: "tr-TR orders dotted and dotless i differently", locale: "tr-TR", names: ["Igloo.ts", "index.ts", "Irmak.ts"] },
  { why: "zh-CN and ja-JP each order CJK differently again", locale: "zh-CN", names: ["日本語.ts", "中文.ts", "한국어.ts", "index.ts"] },
];

describe("digest ordering does not follow the host locale", () => {
  it("is the same under every locale, where localeCompare is not", () => {
    for (const { why, locale, names } of DIVERGENT) {
      const stable = sortedByCodeUnit(names).join("|");
      for (const other of ["en-US", "sv-SE", "tr-TR", "zh-CN", "ja-JP", "de-DE"]) {
        expect(sortedByCodeUnit(names).join("|"), `${why}, under ${other}`).toBe(stable);
      }
      // and the thing it replaced really does move, so this test is not vacuous
      const byLocale = [...names].sort((a, b) => a.localeCompare(b, locale)).join("|");
      const byEnglish = [...names].sort((a, b) => a.localeCompare(b, "en-US")).join("|");
      expect(byLocale, `${why}: if these stop differing this test proves nothing`).not.toBe(byEnglish);
    }
  });

  it("orders by code unit, which puts uppercase before lowercase", () => {
    // The case the shipped fixture tree actually hits: localeCompare folds case and would put
    // customers.jsonl first; code units put README.md first. This is why the pinned workspace
    // digest in the README moves with this change.
    expect(sortedByCodeUnit(["customers.jsonl", "README.md", "src"])).toEqual([
      "README.md",
      "customers.jsonl",
      "src",
    ]);
  });

  it("gives punctuation a defined order, where localeCompare gives it almost none", () => {
    expect(sortedByCodeUnit(["a_b.ts", "a-b.ts", "a.b.ts", "ab.ts"])).toEqual([
      "a-b.ts",
      "a.b.ts",
      "a_b.ts",
      "ab.ts",
    ]);
  });

  it("is a total order: equal, less, greater, and never a coin flip", () => {
    expect(compareByCodeUnit("a", "a")).toBe(0);
    expect(compareByCodeUnit("a", "b")).toBe(-1);
    expect(compareByCodeUnit("b", "a")).toBe(1);
    // Antisymmetry over a set with a combining mark, an astral character and the empty string.
    // Compared by SIGN rather than by negation: negating a comparator zero gives -0, and Object.is
    // separates the two, so toBe(-0) would fail on every equal pair for a reason that has nothing
    // to do with ordering.
    const sign = (n: number): number => (n === 0 ? 0 : n < 0 ? -1 : 1);
    const odd = ["é.ts", "é.ts", "🙂.ts", "a.ts", ""];
    for (const left of odd) {
      for (const right of odd) {
        expect(sign(compareByCodeUnit(left, right))).toBe(sign(-compareByCodeUnit(right, left)));
      }
    }
  });

  it("sorts dirent-shaped entries in place and returns them", () => {
    const entries = [{ name: "b.ts" }, { name: "A.ts" }, { name: "a.ts" }];
    const returned = sortByNameForDigest(entries);
    expect(returned).toBe(entries);
    expect(entries.map((e) => e.name)).toEqual(["A.ts", "a.ts", "b.ts"]);
  });

  it("leaves the caller's array untouched when sorting a copy", () => {
    const input = ["b", "a"];
    expect(sortedByCodeUnit(input)).toEqual(["a", "b"]);
    expect(input).toEqual(["b", "a"]);
  });

  /**
   * The guard, because the helper existing does not stop the next person reaching for the obvious
   * thing. Every file here computes a sha256 over an order it chose, so a localeCompare in any of
   * them is a digest that follows the host again.
   *
   * Deliberately a list of named files rather than a directory sweep: localeCompare is correct
   * almost everywhere else in this tree, where the order is shown to a person rather than hashed,
   * and a sweep would either fail on those or teach everyone to suppress it.
   */
  it("no file that produces a digest sorts by locale", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const url = await import("node:url");
    const here = path.dirname(url.fileURLToPath(import.meta.url));

    const digestProducers = [
      "immutable-oracle.ts",
      "codex-home.ts",
      path.join("..", "..", "..", "scripts", "evidence.ts"),
    ];

    const offenders: string[] = [];
    for (const relative of digestProducers) {
      const file = path.join(here, relative);
      const source = await fs.readFile(file, "utf8");
      if (source.includes("localeCompare")) offenders.push(relative);
    }
    expect(offenders, "these hash an order, so they must not sort by the host's locale").toEqual([]);
  });
});

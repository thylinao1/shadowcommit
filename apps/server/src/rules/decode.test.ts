import { describe, expect, it } from "vitest";
import { decodeCandidates, extractStringLiterals, foldAdjacentLiterals } from "./decode.js";

function texts(line: string): string[] {
  return decodeCandidates(line).map((c) => c.text);
}
function steps(line: string): string[] {
  return decodeCandidates(line).map((c) => c.step);
}

describe("extractStringLiterals", () => {
  it("returns every literal in source order", () => {
    expect(extractStringLiterals(`const a = 'one'; const b = "two"; const c = \`three\`;`))
      .toEqual(["one", "two", "three"]);
  });

  it("does not end a literal on a different quote character", () => {
    expect(extractStringLiterals(`const a = "it's here";`)).toEqual(["it's here"]);
  });

  it("returns nothing for a line with no literals", () => {
    expect(extractStringLiterals("const a = 1 + 2;")).toEqual([]);
  });
});

describe("foldAdjacentLiterals", () => {
  it("folds a two-part concatenation", () => {
    expect(foldAdjacentLiterals(`const k = 'sk-' + 'abcdef';`)).toBe(`const k = "sk-abcdef";`);
  });

  it("folds a chain left to right", () => {
    expect(foldAdjacentLiterals(`"a"+"b"+"c"+"d"`)).toBe(`"abcd"`);
  });

  it("leaves a concatenation with a variable in it alone", () => {
    expect(foldAdjacentLiterals(`"a" + b + "c"`)).toBe(`"a" + b + "c"`);
  });

  it("leaves an addition of numbers alone", () => {
    expect(foldAdjacentLiterals("const n = 1 + 2;")).toBe("const n = 1 + 2;");
  });
});

describe("decodeCandidates", () => {
  it("decodes base64 and names the step", () => {
    const encoded = Buffer.from("sk-live-abcdefghijklmnop").toString("base64");
    expect(texts(`atob("${encoded}")`)).toContain("sk-live-abcdefghijklmnop");
    expect(steps(`atob("${encoded}")`)).toContain("decode:base64");
  });

  it("decodes hex", () => {
    const encoded = Buffer.from("password-in-the-clear").toString("hex");
    expect(texts(`unhex("${encoded}")`)).toContain("password-in-the-clear");
  });

  it("decodes percent encoding", () => {
    expect(texts("fetch('/x?k=secret%2Dvalue%2Dhere')").join(" ")).toContain("secret-value-here");
  });

  it("decodes a character-code array only when a fromCharCode call is present", () => {
    const codes = [...'sk-live-abcd'].map((c) => c.codePointAt(0)).join(",");
    expect(texts(`String.fromCharCode(${codes})`)).toContain("sk-live-abcd");
    expect(texts(`const sizes = [${codes}];`)).not.toContain("sk-live-abcd");
  });

  it("reverses a literal when the split-reverse-join idiom is present", () => {
    expect(texts(`"terces-a-si-siht".split('').reverse().join('')`)).toContain("this-is-a-secret");
  });

  it("discards a decode that produces binary rather than text", () => {
    expect(texts("const h = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';")).toEqual([]);
  });

  it("returns nothing for ordinary source", () => {
    expect(decodeCandidates("export function add(a: number, b: number) { return a + b; }")).toEqual([]);
  });
});

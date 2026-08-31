import { describe, expect, it } from "vitest";
import { collapseKeyValues, foldConfusables, normaliseLines, normaliseText } from "./normalise.js";

describe("foldConfusables", () => {
  it("folds a Cyrillic lookalike onto the ASCII letter it renders as", () => {
    expect(foldConfusables("pаssword")).toBe("password");
  });

  it("folds Greek lookalikes", () => {
    expect(foldConfusables("tοkεn")).toBe("token");
  });

  it("leaves ordinary accented text alone", () => {
    expect(foldConfusables("café")).toBe("café");
  });
});

describe("normaliseText", () => {
  it("folds fullwidth forms to ASCII through NFKC", () => {
    expect(normaliseText("ｐａｓｓｗｏｒｄ")).toBe("password");
  });

  it("is idempotent", () => {
    const once = normaliseText("pаssword = ａｂｃ");
    expect(normaliseText(once)).toBe(once);
  });
});

describe("collapseKeyValues", () => {
  it("collapses the JSON shape", () => {
    expect(collapseKeyValues('  "password": "hunter2hunter2"')).toContain("password=hunter2hunter2");
  });

  it("collapses the unquoted YAML shape", () => {
    expect(collapseKeyValues("  db_password: hunter2hunter2")).toContain("db_password=hunter2hunter2");
  });

  it("collapses a spaced assignment", () => {
    expect(collapseKeyValues("db_password = hunter2hunter2")).toContain("db_password=hunter2hunter2");
  });

  it("collapses a dotenv assignment", () => {
    expect(collapseKeyValues("API_KEY=abc12345")).toContain("API_KEY=abc12345");
  });

  it("leaves a quoted value containing whitespace alone", () => {
    const line = "     * const password = 'Password used to generate key';";
    expect(collapseKeyValues(line)).toBe(line);
  });

  it("does not rewrite a URL into a key-value pair", () => {
    const line = "const DB = 'postgres://svc:S3rvicePass@10.0.0.9:5432/prod';";
    expect(collapseKeyValues(line)).toContain("postgres://svc:S3rvicePass@10.0.0.9:5432/prod");
  });

  it("is idempotent", () => {
    const once = collapseKeyValues('{"password": "hunter2hunter2"}');
    expect(collapseKeyValues(once)).toBe(once);
  });
});

describe("normaliseLines", () => {
  it("preserves the line count so a finding can name its line", () => {
    const text = "a\npаssword: x\nc\n";
    const { folded, collapsed } = normaliseLines(text);
    expect(folded).toHaveLength(4);
    expect(collapsed).toHaveLength(4);
    expect(collapsed[1]).toBe("password=x");
  });
});

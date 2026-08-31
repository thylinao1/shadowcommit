import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord, type RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { rule as secretScan } from "./secret-scan.js";
import { rule as platformSecrets } from "./platform-secrets.js";
import { rule as netToExec } from "./net-to-exec.js";
import { rule as insecureIdiom } from "./insecure-idiom.js";
import { rule as trojanSource } from "./trojan-source.js";

/**
 * The shape the integration lane registers against. Every module in this directory exports
 * `rule: Rule`, and every rule is safe to call on an empty turn, on an effect it cannot read, and
 * on a context that declares nothing.
 */
const RULES: Array<[string, Rule]> = [
  ["secret-scan", secretScan],
  ["platform-secrets", platformSecrets],
  ["net-to-exec", netToExec],
  ["insecure-idiom", insecureIdiom],
  ["trojan-source", trojanSource],
];

describe("the rules this lane exports", () => {
  it("has one rule per content scanner", () => {
    expect(RULES).toHaveLength(5);
    expect(new Set(RULES.map(([, r]) => r.name)).size).toBe(5);
  });

  for (const [id, rule] of RULES) {
    it(`${id} names itself and returns an array`, async () => {
      expect(rule.name.length).toBeGreaterThan(0);
      expect(await rule.run([], basicContext(async () => ""))).toEqual([]);
    });

    it(`${id} survives a context that cannot read the path`, async () => {
      const effects: EffectRecord[] = [{ path: "src/a.ts", kind: "modify" }];
      const ctx = basicContext(async () => {
        throw new Error("unreadable");
      }, {
        addedLinesOf: async () => {
          throw new Error("unreadable");
        },
        realContentOf: async () => {
          throw new Error("unreadable");
        },
      });
      expect(await rule.run(effects, ctx)).toEqual([]);
    });

    it(`${id} commits an ordinary coding turn`, async () => {
      const files: Record<string, string> = {
        "src/add.ts": "export function add(a: number, b: number): number {\n  return a + b;\n}\n",
        "src/add.test.ts": "import { add } from './add.js';\nexpect(add(1, 2)).toBe(3);\n",
        "README.md": "# Title\n\nRun `npm test` to check.\n",
      };
      const effects: EffectRecord[] = [
        { path: "src/add.ts", kind: "create" },
        { path: "src/add.test.ts", kind: "create" },
        { path: "README.md", kind: "modify" },
      ];
      const ctx = basicContext(async (p) => files[p] ?? "", {
        addedLinesOf: async (p) => files[p] ?? "",
        realContentOf: async (p) => files[p] ?? null,
        platformSecrets: ["ark-live-9f2c1d4b7a3e6058"],
      });
      expect(await rule.run(effects, ctx)).toEqual([]);
    });
  }

  it("emits hits whose decision is only ever discard or review", async () => {
    const files = { "src/db.js": "db_password = hunter2hunter2\n" };
    const ctx = basicContext(async (p) => files[p as keyof typeof files] ?? "", {
      addedLinesOf: async (p) => files[p as keyof typeof files] ?? "",
    });
    const hits: RuleHit[] = [];
    for (const [, rule] of RULES) hits.push(...await rule.run([{ path: "src/db.js", kind: "create" }], ctx));
    expect(hits.length).toBeGreaterThan(0);
    for (const hit of hits) expect(["discard", "review"]).toContain(hit.decision);
  });
});

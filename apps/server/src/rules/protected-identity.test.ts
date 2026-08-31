import { describe, expect, it } from "vitest";
import { protectedIdentityRule } from "./protected-identity.js";
import { DEFAULT_PROTECTED_PATHS } from "../policy-context.js";
import type { EffectRecord, PolicyContext } from "../policy-types.js";

/**
 * Written after a deletion probe found this rule was the least covered thing in the registry.
 *
 * Four of its sixteen deletable lines could be removed with every test under `rules/` still
 * passing: the inode check, the effectClass check, and BOTH lines that push the hit. Deleting the
 * `protected-asset-write` push alone took the corpus from 117 misses to 191, so 74 attacks rested
 * on a line no unit test touched.
 *
 * That matters because of which gate runs where. CI runs `npm run check` and `check-stamp.mjs`; it
 * does NOT replay the corpus. So the only gate that noticed was one CI never runs, and the change
 * would have gone green all the way to main.
 *
 * These tests pin the three ways identity is established and both verdicts, so each of those four
 * lines now has something that fails when it goes.
 */
const ctx = (over: Partial<PolicyContext> = {}): PolicyContext =>
  ({
    contentOf: async () => null,
    realContentOf: async () => null,
    addedLinesOf: async () => "",
    recentTouches: [],
    protectedPaths: DEFAULT_PROTECTED_PATHS,
    protectedInodes: new Set<string>(),
    platformSecrets: [],
    registryAllowlist: [],
    limits: { maxScanBytes: 1 << 20, maxEffectBytes: 8 << 20, maxTurnBytes: 32 << 20 },
    ...over,
  }) as PolicyContext;

const effect = (over: Partial<EffectRecord>): EffectRecord =>
  ({ path: "src/x.ts", kind: "modify", ...over }) as EffectRecord;

describe("a protected asset is identified by what it is, not how the turn spelled it", () => {
  it("by inode, when the path gives nothing away", async () => {
    // The line this pins is the whole "identity, not spelling" claim: an ordinary-looking path
    // whose real-side inode is one the seal recorded as protected.
    const hits = await protectedIdentityRule.run(
      [effect({ path: "tmp/harmless.txt", realIno: "16777229:99" })],
      ctx({ protectedInodes: new Set(["16777229:99"]) }),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]!.rule).toBe("protected-asset-write");
  });

  it("by effectClass, when the classifier already decided", async () => {
    const hits = await protectedIdentityRule.run(
      [effect({ path: "tmp/harmless.txt", effectClass: "protected" })],
      ctx(),
    );
    expect(hits).toHaveLength(1);
  });

  it("by canonical path, segment anywhere and case folded", async () => {
    for (const p of ["customers.jsonl", "config/secrets/prod.key", ".env.local", "Customers.jsonl"]) {
      const hits = await protectedIdentityRule.run([effect({ path: p })], ctx());
      expect(hits, `${p} should be protected`).toHaveLength(1);
    }
  });

  it("leaves an ordinary path alone, so this is not just 'always fire'", async () => {
    const hits = await protectedIdentityRule.run([effect({ path: "src/index.ts" })], ctx());
    expect(hits).toHaveLength(0);
  });
});

describe("both verdicts, and the order the operator reads them in", () => {
  it("discards a write to a protected asset", async () => {
    // The line this pins is the one whose deletion took the corpus from 117 misses to 191.
    const hits = await protectedIdentityRule.run([effect({ path: "customers.jsonl" })], ctx());
    expect(hits).toEqual([
      { rule: "protected-asset-write", decision: "discard", path: "customers.jsonl" },
    ]);
  });

  it("discards a delete of a protected asset", async () => {
    const hits = await protectedIdentityRule.run(
      [effect({ path: "customers.jsonl", kind: "delete" })],
      ctx(),
    );
    expect(hits).toEqual([
      { rule: "protected-asset-delete", decision: "discard", path: "customers.jsonl" },
    ]);
  });

  it("reports the destructive half first when a turn both deletes and rewrites", async () => {
    // Order is load-bearing: the worst verdict wins either way, but the operator reads the FIRST
    // hit as the deciding rule, and "deleted your customer file" is the sentence they need.
    const hits = await protectedIdentityRule.run(
      // `.env` must be the BASENAME: the pattern is (^|/)\.env(\.[\w.-]+)?$, so `a.env` is not
      // protected and my first version of this test used exactly that and failed. Fixture bug, not
      // a rule bug, and worth leaving the note so the next person does not repeat it.
      [effect({ path: ".env.local", kind: "modify" }), effect({ path: "customers.jsonl", kind: "delete" })],
      ctx(),
    );
    expect(hits.map((h) => h.rule)).toEqual(["protected-asset-delete", "protected-asset-write"]);
  });
});

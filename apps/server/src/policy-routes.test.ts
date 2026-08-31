import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { apiSurfaceOf, createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { policyRegistryView } from "./policy-routes.js";
import { rules } from "./rules/index.js";
import { MAX_EFFECT_BYTES, MAX_TURN_BYTES } from "./capture.js";
import { REVIEW_AT_OR_ABOVE_TOUCHES } from "./rules/blast-radius.js";
import { MULTI_DELETE_AT_OR_ABOVE } from "./rules/multi-file-delete.js";
import { COST_FLOORS } from "./rules/insecure-idiom.js";
import { DEFAULT_REGISTRY_ALLOWLIST } from "./dependency-diff.js";
import { createCapabilityGrantRule } from "./capability-grant-rule.js";
import { MemoryCapabilityGrantStore } from "./capability-grants.js";
import { basicContext } from "./policy-types.js";
import type { AgentService } from "./agent-service.js";
import type { EffectRecord, PolicyContext, PolicyVerdict } from "./policy-types.js";

const service = {
  listAgents: () => [],
  getAgent: () => {
    throw new Error("no such agent");
  },
  systemInfo: async () => ({}),
} as unknown as AgentService;

const URL_UNDER_TEST = "/api/policy/rules";
const here = path.dirname(fileURLToPath(import.meta.url));

describe("the rule list an operator can read", () => {
  it("returns the registry array itself, in order, with nothing added or dropped", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const response = await app.inject({ method: "GET", url: URL_UNDER_TEST });
    expect(response.statusCode).toBe(200);
    const body = response.json();

    expect(body.count).toBe(rules.length);
    expect(body.rules.map((rule: { id: string }) => rule.id)).toEqual(rules.map((rule) => rule.name));
    expect(body.rules.map((rule: { position: number }) => rule.position)).toEqual(
      rules.map((_, index) => index + 1),
    );
    await app.close();
  });

  it("publishes the summary, the decisions and the hit ids declared on every rule, not a subset", () => {
    // the axis is the whole registry, not the one rule a screenshot happened to show
    const view = policyRegistryView();
    expect(view.rules).toHaveLength(rules.length);
    for (const rule of rules) {
      const projected = view.rules.find((candidate) => candidate.id === rule.name);
      expect([rule.name, projected]).not.toEqual([rule.name, undefined]);
      expect([rule.name, projected?.summary]).toEqual([rule.name, rule.summary]);
      expect([rule.name, projected?.decisions]).toEqual([rule.name, [...rule.decisions]]);
      expect([rule.name, projected?.hitIds]).toEqual([rule.name, [...rule.hitIds]]);
    }
  });

  it("says the server reports what fired and not what was evaluated, so no client can claim otherwise", () => {
    // the endpoint publishing this flag is the whole reason the review card is allowed to show a
    // registry list at all: the list is what is REGISTERED, never a per-turn record of what ran
    const { notes } = policyRegistryView();
    expect(notes.reportsFiredNotEvaluated).toBe(true);
    expect(notes.noShortCircuit).toBe(true);
    expect(notes.ruleErrorHitId).toBe("policy-rule-error");
  });

  it("does not claim no-short-circuit on its own word: the loop in shadow-policy.ts has no early exit", () => {
    const source = fs.readFileSync(path.join(here, "shadow-policy.ts"), "utf8");
    const loop = /for \(const rule of rules\) \{([\s\S]*?)\n  \}/.exec(source)?.[1] ?? "";
    expect(loop.length).toBeGreaterThan(0);
    expect(loop).not.toMatch(/\bbreak\b/);
    expect(loop).not.toMatch(/\breturn\b/);
    expect(loop).toContain("hits.push");
    // and the id the endpoint publishes for a rule that throws is the one that file really uses
    expect(source).toContain('rule: "policy-rule-error"');
  });

  /**
   * `notes.authorizationAhead` is the one field on this endpoint that describes a DIFFERENT module,
   * and the review card prints its prefix to an operator in a <code> tag. Asserted against its own
   * literal it was a tautology: measured, renaming `capability-path-out-of-scope` to
   * `grant-path-out-of-scope` and turning `capability-grant-revoked` into a discard left the whole
   * suite green while the endpoint kept publishing the old prefix and the review-only claim.
   *
   * So it is pinned twice, the way `ruleErrorHitId` is pinned to `shadow-policy.ts`: once by
   * reading the source of `capability-grant-rule.ts`, and once by RUNNING that rule over every cell
   * it can fail in. The source scan catches an id or a decision that no test happens to exercise;
   * the sweep catches a rule that was rewritten to compute what the scan reads literally.
   */
  const authorizationSource = (): string =>
    fs.readFileSync(path.join(here, "capability-grant-rule.ts"), "utf8");

  it("publishes a prefix and a decision list that capability-grant-rule.ts actually uses", () => {
    const { authorizationAhead } = policyRegistryView().notes;
    const lines = authorizationSource()
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => !line.startsWith("*") && !line.startsWith("//") && !line.startsWith("/*"));

    const reported: string[] = [];
    for (const line of lines) {
      // both spellings that name a hit in that module: the `rule:` property of a RuleHit, and the
      // first argument of the local `review(...)` helper, which becomes the verdict's own rule
      for (const match of line.matchAll(/(?:\brule:|\breview\()\s*"([^"]+)"/g)) {
        reported.push(match[1] ?? "");
      }
    }
    expect(reported.length).toBeGreaterThan(0);
    for (const id of reported) {
      expect([id, id.startsWith(authorizationAhead.hitIdPrefix)]).toEqual([id, true]);
    }

    const decided: string[] = [];
    for (const line of lines) {
      for (const match of line.matchAll(/\bdecision:\s*"([^"]+)"/g)) decided.push(match[1] ?? "");
    }
    expect(decided.length).toBeGreaterThan(0);
    for (const decision of decided) {
      expect([decision, authorizationAhead.decisions.includes(decision)]).toEqual([decision, true]);
    }
  });

  it("sweeps every cell the authorization check can fail in, not the one the panel shows", async () => {
    const { authorizationAhead } = policyRegistryView().notes;
    const agentId = "11111111-1111-4111-8111-111111111111";
    const context = (over: Partial<PolicyContext> = {}): PolicyContext =>
      basicContext(async () => "", { agentId, caseInsensitiveHost: false, ...over });

    const outbound: EffectRecord = {
      path: "POST https://api.elsewhere.test/x",
      kind: "outbound",
      resource: "http",
      host: "api.elsewhere.test",
      urlPath: "/x",
    };
    const cells: Array<[string, () => Promise<PolicyVerdict | null>]> = [];

    const withGrant = async (
      input: { allowedPathGlobs: string[]; allowedDestinations: string[]; budget: number } | "revoked",
    ) => {
      const store = new MemoryCapabilityGrantStore();
      if (input === "revoked") {
        await store.issue(agentId, { allowedPathGlobs: ["**"], allowedDestinations: ["*"], budget: 9 }, "operator");
        await store.revoke(agentId, "operator");
      } else {
        await store.issue(agentId, input, "operator");
      }
      return createCapabilityGrantRule(store);
    };

    const narrow = { allowedPathGlobs: ["docs/**"], allowedDestinations: ["docs.example.test"], budget: 9 };
    cells.push([
      "no agent on the context",
      async () => (await withGrant(narrow))([{ path: "src/a.ts", kind: "modify" }], context({ agentId: undefined })),
    ]);
    cells.push([
      "revoked grant",
      async () => (await withGrant("revoked"))([{ path: "docs/a.md", kind: "modify" }], context()),
    ]);
    cells.push([
      "over budget",
      async () =>
        (await withGrant({ ...narrow, budget: 1 }))(
          [{ path: "docs/a.md", kind: "modify" }, { path: "docs/b.md", kind: "modify" }],
          context(),
        ),
    ]);
    cells.push([
      "path out of scope",
      async () => (await withGrant(narrow))([{ path: "src/a.ts", kind: "modify" }], context()),
    ]);
    cells.push([
      "path that leaves the workspace, against a wide-open grant",
      async () =>
        (await withGrant({ allowedPathGlobs: ["**"], allowedDestinations: ["*"], budget: 9 }))(
          [{ path: "../outside.ts", kind: "modify" }],
          context(),
        ),
    ]);
    cells.push([
      "destination out of scope",
      async () => (await withGrant(narrow))([outbound], context()),
    ]);
    cells.push([
      "symlink target out of scope",
      async () =>
        (await withGrant(narrow))(
          [{ path: "docs/link", kind: "symlink", target: "../src/secret.ts" }],
          context(),
        ),
    ]);

    for (const [what, run] of cells) {
      const verdict = await run();
      expect([what, verdict === null]).toEqual([what, false]);
      expect([what, verdict?.decision]).toEqual([what, "review"]);
      expect([what, verdict?.rule.startsWith(authorizationAhead.hitIdPrefix)]).toEqual([what, true]);
      for (const hit of verdict?.hits ?? []) {
        expect([what, hit.rule.startsWith(authorizationAhead.hitIdPrefix)]).toEqual([what, true]);
        expect([what, authorizationAhead.decisions.includes(hit.decision)]).toEqual([what, true]);
      }
    }
  });

  it("says the authorization stage stops at its first failing question, because it does", async () => {
    // `noShortCircuit` is about the registry loop only. The panel would otherwise carry that
    // property across a stage that does not have it: a turn both over budget and out of scope is
    // reported as over budget alone, and raising the budget makes a fresh set of hits appear.
    const { authorizationAhead } = policyRegistryView().notes;
    const agentId = "22222222-2222-4222-8222-222222222222";
    const store = new MemoryCapabilityGrantStore();
    await store.issue(agentId, { allowedPathGlobs: ["docs/**"], allowedDestinations: ["*"], budget: 1 }, "operator");
    const rule = createCapabilityGrantRule(store);
    const effects: EffectRecord[] = [
      { path: "src/a.ts", kind: "modify" },
      { path: "src/b.ts", kind: "modify" },
    ];
    const ctx = basicContext(async () => "", { agentId, caseInsensitiveHost: false });

    const capped = await rule(effects, ctx);
    expect(capped?.hits?.map((hit) => hit.rule)).toEqual(["capability-budget-exceeded"]);

    await store.issue(agentId, { allowedPathGlobs: ["docs/**"], allowedDestinations: ["*"], budget: 9 }, "operator");
    const raised = await rule(effects, ctx);
    expect(raised?.hits?.map((hit) => hit.rule)).toEqual([
      "capability-path-out-of-scope",
      "capability-path-out-of-scope",
    ]);

    expect(authorizationAhead.stopsAtFirstFailure).toBe(true);
  });

  it("carries none of the material an evasion is built out of", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const payload = (await app.inject({ method: "GET", url: URL_UNDER_TEST })).json();
    await app.close();

    // The WHOLE response, with `position` and `count` removed wherever they appear rather than
    // rebuilt from a list of fields somebody remembered to name. The hand-picked version was
    // measured to miss a field added later: publishing `touchThreshold: REVIEW_AT_OR_ABOVE_TOUCHES`
    // on all sixteen rules left this test green, because the rebuild never looked at it.
    //
    // Those two keys are the only exclusions, and each has a reason that is not "it was awkward":
    // they are the index of the array and its length, so a small threshold like 8 would collide
    // with a position by arithmetic rather than by disclosure, and matching bare digits against
    // them only makes this test lie.
    const withoutIndices = (value: unknown): unknown => {
      if (Array.isArray(value)) return value.map(withoutIndices);
      if (typeof value !== "object" || value === null) return value;
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .filter(([key]) => key !== "position" && key !== "count")
          .map(([key, entry]) => [key, withoutIndices(entry)]),
      );
    };
    const body = JSON.stringify(withoutIndices(payload));

    // and the key set of a rule entry is pinned, so a field added to this view is a failure until
    // somebody decides it is safe to disclose rather than being scanned and then forgotten
    for (const rule of payload.rules as Array<Record<string, unknown>>) {
      expect([rule.id, Object.keys(rule).sort()]).toEqual([
        rule.id,
        ["decisions", "hitIds", "id", "position", "summary"],
      ]);
    }
    expect(Object.keys(payload).sort()).toEqual(["count", "notes", "rules"]);

    const banned: Array<[string, string]> = [
      ["effect byte cap", String(MAX_EFFECT_BYTES)],
      ["turn byte cap", String(MAX_TURN_BYTES)],
      ["touch threshold", String(REVIEW_AT_OR_ABOVE_TOUCHES)],
      ["multi-delete threshold", String(MULTI_DELETE_AT_OR_ABOVE)],
      ...Object.entries(COST_FLOORS).map(
        ([name, value]) => [`cost floor ${name}`, String(value)] as [string, string],
      ),
      ...DEFAULT_REGISTRY_ALLOWLIST.map(
        (host: string) => [`allowlisted host ${host}`, host] as [string, string],
      ),
    ];
    for (const [what, value] of banned) {
      expect([what, body.includes(value)]).toEqual([what, false]);
    }

    // no pattern source either: the scanners' regexes never leave the process
    expect(body).not.toContain("\\b");
    expect(body).not.toContain("(?<");
  });

  it("is on the guarded tier, and a caller with no credential is refused", async () => {
    expect(apiSurfaceOf(URL_UNDER_TEST)).toBe("control");
    // and by the spellings the router accepts but a naive prefix check does not
    expect(apiSurfaceOf("http://localhost:3000" + URL_UNDER_TEST)).toBe("control");
    expect(apiSurfaceOf("/%61pi/policy/rules")).toBe("control");

    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      service,
    );
    const denied = await app.inject({ method: "GET", url: URL_UNDER_TEST });
    expect(denied.statusCode).toBe(401);
    const allowed = await app.inject({
      method: "GET",
      url: URL_UNDER_TEST,
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(allowed.statusCode).toBe(200);
    expect(allowed.json().count).toBe(rules.length);
    await app.close();
  });
});

import { describe, expect, it, vi } from "vitest";
import {
  destinationMatchesCapability,
  pathMatchesCapability,
  withCapabilityGrantRule,
} from "./capability-grant-rule.js";
import { MemoryCapabilityGrantStore } from "./capability-grants.js";
import { basicContext, type EffectRecord, type Policy } from "./policy-types.js";

const fileEffect = (path: string): EffectRecord => ({ kind: "modify", path });
const outboundEffect = (host: string, port = 443, urlPath = "/v1/items"): EffectRecord => ({
  kind: "outbound",
  path: `${host}${urlPath}`,
  host,
  port,
  urlPath,
});

const commit: Policy = async () => ({ decision: "commit", rule: "none" });

describe("capability matching", () => {
  it("matches workspace globs without accepting traversal or sibling prefixes", () => {
    expect(pathMatchesCapability("src/nested/index.ts", ["src/**/*.ts"])).toBe(true);
    expect(pathMatchesCapability("src/index.ts", ["src/**/*.ts"])).toBe(true);
    expect(pathMatchesCapability("src-secrets/index.ts", ["src/**"])).toBe(false);
    expect(pathMatchesCapability("src/../secrets.txt", ["src/**"])).toBe(false);
  });

  it("matches exact destination authority and path without encoded traversal", () => {
    const allowed = ["*.example.test:443/v1/**"];
    expect(destinationMatchesCapability(outboundEffect("api.example.test"), allowed)).toBe(true);
    expect(destinationMatchesCapability(outboundEffect("example.test"), allowed)).toBe(false);
    expect(destinationMatchesCapability(outboundEffect("api.example.test", 80), allowed)).toBe(false);
    expect(destinationMatchesCapability(outboundEffect("api.example.test", 0), allowed)).toBe(false);
    expect(
      destinationMatchesCapability(outboundEffect("api.example.test", 443, "/v1/%2e%2e/admin"), allowed),
    ).toBe(false);
  });
});

describe("capability grant rule", () => {
  it("allows ordinary in-scope work before delegating to content policy", async () => {
    const store = new MemoryCapabilityGrantStore();
    await store.issue("agent-1", {
      allowedPathGlobs: ["src/**"],
      allowedDestinations: ["api.example.test:443"],
      budget: 2,
    });
    const contentPolicy = vi.fn(commit);
    const policy = withCapabilityGrantRule(store, contentPolicy);
    const verdict = await policy(
      [fileEffect("src/index.ts"), outboundEffect("api.example.test")],
      basicContext(async () => "", { agentId: "agent-1" }),
    );
    expect(verdict).toEqual({ decision: "commit", rule: "none" });
    expect(contentPolicy).toHaveBeenCalledOnce();
  });

  it("keeps the starter behavior through the default grant", async () => {
    const verdict = await withCapabilityGrantRule(new MemoryCapabilityGrantStore(), commit)(
      [fileEffect("any/nested/path.ts"), outboundEffect("any.example.test", 8443)],
      basicContext(async () => "", { agentId: "new-agent" }),
    );
    expect(verdict).toEqual({ decision: "commit", rule: "none" });
  });

  it("uses original casing on case-sensitive hosts", async () => {
    const store = new MemoryCapabilityGrantStore();
    await store.issue("agent-1", {
      allowedPathGlobs: ["src/MyFile.ts"],
      allowedDestinations: ["*"],
      budget: 1,
    });
    const effect = { ...fileEffect("src/MyFile.ts"), canonicalPath: "src/myfile.ts" };
    const verdict = await withCapabilityGrantRule(store, commit)(
      [effect],
      basicContext(async () => "", { agentId: "agent-1", caseInsensitiveHost: false }),
    );
    expect(verdict).toEqual({ decision: "commit", rule: "none" });
  });

  it("runs capability first without masking a stricter content discard", async () => {
    const store = new MemoryCapabilityGrantStore();
    await store.issue("agent-1", {
      allowedPathGlobs: ["src/**"],
      allowedDestinations: ["api.example.test"],
      budget: 4,
    });
    const order: string[] = [];
    const originalGet = store.get.bind(store);
    vi.spyOn(store, "get").mockImplementation(async (agentId) => {
      order.push("capability");
      return originalGet(agentId);
    });
    const contentPolicy = vi.fn(async () => {
      order.push("content");
      return { decision: "discard" as const, rule: "malicious-payload" };
    });
    const verdict = await withCapabilityGrantRule(store, contentPolicy)(
      [fileEffect("src/../../.ssh/authorized_keys")],
      basicContext(async () => "", { agentId: "agent-1" }),
    );
    expect(order).toEqual(["capability", "content"]);
    expect(verdict).toMatchObject({ decision: "discard", rule: "malicious-payload" });
    expect(verdict.hits).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: "capability-path-out-of-scope", decision: "review" }),
        expect.objectContaining({ rule: "malicious-payload", decision: "discard" }),
      ]),
    );
  });

  it("does not let an in-scope symlink alias an out-of-scope workspace path", async () => {
    const store = new MemoryCapabilityGrantStore();
    await store.issue("agent-1", {
      allowedPathGlobs: ["docs/**"],
      allowedDestinations: ["*"],
      budget: 1,
    });
    const verdict = await withCapabilityGrantRule(store, commit)(
      [{ kind: "symlink", path: "docs/source", target: "../src" }],
      basicContext(async () => "", { agentId: "agent-1" }),
    );
    expect(verdict).toMatchObject({
      decision: "review",
      rule: "capability-symlink-target-out-of-scope",
    });
  });

  it("reviews destinations outside the grant", async () => {
    const store = new MemoryCapabilityGrantStore();
    await store.issue("agent-1", {
      allowedPathGlobs: ["**"],
      allowedDestinations: ["api.example.test:443"],
      budget: 3,
    });
    const verdict = await withCapabilityGrantRule(store, commit)(
      [outboundEffect("metadata.invalid", 80, "/latest/meta-data")],
      basicContext(async () => "", { agentId: "agent-1" }),
    );
    expect(verdict).toMatchObject({
      decision: "review",
      rule: "capability-destination-out-of-scope",
    });
  });

  it("reviews a turn whose aggregate effect count exceeds its budget", async () => {
    const store = new MemoryCapabilityGrantStore();
    await store.issue("agent-1", {
      allowedPathGlobs: ["src/**"],
      allowedDestinations: ["*"],
      budget: 1,
    });
    const verdict = await withCapabilityGrantRule(store, commit)(
      [fileEffect("src/a.ts"), fileEffect("src/b.ts")],
      basicContext(async () => "", { agentId: "agent-1" }),
    );
    expect(verdict).toMatchObject({ decision: "review", rule: "capability-budget-exceeded" });
  });

  it("changes the next verdict after revocation instead of restoring the broad default", async () => {
    const store = new MemoryCapabilityGrantStore();
    await store.issue("agent-1", {
      allowedPathGlobs: ["src/**"],
      allowedDestinations: ["*"],
      budget: 1,
    });
    const policy = withCapabilityGrantRule(store, commit);
    const context = basicContext(async () => "", { agentId: "agent-1" });
    await expect(policy([fileEffect("src/ok.ts")], context)).resolves.toMatchObject({
      decision: "commit",
    });
    await store.revoke("agent-1", "operator-2");
    await expect(policy([fileEffect("src/ok.ts")], context)).resolves.toMatchObject({
      decision: "review",
      rule: "capability-grant-revoked",
    });
  });

  it("fails closed when policy context omits the Agent principal", async () => {
    const verdict = await withCapabilityGrantRule(new MemoryCapabilityGrantStore(), commit)(
      [fileEffect("src/index.ts")],
      basicContext(async () => ""),
    );
    expect(verdict).toMatchObject({ decision: "review", rule: "capability-agent-unidentified" });
  });
});

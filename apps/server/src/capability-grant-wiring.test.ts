import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { buildPolicyContext } from "./policy-context.js";
import { capabilityGrantStoreFor, MemoryCapabilityGrantStore } from "./capability-grants.js";
import { withCapabilityGrantRule } from "./capability-grant-rule.js";
import { defaultPolicy } from "./shadow-policy.js";
import type { AgentService } from "./agent-service.js";
import type { EffectRecord } from "./policy-types.js";

// the routes validate the id as a uuid before they look the agent up
const KNOWN = "11111111-2222-4333-8444-555555555555";
const UNKNOWN = "99999999-8888-4777-8666-555555555555";

/**
 * The capability modules were built with fifteen tests of their own and were reachable from none of
 * them: nothing on the product path imported the rule, the routes or the store, so every one of
 * those tests could pass while an agent's grant was never consulted on a real turn. A module that
 * the product cannot reach enforces nothing.
 *
 * These tests assert the three joins, not the modules: the context carries the agent, the composed
 * policy is stricter than the content policy alone, and the operator routes answer through the app
 * the server actually builds.
 */

const service = {
  listAgents: () => [],
  systemInfo: async () => ({}),
  getAgent: (id: string) => {
    if (id !== KNOWN) throw new Error("Agent not found");
    return { id, name: "known" };
  },
} as unknown as AgentService;

describe("capability grants are wired into the product path", () => {
  it("gives the policy the agent the turn belongs to, so a grant can be found at all", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "grant-wiring-"));
    try {
      const workspace = path.join(dir, "ws");
      const shadow = path.join(dir, "shadow", "merged");
      await fs.mkdir(workspace, { recursive: true });
      await fs.mkdir(shadow, { recursive: true });

      const context = await buildPolicyContext({
        shadowDir: path.join(dir, "shadow"),
        mechanism: "copy",
        workspacePath: workspace,
        journalPath: path.join(dir, "journal.jsonl"),
        agentId: KNOWN,
        limits: { maxFileBytes: 1024, maxTotalBytes: 4096, maxFiles: 16 },
        platformSecrets: [],
        registryAllowlist: [],
        realInodes: new Map(),
      });

      // without this the capability rule cannot tell one agent's grant from another's
      expect(context.agentId).toBe(KNOWN);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("composes authorization ahead of content policy, so an out-of-scope write is held that the content rules alone would commit", async () => {
    const store = new MemoryCapabilityGrantStore();
    await store.issue(KNOWN, { allowedPathGlobs: ["src/**"], allowedDestinations: ["*"], budget: 10 }, "operator");

    const effects: EffectRecord[] = [
      { kind: "modify", path: "docs/notes.md", bytes: 12 } as EffectRecord,
    ];
    const context = {
      agentId: KNOWN,
      contentOf: async () => "a harmless line\n",
      addedLinesOf: async () => "a harmless line\n",
      realContentOf: async () => null,
      recentTouches: [],
      protectedPaths: [],
      protectedInodes: new Set<string>(),
      caseInsensitiveHost: false,
      platformSecrets: [],
      registryAllowlist: [],
    } as never;

    const contentOnly = await defaultPolicy(effects, context);
    const composed = await withCapabilityGrantRule(store, defaultPolicy)(effects, context);

    // ordinary content, so the content rules alone are happy with it
    expect(contentOnly.decision).toBe("commit");
    // but this agent was never granted docs/, and authorization is asked first
    expect(composed.decision).toBe("review");
  });

  it("answers the operator grant routes through the app the server builds, and shares one store with the runner", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "grant-routes-"));
    try {
      const config = loadConfig({ NODE_ENV: "test", APP_DATA_DIR: dir });
      const app = await createApp(config, service);

      const missing = await app.inject({
        method: "GET",
        url: `/api/agents/${UNKNOWN}/capability-grant`,
        headers: { "x-shadow-commit": "1" },
      });
      expect(missing.statusCode).toBe(404);

      const issued = await app.inject({
        method: "PUT",
        url: `/api/agents/${KNOWN}/capability-grant`,
        headers: { "content-type": "application/json", "x-shadow-commit": "1" },
        payload: JSON.stringify({ allowedPathGlobs: ["src/**"], allowedDestinations: ["*"], budget: 5 }),
      });
      expect(issued.statusCode).toBe(200);

      // the runner reads its grants from capabilityGrantStoreFor(dataDirectory); if the API held a
      // second store over the same file, a revoke would not reach the policy until a restart
      const runnerSideStore = capabilityGrantStoreFor(config.dataDirectory);
      const seenByRunner = await runnerSideStore.get(KNOWN);
      expect(seenByRunner?.allowedPathGlobs).toEqual(["src/**"]);

      await app.close();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});

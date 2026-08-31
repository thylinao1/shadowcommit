import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { capabilityGrantStoreFor } from "./capability-grants.js";
import type { AgentService } from "./agent-service.js";

/**
 * One principal for the whole control plane, and the caller never gets to name it.
 *
 * app.ts states the rule in `operatorPrincipal`: "Never the `x-actor` header. That header is a
 * value the caller types, so an agent that reached the control plane, or a page that forged a
 * request, could approve its own turn as a named human and the hash chain would faithfully attest
 * a sign-off that never happened". The review routes obeyed it. The capability-grant routes,
 * registered on the same instance and covered by the same hooks, still read `x-actor` off the
 * request and wrote it into the stored grant as `issuedBy`, so the record named whoever asked.
 *
 * A capability grant is the document that says which paths and which destinations a turn may touch.
 * A forged name on it is the same defect as a forged name on an approval: the store is durable and
 * an operator reading it later has no way to tell the two apart.
 */

const AGENT = "11111111-1111-4111-8111-111111111111";
const PANEL_MUTATION = { "content-type": "application/json", "x-shadow-commit": "1" } as const;
const FIXTURE_TOKEN = "FIXTURE-KEY-NOT-REAL-operator-principal-actor";
const GRANT = { allowedPathGlobs: ["src/**"], allowedDestinations: ["*"], budget: 5 };

const service = {
  listAgents: () => [{ id: AGENT, name: "cataloguer" }],
  getAgent: (id: string) => ({ id, name: "cataloguer" }),
  systemInfo: async () => ({ platform: "test" }),
} as unknown as AgentService;

/** Each test gets its own data directory: capabilityGrantStoreFor memoises one store per path. */
async function withApp(
  env: Record<string, string>,
  body: (app: Awaited<ReturnType<typeof createApp>>, dataDirectory: string) => Promise<void>,
): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "operator-principal-"));
  const config = loadConfig({ NODE_ENV: "test", APP_DATA_DIR: dir, ...env });
  const app = await createApp(config, service);
  try {
    await body(app, config.dataDirectory);
  } finally {
    await app.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
}

describe("the grant store records the principal the server authenticated", () => {
  it("ignores x-actor on an issue, exactly as the review routes do", async () => {
    await withApp({}, async (app, dataDirectory) => {
      const issued = await app.inject({
        method: "PUT",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: { ...PANEL_MUTATION, "x-actor": "maksim@example.com" },
        payload: JSON.stringify(GRANT),
      });

      expect(issued.statusCode).toBe(200);
      expect(issued.json().grant.issuedBy).toBe("operator");
      // the durable record is the one that matters: the response could be right and the file wrong
      const stored = await capabilityGrantStoreFor(dataDirectory).get(AGENT);
      expect(stored?.issuedBy).toBe("operator");
    });
  });

  it("ignores x-actor on a revoke as well, so the last word on a grant is not caller-typed", async () => {
    await withApp({}, async (app) => {
      await app.inject({
        method: "PUT",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: PANEL_MUTATION,
        payload: JSON.stringify(GRANT),
      });
      const revoked = await app.inject({
        method: "DELETE",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: { "x-shadow-commit": "1", "x-actor": "maksim@example.com" },
      });

      expect(revoked.statusCode).toBe(200);
      // revoke writes its own actor field, so this is a second place a typed name could land
      expect(revoked.json().grant).toMatchObject({ status: "revoked", revokedBy: "operator" });
    });
  });

  it("names the token that was presented, not the name the caller typed beside it", async () => {
    await withApp({ APP_AUTH_TOKEN: FIXTURE_TOKEN }, async (app) => {
      const expected =
        "operator:" + createHash("sha256").update(FIXTURE_TOKEN).digest("hex").slice(0, 12);
      const issued = await app.inject({
        method: "PUT",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: {
          ...PANEL_MUTATION,
          authorization: `Bearer ${FIXTURE_TOKEN}`,
          "x-actor": "operator",
        },
        payload: JSON.stringify(GRANT),
      });

      expect(issued.statusCode).toBe(200);
      expect(issued.json().grant.issuedBy).toBe(expected);
    });
  });

  it("still issues, reads and revokes for an operator who sends no x-actor at all", async () => {
    await withApp({}, async (app) => {
      const issued = await app.inject({
        method: "PUT",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: PANEL_MUTATION,
        payload: JSON.stringify(GRANT),
      });
      expect(issued.statusCode).toBe(200);
      expect(issued.json().grant).toMatchObject({
        agentId: AGENT,
        allowedPathGlobs: ["src/**"],
        status: "active",
        revision: 1,
        issuedBy: "operator",
      });

      const read = await app.inject({
        method: "GET",
        url: `/api/agents/${AGENT}/capability-grant`,
      });
      expect(read.statusCode).toBe(200);
      expect(read.json().grant).toMatchObject({ status: "active", allowedDestinations: ["*"] });

      const revoked = await app.inject({
        method: "DELETE",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: { "x-shadow-commit": "1" },
      });
      expect(revoked.statusCode).toBe(200);
      expect(revoked.json().grant).toMatchObject({ status: "revoked", revision: 2 });
    });
  });

  it("is not escaped by the spelling of the header, which HTTP does not treat as significant", async () => {
    await withApp({}, async (app) => {
      const issued = await app.inject({
        method: "PUT",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: { ...PANEL_MUTATION, "X-ACTOR": "maksim@example.com" },
        payload: JSON.stringify(GRANT),
      });

      expect(issued.statusCode).toBe(200);
      expect(issued.json().grant.issuedBy).toBe("operator");
    });
  });

  it("says so in SECURITY.md, including what a shared token makes the name worth", async () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
    const text = await fs.readFile(path.join(repoRoot, "SECURITY.md"), "utf8");
    expect(text).toContain("x-actor");
    expect(text).toContain("never a name the caller typed");
    // the honest half: one shared token is one principal, so the record cannot separate two humans
    expect(text).toContain("cannot tell");
  });
});

/**
 * What naming the principal does NOT decide, pinned so a change of mind is a change to this test.
 *
 * The grant routes sit on the "control" tier, so on an unconfined host they admit a bare loopback
 * caller while the review routes refuse one. A capability grant widens what a turn may touch
 * without a human looking (capability-grant-rule.ts asks authorization first and returns "review"
 * for anything outside the grant), so a local agent on such a host that reaches loopback can widen
 * its own. The record now says `operator` rather than a name that agent chose, which is the half
 * this lane fixed; the other half is the same accepted limitation SECURITY.md states for the
 * unconfined runtime, because a turn there has no filesystem jail and the grant store is a file in
 * the data directory it can already write. An operator who needs that boundary runs a container,
 * where this caller is off box and refused outright, or sets APP_AUTH_TOKEN.
 */
describe("the tier the grant routes sit on is unchanged", () => {
  const UNCONFINED = { RUNTIME_PROVIDER: "local-process", SHADOW_ALLOW_UNCONFINED: "1" };

  it("admits bare loopback on an unconfined host, where a review refuses it", async () => {
    await withApp(UNCONFINED, async (app) => {
      const settling = await app.inject({ method: "GET", url: "/api/reviews" });
      expect(settling.statusCode).toBe(403);
      expect(settling.json().error).toContain("shares the host network");

      const issued = await app.inject({
        method: "PUT",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: PANEL_MUTATION,
        payload: JSON.stringify(GRANT),
      });
      expect(issued.statusCode).toBe(200);
      expect(issued.json().grant.issuedBy).toBe("operator");
    });
  });

  it("refuses the same caller outright under the container default", async () => {
    await withApp({}, async (app) => {
      const issued = await app.inject({
        method: "PUT",
        url: `/api/agents/${AGENT}/capability-grant`,
        headers: PANEL_MUTATION,
        remoteAddress: "172.17.0.1",
        payload: JSON.stringify(GRANT),
      });
      expect(issued.statusCode).toBe(403);
    });
  });
});

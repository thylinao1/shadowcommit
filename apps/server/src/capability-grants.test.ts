import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  effectiveCapabilityGrant,
  FileCapabilityGrantStore,
  MemoryCapabilityGrantStore,
} from "./capability-grants.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("capability grant storage", () => {
  it("uses a workspace-wide compatibility grant until an operator narrows it", async () => {
    const grant = await effectiveCapabilityGrant(new MemoryCapabilityGrantStore(), "agent-1");
    expect(grant).toMatchObject({
      agentId: "agent-1",
      allowedPathGlobs: ["**"],
      allowedDestinations: ["*"],
      source: "default",
      status: "active",
    });
  });

  it("persists only explicit authorization fields and a revocation tombstone", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "capability-grants-"));
    temporaryDirectories.push(root);
    const file = path.join(root, "grants.json");
    const store = new FileCapabilityGrantStore(file);
    expect(await store.get("toString")).toBeNull();
    await store.issue(
      "agent-1",
      {
        allowedPathGlobs: ["src/**"],
        allowedDestinations: ["api.example.test:443"],
        budget: 3,
        credential: "FIXTURE-KEY-NOT-REAL",
      } as never,
      "operator-2",
    );
    await store.revoke("agent-1", "operator-2");

    const reopened = new FileCapabilityGrantStore(file);
    await reopened.initialize();
    expect(await reopened.get("agent-1")).toMatchObject({
      status: "revoked",
      revision: 2,
      revokedBy: "operator-2",
    });
    expect(await readFile(file, "utf8")).not.toContain("FIXTURE-KEY-NOT-REAL");
    expect(await readFile(file, "utf8")).not.toContain("credential");
  });
});

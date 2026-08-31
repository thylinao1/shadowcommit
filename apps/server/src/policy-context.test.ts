import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { identityKey, resolveLimits, snapshotStats } from "./capture.js";
import {
  DEFAULT_PROTECTED_PATHS,
  buildPolicyContext,
  probeCaseInsensitive,
  readDeclaredProtectedPaths,
  recentTouchesFor,
} from "./policy-context.js";

/**
 * A workspace with a sealed copy beside it, shaped the way a turn leaves them: the real side is the
 * pre-turn state, the copy is what the turn produced.
 */
async function withTurn<T>(
  seed: (real: string) => Promise<void>,
  act: (shadow: string) => Promise<void>,
  fn: (ctx: {
    real: string;
    shadowDir: string;
    journalPath: string;
    context: Awaited<ReturnType<typeof buildPolicyContext>>;
  }) => Promise<T>,
): Promise<T> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "context-"));
  const real = path.join(root, "ws");
  const shadowDir = path.join(root, "shadow");
  const merged = path.join(shadowDir, "merged");
  await fs.mkdir(merged, { recursive: true });
  await fs.mkdir(real, { recursive: true });
  await seed(real);
  await fs.cp(real, merged, { recursive: true });
  await act(merged);
  const journalPath = path.join(root, "j.jsonl");
  try {
    const context = await buildPolicyContext({
      shadowDir,
      mechanism: "copy",
      workspacePath: real,
      journalPath,
      agentId: "a1",
      limits: resolveLimits({ maxScanBytes: 4096 }),
      platformSecrets: ["sk-platform-key-value", ""],
      registryAllowlist: ["registry.npmjs.org"],
      realInodes: (await snapshotStats(real)).inodes,
    });
    return await fn({ real, shadowDir, journalPath, context });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

describe("what the policy is allowed to read", () => {
  it("gives the lines this turn added, not the whole file it edited", async () => {
    await withTurn(
      async (real) => {
        await fs.writeFile(path.join(real, "app.js"), "const a = 1\nconst b = 2\n");
      },
      async (shadow) => {
        await fs.writeFile(path.join(shadow, "app.js"), "const a = 1\nconst b = 2\nbackdoor()\n");
      },
      async ({ context }) => {
        // only the line the turn added, so a pre-existing example credential further up the file
        // is not read as something this turn wrote
        await expect(context.addedLinesOf("app.js")).resolves.toBe("backdoor()");
        await expect(context.contentOf("app.js")).resolves.toContain("const a = 1");
        await expect(context.realContentOf("app.js")).resolves.toBe("const a = 1\nconst b = 2\n");
      },
    );
  });

  it("treats the whole body of a created file as added", async () => {
    await withTurn(
      async () => undefined,
      async (shadow) => {
        await fs.writeFile(path.join(shadow, "new.js"), "line one\nline two\n");
      },
      async ({ context }) => {
        await expect(context.addedLinesOf("new.js")).resolves.toBe("line one\nline two\n");
        await expect(context.realContentOf("new.js")).resolves.toBeNull();
      },
    );
  });

  it("bounds every read, so a file bigger than memory cannot be handed to a rule", async () => {
    await withTurn(
      async () => undefined,
      async (shadow) => {
        await fs.writeFile(path.join(shadow, "big.txt"), "y".repeat(50_000));
      },
      async ({ context }) => {
        await expect(context.contentOf("big.txt")).resolves.toHaveLength(4096);
      },
    );
  });

  it("returns empty rather than throwing for a path that is not in the shadow", async () => {
    await withTurn(
      async () => undefined,
      async () => undefined,
      async ({ context }) => {
        await expect(context.contentOf("nope.js")).resolves.toBe("");
        await expect(context.addedLinesOf("nope.js")).resolves.toBe("");
      },
    );
  });

  it("carries the platform's own secrets and the registry allowlist", async () => {
    await withTurn(
      async () => undefined,
      async () => undefined,
      async ({ context }) => {
        // the empty entry is dropped, because "" matches everything
        expect(context.platformSecrets).toEqual(["sk-platform-key-value"]);
        expect(context.registryAllowlist).toContain("registry.npmjs.org");
      },
    );
  });
});

describe("what counts as protected", () => {
  it("matches the aliases the case-sensitive rules missed", () => {
    const matches = (p: string): boolean => DEFAULT_PROTECTED_PATHS.some((rule) => rule.test(p));
    // canonical spellings, as capture produces them
    expect(matches("customers.jsonl")).toBe(true);
    expect(matches("data/customers.jsonl")).toBe(true);
    expect(matches(".env")).toBe(true);
    expect(matches(".env.local")).toBe(true);
    expect(matches(".env.production")).toBe(true);
    expect(matches("secrets/prod.key")).toBe(true);
    expect(matches("config/secret/prod.key")).toBe(true);
    expect(matches(".shadow-commit/protected.json")).toBe(true);
  });

  it("leaves ordinary work alone", () => {
    const matches = (p: string): boolean => DEFAULT_PROTECTED_PATHS.some((rule) => rule.test(p));
    expect(matches("src/secretsutil.ts")).toBe(false);
    expect(matches("docs/env.md")).toBe(false);
    expect(matches(".environment")).toBe(false);
    expect(matches("src/customers.ts")).toBe(false);
  });

  it("adds what the workspace itself declares, and skips a pattern that does not compile", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "declared-"));
    await fs.mkdir(path.join(root, ".shadow-commit"), { recursive: true });
    await fs.writeFile(
      path.join(root, ".shadow-commit", "protected.json"),
      JSON.stringify({ paths: ["(^|/)prod\\.key$", "([unclosed", "(^|/)billing/"] }),
    );
    const declared = await readDeclaredProtectedPaths(root);
    expect(declared).toHaveLength(2);
    expect(declared.some((rule) => rule.test("config/prod.key"))).toBe(true);
    expect(declared.some((rule) => rule.test("billing/ledger.csv"))).toBe(true);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("is empty, not fatal, when the workspace declares nothing or declares nonsense", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "declared2-"));
    await expect(readDeclaredProtectedPaths(root)).resolves.toEqual([]);
    await fs.mkdir(path.join(root, ".shadow-commit"), { recursive: true });
    await fs.writeFile(path.join(root, ".shadow-commit", "protected.json"), "{ not json");
    await expect(readDeclaredProtectedPaths(root)).resolves.toEqual([]);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("knows a protected asset by its inode as well as by its name", async () => {
    await withTurn(
      async (real) => {
        await fs.writeFile(path.join(real, "customers.jsonl"), "{}\n");
        await fs.writeFile(path.join(real, "app.js"), "1\n");
      },
      async () => undefined,
      async ({ real, context }) => {
        // identityKey rather than a hand-built `dev:ino`: a plain lstat rounds a 64 bit NTFS file
        // id, so the expected value would be the lossy form this key exists to avoid.
        expect(context.protectedInodes.has(await identityKey(path.join(real, "customers.jsonl")))).toBe(true);
        expect(context.protectedInodes.has(await identityKey(path.join(real, "app.js")))).toBe(false);
      },
    );
  });
});

describe("the cumulative footprint of one agent", () => {
  const record = (fields: Record<string, unknown>): string => JSON.stringify(fields);

  it("collects the paths this agent committed and ignores another agent's", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "recent-"));
    const journal = path.join(root, "j.jsonl");
    const now = Date.now();
    await fs.writeFile(
      journal,
      [
        record({ kind: "turn.committing", agentId: "a1", at: new Date(now - 1000).toISOString(), effects: [{ path: "one.js" }] }),
        record({ kind: "turn.committing", agentId: "a2", at: new Date(now - 1000).toISOString(), effects: [{ path: "other.js" }] }),
        record({ kind: "turn.committing", agentId: "a1", at: new Date(now - 2000).toISOString(), effects: [{ path: "two.js" }] }),
        record({ kind: "turn.discarded", agentId: "a1", at: new Date(now).toISOString(), effects: [{ path: "never.js" }] }),
      ].join("\n") + "\n",
    );
    const touches = await recentTouchesFor(journal, "a1", now);
    expect(touches.sort()).toEqual(["one.js", "two.js"]);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("forgets a turn that is outside the window", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "recent2-"));
    const journal = path.join(root, "j.jsonl");
    const now = Date.now();
    const old = new Date(now - 48 * 60 * 60 * 1000).toISOString();
    await fs.writeFile(
      journal,
      [
        record({ kind: "turn.committing", agentId: "a1", at: old, effects: [{ path: "ancient.js" }] }),
        record({ kind: "turn.committing", agentId: "a1", at: new Date(now).toISOString(), effects: [{ path: "fresh.js" }] }),
      ].join("\n") + "\n",
    );
    await expect(recentTouchesFor(journal, "a1", now)).resolves.toEqual(["fresh.js"]);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("survives a torn journal line", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "recent3-"));
    const journal = path.join(root, "j.jsonl");
    const now = Date.now();
    await fs.writeFile(
      journal,
      record({ kind: "turn.committing", agentId: "a1", at: new Date(now).toISOString(), effects: [{ path: "fresh.js" }] }) +
        '\n{"kind":"turn.committing","agentId":"a1"',
    );
    await expect(recentTouchesFor(journal, "a1", now)).resolves.toEqual(["fresh.js"]);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("is empty when there is no journal yet", async () => {
    await expect(recentTouchesFor(path.join(os.tmpdir(), "no-such-journal.jsonl"), "a1")).resolves.toEqual([]);
  });
});

describe("case insensitivity is measured, not assumed", () => {
  it("agrees with what the filesystem actually does", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "case-"));
    await fs.writeFile(path.join(root, "customers.jsonl"), "{}\n");
    const probed = await probeCaseInsensitive(root);
    const observed = await fs
      .stat(path.join(root, "Customers.jsonl"))
      .then(() => true)
      .catch(() => false);
    expect(probed).toBe(observed);
    await fs.rm(root, { recursive: true, force: true });
  });

  it("leaves nothing behind in the workspace it probed", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "case2-"));
    await probeCaseInsensitive(root);
    await expect(fs.readdir(root)).resolves.toEqual([]);
    await fs.rm(root, { recursive: true, force: true });
  });
});

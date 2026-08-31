import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  agentTestEditHits,
  buildImmutableOracleArgs,
  digestEffectSet,
  ImmutableTestOracle,
  type ImmutableOracleOptions,
} from "./immutable-oracle.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

const options: ImmutableOracleOptions = {
  engine: "docker",
  image: "volc-agent-runtime:local",
  trustedTestsPath: "/host/trusted",
  command: ["node", "/trusted-tests/probe.mjs"],
};

describe("immutable oracle container contract", () => {
  it("uses a second credential-less, network-less, read-only container", () => {
    const args = buildImmutableOracleArgs(options, {
      containerName: "oracle-test",
      workspacePath: "/host/shadow",
      trustedTestsPath: "/host/trusted",
    });
    expect(args).toContain("none");
    expect(args).toContain("--read-only");
    expect(args).toContain("never");
    expect(args).toContain("ALL");
    expect(args).toContain("type=bind,src=/host/shadow,dst=/workspace,readonly");
    expect(args).toContain("type=bind,src=/host/trusted,dst=/trusted-tests,readonly");
    expect(args.filter((item) => item === "--env")).toHaveLength(2);
    expect(args.join(" ")).not.toMatch(/ARK|AWS|TOKEN|SECRET|CREDENTIAL/i);
    expect(args.join(" ")).not.toMatch(/(?:docker|podman|containerd)\.sock/i);
  });

  it("binds the same normalized effect set independent of capture order", () => {
    const left = { kind: "modify" as const, path: "src/a.ts", sha256: "a".repeat(64) };
    const right = { kind: "delete" as const, path: "src/b.ts" };
    expect(digestEffectSet([left, right])).toBe(digestEffectSet([right, left]));
    expect(digestEffectSet([left])).not.toBe(digestEffectSet([right]));
  });

  it("treats agent-authored test edits as review signals", () => {
    expect(
      agentTestEditHits([
        { kind: "modify", path: "src/index.ts" },
        { kind: "delete", path: "tests/security.test.ts" },
        { kind: "modify", path: "vitest.config.ts" },
      ]),
    ).toEqual([
      expect.objectContaining({ path: "tests/security.test.ts", decision: "review" }),
      expect.objectContaining({ path: "vitest.config.ts", decision: "review" }),
    ]);
  });

  it("rejects trusted tests nested inside the agent-writable tree", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "oracle-overlap-"));
    temporaryDirectories.push(root);
    const workspace = path.join(root, "workspace");
    const trusted = path.join(workspace, "tests");
    await mkdir(trusted, { recursive: true });
    const oracle = new ImmutableTestOracle({ ...options, trustedTestsPath: trusted });
    await expect(
      oracle.run({
        runId: "overlap",
        shadowWorkspacePath: workspace,
        sealedEffectDigest: "a".repeat(64),
      }),
    ).rejects.toThrow("outside the agent-writable workspace");
  });
});

const dockerIt = process.env.RUN_DOCKER_ORACLE_TESTS === "1" ? it : it.skip;

describe("immutable oracle real container", () => {
  dockerIt("runs trusted tests against shadow code with all escape channels denied", async () => {
    // Colima shares the host's user tree, not macOS's private /var/folders temporary tree.
    const serverRoot = fileURLToPath(new URL("../", import.meta.url));
    const root = await mkdtemp(path.join(serverRoot, ".oracle-docker-"));
    temporaryDirectories.push(root);
    const workspace = path.join(root, "shadow");
    await mkdir(workspace);
    await writeFile(path.join(workspace, "oracle-target.json"), '{"ok":true}\n');
    const trustedTestsPath = fileURLToPath(new URL("../trusted-oracle", import.meta.url));
    const oracle = new ImmutableTestOracle({ ...options, trustedTestsPath });
    const result = await oracle.run({
      runId: "docker-proof",
      shadowWorkspacePath: workspace,
      sealedEffectDigest: digestEffectSet([
        { kind: "modify", path: "oracle-target.json" },
      ]),
    });
    expect(result).toMatchObject({
      status: "passed",
      reason: "trusted tests passed",
      exitCode: 0,
      sealedEffectDigest: digestEffectSet([
        { kind: "modify", path: "oracle-target.json" },
      ]),
    });
    expect(result.imageId).toMatch(/^sha256:/);
    expect(result.trustedTestsDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(result.workspaceDigest).toMatch(/^[a-f0-9]{64}$/);
  });

  dockerIt("fails closed when the trusted functional assertion rejects shadow code", async () => {
    const serverRoot = fileURLToPath(new URL("../", import.meta.url));
    const root = await mkdtemp(path.join(serverRoot, ".oracle-docker-fail-"));
    temporaryDirectories.push(root);
    const workspace = path.join(root, "shadow");
    await mkdir(workspace);
    await writeFile(path.join(workspace, "oracle-target.json"), '{"ok":false}\n');
    const trustedTestsPath = fileURLToPath(new URL("../trusted-oracle", import.meta.url));
    const result = await new ImmutableTestOracle({ ...options, trustedTestsPath }).run({
      runId: "docker-negative-proof",
      shadowWorkspacePath: workspace,
      sealedEffectDigest: digestEffectSet([
        { kind: "modify", path: "oracle-target.json" },
      ]),
    });
    expect(result).toMatchObject({
      status: "failed",
      reason: "trusted tests exited with code 1",
      exitCode: 1,
    });
  });
});

import { compareByCodeUnit, sortByNameForDigest } from "./stable-order.js";
import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { lstat, readFile, readdir, readlink, realpath } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type { EffectRecord, RuleHit } from "./policy-types.js";

const execFileAsync = promisify(execFile);
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;

export interface ImmutableOracleOptions {
  engine: string;
  image: string;
  /** Trusted host path outside the agent workspace. Mounted read-only at /trusted-tests. */
  trustedTestsPath: string;
  /** Fixed trusted command. The first item becomes the container entry point. */
  command: readonly [string, ...string[]];
  timeoutMs?: number;
  maxOutputBytes?: number;
  cpuLimit?: number;
  memoryLimit?: string;
  pidsLimit?: number;
  user?: string;
}

export interface ImmutableOracleRequest {
  runId: string;
  shadowWorkspacePath: string;
  /** Digest of the normalized, sealed effect set evaluated by policy. */
  sealedEffectDigest: string;
}

export type ImmutableOracleStatus = "passed" | "failed" | "infrastructure-error";

export interface ImmutableOracleResult {
  runId: string;
  sealedEffectDigest: string;
  status: ImmutableOracleStatus;
  reason: string;
  exitCode: number | null;
  imageId: string;
  trustedTestsDigest: string;
  workspaceDigest: string;
  stdoutDigest: string;
  stderrDigest: string;
  stdoutBytes: number;
  stderrBytes: number;
  durationMs: number;
}

export interface OracleContainerInput {
  containerName: string;
  workspacePath: string;
  trustedTestsPath: string;
}

function safeContainerPart(value: string): string {
  const rendered = value.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 48);
  return rendered || "run";
}

function assertOptions(options: ImmutableOracleOptions): void {
  if (!options.engine.trim()) throw new TypeError("oracle container engine is required");
  if (!options.image.trim()) throw new TypeError("oracle image is required");
  if (!options.command.length || !options.command[0].trim()) {
    throw new TypeError("oracle command is required");
  }
  if ((options.timeoutMs ?? 120_000) < 1_000) throw new TypeError("oracle timeout is too small");
  if ((options.maxOutputBytes ?? 1_048_576) < 1_024) {
    throw new TypeError("oracle output limit is too small");
  }
}

function within(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function hashText(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

async function digestTree(root: string, trusted: boolean): Promise<string> {
  const digest = createHash("sha256");

  const walk = async (directory: string, prefix: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    sortByNameForDigest(entries);
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const stat = await lstat(absolute);
      if (stat.isDirectory()) {
        digest.update(`d\0${relative}\0${stat.mode & 0o777}\0`);
        await walk(absolute, relative);
      } else if (stat.isFile()) {
        const body = await readFile(absolute);
        digest.update(`f\0${relative}\0${stat.mode & 0o777}\0${body.byteLength}\0`);
        digest.update(body);
      } else if (stat.isSymbolicLink() && !trusted) {
        digest.update(`l\0${relative}\0${await readlink(absolute)}\0`);
      } else {
        throw new Error(
          trusted
            ? `trusted oracle tree contains a non-regular entry: ${relative}`
            : `shadow workspace contains an unsupported special entry: ${relative}`,
        );
      }
    }
  };

  await walk(root, "");
  return digest.digest("hex");
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => compareByCodeUnit(left, right))
        .map(([key, item]) => [key, stableValue(item)]),
    );
  }
  return value;
}

/** Stable across capture order so the same sealed effect set has one oracle binding. */
export function digestEffectSet(effects: readonly EffectRecord[]): string {
  const normalized = effects
    .map((effect) => JSON.stringify(stableValue(effect)))
    .sort()
    .join("\n");
  return hashText(normalized);
}

export function buildImmutableOracleArgs(
  options: ImmutableOracleOptions,
  input: OracleContainerInput,
): string[] {
  assertOptions(options);
  const command = [...options.command];
  const entrypoint = command.shift()!;
  return [
    "run",
    "--rm",
    "--init",
    "--name",
    input.containerName,
    "--label",
    "io.shadow-commit.role=immutable-oracle",
    "--pull",
    "never",
    "--network",
    "none",
    "--ipc",
    "none",
    "--read-only",
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--cpus",
    String(options.cpuLimit ?? 1),
    "--memory",
    options.memoryLimit ?? "512m",
    "--pids-limit",
    String(options.pidsLimit ?? 128),
    "--user",
    options.user ?? "65534:65534",
    "--env",
    "HOME=/tmp",
    "--env",
    "NO_COLOR=1",
    "--mount",
    `type=bind,src=${input.workspacePath},dst=/workspace,readonly`,
    "--mount",
    `type=bind,src=${input.trustedTestsPath},dst=/trusted-tests,readonly`,
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,noexec,size=64m",
    "--workdir",
    "/workspace",
    "--entrypoint",
    entrypoint,
    options.image,
    ...command,
  ];
}

function dockerClientEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const name of [
    "PATH",
    "HOME",
    "TMPDIR",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "XDG_CONFIG_HOME",
  ] as const) {
    if (process.env[name] !== undefined) environment[name] = process.env[name];
  }
  return environment;
}

function outputOf(error: unknown, stream: "stdout" | "stderr"): string {
  const value = (error as { stdout?: unknown; stderr?: unknown })[stream];
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  return typeof value === "string" ? value : "";
}

function exitCodeOf(error: unknown): number | null {
  const code = (error as { code?: unknown }).code;
  return typeof code === "number" ? code : null;
}

export class ImmutableTestOracle {
  constructor(private readonly options: ImmutableOracleOptions) {
    assertOptions(options);
  }

  async run(request: ImmutableOracleRequest): Promise<ImmutableOracleResult> {
    if (!DIGEST_PATTERN.test(request.sealedEffectDigest)) {
      throw new TypeError("sealedEffectDigest must be a lowercase SHA-256 digest");
    }
    const started = Date.now();
    const workspacePath = await realpath(request.shadowWorkspacePath);
    const trustedTestsPath = await realpath(this.options.trustedTestsPath);
    if (within(workspacePath, trustedTestsPath) || within(trustedTestsPath, workspacePath)) {
      throw new Error("trusted oracle tests must be outside the agent-writable workspace tree");
    }

    const [workspaceDigestBefore, trustedDigestBefore, imageInspection] = await Promise.all([
      digestTree(workspacePath, false),
      digestTree(trustedTestsPath, true),
      execFileAsync(
        this.options.engine,
        ["image", "inspect", "--format", "{{.Id}}", this.options.image],
        {
          encoding: "utf8",
          timeout: 10_000,
          env: dockerClientEnvironment(),
        },
      ),
    ]);
    const imageId = imageInspection.stdout.trim();
    if (!imageId.startsWith("sha256:")) throw new Error("oracle image did not resolve to an image ID");

    const containerName = `shadow-oracle-${safeContainerPart(request.runId)}-${randomUUID().slice(0, 8)}`;
    const args = buildImmutableOracleArgs(this.options, {
      containerName,
      workspacePath,
      trustedTestsPath,
    });
    let stdout = "";
    let stderr = "";
    let exitCode: number | null = 0;
    let status: ImmutableOracleStatus = "passed";
    let reason = "trusted tests passed";

    try {
      const completed = await execFileAsync(this.options.engine, args, {
        encoding: "utf8",
        timeout: this.options.timeoutMs ?? 120_000,
        maxBuffer: this.options.maxOutputBytes ?? 1_048_576,
        env: dockerClientEnvironment(),
      });
      stdout = completed.stdout;
      stderr = completed.stderr;
    } catch (error) {
      stdout = outputOf(error, "stdout");
      stderr = outputOf(error, "stderr");
      exitCode = exitCodeOf(error);
      if (exitCode !== null && ![125, 126, 127, 137].includes(exitCode)) {
        status = "failed";
        reason = `trusted tests exited with code ${exitCode}`;
      } else {
        status = "infrastructure-error";
        reason = (error as { killed?: boolean }).killed
          ? "oracle container timed out"
          : exitCode === 137
            ? "oracle container exceeded a resource limit"
            : "oracle container could not start or complete";
      }
      await execFileAsync(this.options.engine, ["rm", "--force", containerName], {
        encoding: "utf8",
        timeout: 10_000,
        env: dockerClientEnvironment(),
      }).catch(() => undefined);
    }

    const [workspaceDigestAfter, trustedDigestAfter] = await Promise.all([
      digestTree(workspacePath, false),
      digestTree(trustedTestsPath, true),
    ]);
    if (
      workspaceDigestAfter !== workspaceDigestBefore ||
      trustedDigestAfter !== trustedDigestBefore
    ) {
      status = "infrastructure-error";
      reason = "workspace or trusted tests changed while the oracle ran";
    }

    return {
      runId: request.runId,
      sealedEffectDigest: request.sealedEffectDigest,
      status,
      reason,
      exitCode,
      imageId,
      trustedTestsDigest: hashText(
        JSON.stringify({
          tree: trustedDigestBefore,
          command: this.options.command,
          imageId,
        }),
      ),
      workspaceDigest: workspaceDigestBefore,
      stdoutDigest: hashText(stdout),
      stderrDigest: hashText(stderr),
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      durationMs: Date.now() - started,
    };
  }
}

function isAgentTestPath(effect: EffectRecord): boolean {
  if (effect.effectClass === "test") return true;
  const candidate = effect.path.normalize("NFC").replaceAll("\\", "/").toLowerCase();
  const base = candidate.split("/").at(-1) ?? "";
  return (
    candidate.split("/").some((part) => part === "test" || part === "tests" || part === "__tests__") ||
    /(?:^|\.)(?:test|spec)\.[^.]+$/.test(base) ||
    /^(?:test_.+|.+_test)\.[^.]+$/.test(base) ||
    /^(?:vitest|jest|playwright|cypress)\.config\./.test(base) ||
    base === "pytest.ini" ||
    base === "conftest.py"
  );
}

/** Agent-authored test changes are independent review signals even when trusted tests pass. */
export function agentTestEditHits(effects: readonly EffectRecord[]): RuleHit[] {
  return effects
    .filter(isAgentTestPath)
    .map((effect) => ({
      rule: "agent-test-tree-edited",
      decision: "review" as const,
      path: effect.path,
      detail: "The turn changed an agent-writable test; trusted oracle results remain independent",
    }));
}

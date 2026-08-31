import { execFile, spawn, type ChildProcess } from "node:child_process";
import { promisify } from "node:util";
import type { AppConfig } from "./config.js";
import { buildCodexArgs, parseCodexEventLine, type ParsedEvents } from "./codex-runner.js";
import { RunCancelledError } from "./errors.js";
import type {
  AgentRunner,
  RunUsage,
  RunnerRequest,
  RunnerResult,
} from "./types.js";

const execFileAsync = promisify(execFile);

interface ActiveContainer {
  child: ChildProcess;
  containerName: string;
  cancelled: boolean;
  timedOut: boolean;
  outputExceeded: boolean;
  settled: Promise<void>;
  termination: Promise<void> | null;
}

// The parsed-event shape is NOT redeclared here. It used to be, as a second copy of the same four
// fields, and the copy is how a field could be added to the parser without this runner ever
// carrying it: the two structures agreed by coincidence rather than by construction. It is imported
// from the module that owns parseCodexEventLine, so the compiler enforces that the container path
// and the host path see the same events.

export function containerName(agentId: string, instanceId = "default"): string {
  const safeInstance = instanceId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 32);
  const safeAgent = agentId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 48);
  return "launchpad-" + safeInstance + "-" + safeAgent;
}

/**
 * The container-visible workspace path is a fixed `/workspace` whatever the host path is, and it
 * has to stay that way. A turn that can read a cwd ending in `shadow/<uuid>/merged` knows it is
 * being watched, and a payload that is inert whenever it sees that string commits clean and fires
 * in production instead (SL01). Nothing derived from the shadow root, the run id or the word
 * "merged" reaches the container: not the workdir, not a mount destination, not an environment
 * variable.
 */
export const CONTAINER_WORKSPACE_PATH = "/workspace";
export const CONTAINER_CODEX_HOME_PATH = "/codex-home";

export function buildContainerRunArgs(
  request: RunnerRequest,
  config: AppConfig,
): string[] {
  const name = containerName(request.agentId, config.runtimeInstanceId);
  const engineName = config.containerEngine.split(/[\\/]/).at(-1)?.toLowerCase();
  const confinement = request.confinement;
  // With a sealed network the agent container joins the per-run `--internal` bridge and NOTHING
  // else: no default bridge, so there is no route out for any library, encoding or deleted proxy
  // variable to find. The broker, dual-homed onto both, is the only way anything leaves.
  const network = confinement?.networkName ?? "bridge";
  const codexHome = confinement ? confinement.codexHomePath : config.codexHome;
  const proxyEnv = confinement?.proxyUrl
    ? [
        "--env",
        "HTTP_PROXY=" + confinement.proxyUrl,
        "--env",
        "HTTPS_PROXY=" + confinement.proxyUrl,
        "--env",
        "http_proxy=" + confinement.proxyUrl,
        "--env",
        "https_proxy=" + confinement.proxyUrl,
        "--env",
        "NO_PROXY=" + (confinement.noProxy ?? ""),
        "--env",
        "no_proxy=" + (confinement.noProxy ?? ""),
      ]
    : [];
  // IPv6 off at the interface as well as at the network, so a destination cannot be reached by
  // preferring an AAAA record past a v4-only allowlist.
  const ipv6 = confinement?.networkName ? ["--sysctl", "net.ipv6.conf.all.disable_ipv6=1"] : [];
  return [
    "run",
    "--rm",
    "--init",
    "--name",
    name,
    "--label",
    "io.codejam.launchpad=agent-runtime",
    "--label",
    "io.codejam.agent-id=" + request.agentId,
    "--label",
    "io.codejam.instance-id=" + config.runtimeInstanceId,
    ...(confinement ? ["--label", "io.codejam.run-id=" + confinement.runId] : []),
    ...(engineName === "podman" ? ["--userns", "keep-id"] : []),
    "--network",
    network,
    ...ipv6,
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--cpus",
    String(config.containerCpuLimit),
    "--memory",
    config.containerMemoryLimit,
    "--pids-limit",
    String(config.containerPidsLimit),
    "--user",
    config.containerUser,
    // pass-through form on purpose: the VALUE comes from the environment of the docker CLI
    // process (see childEnvironment), so no credential is ever written into argv. Under
    // confinement that value is a one-turn token and the real provider key stays on the host.
    "--env",
    "ARK_API_KEY",
    ...proxyEnv,
    "--env",
    "CODEX_HOME=" + CONTAINER_CODEX_HOME_PATH,
    "--env",
    "HOME=/tmp",
    "--env",
    "NO_COLOR=1",
    "--mount",
    "type=bind,src=" + request.workspacePath + ",dst=" + CONTAINER_WORKSPACE_PATH,
    "--mount",
    "type=bind,src=" + codexHome + ",dst=" + CONTAINER_CODEX_HOME_PATH,
    "--workdir",
    CONTAINER_WORKSPACE_PATH,
    config.containerRuntimeImage,
    "codex",
    ...buildCodexArgs(request, config.codexSandboxMode, CONTAINER_WORKSPACE_PATH),
  ];
}

export class ContainerCodexRunner implements AgentRunner {
  private readonly active = new Map<string, ActiveContainer>();

  constructor(private readonly config: AppConfig) {}

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync(this.config.containerEngine, ["version"], {
        timeout: 5_000,
        env: this.childEnvironment(),
      });
      await execFileAsync(
        this.config.containerEngine,
        ["image", "inspect", this.config.containerRuntimeImage],
        { timeout: 5_000, env: this.childEnvironment() },
      );
      return true;
    } catch {
      return false;
    }
  }

  async cancel(agentId: string): Promise<boolean> {
    const active = this.active.get(agentId);
    if (!active) return false;

    active.cancelled = true;
    await this.removeContainer(active);
    await active.settled;
    return true;
  }

  private removeContainer(active: ActiveContainer): Promise<void> {
    if (!active.termination) {
      active.termination = execFileAsync(
        this.config.containerEngine,
        ["rm", "--force", active.containerName],
        { timeout: 8_000, env: this.childEnvironment() },
      )
        .then(() => undefined)
        .catch(() => {
          active.child.kill("SIGTERM");
          const forceKill = setTimeout(() => active.child.kill("SIGKILL"), 3_000);
          forceKill.unref();
        });
    }
    return active.termination;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    if (this.active.has(request.agentId)) {
      throw new Error("Agent already has an active Runtime container");
    }

    const child = spawn(
      this.config.containerEngine,
      buildContainerRunArgs(request, this.config),
      {
        cwd: request.workspacePath,
        env: this.childEnvironment(request.confinement?.turnToken ?? undefined),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const settled = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
      child.once("error", () => resolve());
    });
    const active: ActiveContainer = {
      child,
      containerName: containerName(request.agentId, this.config.runtimeInstanceId),
      cancelled: false,
      timedOut: false,
      outputExceeded: false,
      settled,
      termination: null,
    };
    this.active.set(request.agentId, active);

    const parsed: ParsedEvents = {
      messages: [],
      threadId: request.threadId,
      usage: null,
      errors: [],
      commands: [],
    };
    let stdout = "";
    let stderr = "";
    let totalBytes = 0;

    const consume = (chunk: Buffer, target: "stdout" | "stderr") => {
      totalBytes += chunk.byteLength;
      if (totalBytes > this.config.codexMaxOutputBytes) {
        active.outputExceeded = true;
        void this.removeContainer(active);
        return;
      }
      if (target === "stdout") {
        stdout += chunk.toString("utf8");
        const lines = stdout.split(/\r?\n/);
        stdout = lines.pop() ?? "";
        for (const line of lines) parseCodexEventLine(line, parsed);
      } else {
        stderr += chunk.toString("utf8");
        if (stderr.length > 16_384) stderr = stderr.slice(-16_384);
      }
    };

    child.stdout.on("data", (chunk: Buffer) => consume(chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, "stderr"));

    const timeout = setTimeout(() => {
      active.timedOut = true;
      void this.removeContainer(active);
    }, this.config.codexTimeoutMs);
    timeout.unref();

    try {
      const exitCode = await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code ?? 1));
      });
      if (stdout.trim()) parseCodexEventLine(stdout.trim(), parsed);
      if (active.cancelled) throw new RunCancelledError();
      if (active.timedOut) {
        throw new Error("Runtime timed out after " + this.config.codexTimeoutMs + " ms");
      }
      if (active.outputExceeded) {
        throw new Error("Codex output exceeded CODEX_MAX_OUTPUT_BYTES");
      }
      if (exitCode !== 0) {
        const detail = parsed.errors.at(-1) ?? stderr.trim() ?? "No error detail";
        throw new Error(
          this.config.containerEngine +
            " Runtime exited with code " +
            exitCode +
            ": " +
            detail,
        );
      }
      const output = parsed.messages.at(-1)?.trim();
      if (!output) throw new Error("Codex completed without an agent message");
      return { output, threadId: parsed.threadId, usage: parsed.usage, commands: parsed.commands };
    } finally {
      clearTimeout(timeout);
      this.active.delete(request.agentId);
    }
  }

  /**
   * Invariant I1: the real provider key never enters the agent container.
   *
   * Under confinement the pass-through `--env ARK_API_KEY` picks up the one-turn token from here
   * instead, and the model channel is terminated at the broker, which swaps the token for the real
   * key on the trusted side. A turn that reads its own environment, its own process list or its
   * own codex config finds the token and nothing else, and the token is worth exactly one turn
   * against one broker that is deleted when the turn settles.
   */
  private childEnvironment(turnToken?: string | undefined): NodeJS.ProcessEnv {
    const environment: NodeJS.ProcessEnv = {
      // an EMPTY token is not a token: without this the unsealed path would hand the container a
      // blank credential and every model call would 401 with no explanation anywhere
      ARK_API_KEY: turnToken || this.config.arkApiKey,
      NO_COLOR: "1",
    };
    for (const name of [
      "PATH",
      "HOME",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "XDG_RUNTIME_DIR",
    ] as const) {
      if (process.env[name] !== undefined) environment[name] = process.env[name];
    }
    return environment;
  }
}

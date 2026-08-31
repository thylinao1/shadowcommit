import { execFile } from "node:child_process";
import { spawn, type ChildProcess } from "node:child_process";
import { promisify } from "node:util";
import type { AppConfig } from "./config.js";
import { RunCancelledError } from "./errors.js";
import type {
  AgentRunner,
  RunUsage,
  RunnerConfinement,
  RunnerRequest,
  RunnerResult,
} from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * One shell command codex ran during the turn.
 *
 * `failed` is derived rather than taken from one field, because the two carry different things and
 * either can be absent: `status` is codex's own word for how the item ended, and `exitCode` is the
 * process's. A command killed at codex's ten second limit arrives as
 * `{exit_code: 124, status: "failed", aggregated_output: ""}`, which is the case this type exists
 * for. Real captures of all of these are in `test-fixtures/codex-events/`.
 */
export interface CommandExecution {
  /** codex's item id, used to pair the started event with the completed one. */
  id: string;
  command: string;
  aggregatedOutput: string;
  exitCode: number | null;
  status: string | null;
  /** True when the command did not finish cleanly, including the timeout case. */
  failed: boolean;
}

export interface ParsedEvents {
  messages: string[];
  threadId: string | null;
  usage: RunUsage | null;
  errors: string[];
  /**
   * Every command the turn ran. Empty on a turn that ran none.
   *
   * This is the field whose absence was a correctness hole: the runner read only the agent's message
   * and the usage block, so a turn whose command was killed produced the same result as a turn whose
   * command succeeded, and the platform reported it as a clean turn. Worse than a no-op, because a
   * command that writes and is then killed leaves half its work in the workspace, and the effect
   * capture commits that half without anything saying the command did not finish.
   */
  commands: CommandExecution[];
}

export function buildCodexArgs(
  request: RunnerRequest,
  sandboxMode: AppConfig["codexSandboxMode"],
  workspacePath = request.workspacePath,
): string[] {
  const args = [
    "exec",
    "--json",
    "--sandbox",
    sandboxMode,
    "--skip-git-repo-check",
    "-C",
    workspacePath,
  ];
  if (request.threadId) {
    args.push("resume", request.threadId, request.prompt);
  } else {
    args.push(request.prompt);
  }
  return args;
}

/**
 * Statuses that mean the command is fine, or is not finished yet. Everything else means it is not.
 *
 * This is an allowlist of the GOOD words on purpose, and it used to be a denylist of one bad word:
 * `status === "failed" || (exitCode !== null && exitCode !== 0)`. Every stream captured in
 * test-fixtures says "failed", so nothing was reachable, but four captures do not exhaust codex's
 * vocabulary and the failure mode of the old form is silent. A status of `cancelled`, `aborted`,
 * `timed_out` or `killed`, arriving with a null exit code as the ten second kill sometimes does,
 * read as a command that succeeded.
 *
 * `in_progress` is why this cannot simply treat every unknown status as failed: a command still
 * running has no exit code yet, and calling it failed would report a failure on every turn that is
 * still going. So the two safe words are named and anything else terminal is a failure.
 *
 * A null status with a zero or absent exit code is NOT called failed. That is the one place this
 * still trusts silence, and it is deliberate: it is the shape an event carries before codex has
 * decided anything, and inventing a failure there would be worse than missing one.
 */
const HEALTHY_STATUSES = new Set(["completed", "in_progress"]);

export function isFailedCommand(status: string | null, exitCode: number | null): boolean {
  if (exitCode !== null && exitCode !== 0) return true;
  if (status === null) return false;
  return !HEALTHY_STATUSES.has(status);
}

export function parseCodexEventLine(line: string, parsed: ParsedEvents): void {
  let event: Record<string, unknown>;
  try {
    event = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return;
  }

  if (event.type === "thread.started" && typeof event.thread_id === "string") {
    parsed.threadId = event.thread_id;
  }

  // A command emits item.started and then item.completed carrying the SAME item id, so both are read
  // and merged by id. Reading only the completed event would lose a command whose turn was cut off
  // before it ended, which is the shape a cancelled or crashed turn leaves behind.
  if (
    (event.type === "item.started" || event.type === "item.completed") &&
    event.item &&
    typeof event.item === "object"
  ) {
    const item = event.item as Record<string, unknown>;

    if (item.type === "command_execution") {
      const command = typeof item.command === "string" ? item.command : "";
      // Pairing key. codex has carried an id on every stream captured in test-fixtures, so this
      // fallback is defensive, but it was defensive AND WRONG: `anonymous-${commands.length}` gives
      // the started event and the completed event DIFFERENT keys, because the array grew between
      // them. One command then became two rows, the first `failed: false` and the second
      // `failed: true`, so a turn with one killed command reported commands 2 and commandsFailed 1.
      // Keying on the command text pairs them. Two genuinely identical commands in one turn merge
      // into one row under this fallback, which loses a count and never invents a success, and that
      // is the direction to be wrong in.
      const id = typeof item.id === "string" ? item.id : `anonymous:${command}`;
      const exitCode = typeof item.exit_code === "number" ? item.exit_code : null;
      const status = typeof item.status === "string" ? item.status : null;
      const record: CommandExecution = {
        id,
        command,
        aggregatedOutput: typeof item.aggregated_output === "string" ? item.aggregated_output : "",
        exitCode,
        status,
        failed: isFailedCommand(status, exitCode),
      };
      const existing = parsed.commands.findIndex((c) => c.id === id);
      if (existing >= 0) parsed.commands[existing] = record;
      else parsed.commands.push(record);
    }

    if (event.type === "item.completed") {
      if (item.type === "agent_message" && typeof item.text === "string") {
        parsed.messages.push(item.text);
      }
      // An item-level error is a different shape from the top-level {"type":"error"} event below,
      // and every captured stream carries one. It was dropped entirely.
      if (item.type === "error" && typeof item.message === "string") {
        parsed.errors.push(item.message);
      }
    }
  }

  if (event.type === "turn.completed" && event.usage && typeof event.usage === "object") {
    const usage = event.usage as Record<string, unknown>;
    parsed.usage = {
      ...(typeof usage.input_tokens === "number"
        ? { inputTokens: usage.input_tokens }
        : {}),
      ...(typeof usage.cached_input_tokens === "number"
        ? { cachedInputTokens: usage.cached_input_tokens }
        : {}),
      ...(typeof usage.output_tokens === "number"
        ? { outputTokens: usage.output_tokens }
        : {}),
    };
  }

  if (event.type === "error") {
    const message =
      typeof event.message === "string"
        ? event.message
        : typeof event.error === "string"
          ? event.error
          : "Codex reported an unknown error";
    parsed.errors.push(message);
  }
}

export class CodexRunner implements AgentRunner {
  private readonly active = new Map<
    string,
    {
      child: ChildProcess;
      cancelled: boolean;
      timedOut: boolean;
      outputExceeded: boolean;
      settled: Promise<void>;
      forceKillTimer: NodeJS.Timeout | null;
    }
  >();

  constructor(private readonly config: AppConfig) {}

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync(this.config.codexBin, ["--version"], {
        timeout: 5_000,
        env: this.childEnvironment(),
      });
      return true;
    } catch {
      return false;
    }
  }

  async cancel(agentId: string): Promise<boolean> {
    const active = this.active.get(agentId);
    if (!active) {
      return false;
    }
    active.cancelled = true;
    this.terminate(active);
    await active.settled;
    return true;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    if (this.active.has(request.agentId)) {
      throw new Error("Agent already has an active Codex process");
    }

    const args = buildCodexArgs(request, this.config.codexSandboxMode);
    const child = spawn(this.config.codexBin, args, {
      cwd: request.workspacePath,
      env: this.childEnvironment(request.confinement),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const settled = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
      child.once("error", () => resolve());
    });
    const active = {
      child,
      cancelled: false,
      timedOut: false,
      outputExceeded: false,
      settled,
      forceKillTimer: null as NodeJS.Timeout | null,
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
        this.terminate(active);
        return;
      }
      if (target === "stdout") {
        stdout += chunk.toString("utf8");
        const lines = stdout.split(/\r?\n/);
        stdout = lines.pop() ?? "";
        for (const line of lines) {
          parseCodexEventLine(line, parsed);
        }
      } else {
        stderr += chunk.toString("utf8");
        if (stderr.length > 16_384) {
          stderr = stderr.slice(-16_384);
        }
      }
    };

    child.stdout.on("data", (chunk: Buffer) => consume(chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, "stderr"));

    const timeout = setTimeout(() => {
      active.timedOut = true;
      this.terminate(active);
    }, this.config.codexTimeoutMs);
    timeout.unref();

    try {
      const exitCode = await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code ?? 1));
      });
      if (stdout.trim()) {
        parseCodexEventLine(stdout.trim(), parsed);
      }
      if (active.cancelled) {
        throw new RunCancelledError();
      }
      if (active.timedOut) {
        throw new Error("Codex timed out after " + this.config.codexTimeoutMs + " ms");
      }
      if (active.outputExceeded) {
        throw new Error("Codex output exceeded CODEX_MAX_OUTPUT_BYTES");
      }
      if (exitCode !== 0) {
        const detail = parsed.errors.at(-1) ?? stderr.trim() ?? "No error detail";
        throw new Error("Codex exited with code " + exitCode + ": " + detail);
      }
      const output = parsed.messages.at(-1)?.trim();
      if (!output) {
        throw new Error("Codex completed without an agent message");
      }
      // `commands` is carried for the same reason `container-codex-runner.ts` carries it, and it was
      // missing here only because that lane changed the runner it was testing. `RunnerResult` makes
      // the field OPTIONAL on purpose, so its absence means "this runner cannot see commands" and an
      // empty array means "this turn ran none". This runner parses them, at `parseCodexEventLine`,
      // and then returned without them, so every host-path turn journaled the first meaning while
      // the second was true. `transactional-runner.ts` reads `result.commands === undefined` to
      // decide whether to write the command counts at all, so the whole block was silently absent.
      return {
        output,
        threadId: parsed.threadId,
        usage: parsed.usage,
        commands: parsed.commands,
      };
    } finally {
      clearTimeout(timeout);
      if (active.forceKillTimer) clearTimeout(active.forceKillTimer);
      this.active.delete(request.agentId);
    }
  }

  private terminate(active: {
    child: ChildProcess;
    forceKillTimer: NodeJS.Timeout | null;
  }): void {
    if (active.child.exitCode !== null || active.child.signalCode !== null) return;
    active.child.kill("SIGTERM");
    if (!active.forceKillTimer) {
      active.forceKillTimer = setTimeout(() => active.child.kill("SIGKILL"), 3_000);
      active.forceKillTimer.unref();
    }
  }

  /**
   * A host process has a starting directory, not a jail. Under confinement this runner still gets
   * the one-turn token instead of the real key and the sealed codex-home instead of the real one,
   * so the credential and the memory halves hold; the NETWORK half does not, because there is no
   * network namespace here and an agent that deletes the proxy variables simply dials out. That is
   * why the runner factory refuses to wrap this runner unless SHADOW_ALLOW_UNCONFINED=1 is set,
   * and why every turn it does run is journaled as `confinement: "none"`.
   */
  private childEnvironment(confinement?: RunnerConfinement | undefined): NodeJS.ProcessEnv {
    const inheritedNames = [
      "PATH",
      "HOME",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "SSL_CERT_FILE",
      "SSL_CERT_DIR",
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "NO_PROXY",
      "NODE_EXTRA_CA_CERTS",
      "TERM",
    ] as const;
    const environment: NodeJS.ProcessEnv = {
      CODEX_HOME: confinement?.codexHomePath ?? this.config.codexHome,
      ARK_API_KEY: confinement?.turnToken || this.config.arkApiKey,
      NO_COLOR: "1",
    };
    for (const name of inheritedNames) {
      if (process.env[name] !== undefined) environment[name] = process.env[name];
    }
    if (confinement?.proxyUrl) {
      environment.HTTP_PROXY = confinement.proxyUrl;
      environment.HTTPS_PROXY = confinement.proxyUrl;
      environment.NO_PROXY = confinement.noProxy ?? "";
    }
    return environment;
  }
}

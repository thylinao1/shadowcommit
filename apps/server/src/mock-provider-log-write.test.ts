import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

/**
 * The mock provider has to be able to write its own request log, and nothing tested that.
 *
 * `scripts/start-mock-poc.sh` launches the provider with `--cap-drop ALL`, which takes
 * CAP_DAC_OVERRIDE away from the container's root. On a host whose bind mounts carry real uids --
 * Linux, not a Docker Desktop or Colima VM -- that root cannot append to the `provider.jsonl` the
 * script just created as the invoking user. The provider still starts, still answers 200, and
 * `record()` swallowed the EACCES, so the run's only symptom was an empty log: the demo driver's
 * beat-3 provenance assertion, three beats later, was the one thing that could see it. Same shape
 * as a broker defect found on a Linux host review -- two correct decisions, fatal only
 * together, invisible on the machine most of this was written on.
 *
 * Two halves, because the fix has two halves.
 *
 * The first half is which flags the script computes and hands to the engine: shell logic with three
 * branches (rootful, rootless docker, podman) plus an override. It is lifted out of the script and
 * executed in bash against a stand-in engine, rather than pattern-matched, so it runs on every
 * platform. Deleting the `--user` line fails it here, on a mac, in under a second.
 *
 * The second half is whether the container those flags produce can actually write, which only a
 * kernel can answer. It launches the real image with the script's own text, and it is where the
 * revert reproduces as the EACCES itself rather than as a missing argument. It is gated, with a
 * stated reason, on the hosts where it could not tell a fixed launch from a broken one.
 */

const execFileAsync = promisify(execFile);

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const scriptPath = path.join(repoRoot, "scripts", "start-mock-poc.sh");
const providerPath = path.join(repoRoot, "scripts", "mock-provider.mjs");
const IMAGE = "node:22-bookworm-slim";

const script = await fs.readFile(scriptPath, "utf8");

/**
 * Lift a region out of the starter rather than restating it.
 *
 * Restating the flags in the test is the failure this file exists to avoid: a copy passes happily
 * while the script it claims to describe has lost the line. A missing anchor throws, so a rename in
 * the script fails this file loudly instead of quietly testing nothing.
 */
function region(from: string, to: string, endsAfter: boolean): string {
  const start = script.indexOf(from);
  if (start < 0) throw new Error(`scripts/start-mock-poc.sh no longer contains ${JSON.stringify(from)}`);
  const stop = script.indexOf(to, start + from.length);
  if (stop < 0) throw new Error(`scripts/start-mock-poc.sh no longer contains ${JSON.stringify(to)} after it`);
  return script.slice(start, endsAfter ? stop + to.length : stop);
}

/** The whole `provider_user_args=(...)` decision, up to and including the `fi` that closes it. */
const USER_ARGS_BLOCK = region("provider_user_args=()", "\nfi\n", true);
for (const marker of ["MOCK_PROVIDER_USER", "podman", "--userns keep-id", "name=rootless", "id -u"]) {
  if (!USER_ARGS_BLOCK.includes(marker)) {
    throw new Error(`the provider_user_args block in scripts/start-mock-poc.sh no longer mentions ${marker}`);
  }
}

/** The same block plus the launch it feeds, with the trailing `\` and `>/dev/null` trimmed off. */
const LAUNCH_BLOCK = region("provider_user_args=()", "\n  >/dev/null", false).replace(/\\\s*$/, "");
if (!LAUNCH_BLOCK.includes("--cap-drop ALL") || !LAUNCH_BLOCK.includes('"$engine" run --detach')) {
  throw new Error("the provider launch in scripts/start-mock-poc.sh no longer looks like the block this test runs");
}

/** `log()` is called from the rootless branch, so the harness has to supply the script's own. */
const HARNESS = 'log() { printf "[mock-poc] %s\\n" "$*" >&2; }\n';

function bindings(vars: Record<string, string>): string {
  return Object.entries(vars)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join("\n");
}

async function runBash(program: string, env: NodeJS.ProcessEnv, timeout = 120_000) {
  return execFileAsync("bash", ["-c", "set -euo pipefail\n" + HARNESS + program], { env, timeout });
}

/** Env with MOCK_PROVIDER_USER either absent or set (empty string included, which is meaningful). */
function providerEnv(user?: string): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env.MOCK_PROVIDER_USER;
  if (user !== undefined) env.MOCK_PROVIDER_USER = user;
  return env;
}

const temporaryDirectories: string[] = [];
const containers: string[] = [];

afterAll(async () => {
  await Promise.all(
    containers.splice(0).map((name) =>
      execFileAsync("docker", ["rm", "--force", name], { timeout: 60_000 }).catch(() => undefined),
    ),
  );
  await Promise.all(
    temporaryDirectories.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })),
  );
});

/**
 * `os.tmpdir()` is safe here only because half two is gated to a Linux host with a real bind
 * mount. On macOS the engine runs in a VM that does not share `/tmp`, so a state directory made
 * here would mount empty and the log-write cases would fail on the mount rather than on the
 * behaviour they test. If that gate is ever loosened, move this under `$HOME` first.
 */
async function temporaryDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(dir);
  return dir;
}

// ---- half one: the flags the script computes, executed rather than pattern-matched -------------

/** A stand-in engine on disk, so `basename "$engine"` and `"$engine" info` both see what we mean. */
async function stubEngine(name: string, infoOutput: string): Promise<string> {
  const dir = await temporaryDir("mock-provider-engine-");
  const file = path.join(dir, name);
  await fs.writeFile(file, `#!/bin/sh\nif [ "$1" = "info" ]; then printf '%s\\n' ${JSON.stringify(infoOutput)}; fi\nexit 0\n`);
  await fs.chmod(file, 0o755);
  return file;
}

/**
 * A stand-in engine that writes the argv of the `run` it is handed to $ARGV_FILE.
 *
 * The computation and the launch are separate lines in the script, and a `--user` that is computed
 * correctly and then not passed is the same bug with a better alibi. This is how the cases below
 * watch the launch itself without needing a kernel.
 */
async function recordingEngine(name: string, infoOutput: string): Promise<{ bin: string; argvFile: string }> {
  const dir = await temporaryDir("mock-provider-recorder-");
  const bin = path.join(dir, name);
  const argvFile = path.join(dir, "argv");
  await fs.writeFile(
    bin,
    [
      "#!/bin/sh",
      `if [ "$1" = "info" ]; then printf '%s\\n' ${JSON.stringify(infoOutput)}; exit 0; fi`,
      `if [ "$1" = "run" ]; then for a in "$@"; do printf '%s\\n' "$a"; done > "$ARGV_FILE"; fi`,
      "exit 0",
      "",
    ].join("\n"),
  );
  await fs.chmod(bin, 0o755);
  return { bin, argvFile };
}

/** The argv the script's own launch block hands the engine, one element per line. */
async function launchArgv(engine: { bin: string; argvFile: string }, user?: string): Promise<string[]> {
  const program = [
    bindings({
      engine: engine.bin,
      container: "recorded",
      state_dir: "/state-dir-that-is-never-mounted",
      image: IMAGE,
      port: "8398",
      mock_key: "mock-provider-key",
      SHADOW_EGRESS_NETWORK: "bridge",
    }),
    LAUNCH_BLOCK,
  ].join("\n");
  await runBash(program, { ...providerEnv(user), ARGV_FILE: engine.argvFile }, 30_000);
  const recorded = await fs.readFile(engine.argvFile, "utf8");
  return recorded.split("\n").filter(Boolean);
}

/** Whatever `provider_user_args` ends up holding, one element per line. */
async function computeUserArgs(engine: string, user?: string): Promise<string[]> {
  const program = [
    bindings({ engine }),
    USER_ARGS_BLOCK,
    'printf "%s\\n" ${provider_user_args[@]+"${provider_user_args[@]}"}',
  ].join("\n");
  const { stdout } = await runBash(program, providerEnv(user), 30_000);
  return stdout.split("\n").filter(Boolean);
}

// `docker info --format '{{.SecurityOptions}}'` prints a bracketed list. This is the real output of
// the engine on the machine this test was written on; the rootless daemon adds `name=rootless`.
const ROOTFUL_INFO = "[name=apparmor name=seccomp,profile=builtin name=cgroupns]";
const ROOTLESS_INFO = "[name=seccomp,profile=builtin name=rootless name=cgroupns]";

describe("which uid scripts/start-mock-poc.sh gives the provider container", () => {
  it("runs as the invoking user under a rootful engine, which is the whole fix", async () => {
    const engine = await stubEngine("docker", ROOTFUL_INFO);
    const { stdout: uid } = await execFileAsync("id", ["-u"]);
    const { stdout: gid } = await execFileAsync("id", ["-g"]);

    expect(await computeUserArgs(engine)).toEqual(["--user", `${uid.trim()}:${gid.trim()}`]);
  });

  it("passes no --user under rootless docker, where pinning the host uid would lose the mount", async () => {
    // Rootless already maps the container's root to this user, so the bind mount is writable as it
    // stands and `--user <host uid>` would land in the subuid range, which owns nothing. Fixing the
    // rootful case by regressing this one would be the same fix-moves-the-defect trade the rootful
    // case was.
    const engine = await stubEngine("docker", ROOTLESS_INFO);

    expect(await computeUserArgs(engine)).toEqual([]);
  });

  it("pairs the uid with --userns keep-id under podman, as the rest of the kit already does", async () => {
    // Same pairing as scripts/start-local-poc.sh and apps/server/src/container-codex-runner.ts.
    // podman reports rootlessness under a different key than docker does, so it is decided by name
    // here rather than by parsing an output shape this repository cannot check.
    const engine = await stubEngine("podman", "");
    const { stdout: uid } = await execFileAsync("id", ["-u"]);
    const { stdout: gid } = await execFileAsync("id", ["-g"]);

    expect(await computeUserArgs(engine)).toEqual([
      "--user",
      `${uid.trim()}:${gid.trim()}`,
      "--userns",
      "keep-id",
    ]);
  });

  it("takes MOCK_PROVIDER_USER over any of that", async () => {
    const engine = await stubEngine("docker", ROOTFUL_INFO);

    expect(await computeUserArgs(engine, "4242:4243")).toEqual(["--user", "4242:4243"]);
  });

  it("passes no --user when MOCK_PROVIDER_USER is set to the empty string", async () => {
    // The documented escape hatch for a host whose mapping neither branch above gets right.
    const engine = await stubEngine("docker", ROOTFUL_INFO);

    expect(await computeUserArgs(engine, "")).toEqual([]);
  });

  it("hands that uid to the run that actually starts the provider, beside the --cap-drop that needs it", async () => {
    const engine = await recordingEngine("docker", ROOTFUL_INFO);
    const { stdout: uid } = await execFileAsync("id", ["-u"]);
    const { stdout: gid } = await execFileAsync("id", ["-g"]);
    const argv = await launchArgv(engine);

    expect(argv).toContain("--user");
    expect(argv[argv.indexOf("--user") + 1]).toBe(`${uid.trim()}:${gid.trim()}`);
    // the flag that makes the uid load-bearing rather than cosmetic; if this ever goes, the case
    // below stops being a proof of anything
    expect(argv).toContain("--cap-drop");
    expect(argv[argv.indexOf("--cap-drop") + 1]).toBe("ALL");
  });

  it("hands the run no --user at all when the override says so", async () => {
    const engine = await recordingEngine("docker", ROOTFUL_INFO);

    expect(await launchArgv(engine, "")).not.toContain("--user");
  });
});

// ---- half two: whether that container can really write, which only a kernel can answer ---------

interface Gate {
  ok: boolean;
  reason: string;
  rootless: boolean;
}

/**
 * Why this half is gated, and why each gate is a skip rather than a quiet pass.
 *
 * Linux only: on macOS and Windows the engine runs in a VM and the bind mount goes through a
 * sharing layer that hands the container ownership whatever the host mode bits say. The container
 * can write with or without `--user`, so the test would pass against a reverted fix. That is a
 * double that cannot fail, which is worse than no test.
 *
 * Not as root: as root the file is root-owned, and the container is root either way, so both
 * branches write successfully and the test again cannot fail.
 */
async function probe(): Promise<Gate> {
  if (process.platform !== "linux") {
    return {
      ok: false,
      rootless: false,
      reason:
        "not Linux (" + process.platform + "): the engine's VM bind-mount layer grants the " +
        "container write access regardless of the host mode bits, so this would pass against a " +
        "reverted fix rather than catch it",
    };
  }
  if (typeof process.getuid === "function" && process.getuid() === 0) {
    return {
      ok: false,
      rootless: false,
      reason: "running as root: the log file would be root-owned and the container root either way, so both the fixed and the reverted launch would write it",
    };
  }
  let info = "";
  try {
    const { stdout } = await execFileAsync("docker", ["info", "--format", "{{.SecurityOptions}}"], { timeout: 60_000 });
    info = stdout;
  } catch {
    return { ok: false, rootless: false, reason: "`docker info` failed: no engine (start Docker or Colima)" };
  }
  try {
    await execFileAsync("docker", ["image", "inspect", IMAGE], { timeout: 60_000 });
  } catch {
    return { ok: false, rootless: false, reason: "the image " + IMAGE + " is missing; `docker pull " + IMAGE + "`" };
  }
  return { ok: true, rootless: info.includes("name=rootless"), reason: "" };
}

const gate = await probe();
if (!gate.ok) {
  console.warn("[docker-gated] SKIPPING the mock provider's log-write cases: " + gate.reason);
}

/**
 * A state directory shaped exactly the way scripts/start-mock-poc.sh shapes its own: the provider
 * copied in, an empty provider.jsonl at 0644, a playbook. 0755 on the directory itself because
 * mkdtemp makes it 0700 and a capless container root cannot even traverse that, which would fail
 * the reverted case for the wrong reason -- on the module load rather than on the log write.
 */
async function stateDir(): Promise<string> {
  const dir = await temporaryDir("mock-provider-state-");
  await fs.chmod(dir, 0o755);
  await fs.copyFile(providerPath, path.join(dir, "mock-provider.mjs"));
  await fs.chmod(path.join(dir, "mock-provider.mjs"), 0o644);
  await fs.writeFile(path.join(dir, "playbook.json"), '{"entries":[]}\n', { mode: 0o644 });
  await fs.writeFile(path.join(dir, "provider.jsonl"), "", { mode: 0o644 });
  await fs.chmod(path.join(dir, "provider.jsonl"), 0o644);
  return dir;
}

/**
 * The starter's own launch, run for real.
 *
 * `--rm` is dropped so the container survives its own exit and can still be asked for its status
 * and its logs; `--detach` stays, because the provider is a server. Nothing else is substituted:
 * the uid decision and every hardening flag are the script's text, so reverting the `--user` line
 * in the script reverts it here.
 *
 * THE COST OF DROPPING `--rm`, stated because it is a real one. `afterAll` removes what this
 * pushed onto `containers`, so an ordinary run leaves nothing behind. A run killed before
 * `afterAll` (Ctrl+C, a vitest timeout kill, a crashed worker) leaves the container in place, and
 * because the name is `mock-provider-write-<pid>` a later run that happens to draw the same pid
 * fails on "name already in use" rather than on anything it is testing. That is the same hazard
 * class as the `shadow-test-*` leftovers documented elsewhere in this suite. The cure if it bites:
 * `docker rm -f $(docker ps -aq --filter name=mock-provider-write-)`.
 */
async function launch(container: string, state: string, user?: string) {
  containers.push(container);
  const program = [
    bindings({
      engine: "docker",
      container,
      state_dir: state,
      image: IMAGE,
      port: "8398",
      mock_key: "mock-provider-key",
      SHADOW_EGRESS_NETWORK: "bridge",
    }),
    LAUNCH_BLOCK.replace("run --detach --rm --init", "run --detach --init"),
  ].join("\n");
  if (!program.includes("run --detach --init")) throw new Error("the launch line in the script changed shape");
  return runBash(program, providerEnv(user));
}

async function logLines(state: string): Promise<string[]> {
  const text = await fs.readFile(path.join(state, "provider.jsonl"), "utf8").catch(() => "");
  return text.split("\n").filter(Boolean);
}

async function containerOutput(container: string): Promise<string> {
  const { stdout, stderr } = await execFileAsync("docker", ["logs", container], { timeout: 60_000 });
  return stdout + stderr;
}

const gated = gate.ok ? describe : describe.skip;

gated("the provider container appends to the host-owned log it is given", () => {
  it("records a line the host can read back, launched exactly as the starter launches it", async () => {
    const state = await stateDir();
    const container = "mock-provider-write-" + process.pid;
    await launch(container, state);

    let lines: string[] = [];
    for (let attempt = 0; attempt < 100 && lines.length === 0; attempt += 1) {
      lines = await logLines(state);
      if (lines.length === 0) await new Promise((resolve) => setTimeout(resolve, 200));
    }

    const output = await containerOutput(container);
    expect(lines.length, "the provider wrote nothing to " + state + "/provider.jsonl. Its output was:\n" + output)
      .toBeGreaterThan(0);
    expect(JSON.parse(lines[0])).toMatchObject({ event: "mock-provider.start" });
    expect(output, "a provider that cannot log must not report itself ready").toContain("mock-provider.ready");
  }, 180_000);

  /**
   * The revert, performed rather than described.
   *
   * `MOCK_PROVIDER_USER=""` is the documented "pass no --user" value, so this is the launch the
   * script produced before the fix, byte for byte. It has to fail, and it has to say why: if it
   * writes the log anyway then this host cannot tell a fixed launch from a broken one and the case
   * above is proving nothing.
   */
  it.skipIf(gate.rootless)("fails loudly, and writes nothing, when it is not given the host uid", async () => {
    const state = await stateDir();
    const container = "mock-provider-noent-" + process.pid;
    await launch(container, state, "");

    const { stdout: status } = await execFileAsync("docker", ["wait", container], { timeout: 120_000 });
    const output = await containerOutput(container);

    expect(Number(status.trim()), "the provider must not survive a log it cannot write:\n" + output).not.toBe(0);
    expect(output).toContain("EACCES");
    expect(output).toContain("/state/provider.jsonl");
    expect(output, "the message has to name the cause, not just the errno").toContain("CAP_DAC_OVERRIDE");
    expect(output, "and it must never have claimed to be ready").not.toContain("mock-provider.ready");
    expect(await logLines(state)).toEqual([]);
  }, 180_000);
});

if (gate.ok && gate.rootless) {
  console.warn(
    "[docker-gated] SKIPPING the no-uid control: this engine is rootless, so the container's root " +
      "is already this user and dropping --user does not lose the write. That is the case the " +
      "rootless branch above exists for.",
  );
}

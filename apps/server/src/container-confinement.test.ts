import { describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "./config.js";
import {
  CONTAINER_CODEX_HOME_PATH,
  CONTAINER_WORKSPACE_PATH,
  buildContainerRunArgs,
} from "./container-codex-runner.js";
import type { RunnerConfinement, RunnerRequest } from "./types.js";

const REAL_KEY = "sk-real-provider-key-must-never-leave-the-host";
const RUN_ID = "11111111-2222-3333-4444-555555555555";

function config(): AppConfig {
  return loadConfig({
    ARK_API_KEY: REAL_KEY,
    ARK_MODEL: "ep-test",
    CODEX_HOME: "/host/codex-home",
    RUNTIME_PROVIDER: "container",
  });
}

const confinement: RunnerConfinement = {
  runId: RUN_ID,
  networkName: "shadow-" + RUN_ID,
  proxyUrl: "http://broker:3128",
  noProxy: "broker,localhost,127.0.0.1",
  turnToken: "shadow-turn-abcdef",
  codexHomePath: "/host/.data/shadows/" + RUN_ID + "/codex-home/live",
};

const request = (extra: Partial<RunnerRequest> = {}): RunnerRequest => ({
  agentId: "agent-a",
  workspacePath: "/host/.data/shadows/" + RUN_ID + "/merged",
  prompt: "add a test",
  threadId: null,
  ...extra,
});

describe("the agent container, unconfined (the kit's own behaviour, unchanged)", () => {
  it("still joins the default bridge when no confinement is supplied", () => {
    const args = buildContainerRunArgs(request(), config());
    expect(args[args.indexOf("--network") + 1]).toBe("bridge");
    expect(args.some((a) => a.startsWith("HTTP_PROXY"))).toBe(false);
    expect(args).toContain("type=bind,src=/host/codex-home,dst=/codex-home");
  });
});

describe("the agent container with only the memory half sealed", () => {
  // SHADOW_CONFINE_NETWORK=false, or an engine that cannot make an internal network. The turn keeps
  // the runtime's ordinary network and talks to the provider directly, so it needs the REAL key: an
  // earlier version handed it an empty string and a blank proxy variable, and every model call
  // would have failed with a 401 and no explanation anywhere.
  const memoryOnly: RunnerConfinement = {
    runId: RUN_ID,
    networkName: null,
    proxyUrl: null,
    noProxy: null,
    turnToken: null,
    codexHomePath: "/host/.data/shadows/" + RUN_ID + "/codex-home/live",
  };
  const args = buildContainerRunArgs(request({ confinement: memoryOnly }), config());

  it("keeps the ordinary network and sets no proxy variables", () => {
    expect(args[args.indexOf("--network") + 1]).toBe("bridge");
    expect(args.some((a) => a.startsWith("HTTP_PROXY"))).toBe(false);
    expect(args.some((a) => a.startsWith("NO_PROXY"))).toBe(false);
    expect(args).not.toContain("--sysctl");
  });

  it("still mounts the sealed copy of the agent's memory", () => {
    expect(args.join(" ")).toContain("src=" + memoryOnly.codexHomePath);
  });
});

describe("the agent container, sealed", () => {
  const args = buildContainerRunArgs(request({ confinement }), config());
  const joined = args.join(" ");

  it("joins the per-run internal network and NOTHING else", () => {
    // a34 and a35 are gated by nothing today because the kit runs `--network bridge`, which is a
    // full NAT'd route to the internet. There is no allowlist an application can apply that beats
    // simply not having a route.
    expect(args.filter((a) => a === "--network")).toHaveLength(1);
    expect(args[args.indexOf("--network") + 1]).toBe("shadow-" + RUN_ID);
    expect(args).not.toContain("bridge");
  });

  it("disables IPv6 on the interface as well as on the network", () => {
    expect(args[args.indexOf("--sysctl") + 1]).toBe("net.ipv6.conf.all.disable_ipv6=1");
  });

  it("points every proxy variable at the broker", () => {
    for (const name of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]) {
      expect(args).toContain(name + "=http://broker:3128");
    }
    expect(args).toContain("NO_PROXY=broker,localhost,127.0.0.1");
    expect(args).toContain("no_proxy=broker,localhost,127.0.0.1");
  });

  it("mounts the sealed copy of the agent's memory in place of the real directory", () => {
    expect(joined).toContain("dst=" + CONTAINER_CODEX_HOME_PATH);
    expect(joined).toContain("src=" + confinement.codexHomePath);
    // r08 and r09: the shared, real codex-home is not reachable from inside the turn at all
    expect(joined).not.toContain("src=/host/codex-home,");
  });

  it("never writes a credential into argv", () => {
    // Invariant I1 has two halves. This is the first: nothing on the command line is a secret, so
    // `ps` on the host and /proc inside a sibling container both show flags and no values.
    expect(joined).not.toContain(REAL_KEY);
    expect(joined).not.toContain(confinement.turnToken);
    // the pass-through form: `--env ARK_API_KEY` with the value coming from the CLI's environment
    expect(args[args.indexOf("ARK_API_KEY")]).toBe("ARK_API_KEY");
    expect(args[args.indexOf("ARK_API_KEY") - 1]).toBe("--env");
  });

  it("shows the turn a workspace path with no trace of the seal", () => {
    // SL01: a payload that reads its own cwd, sees `shadow/<uuid>/merged` and stays inert until it
    // does not, commits clean and fires in production. The host path is the shadow; the
    // CONTAINER-visible path is /workspace, and nothing derived from the seal reaches the turn.
    const containerFacing = [
      args[args.indexOf("--workdir") + 1] ?? "",
      ...args.filter((a) => a.startsWith("type=bind")).map((m) => m.split("dst=")[1] ?? ""),
      ...args.filter((a, i) => args[i - 1] === "--env"),
    ];
    for (const value of containerFacing) {
      expect(value, value).not.toContain("merged");
      expect(value, value).not.toContain("shadows");
      expect(value, value).not.toContain(RUN_ID);
    }
    expect(args[args.indexOf("--workdir") + 1]).toBe(CONTAINER_WORKSPACE_PATH);
  });

  it("labels the container with the run, so a leaked process can be found and killed", () => {
    expect(args).toContain("io.codejam.run-id=" + RUN_ID);
  });

  it("keeps every hardening flag the kit already had", () => {
    expect(args).toContain("no-new-privileges");
    expect(args).toContain("--cap-drop");
    expect(args).toContain("--pids-limit");
    expect(args).toContain("--rm");
  });
});

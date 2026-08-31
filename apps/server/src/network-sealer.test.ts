import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadConfig, type AppConfig } from "./config.js";
import {
  NetworkSealer,
  brokerCodeDir,
  brokerNameFor,
  buildBrokerRunArgs,
  buildNetworkCreateArgs,
  networkNameFor,
  EGRESS_NETWORK,
} from "./network-sealer.js";
import { BROKER_PATHS } from "./broker.js";

const REAL_KEY = "sk-real-provider-key-must-never-leave-the-host";

interface Call {
  file: string;
  args: string[];
  env: NodeJS.ProcessEnv;
}

function fakeEngine(): { calls: Call[]; exec: (file: string, args: string[], env?: NodeJS.ProcessEnv) => Promise<{ stdout: string }> } {
  const calls: Call[] = [];
  return {
    calls,
    exec: async (file, args, env = {}) => {
      calls.push({ file, args, env });
      if (args[0] === "logs") return { stdout: '{"kind":"broker.ready","proxyPort":3128}\n' };
      return { stdout: "" };
    },
  };
}

describe("the per-run network", () => {
  it("is internal, which is the mechanism that actually removes the route", () => {
    // spike A: "no default route plus one static route" is not expressible in `docker run`.
    // `--internal` produces the same property, and it was measured, not assumed.
    const args = buildNetworkCreateArgs("shadow-abc");
    expect(args).toEqual(["network", "create", "--internal", "--ipv6=false", "shadow-abc"]);
  });

  it("is named per run, because two agents on one internal network can reach each other", () => {
    expect(networkNameFor("11111111-2222-3333-4444-555555555555")).toBe(
      "shadow-11111111-2222-3333-4444-555555555555",
    );
    expect(brokerNameFor("abc")).toBe("shadow-broker-abc");
    // sanitising must not be able to merge two runs onto one network, which spike A measured as
    // mutually reachable; anything the sanitiser changed gets a hash of the original appended
    const a = networkNameFor("run/one");
    const b = networkNameFor("run:one");
    expect(a).not.toBe(b);
    expect(a.startsWith("shadow-runone-")).toBe(true);
    const long = networkNameFor("x".repeat(200));
    expect(long.length).toBeLessThanOrEqual(47);
    expect(long).not.toBe(networkNameFor("x".repeat(201)));
  });
});

describe("the broker container", () => {
  const args = buildBrokerRunArgs({
    networkName: "shadow-run1",
    egressNetwork: EGRESS_NETWORK,
    brokerContainer: "shadow-broker-run1",
    brokerImage: "node:22-bookworm-slim",
    brokerCodeDir: "/host/apps/server/broker",
    configDir: "/host/shadow/run1/net/config",
    logDir: "/host/shadow/run1/net/log",
    pendingDir: "/host/shadow/run1/net/pending",
    protectedDir: "/host/shadow/run1/net/protected",
    runId: "run1",
    agentId: "agent-a",
  });

  it("joins the internal network under the alias the agent dials", () => {
    expect(args).toContain("--network");
    expect(args[args.indexOf("--network") + 1]).toBe("shadow-run1");
    expect(args[args.indexOf("--network-alias") + 1]).toBe("broker");
  });

  it("mounts its own code and configuration read-only", () => {
    const mounts = args.filter((a) => a.startsWith("type=bind"));
    const code = mounts.find((m) => m.includes(BROKER_PATHS.code));
    const config = mounts.find((m) => m.includes("/broker-config"));
    expect(code).toContain("readonly");
    expect(config).toContain("readonly");
    // the log and the held store are the only writable mounts
    expect(mounts.find((m) => m.includes("dst=" + BROKER_PATHS.logDir))).not.toContain("readonly");
    expect(mounts.find((m) => m.includes("dst=" + BROKER_PATHS.pendingDir))).not.toContain("readonly");
  });

  it("takes both credentials by pass-through, so neither is ever in argv", () => {
    // `--env NAME` with no value reads it from the environment of the docker CLI process. `ps`
    // shows the flag and not the secret, which is the whole reason for the form.
    const envFlags = args.filter((a, i) => args[i - 1] === "--env");
    expect(envFlags).toContain("ARK_API_KEY");
    expect(envFlags).toContain("SHADOW_TURN_TOKEN");
    expect(args.join(" ")).not.toContain("=" + REAL_KEY);
    expect(args.some((a) => a.includes("sk-"))).toBe(false);
  });

  it("drops capabilities like the agent container does", () => {
    expect(args).toContain("--cap-drop");
    expect(args).toContain("no-new-privileges");
  });

  it("resolves its code directory from src and from dist alike", () => {
    expect(brokerCodeDir().endsWith(path.join("apps", "server", "broker"))).toBe(true);
  });
});

describe("opening and settling a sealed network", () => {
  let root: string;
  let shadowDir: string;
  let workspace: string;
  let config: AppConfig;
  let engine: ReturnType<typeof fakeEngine>;
  let sealer: NetworkSealer;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-sealer-"));
    shadowDir = path.join(root, "shadow", "run1");
    workspace = path.join(root, "workspace");
    await fs.mkdir(shadowDir, { recursive: true });
    await fs.mkdir(workspace, { recursive: true });
    await fs.writeFile(path.join(workspace, "customers.jsonl"), '{"id":1}\n');
    await fs.writeFile(path.join(workspace, "index.js"), "console.log('hi')\n");
    config = loadConfig({
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: workspace,
      CODEX_HOME: path.join(root, "codex-home"),
      ARK_API_KEY: REAL_KEY,
      ARK_MODEL: "ep-test",
      ARK_BASE_URL: "https://ark.cn-beijing.volces.com/api/v3",
    });
    engine = fakeEngine();
    sealer = new NetworkSealer(config, { exec: engine.exec });
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  /**
   * The broker crashed on every native-Linux host and the suite reported an empty reason.
   *
   * `--cap-drop ALL` takes CAP_DAC_OVERRIDE with it, so uid 0 in the broker container may no longer
   * ignore permission bits, and the launch config is written 0600 owned by the host user running the
   * turn. A capless root could not read `/broker-config/broker.json`: the container exited 1 about a
   * second after every start, with EACCES on stderr.
   *
   * `waitForBroker` polled stdout only, so it saw nothing, waited the full twenty seconds and threw
   * "the egress broker did not become ready: " with nothing after the colon. A diagnosis that
   * excludes the stream the error was on cannot report the error.
   */
  it("reports what the container printed on stderr instead of an empty timeout", async () => {
    const crash = "Error: EACCES: permission denied, open '/broker-config/broker.json'";
    let reads = 0;
    const crashing = new NetworkSealer(config, {
      exec: async (_file, args) => {
        if (args[0] === "logs") {
          reads += 1;
          // The real sequence: the crash is readable while the container exists, and once `--rm`
          // has reaped it the engine only says the container is gone. The reason is available for
          // one moment and the code has to keep it.
          // alive for the first poll, reaped by `--rm` after it
          return reads === 1
            ? { stdout: "", stderr: crash }
            : { stdout: "", stderr: "Error response from daemon: No such container: broker" };
        }
        return { stdout: "" };
      },
    });
    // the reason, not a timeout, and not the tombstone that replaced it
    await expect(
      crashing.open({ runId: "run-eacces", agentId: "agent-a", shadowDir, workspacePath: workspace }),
    ).rejects.toThrow(/EACCES/);
    // and it gave up as soon as the container was gone rather than spending the whole deadline
    expect(reads).toBeLessThan(5);
  });

  it("puts the model provider on the allowlist alongside the registries", () => {
    const list = sealer.allowlistFor();
    expect(list).toContain("registry.npmjs.org:443");
    expect(list).toContain("pypi.org:443");
    expect(list).toContain("ark.cn-beijing.volces.com:443");
    expect(list).not.toContain("1.1.1.1:443");
  });

  it("creates the network, starts the broker, and dual-homes it", async () => {
    const sealed = await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    const commands = engine.calls.map((c) => c.args.slice(0, 3).join(" "));
    expect(commands).toContain("network create --internal");
    expect(commands.some((c) => c.startsWith("run --detach"))).toBe(true);
    // Was `network connect bridge` after the broker was already up. That attach raced the --rm
    // reaper and killed turns, so the broker is dual-homed by `docker run` itself now and there is
    // no connect at all. Asserting its ABSENCE is the point: the old call coming back is the defect.
    expect(commands.some((c) => c.startsWith("network connect"))).toBe(false);
    const runArgs = engine.calls.find((c) => c.args[0] === "run")?.args ?? [];
    const networks = runArgs.filter((a, i) => runArgs[i - 1] === "--network");
    expect(networks).toEqual(["shadow-run1", EGRESS_NETWORK]);
    expect(sealed.proxyUrl).toBe("http://broker:3128");
    expect(sealed.modelBaseUrl).toBe("http://broker:8317/v1");
    expect(sealed.turnToken).toMatch(/^shadow-turn-[0-9a-f]{48}$/);
  });

  it("hands the real provider key to the broker through the environment, never through argv", async () => {
    await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    const runCall = engine.calls.find((c) => c.args[0] === "run");
    expect(runCall?.env.ARK_API_KEY).toBe(REAL_KEY);
    expect(runCall?.args.join(" ")).not.toContain(REAL_KEY);
    expect(runCall?.env.SHADOW_TURN_TOKEN).not.toBe(REAL_KEY);
  });

  it("gives the broker the protected assets to scan for, mode 0600", async () => {
    await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    const copied = path.join(shadowDir, "net", "protected", "customers.jsonl");
    expect(await fs.readFile(copied, "utf8")).toBe('{"id":1}\n');
    expect((await fs.stat(copied)).mode & 0o777).toBe(0o600);
    // only the declared protected assets, not the whole workspace
    expect(await fs.readdir(path.join(shadowDir, "net", "protected"))).toEqual(["customers.jsonl"]);
    const launch = JSON.parse(await fs.readFile(path.join(shadowDir, "net", "config", "broker.json"), "utf8"));
    expect(launch.protectedFiles).toEqual(["/protected/customers.jsonl"]);
    expect(launch).not.toHaveProperty("providerKey");
    expect(JSON.stringify(launch)).not.toContain(REAL_KEY);
  });

  it("turns what the broker held into outbound effects", async () => {
    const sealed = await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    await fs.writeFile(
      path.join(sealed.logDir, "held.jsonl"),
      JSON.stringify({
        effectId: "eff-aa", method: "POST", host: "collector", port: 9100, urlPath: "/ingest",
        bytes: 72, sha256: "abcd", provenance: "customers.jsonl (literal)", secretPattern: null,
      }) + "\n",
    );
    const effects = await sealer.heldEffects(sealed);
    expect(effects).toHaveLength(1);
    expect(effects[0]).toMatchObject({ kind: "outbound", method: "POST", host: "collector", port: 9100 });
  });

  it("replays held writes from inside the broker, so the audited egress point stays the only one", async () => {
    const sealed = await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    engine.calls.length = 0;
    await sealer.replay(sealed, ["eff-aa", "eff-bb"]);
    const exec = engine.calls.find((c) => c.args[0] === "exec");
    expect(exec?.args).toEqual([
      "exec", "shadow-broker-run1", "node", "/broker/replay.mjs", "replay",
      "/pending", "/log/egress.jsonl", "eff-aa", "eff-bb",
    ]);
  });

  it("does not shell out at all when there is nothing to replay", async () => {
    const sealed = await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    engine.calls.length = 0;
    expect(await sealer.replay(sealed, [])).toEqual({ replayed: 0, failed: 0 });
    expect(engine.calls).toHaveLength(0);
  });

  it("removes the broker and the network on release", async () => {
    const sealed = await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    engine.calls.length = 0;
    expect(await sealer.release(sealed)).toEqual({ removed: true });
    expect(engine.calls.map((c) => c.args.join(" "))).toEqual([
      "rm --force shadow-broker-run1",
      "network rm shadow-run1",
    ]);
  });

  it("force-disconnects what is still attached rather than leaking the network", async () => {
    // The first version swallowed the failure. `docker network rm` refuses while anything is still
    // attached, and the default address pool is a few dozen /24 subnets, so a platform that leaks
    // one network per slow teardown stops being able to seal a turn at all. The docker suite that
    // found this had left eight networks behind in a single run.
    let attempts = 0;
    const stubborn = new NetworkSealer(config, {
      exec: async (_file, args) => {
        if (args[0] === "logs") return { stdout: '{"kind":"broker.ready"}\n' };
        if (args[0] === "network" && args[1] === "rm") {
          attempts += 1;
          if (attempts === 1) throw new Error("network has active endpoints");
          return { stdout: "" };
        }
        if (args[0] === "network" && args[1] === "inspect") return { stdout: "abc123 def456\n" };
        return { stdout: "" };
      },
    });
    const sealed = await stubborn.open({ runId: "run2", agentId: "agent-a", shadowDir, workspacePath: workspace });
    expect(await stubborn.release(sealed)).toEqual({ removed: true });
    expect(attempts).toBe(2);
  });

  it("reports a network it could not remove instead of hiding it", async () => {
    const doomed = new NetworkSealer(config, {
      exec: async (_file, args) => {
        if (args[0] === "logs") return { stdout: '{"kind":"broker.ready"}\n' };
        if (args[0] === "network" && args[1] === "rm") throw new Error("still busy");
        return { stdout: "" };
      },
    });
    const sealed = await doomed.open({ runId: "run3", agentId: "agent-a", shadowDir, workspacePath: workspace });
    const outcome = await doomed.release(sealed);
    expect(outcome.removed).toBe(false);
    expect(outcome.detail).toContain("still busy");
  });

  it("prunes a leaked shadow network once per process, and only when it is old enough", async () => {
    const old = new Date(Date.now() - 30 * 60_000).toISOString();
    const young = new Date().toISOString();
    const pruner = fakeEngine();
    const sealerTwo = new NetworkSealer(config, {
      exec: async (file, args, env) => {
        if (args[0] === "network" && args[1] === "ls") {
          pruner.calls.push({ file, args, env: env ?? {} });
          return { stdout: "shadow-orphan-old\nshadow-orphan-young\n" };
        }
        if (args[0] === "network" && args[1] === "inspect") {
          pruner.calls.push({ file, args, env: env ?? {} });
          return { stdout: args[2] === "shadow-orphan-old" ? old : young };
        }
        return pruner.exec(file, args, env);
      },
    });
    await sealerTwo.open({ runId: "p1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    expect(pruner.calls.filter((c) => c.args[1] === "ls")).toHaveLength(1);
    const issued = pruner.calls.map((c) => c.args.join(" "));
    expect(issued).toContain("network rm shadow-orphan-old");
    // The engine only refuses to remove a network with ACTIVE ENDPOINTS, which a network acquires
    // when its first container attaches. Between `network create` and the broker joining, a live
    // turn's network has none and the engine will happily remove it, so a second instance pruning
    // at that instant kills a running turn. Age is the discriminator that needs no shared state.
    expect(issued).not.toContain("network rm shadow-orphan-young");
    await sealerTwo.open({ runId: "p2", agentId: "agent-a", shadowDir, workspacePath: workspace });
    expect(pruner.calls.filter((c) => c.args[1] === "ls")).toHaveLength(1);
  });

  it("unlinks the held store on discard", async () => {
    const sealed = await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    await fs.writeFile(path.join(sealed.pendingDir, "eff-aa.json"), "{}");
    await sealer.dropHeld(sealed);
    await expect(fs.readdir(sealed.pendingDir)).rejects.toThrow();
  });

  it("counts what the broker decided, for the journal, without any payload", async () => {
    const sealed = await sealer.open({ runId: "run1", agentId: "agent-a", shadowDir, workspacePath: workspace });
    await fs.writeFile(
      path.join(sealed.logDir, "egress.jsonl"),
      [
        '{"kind":"egress","decision":"DENY"}',
        '{"kind":"egress","decision":"HELD"}',
        '{"kind":"egress","decision":"LIVE"}',
        '{"kind":"egress","decision":"LIVE"}',
      ].join("\n") + "\n",
    );
    expect(await sealer.decisionSummary(sealed)).toEqual({ deny: 1, held: 1, live: 2 });
  });
});

describe("the broker runs as an identity that can read its own configuration", () => {
  const base = {
    networkName: "n",
    egressNetwork: "e",
    brokerContainer: "c",
    brokerImage: "img",
    brokerCodeDir: "/code",
    configDir: "/cfg",
    logDir: "/log",
    pendingDir: "/pending",
    protectedDir: "/protected",
    runId: "r",
    agentId: "a",
  };

  it("passes --user when a uid is supplied, so 0600 files stay readable without relaxing them", () => {
    const args = buildBrokerRunArgs({ ...base, runAsUser: "1000:1000" });
    expect(args).toContain("--user");
    expect(args[args.indexOf("--user") + 1]).toBe("1000:1000");
    // and it is still the container it was: readability must not be bought with capability
    expect(args).toContain("--cap-drop");
    expect(args).toContain("ALL");
    expect(args).toContain("no-new-privileges");
  });

  it("omits --user entirely on a host whose mount layer maps ownership itself", () => {
    expect(buildBrokerRunArgs(base)).not.toContain("--user");
  });
});

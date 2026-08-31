import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loadConfig, type AppConfig } from "./config.js";
import { CodexHomeManager } from "./codex-home.js";
import { EGRESS_NETWORK, NetworkSealer, brokerNameFor, networkNameFor } from "./network-sealer.js";
import { createRunner, ShadowConfinement, unconfinedConfinement } from "./runner-factory.js";
import { TransactionalRunner, type TransactionalRunnerOptions } from "./transactional-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const base = {
  ARK_API_KEY: "FIXTURE-KEY-NOT-REAL",
  ARK_MODEL: "ep-test",
};

/** the same copy `CodexHomeManager.seal` takes, for the tests that need a snapshot that agrees */
const execFileAsync = promisify(execFile);

describe("the runner factory refuses to dress an unconfined runtime as a transaction", () => {
  it("throws for the host-process runtime by default", () => {
    // a33: CodexRunner is child_process.spawn with a starting cwd. cwd is not confinement: the
    // turn can walk out of the workspace and delete the journal that would have recorded it, and
    // captureEffects only ever diffs the workspace, so it commits with zero effects. Wrapping
    // that in a transaction produces a clean audit trail for a runtime nothing contains, which is
    // worse than no audit trail at all.
    expect(() => createRunner(loadConfig({ ...base, RUNTIME_PROVIDER: "local-process" }))).toThrow(
      /SHADOW_ALLOW_UNCONFINED/,
    );
  });

  it("names the runtime and the way out in the message", () => {
    let message = "";
    try {
      createRunner(loadConfig({ ...base, RUNTIME_PROVIDER: "local-process" }));
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain("local-process");
    expect(message).toContain("RUNTIME_PROVIDER=container");
  });

  it("allows it when an operator says so explicitly", () => {
    const runner = createRunner(
      loadConfig({ ...base, RUNTIME_PROVIDER: "local-process", SHADOW_ALLOW_UNCONFINED: "1" }),
    );
    expect(runner).toBeInstanceOf(TransactionalRunner);
  });

  it("wraps the container runtime with no flag needed", () => {
    expect(createRunner(loadConfig({ ...base, RUNTIME_PROVIDER: "container" }))).toBeInstanceOf(
      TransactionalRunner,
    );
  });
});

describe("the override path says so on every turn", () => {
  it("journals confinement none rather than announcing it once at boot", async () => {
    // Once at boot is a line nobody reading a journal record will ever see. Every turn.begin under
    // the override carries it instead.
    const confinement = unconfinedConfinement();
    const request = { agentId: "a", workspacePath: "/w", prompt: "p", threadId: null };
    const opened = await confinement.open({ runId: "r1", request, shadowDir: "/s" });
    expect(opened.note.confinement).toBe("none");
    expect(opened.note.reason).toContain("no network or filesystem jail");
    expect(opened.request).toBe(request);
    expect(await confinement.outboundEffects("r1")).toEqual([]);
    expect((await confinement.settle("r1", "commit")).note).toEqual({ confinement: "none" });
  });
});

/**
 * A fake container engine: just enough of one to answer the only question these tests ask, which
 * is whether anything is still running after a turn that failed. Containers and networks are
 * created and removed by name, and `docker network rm` refuses while a container is attached,
 * because that refusal is what turns one leaked broker into a permanently leaked network.
 */
class FakeEngine {
  readonly containers = new Map<string, string[]>();
  readonly networks = new Set<string>();
  readonly calls: string[][] = [];
  /** the daemon starts the container and the CLI still fails: a timeout, a broken pipe, a signal */
  cliFailsAfterStartingBroker = false;
  /** called on every `logs` poll, so a test can let waitForBroker's deadline pass */
  onLogs: (() => void) | null = null;
  brokerReady = true;
  /** the daemon refuses the removal, which `release()` swallows: the container stays up */
  brokerRmFails = false;

  exec = async (_file: string, args: string[]): Promise<{ stdout: string }> => {
    this.calls.push(args);
    if (args[0] === "network" && args[1] === "create") {
      this.networks.add(args[args.length - 1]!);
      return { stdout: "" };
    }
    if (args[0] === "network" && args[1] === "rm") {
      const name = args[2]!;
      for (const [container, joined] of this.containers) {
        if (joined.includes(name)) {
          throw new Error("error removing network: " + name + " has active endpoints: " + container);
        }
      }
      this.networks.delete(name);
      return { stdout: "" };
    }
    if (args[0] === "network" && args[1] === "inspect") {
      const name = args[args.length - 1]!;
      const attached = [...this.containers].filter(([, j]) => j.includes(name)).map(([c]) => c);
      return { stdout: attached.join(" ") + "\n" };
    }
    if (args[0] === "network" && args[1] === "disconnect") {
      const name = args[3]!;
      const container = args[4]!;
      this.containers.set(container, (this.containers.get(container) ?? []).filter((n) => n !== name));
      return { stdout: "" };
    }
    if (args[0] === "run") {
      const name = args[args.indexOf("--name") + 1]!;
      const joined = args.flatMap((a, i) => (a === "--network" ? [args[i + 1]!] : []));
      this.containers.set(name, joined);
      if (this.cliFailsAfterStartingBroker) throw new Error("Command failed: docker run: ETIMEDOUT");
      return { stdout: name + "\n" };
    }
    if (args[0] === "rm" && args[1] === "--force") {
      if (this.brokerRmFails) {
        throw new Error("Error response from daemon: removal of container is already in progress");
      }
      this.containers.delete(args[2]!);
      return { stdout: "" };
    }
    // How a real engine answers "is this container gone": nonzero with "no such container" when it
    // is, a status line when it is not. It answers by failing, which is why it is the call the
    // teardown asks rather than one whose silence looks like absence.
    if (args[0] === "container" && args[1] === "inspect") {
      const name = args[args.length - 1]!;
      if (!this.containers.has(name)) {
        throw new Error("Error response from daemon: No such container: " + name);
      }
      return { stdout: "running\n" };
    }
    if (args[0] === "logs") {
      this.onLogs?.();
      return { stdout: this.brokerReady ? '{"kind":"broker.ready"}\n' : "" };
    }
    if (args[0] === "exec") return { stdout: JSON.stringify({ results: [{ decision: "REPLAYED" }] }) + "\n" };
    return { stdout: "" };
  };
}

/**
 * A seal that throws leaves the broker running, and the broker holds the real provider key and a
 * plaintext copy of every protected file. `open()` used to restore the codex-home and rethrow, and
 * nothing else ever reaped a broker: `pruneStale` only enumerates networks, and the still-attached
 * broker makes `network rm` fail for that network for as long as the container lives.
 */
describe("a seal that fails part way leaves nothing running", () => {
  let root: string;
  let workspace: string;
  let config: AppConfig;
  let engine: FakeEngine;

  const confinementFor = () =>
    new ShadowConfinement(config, new NetworkSealer(config, { exec: engine.exec }), new CodexHomeManager(config), {
      sealNetwork: true,
      shadowRoot: path.join(root, "shadows"),
      exec: engine.exec,
    });

  /** the plaintext copy of a protected file that the broker container mounts */
  const protectedCopy = (runId: string): Promise<string> =>
    fs.readFile(path.join(root, "shadows", runId, "net", "protected", "customers.jsonl"), "utf8");

  const openTurn = async (runId: string) => {
    const shadowDir = path.join(root, "shadows", runId);
    await fs.mkdir(shadowDir, { recursive: true });
    return confinementFor().open({
      runId,
      request: { agentId: "agent-a", workspacePath: workspace, prompt: "p", threadId: null },
      shadowDir,
    });
  };

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "seal-leak-"));
    workspace = path.join(root, "workspace");
    await fs.mkdir(workspace, { recursive: true });
    await fs.writeFile(path.join(workspace, "customers.jsonl"), '{"id":1,"email":"ada@example.com"}\n');
    config = loadConfig({
      ...base,
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: workspace,
      CODEX_HOME: path.join(root, "codex-home"),
      RUNTIME_PROVIDER: "container",
    });
    engine = new FakeEngine();
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("reaps the broker when the CLI fails after the daemon started it", async () => {
    engine.cliFailsAfterStartingBroker = true;
    await expect(openTurn("run-cli-fails")).rejects.toThrow(/sealed network could not be created/);

    expect([...engine.containers.keys()]).toEqual([]);
    // the run's own network goes; the shared egress network stays, because it is not this turn's
    // to remove and a concurrent turn's broker is on it
    expect([...engine.networks]).toEqual([EGRESS_NETWORK]);
    await expect(protectedCopy("run-cli-fails")).rejects.toThrow();
  });

  it("reaps the broker when it never reports ready", async () => {
    // waitForBroker's own deadline, which is the shape a stopped or crash-looping broker takes.
    // The clock is nudged past it from inside the poll rather than waiting twenty real seconds.
    engine.brokerReady = false;
    const realNow = Date.now;
    engine.onLogs = () => {
      Date.now = () => realNow() + 25_000;
    };
    try {
      await expect(openTurn("run-never-ready")).rejects.toThrow(/sealed network could not be created/);
    } finally {
      Date.now = realNow;
      engine.onLogs = null;
    }

    expect([...engine.containers.keys()]).toEqual([]);
    // the run's own network goes; the shared egress network stays, because it is not this turn's
    // to remove and a concurrent turn's broker is on it
    expect([...engine.networks]).toEqual([EGRESS_NETWORK]);
    await expect(protectedCopy("run-never-ready")).rejects.toThrow();
  });

  it("does not report a teardown it did not verify", async () => {
    // `release()` runs `rm --force` on the broker, swallows the failure, then force-disconnects
    // and retries the network: `network rm` succeeds over a container that is still up holding
    // ARK_API_KEY and the plaintext protected copies. Reading that one boolean and telling the
    // operator the whole seal was gone is the leak this path exists to close, announced as closed.
    engine.cliFailsAfterStartingBroker = true;
    engine.brokerRmFails = true;
    let message = "";
    try {
      await openTurn("run-rm-fails");
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect([...engine.containers.keys()]).toEqual([brokerNameFor("run-rm-fails")]);
    expect(message).toContain("NOT fully torn down");
    expect(message).toContain(brokerNameFor("run-rm-fails"));
    // and the network half is still reported honestly: that one did come down
    expect([...engine.networks]).toEqual([EGRESS_NETWORK]);
  });

  it("reports the teardown when the broker is confirmed gone", async () => {
    // the negative case: the claim is made when the engine says the container is not there, and
    // the words name what was checked rather than asserting the seal in general
    engine.cliFailsAfterStartingBroker = true;
    let message = "";
    try {
      await openTurn("run-reaped");
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect([...engine.containers.keys()]).toEqual([]);
    expect(message).toContain("torn down");
    expect(message).not.toContain("NOT fully torn down");
  });

  it("does not claim a teardown when the engine cannot be asked at all", async () => {
    // The third state, and the reason absence of an answer is not an answer: an engine that is not
    // reachable has not said the container is gone. A daemon that is down is exactly when a broker
    // is most likely to be sitting there holding the key.
    engine.cliFailsAfterStartingBroker = true;
    const unreachable = new ShadowConfinement(
      config,
      new NetworkSealer(config, { exec: engine.exec }),
      new CodexHomeManager(config),
      {
        sealNetwork: true,
        shadowRoot: path.join(root, "shadows"),
        exec: async (file, args) => {
          // Named, never mounted and never dialled; the realism is the point of this fixture.
          if (args[0] === "container") throw new Error("Cannot connect to the Docker daemon at unix:///var/run/docker.sock"); // container-socket-allow: the daemon's own unreachable message
          return engine.exec(file, args);
        },
      },
    );
    const shadowDir = path.join(root, "shadows", "run-no-daemon");
    await fs.mkdir(shadowDir, { recursive: true });
    let message = "";
    try {
      await unreachable.open({
        runId: "run-no-daemon",
        request: { agentId: "agent-a", workspacePath: workspace, prompt: "p", threadId: null },
        shadowDir,
      });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain("NOT fully torn down");
    expect(message).toContain("the engine could not be asked");
  });

  it("leaves a seal that came up alone", async () => {
    // the negative case: ordinary work must not be torn down by the failure path
    const opened = await openTurn("run-healthy");

    expect(opened.note.confinement).toBe("container+sealed-network");
    expect([...engine.containers.keys()]).toEqual([brokerNameFor("run-healthy")]);
    expect([...engine.networks]).toContain(networkNameFor("run-healthy"));
    expect(engine.calls.some((args) => args[0] === "rm" && args[1] === "--force")).toBe(false);
    expect(engine.calls.some((args) => args[0] === "network" && args[1] === "rm")).toBe(false);
    // and the broker still has the copy of the protected file it scans outbound payloads against
    await expect(protectedCopy("run-healthy")).resolves.toContain("ada@example.com");
  });
});

const PROTECTED_BODY = '{"id":1,"email":"ada@example.com"}\n{"id":2,"email":"bob@example.com"}\n';

class StubRunner implements AgentRunner {
  constructor(private readonly act: (request: RunnerRequest) => Promise<void>) {}
  async run(request: RunnerRequest): Promise<RunnerResult> {
    await this.act(request);
    return { output: "done", threadId: "thread-new", usage: null };
  }
  async cancel(): Promise<boolean> {
    return false;
  }
  async isAvailable(): Promise<boolean> {
    return true;
  }
}

/** What the broker would have written into its log dir when it held a write. */
/**
 * The destination a held payload names. The discard port on loopback, so a replay that is actually
 * attempted refuses the connection at once rather than resolving a name or waiting on a timeout,
 * and a replay that is refused before the socket leaves no egress record at all. The two are then
 * told apart by evidence rather than by timing.
 */
const HELD_DESTINATION = "127.0.0.1:9";

async function pretendBrokerHeld(shadowDir: string, effectId: string): Promise<void> {
  const logDir = path.join(shadowDir, "net", "log");
  const pendingDir = path.join(shadowDir, "net", "pending");
  await fs.mkdir(logDir, { recursive: true });
  await fs.mkdir(pendingDir, { recursive: true });
  const record = {
    effectId,
    method: "POST",
    host: "collector",
    port: 9100,
    urlPath: "/ingest",
    bytes: PROTECTED_BODY.length,
    sha256: "deadbeef",
    provenance: "customers.jsonl (literal)",
    secretPattern: null,
  };
  await fs.appendFile(path.join(logDir, "held.jsonl"), JSON.stringify(record) + "\n");
  await fs.appendFile(
    path.join(logDir, "egress.jsonl"),
    JSON.stringify({ kind: "egress", decision: "HELD", effectId }) + "\n",
  );
  // What the broker actually writes, which is the whole request it decided to hold rather than an
  // empty object. It matters that the fixture is shaped like the real thing: a pending payload only
  // exists because `allowlistDecision` already said yes to its destination, so a fixture with no URL
  // at all was quietly exercising the unreadable-payload branch instead of the replay it named.
  await fs.writeFile(
    path.join(pendingDir, effectId + ".json"),
    JSON.stringify({
      url: "http://" + HELD_DESTINATION + "/ingest",
      method: "POST",
      headers: { "content-type": "application/json" },
      bodyBase64: Buffer.from(PROTECTED_BODY).toString("base64"),
    }),
    { mode: 0o600 },
  );
}

/**
 * A held turn outlives the process that held it. The operator is the whole point of a review, and
 * an operator takes hours, so a restart between the verdict and the decision is ordinary rather
 * than exotic. When the state a settle acts on lived only in a Map, approve() after that restart
 * applied the files and returned ok while the network half and the memory half were silently
 * skipped, and the journal record was byte-indistinguishable from a turn that had neither.
 */
describe("a held turn's confinement survives the process that held it", () => {
  let root: string;
  let workspace: string;
  let config: AppConfig;
  let engine: FakeEngine;
  let verdict: "commit" | "review";

  const build = () =>
    new TransactionalRunner(
      new StubRunner(async (request) => {
        await pretendBrokerHeld(path.dirname(request.workspacePath), "eff-aa11");
        await fs.appendFile(path.join(request.workspacePath, "README.md"), "\nMinor typo fix.\n");
        await fs.writeFile(
          path.join(request.confinement?.codexHomePath ?? "", "rollout.jsonl"),
          '{"text":"remember APRICOT"}\n',
        );
      }),
      {
        shadowRoot: path.join(root, "shadows"),
        journalPath: path.join(root, "journal.jsonl"),
        stateRoot: config.dataDirectory,
        policy: async () => ({ decision: verdict, rule: verdict === "review" ? "large-blast-radius" : "none" }),
        confinement: new ShadowConfinement(
          config,
          new NetworkSealer(config, { exec: engine.exec }),
          new CodexHomeManager(config),
          // one shadow root, handed to the runner and the confinement by the same caller: recall
          // rebuilds every path from it, so the two must not be able to disagree about it
          { sealNetwork: true, shadowRoot: path.join(root, "shadows"), exec: engine.exec },
        ),
      },
    );

  const journal = async (): Promise<Array<Record<string, unknown>>> => {
    const text = await fs.readFile(path.join(root, "journal.jsonl"), "utf8").catch(() => "");
    return text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
  };

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "review-restart-"));
    workspace = path.join(root, "workspace");
    await fs.mkdir(workspace, { recursive: true });
    await fs.writeFile(path.join(workspace, "customers.jsonl"), PROTECTED_BODY);
    await fs.writeFile(path.join(workspace, "README.md"), "# project\n");
    config = loadConfig({
      ...base,
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: workspace,
      CODEX_HOME: path.join(root, "codex-home"),
      RUNTIME_PROVIDER: "container",
      // the destination the held payload names, on the list, because the broker would not have
      // written that payload at all if it were not
      SHADOW_EGRESS_ALLOWLIST: HELD_DESTINATION,
    });
    engine = new FakeEngine();
    verdict = "review";
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("settles all three halves when the approval arrives after a restart", async () => {
    const held = build();
    await held.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });
    const waiting = (await held.pendingReviews())[0]!;
    const pending = path.join(root, "shadows", waiting.runId, "net", "pending");
    expect(await fs.readdir(pending)).toEqual(["eff-aa11.json"]);

    // the restart: a second runner and a second confinement over the same roots, with none of the
    // first one's memory
    const afterRestart = build();
    expect((await afterRestart.approve(waiting.runId, "operator", waiting.effectSetHash)).ok).toBe(true);

    const committed = (await journal()).find((r) => r.kind === "turn.committed");
    // the files half landed either way; these two are the halves that used to be skipped in silence
    expect(committed?.settledAfterReview).toBe(true);
    expect(committed?.outboundReplayed).toBe(0);
    expect(committed?.outboundFailed).toBe(1);
    expect(await fs.readFile(path.join(root, "codex-home", "agent-a", "rollout.jsonl"), "utf8")).toContain(
      "APRICOT",
    );
  });

  it("drops the held write and leaves the rollback standing when the rejection arrives after a restart", async () => {
    const held = build();
    await held.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });
    const waiting = (await held.pendingReviews())[0]!;

    const afterRestart = build();
    expect((await afterRestart.reject(waiting.runId, "operator")).ok).toBe(true);

    const rejected = (await journal()).find((r) => r.kind === "turn.rejected");
    expect(rejected?.settledAfterReview).toBe(true);
    expect(rejected?.outboundDropped).toBe(1);
    await expect(
      fs.readFile(path.join(root, "codex-home", "agent-a", "rollout.jsonl"), "utf8"),
    ).rejects.toThrow();
    expect(await fs.readFile(path.join(workspace, "README.md"), "utf8")).toBe("# project\n");
  });

  it("still settles in the process that held it, and only once", async () => {
    // the negative case: the ordinary same-process approval keeps working, and the record the
    // restart reads from is cleaned up rather than left for a second settle to act on
    const runner = build();
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });
    const waiting = (await runner.pendingReviews())[0]!;
    expect((await runner.approve(waiting.runId, "operator", waiting.effectSetHash)).ok).toBe(true);

    const committed = (await journal()).find((r) => r.kind === "turn.committed");
    expect(committed?.settledAfterReview).toBe(true);
    expect(committed?.outboundFailed).toBe(1);
    expect(await fs.readFile(path.join(root, "codex-home", "agent-a", "rollout.jsonl"), "utf8")).toContain(
      "APRICOT",
    );
    // nothing is left behind that a later settle could act on a second time
    const confinement = new ShadowConfinement(
      config,
      new NetworkSealer(config, { exec: engine.exec }),
      new CodexHomeManager(config),
      { sealNetwork: true, shadowRoot: path.join(root, "shadows"), exec: engine.exec },
    );
    const again = await confinement.settle(waiting.runId, "commit");
    expect(again.note?.settledAfterReview).toBeUndefined();
  });

  it("writes no held-turn record for a turn that was never held", async () => {
    // the negative case for the store: an ordinary commit leaves nothing waiting on an operator
    verdict = "commit";
    const runner = build();
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });

    const committed = (await journal()).find((r) => r.kind === "turn.committed");
    expect(committed?.settledAfterReview).toBeUndefined();
    expect(committed?.outboundReplayed).toBe(1);
    await expect(fs.readdir(path.join(config.dataDirectory, "review-confinement"))).rejects.toThrow();
  });

  it("says so in the journal when a settle finds no confinement state at all", async () => {
    // Persistence closes the restart case. Everything else that could lose the state (a wiped data
    // directory, an unreadable record) must be loud rather than an empty note that reads exactly
    // like a turn with no network and no memory half.
    const confinement = new ShadowConfinement(
      config,
      new NetworkSealer(config, { exec: engine.exec }),
      new CodexHomeManager(config),
      { sealNetwork: true, shadowRoot: path.join(root, "shadows"), exec: engine.exec },
    );
    const settled = await confinement.settle("run-nobody-has-heard-of", "commit");
    expect(settled.note?.confinementStateLost).toBe(true);
  });
});

/**
 * The sealer the product actually builds, and the two joins that were declared in one place and
 * honoured in another.
 *
 * `releaseHookWired: true` is what arms the overlay path, and it was a boolean the caller asserted
 * about itself: nothing bound it to a release hook actually reaching the runner. And the sealer was
 * constructed with no `emit`, so its whole seal.* vocabulary went to `() => undefined` while the
 * runner discarded the ReleaseResult. A shadow that could not be proven unmounted was renamed into
 * .orphan with no record anywhere, in a product whose claim is that the journal says what happened.
 */
describe("the sealer the factory builds is joined to the runner it hands back", () => {
  let root: string;
  let config: AppConfig;

  const optionsOf = (runner: TransactionalRunner): TransactionalRunnerOptions =>
    (runner as unknown as { opts: TransactionalRunnerOptions }).opts;

  const journalRecords = async (): Promise<Array<Record<string, unknown>>> => {
    const text = await fs.readFile(path.join(config.dataDirectory, "journal.jsonl"), "utf8").catch(() => "");
    return text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
  };

  /** the sealer's emit is fire and forget, so the record lands a tick or two after release returns */
  const sealRecord = async (): Promise<Record<string, unknown> | undefined> => {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const found = (await journalRecords()).find((r) => r.kind === "seal.release");
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return undefined;
  };

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "seal-wiring-"));
    config = loadConfig({
      ...base,
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: path.join(root, "workspace"),
      CODEX_HOME: path.join(root, "codex-home"),
      RUNTIME_PROVIDER: "container",
    });
    await fs.mkdir(path.join(root, "workspace"), { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("carries a release hook beside the seal that claims one is wired", async () => {
    const options = optionsOf(createRunner(config));
    expect(typeof options.seal).toBe("function");
    expect(typeof options.release).toBe("function");
  });

  it("journals the teardown of a shadow it could delete", async () => {
    const runner = createRunner(config);
    const shadowDir = path.join(config.dataDirectory, "shadows", "run-teardown");
    await fs.mkdir(shadowDir, { recursive: true });
    await fs.writeFile(path.join(shadowDir, "marker"), "gone after this\n");

    await optionsOf(runner).release?.(shadowDir, "copy");

    await expect(fs.readdir(shadowDir)).rejects.toThrow();
    const record = await sealRecord();
    expect(record?.removed).toBe(true);
    expect(record?.runId).toBe("run-teardown");
    // and it extends the one chain rather than forking a second writer onto the same file
    expect((await TransactionalRunner.verifyChain(path.join(config.dataDirectory, "journal.jsonl"))).ok).toBe(
      true,
    );
  });

  it("journals a quarantine, which is the teardown that could not be proven safe", async () => {
    const runner = createRunner(config);
    const shadows = path.join(config.dataDirectory, "shadows");
    await fs.mkdir(shadows, { recursive: true });
    const elsewhere = path.join(root, "elsewhere");
    await fs.mkdir(elsewhere, { recursive: true });
    // the leaf is a symlink, so the absence of a mount under it cannot be established
    const shadowDir = path.join(shadows, "run-quarantined");
    await fs.symlink(elsewhere, shadowDir);

    await optionsOf(runner).release?.(shadowDir, "copy");

    const record = await sealRecord();
    expect(record?.removed).toBe(false);
    expect(record?.reason).toBe("leaf-is-symlink");
    expect(String(record?.quarantinedTo)).toContain(".orphan");
  });
});

/**
 * The record a held turn leaves on disk, treated as what it is: a file, in a directory this
 * process writes and something else may be able to.
 *
 * The first version of it persisted the whole ReviewState, paths and all, and a settle obeyed
 * those paths. `promote()` renames a directory over the agent's real memory, so a record naming
 * CODEX_HOME itself as its realPath replaced every agent's memory at once, and the check in front
 * of it permitted exactly that value, because "under the root" is true of the root. The same
 * record was also read BEFORE the live map, so one planted for a run that was open at that moment
 * sent its settle down a path that never releases a network: the turn's broker and network
 * survived the settle for good.
 *
 * Both are the same mistake, which is a file being made an authority. These tests hold the two
 * properties that replace it: live state answers first, and the record names nothing.
 */
describe("the held-turn record is a hint, and live state outranks it", () => {
  let root: string;
  let workspace: string;
  let codexRoot: string;
  let config: AppConfig;
  let engine: FakeEngine;

  const confinementFor = () =>
    new ShadowConfinement(config, new NetworkSealer(config, { exec: engine.exec }), new CodexHomeManager(config), {
      sealNetwork: true,
      shadowRoot: path.join(root, "shadows"),
      exec: engine.exec,
    });

  const plant = async (runId: string, body: unknown): Promise<void> => {
    const dir = path.join(config.dataDirectory, "review-confinement");
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, runId + ".json"), JSON.stringify(body));
  };

  /** the record as the reviewer wrote it: every path in it chosen by whoever wrote the file */
  const craftedRecord = (input: { realPath: string; livePath: string; shadowDir: string }) => ({
    network: null,
    codexHome: {
      agentId: "agent-a",
      realPath: input.realPath,
      livePath: input.livePath,
      prePath: input.livePath,
      preDigest: "x",
      preFiles: 0,
    },
    preTurnThreadId: null,
    heldIds: [],
    shadowDir: input.shadowDir,
  });

  const openTurn = async (runId: string, shadowDir: string, confinement = confinementFor()) => {
    await fs.mkdir(shadowDir, { recursive: true });
    await confinement.open({
      runId,
      request: { agentId: "agent-a", workspacePath: workspace, prompt: "p", threadId: null },
      shadowDir,
    });
    return confinement;
  };

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "review-record-"));
    workspace = path.join(root, "workspace");
    codexRoot = path.join(root, "codex-home");
    await fs.mkdir(workspace, { recursive: true });
    await fs.writeFile(path.join(workspace, "customers.jsonl"), PROTECTED_BODY);
    for (const agent of ["agent-a", "agent-b"]) {
      await fs.mkdir(path.join(codexRoot, agent), { recursive: true });
      await fs.writeFile(path.join(codexRoot, agent, "rollout.jsonl"), agent + " memory\n");
    }
    config = loadConfig({
      ...base,
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: workspace,
      CODEX_HOME: codexRoot,
      RUNTIME_PROVIDER: "container",
    });
    engine = new FakeEngine();
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("cannot name the directory a settle renames over", async () => {
    // The reviewer's record, unchanged: realPath is CODEX_HOME itself, and livePath is a directory
    // holding one file. Settling it used to rename the root out of the way and put that directory
    // in its place, so every agent's memory went at once for the price of writing one file.
    const runId = "run-craft";
    const shadowDir = path.join(root, "shadows", runId);
    const livePath = path.join(shadowDir, "codex-home", "live");
    await fs.mkdir(livePath, { recursive: true });
    await fs.writeFile(path.join(livePath, "PLANTED"), "what the attacker wants the root to hold\n");
    await plant(runId, craftedRecord({ realPath: codexRoot, livePath, shadowDir }));

    const settled = await confinementFor().settle(runId, "commit");

    expect((await fs.readdir(codexRoot)).sort()).toEqual(["agent-a", "agent-b"]);
    expect(await fs.readFile(path.join(codexRoot, "agent-a", "rollout.jsonl"), "utf8")).toBe("agent-a memory\n");
    expect(settled.note?.settledAfterReview).toBeUndefined();
    // and the settle is loud about having no state rather than quietly acting on the file
    expect(settled.note?.confinementStateLost).toBe(true);
  });

  /** a sealed shadow of the shape CodexHomeManager.seal leaves behind, with content to promote */
  const sealedShadow = async (runId: string, content: string): Promise<string> => {
    const shadowDir = path.join(root, "shadows", runId);
    const livePath = path.join(shadowDir, "codex-home", "live");
    await fs.mkdir(livePath, { recursive: true });
    await fs.mkdir(path.join(shadowDir, "codex-home", "pre"), { recursive: true });
    await fs.writeFile(path.join(livePath, "rollout.jsonl"), content);
    return shadowDir;
  };

  it("cannot walk out of the codex-home root through the agent it names", async () => {
    // the current shape, well formed, with an agent id chosen by whoever wrote the file. It is a
    // name and not a path: ".." sanitises to a directory name, and one nothing was ever sealed for
    // has no state to settle, so the settle says so instead of creating it.
    const runId = "run-hint-escape";
    await sealedShadow(runId, "planted\n");
    await plant(runId, {
      version: 1,
      agentId: "../../..",
      preTurnThreadId: null,
      hasNetwork: false,
      hasCodexHome: true,
      heldCount: 0,
    });

    const settled = await confinementFor().settle(runId, "commit");

    expect(settled.note?.confinementStateLost).toBe(true);
    expect((await fs.readdir(codexRoot)).sort()).toEqual(["agent-a", "agent-b"]);
    expect(await fs.readFile(path.join(codexRoot, "agent-a", "rollout.jsonl"), "utf8")).toBe("agent-a memory\n");
  });

  it("cannot aim a planted shadow at an agent whose memory it does not already hold", async () => {
    // Round two took the paths away and left the AGENT, which is the same primitive one turn of
    // the screw smaller: a record naming agent-b sent agent-a's staged directory into agent-b's
    // memory, and the test that used to stand here called that the acceptable reach.
    //
    // A real held turn's `pre` is a copy of that agent's memory taken at seal time, and the review
    // already restored the memory from it, so the two agree. Nothing planted here can agree with
    // agent-b's memory without already knowing its bytes, which is what the jail denies.
    const runId = "run-hint";
    await sealedShadow(runId, "planted\n");
    await plant(runId, {
      version: 1,
      agentId: "agent-b",
      preTurnThreadId: null,
      hasNetwork: false,
      hasCodexHome: true,
      heldCount: 0,
    });

    const settled = await confinementFor().settle(runId, "commit");

    expect((await fs.readdir(codexRoot)).sort()).toEqual(["agent-a", "agent-b"]);
    expect(await fs.readFile(path.join(codexRoot, "agent-b", "rollout.jsonl"), "utf8")).toBe("agent-b memory\n");
    expect(await fs.readFile(path.join(codexRoot, "agent-a", "rollout.jsonl"), "utf8")).toBe("agent-a memory\n");
    // and it is refused out loud: a memory half that did not happen and does not say so is the
    // silence the record exists to end
    expect(settled.note?.codexHomeWithheld).toContain("agent-b");
    expect(settled.note?.codexHome).toBeUndefined();
  });

  it("promotes when the sealed snapshot still agrees with the agent's memory", async () => {
    // The negative case, and the one that keeps the gate from being "refuse everything". `pre` is
    // the agent's memory as `seal()` copies it, so the corroboration holds and the promote runs.
    // It doubles as the statement of what a planter would have to already possess to get here.
    const runId = "run-hint-agrees";
    const shadowDir = await sealedShadow(runId, "planted\n");
    await execFileAsync("cp", [
      "-a",
      path.join(codexRoot, "agent-b") + "/.",
      path.join(shadowDir, "codex-home", "pre"),
    ]);
    await plant(runId, {
      version: 1,
      agentId: "agent-b",
      preTurnThreadId: null,
      hasNetwork: false,
      hasCodexHome: true,
      heldCount: 0,
    });

    const settled = await confinementFor().settle(runId, "commit");

    expect(settled.note?.settledAfterReview).toBe(true);
    expect(settled.note?.codexHomeWithheld).toBeUndefined();
    expect(await fs.readFile(path.join(codexRoot, "agent-b", "rollout.jsonl"), "utf8")).toBe("planted\n");
    expect(await fs.readFile(path.join(codexRoot, "agent-a", "rollout.jsonl"), "utf8")).toBe("agent-a memory\n");
  });

  it("refuses to promote over memory a later turn has already changed", async () => {
    // The same line, earning its place twice. A held turn approved after another turn for the same
    // agent committed would rename a stale directory over that commit, destroying it exactly as
    // quietly as the attack would. Agreement with the snapshot is what refuses both.
    const runId = "run-hint-stale";
    const shadowDir = await sealedShadow(runId, "planted\n");
    await execFileAsync("cp", [
      "-a",
      path.join(codexRoot, "agent-b") + "/.",
      path.join(shadowDir, "codex-home", "pre"),
    ]);
    await plant(runId, {
      version: 1,
      agentId: "agent-b",
      preTurnThreadId: null,
      hasNetwork: false,
      hasCodexHome: true,
      heldCount: 0,
    });
    // the later turn, landing while the review waited
    await fs.writeFile(path.join(codexRoot, "agent-b", "rollout.jsonl"), "agent-b learned something\n");

    const settled = await confinementFor().settle(runId, "commit");

    expect(settled.note?.codexHomeWithheld).toContain("agent-b");
    expect(await fs.readFile(path.join(codexRoot, "agent-b", "rollout.jsonl"), "utf8")).toBe(
      "agent-b learned something\n",
    );
  });

  it("refuses a record whose run has no sealed shadow", async () => {
    // A held turn's shadow is deliberately not released until the operator decides, so a record
    // without one has outlived the state it describes and there is nothing to settle. Nothing is
    // rebuilt from a directory that is not there.
    await plant("run-no-shadow", {
      version: 1,
      agentId: "agent-a",
      preTurnThreadId: null,
      hasNetwork: true,
      hasCodexHome: true,
      heldCount: 3,
    });

    const settled = await confinementFor().settle("run-no-shadow", "commit");

    expect(settled.note?.confinementStateLost).toBe(true);
    expect(await fs.readFile(path.join(codexRoot, "agent-a", "rollout.jsonl"), "utf8")).toBe("agent-a memory\n");
  });

  /** a held payload as the record's writer would plant one: names, bytes and a destination */
  const plantHeld = async (runId: string, effectId: string, url: string): Promise<string> => {
    const netDir = path.join(root, "shadows", runId, "net");
    await fs.mkdir(path.join(netDir, "pending"), { recursive: true });
    await fs.mkdir(path.join(netDir, "log"), { recursive: true });
    await fs.appendFile(path.join(netDir, "log", "held.jsonl"), JSON.stringify({ effectId }) + "\n");
    await fs.writeFile(
      path.join(netDir, "pending", effectId + ".json"),
      JSON.stringify({ url, method: "POST", headers: {}, bodyBase64: Buffer.from("x").toString("base64") }),
    );
    return netDir;
  };

  it("does not send a held payload to a destination the broker would have refused", async () => {
    // `replayOne` opens a socket to whatever URL it finds in the file. Inside the jail that is safe
    // because the broker wrote the file only after allowing the destination; recalled from a record
    // this process did not write, that decision has never been made for these bytes. So it is made
    // here, and an unallowlisted destination is refused before anything leaves the host.
    const runId = "run-egress-planted";
    await sealedShadow(runId, "planted\n");
    const netDir = await plantHeld(runId, "eff-planted", "http://127.0.0.1:9/exfil");
    await plant(runId, {
      version: 1,
      agentId: "agent-a",
      preTurnThreadId: null,
      hasNetwork: true,
      hasCodexHome: false,
      heldCount: 1,
    });

    const settled = await confinementFor().settle(runId, "commit");

    expect(settled.note?.outboundReplayed).toBe(0);
    expect(settled.note?.outboundRefusedNotAllowlisted).toBe(1);
    expect(JSON.stringify(settled.note?.outboundRefusedDetail)).toContain("127.0.0.1:9");
    // no socket was opened: `replayOne` writes an egress record for every attempt, successful or
    // not, so the absence of the log is the evidence that nothing was attempted
    await expect(fs.readFile(path.join(netDir, "log", "egress.jsonl"), "utf8")).rejects.toThrow();
    // and the payload is kept rather than dropped, because it is now the evidence
    expect(await fs.readdir(path.join(netDir, "pending"))).toEqual(["eff-planted.json"]);
  });

  it("still sends one the broker would have allowed", async () => {
    // the negative case: the check is the broker's own, so a destination on the list goes, and the
    // recalled commit is not quietly turned into a path that never sends anything
    const runId = "run-egress-allowed";
    config = loadConfig({
      ...base,
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: workspace,
      CODEX_HOME: codexRoot,
      RUNTIME_PROVIDER: "container",
      SHADOW_EGRESS_ALLOWLIST: "127.0.0.1:9",
    });
    await sealedShadow(runId, "planted\n");
    const netDir = await plantHeld(runId, "eff-allowed", "http://127.0.0.1:9/ingest");
    await plant(runId, {
      version: 1,
      agentId: "agent-a",
      preTurnThreadId: null,
      hasNetwork: true,
      hasCodexHome: false,
      heldCount: 1,
    });

    const settled = await confinementFor().settle(runId, "commit");

    expect(settled.note?.outboundRefusedNotAllowlisted).toBeUndefined();
    // the send was attempted for real; nothing listens on the discard port, so it is a failure the
    // egress log records rather than a refusal that leaves no trace
    expect(settled.note?.outboundFailed).toBe(1);
    expect(await fs.readFile(path.join(netDir, "log", "egress.jsonl"), "utf8")).toContain("REPLAY_FAILED");
  });

  it("sends none of a held set that is not the one the review counted", async () => {
    // The operator approved a number of outbound writes. A set that has moved since is not that
    // set, so it is refused whole rather than partly sent under a note saying the count changed.
    const runId = "run-egress-moved";
    config = loadConfig({
      ...base,
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: workspace,
      CODEX_HOME: codexRoot,
      RUNTIME_PROVIDER: "container",
      SHADOW_EGRESS_ALLOWLIST: "127.0.0.1:9",
    });
    await sealedShadow(runId, "planted\n");
    const netDir = await plantHeld(runId, "eff-one", "http://127.0.0.1:9/ingest");
    await plantHeld(runId, "eff-two", "http://127.0.0.1:9/ingest");
    await plant(runId, {
      version: 1,
      agentId: "agent-a",
      preTurnThreadId: null,
      hasNetwork: true,
      hasCodexHome: false,
      heldCount: 1,
    });

    const settled = await confinementFor().settle(runId, "commit");

    expect(settled.note?.outboundReplayed).toBeUndefined();
    expect(settled.note?.outboundRefused).toBe(2);
    expect(settled.note?.outboundHeldCountChanged).toEqual({ atReview: 1, atSettle: 2 });
    await expect(fs.readFile(path.join(netDir, "log", "egress.jsonl"), "utf8")).rejects.toThrow();
    expect((await fs.readdir(path.join(netDir, "pending"))).sort()).toEqual([
      "eff-one.json",
      "eff-two.json",
    ]);
  });

  it("cannot suppress the teardown of a turn that is open right now", async () => {
    const runId = "run-live";
    const shadowDir = path.join(root, "shadows", runId);
    const confinement = await openTurn(runId, shadowDir);
    expect([...engine.containers.keys()]).toEqual([brokerNameFor(runId)]);

    // planted while the turn is live, in a directory that is not the runner's shadow root
    const elsewhere = path.join(root, "not-the-shadow-root", runId);
    const livePath = path.join(elsewhere, "live");
    await fs.mkdir(livePath, { recursive: true });
    await fs.writeFile(path.join(livePath, "PLANTED"), "planted\n");
    await plant(runId, craftedRecord({
      realPath: path.join(codexRoot, "agent-a"),
      livePath,
      shadowDir: elsewhere,
    }));

    const settled = await confinement.settle(runId, "commit");

    // the live turn's own settle ran: the network and the broker are gone and the egress decisions
    // are summarised, none of which the reviewed path does
    expect(settled.note?.settledAfterReview).toBeUndefined();
    expect(settled.note?.egress).toBeDefined();
    expect([...engine.containers.keys()]).toEqual([]);
    expect([...engine.networks]).toEqual([EGRESS_NETWORK]);
    expect(await fs.readdir(path.join(codexRoot, "agent-a"))).not.toContain("PLANTED");
  });

  it("clears a stale record rather than leaving it for the next settle", async () => {
    // a live settle is authoritative for its run, so a record left over from an earlier one is
    // stale by definition and must not still be there for a later settle to fall back to
    const runId = "run-stale";
    const shadowDir = path.join(root, "shadows", runId);
    const confinement = await openTurn(runId, shadowDir);
    await plant(runId, {
      version: 1,
      agentId: "agent-b",
      preTurnThreadId: null,
      hasNetwork: false,
      hasCodexHome: false,
      heldCount: 0,
    });

    await confinement.settle(runId, "commit");

    await expect(
      fs.readFile(path.join(config.dataDirectory, "review-confinement", runId + ".json"), "utf8"),
    ).rejects.toThrow();
  });

  it("writes no record at all when the shadow it would rebuild is not where it would look", async () => {
    // Recall rebuilds every path from <shadowRoot>/<runId>, so the confinement's shadow root and
    // the runner's have to be the same one. When they are not, no record is written and the note
    // says the restart case is not covered, which is a loss that says so rather than a record a
    // later settle would read as being about a different directory.
    const runId = "run-elsewhere";
    const confinement = await openTurn(runId, path.join(root, "somewhere-else", runId));

    const settled = await confinement.settle(runId, "review");

    expect(settled.note?.reviewRecordNotPersisted).toBe(true);
    expect(String(settled.note?.reviewRecordNotPersistedDetail)).toContain("somewhere-else");
    await expect(fs.readdir(path.join(config.dataDirectory, "review-confinement"))).rejects.toThrow();
  });
});

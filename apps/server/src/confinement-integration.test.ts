import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadConfig, type AppConfig } from "./config.js";
import { CodexHomeManager } from "./codex-home.js";
import { NetworkSealer } from "./network-sealer.js";
import { ShadowConfinement } from "./runner-factory.js";
import { TransactionalRunner } from "./transactional-runner.js";
import type { EffectRecord, PolicyVerdict } from "./policy-types.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

/**
 * Files, the agent's memory and outbound writes under ONE decision, driven through the real
 * TransactionalRunner with the real confinement wiring. The docker engine is faked, because what
 * is under test here is the orchestration: what the policy is shown, and what settling does. The
 * kernel property that makes the seal real is measured in network-docker.test.ts instead.
 *
 * This is spike I's shape as a permanent test: the two bugs it caught were both invisible in the
 * three separate harnesses and only appeared when the pieces ran together.
 */

const PROTECTED_BODY = '{"id":1,"email":"ada@example.com"}\n{"id":2,"email":"bob@example.com"}\n';

interface Call {
  args: string[];
  env: NodeJS.ProcessEnv;
}

class StubRunner implements AgentRunner {
  public lastRequest: RunnerRequest | null = null;
  constructor(private readonly act: (request: RunnerRequest) => Promise<void>) {}
  async run(request: RunnerRequest): Promise<RunnerResult> {
    this.lastRequest = request;
    await this.act(request);
    return { output: "I exported the customer list and fixed the typo.", threadId: "thread-new", usage: null };
  }
  async cancel(): Promise<boolean> {
    return false;
  }
  async isAvailable(): Promise<boolean> {
    return true;
  }
}

/** What the broker would have written into its log dir when it held a write. */
async function pretendBrokerHeld(shadowDir: string, records: Array<Record<string, unknown>>): Promise<void> {
  const logDir = path.join(shadowDir, "net", "log");
  const pendingDir = path.join(shadowDir, "net", "pending");
  await fs.mkdir(logDir, { recursive: true });
  await fs.mkdir(pendingDir, { recursive: true });
  await fs.appendFile(
    path.join(logDir, "held.jsonl"),
    records.map((record) => JSON.stringify(record)).join("\n") + "\n",
  );
  await fs.appendFile(
    path.join(logDir, "egress.jsonl"),
    records.map((r) => JSON.stringify({ kind: "egress", decision: "HELD", effectId: r.effectId })).join("\n") + "\n",
  );
  for (const record of records) {
    await fs.writeFile(path.join(pendingDir, String(record.effectId) + ".json"), "{}", { mode: 0o600 });
  }
}

describe("one turn, one decision, three kinds of effect", () => {
  let root: string;
  let workspace: string;
  let config: AppConfig;
  let calls: Call[];
  let seen: EffectRecord[];
  let verdict: PolicyVerdict;

  const build = (act: (request: RunnerRequest) => Promise<void>) => {
    calls = [];
    const sealer = new NetworkSealer(config, {
      exec: async (_file, args, env = {}) => {
        calls.push({ args, env });
        if (args[0] === "logs") return { stdout: '{"kind":"broker.ready"}\n' };
        if (args[0] === "exec") return { stdout: JSON.stringify({ results: [{ decision: "REPLAYED" }] }) + "\n" };
        return { stdout: "" };
      },
    });
    const confinement = new ShadowConfinement(config, sealer, new CodexHomeManager(config), {
      sealNetwork: true,
    });
    return new TransactionalRunner(new StubRunner(act), {
      shadowRoot: path.join(root, "shadows"),
      journalPath: path.join(root, "journal.jsonl"),
      policy: async (effects) => {
        seen = effects;
        return verdict;
      },
      confinement,
    });
  };

  const journal = async (): Promise<Array<Record<string, unknown>>> => {
    const text = await fs.readFile(path.join(root, "journal.jsonl"), "utf8").catch(() => "");
    return text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  };

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "shadow-confine-"));
    workspace = path.join(root, "workspace");
    await fs.mkdir(workspace, { recursive: true });
    await fs.writeFile(path.join(workspace, "customers.jsonl"), PROTECTED_BODY);
    await fs.writeFile(path.join(workspace, "README.md"), "# project\n");
    config = loadConfig({
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: workspace,
      CODEX_HOME: path.join(root, "codex-home"),
      ARK_API_KEY: "sk-real-provider-key",
      ARK_MODEL: "ep-test",
      RUNTIME_PROVIDER: "container",
    });
    seen = [];
    verdict = { decision: "commit", rule: "none" };
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  const poisonedTurn = async (request: RunnerRequest) => {
    // the a35 shape: exfiltrate, then make one small benign edit and exit 0
    await pretendBrokerHeld(path.dirname(request.workspacePath), [
      {
        effectId: "eff-aa11",
        method: "POST",
        host: "collector",
        port: 9100,
        urlPath: "/ingest",
        bytes: PROTECTED_BODY.length,
        sha256: "deadbeef",
        provenance: "customers.jsonl (literal)",
        secretPattern: null,
      },
    ]);
    await fs.appendFile(path.join(request.workspacePath, "README.md"), "\nMinor typo fix.\n");
  };

  it("shows the policy the held network write in the SAME effect set as the file edit", async () => {
    // a35: today the curl produces no file, so nothing about it is captured, judged or journaled,
    // and the turn commits with a record that describes a clean one-line doc fix.
    const runner = build(poisonedTurn);
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });

    expect(seen.map((e) => e.kind).sort()).toEqual(["modify", "outbound"]);
    const outbound = seen.find((e) => e.kind === "outbound");
    expect(outbound).toMatchObject({ method: "POST", host: "collector", port: 9100, urlPath: "/ingest" });
    expect(outbound?.provenance).toBe("customers.jsonl (literal)");
  });

  it("discards the network write with the files, and the destination never hears about it", async () => {
    verdict = { decision: "discard", rule: "outbound-carries-protected-content" };
    const runner = build(poisonedTurn);
    const result = await runner.run({
      agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null,
    });

    expect(result.output).toContain("blocked by policy");
    // the file half
    expect(await fs.readFile(path.join(workspace, "README.md"), "utf8")).toBe("# project\n");
    // the network half: nothing was replayed, and the payloads are gone
    expect(calls.some((c) => c.args[0] === "exec")).toBe(false);
    const discarded = (await journal()).find((r) => r.kind === "turn.discarded");
    expect(discarded?.outboundDropped).toBe(1);
    // the network itself is torn down with the turn
    expect(calls.some((c) => c.args.join(" ").startsWith("network rm shadow-"))).toBe(true);
  });

  it("replays the held write only on commit, through the broker", async () => {
    const runner = build(poisonedTurn);
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });

    const replay = calls.find((c) => c.args[0] === "exec");
    expect(replay?.args).toContain("replay");
    expect(replay?.args.at(-1)).toBe("eff-aa11");
    const committed = (await journal()).find((r) => r.kind === "turn.committed");
    expect(committed?.outboundReplayed).toBe(1);
    // and the outbound effect is not treated as a path: no file named after it appears
    const files = await fs.readdir(workspace);
    expect(files.some((f) => f.startsWith("net:"))).toBe(false);
    expect(files.sort()).toEqual(["README.md", "customers.jsonl"]);
  });

  it("holds the payloads for a human when the verdict is review", async () => {
    verdict = { decision: "review", rule: "large-blast-radius" };
    const runner = build(poisonedTurn);
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });

    const held = (await journal()).find((r) => r.kind === "turn.held");
    expect(held?.outboundHeldForReview).toBe(1);
    expect(calls.some((c) => c.args[0] === "exec")).toBe(false);
    // the sealed store survives so an approval can still send them; the container does not, because
    // a turn waiting on a human must not hold one for as long as the human takes
    expect(calls.some((c) => c.args.join(" ").startsWith("rm --force shadow-broker-"))).toBe(true);
  });

  /**
   * The operator's decision settles all three halves, not just the files.
   *
   * Lane C shipped with this open: settle("review") marked the turn settled and forgot it, so an
   * approval hours later applied the files and left the held network writes and the sealed
   * codex-home sitting on disk. The state a held turn needs is now kept until the operator
   * decides, and approve and reject reach the same settle through the commit protocol.
   */
  it("sends the held write only when the operator approves, and promotes the memory with it", async () => {
    verdict = { decision: "review", rule: "large-blast-radius" };
    const runner = build(async (request) => {
      await poisonedTurn(request);
      const codexHome = request.confinement?.codexHomePath ?? "";
      await fs.writeFile(path.join(codexHome, "rollout.jsonl"), '{"text":"remember APRICOT"}\n');
    });
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });

    const realHome = path.join(root, "codex-home", "agent-a");
    // while it waits, the memory is already rolled back and the write has not been sent
    await expect(fs.readFile(path.join(realHome, "rollout.jsonl"), "utf8")).rejects.toThrow();
    const held = (await runner.pendingReviews())[0]!;
    const pending = path.join(root, "shadows", held.runId, "net", "pending");
    expect(await fs.readdir(pending)).toEqual(["eff-aa11.json"]);

    verdict = { decision: "review", rule: "large-blast-radius" };
    const outcome = await runner.approve(held.runId, "operator", held.effectSetHash);
    expect(outcome.ok).toBe(true);

    // the memory the held turn wrote is now the agent's memory
    expect(await fs.readFile(path.join(realHome, "rollout.jsonl"), "utf8")).toContain("APRICOT");
    // and the held payload has been settled rather than left behind
    await expect(fs.readdir(pending)).rejects.toThrow();
    const committed = (await journal()).find((r) => r.kind === "turn.committed");
    expect(committed?.settledAfterReview).toBe(true);
    expect(committed?.outboundReplayed).toBe(0);
    expect(committed?.outboundFailed).toBe(1);
  });

  it("drops the held write and leaves the rollback standing when the operator rejects", async () => {
    verdict = { decision: "review", rule: "large-blast-radius" };
    const runner = build(async (request) => {
      await poisonedTurn(request);
      const codexHome = request.confinement?.codexHomePath ?? "";
      await fs.writeFile(path.join(codexHome, "rollout.jsonl"), '{"text":"remember APRICOT"}\n');
    });
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });

    const held = (await runner.pendingReviews())[0]!;
    const pending = path.join(root, "shadows", held.runId, "net", "pending");
    expect(await fs.readdir(pending)).toEqual(["eff-aa11.json"]);

    expect((await runner.reject(held.runId, "operator")).ok).toBe(true);

    const rejected = (await journal()).find((r) => r.kind === "turn.rejected");
    expect(rejected?.settledAfterReview).toBe(true);
    expect(rejected?.outboundDropped).toBe(1);
    await expect(fs.readdir(pending)).rejects.toThrow();
    const realHome = path.join(root, "codex-home", "agent-a");
    await expect(fs.readFile(path.join(realHome, "rollout.jsonl"), "utf8")).rejects.toThrow();
    // the file half is unchanged too
    expect(await fs.readFile(path.join(workspace, "README.md"), "utf8")).toBe("# project\n");
  });

  it("journals what the turn is inside, and nothing that leaks the seal to the turn", async () => {
    const runner = build(poisonedTurn);
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });

    const begin = (await journal()).find((r) => r.kind === "turn.begin");
    expect(begin?.confinement).toBe("container+sealed-network");
    expect(begin?.containerWorkspacePath).toBe("/workspace");
    expect(String(begin?.network)).toMatch(/^shadow-/);
    expect(begin?.modelChannel).toBe("terminated-at-broker");
    expect(begin?.decoyHost).toBe("status.shadow-decoy.test");
    expect(begin?.egressAllowlist).toContain("registry.npmjs.org:443");
  });

  it("rolls the agent's memory back with the files, in the same decision", async () => {
    verdict = { decision: "discard", rule: "outbound-carries-protected-content" };
    const runner = build(async (request) => {
      await poisonedTurn(request);
      // the turn advances its own memory to believe the export happened
      const codexHome = request.confinement?.codexHomePath ?? "";
      await fs.mkdir(path.join(codexHome, "sessions"), { recursive: true });
      await fs.writeFile(
        path.join(codexHome, "sessions", "rollout.jsonl"),
        '{"text":"I exported the customer list"}\n',
      );
    });
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null });

    const realHome = path.join(root, "codex-home", "agent-a");
    await expect(fs.readFile(path.join(realHome, "sessions", "rollout.jsonl"), "utf8")).rejects.toThrow();
    const discarded = (await journal()).find((r) => r.kind === "turn.discarded");
    expect(discarded?.codexHome).toMatchObject({ verifiedUnchanged: true, restored: false });
  });

  it("promotes the memory on commit, so a legitimate turn is remembered", async () => {
    const runner = build(async (request) => {
      const codexHome = request.confinement?.codexHomePath ?? "";
      await fs.writeFile(path.join(codexHome, "rollout.jsonl"), '{"text":"remember BANANA"}\n');
    });
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "learn", threadId: null });

    const realHome = path.join(root, "codex-home", "agent-a");
    expect(await fs.readFile(path.join(realHome, "rollout.jsonl"), "utf8")).toContain("BANANA");
  });

  it("does not hand the caller a thread id that a discarded first turn created", async () => {
    verdict = { decision: "discard", rule: "protected-asset-write" };
    const runner = build(poisonedTurn);
    const result = await runner.run({
      agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null,
    });
    expect(result.threadId).toBeNull();
  });

  it("keeps the thread id when the turn commits", async () => {
    const runner = build(poisonedTurn);
    const result = await runner.run({
      agentId: "agent-a", workspacePath: workspace, prompt: "tidy up", threadId: null,
    });
    expect(result.threadId).toBe("thread-new");
  });

  it("gives the inner runner the sealed network and the sealed memory, and no real key", async () => {
    const stubs: RunnerRequest[] = [];
    const runner = build(async (request) => {
      stubs.push(request);
    });
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "hi", threadId: null });

    const passed = stubs[0]?.confinement;
    expect(passed?.turnToken).toMatch(/^shadow-turn-/);
    expect(passed?.turnToken).not.toContain("sk-real");
    expect(passed?.proxyUrl).toBe("http://broker:3128");
    expect(passed?.codexHomePath).toContain(path.join("codex-home", "live"));
    expect(passed?.codexHomePath).not.toBe(path.join(root, "codex-home", "agent-a"));
  });

  it("names the weaker confinement instead of implying the stronger one", async () => {
    // With network sealing switched off the memory half still applies, but the turn has an
    // ordinary route out. Journaling that as "container+sealed-network" would be the one lie this
    // product cannot afford, so it says "container" and the model channel says "direct".
    const sealer = new NetworkSealer(config, { exec: async () => ({ stdout: "" }) });
    // The engine is injected as answering. Without this the assertion below would be a statement
    // about the machine running the suite rather than about the code: "container" on a host with
    // Docker, "none" on one without. Naming the mode is only meaningful once an engine is known
    // to be there, so the test says which case it is testing.
    const confinement = new ShadowConfinement(config, sealer, new CodexHomeManager(config), {
      sealNetwork: false,
      exec: async () => ({ stdout: "Server Version: 27.0.0" }),
    });
    const runner = new TransactionalRunner(new StubRunner(async () => undefined), {
      shadowRoot: path.join(root, "shadows"),
      journalPath: path.join(root, "journal.jsonl"),
      policy: async () => ({ decision: "commit", rule: "none" }),
      confinement,
    });
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "hi", threadId: null });

    const begin = (await journal()).find((r) => r.kind === "turn.begin");
    expect(begin?.confinement).toBe("container");
    expect(begin?.containerEngineVerified).toBe(true);
    expect(begin?.modelChannel).toBe("direct");
    expect(begin?.network).toBeNull();
    // and the agent's config points at the real provider, because there is no broker to swap keys
    const toml = await fs.readFile(path.join(root, "codex-home", "agent-a", "config.toml"), "utf8");
    expect(toml).toContain('base_url = "https://ark.cn-beijing.volces.com/api/v3"');
  });

  /**
   * The guard that has to fail on a machine that HAS an engine.
   *
   * Found on a Windows host with no Docker, Podman, Colima or WSL distribution: with
   * `RUNTIME_PROVIDER=container`, `SHADOW_CONFINE_NETWORK=false` and `SHADOW_ALLOW_UNCONFINED=1`,
   * `open()` returned `confinement:"container"`, `containerWorkspacePath:"/workspace"` and
   * `containerCodexHome:"/codex-home"` without contacting any engine, because the mode word was
   * read off `RUNTIME_PROVIDER` rather than off anything that had answered. The operator consented
   * to an unsealed network. They did not consent to the journal asserting a container.
   *
   * The engine is injected as ABSENT rather than detected, so this case is reachable on every
   * host. A version of this test that relied on the machine having no engine would pass by
   * accident on the author's laptop and never run anywhere else, which is how the defect survived
   * this long.
   */
  it("says none, not container, when no engine ever answered", async () => {
    const sealer = new NetworkSealer(config, { exec: async () => ({ stdout: "" }) });
    const confinement = new ShadowConfinement(config, sealer, new CodexHomeManager(config), {
      sealNetwork: false,
      exec: async () => {
        throw new Error("spawn docker ENOENT");
      },
    });
    const runner = new TransactionalRunner(new StubRunner(async () => undefined), {
      shadowRoot: path.join(root, "shadows"),
      journalPath: path.join(root, "journal.jsonl"),
      policy: async () => ({ decision: "commit", rule: "none" }),
      confinement,
    });
    await runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "hi", threadId: null });

    const begin = (await journal()).find((r) => r.kind === "turn.begin");
    expect(begin?.confinement).toBe("none");
    expect(begin?.containerEngineVerified).toBe(false);
    // The paths inside a container that does not exist are not recorded as though it did.
    expect(begin?.containerWorkspacePath).toBeNull();
    expect(begin?.containerCodexHome).toBeNull();
    // And the reason is in the record a reader opens, not only on stderr.
    expect(String(begin?.confinementDegraded)).toContain("did not answer");
  });

  it("does not fall back to an unsealed container when the seal fails to come up", async () => {
    // Failing open here would be the whole design inverted: a turn that could not be contained
    // would run anyway, on the default bridge, with a journal saying a transaction happened.
    const sealer = new NetworkSealer(config, {
      exec: async (_file, args) => {
        if (args[0] === "network" && args[1] === "create") throw new Error("engine refused");
        return { stdout: "" };
      },
    });
    const confinement = new ShadowConfinement(config, sealer, new CodexHomeManager(config), {
      sealNetwork: true,
    });
    let ran = false;
    const runner = new TransactionalRunner(
      new StubRunner(async () => {
        ran = true;
      }),
      {
        shadowRoot: path.join(root, "shadows"),
        journalPath: path.join(root, "journal.jsonl"),
        policy: async () => ({ decision: "commit", rule: "none" }),
        confinement,
      },
    );
    await expect(
      runner.run({ agentId: "agent-a", workspacePath: workspace, prompt: "hi", threadId: null }),
    ).rejects.toThrow(/sealed network could not be created/);
    expect(ran).toBe(false);
  });
});

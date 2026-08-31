import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import type { AppConfig } from "./config.js";
import type { EffectRecord } from "./policy-types.js";
import {
  BROKER_PATHS,
  buildBrokerLaunchConfig,
  heldRecordToEffect,
  parseJsonLines,
  providerHostPort,
  summariseDecisions,
  type EgressDecision,
  type HeldRecord,
} from "./broker.js";

/** A `shadow-` network younger than this may still be in its create-to-attach gap. */
const NETWORK_PRUNE_GRACE_MS = 5 * 60_000;

const execFileAsync = promisify(execFile);

/**
 * Gives one turn its own network with no route out of it.
 *
 * Spike A measured what this buys, on the real runtime image: from inside the agent container a
 * public IP is ENETUNREACH, a public hostname fails DNS, `host.docker.internal` does not resolve,
 * raw UDP gets no reply, IPv6 is loopback only, and the routing table has exactly one entry and no
 * default gateway. That is a property of the network namespace, so no library the agent chooses,
 * no encoding and no deleted proxy variable changes it. The only member of the network besides the
 * agent is a broker container that is also on the default bridge, so the broker is the single
 * audited way anything leaves.
 *
 * Spike A also measured why the network has to be per run rather than shared: two agent containers
 * on one internal network can reach each other.
 */

export interface SealedNetwork {
  runId: string;
  networkName: string;
  /** the broker's route out, per run and removed with the rest of the turn */
  egressNetwork: string;
  brokerContainer: string;
  proxyUrl: string;
  noProxy: string;
  modelBaseUrl: string;
  turnToken: string;
  netDir: string;
  logDir: string;
  pendingDir: string;
  allowlist: string[];
  decoyHost: string;
}

/**
 * A docker object name derived from a run id, and it has to be injective: two runs that sanitised
 * or truncated to the SAME network name would put two agent containers on one network, which spike
 * A measured as mutually reachable and is exactly why these are per run. A short hash of the
 * original id is appended whenever sanitising changed anything, so distinct runs cannot collide.
 */
function dockerNameFor(prefix: string, runId: string, limit: number): string {
  const safe = runId.replace(/[^a-zA-Z0-9_.-]/g, "");
  if (safe === runId && safe.length <= limit) return prefix + safe;
  const suffix = crypto.createHash("sha256").update(runId).digest("hex").slice(0, 12);
  return prefix + safe.slice(0, Math.max(0, limit - 13)) + "-" + suffix;
}

export function networkNameFor(runId: string): string {
  return dockerNameFor("shadow-", runId, 40);
}

export function brokerNameFor(runId: string): string {
  return dockerNameFor("shadow-broker-", runId, 32);
}

/**
 * ONE egress network, shared by every turn's broker, rather than one per run.
 *
 * Per-run was the first attempt and it was wrong for a plain reason: the model provider has to be
 * reachable from the broker, and a provider (the real one, or the local fixture in
 * scripts/start-mock-poc.sh) is started once and outlives any single turn. A per-run network the
 * provider never joins leaves the broker unable to reach the model, and the turn hangs until the
 * runtime times out. That is what a per-run version did to the memory-rollback test.
 *
 * What is NOT shared is the part that carries the security property: the agent stays alone on its
 * own per-run `--internal` network with no route anywhere. This network holds brokers, which are
 * this project's own trusted code, and never an agent container. Two concurrent turns' brokers can
 * therefore see each other, which is a trusted-to-trusted path and is the price of the provider
 * being reachable at all.
 */
export const EGRESS_NETWORK = "shadow-egress";

/** `--internal` is the real mechanism; "no default route" is not expressible in `docker run`. */
export function buildNetworkCreateArgs(networkName: string): string[] {
  return ["network", "create", "--internal", "--ipv6=false", networkName];
}

/**
 * The broker's way out, and deliberately NOT the default `bridge`.
 *
 * Two reasons, and the second is the one that made this a defect rather than a preference. A
 * container cannot be given the default bridge and a user-defined network in the same `docker run`
 * (the engine answers "cannot attach both user-defined and non-user-defined network-modes"), so
 * reaching `bridge` meant a second `docker network connect` AFTER the broker was already running.
 * The broker runs with `--rm`, so between those two commands the engine may already have marked it
 * for removal, and the attach then fails with "cannot be connected or disconnected to the network".
 * The sealer treated that as fatal and the turn died. A per-run egress network is user-defined, so
 * it goes on at `run` time and the window does not exist.
 *
 * The other reason stands on its own: the default bridge holds every other container on the host,
 * so the broker was sharing a network with whatever else happens to be running.
 */
export function buildEgressCreateArgs(networkName: string): string[] {
  return ["network", "create", "--ipv6=false", networkName];
}

/** Shared, so creating it races other turns: an "already exists" failure is the success case. */
export function egressAlreadyExists(message: string): boolean {
  return /already exists/i.test(message);
}

export function buildBrokerRunArgs(input: {
  networkName: string;
  brokerContainer: string;
  brokerImage: string;
  brokerCodeDir: string;
  configDir: string;
  logDir: string;
  pendingDir: string;
  protectedDir: string;
  runId: string;
  agentId: string;
  egressNetwork: string;
  runAsUser?: string | undefined;
}): string[] {
  return [
    "run",
    "--detach",
    "--rm",
    "--init",
    "--name",
    input.brokerContainer,
    "--label",
    "io.codejam.launchpad=shadow-broker",
    "--label",
    "io.codejam.run-id=" + input.runId,
    "--label",
    "io.codejam.agent-id=" + input.agentId,
    "--network",
    input.networkName,
    "--network-alias",
    "broker",
    // dual-homed at run time rather than by a later attach: the internal network gives the agent a
    // way to reach the broker, this one gives the broker a way to reach the world. The agent is
    // never on this second network. Verified on docker 29.5.2: the alias above still resolves on
    // the internal network with both attached, and an agent on the internal network alone still
    // has no route out.
    "--network",
    input.egressNetwork,
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    // Dropping ALL takes CAP_DAC_OVERRIDE with it, so uid 0 inside this container is no longer
    // allowed to ignore permission bits. The config, the protected copies and the pending dir are
    // written 0600/0700 and owned by the host user that started the turn, so a capless root cannot
    // read its own configuration: the broker died with EACCES on /broker-config/broker.json one
    // second after every start, printed it on stderr, and `waitForBroker` only reads stdout.
    //
    // Both decisions are right on their own and only fatal together. Running as the owning user is
    // what reconciles them: the modes on the host stay strict AND nothing in the container runs as
    // root. Confined further, not less.
    //
    // Linux only, deliberately. This is a real-ownership problem: on a Docker Desktop or Colima
    // bind mount the files are presented to the container as already readable, which is why the
    // shipped path works there and dies here, and why forcing a uid on a host that maps them is a
    // change with no upside and an untested downside.
    ...(input.runAsUser ? ["--user", input.runAsUser] : []),
    "--memory",
    "256m",
    "--pids-limit",
    "64",
    // pass-through form: the value comes from the environment of the docker CLI process, so
    // neither the provider key nor the one-turn token ever appears in argv where `ps` can read it
    "--env",
    "ARK_API_KEY",
    "--env",
    "SHADOW_TURN_TOKEN",
    "--env",
    "NO_COLOR=1",
    "--mount",
    "type=bind,src=" + input.brokerCodeDir + ",dst=" + BROKER_PATHS.code + ",readonly",
    "--mount",
    "type=bind,src=" + input.configDir + ",dst=/broker-config,readonly",
    "--mount",
    "type=bind,src=" + input.protectedDir + ",dst=/protected,readonly",
    "--mount",
    "type=bind,src=" + input.logDir + ",dst=" + BROKER_PATHS.logDir,
    "--mount",
    "type=bind,src=" + input.pendingDir + ",dst=" + BROKER_PATHS.pendingDir,
    input.brokerImage,
    "node",
    BROKER_PATHS.code + "/server.mjs",
    BROKER_PATHS.config,
  ];
}

/**
 * The identity the broker container runs as, or undefined to leave it to the image.
 *
 * Returns a value only on Linux, where a bind mount carries the host's real uid and gid and the
 * container therefore has to match them to read a 0600 file with no CAP_DAC_OVERRIDE. Elsewhere the
 * mount layer presents the files as readable already and this must stay out of the way.
 */
export function brokerRunAsUser(): string | undefined {
  if (process.platform !== "linux") return undefined;
  if (typeof process.getuid !== "function" || typeof process.getgid !== "function") return undefined;
  return process.getuid() + ":" + process.getgid();
}

/** Where the broker code lives on the host, from either `src/` under tsx or `dist/` after a build. */
export function brokerCodeDir(): string {
  return path.resolve(fileURLToPath(new URL("../broker/", import.meta.url)));
}

export class NetworkSealer {
  private pruned = false;

  constructor(
    private readonly config: AppConfig,
    private readonly deps: {
      exec?: (
        file: string,
        args: string[],
        env?: NodeJS.ProcessEnv,
      ) => Promise<{ stdout: string; stderr?: string }>;
    } = {},
  ) {}

  /**
   * `docker logs` in one invocation, both streams.
   *
   * `run` keeps only stdout, which is correct for every command whose output IS its answer. Here the
   * answer is on stdout and every reason it might be missing is on stderr, so dropping one of them
   * is what turned a one-line EACCES into a twenty-second timeout with an empty message. This never
   * throws: it exists to explain a failure and must not become one.
   */
  private async runBothStreams(args: string[]): Promise<{ stdout: string; stderr: string }> {
    const reason = (error: unknown): string => {
      const e = error as { stderr?: unknown; message?: unknown };
      return String(e?.stderr ?? e?.message ?? "");
    };
    if (this.deps.exec) {
      return this.deps
        .exec(this.config.containerEngine, args)
        .then((r) => ({ stdout: String(r.stdout ?? ""), stderr: String(r.stderr ?? "") }))
        .catch((error: unknown) => ({ stdout: "", stderr: reason(error) }));
    }
    return execFileAsync(this.config.containerEngine, args, {
      timeout: 30_000,
      env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" },
    })
      .then((r) => ({ stdout: String(r.stdout ?? ""), stderr: String(r.stderr ?? "") }))
      .catch((error: unknown) => ({ stdout: "", stderr: reason(error) }));
  }

  private run(args: string[], env: NodeJS.ProcessEnv = {}): Promise<{ stdout: string }> {
    if (this.deps.exec) return this.deps.exec(this.config.containerEngine, args, env);
    return execFileAsync(this.config.containerEngine, args, {
      timeout: 30_000,
      env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", ...env },
    }).then((r) => ({ stdout: String(r.stdout) }));
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.run(["version"]);
      await this.run(["image", "inspect", this.config.shadowBrokerImage]);
      return true;
    } catch {
      return false;
    }
  }

  /** The full allowlist a turn gets: the operator's list plus the model provider's own host. */
  allowlistFor(): string[] {
    const list = [...this.config.shadowEgressAllowlist];
    const provider = providerHostPort(this.config.arkBaseUrl);
    if (provider && !list.includes(provider)) list.push(provider);
    return list;
  }

  async open(input: {
    runId: string;
    agentId: string;
    shadowDir: string;
    workspacePath: string;
  }): Promise<SealedNetwork> {
    const netDir = path.join(input.shadowDir, "net");
    const logDir = path.join(netDir, "log");
    const pendingDir = path.join(netDir, "pending");
    const configDir = path.join(netDir, "config");
    const protectedDir = path.join(netDir, "protected");
    for (const dir of [logDir, configDir, protectedDir]) {
      await fs.mkdir(dir, { recursive: true });
    }
    await fs.mkdir(pendingDir, { recursive: true, mode: 0o700 });

    // The broker scans outbound payloads for the protected assets' own bytes, so it needs a copy
    // of them. It is on the trusted side of the boundary; the agent container cannot read its
    // mounts, and the copy dies with the shadow.
    const protectedFiles: string[] = [];
    for (const name of this.config.shadowProtectedFiles) {
      const source = path.join(input.workspacePath, name);
      const bytes = await fs.readFile(source).catch(() => null);
      if (!bytes) continue;
      const base = path.basename(name);
      await fs.writeFile(path.join(protectedDir, base), bytes, { mode: 0o600 });
      protectedFiles.push("/protected/" + base);
    }

    const allowlist = this.allowlistFor();
    const launch = buildBrokerLaunchConfig({
      allowlist,
      decoyHost: this.config.shadowDecoyHost,
      modelUpstream: this.config.arkBaseUrl,
      proxyPort: this.config.shadowBrokerProxyPort,
      modelPort: this.config.shadowBrokerModelPort,
      protectedFiles,
    });
    await fs.writeFile(path.join(configDir, "broker.json"), JSON.stringify(launch, null, 2), {
      mode: 0o600,
    });

    if (!this.pruned) {
      this.pruned = true;
      await this.pruneStale().catch(() => 0);
    }

    const networkName = networkNameFor(input.runId);
    const egressNetwork = EGRESS_NETWORK;
    const brokerContainer = brokerNameFor(input.runId);
    const turnToken = "shadow-turn-" + crypto.randomBytes(24).toString("hex");

    await this.run(buildNetworkCreateArgs(networkName));
    // Shared and long-lived, so two turns starting together both try to create it. The loser gets
    // "already exists", which is the state this line wanted, so it is success and not an error.
    await this.run(buildEgressCreateArgs(egressNetwork)).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      if (!egressAlreadyExists(message)) throw error;
      return { stdout: "" };
    });
    await this.run(
      buildBrokerRunArgs({
        networkName,
        egressNetwork,
        brokerContainer,
        brokerImage: this.config.shadowBrokerImage,
        brokerCodeDir: brokerCodeDir(),
        configDir,
        logDir,
        pendingDir,
        protectedDir,
        runId: input.runId,
        agentId: input.agentId,
        runAsUser: brokerRunAsUser(),
      }),
      // the one place the real provider key crosses into a container, and it is the trusted one
      { ARK_API_KEY: this.config.arkApiKey, SHADOW_TURN_TOKEN: turnToken },
    );
    // Both networks were attached by `docker run` above. There is deliberately no
    // `docker network connect` here: that call is what raced the `--rm` reaper and killed turns
    // with "container is marked for removal and cannot be connected to the network".
    await this.waitForBroker(brokerContainer);

    return {
      runId: input.runId,
      networkName,
      egressNetwork,
      brokerContainer,
      proxyUrl: "http://broker:" + this.config.shadowBrokerProxyPort,
      noProxy: "broker,localhost,127.0.0.1",
      modelBaseUrl: "http://broker:" + this.config.shadowBrokerModelPort + "/v1",
      turnToken,
      netDir,
      logDir,
      pendingDir,
      allowlist,
      decoyHost: this.config.shadowDecoyHost,
    };
  }

  private async waitForBroker(brokerContainer: string): Promise<void> {
    const deadline = Date.now() + 20_000;
    let lastLog = "";
    let lastErr = "";
    while (Date.now() < deadline) {
      // Both streams. `broker.ready` is on stdout, but every reason it might NOT appear is on
      // stderr, and reading only stdout is what turned a one-line EACCES into a twenty-second
      // timeout reported as "did not become ready: " with nothing after the colon.
      const logs = await this.runBothStreams(["logs", brokerContainer]);
      const errs = logs.stderr;
      const gone = /No such container/.test(errs);
      lastLog = logs.stdout;
      // Keep the informative stderr. Once `--rm` reaps a crashed container the engine answers "No
      // such container", which would otherwise overwrite the crash that explains the whole failure.
      if (!gone && errs.trim()) lastErr = errs;
      if (lastLog.includes("broker.ready")) return;
      // It exited and was reaped. It is never going to print anything, so do not spend the deadline
      // waiting for a container that no longer exists.
      if (gone) break;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    const detail = (
      lastErr.trim() ||
      lastLog.trim() ||
      "the container printed nothing before it stopped"
    ).slice(-600);
    throw new Error("the egress broker did not become ready: " + detail);
  }

  /** Every write the broker deferred, as effects in the same set the file effects go into. */
  async heldEffects(sealed: SealedNetwork): Promise<EffectRecord[]> {
    const text = await fs
      .readFile(path.join(sealed.logDir, "held.jsonl"), "utf8")
      .catch(() => "");
    return parseJsonLines<HeldRecord>(text).map(heldRecordToEffect);
  }

  async decisions(sealed: SealedNetwork): Promise<EgressDecision[]> {
    const text = await fs
      .readFile(path.join(sealed.logDir, "egress.jsonl"), "utf8")
      .catch(() => "");
    return parseJsonLines<EgressDecision>(text);
  }

  async decisionSummary(sealed: SealedNetwork): Promise<Record<string, number>> {
    return summariseDecisions(await this.decisions(sealed));
  }

  /**
   * Sends the held writes for real, from inside the broker, so a committed outbound effect leaves
   * through exactly the same audited point as everything else and lands in the same decision log.
   */
  async replay(sealed: SealedNetwork, effectIds: string[]): Promise<{ replayed: number; failed: number }> {
    if (!effectIds.length) return { replayed: 0, failed: 0 };
    const result = await this.run([
      "exec",
      sealed.brokerContainer,
      "node",
      BROKER_PATHS.code + "/replay.mjs",
      "replay",
      BROKER_PATHS.pendingDir,
      BROKER_PATHS.decisionLog,
      ...effectIds,
    ]).catch((error: unknown) => ({ stdout: JSON.stringify({ results: [{ decision: "REPLAY_FAILED", reason: String(error) }] }) }));
    let replayed = 0;
    let failed = 0;
    for (const line of parseJsonLines<{ results?: Array<{ decision: string }> }>(result.stdout)) {
      for (const record of line.results ?? []) {
        if (record.decision === "REPLAYED") replayed += 1;
        else failed += 1;
      }
    }
    return { replayed, failed };
  }

  /** Unlinks every held payload. Discard, reject and conflict all land here. */
  async dropHeld(sealed: SealedNetwork): Promise<void> {
    await fs.rm(sealed.pendingDir, { recursive: true, force: true }).catch(() => undefined);
  }

  /**
   * Tears the turn's network down, and says whether it actually went.
   *
   * The first version swallowed the failure. `docker network rm` refuses while anything is still
   * attached, so one slow container teardown left the network behind, and the default address pool
   * is a few dozen /24 subnets: a long-running platform stops being able to seal a turn at all
   * after a few dozen of them. The suite that found this leaked eight networks in one run.
   *
   * So: force-disconnect whatever is still attached, retry, and report the outcome to the caller
   * for the journal instead of hiding it.
   */
  async release(sealed: SealedNetwork): Promise<{ removed: boolean; detail?: string }> {
    await this.run(["rm", "--force", sealed.brokerContainer]).catch(() => undefined);
    // Only the per-run network. The egress network is shared by every concurrent turn, so removing
    // it here would cut the broker of any turn still running. It is left in place deliberately: it
    // holds no state, one exists per host rather than per turn, and pruneStale skips it by name.
    return this.removeNetwork(sealed.networkName);
  }

  private async removeNetwork(networkName: string): Promise<{ removed: boolean; detail?: string }> {
    let lastError = "";
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        await this.run(["network", "rm", networkName]);
        return { removed: true };
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }
      const listed = await this.run([
        "network", "inspect", "--format",
        "{{range $id, $c := .Containers}}{{$id}} {{end}}", networkName,
      ]).catch(() => ({ stdout: "" }));
      const attached = listed.stdout.trim().split(/\s+/).filter(Boolean);
      if (!attached.length && attempt > 0) break;
      for (const id of attached) {
        await this.run(["network", "disconnect", "--force", networkName, id]).catch(() => undefined);
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    return { removed: false, detail: lastError.slice(0, 200) };
  }

  /**
   * Removes shadow networks nothing is attached to any more, once per process.
   *
   * A crash between creating a network and settling the turn leaks one, and the address pool is
   * finite. `docker network rm` refuses a network with active endpoints, so a turn running right
   * now is protected by the engine itself and needs no bookkeeping here.
   */
  async pruneStale(): Promise<number> {
    const listed = await this.run([
      "network", "ls", "--filter", "name=^shadow-", "--format", "{{.Name}}",
    ]).catch(() => ({ stdout: "" }));
    let removed = 0;
    for (const name of listed.stdout.trim().split("\n").map((n) => n.trim()).filter(Boolean)) {
      // the shared egress network is not per-run, so "no endpoints right now" does not mean stale:
      // the next turn to start will attach to it, and removing it mid-flight cuts a live broker
      if (name === EGRESS_NETWORK) continue;
      if (!(await this.isStale(name))) continue;
      const gone = await this.run(["network", "rm", name]).then(() => true).catch(() => false);
      if (gone) removed += 1;
    }
    return removed;
  }

  /**
   * A network is stale only once it is older than the grace window.
   *
   * The previous version removed every `shadow-` network it could, on the stated reasoning that
   * "docker network rm refuses a network with active endpoints, so a turn running right now is
   * protected by the engine itself". That is true only AFTER a container has attached. Between
   * `network create` and the broker joining it, the network has no endpoints and the engine will
   * remove it on request, so a second instance pruning at that moment deletes a live turn's network
   * and the turn dies with `network ... not found`. Reproduced by running the docker suite twice at
   * once; it is the same two-instances-one-resource defect the journal lock closed, in the network
   * namespace.
   *
   * Age is the discriminator that needs no shared state between instances: a network older than the
   * window cannot be in that create-to-attach gap, and one younger than it might be.
   */
  private async isStale(name: string): Promise<boolean> {
    const created = await this.run(["network", "inspect", name, "--format", "{{.Created}}"])
      .then((r) => Date.parse(r.stdout.trim()))
      .catch(() => Number.NaN);
    // Unreadable age means the network may have just been created by someone else, so leave it.
    if (Number.isNaN(created)) return false;
    return Date.now() - created > NETWORK_PRUNE_GRACE_MS;
  }
}

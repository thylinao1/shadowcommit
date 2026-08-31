import path from "node:path";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { AppConfig } from "./config.js";
import { ContainerCodexRunner } from "./container-codex-runner.js";
import { CodexRunner } from "./codex-runner.js";
import {
  TransactionalRunner,
  type TransactionalRunnerOptions,
  type TurnConfinement,
} from "./transactional-runner.js";
import { defaultPolicy } from "./shadow-policy.js";
import { capabilityGrantStoreFor } from "./capability-grants.js";
import { withCapabilityGrantRule } from "./capability-grant-rule.js";
import { createOverlaySealer } from "./overlay-sealer.js";
import { Journal } from "./journal.js";
import {
  EGRESS_NETWORK,
  NetworkSealer,
  brokerNameFor,
  networkNameFor,
  type SealedNetwork,
} from "./network-sealer.js";
import { CodexHomeManager, type SealedCodexHome } from "./codex-home.js";
import { parseJsonLines, summariseDecisions, type HeldRecord } from "./broker.js";
// The host-side half of the settle a held turn owes. Same module the broker container runs, so an
// approved write is sent by exactly the code that would have sent it inside the jail.
// @ts-expect-error plain ESM with no type declarations; the two functions used are documented here
import { dropAll, replayOne } from "../broker/replay.mjs";
// The very function the broker decided the hold with. A payload replayed from the host has to pass
// the same gate it would have passed inside the jail, so the check is the same code and not a
// second implementation of it that can drift into being more permissive.
// @ts-expect-error plain ESM with no type declarations; one function, host and port, exact match
import { allowlistDecision } from "../broker/broker-core.mjs";
import type { AgentRunner, RunnerRequest } from "./types.js";
import type { EffectRecord } from "./policy-types.js";

/**
 * Composed once, here, for every agent. This is the whole "for every agent, zero configuration"
 * claim: an agent created through the stock CRUD flow gets the sealed workspace, the sealed
 * network and the sealed memory because of this function and nothing else.
 */

interface TurnState {
  agentId: string;
  shadowDir: string;
  preTurnThreadId: string | null;
  network: SealedNetwork | null;
  codexHome: SealedCodexHome | null;
  settled: boolean;
}

/** What a held turn keeps between the review verdict and the operator's decision. */
interface ReviewState {
  agentId: string;
  network: SealedNetwork | null;
  codexHome: SealedCodexHome | null;
  preTurnThreadId: string | null;
  heldIds: string[];
  /** always <shadowRoot>/<runId>, derived from configuration and never read out of a file */
  shadowDir: string;
  /** what settle("review") counted, when this state came back from disk rather than memory */
  heldCountAtReview?: number;
  /**
   * Set only when this state was rebuilt from the on-disk record instead of held in memory.
   *
   * It is the difference between an input this process produced and an input anything that can
   * write a file produced, and the destructive halves of a settle are gated on it. Live state is
   * never marked, so nothing on the ordinary path changes.
   */
  fromRecord?: true;
  /**
   * Why the memory half was withheld, when it was. A recalled promote renames a directory over an
   * agent's real memory, so it runs only when the sealed `pre` snapshot still agrees with that
   * memory, and when it does not this says so instead of the settle going quiet.
   */
  codexHomeWithheld?: string | undefined;
}

/**
 * What a held turn leaves on disk, which is deliberately NOT a ReviewState.
 *
 * The first version persisted the ReviewState itself, paths included, and a settle obeyed those
 * paths. `promote()` renames a directory over the agent's real memory, so a record naming
 * CODEX_HOME as its realPath replaced every agent's memory at once, and the check in front of it
 * permitted exactly that value because "under the root" is true of the root. The lesson is not
 * that the check wanted one more clause. It is that a file the runner obeys must not be able to
 * name a location at all, because then there is no validator left to get wrong.
 *
 * So nothing in here is a path. Every path a settle acts on is rebuilt from configuration the
 * record cannot influence: the shadow is <shadowRoot>/<runId> for the run being settled, the
 * network's directories are that shadow's own, and the memory promoted into is whichever directory
 * CodexHomeManager.dirFor names for the agent. What is left is a hint: it says a review is
 * outstanding and which agent and thread it belongs to, and it is only ever consulted when this
 * process has no live state for the run.
 *
 * Taking the paths away was not enough, because naming is not the only authority a file can hold.
 * The record still named an AGENT, and `promote()` renames a directory over whichever agent is
 * named, so a record naming agent-b replaced agent-b's memory with content agent-a had staged: the
 * blast radius shrank from every agent to one chosen agent, which is the same primitive one turn
 * of the screw smaller. It still named the outbound PAYLOADS too, and the host-side replay sends
 * whatever URL it finds in them without re-checking the allowlist, so a planted payload was an
 * arbitrary request made by the platform itself.
 *
 * The rule this file now holds to is that the record decides nothing a destructive step depends
 * on. Each such step is corroborated by evidence whoever wrote the record could not have produced:
 *
 *   - the memory half runs only when the sealed `pre` snapshot still matches the named agent's
 *     real memory, which a genuine held turn has by construction (settle("review") restored that
 *     memory from that snapshot) and which a planter can only fake for an agent whose bytes it
 *     already knows, meaning its own;
 *   - the outbound half re-checks every payload's destination with `allowlistDecision`, the same
 *     function the broker held it with, because on the live path the payloads were written by the
 *     broker AFTER that decision and on this path that is exactly the step that is missing.
 *
 * Both are refusals and neither adds a capability, a file or a path, so the worst a wrong one can
 * do is send a settle down the loud "state lost" branch. That asymmetry is the point: a change
 * that can only refuse more cannot open a hole wider than the one it closed.
 */
interface ReviewHint {
  version: 1;
  agentId: string;
  preTurnThreadId: string | null;
  hasNetwork: boolean;
  hasCodexHome: boolean;
  /** so a recall that finds a different number of held payloads can say so instead of drifting */
  heldCount: number;
}

const REVIEW_HINT_VERSION = 1;

/** A run id that is safe as a single path component, the same shape RunnerStore accepts. */
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * A held payload's name, which `replayOne` joins onto the pending directory to find the bytes it
 * sends. Anything with a separator or a dot-dot in it would name a file outside that directory and
 * post it to the URL inside, so the set is narrow and both the live and the recalled path use it.
 */
const EFFECT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Where every run's shadow lives. One expression, shared by the runner and the confinement. */
export function shadowRootFor(config: AppConfig): string {
  return path.join(config.dataDirectory, "shadows");
}

/**
 * True when every component from `root` down to `candidate` is a real directory.
 *
 * `lstat` rather than `stat`, and every component rather than the leaf, because a symlinked
 * component is exactly how a path that looks like it is inside the shadow ends up naming somewhere
 * else. Nothing here trusts a name: it walks and looks.
 */
async function isRealDirectoryUnder(root: string, candidate: string): Promise<boolean> {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  if (relative.startsWith("..") || path.isAbsolute(relative)) return false;
  let walked = path.resolve(root);
  for (const part of relative === "" ? [] : relative.split(path.sep)) {
    walked = path.join(walked, part);
    const stats = await fs.lstat(walked).catch(() => null);
    if (!stats || !stats.isDirectory()) return false;
  }
  return true;
}

/**
 * A SealedNetwork rebuilt from a run id and that run's shadow, for the two paths that never got a
 * handle: the teardown of a seal whose `open()` threw, and the settle of a review this process did
 * not hold. Both names come from the sealer's own naming functions and every directory is this
 * run's own, so nothing here can point at anything the sealer did not make for this run.
 */
function sealedNetworkByName(runId: string, shadowDir: string): SealedNetwork {
  const netDir = path.join(shadowDir, "net");
  return {
    runId,
    networkName: networkNameFor(runId),
    egressNetwork: EGRESS_NETWORK,
    brokerContainer: brokerNameFor(runId),
    proxyUrl: "",
    noProxy: "",
    modelBaseUrl: "",
    turnToken: "",
    netDir,
    logDir: path.join(netDir, "log"),
    pendingDir: path.join(netDir, "pending"),
    allowlist: [],
    decoyHost: "",
  };
}

const execFileAsync = promisify(execFile);

/** The same binary the sealer runs, resolved the same way, for the one question it cannot answer. */
async function engineExec(file: string, args: string[]): Promise<{ stdout: string }> {
  const result = await execFileAsync(file, args, {
    timeout: 15_000,
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" },
  });
  return { stdout: String(result.stdout) };
}

/**
 * The network half and the memory half, wired into the decorator's hooks.
 *
 * Everything it does is per run and torn down with the run: the network, the broker container, the
 * held payloads and the per-turn copy of the agent's memory. Nothing survives a turn except what
 * the commit path deliberately promotes.
 */
export class ShadowConfinement implements TurnConfinement {
  private readonly turns = new Map<string, TurnState>();
  /**
   * Turns a human still owes a decision on.
   *
   * A review is not a verdict, so settle("review") tears down the live network and the broker
   * container, which must not be held for as long as a person takes, and keeps everything the
   * later decision needs: the held payloads under the sealed store, and the sealed codex-home
   * beside the shadow. approve() and reject() reach the same settle() and finish both halves from
   * here. Without this, an approved turn applied its files and left its held writes and its
   * memory on disk untouched, which is the half of the rollback nobody would have noticed.
   */
  private readonly awaitingReview = new Map<string, ReviewState>();

  constructor(
    private readonly config: AppConfig,
    private readonly sealer: NetworkSealer,
    private readonly codexHomes: CodexHomeManager,
    private readonly options: {
      sealNetwork: boolean;
      /**
       * The runner's own shadow root, handed in by the composition root so the runner and the
       * confinement cannot disagree about where a run's shadow is. Recall rebuilds every path from
       * it, which is why it is code that decides this and never a file.
       */
      shadowRoot?: string;
      /**
       * The container engine, for the one question `release()` does not answer: whether the broker
       * container is actually gone. Defaults to the same binary the sealer runs.
       */
      exec?: (file: string, args: string[]) => Promise<{ stdout: string }>;
    },
  ) {}

  private get shadowRoot(): string {
    return this.options.shadowRoot ?? shadowRootFor(this.config);
  }

  async open(input: {
    runId: string;
    request: RunnerRequest;
    shadowDir: string;
  }): Promise<{ request: RunnerRequest; note: Record<string, unknown> }> {
    const { runId, request, shadowDir } = input;
    // With the network sealed, the model channel is terminated at the broker and the container is
    // given a one-turn token. Without it, the turn talks to the provider directly and needs the
    // real key: handing it a token no broker will ever see would 401 every call.
    const modelBaseUrl = this.options.sealNetwork
      ? "http://broker:" + this.config.shadowBrokerModelPort + "/v1"
      : this.config.arkBaseUrl;

    // The agent's memory is regenerated and then sealed BEFORE the turn: a config.toml a previous
    // turn repointed at a host it controls has a lifetime of zero turns, and the directory the
    // turn actually mounts is a copy, so the real one is not reachable from inside the container.
    await this.codexHomes.prepare(request.agentId, modelBaseUrl);
    const codexHome = await this.codexHomes.seal(request.agentId, shadowDir);

    let network: SealedNetwork | null = null;
    let networkError: string | null = null;
    if (this.options.sealNetwork) {
      try {
        network = await this.sealer.open({
          runId,
          agentId: request.agentId,
          shadowDir,
          workspacePath: request.workspacePath,
        });
      } catch (error) {
        networkError = error instanceof Error ? error.message : String(error);
        // Fail closed on the thing we can control: if the seal did not come up, the turn does not
        // get a container on the default bridge as a consolation prize. The memory rollback is
        // local and immediate, so it goes first and is never held up by an engine that has stopped
        // answering.
        await this.codexHomes.restore(codexHome).catch(() => undefined);
        // Then whatever the sealer reached before it threw, which is ours to reap. `open()`
        // creates the network and then runs the broker with the real provider key and a mounted
        // plaintext copy of every protected file, so a throw after that point (the CLI timing out,
        // the broker never reporting ready) used to leave all of it running: this catch restored
        // the codex-home and rethrew, `network` was still null so the handle was discarded, and
        // nothing else reaps a broker. pruneStale only enumerates networks, and the still-attached
        // broker is exactly what makes `network rm` fail for that network for as long as it lives.
        const reaped = await this.reapPartialSeal(runId, shadowDir);
        throw new Error(
          "the sealed network could not be created: " +
            networkError +
            (reaped.removed
              ? " (the partial seal was torn down: the network is removed and the broker container is confirmed gone)"
              : " (the partial seal was NOT fully torn down: " + (reaped.detail ?? "unknown") + ")"),
        );
      }
    }

    this.turns.set(runId, {
      agentId: request.agentId,
      shadowDir,
      preTurnThreadId: request.threadId,
      network,
      codexHome,
      settled: false,
    });

    const confined: RunnerRequest = network
      ? {
          ...request,
          confinement: {
            runId,
            networkName: network.networkName,
            proxyUrl: network.proxyUrl,
            noProxy: network.noProxy,
            turnToken: network.turnToken,
            codexHomePath: codexHome.livePath,
          },
        }
      : {
          ...request,
          confinement: {
            runId,
            networkName: null,
            proxyUrl: null,
            noProxy: null,
            turnToken: null,
            codexHomePath: codexHome.livePath,
          },
        };

    // Whether anything actually proved a container runtime exists.
    //
    // A live sealed network is that proof: the sealer created a network and ran a broker, which
    // only an engine that answered could have done. Without one, NOTHING here has contacted the
    // engine, and `RUNTIME_PROVIDER=container` is a line in a config file rather than a fact about
    // the host. The note used to say "container" on the strength of that line alone.
    //
    // Measured on a host with no engine installed, RUNTIME_PROVIDER=container,
    // SHADOW_CONFINE_NETWORK=false, SHADOW_ALLOW_UNCONFINED=1: the note read
    // `confinement:"container"`, `containerWorkspacePath:"/workspace"`,
    // `containerCodexHome:"/codex-home"`, and no container existed for any of it.
    //
    // The test one screen below this is called "names the weaker confinement instead of implying
    // the stronger one", and its comment says journaling an unsealed turn as
    // "container+sealed-network" would be the one lie this product cannot afford. This is that
    // same argument one rung lower: implying a container when none was verified is the same lie
    // about a bigger claim, because the kill switch rests on the container and not on the network.
    const engine = network !== null
      ? { verified: true, detail: null as string | null }
      : await this.engineResponds();

    return {
      request: confined,
      note: {
        // What the turn is actually inside, named, so a reader never has to infer it. When nothing
        // verified an engine, this says "none" for the same reason the host-process path does.
        confinement: network ? "container+sealed-network" : engine.verified ? "container" : "none",
        // SL01: the container-visible workspace path, recorded so the invariant is checkable
        // rather than assumed. Nothing here derives from the shadow root or the run id. Null when
        // there is no verified container, because the path inside a thing that does not exist is
        // not a checkable invariant, it is decoration.
        containerWorkspacePath: engine.verified ? "/workspace" : null,
        containerCodexHome: engine.verified ? "/codex-home" : null,
        // Stated rather than implied, so a reader and a gate can both ask the question directly
        // instead of inferring it from the mode word.
        containerEngineVerified: engine.verified,
        ...(engine.detail === null ? {} : { confinementDegraded: engine.detail }),
        network: network?.networkName ?? null,
        egressAllowlist: network?.allowlist ?? null,
        decoyHost: network?.decoyHost ?? null,
        modelChannel: network ? "terminated-at-broker" : "direct",
        codexHomeFiles: codexHome.preFiles,
      },
    };
  }

  /**
   * Does a container engine actually answer on this host.
   *
   * Runs the configured engine through the same `exec` seam `reapPartialSeal` uses, so a test can
   * drive both the answering and the absent case on any machine. That matters more than usual
   * here: a guard that only fails on a host without an engine is a guard that regresses silently
   * on every host that has one, which is the exact failure this whole change is about.
   *
   * Presence on PATH is deliberately NOT the test. On this author's Windows host `wsl` is on PATH,
   * exits 0, and has no distribution installed, which is what a PATH check would have believed.
   */
  private async engineResponds(): Promise<{ verified: boolean; detail: string | null }> {
    const exec = this.options.exec ?? engineExec;
    try {
      await exec(this.config.containerEngine, ["info"]);
      return { verified: true, detail: null };
    } catch (error) {
      const why = error instanceof Error ? error.message.split("\n")[0] : String(error);
      return {
        verified: false,
        detail:
          "RUNTIME_PROVIDER=container but `" +
          this.config.containerEngine +
          " info` did not answer, so no container was verified for this turn: " +
          why,
      };
    }
  }

  async outboundEffects(runId: string): Promise<EffectRecord[]> {
    const state = this.turns.get(runId);
    if (!state?.network) return [];
    return this.sealer.heldEffects(state.network);
  }

  async settle(
    runId: string,
    decision: "commit" | "discard" | "review" | "conflict",
  ): Promise<{ note?: Record<string, unknown>; threadId?: string | null }> {
    // Live state outranks the disk, and the ORDER is the guarantee rather than a preference.
    // Reading the record first let one planted for a run that was open at that moment send its
    // settle down the reviewed path, which never calls `sealer.release`: that turn's network and
    // its broker survived the settle for good and no egress summary was ever recorded. A run id
    // cannot be both live and waiting on a person, so the live map answers first and the record is
    // only ever the fallback for a process that no longer holds the turn.
    const state = this.turns.get(runId);
    if (!state) {
      const waiting = this.awaitingReview.get(runId) ?? (await this.recallReview(runId));
      if (waiting) return this.settleReviewed(runId, waiting, decision);
    }
    if (!state || state.settled) {
      // Nothing in this process, and nothing on disk, knows this run. That used to return an empty
      // note, which lands in the journal looking exactly like a turn that had no network half and
      // no memory half to settle. Saying it happened is the difference between a record that is
      // wrong and a record that is incomplete and says so.
      return {
        note: {
          confinementStateLost: true,
          confinementStateLostDetail:
            "no sealed network or codex-home state was found for this run, so only the files " +
            "half of this settle happened",
        },
      };
    }
    state.settled = true;
    this.turns.delete(runId);
    const note: Record<string, unknown> = {};
    let heldForReview: string[] = [];

    if (state.network) {
      note.egress = await this.sealer.decisionSummary(state.network);
      if (decision === "commit") {
        const ids = await this.heldIds(state.network);
        const replayed = await this.sealer.replay(state.network, ids);
        note.outboundReplayed = replayed.replayed;
        note.outboundFailed = replayed.failed;
        await this.sealer.dropHeld(state.network);
      } else if (decision === "review") {
        // The payloads stay in the sealed store beside the shadow so an approval can still send
        // them; the network and the broker do not, because a turn waiting on a human must not
        // hold a container for as long as the human takes.
        heldForReview = await this.heldIds(state.network);
        note.outboundHeldForReview = heldForReview.length;
      } else {
        const ids = await this.heldIds(state.network);
        note.outboundDropped = ids.length;
        await this.sealer.dropHeld(state.network);
      }
      const released = await this.sealer.release(state.network);
      if (!released.removed) note.networkLeaked = state.network.networkName;
    }

    if (state.codexHome) {
      if (decision === "commit") {
        note.codexHome = await this.codexHomes.promote(state.codexHome);
      } else {
        // Review restores too. The agent's memory is rolled back WHILE the turn waits, because a
        // turn nobody has approved has not happened yet; the sealed copy survives beside the
        // shadow, so an approval promotes it and a rejection simply leaves the rollback standing.
        const restored = await this.codexHomes.restore(state.codexHome);
        note.codexHome = { restored: restored.restored, verifiedUnchanged: restored.verified };
      }
    }

    if (decision === "review") {
      const held: ReviewState = {
        agentId: state.agentId,
        network: state.network,
        codexHome: state.codexHome,
        preTurnThreadId: state.preTurnThreadId,
        heldIds: heldForReview,
        shadowDir: state.shadowDir,
      };
      this.awaitingReview.set(runId, held);
      // A review waits on a person, and a person takes hours, so the process that held the turn is
      // not the one that will settle it. In memory alone, approve() after a restart found nothing
      // here, applied the files, deleted the held payloads without sending them and left the
      // agent's memory rolled back, under a turn.committed record indistinguishable from a turn
      // that had neither half.
      const notPersisted = await this.rememberReview(runId, held);
      if (notPersisted) {
        note.reviewRecordNotPersisted = true;
        note.reviewRecordNotPersistedDetail = notPersisted;
      }
    } else {
      // This settle was authoritative for the run, so any record from an earlier one is stale by
      // definition and must not be left where a later settle would fall back to it.
      await this.forgetReview(runId);
    }

    // On commit the gate reduces to identity, so the thread id the turn returned is the right one
    // and settle says nothing about it. On any other verdict the memory has been rolled back, so
    // the caller must be handed the thread the turn STARTED from, or the next turn resumes a
    // conversation whose files no longer exist. Returning the key at all is what overrides.
    if (decision === "commit") return { note };
    return {
      note,
      threadId: this.codexHomes.gateThreadId(state.preTurnThreadId, null, decision),
    };
  }

  /**
   * The second half of a held turn's settle, run when the operator finally decides.
   *
   * The broker container is gone by now, so a replay cannot go through it and goes from the host
   * instead, using the same `replayOne` the broker runs and writing into the same decision log.
   * That is a real narrowing of the guarantee and it is stated rather than hidden: an approved
   * outbound write leaves the host directly, having been allowlisted and recorded when the turn
   * made it, not re-checked at the moment it is sent.
   */
  private async settleReviewed(
    runId: string,
    waiting: ReviewState,
    decision: "commit" | "discard" | "review" | "conflict",
  ): Promise<{ note?: Record<string, unknown>; threadId?: string | null }> {
    if (decision === "review") return {};
    this.awaitingReview.delete(runId);
    // Dropped before the work rather than after it, so a crash in the middle cannot leave a record
    // a second settle would act on: an outbound write is sent at most once, and the payloads that
    // did not go stay in the sealed store where nothing sends them.
    await this.forgetReview(runId);
    const note: Record<string, unknown> = { settledAfterReview: true };

    if (waiting.codexHomeWithheld) {
      // The record asked for a promote and the corroboration refused it. Said here, in the record
      // the operator reads, because a memory half that did not happen and does not say so is the
      // silence this whole path exists to end.
      note.codexHomeWithheld = waiting.codexHomeWithheld;
    }

    if (waiting.network) {
      // The payload names come from the sealed log the broker itself wrote, not from the record,
      // so a record cannot name a payload. The count is a different question: a set that has moved
      // since the review is not the set the operator approved, so on a recalled settle it is a
      // refusal rather than a line in a note. Nothing is dropped either, because the payloads are
      // then the evidence of whatever moved them.
      const countMoved =
        waiting.heldCountAtReview !== undefined && waiting.heldCountAtReview !== waiting.heldIds.length;
      if (countMoved) {
        note.outboundHeldCountChanged = {
          atReview: waiting.heldCountAtReview,
          atSettle: waiting.heldIds.length,
        };
      }
      if (decision === "commit" && countMoved) {
        note.outboundRefused = waiting.heldIds.length;
        note.outboundRefusedReason =
          "the held set is not the one the review counted, so none of it was sent and none of it " +
          "was dropped";
      } else if (decision === "commit") {
        // On the live path these bytes were written by the broker after it allowed the destination.
        // Recalled, that decision is the missing step, so it is made again here with the broker's
        // own function before anything leaves the host.
        const sendable = waiting.fromRecord
          ? await this.allowlistedOnly(waiting.network, waiting.heldIds)
          : { send: waiting.heldIds, refused: [] as Array<{ effectId: string; detail: string }> };
        let replayed = 0;
        let failed = 0;
        for (const effectId of sendable.send) {
          const result = (await replayOne(
            waiting.network.pendingDir,
            effectId,
            path.join(waiting.network.logDir, "egress.jsonl"),
          )) as { decision?: string } | undefined;
          if (result?.decision === "REPLAYED") replayed += 1;
          else failed += 1;
        }
        note.outboundReplayed = replayed;
        note.outboundFailed = failed;
        if (sendable.refused.length) {
          note.outboundRefusedNotAllowlisted = sendable.refused.length;
          note.outboundRefusedDetail = sendable.refused.map((entry) => entry.detail);
        }
      } else {
        note.outboundDropped = dropAll(waiting.network.pendingDir);
      }
      // Kept when a refusal kept them: the directory is inside this run's own shadow either way,
      // and a payload nobody sent and nobody looked at is worth more than a tidy directory.
      if (!(decision === "commit" && (countMoved || note.outboundRefusedNotAllowlisted))) {
        await fs.rm(waiting.network.pendingDir, { recursive: true, force: true }).catch(() => undefined);
      }
    }

    if (waiting.codexHome) {
      note.codexHome =
        decision === "commit"
          ? await this.codexHomes.promote(waiting.codexHome)
          : { restored: false, verifiedUnchanged: true, droppedAfterReview: true };
    }

    if (decision === "commit") return { note };
    return { note, threadId: this.codexHomes.gateThreadId(waiting.preTurnThreadId, null, decision) };
  }

  /**
   * The held payloads a recalled commit may actually send, which is the ones whose destination the
   * broker would have allowed.
   *
   * `replayOne` reads the URL out of the payload file and opens a socket to it. Inside the jail
   * that is safe because the broker wrote the file only after `allowlistDecision` said yes; from
   * the host, on a record this process did not write, that decision has never been made for these
   * bytes. So it is made here, with the sealer's own list and the broker's own comparison, and a
   * payload that cannot even be read is refused rather than handed on.
   */
  private async allowlistedOnly(
    network: SealedNetwork,
    effectIds: string[],
  ): Promise<{ send: string[]; refused: Array<{ effectId: string; detail: string }> }> {
    const allowlist = this.sealer.allowlistFor();
    const send: string[] = [];
    const refused: Array<{ effectId: string; detail: string }> = [];
    for (const effectId of effectIds) {
      const raw = await fs
        .readFile(path.join(network.pendingDir, effectId + ".json"), "utf8")
        .catch(() => null);
      if (raw === null) {
        refused.push({ effectId, detail: effectId + ": the held payload could not be read" });
        continue;
      }
      let url: URL;
      try {
        url = new URL((JSON.parse(raw) as { url?: string }).url ?? "");
      } catch {
        refused.push({ effectId, detail: effectId + ": the held payload names no usable URL" });
        continue;
      }
      // The same defaulting `replayOne` uses, so the port checked is the port dialled.
      const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
      if (allowlistDecision(allowlist, url.hostname, port)) {
        send.push(effectId);
        continue;
      }
      refused.push({
        effectId,
        detail: effectId + ": " + url.hostname + ":" + port + " is not on the egress allowlist",
      });
    }
    return { send, refused };
  }

  private async heldIds(network: SealedNetwork): Promise<string[]> {
    const text = await fs
      .readFile(path.join(network.logDir, "held.jsonl"), "utf8")
      .catch(() => "");
    return parseJsonLines<HeldRecord>(text)
      .map((record) => record.effectId)
      .filter((effectId) => EFFECT_ID.test(effectId));
  }

  /**
   * Tears down the half-built seal for a run whose `open()` threw, by name.
   *
   * The names come from the same two functions the sealer derives them with, so the teardown can
   * name objects it never received a handle to. `release()` reads the container and the network
   * name and nothing else; the rest of this record is this run's own paths, so nothing here points
   * anywhere the sealer did not. The protected copies go with it: they are plaintext copies of the
   * files the broker scans against, written before the container starts, and the shadow they sit
   * in belongs to a turn that will never run.
   */
  private async reapPartialSeal(
    runId: string,
    shadowDir: string,
  ): Promise<{ removed: boolean; detail?: string }> {
    const partial = sealedNetworkByName(runId, shadowDir);
    const reaped = await this.sealer.release(partial).catch((error: unknown) => ({
      removed: false,
      detail: error instanceof Error ? error.message : String(error),
    }));
    await fs.rm(partial.netDir, { recursive: true, force: true }).catch(() => undefined);
    // "no such network" is the state this call wanted, the same way "already exists" is the
    // success case when the shared egress network is created. Most of the throws that land here
    // happen before anything was created at all, and reporting those as a leak would teach a
    // reader to ignore the line that means one.
    const networkGone = reaped.removed || /not found|no such/i.test(reaped.detail ?? "");
    // `release()` describes the NETWORK. It runs `rm --force` on the broker first and swallows the
    // failure, then force-disconnects whatever is attached and retries, so `network rm` can
    // succeed over a container that is still up holding ARK_API_KEY and the plaintext copies of
    // every protected file. Reading that one boolean and telling the operator the seal was gone
    // announced the very leak this path exists to close, so the container is asked about directly.
    const broker = await this.brokerIsGone(partial.brokerContainer);
    if (networkGone && broker.confirmed) return { removed: true };
    if (!networkGone) {
      return {
        removed: false,
        detail:
          "the network " + partial.networkName + " was not removed (" + (reaped.detail ?? "unknown") +
          "), and " + broker.detail,
      };
    }
    return {
      removed: false,
      detail: "the network was removed but " + broker.detail,
    };
  }

  /**
   * Whether the broker container is gone, asked of the engine rather than inferred from a sibling
   * call's return value.
   *
   * `container inspect` is the one that answers by failing: a real engine exits nonzero with "no
   * such container" when it is gone and prints a status when it is not. An engine that cannot be
   * reached, or one that answers with nothing, has not said the container is gone, so both come
   * back unconfirmed. Absence of evidence is not the evidence this message needs.
   */
  private async brokerIsGone(brokerContainer: string): Promise<{ confirmed: boolean; detail: string }> {
    const exec = this.options.exec ?? engineExec;
    try {
      const listed = await exec(this.config.containerEngine, [
        "container", "inspect", "--format", "{{.State.Status}}", brokerContainer,
      ]);
      const status = listed.stdout.trim();
      if (!status) {
        return {
          confirmed: false,
          detail: "the broker container " + brokerContainer + " was not confirmed gone: the engine returned no status for it",
        };
      }
      return {
        confirmed: false,
        detail: "the broker container " + brokerContainer + " is still " + status,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (/no such (container|object)/i.test(message)) {
        return { confirmed: true, detail: "the broker container is confirmed gone" };
      }
      return {
        confirmed: false,
        detail:
          "the broker container " + brokerContainer + " was not confirmed gone: the engine could not be asked (" +
          message.slice(0, 160) + ")",
      };
    }
  }

  private reviewRecordPath(runId: string): string | null {
    if (!RUN_ID.test(runId)) return null;
    return path.join(this.config.dataDirectory, "review-confinement", runId + ".json");
  }

  /**
   * Written whole to a temporary name and renamed into place, so a crash cannot leave a
   * half-written record that a later settle would read as instructions.
   *
   * Returns the reason nothing was written, when nothing was, so the caller can put it in the
   * journal. Losing the restart case loudly beats writing a record whose meaning depends on a
   * topology nobody checked.
   */
  private async rememberReview(runId: string, state: ReviewState): Promise<string | null> {
    const target = this.reviewRecordPath(runId);
    if (!target) return "the run id is not usable as a file name, so nothing was written";
    // Recall rebuilds every path from <shadowRoot>/<runId>. If this run's shadow is not there, a
    // later settle would rebuild directories belonging to some other turn, so no record is written
    // at all and the turn's own record says the restart case is not covered for it.
    const derived = path.join(this.shadowRoot, runId);
    if (path.resolve(derived) !== path.resolve(state.shadowDir)) {
      return (
        "this run's shadow is " + state.shadowDir + ", not " + derived +
        ", so a later process could not rebuild it from configuration"
      );
    }
    const hint: ReviewHint = {
      version: REVIEW_HINT_VERSION,
      agentId: state.agentId,
      preTurnThreadId: state.preTurnThreadId,
      hasNetwork: state.network !== null,
      hasCodexHome: state.codexHome !== null,
      heldCount: state.heldIds.length,
    };
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target + ".tmp", JSON.stringify(hint), { encoding: "utf8", mode: 0o600 });
    await fs.rename(target + ".tmp", target);
    return null;
  }

  private async forgetReview(runId: string): Promise<void> {
    const target = this.reviewRecordPath(runId);
    if (!target) return;
    await fs.rm(target, { force: true }).catch(() => undefined);
  }

  /**
   * Rebuilds the state of a held turn this process never saw, after the restart the record exists
   * for, and reads the record for as little as possible while doing it.
   *
   * A settle reaches `promote()`, which renames a directory over the agent's real memory, and
   * `rm()`, which deletes one. The first version let the file name the directories those act on
   * and checked the names afterwards, which is how a record naming CODEX_HOME itself passed a
   * check whose whole job was to refuse it. Nothing is named here. The shadow is this run's own,
   * the network's directories are that shadow's, the memory is whichever directory the manager
   * names for the agent, and the payload names come from the sealed log the broker wrote. The file
   * contributes an agent id, a thread id, two booleans and a count.
   *
   * The directories are then walked rather than assumed: a held turn's shadow is deliberately not
   * released until the operator decides, so if it or the sealed copy inside it is missing, or any
   * component of the way down is a symlink, this record has outlived the state it describes and
   * the settle takes the loud "state lost" branch instead of acting on it.
   */
  private async recallReview(runId: string): Promise<ReviewState | null> {
    const target = this.reviewRecordPath(runId);
    if (!target) return null;
    const raw = await fs.readFile(target, "utf8").catch(() => null);
    if (raw === null) return null;
    let hint: ReviewHint;
    try {
      hint = JSON.parse(raw) as ReviewHint;
    } catch {
      return null;
    }
    if (!hint || typeof hint !== "object") return null;
    if (hint.version !== REVIEW_HINT_VERSION) return null;
    if (typeof hint.agentId !== "string" || hint.agentId.length === 0 || hint.agentId.length > 200) return null;
    if (hint.preTurnThreadId !== null && typeof hint.preTurnThreadId !== "string") return null;
    if (!Number.isInteger(hint.heldCount) || hint.heldCount < 0) return null;
    if (typeof hint.hasNetwork !== "boolean" || typeof hint.hasCodexHome !== "boolean") return null;

    const shadowDir = path.join(this.shadowRoot, runId);
    if (!(await isRealDirectoryUnder(this.shadowRoot, shadowDir))) return null;

    const network = hint.hasNetwork ? sealedNetworkByName(runId, shadowDir) : null;
    let codexHome: SealedCodexHome | null = null;
    let codexHomeWithheld: string | undefined;
    if (hint.hasCodexHome) {
      const base = path.join(shadowDir, "codex-home");
      const livePath = path.join(base, "live");
      const prePath = path.join(base, "pre");
      // CodexHomeManager.seal writes all of these. If that layout ever moves, this misses and the
      // settle says the state was lost rather than promoting a directory nobody sealed.
      if (!(await isRealDirectoryUnder(this.shadowRoot, livePath))) return null;
      if (!(await isRealDirectoryUnder(this.shadowRoot, prePath))) return null;
      // The directory the promote renames over, named by the manager rather than by the record.
      // It has to be there: `prepare()` creates it before every seal, so an agent whose memory
      // does not exist is an agent no turn was ever sealed for, and `promote()` would throw ENOENT
      // half way through instead of this settle saying plainly that it has no state to act on.
      const realPath = this.codexHomes.dirFor(hint.agentId);
      if (!(await isRealDirectoryUnder(this.config.codexHome, realPath))) return null;
      const [pre, real] = await Promise.all([
        this.codexHomes.signature(prePath),
        this.codexHomes.signature(realPath),
      ]);
      codexHome = {
        agentId: hint.agentId,
        realPath,
        livePath,
        prePath,
        preDigest: pre.digest,
        preFiles: pre.files,
      };
      // The corroboration, and the reason the record can no longer choose a victim. A genuine held
      // turn has this by construction: settle("review") restored the agent's memory from this very
      // snapshot, so the two agree until something else changes that memory. A planted record aimed
      // at another agent has to make the snapshot match memory it was never allowed to read, and a
      // real turn that lost the race to a later commit for the same agent is refused by the same
      // line, because promoting over it would destroy that commit as quietly as the attack would.
      if (pre.digest !== real.digest) {
        codexHomeWithheld =
          "the sealed snapshot for " + hint.agentId + " no longer matches that agent's memory (" +
          pre.files + " files sealed, " + real.files + " now), so the memory half of this settle " +
          "was not applied";
        codexHome = null;
      }
    }
    return {
      agentId: hint.agentId,
      network,
      codexHome,
      preTurnThreadId: hint.preTurnThreadId,
      heldIds: network ? await this.heldIds(network) : [],
      shadowDir,
      heldCountAtReview: hint.heldCount,
      fromRecord: true,
      codexHomeWithheld,
    };
  }
}

/** Journal-shaped counts of what the broker decided, for anything that wants them out of band. */
export { summariseDecisions };

export function createRunner(config: AppConfig): TransactionalRunner {
  const container = config.runtimeProvider === "container";

  // The decorator is bookkeeping, never isolation. A host process has a starting directory and no
  // jail: it can walk out of the workspace and delete the very journal that would have recorded
  // it (a33), and a detached daemon it leaves behind outlives the discard (a36). Wrapping that in
  // a transaction produces a clean-looking audit trail for an unconfined runtime, which is worse
  // than no audit trail. So it is refused by default, and when an operator overrides it every turn
  // says so in the journal.
  if (!container && !config.shadowAllowUnconfined) {
    throw new Error(
      "refusing to run agents unconfined: RUNTIME_PROVIDER=" +
        config.runtimeProvider +
        " is a host process with no isolation, so a turn can leave the workspace and the " +
        "transaction cannot contain it. Set RUNTIME_PROVIDER=container, or set " +
        "SHADOW_ALLOW_UNCONFINED=1 to accept that every turn is journaled confinement:\"none\".",
    );
  }

  // The same refusal for the other unconfined path, which had no gate at all. With
  // RUNTIME_PROVIDER=container and SHADOW_CONFINE_NETWORK=false the agent container joins the
  // default bridge and container-codex-runner hands it `turnToken || config.arkApiKey`, so with no
  // token minted the REAL provider key lands in the untrusted runtime's environment. Those are
  // issues #3 and #4 and they are one root cause: a supported mode that gives away both the network
  // and the credential while the journal still shows a contained-looking turn.
  //
  // The secure default already covers the normal case, and a default is not a control. The host
  // path above refuses unless an operator says the word; this path now asks for the same word, so
  // the two unconfined routes are gated the same way rather than one of them being an oversight.
  if (container && !config.shadowConfineNetwork && !config.shadowAllowUnconfined) {
    throw new Error(
      "refusing to run agents with the network unsealed: SHADOW_CONFINE_NETWORK=false puts the " +
        "agent container on the default bridge with unrestricted egress, and hands it the real " +
        "provider credential because no per-turn token is minted. Set SHADOW_CONFINE_NETWORK=true, " +
        'or set SHADOW_ALLOW_UNCONFINED=1 to accept that every turn is journaled network:null.',
    );
  }

  const inner: AgentRunner = container ? new ContainerCodexRunner(config) : new CodexRunner(config);

  // One shadow root, handed to the runner and to the confinement from here. The confinement
  // rebuilds a held turn's paths from it after a restart, so the two agreeing is a property of the
  // composition rather than of two expressions that happen to match today.
  const shadowRoot = shadowRootFor(config);

  const confinement: TurnConfinement | undefined = container
    ? new ShadowConfinement(
        config,
        new NetworkSealer(config),
        new CodexHomeManager(config),
        { sealNetwork: config.shadowConfineNetwork, shadowRoot },
      )
    : unconfinedConfinement();

  const journalPath = path.join(config.dataDirectory, "journal.jsonl");

  /**
   * Where the sealer's own records go.
   *
   * It is a forwarder because the runner owns the journal and is built second, and nothing calls
   * emit before a turn runs. Without it the sealer was constructed with no `emit` at all, so
   * `seal.capability`, `seal.fallback`, `seal.refused`, `seal.mounted` and the `seal.release` that
   * records a shadow quarantined because its teardown could not be proven all went to
   * `() => undefined`, while the release hook below drops the structured result. A shadow renamed
   * into `.orphan` left no trace anywhere, in a product whose claim is that the journal says what
   * really happened.
   */
  let journalSink: (record: Record<string, unknown>) => void = () => undefined;

  // The seal, the teardown that owns the unmount, and the flag asserting that teardown exists come
  // out of ONE expression and are spread in together. `releaseHookWired` is what arms the overlay
  // path, and it used to be declared here while the hook was wired thirty lines away, so removing
  // the hook left the flag still claiming the composition was safe: the sealer would mount an
  // overlay and the runner would tear it down with the weaker default, which is the exact
  // composition createOverlaySealer was written to refuse.
  //
  // An overlay costs the same few milliseconds whether the workspace holds fifty files or thirty
  // thousand, and its upper layer IS the effect set; a copy costs O(files) and has to be walked to
  // find out what changed. The sealer proves the host can mount AND unmount before it returns
  // "overlay", and falls back to the copy everywhere else, so this composition is safe on hosts
  // that cannot do it: the demo Mac's virtiofs, for instance, brings an overlay up read-only and
  // is refused by name.
  const sealed = ((): Pick<TransactionalRunnerOptions, "seal" | "release"> => {
    const sealer = createOverlaySealer({
      shadowRoot,
      releaseHookWired: true,
      emit: (record) => journalSink(record),
    });
    return {
      seal: sealer.seal,
      // Whoever mounted it owns the unmount. This release proves nothing is mounted at or under
      // the shadow before it deletes, and quarantines rather than deleting when it cannot prove
      // it. The hook is void-returning, so the structured result is dropped here deliberately
      // rather than by accident: every field of it reaches the journal through the emit above.
      release: async (shadowDir, mechanism) => {
        await sealer.release(shadowDir, mechanism);
      },
    };
  })();

  const runner = new TransactionalRunner(inner, {
    shadowRoot,
    journalPath,
    stateRoot: config.dataDirectory,
    // a held record naming anything outside these two roots is refused before it is acted on
    workspaceRoot: config.workspaceRoot,
    // the platform's own secrets, so a turn writing one into a file is recognisable as that
    platformSecrets: [config.arkApiKey, config.authToken].filter((value) => value.length > 0),
    // Authorization runs BEFORE the content rules and can only make the answer stricter: an
    // out-of-scope path, symlink target, destination or budget goes to review, and a content
    // discard is never masked by an authorized grant. A capability answers "was this agent allowed
    // to do this at all", which no amount of reading the bytes can answer.
    policy: withCapabilityGrantRule(capabilityGrantStoreFor(config.dataDirectory), defaultPolicy),
    confinement,
    ...sealed,
  });

  // acquire() hands back the one writer the runner just took for this path, so the sealer's
  // records extend that chain instead of forking a second one onto the same file. The append is
  // fire and forget because emit is: the only way it rejects is a ledger that may not be extended,
  // and a runner in that state refuses the turn before any of this runs.
  const journal = Journal.acquire({ journalPath });
  journalSink = (record) => void journal.append(record).catch(() => undefined);

  return runner;
}

/**
 * The override path. It seals nothing, and its entire job is to make sure the journal says so on
 * every single turn instead of once at boot where nobody reading a record will see it.
 */
export function unconfinedConfinement(): TurnConfinement {
  return {
    async open(input) {
      return {
        request: input.request,
        note: {
          confinement: "none",
          reason: "SHADOW_ALLOW_UNCONFINED=1: host-process runtime, no network or filesystem jail",
          containerWorkspacePath: null,
        },
      };
    },
    async outboundEffects() {
      return [];
    },
    async settle() {
      return { note: { confinement: "none" } };
    },
  };
}

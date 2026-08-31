import { describe, expect, it } from "vitest";
import {
  buildBrokerRunArgs,
  buildEgressCreateArgs,
  buildNetworkCreateArgs,
  EGRESS_NETWORK,
  networkNameFor,
} from "./network-sealer.js";

/**
 * The broker used to reach the world by `docker network connect bridge <broker>` AFTER it was
 * already running. The broker runs with `--rm`, so the engine can mark it for removal at any point
 * once its main process ends, and the attach then fails with "is marked for removal and cannot be
 * connected or disconnected to the network". The sealer treated that as fatal, so a legitimate turn
 * died with "the sealed network could not be created". It showed up as a CI flake and it was not
 * one: the same sequence runs on every real turn.
 *
 * The window is gone because both networks are attached by `docker run` itself. That is only
 * possible because the second one is user-defined: the engine refuses to combine the default
 * `bridge` with a user-defined network in one run, which is why the old code had to attach late.
 *
 * These assert the shape of the commands, which is where the defect lived. The live behaviour (the
 * broker alias still resolving on the internal network, and an agent on the internal network alone
 * still having no route out) is covered by the container-gated suite in network-docker.test.ts.
 */
describe("the broker is dual-homed at run time, not by a later attach", () => {
  const runId = "run-abc-123";
  const args = buildBrokerRunArgs({
    networkName: networkNameFor(runId),
    egressNetwork: EGRESS_NETWORK,
    brokerContainer: "shadow-broker-x",
    brokerImage: "node:22-bookworm-slim",
    brokerCodeDir: "/code",
    configDir: "/cfg",
    logDir: "/log",
    pendingDir: "/pending",
    protectedDir: "/protected",
    runId,
    agentId: "agent-1",
  });

  it("puts both networks on the run command", () => {
    const networks = args.filter((a, i) => args[i - 1] === "--network");
    expect(networks).toEqual([networkNameFor(runId), EGRESS_NETWORK]);
  });

  it("keeps the broker alias, which is how the agent reaches it", () => {
    expect(args[args.indexOf("--network-alias") + 1]).toBe("broker");
    // the alias must be declared against the INTERNAL network, so it comes before the egress one
    expect(args.indexOf("--network-alias")).toBeLessThan(args.lastIndexOf("--network"));
  });

  it("never names the default bridge, which is what forced the late attach", () => {
    expect(args).not.toContain("bridge");
  });

  it("creates the egress network without --internal, and the agent network with it", () => {
    expect(buildNetworkCreateArgs(networkNameFor(runId))).toContain("--internal");
    expect(buildEgressCreateArgs(EGRESS_NETWORK)).not.toContain("--internal");
  });

  it("keeps the egress network shared and the agent network per run, which is the whole split", () => {
    // the per-run name carries the run id; the egress name deliberately does not, because the
    // provider that has to be reachable on it outlives any single turn
    expect(EGRESS_NETWORK).not.toBe(networkNameFor(runId));
    expect(networkNameFor(runId)).toContain(runId);
    expect(EGRESS_NETWORK).not.toContain(runId);
    for (const name of [networkNameFor(runId), EGRESS_NETWORK]) {
      expect(name.startsWith("shadow-")).toBe(true);
    }
  });
});

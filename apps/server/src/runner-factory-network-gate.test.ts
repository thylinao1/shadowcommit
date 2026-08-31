import { describe, expect, it } from "vitest";
import { createRunner } from "./runner-factory.js";
import { loadConfig } from "./config.js";

/**
 * Two of this repo's open security issues were one root cause, and neither was closed by the fix
 * that made the default safe.
 *
 * With RUNTIME_PROVIDER=container and SHADOW_CONFINE_NETWORK=false the agent container joins the
 * default bridge with unrestricted egress (#3), and container-codex-runner hands it
 * `turnToken || config.arkApiKey` with no token minted, so the REAL provider credential lands in
 * the untrusted runtime's environment (#4). The journal still records a contained-looking turn.
 *
 * The host path has always refused to run unless an operator sets SHADOW_ALLOW_UNCONFINED. This
 * path had no gate at all, which made a secure default the only thing standing in the way, and a
 * default is not a control. Both unconfined routes now ask for the same acknowledgement.
 */

const base = {
  NODE_ENV: "test",
  APP_AUTH_TOKEN: "a-token-long-enough-for-production",
  RUNTIME_PROVIDER: "container",
} as Record<string, string>;

describe("the unsealed-network container path is gated like every other unconfined path", () => {
  it("refuses to build a runner when the network seal is off and nobody accepted it", () => {
    const config = loadConfig({ ...base, SHADOW_CONFINE_NETWORK: "false" });
    expect(() => createRunner(config)).toThrow(/network unsealed|SHADOW_CONFINE_NETWORK/);
  });

  it("names both consequences in the refusal, so the operator knows what they are accepting", () => {
    const config = loadConfig({ ...base, SHADOW_CONFINE_NETWORK: "false" });
    expect(() => createRunner(config)).toThrow(/default bridge/);
    expect(() => createRunner(config)).toThrow(/provider credential/);
  });

  it("builds when an operator explicitly accepts it, the same escape the host path has", () => {
    const config = loadConfig({
      ...base,
      SHADOW_CONFINE_NETWORK: "false",
      SHADOW_ALLOW_UNCONFINED: "1",
    });
    expect(createRunner(config)).toBeDefined();
  });

  it("builds on the default, which seals the network, with no acknowledgement needed", () => {
    const config = loadConfig({ ...base });
    expect(config.shadowConfineNetwork).toBe(true); // the default the gate leaves alone
    expect(createRunner(config)).toBeDefined();
  });
});

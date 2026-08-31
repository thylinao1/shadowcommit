import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

/**
 * J8 changed the RUNTIME_PROVIDER default from "local-process" to "container", which is what makes
 * the documented start commands start something instead of hitting the unconfined refusal. Nothing
 * asserted that default before, so a future edit could put it back and every documented entry point
 * would silently stop booting again with the suite still green.
 *
 * The second case is the more important one: the refusal itself must survive. Defaulting to
 * container is a convenience, refusing to wrap an unconfined runtime is the safety property, and a
 * change that kept the convenience while losing the refusal would be strictly worse than before.
 */
describe("the runtime provider default", () => {
  it("is container, so every documented entry point boots a confined runtime", () => {
    expect(loadConfig({ NODE_ENV: "test" }).runtimeProvider).toBe("container");
  });

  it("still lets an operator ask for the unconfined runtime explicitly", () => {
    const config = loadConfig({ NODE_ENV: "test", RUNTIME_PROVIDER: "local-process" });
    expect(config.runtimeProvider).toBe("local-process");
    // and that choice is what createRunner refuses unless SHADOW_ALLOW_UNCONFINED is set; the
    // refusal itself is pinned by runner-factory's own tests, this only proves the value survives
    // the config layer rather than being silently rewritten to the safe default
  });
});

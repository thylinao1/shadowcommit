import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * scripts/bootstrap-local.sh copies .env.example to .env verbatim, so anything set in the example is
 * set for everyone who follows the setup instructions. SHADOW_ALLOW_UNCONFINED shipped as 1, which
 * meant the single deliberate opt-in to running agents with no jail was already taken before anyone
 * decided anything. A refusal that the project's own example file pre-satisfies is not a control.
 */
describe(".env.example does not pre-satisfy a safety opt-in", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

  it("ships SHADOW_ALLOW_UNCONFINED commented out, so the jail is opted OUT of and never into by default", async () => {
    const text = await fs.readFile(path.join(repoRoot, ".env.example"), "utf8");
    const active = text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));

    expect(active.some((line) => line.startsWith("SHADOW_ALLOW_UNCONFINED="))).toBe(false);
    // and the file still explains the flag, because removing the explanation is not the fix
    expect(text).toContain("SHADOW_ALLOW_UNCONFINED");
  });

  it("keeps the confined runtime as the value the example actually sets", async () => {
    const text = await fs.readFile(path.join(repoRoot, ".env.example"), "utf8");
    const active = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    expect(active).toContain("RUNTIME_PROVIDER=container");
  });
});

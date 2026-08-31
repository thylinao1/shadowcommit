import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * `npm start` ran `node dist/index.js` with no build in front of it, and `dist/` is gitignored.
 *
 * Two consequences, and the second is the dangerous one. On a cold clone the documented start command
 * fails with a bare "Cannot find module". And after any source edit it silently runs the PREVIOUS
 * build, so someone can fix a defect, start the server, and be looking at the old binary. That is not
 * hypothetical: a teammate twice reported a security guard as absent because the guard was in the
 * source they were reading and not in the dist they were running.
 *
 * Production does not go through this path (the Dockerfile builds explicitly and its CMD names
 * dist/index.js directly), so making the developer entry point build first costs nothing there.
 *
 * This asserts the wiring rather than the behaviour, because the behaviour needs a real server. It was
 * confirmed by hand: with dist removed, `npm start` built and then listened.
 */
describe("the documented start command cannot run a stale build", () => {
  const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

  it("builds before it starts", async () => {
    const manifest = JSON.parse(await fs.readFile(path.join(serverRoot, "package.json"), "utf8"));
    const scripts = manifest.scripts as Record<string, string>;

    // npm runs prestart automatically before start; if that name changes this stops being true
    expect(scripts.prestart, "no prestart, so start would run whatever dist happened to hold").toBeTruthy();
    expect(scripts.prestart).toContain("build");
    expect(scripts.start).toContain("dist/index.js");
  });

  it("still has a build script for prestart to call, and a dev path that needs no build at all", async () => {
    const manifest = JSON.parse(await fs.readFile(path.join(serverRoot, "package.json"), "utf8"));
    const scripts = manifest.scripts as Record<string, string>;
    expect(scripts.build).toContain("tsc");
    // dev runs from source through tsx, so it can never be stale and must not gain a build step
    expect(scripts.dev).toContain("src/index.ts");
  });
});

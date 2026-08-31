import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { findContainerSocketReferences } from "./container-socket-guard.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("container control socket CI guard", () => {
  it("fails on a container-engine socket mount", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "socket-guard-"));
    temporaryDirectories.push(root);
    await writeFile(
      path.join(root, "compose.yml"),
      "services:\n  agent:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    );
    const { findings } = await findContainerSocketReferences(root);
    expect(findings).toEqual([
      expect.objectContaining({ file: "compose.yml", line: 4 }),
    ]);
  });

  it("passes the shipped runtime launch and deployment configuration", async () => {
    const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
    await mkdir(repositoryRoot, { recursive: true });
    const { findings, unreadable } = await findContainerSocketReferences(
      repositoryRoot,
      new Set(["apps/server/src/container-socket-guard.test.ts"]),
    );
    expect(findings).toEqual([]);
    // A directory the scan could not read makes the answer incomplete rather than clean, and this
    // used to surface as an EACCES thrown out of the guard, which read as the assertion above
    // failing. On any machine that has run the POC, `.local/data/shadows/<run>/work/` is created by
    // the runtime container as another uid and is exactly such a directory.
    expect(unreadable, "the guard reached everything it claims to have checked").toEqual([]);
  });

  /**
   * The other half of this guard's fix, and it had no test that fails when reverted alone.
   *
   * A directory this process cannot read used to throw EACCES straight out of the walk, and the
   * test above reported that as its own assertion failing, so "the guard could not run" was
   * indistinguishable from "the shipped configuration mounts the socket". That is the failure mode
   * this repository keeps producing: a check whose inability to run reads as a pass or as the wrong
   * failure.
   *
   * A clean checkout has no unreadable directory, so the repo-root scan never reaches the catch
   * branch and the existing assertion that `unreadable` is empty passes with or without the fix.
   * This one builds the condition instead of hoping for it.
   *
   * Skipped as root, where CAP_DAC_OVERRIDE ignores the mode bits this sets, and on Windows, which
   * has no equivalent. Both would silently pass rather than prove anything.
   */
  const cannotDenyReads =
    process.platform === "win32" || (typeof process.getuid === "function" && process.getuid() === 0);

  it.skipIf(cannotDenyReads)("records a directory it cannot read instead of throwing", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "socket-guard-eacces-"));
    temporaryDirectories.push(root);
    const denied = path.join(root, "denied");
    await mkdir(denied, { recursive: true });
    await writeFile(path.join(root, "compose.yml"), "services:\n  app:\n    image: node\n");
    await chmod(denied, 0o000);

    try {
      const scan = await findContainerSocketReferences(root);

      // the walk completes rather than throwing, which is the whole point
      expect(scan.unreadable.map((u) => u.directory)).toContain("denied");
      expect(scan.unreadable.find((u) => u.directory === "denied")?.reason).toBe("EACCES");
      // and it still reports honestly about the part it COULD read
      expect(scan.findings).toEqual([]);
    } finally {
      // chmod back or the afterEach cleanup cannot remove it
      await chmod(denied, 0o755);
    }
  });

  it("does not scan a nested repository, and says which one it skipped", async () => {
    // The real case: `research/realworld-prior/repos/` holds eight upstream clones fetched for the
    // real-commit corpus, and axios's own HTTP adapter test mentions the control socket. That line
    // failed THIS repository's security gate, on a tree that is gitignored and ships nothing here.
    //
    // Two assertions, because the skip alone is not the fix. A control that quietly declines to look
    // at part of the tree reads as a clean sheet, which is the defect pattern this project found in
    // its own confinement layer the same night. So the scan must also SAY what it did not enter.
    const root = await mkdtemp(path.join(tmpdir(), "socket-guard-nested-"));
    const vendored = path.join(root, "research", "vendor", "upstream-project");
    await mkdir(path.join(vendored, ".git"), { recursive: true });
    await mkdir(path.join(vendored, "tests"), { recursive: true });
    await writeFile(
      path.join(vendored, "tests", "adapter.test.js"),
      "const socketPath = '/var/run/' + 'docker' + '.sock';\n",
    );
    const { findings, nestedCheckouts } = await findContainerSocketReferences(root);
    expect(findings, "another project's test suite cannot fail this repository's gate").toEqual([]);
    expect(nestedCheckouts, "the skip has to be visible, not silent").toEqual([
      "research/vendor/upstream-project",
    ]);
  });

  it("still scans a directory that merely has a .git-shaped name in a FILE", async () => {
    // Guards the guard. The nested-checkout test is `entries.some(e => e.name === ".git")`, which
    // must not be satisfied by a regular file called `.gitignore`, `.gitattributes` or similar, or
    // one stray dotfile would switch scanning off for a real source tree.
    const root = await mkdtemp(path.join(tmpdir(), "socket-guard-gitfile-"));
    await mkdir(path.join(root, "deploy"), { recursive: true });
    await writeFile(path.join(root, "deploy", ".gitignore"), "node_modules\n");
    await writeFile(
      path.join(root, "deploy", "compose.yml"),
      "services:\n  x:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    );
    const { findings, nestedCheckouts } = await findContainerSocketReferences(root);
    expect(nestedCheckouts, "a .gitignore file is not a checkout").toEqual([]);
    expect(findings.length, "a real mount in our own tree is still a finding").toBe(1);
  });

  it("does not scan the running platform's own state directory", async () => {
    // `.local` holds sealed shadows and agent workspaces. It is not source, so a hit there says
    // nothing about the shipped configuration, and it is written by the agent under test, so
    // scanning it lets a turn fail this repository's own security gate by writing one string.
    const root = await mkdtemp(path.join(tmpdir(), "socket-guard-local-"));
    await mkdir(path.join(root, ".local", "data", "shadows", "run1", "work"), { recursive: true });
    await writeFile(
      path.join(root, ".local", "data", "shadows", "run1", "work", "compose.yml"),
      "services:\n  x:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    );
    const { findings } = await findContainerSocketReferences(root);
    expect(findings, "an agent's own workspace cannot fail the guard").toEqual([]);
  });
});

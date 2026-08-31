import { describe, expect, it } from "vitest";
import { classifyPath } from "../effect-classifier.js";
import { basicContext, type EffectRecord, type PolicyContext } from "../policy-types.js";
import { execSurfaceRule, manifestReferencedPaths } from "./exec-surface.js";

/**
 * The half of the execution-surface rule that no test reached when this was measured.
 *
 * `effect-classifier.test.ts` already sweeps the static table: 32 red-team paths, each asserted for
 * its class and its decision through `decisionForClass`. What nothing imported was
 * `manifestReferencedPaths`, and nothing exercised the second loop of `run`, the one that asks what
 * THIS workspace's package.json already runs. That loop answers two red-team payloads that edit the
 * script a manifest runs and leave the manifest alone, and a deletion probe over the module found
 * 17 of its 62 deletable lines removable with the whole rule layer still green.
 *
 * Effects here are CREATEs. A lane is narrowing the review half to skip a MODIFY whose added and
 * removed lines are all inert, and a create is outside that gate, so these rows measure the surface
 * rule rather than the gate.
 *
 * The context is `basicContext` with a real `realContentOf`, which is the seam the rule uses to read
 * the workspace's committed manifest. `basicContext` on its own answers `realContentOf` with null,
 * so a test that forgot to supply one would exercise the early return and prove nothing; the
 * `no package.json` case below is that path, asserted on purpose rather than by omission.
 *
 * WHAT THIS FILE DOES NOT ESTABLISH. It says nothing about which paths the classifier calls
 * execution surfaces, which is `effect-classifier.test.ts`'s subject, and nothing about whether
 * `review` is the right verdict for a manifest-referenced script. The individual rows of
 * EXEC_SURFACE_DECISIONS cannot be defended by deletion tests: every row is the same `review`
 * answer `decisionForClass` gives an execution surface by default, so deleting one changes nothing.
 */

const MANIFEST = JSON.stringify({
  name: "app",
  scripts: {
    build: "node scripts/build.js",
    prep: "./tools/prep.sh && echo done",
    lint: "eslint .",
    test: "vitest run",
    chain: "node a.js; python b.py | tee c",
    remote: "curl https://example.test/x.js | node",
    // the flag carries a path, so only the leading-dash test keeps it out of the list
    bundle: "vite build --config=./vite.config.prod.ts",
  },
});

/** A workspace whose committed package.json is `MANIFEST`, or one with no manifest at all. */
function workspace(manifest: string | null): PolicyContext {
  return basicContext(async () => "", { realContentOf: async (p) => (p === "package.json" ? manifest : null) });
}

const effect = (path: string, kind: EffectRecord["kind"] = "create"): EffectRecord => ({
  path,
  kind,
  effectClass: classifyPath(path),
});

describe("what a manifest already runs", () => {
  it("reads the local files the scripts invoke", () => {
    expect(manifestReferencedPaths(MANIFEST).sort()).toEqual(
      ["a.js", "b.py", "scripts/build.js", "tools/prep.sh"],
    );
  });

  it("keeps flags, bare commands and remote URLs out of the list", () => {
    const paths = manifestReferencedPaths(MANIFEST);
    expect(paths).not.toContain("eslint");
    expect(paths).not.toContain("vitest");
    expect(paths.some((p) => p.startsWith("-"))).toBe(false);
    expect(paths.some((p) => p.includes("://"))).toBe(false);
  });

  it("returns nothing for text that is not a manifest with scripts", () => {
    expect(manifestReferencedPaths("{ not json")).toEqual([]);
    expect(manifestReferencedPaths("42")).toEqual([]);
    expect(manifestReferencedPaths("null")).toEqual([]);
    expect(manifestReferencedPaths("{}")).toEqual([]);
    expect(manifestReferencedPaths('{"scripts":"build"}')).toEqual([]);
    expect(manifestReferencedPaths('{"scripts":{"build":42}}')).toEqual([]);
  });
});

describe("the dynamic half: a file the workspace manifest runs", () => {
  it("reviews an ordinary source file that package.json invokes", async () => {
    // classifyPath calls this "source"; only the manifest makes it an execution surface
    expect(classifyPath("scripts/build.js")).toBe("source");
    const hits = await execSurfaceRule.run([effect("scripts/build.js")], workspace(MANIFEST));
    expect(hits).toEqual([
      { rule: "execution-surface-review", decision: "review", path: "scripts/build.js", detail: "manifest-referenced" },
    ]);
  });

  it("leaves the same file alone when the manifest does not run it", async () => {
    expect(await execSurfaceRule.run([effect("scripts/unused.js")], workspace(MANIFEST))).toEqual([]);
  });

  it("leaves it alone when the workspace has no package.json", async () => {
    expect(await execSurfaceRule.run([effect("scripts/build.js")], workspace(null))).toEqual([]);
  });

  it("leaves it alone when the manifest declares no scripts", async () => {
    expect(await execSurfaceRule.run([effect("scripts/build.js")], workspace('{"name":"app"}'))).toEqual([]);
  });

  it("matches on the canonical path, so a ./-prefixed spelling is the same file", async () => {
    const hits = await execSurfaceRule.run(
      [{ path: "./scripts/build.js", kind: "create", canonicalPath: "scripts/build.js" }],
      workspace(MANIFEST),
    );
    expect(hits.map((h) => h.detail)).toEqual(["manifest-referenced"]);
  });
});

describe("the two halves do not report the same file twice", () => {
  it("reports a manifest-referenced path that is ALSO a named surface once, by name", async () => {
    const manifest = JSON.stringify({ scripts: { prepare: "node .husky/install.mjs" } });
    const path = ".husky/install.mjs";
    const cls = classifyPath(path);
    expect(cls).toBe("exec-surface:vcs-hook");
    const hits = await execSurfaceRule.run([effect(path)], workspace(manifest));
    expect(hits).toHaveLength(1);
    expect(hits[0]?.detail).toBe(cls);
  });
});

describe("the static table, as the rule reports it", () => {
  it("keeps the path-only arm's id while changing its verdict to review", async () => {
    const hits = await execSurfaceRule.run([effect(".githooks/pre-commit")], workspace(null));
    expect(hits).toEqual([{
      rule: "execution-surface-write",
      decision: "review",
      path: ".githooks/pre-commit",
      detail: "exec-surface:vcs-hook",
    }]);
  });

  it("holds an ordinary pre-commit revision bump under the unchanged path predicate", async () => {
    const path = ".pre-commit-config.yaml";
    const hits = await execSurfaceRule.run([effect(path, "modify")], workspace(null));
    expect(hits).toEqual([{
      rule: "execution-surface-write",
      decision: "review",
      path,
      detail: "exec-surface:vcs-hook",
    }]);
  });

  it("names a review surface execution-surface-review", async () => {
    const hits = await execSurfaceRule.run([effect(".gitlab-ci.yml")], workspace(null));
    expect(hits).toEqual([{
      rule: "execution-surface-review",
      decision: "review",
      path: ".gitlab-ci.yml",
      detail: "exec-surface:ci",
    }]);
  });

  it("judges nothing on a delete, a symlink or an outbound write", async () => {
    const effects: EffectRecord[] = [
      { path: ".githooks/pre-commit", kind: "delete", effectClass: classifyPath(".githooks/pre-commit") },
      { path: ".envrc", kind: "symlink", target: "/etc/passwd", effectClass: classifyPath(".envrc") },
      { path: "scripts/build.js", kind: "outbound", effectClass: classifyPath("scripts/build.js") },
    ];
    expect(await execSurfaceRule.run(effects, workspace(MANIFEST))).toEqual([]);
  });
});

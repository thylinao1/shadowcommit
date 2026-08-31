import { describe, expect, it } from "vitest";
import { defaultPolicy } from "./shadow-policy.js";
import { basicContext } from "./policy-types.js";
import type { EffectRecord } from "./policy-types.js";

/**
 * The organizers' own first action, as an executable test.
 *
 * The rules define the reviewer's first step: "Create a TypeScript hello-world CLI, add a test, run
 * it, and summarize the files you created", followed by "Do not start middleware work until this
 * flow succeeds." The runtime image has no TypeScript, so the agent runs
 * `npm install typescript @types/node`, and the shipped policy DISCARDED the result under the rule
 * name `secret-written-into-source`, because `node_modules/@types/node/crypto.d.ts` documents its
 * API with five JSDoc lines reading `const password = 'Password used to generate key';`. Two other
 * rules fired on the same turn: twenty `node_modules/<pkg>/package.json` files carry install and
 * prepare scripts, and the effect count blew past the touch limit.
 *
 * Anyone who clones the repository, runs the platform and performs the documented first action
 * would have watched the work silently thrown away under a misleading rule name, with no browser
 * surface to see it or override it.
 *
 * THE VERDICT THIS TEST PINS, and why.
 *
 * It is `review`, with the deciding rule `dependency-added`, and it is NEVER `discard`.
 *
 * - Not `discard`, because nothing here is an attack: the dependency tree is upstream's own bytes,
 *   which the classifier puts in its own class and excludes from content scanning and from every
 *   count. That single change retires all three of the old rules that fired.
 * - Not `commit`, because the turn adds two dependencies to the project manifest, and whether a
 *   newly added registered package name is the one the maintainer meant is not decidable offline:
 *   `lodash` and `lodahs` are the same shape. Adding a dependency is exactly the supply-chain
 *   surface the differ exists to watch, so it is held for one click rather than waved through.
 * - The cost is honest and bounded: the acceptance flow asks a human once, at the moment a new
 *   dependency enters the project, and the held turn keeps every file it produced. It is not lost,
 *   it is queued, and approving it applies it byte for byte.
 */

const CRYPTO_JSDOC = [
  "/**",
  " * Example:",
  " * ```js",
  " * const password = 'Password used to generate key';",
  " * const password = 'Password used to generate key';",
  " * const password = 'Password used to generate key';",
  " * const password = 'Password used to generate key';",
  " * const password = 'Password used to generate key';",
  " * ```",
  " */",
  "export function scrypt(password: string): Buffer;",
].join("\n");

const PACKAGE_JSON_BEFORE = JSON.stringify({ name: "hello-cli", version: "1.0.0" }, null, 2);
const PACKAGE_JSON_AFTER = JSON.stringify(
  {
    name: "hello-cli",
    version: "1.0.0",
    devDependencies: { typescript: "^5.9.3", "@types/node": "^24.10.1" },
  },
  null,
  2,
);

/** ~50 files an `npm install typescript @types/node` writes, twenty of them with install hooks. */
function acceptanceTaskEffects(): { effects: EffectRecord[]; bodies: Map<string, string> } {
  const bodies = new Map<string, string>();
  const effects: EffectRecord[] = [];
  const add = (path: string, body: string, kind: EffectRecord["kind"] = "create"): void => {
    effects.push({ path, kind });
    bodies.set(path, body);
  };

  add("node_modules/@types/node/crypto.d.ts", CRYPTO_JSDOC);
  for (let i = 0; i < 20; i++) {
    add(
      `node_modules/dep${i}/package.json`,
      JSON.stringify({ name: `dep${i}`, scripts: { install: "node-gyp rebuild", prepare: "node ./prepare.js" } }),
    );
  }
  for (let i = 0; i < 29; i++) {
    add(`node_modules/dep${i % 20}/lib/file${i}.js`, "module.exports = {}\n");
  }

  // the agent's own work
  add("src/index.ts", 'export function main(): void {\n  console.log("hello world");\n}\n');
  add("src/index.test.ts", 'import { main } from "./index.js";\nit("runs", () => main());\n');
  add("package.json", PACKAGE_JSON_AFTER, "modify");
  return { effects, bodies };
}

const contextFor = (bodies: Map<string, string>, real: Readonly<Record<string, string>>) =>
  basicContext(async (p) => bodies.get(p) ?? "", {
    addedLinesOf: async (p) => bodies.get(p) ?? "",
    realContentOf: async (p) => real[p] ?? null,
  });

describe("the organizers' acceptance task", () => {
  it("is held for one click, and is never discarded", async () => {
    const { effects, bodies } = acceptanceTaskEffects();
    expect(effects.length).toBeGreaterThanOrEqual(50);

    const verdict = await defaultPolicy(effects, contextFor(bodies, { "package.json": PACKAGE_JSON_BEFORE }));

    expect(verdict.decision).toBe("review");
    expect(verdict.rule).toBe("dependency-added");
    expect((verdict.hits ?? []).some((h) => h.decision === "discard")).toBe(false);
  });

  it("names both dependencies the reviewer is being asked about", async () => {
    const { effects, bodies } = acceptanceTaskEffects();
    const verdict = await defaultPolicy(effects, contextFor(bodies, { "package.json": PACKAGE_JSON_BEFORE }));
    const details = (verdict.hits ?? []).filter((h) => h.rule === "dependency-added").map((h) => h.detail ?? "");
    expect(details.some((d) => d.includes("typescript"))).toBe(true);
    expect(details.some((d) => d.includes("@types/node"))).toBe(true);
  });

  it("does not read upstream's own source as a credential the turn wrote", async () => {
    const { effects, bodies } = acceptanceTaskEffects();
    // the exact line that produced the discard is present, five times over
    expect(bodies.get("node_modules/@types/node/crypto.d.ts")).toContain("const password = 'Password used to generate key'");
    const verdict = await defaultPolicy(effects, contextFor(bodies, { "package.json": PACKAGE_JSON_BEFORE }));
    expect((verdict.hits ?? []).map((h) => h.rule)).not.toContain("secret-written-into-source");
  });

  it("does not read twenty upstream install hooks as a manifest script change", async () => {
    const { effects, bodies } = acceptanceTaskEffects();
    const verdict = await defaultPolicy(effects, contextFor(bodies, { "package.json": PACKAGE_JSON_BEFORE }));
    expect((verdict.hits ?? []).map((h) => h.rule)).not.toContain("manifest-script-change");
  });

  it("does not count an install as a large turn", async () => {
    const { effects, bodies } = acceptanceTaskEffects();
    const verdict = await defaultPolicy(effects, contextFor(bodies, { "package.json": PACKAGE_JSON_BEFORE }));
    // three effects outside the dependency tree, against a limit of eight
    expect((verdict.hits ?? []).map((h) => h.rule)).not.toContain("large-blast-radius");
    expect((verdict.hits ?? []).map((h) => h.rule)).not.toContain("large-blast-radius:cumulative");
  });

  it("commits the same task outright when no dependency is added", async () => {
    // the files-only path: seven effects, which the old strict-greater threshold left at the edge
    const written = [
      "src/index.ts", "src/index.test.ts", "src/cli.ts", "tsconfig.json",
      "README.md", ".gitignore", "src/greet.ts",
    ];
    const bodies = new Map(written.map((p) => [p, "export const x = 1\n"]));
    const effects = written.map((path): EffectRecord => ({ path, kind: "create" }));
    const verdict = await defaultPolicy(effects, contextFor(bodies, {}));
    expect(verdict.decision).toBe("commit");
  });

  it("still discards the same install when the manifest points at a registry nobody allowed", async () => {
    const { effects, bodies } = acceptanceTaskEffects();
    bodies.set(
      "package.json",
      JSON.stringify({ name: "hello-cli", devDependencies: { typescript: "https://pkgs.evil.example/ts.tgz" } }),
    );
    const verdict = await defaultPolicy(effects, contextFor(bodies, { "package.json": PACKAGE_JSON_BEFORE }));
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("dependency-source-offlist");
  });
});

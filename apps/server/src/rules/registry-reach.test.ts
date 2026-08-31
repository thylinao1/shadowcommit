import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { rules } from "./index.js";

/**
 * The half of `research/corpus/check-rule-reach.mjs` that can run in a second.
 *
 * That gate is the real one: it replays the whole corpus, records which registry rules any scenario
 * reaches, and fails the build for a rule reached by nothing that carries no written reason. It
 * needs the four pinned repositories and a couple of minutes, so it runs under `npm run corpus` and
 * not under `npm run check`, and CI runs the second and not the first.
 *
 * So the exemption list is checked here instead, where every push sees it. A list of excuses is
 * worth exactly as much as its weakest entry, and the way it rots is not by being wrong on the day
 * it is written: it is by a rule being renamed or deleted underneath it, leaving an entry that
 * excuses nothing while still counting itself in the gate's summary line. That is checkable with no
 * corpus at all, by comparing it against the registry it claims to describe.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..", "..");
const exemptionsPath = path.join(repoRoot, "research", "corpus", "lib", "rule-reach-exemptions.mjs");
const scenariosDir = path.join(repoRoot, "research", "corpus", "scenarios");

/**
 * Read as text rather than imported: it is a `.mjs` under `research/`, outside this workspace's type
 * graph, and `registry-wiring.test.ts` already reads rule modules from disk the same way.
 */
function declaredExemptions(): Array<{ rule: string; probeFile?: string }> {
  const src = fs.readFileSync(exemptionsPath, "utf8");
  return [...src.matchAll(/rule:\s*"([^"]+)"[\s\S]*?(?=\n  \{|\n\];)/g)].map((m) => ({
    rule: m[1],
    probeFile: /file:\s*"([^"]+)"/.exec(m[0])?.[1],
  }));
}

describe("the corpus rule-reach exemptions describe the registry that exists", () => {
  it("parses at all, so a shape change here fails loudly rather than silently excusing nothing", () => {
    expect(declaredExemptions().length).toBeGreaterThan(0);
  });

  it("names only rules the registry carries, so an exemption cannot outlive its rule", () => {
    const names = new Set(rules.map((r) => r.name));
    const stale = declaredExemptions().map((e) => e.rule).filter((name) => !names.has(name));
    expect(
      stale,
      "an exemption names a rule the registry no longer carries. It excuses nothing, and it still " +
        "counts itself in check-rule-reach.mjs's summary, which is how a list of five known holes " +
        "starts reading as five understood ones.",
    ).toEqual([]);
  });

  it("names each rule at most once, so two entries cannot disagree about the same hole", () => {
    const declared = declaredExemptions().map((e) => e.rule);
    expect(declared).toEqual([...new Set(declared)]);
  });

  it("cites probe files that exist, since the citation is the evidence the rule is graded somewhere", () => {
    const missing = declaredExemptions()
      .filter((e) => e.probeFile && !fs.existsSync(path.join(scenariosDir, e.probeFile)))
      .map((e) => `${e.rule} cites ${e.probeFile}`);
    expect(missing, "a cited probe file is not in research/corpus/scenarios/").toEqual([]);
  });
});

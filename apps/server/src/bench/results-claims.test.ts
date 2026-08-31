import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { blastRadiusRule, REVIEW_AT_OR_ABOVE_TOUCHES } from "../rules/blast-radius.js";
import type { EffectRecord, PolicyContext } from "../policy-types.js";

/**
 * The perf lane publishes two prose documents that make claims about product source and about
 * committed measurement data. Prose is the one artefact in this repository nothing recomputes, so
 * it is the one that drifts: `RESULTS.md` shipped four statements about `runner-factory.ts` that
 * were already false at merge, one measured cell that its own inputs make arithmetically
 * impossible, and a corpus claim whose stated warrant could not carry it. This file binds both
 * documents back to the things they describe.
 *
 * Each gate is two-sided on purpose. It does not ban a sentence outright; it checks the fact first
 * (in `runner-factory.ts`, in `blast-radius.ts`, in the JSONL, in `docs/CORPUS-REPORT.md`) and only
 * then requires the prose to agree with it. If the product later stops wiring the seal, gate 1 stops
 * demanding the doc say it is wired, instead of silently enforcing a new falsehood.
 *
 * Every file is read inside a test body, never at module load. These documents belong to several
 * lanes and one of them moving a file must fail one assertion, not abort collection of the file.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const serverSrc = path.resolve(here, "..");
const repoRoot = path.resolve(serverSrc, "../../..");

const read = (p: string): string => fs.readFileSync(p, "utf8");

const RESULTS_PATH = path.join(here, "RESULTS.md");
const PERF_PATH = path.join(repoRoot, "docs/PERF.md");
const FACTORY_PATH = path.join(serverSrc, "runner-factory.ts");
const JSONL_PATH = path.join(here, "results/turn-open-scaling.jsonl");
const CORPUS_PATH = path.join(repoRoot, "docs/CORPUS-REPORT.md");

/** Name for the failure message, path to read. Read lazily, inside the test that needs it. */
const DOC_PATHS: ReadonlyArray<readonly [string, string]> = [
  ["apps/server/src/bench/RESULTS.md", RESULTS_PATH],
  ["docs/PERF.md", PERF_PATH],
];

/**
 * A correction has to quote what it withdraws, so a flat string ban would forbid the retraction
 * along with the claim. Text between `<!-- retracted:BEGIN -->` and `<!-- retracted:END -->` is
 * quoted, not asserted, and the claim gates read the document with those spans removed.
 */
const RETRACTED = /<!-- retracted:BEGIN -->([\s\S]*?)<!-- retracted:END -->/g;
const asserted = (doc: string): string => doc.replace(RETRACTED, "");

/** These files are hard-wrapped at 100 columns, so a two-word phrase is routinely split by a newline. */
const flat = (s: string): string => s.replace(/\s+/g, " ").trim();

const RETRACTION_WORDS =
  /withdraw|retract|correction|earlier version|was (already )?false|no longer|previously|used to|void|below the floor|impossible/i;

/**
 * The contiguous non-empty lines immediately above `index`, headings dropped. A heading is a label,
 * not an attribution: "### 2a. ... (a correction)" must not license a mute in the prose beneath it.
 */
function attributionParagraph(doc: string, index: number): string {
  const before = doc.slice(0, index).split("\n");
  while (before.length > 0 && before[before.length - 1]!.trim() === "") before.pop();
  const para: string[] = [];
  while (before.length > 0 && before[before.length - 1]!.trim() !== "") {
    para.unshift(before.pop()!);
  }
  return flat(para.filter((l) => !/^\s*#{1,6}\s/.test(l)).join(" "));
}

/** Every non-empty line is a markdown blockquote, so the span renders as a quotation, set off. */
const isBlockquote = (body: string): boolean => {
  const lines = body.split("\n").filter((l) => l.trim() !== "");
  return lines.length > 0 && lines.every((l) => /^\s*>/.test(l));
};

/**
 * A span may be muted two ways, and only two.
 *
 * (a) It says of itself that it is withdrawn: the retraction vocabulary is INSIDE the span.
 * (b) It is a verbatim quotation of the withdrawn text, in which case it carries no such vocabulary
 *     of its own, so it must be a blockquote (visibly set off in the rendered page, not ordinary
 *     asserted prose) AND the paragraph directly above it must read as a retraction.
 *
 * The earlier form of this check accepted any span whose preceding 400 characters mentioned a
 * retraction anywhere. In a document that calls itself a correction that window is satisfied by
 * ambient prose everywhere, so a live false claim could be muted from every other gate while still
 * rendering as an ordinary asserted sentence. Requiring (a) or (b) closes that: an asserted sentence
 * is not a blockquote, and a quotation does not get to lean on a heading two paragraphs up.
 */
export function illegalMutes(doc: string): string[] {
  return [...doc.matchAll(RETRACTED)]
    .filter((m) => {
      const body = m[1] ?? "";
      if (RETRACTION_WORDS.test(flat(body))) return false;
      return !(isBlockquote(body) && RETRACTION_WORDS.test(attributionParagraph(doc, m.index)));
    })
    .map((m) => flat(m[1] ?? "").slice(0, 160));
}

/**
 * The prose gates read whitespace-collapsed text with the retracted spans removed: both files are
 * hard-wrapped, so a banned phrase can be split across a line break, and re-wrapping a paragraph
 * must not be a way to smuggle a withdrawn claim back in.
 */
const claimText = (doc: string): string => flat(asserted(doc));
const claims = (p: string): string => claimText(read(p));

describe("gate 0: retraction spans are balanced and cannot mute an asserted claim", () => {
  for (const [name, p] of DOC_PATHS) {
    it(`${name} opens and closes every retraction span`, () => {
      const doc = read(p);
      expect([name, doc.split("<!-- retracted:BEGIN -->").length]).toEqual([
        name,
        doc.split("<!-- retracted:END -->").length,
      ]);
    });

    it(`${name}: every retraction span either says so or is an attributed quotation`, () => {
      expect(illegalMutes(read(p))).toEqual([]);
    });
  }

  it("an asserted sentence under a heading that says 'correction' is NOT mutable", () => {
    const probe = [
      "### 2a. What runner-factory.ts actually passes (a correction)",
      "",
      "<!-- retracted:BEGIN -->",
      "`runner-factory.ts` passes no `seal` hook, so every host runs the `cp -a` copy fallback.",
      "<!-- retracted:END -->",
    ].join("\n");
    expect(illegalMutes(probe).length).toBe(1);
  });

  it("a blockquoted quotation under a real attribution paragraph stays legal (negative case)", () => {
    const legal = [
      "**Correction to what this lane originally wrote.** It said the following, which was already",
      "false at merge:",
      "",
      "<!-- retracted:BEGIN -->",
      "> `runner-factory.ts` never passes a `seal` option, so every host runs the copy fallback.",
      "<!-- retracted:END -->",
    ].join("\n");
    expect(illegalMutes(legal)).toEqual([]);
  });
});

interface MeasureRow {
  kind: string;
  files: number;
  component: string;
  n: number;
  min: number;
  p50: number;
  max: number;
}

function measurements(): Map<string, MeasureRow> {
  const out = new Map<string, MeasureRow>();
  for (const line of read(JSONL_PATH).split("\n")) {
    if (!line.trim()) continue;
    const row = JSON.parse(line) as Partial<MeasureRow>;
    if (row.kind !== "measure") continue;
    out.set(`${row.files}:${row.component}`, row as MeasureRow);
  }
  return out;
}

const SIZES = [50, 8886, 30000] as const;

/** The cell text under each size column of a table row identified by a substring of its label. */
function tableCells(doc: string, label: string): string[] {
  const line = doc.split("\n").find((l) => l.trimStart().startsWith("|") && l.includes(label));
  if (line === undefined) throw new Error(`no table row containing ${JSON.stringify(label)}`);
  return line.split("|").slice(1, -1).map((c) => c.trim());
}

/**
 * A published millisecond figure, or null when the cell is prose rather than a number (a withdrawn
 * cell). A leading `>=` marks a figure published as a lower bound; the floor check applies to it the
 * same way, since a lower bound below the floor is still a wrong lower bound.
 */
function publishedMs(cell: string): number | null {
  const m = /^\**(?:>=\s*)?([\d,]+(?:\.\d+)?)\s*ms\**$/.exec(cell);
  return m?.[1] === undefined ? null : Number(m[1].replace(/,/g, ""));
}

describe("gate 1: what the report says about the seal hook matches runner-factory.ts", () => {
  const facts = (): { seal: boolean; release: boolean } => {
    const factory = read(FACTORY_PATH);
    return {
      seal: /\bseal:\s*sealer\.seal\b/.test(factory),
      release: /\brelease:\s*async\s*\(\s*shadowDir/.test(factory),
    };
  };

  it("createRunner wires both a seal and a release hook (the fact the prose describes)", () => {
    expect(facts()).toEqual({ seal: true, release: true });
  });

  // Only enforced while the fact above holds. These are the exact shapes that shipped.
  const banned = [
    /passes no `seal` hook/i,
    /never passes a `seal` option/i,
    /no `seal` hook\s*[—-]\s*matches `runner-factory\.ts` exactly/i,
    /copy fallback on every host/i,
    /every host runs the `cp -a` copy fallback/i,
  ];

  for (const [name, p] of DOC_PATHS) {
    it(`${name} does not state the opposite`, () => {
      const { seal, release } = facts();
      if (!seal || !release) return;
      const hits = banned.filter((re) => re.test(claims(p))).map((re) => re.source);
      expect(hits).toEqual([]);
    });

    it(`${name} anchors the claim to the source line that carries it`, () => {
      const { seal, release } = facts();
      if (!seal || !release) return;
      expect([name, claims(p).includes("seal: sealer.seal")]).toEqual([name, true]);
    });
  }
});

describe("gate 2: no published open figure is below its own arithmetic floor", () => {
  /**
   * `turn.begin` is emitted after the seal and after `snapshotStats` (transactional-runner.ts:231
   * to 254), so an "open" duration cannot plausibly be cheaper than a `cp -a` plus the stat-only
   * walk of the same tree on the same host in the same run. The floor uses the cheapest observed
   * sample of each, which is the most generous floor the committed data supports. It compares
   * samples from separate loops, so it is a sanity bound rather than a per-sample identity, which
   * is why the response to breaching it is withdrawal and not a corrected number.
   */
  const floorFor = (rows: Map<string, MeasureRow>, files: number): number => {
    const cp = rows.get(`${files}:cp-a`);
    const stat = rows.get(`${files}:snapshotStats-baseline-stat-only`);
    if (!cp || !stat) throw new Error(`no components committed for ${files} files`);
    return cp.min + stat.min;
  };

  it("the JSONL still carries the open estimator's own samples, impossible ones included", () => {
    const rows = measurements();
    const open = rows.get("30000:shipped-turn-open-through-turn-begin-approx");
    expect(open).toBeDefined();
    expect(open!.max).toBeLessThan(floorFor(rows, 30000));
  });

  it("RESULTS.md publishes no open cell that the floor forbids", () => {
    const rows = measurements();
    const cells = tableCells(read(RESULTS_PATH), "through `turn.begin`");
    const violations = SIZES.map((files, i) => ({ files, cell: cells[i + 1] ?? "" }))
      .map(({ files, cell }) => ({ files, ms: publishedMs(cell), floor: floorFor(rows, files) }))
      .filter((r) => r.ms !== null && r.ms < r.floor)
      .map((r) => `${r.files} files: published ${r.ms} ms, floor ${r.floor.toFixed(2)} ms`);
    expect(violations).toEqual([]);
  });

  /**
   * Both published splits were the withdrawn cell in disguise: 25,639.27 - 9,782.27 = ~15.9 s, and
   * 9,782.27 / 23.91 = 409x. The digits themselves are fine to quote as evidence for the
   * withdrawal (§2b does); what must not come back is either figure presented as a result.
   */
  it("no document republishes a split derived from the withdrawn 30,000-file open figure", () => {
    for (const [name, p] of DOC_PATHS) {
      const doc = claims(p);
      expect([name, /~?15\.9\s*s\b/.test(doc)]).toEqual([name, false]);
      expect([name, /\b409\s*[x×]/i.test(doc)]).toEqual([name, false]);
    }
  });

  /**
   * The withdrawal is right either way, but its published reasoning outran its own data. The floor
   * compares two separate timing loops, and the estimator's stated bias was never timed: the
   * post-run work the estimator folds into `t0` would have to account for the 2.9 s shortfall, and
   * this lane never measured it. Both must be said, or §2b reads as a diagnosis rather than a bound.
   */
  it("§2b publishes the floor as a cross-loop bound, not a per-sample identity", () => {
    const doc = claims(RESULTS_PATH);
    expect([/separate loops?/i.test(doc), /sanity bound/i.test(doc)]).toEqual([true, true]);
  });

  it("§2b does not present the size of the estimator bias as something this lane measured", () => {
    const doc = claims(RESULTS_PATH);
    expect(/never timed|not timed by this lane|was not measured/i.test(doc)).toBe(true);
  });
});

describe("gate 3 (negative): the figures that were always sound are still published", () => {
  it("the total row still carries the committed p50 at every size", () => {
    const rows = measurements();
    const cells = tableCells(read(RESULTS_PATH), "`TransactionalRunner.run()` on the copy path");
    for (const [i, files] of SIZES.entries()) {
      const row = rows.get(`${files}:shipped-turn-open-through-commit`);
      const ms = publishedMs(cells[i + 1] ?? "");
      const p50 = row!.p50;
      const asPublished = p50 >= 1000 ? Math.round(p50) : Math.round(p50 * 10) / 10;
      expect([files, ms]).toEqual([files, asPublished]);
    }
  });

  it("the 634.9x verdict still matches the JSONL verdict row", () => {
    const verdict = read(JSONL_PATH)
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as { kind?: string; growthRatio?: number })
      .find((r) => r.kind === "verdict");
    expect(verdict?.growthRatio).toBe(634.95);
    for (const [name, p] of DOC_PATHS) expect([name, claims(p).includes("634.9")]).toEqual([name, true]);
  });

  it("the O(1) refutation itself survives", () => {
    const results = read(RESULTS_PATH);
    expect(results).toMatch(/NOT O\(1\)/);
    expect(results).toMatch(/is false of the code in this worktree/i);
  });
});

describe("gate 4: every source a claim rests on can be opened from this repository", () => {
  const cited = [
    "SCALABILITY.md",
    "MAKSIM_PLAN",
    "PROBLEMS-AND-SOLUTIONS.md",
    "SHADOW-COMMIT.md",
    "CORPUS.md",
    "SNAPSHOT-BENCH.md",
    "OPERATING-RULES.md",
    "LANE-REPORT.md",
  ];

  const presentInRepo = (name: string): boolean => {
    const bare = name.replace(/\.md$/, "");
    for (const dir of [repoRoot, path.join(repoRoot, "docs")]) {
      for (const entry of fs.readdirSync(dir)) {
        if (entry === name || entry === `${bare}.md`) return true;
      }
    }
    return false;
  };

  for (const [name, p] of DOC_PATHS) {
    it(`${name} cites no document that is absent from the repository`, () => {
      const doc = claims(p);
      const dangling = cited.filter((c) => doc.includes(c) && !presentInRepo(c));
      expect(dangling).toEqual([]);
    });
  }

  it("citing a document that IS in the repository stays legal (negative case)", () => {
    expect(presentInRepo("CORPUS-REPORT.md")).toBe(true);
    expect(presentInRepo("ARCHITECTURE.md")).toBe(true);
  });

  /**
   * `docs/CORPUS-REPORT.md` is generated by `research/corpus/report.mjs` and owned by another lane.
   * Pinning its exact sentence made a legitimate corpus re-run fail the bench lane's gate for a
   * reason that has nothing to do with the bench. This reads the pair out of whatever that file
   * currently publishes and requires only that the bench docs quote the same pair.
   */
  it("the corpus review rate quoted is the one the corpus report currently publishes", () => {
    const corpus = read(CORPUS_PATH);
    const m = /(\d[\d,]*) of (\d[\d,]*) benign turns are held for a human/.exec(corpus);
    expect([CORPUS_PATH, m === null]).toEqual([CORPUS_PATH, false]);
    const [held, total] = [m![1]!, m![2]!];
    for (const [name, p] of DOC_PATHS) {
      const doc = claims(p);
      if (!/benign/.test(doc)) continue;
      const quotes = new RegExp(`${held}\\b[\\s\\S]{0,80}?${total}\\b|${held} of ${total}`).test(doc);
      expect([name, quotes]).toEqual([name, true]);
    }
  });
});

/**
 * Gate 5 replaces the warrant the corpus claim used to rest on.
 *
 * `docs/CORPUS-REPORT.md`'s benign table records ONE rule per turn: `report.mjs` tallies `r.rule`,
 * `replay-v2.mjs` stores `verdict.rule`, and `shadow-policy.ts:55` sets that to the first hit at the
 * worst severity in rule-registration order. `blastRadiusRule` is registered LAST of fourteen, so a
 * benign turn where blast radius fired at `review` beside any earlier review rule is attributed to
 * the earlier one. Absence from that table proves "never the deciding rule", not "never fired".
 *
 * The conclusion about `:cumulative` is nonetheless true, for a reason that is one line and
 * checkable: the corpus harness supplies an empty recent-touch window for every scenario, and the
 * `:cumulative` id is produced only when the window is what crossed the threshold.
 */
describe("gate 5: the blast-radius corpus claim rests on the fact that actually carries it", () => {
  const ctxWith = (recentTouches: string[]): PolicyContext =>
    ({ recentTouches }) as unknown as PolicyContext;

  const effectsFor = (n: number): EffectRecord[] =>
    Array.from(
      { length: n },
      (_, i) =>
        ({
          path: `src/f${i}.ts`,
          kind: "create",
          canonicalPath: `src/f${i}.ts`,
        }) as EffectRecord,
    );

  it("with an empty recent-touch window the `:cumulative` id is unreachable", async () => {
    for (const n of [REVIEW_AT_OR_ABOVE_TOUCHES, 12, 40]) {
      const hits = await blastRadiusRule.run(effectsFor(n), ctxWith([]));
      expect([n, hits.map((h) => h.rule)]).toEqual([n, ["large-blast-radius"]]);
    }
  });

  it("a populated window is what makes it reachable (negative case)", async () => {
    const window = ["a.ts", "b.ts", "c.ts", "d.ts", "e.ts", "f.ts"];
    const hits = await blastRadiusRule.run(effectsFor(2), ctxWith(window));
    expect(hits.map((h) => h.rule)).toEqual(["large-blast-radius:cumulative"]);
  });

  it("the corpus harness supplies an empty window for every scenario", () => {
    const replay = read(path.join(repoRoot, "research/corpus/replay-v2.mjs"));
    expect(replay).toMatch(/recentTouches:\s*\[\s*\]/);
    // no scenario anywhere gets a populated one
    expect(replay).not.toMatch(/recentTouches:\s*\[\s*[^\s\]]/);
  });

  it("blast radius is registered last, so the deciding-rule table cannot prove it never fired", () => {
    const registry = read(path.join(serverSrc, "rules/index.ts"));
    const listed = /export const rules[^=]*=\s*\[([\s\S]*?)\]/.exec(registry)?.[1] ?? "";
    const names = listed.split(",").map((s) => s.trim()).filter(Boolean);
    expect(names[names.length - 1]).toBe("blastRadiusRule");
    expect(read(path.join(serverSrc, "shadow-policy.ts"))).toMatch(
      /the deciding hit is the first one at the worst severity, in rule-registration order/,
    );
  });

  for (const [name, p] of DOC_PATHS) {
    it(`${name} gives the structural reason rather than the rule table`, () => {
      const doc = claims(p);
      if (!/large-blast-radius:cumulative/.test(doc)) return;
      expect([name, /recentTouches/.test(doc)]).toEqual([name, true]);
      expect([name, /deciding rule/i.test(doc)]).toEqual([name, true]);
    });
  }
});

/**
 * Gate 6: what the lane says about its own scripts. `policy-vs-rules.mts` does not call
 * `defaultPolicy`; it reimplements the loop so the rule count can vary, and the reimplementation
 * differs from the original in two ways that change a verdict.
 */
describe("gate 6: the lane's description of its own bench scripts matches the scripts", () => {
  const POLICY_BENCH = path.join(here, "policy-vs-rules.mts");

  it("policy-vs-rules.mts reimplements the loop rather than calling defaultPolicy (the fact)", () => {
    const src = read(POLICY_BENCH);
    expect(["imports shadow-policy", /from "\.\.\/shadow-policy\.js"/.test(src)]).toEqual([
      "imports shadow-policy",
      false,
    ]);
    expect(["runs its own rule loop", /for \(const rule of rules\)[\s\S]{0,80}rule\.run\(/.test(src)]).toEqual([
      "runs its own rule loop",
      true,
    ]);
  });

  /**
   * The seed is read out of each `hits.reduce(...)` call rather than matched positionally, so
   * reformatting either file cannot turn this red on its own. If a lane deliberately aligns the two,
   * this fails on the fact side and the right response is to drop the bullet from RESULTS.md §5, not
   * to loosen the check.
   */
  it("the reimplementation drops the try/catch and seeds the reduce differently (the fact)", () => {
    const bench = read(POLICY_BENCH);
    const product = read(path.join(serverSrc, "shadow-policy.ts"));
    const seedOf = (src: string): string | undefined =>
      /hits\.reduce[\s\S]{0,300}?,\s*"(commit|review|discard)"\s*,?\s*\)/.exec(src)?.[1];
    expect([
      /rule: "policy-rule-error"/.test(product),
      /policy-rule-error/.test(bench),
      seedOf(product),
      seedOf(bench),
    ]).toEqual([true, false, "review", "commit"]);
  });

  it("perf.md does not claim the lane reimplements nothing", () => {
    expect(["perf.md claims it reimplements nothing", /touches, mocks, or reimplements any kit file/.test(claims(PERF_PATH))]).toEqual(["perf.md claims it reimplements nothing", false]);
  });

  it("RESULTS.md does not call the reproduction exact or verbatim", () => {
    expect(["RESULTS.md calls the reproduction verbatim", /exact classify-then-loop pipeline verbatim/i.test(claims(RESULTS_PATH))]).toEqual(["RESULTS.md calls the reproduction verbatim", false]);
  });

  it("RESULTS.md names both ways the reproduction differs from the product loop", () => {
    const doc = claims(RESULTS_PATH);
    expect([/policy-rule-error/.test(doc), /seeds?/i.test(doc)]).toEqual([true, true]);
  });
});

/**
 * Gate 7: the shipped judge path is not the 14-rule array. `runner-factory.ts` composes
 * `withCapabilityGrantRule(...)` on top of `defaultPolicy`, so a row labelled "14 (shipped)" names
 * a rule set the product does not run.
 */
describe("gate 7: the rule-count label matches what runner-factory.ts composes", () => {
  it("the product wraps defaultPolicy with the capability grant rule (the fact)", () => {
    expect(/withCapabilityGrantRule\([\s\S]{0,160}?defaultPolicy\)/.test(read(FACTORY_PATH))).toBe(true);
  });

  it("RESULTS.md does not present 14 as the whole shipped judge path", () => {
    expect(["RESULTS.md labels 14 as the shipped set", /\| 14 \(shipped\) \|/.test(claims(RESULTS_PATH))]).toEqual(["RESULTS.md labels 14 as the shipped set", false]);
  });

  it("RESULTS.md names the rule the product adds", () => {
    expect(["RESULTS.md names withCapabilityGrantRule", /withCapabilityGrantRule/.test(claims(RESULTS_PATH))]).toEqual(["RESULTS.md names withCapabilityGrantRule", true]);
  });
});

/**
 * Gate 8: two prose claims whose product-side fix belongs to other lanes, but whose correction in
 * this lane's own documents needs no re-measurement.
 */
describe("gate 8: the two caveats this lane's own data requires", () => {
  /**
   * If someone hoists the fixture build out of the timed callback, this fails on the fact side and
   * the correct response is to remove the caveat from RESULTS.md §3 and re-run the sweep, not to
   * weaken the assertion.
   */
  it("concurrency-sweep.mts starts its clock after its own fixture copy (the fact)", () => {
    const src = read(path.join(here, "concurrency-sweep.mts"));
    const start = src.indexOf("Array.from({ length: level }");
    const clock = src.indexOf("const preRunMs", start);
    expect([start >= 0, clock > start]).toEqual([true, true]);
    // the copy is inside the same concurrent callback, ahead of the clock
    expect(src.slice(start, clock)).toMatch(/execFileAsync\("cp", \["-a"/);
  });

  it("RESULTS.md §3 does not attribute the growth to product I/O alone", () => {
    expect(["RESULTS.md carries the fixture-copy caveat", /fixture cop(y|ies)/i.test(claims(RESULTS_PATH))]).toEqual(["RESULTS.md carries the fixture-copy caveat", true]);
  });

  it("buildPolicyContext walks every real inode on every turn (the fact)", () => {
    const src = read(path.join(serverSrc, "policy-context.ts"));
    expect(src).toMatch(/for \(const \[rel, ino\] of realInodes\)/);
    expect(read(path.join(serverSrc, "transactional-runner.ts"))).toMatch(/realInodes: opened\.inodes/);
  });

  it("RESULTS.md does not describe judge as bounded by rules and effects alone", () => {
    const doc = claims(RESULTS_PATH);
    expect([
      /`buildPolicyContext` \+ `defaultPolicy` over 14 rules and 3 effects \|/.test(doc),
      /realInodes/.test(doc),
    ]).toEqual([false, true]);
  });
});

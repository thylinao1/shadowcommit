import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { MAX_EFFECT_BYTES, MAX_TURN_BYTES } from "../capture.js";
import { blastRadiusRule, OVERSIZE_RULE, OVERSIZE_TURN_RULE, REVIEW_AT_OR_ABOVE_TOUCHES } from "./blast-radius.js";

const ctx = basicContext(async () => "");

async function hitsFor(effects: EffectRecord[], recentTouches: string[] = []) {
  return blastRadiusRule.run(effects, basicContext(async () => "", { recentTouches }));
}

function paths(n: number, kind: EffectRecord["kind"] = "modify"): EffectRecord[] {
  return Array.from({ length: n }, (_, i) => ({ path: `src/mod${i}.js`, kind }));
}

/**
 * The size axis, swept from far under the cap to far over it. The corpus demonstrates 9 MiB, 64
 * MiB, 512 MiB and 1 GiB; a rule proven only at those four points is a rule whose boundary nobody
 * checked, and the boundary is the only part of a threshold that can be wrong.
 */
describe("a declared size over the per-effect cap holds the turn", () => {
  const UNDER = [0, 1, 1024, 1024 * 1024, MAX_EFFECT_BYTES - 1, MAX_EFFECT_BYTES];
  for (const bytes of UNDER) {
    it(`commits a single effect of ${bytes} bytes`, async () => {
      expect(await hitsFor([{ path: "data/blob0.bin", kind: "create", bytes }])).toEqual([]);
    });
  }

  const OVER = [
    MAX_EFFECT_BYTES + 1,
    9 * 1024 * 1024,
    64 * 1024 * 1024,
    512 * 1024 * 1024,
    1024 * 1024 * 1024,
    8 * 1024 * 1024 * 1024,
  ];
  for (const bytes of OVER) {
    it(`holds a single effect of ${bytes} bytes`, async () => {
      const hits = await hitsFor([{ path: "data/blob0.bin", kind: "create", bytes }]);
      expect(hits[0]?.rule).toBe(OVERSIZE_RULE);
      expect(hits[0]?.path).toBe("data/blob0.bin");
      // REVIEW, not discard. The platform cannot read this file, which is a fact about the
      // platform's budget and not a judgement about the turn, and a discard is the one outcome a
      // person can never appeal. Measured on a real provider: the demo's own first prompt ran
      // `npm install`, wrote a 9,112,572-byte typescript.js and had the whole turn destroyed.
      expect(hits.every((h) => h.decision === "review")).toBe(true);
      // Sweeping the whole range rather than the corpus's four points is what turned this up: one
      // effect past the 256 MiB turn cap is over BOTH limits, so it is reported twice, once per
      // limit it broke. The worst verdict is the same either way, and an operator reading the hits
      // should see both reasons rather than whichever one the loop happened to reach first.
      const expected = bytes > MAX_TURN_BYTES ? [OVERSIZE_RULE, OVERSIZE_TURN_RULE] : [OVERSIZE_RULE];
      expect(hits.map((h) => h.rule)).toEqual(expected);
    });
  }

  it("uses the same limit the capture layer uses", () => {
    expect(MAX_EFFECT_BYTES).toBe(8 * 1024 * 1024);
    expect(MAX_TURN_BYTES).toBe(256 * 1024 * 1024);
  });

  it("names every oversize effect, not only the first", async () => {
    const hits = await hitsFor([
      { path: "a.bin", kind: "create", bytes: MAX_EFFECT_BYTES + 1 },
      { path: "b.bin", kind: "create", bytes: MAX_EFFECT_BYTES + 2 },
    ]);
    expect(hits.filter((h) => h.rule === OVERSIZE_RULE).map((h) => h.path)).toEqual(["a.bin", "b.bin"]);
  });
});

/** The turn total is its own limit, so many legal effects can still be an illegal turn. */
describe("a turn whose declared effects total over the turn cap is held", () => {
  const EACH = 4 * 1024 * 1024;
  const JUST_UNDER = MAX_TURN_BYTES / EACH;
  it(`commits ${JUST_UNDER} effects of ${EACH} bytes, exactly at the turn limit`, async () => {
    const effects = Array.from({ length: JUST_UNDER }, (_, i) => ({ path: `p${i}`, kind: "create" as const, bytes: EACH }));
    const hits = await hitsFor(effects);
    expect(hits.map((h) => h.rule)).not.toContain(OVERSIZE_TURN_RULE);
  });

  it("holds one effect past the turn limit", async () => {
    const effects = Array.from({ length: JUST_UNDER + 1 }, (_, i) => ({ path: `p${i}`, kind: "create" as const, bytes: EACH }));
    const hits = await hitsFor(effects);
    const turnHit = hits.find((h) => h.rule === OVERSIZE_TURN_RULE);
    expect(turnHit?.decision).toBe("review");
  });
});

/** A field the capture layer did not fill, or filled with nonsense, must not decide anything. */
describe("a missing or unusable size decides nothing", () => {
  it("commits an effect that declares no size at all", async () => {
    expect(await hitsFor([{ path: "vendor/data.bin", kind: "create" }])).toEqual([]);
  });

  for (const bytes of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
    it(`ignores a declared size of ${bytes}`, async () => {
      expect(await hitsFor([{ path: "x.bin", kind: "create", bytes }])).toEqual([]);
    });
  }
});

/**
 * The path-count half of the rule, unchanged. Adding the size check must not move the count
 * threshold, and the count threshold must keep reporting through the same two rule ids.
 */
describe("the touch count still decides what it decided", () => {
  for (let n = 1; n < REVIEW_AT_OR_ABOVE_TOUCHES; n += 1) {
    it(`commits a turn touching ${n} path(s)`, async () => {
      expect(await hitsFor(paths(n))).toEqual([]);
    });
  }

  for (const n of [REVIEW_AT_OR_ABOVE_TOUCHES, REVIEW_AT_OR_ABOVE_TOUCHES + 1, 16]) {
    it(`holds a turn touching ${n} paths`, async () => {
      const hits = await hitsFor(paths(n));
      expect(hits).toHaveLength(1);
      expect(hits[0]?.rule).toBe("large-blast-radius");
      expect(hits[0]?.decision).toBe("review");
    });
  }

  it("still holds on the cumulative window and still names it separately", async () => {
    const hits = await hitsFor(paths(2), ["src/old0.js", "src/old1.js", "src/old2.js", "src/old3.js", "src/old4.js", "src/old5.js"]);
    expect(hits[0]?.rule).toBe("large-blast-radius:cumulative");
  });

  it("still leaves a dependency tree out of the count", async () => {
    const tree = Array.from({ length: 40 }, (_, i) => ({
      path: `node_modules/x/f${i}.js`, kind: "create" as const, effectClass: "dependency-tree",
    }));
    expect(await hitsFor(tree)).toEqual([]);
  });

  it("reports both halves when a turn is wide and oversize at once", async () => {
    const effects: EffectRecord[] = [
      ...paths(REVIEW_AT_OR_ABOVE_TOUCHES),
      { path: "data/blob.bin", kind: "create", bytes: MAX_EFFECT_BYTES + 1 },
    ];
    const hits = await blastRadiusRule.run(effects, ctx);
    expect(hits.map((h) => h.rule)).toEqual([OVERSIZE_RULE, "large-blast-radius"]);
    expect(hits.map((h) => h.decision)).toEqual(["review", "review"]);
  });
});

/**
 * The exemption axis, swept whole rather than at the one point it was demonstrated.
 *
 * `npm install` writing a 9,112,572-byte `typescript.js` is where this was found, but the thing
 * being changed is a pair of booleans (is it a dependency tree, is it a create) crossed with a size
 * threshold, so all six combinations are checked at both sides of the boundary. A fix right at the
 * demonstrated point and wrong two hundred bytes later is the failure this repository keeps
 * producing.
 */
const SIZE_SWEEP = [
  1024 * 1024,
  MAX_EFFECT_BYTES - 1,
  MAX_EFFECT_BYTES,
  MAX_EFFECT_BYTES + 1,
  9_112_572, // the real typescript.js from the real run
  10_573_778, // the real esbuild binary from this repository's own node_modules
  64 * 1024 * 1024,
  512 * 1024 * 1024,
];

/**
 * One effect large enough can break BOTH limits, and then it is reported once per limit it broke.
 * Spelling that out here rather than at each call site keeps the sweep honest at 512 MiB, which is
 * over the per-effect cap and over the per-turn cap at the same time.
 */
function expectedSizeRules(bytes: number): string[] {
  if (bytes <= MAX_EFFECT_BYTES) return [];
  return bytes > MAX_TURN_BYTES ? [OVERSIZE_RULE, OVERSIZE_TURN_RULE] : [OVERSIZE_RULE];
}

const DEPENDENCY_PATHS = [
  "node_modules/typescript/lib/typescript.js",
  "vendor/pkg/lib.rb",
  ".venv/lib/python3.12/site-packages/torch/_C.so",
];

describe("an install is upstream's bytes, so a dependency-tree CREATE is not capped", () => {
  for (const dependencyPath of DEPENDENCY_PATHS) {
    for (const bytes of SIZE_SWEEP) {
      it(`commits a ${bytes}-byte create at ${dependencyPath}`, async () => {
        const hits = await hitsFor([
          { path: dependencyPath, kind: "create", bytes, effectClass: "dependency-tree" },
        ]);
        expect(hits).toEqual([]);
      });
    }
  }

  it("exempts the create from the TURN total as well, not only from the per-effect check", async () => {
    // Without this the per-effect exemption is defeated by the per-turn cap on the very next real
    // project and only the rule id in the journal changes. This repository's own node_modules is
    // 115 MiB, so a project with no framework at all is already at 45% of the 256 MiB line.
    const tree = Array.from({ length: 200 }, (_, i) => ({
      path: `node_modules/big/chunk${i}.bin`,
      kind: "create" as const,
      bytes: 4 * 1024 * 1024, // 800 MiB of install, more than three times the turn cap
      effectClass: "dependency-tree",
    }));
    expect(await hitsFor(tree)).toEqual([]);
  });

  it("still counts the turn's OWN bytes when an install rides alongside them", async () => {
    const tree = Array.from({ length: 200 }, (_, i) => ({
      path: `node_modules/big/chunk${i}.bin`,
      kind: "create" as const,
      bytes: 4 * 1024 * 1024,
      effectClass: "dependency-tree",
    }));
    const mine = Array.from({ length: 65 }, (_, i) => ({
      path: `dist/part${i}.js`,
      kind: "create" as const,
      bytes: 4 * 1024 * 1024, // 260 MiB of the turn's own work, past the 256 MiB line
      effectClass: "source",
    }));
    const hits = await hitsFor([...tree, ...mine]);
    expect(hits.map((h) => h.rule)).toContain(OVERSIZE_TURN_RULE);
  });
});

describe("tampering with an installed tree is a MODIFY, and a modify is still capped", () => {
  for (const dependencyPath of DEPENDENCY_PATHS) {
    for (const bytes of SIZE_SWEEP) {
      it(`${expectedSizeRules(bytes).length ? "holds" : "commits"} a ${bytes}-byte modify at ${dependencyPath}`, async () => {
        const hits = await hitsFor([
          { path: dependencyPath, kind: "modify", bytes, effectClass: "dependency-tree" },
        ]);
        expect(hits.map((h) => h.rule)).toEqual(expectedSizeRules(bytes));
        expect(hits.every((h) => h.decision === "review")).toBe(true);
      });
    }
  }

  it("counts a dependency-tree modify against the turn total", async () => {
    const effects = Array.from({ length: 65 }, (_, i) => ({
      path: `node_modules/x/f${i}.bin`,
      kind: "modify" as const,
      bytes: 4 * 1024 * 1024,
      effectClass: "dependency-tree",
    }));
    expect((await hitsFor(effects)).map((h) => h.rule)).toContain(OVERSIZE_TURN_RULE);
  });
});

describe("an ordinary path is capped at every size, whichever way it was written", () => {
  for (const kind of ["create", "modify"] as const) {
    for (const bytes of SIZE_SWEEP) {
      it(`${expectedSizeRules(bytes).length ? "holds" : "commits"} a ${bytes}-byte ${kind} at dist/bundle.js`, async () => {
        const hits = await hitsFor([{ path: "dist/bundle.js", kind, bytes, effectClass: "source" }]);
        expect(hits.map((h) => h.rule)).toEqual(expectedSizeRules(bytes));
        expect(hits.every((h) => h.decision === "review")).toBe(true);
      });
    }
  }

  it("holds a dependency-shaped path whose class says it is not a dependency tree", async () => {
    // the class decides, not the spelling, so a mis-declared class cannot buy the exemption
    const hits = await hitsFor([
      { path: "node_modules/.hooks/postinstall", kind: "create", bytes: 9 * 1024 * 1024, effectClass: "exec-surface:shell" },
    ]);
    expect(hits.map((h) => h.rule)).toEqual([OVERSIZE_RULE]);
  });
});

/**
 * Capture's own marker, which is the authority when the effect came from a real turn: the runner's
 * caps are constructor options while this rule compares against the shipped constants it imports,
 * so a runner configured with a LOWER cap records a file it never read whose declared size is under
 * the constant. Reading only the size there would commit an unread file.
 */
describe("capture's oversize marker holds the turn on its own", () => {
  it("holds an effect marked oversize whose declared size is under the shipped cap", async () => {
    const hits = await hitsFor([
      { path: "data/blob.bin", kind: "create", bytes: 2 * 1024 * 1024, oversize: true },
    ]);
    expect(hits.map((h) => h.rule)).toEqual([OVERSIZE_RULE]);
    expect(hits[0]?.decision).toBe("review");
  });

  it("holds an effect marked oversize that declares no size at all", async () => {
    const hits = await hitsFor([{ path: "data/blob.bin", kind: "create", oversize: true }]);
    expect(hits.map((h) => h.rule)).toEqual([OVERSIZE_RULE]);
  });

  it("does not double-report an effect that is both marked and over the shipped cap", async () => {
    const hits = await hitsFor([
      { path: "data/blob.bin", kind: "create", bytes: MAX_EFFECT_BYTES + 1, oversize: true },
    ]);
    expect(hits.map((h) => h.rule)).toEqual([OVERSIZE_RULE]);
  });
});

import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  MIN_ARMED_FILES,
  READ_EXPOSURE_RULE,
  SELECTIVITY_CEILING,
  observedPath,
  readExposureOf,
  readExposureRule,
} from "./read-exposure.js";
import { rules } from "./index.js";
import { defaultPolicy } from "../shadow-policy.js";
import { attachReadWitness, readWitnessOf, type ReadWitnessRecord } from "../read-witness.js";
import { buildPolicyContext } from "../policy-context.js";
import { resolveLimits } from "../capture.js";
import { basicContext, type EffectRecord, type PolicyContext } from "../policy-types.js";

/**
 * The rule that makes a read judgeable, and the near misses that must stay committed.
 *
 * The signal underneath it is cheap to misuse. `docs/READ-WITNESS.md` measured the raw
 * protected-read bit at 48/48 on read-only attack turns and 17/48 = 35.4% on benign ones, so the
 * only interesting question about this rule is which of those seventeen it refuses to hold. Every
 * negative below is one of those shapes, written as a turn rather than as a number, so a later edit
 * that widens the rule fails here instead of in a queue somebody has to work through.
 *
 * The witness is supplied through `attachReadWitness`, which is the same accessor the runner uses
 * (`transactional-runner.ts` at the policy call) and the same one `buildPolicyContext` now fills
 * from its input. No test here fakes the rule's own reader.
 */

const WORKSPACE_FILES = 200;

/** a witness in the shape `summariseReadWitness` produces, with the fields a test wants named */
function witness(over: Partial<ReadWitnessRecord> = {}): ReadWitnessRecord {
  const reads = over.reads ?? 1;
  const armed = over.armed ?? WORKSPACE_FILES;
  return {
    supported: true,
    reason: "armed",
    armed,
    reads,
    tampered: 0,
    protectedReads: 0,
    blindSpots: 0,
    selectivity: armed === 0 ? null : reads / armed,
    paths: [],
    pathsTruncated: 0,
    ...over,
  };
}

function contextWith(
  record: ReadWitnessRecord | null,
  extra: Partial<PolicyContext> = {},
): PolicyContext {
  return attachReadWitness(basicContext(async () => "", extra), record);
}

const created = (p: string): EffectRecord => ({ path: p, kind: "create", canonicalPath: p });
const outbound: EffectRecord = {
  path: "net:POST audit.example:443/collect",
  kind: "outbound",
  method: "POST",
  host: "audit.example",
  port: 443,
  urlPath: "/collect",
};

describe("a turn that opened a protected file and produced nothing to roll back", () => {
  it("holds a selective read of the credential with no effects at all", async () => {
    const hits = await readExposureRule.run(
      [],
      contextWith(witness({ protectedReads: 1, paths: [".env"] })),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.rule).toBe(READ_EXPOSURE_RULE);
    expect(hits[0]?.decision).toBe("review");
    expect(hits[0]?.path).toBe(".env");
    // the operator has to be able to read WHY without opening the source
    expect(hits[0]?.detail).toContain("wrote nothing");
    expect(hits[0]?.detail).toContain(".env");
  });

  it("holds a selective read followed by an outbound request", async () => {
    const hits = await readExposureRule.run(
      [outbound],
      contextWith(witness({ protectedReads: 1, paths: ["config/secrets/prod.key"] })),
    );
    expect(hits.map((h) => h.decision)).toEqual(["review"]);
    expect(hits[0]?.detail).toContain("outbound request");
    expect(hits[0]?.path).toBe("config/secrets/prod.key");
  });

  it("holds the evasion: the read bit restored by hand, which leaves only the change time", async () => {
    // `cp -p` then `touch -r` puts the access time back exactly, so `reads` is 0 and the observation
    // arrives as a tampered one. It is still a protected file this turn opened.
    const hits = await readExposureRule.run(
      [],
      contextWith(
        witness({
          reads: 0,
          tampered: 1,
          protectedReads: 1,
          paths: [".env (timestamp-tampered)"],
        }),
      ),
    );
    expect(hits).toHaveLength(1);
    // the marker is a display suffix, not part of the path, and the hit must not carry it
    expect(hits[0]?.path).toBe(".env");
  });

  it("uses the context's protected set, not a list of its own", async () => {
    const declared = { protectedPaths: [/(^|\/)vault\.txt$/] };
    const record = witness({ protectedReads: 1, paths: ["ops/vault.txt"] });
    expect(await readExposureRule.run([], contextWith(record, declared))).toHaveLength(1);
    // the same turn on a workspace that never declared it is ordinary
    expect(await readExposureRule.run([], contextWith(record))).toEqual([]);
  });

  it("names several files and bounds the list rather than printing a directory", async () => {
    const paths = Array.from({ length: 9 }, (_, i) => `secrets/key-${i}.pem`);
    const hits = await readExposureRule.run(
      [],
      contextWith(witness({ reads: 9, protectedReads: 9, paths })),
    );
    expect(hits[0]?.detail).toContain("and 4 more");
    expect(hits[0]?.detail).not.toContain("key-8.pem");
  });
});

describe("the benign shapes the raw witness fires on, which this rule must not hold", () => {
  it("abstains on a whole-tree sweep, which is 12 of the 17 measured false positives", async () => {
    // `grep -rn router .` opens every file in the workspace and takes the credential with it.
    const hits = await readExposureRule.run(
      [],
      contextWith(
        witness({ reads: WORKSPACE_FILES, protectedReads: 1, paths: [".env", "src/app.ts"] }),
      ),
    );
    expect(hits).toEqual([]);
  });

  it("abstains when the turn read the credential and then did ordinary work", async () => {
    const hits = await readExposureRule.run(
      [created("src/db.ts")],
      contextWith(witness({ protectedReads: 1, paths: [".env"] })),
    );
    expect(hits).toEqual([]);
  });

  it("abstains when nothing protected was opened, however selective the turn was", async () => {
    const hits = await readExposureRule.run(
      [],
      contextWith(witness({ protectedReads: 0, paths: ["src/app.ts"] })),
    );
    expect(hits).toEqual([]);
  });

  it("abstains on a checked-in credential template, which carries nothing to take", async () => {
    // `.env.example` matches the shipped protected pattern and was the fifth of the five benign
    // turns that fired at every selectivity threshold. This exclusion is local to reads: the same
    // name as a WRITE target is still `protected-asset-write`, which this rule does not touch.
    for (const template of [".env.example", ".env.sample", "config/.env.template"]) {
      const hits = await readExposureRule.run(
        [],
        contextWith(witness({ protectedReads: 1, paths: [template] })),
      );
      expect([template, hits]).toEqual([template, []]);
    }
  });

  it("still holds the real credential when a template was read beside it", async () => {
    const hits = await readExposureRule.run(
      [],
      contextWith(witness({ reads: 2, protectedReads: 2, paths: [".env.example", ".env"] })),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.path).toBe(".env");
  });
});

describe("the three silences, which are not evidence and must never become a hold", () => {
  it("abstains with no witness at all, which is every overlay-sealed turn", async () => {
    expect(await readExposureRule.run([], contextWith(null))).toEqual([]);
    expect(readExposureOf([], contextWith(null))).toBe("no-witness");
    // and a context that never carried the field, which is every direct caller of basicContext
    expect(await readExposureRule.run([], basicContext(async () => ""))).toEqual([]);
  });

  it("abstains on a mount that cannot show reads, even with counts still on the record", async () => {
    // "cannot see reads" and "read nothing" are different answers. A record that reports itself
    // unsupported is the first, and no count on it may be quoted.
    const frozen = witness({
      supported: false,
      reason: "atime-frozen",
      protectedReads: 1,
      paths: [".env"],
    });
    expect(await readExposureRule.run([], contextWith(frozen))).toEqual([]);
    expect(readExposureOf([], contextWith(frozen))).toBe("unsupported");
    for (const reason of ["probe-failed", "collect-failed", "arm-failed"]) {
      const record = { ...frozen, reason };
      expect([reason, await readExposureRule.run([], contextWith(record))]).toEqual([reason, []]);
    }
  });

  it("abstains on a tree too small for the selectivity fraction to mean anything", async () => {
    // The gate is `reads / armed <= 0.05`. On four files the smallest non-zero value is 0.25, so no
    // turn that read anything can pass it and the only turns that could are the ones with no read
    // bit at all. That is not the discriminator the 96 measured turns describe, so the rule declines
    // the whole tree instead of applying a fraction it cannot compute.
    const tiny = witness({
      armed: 4,
      reads: 0,
      tampered: 1,
      protectedReads: 1,
      paths: [".env (timestamp-tampered)"],
    });
    expect(await readExposureRule.run([], contextWith(tiny))).toEqual([]);
    expect(readExposureOf([], contextWith(tiny))).toBe("tree-too-small");

    // one file above the floor, the same turn is judged
    const enough = { ...tiny, armed: MIN_ARMED_FILES, selectivity: 0 };
    expect(await readExposureRule.run([], contextWith(enough))).toHaveLength(1);
  });

  it("abstains when nothing was armed, so selectivity is null rather than zero", async () => {
    const nothing = witness({ armed: 0, reads: 0, protectedReads: 1, paths: [".env"] });
    expect(nothing.selectivity).toBeNull();
    expect(await readExposureRule.run([], contextWith(nothing))).toEqual([]);
  });
});

describe("the threshold is where the measurement put it", () => {
  it("holds at the ceiling and abstains one read above it", async () => {
    const armed = 100;
    const atCeiling = Math.round(armed * SELECTIVITY_CEILING);
    const record = (reads: number): ReadWitnessRecord =>
      witness({ armed, reads, protectedReads: 1, paths: [".env"] });

    expect(await readExposureRule.run([], contextWith(record(atCeiling)))).toHaveLength(1);
    expect(await readExposureRule.run([], contextWith(record(atCeiling + 1)))).toEqual([]);
    expect(readExposureOf([], contextWith(record(atCeiling + 1)))).toBe("swept-the-tree");
  });

  it("the armed floor is the smallest tree on which one read can reach the ceiling", () => {
    expect(MIN_ARMED_FILES).toBe(Math.ceil(1 / SELECTIVITY_CEILING));
    expect(1 / MIN_ARMED_FILES).toBeLessThanOrEqual(SELECTIVITY_CEILING);
    expect(1 / (MIN_ARMED_FILES - 1)).toBeGreaterThan(SELECTIVITY_CEILING);
  });

  it("strips only the kind marker and leaves a path that merely looks like one", () => {
    expect(observedPath(".env (timestamp-tampered)")).toBe(".env");
    expect(observedPath("src/a (timestamp-tampered).ts")).toBe("src/a (timestamp-tampered).ts");
    expect(observedPath(".env")).toBe(".env");
  });
});

describe("the wiring, without which the rule is a module nobody calls", () => {
  it("is registered, and is registered before blast radius, which stays last", () => {
    const names = rules.map((rule) => rule.name);
    expect(names).toContain(READ_EXPOSURE_RULE);
    expect(names[names.length - 1]).toBe("large-blast-radius");
    expect(names.indexOf(READ_EXPOSURE_RULE)).toBeLessThan(names.length - 1);
  });

  it("can only ever ask a person, so a false positive costs a hold and never the work", () => {
    expect(readExposureRule.decisions).toEqual(["review"]);
  });

  it("changes the shipped verdict on a read-only turn, and only when the witness is there", async () => {
    const record = witness({ protectedReads: 1, paths: [".env"] });
    const withWitness = await defaultPolicy([], contextWith(record));
    expect(withWitness.decision).toBe("review");
    expect(withWitness.rule).toBe(READ_EXPOSURE_RULE);

    // THE CONTROL. The same empty effect set with no witness on the context is what the product
    // returned before this rule existed, and still returns for every overlay-sealed turn.
    const without = await defaultPolicy([], contextWith(null));
    expect([without.decision, without.rule]).toEqual(["commit", "none"]);
  });

  it("never turns a discard into anything weaker, because the worst decision still wins", async () => {
    const record = witness({ protectedReads: 1, paths: [".env"] });
    const verdict = await defaultPolicy([{ path: ".env", kind: "modify", canonicalPath: ".env" }], contextWith(record));
    expect(verdict.decision).toBe("discard");
    expect(verdict.rule).toBe("protected-asset-write");
  });

  it("buildPolicyContext carries the record onto the context it hands the policy", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "read-exposure-ctx-"));
    try {
      const workspace = path.join(root, "ws");
      await fs.mkdir(workspace, { recursive: true });
      const input = {
        shadowDir: path.join(root, "shadow"),
        mechanism: "copy" as const,
        workspacePath: workspace,
        journalPath: path.join(root, "journal.jsonl"),
        agentId: "11111111-1111-4111-8111-111111111111",
        limits: resolveLimits(),
        platformSecrets: [],
        registryAllowlist: [],
        realInodes: new Map<string, string>(),
      };
      const record = witness({ protectedReads: 1, paths: [".env"] });

      const carried = await buildPolicyContext({ ...input, readWitness: record });
      expect(readWitnessOf(carried)).toEqual(record);
      expect(await readExposureRule.run([], carried)).toHaveLength(1);

      // and a builder given nothing produces the null state rather than an absent field, so the
      // three answers stay distinguishable at the far end
      const bare = await buildPolicyContext(input);
      expect(bare.readWitness).toBeNull();
      expect(await readExposureRule.run([], bare)).toEqual([]);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

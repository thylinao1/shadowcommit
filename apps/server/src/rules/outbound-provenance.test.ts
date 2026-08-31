import { describe, expect, it } from "vitest";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { heldRecordToEffect } from "../broker.js";
import { OUTBOUND_PROVENANCE_RULE, rule } from "./outbound-provenance.js";

/**
 * Measured on a running instance before this rule existed: a PUT of the raw protected file was
 * correctly HELD by the broker, the journal recorded provenance "customers.jsonl (literal)" with
 * its sha256, and the policy returned commit with ZERO hits, so the turn auto-committed and the
 * write was replayed to the destination. The broker knew exactly what the body was and the decision
 * layer never asked.
 *
 * Two things had to be true for that: no rule read `provenance`, and `heldRecordToEffect` dropped
 * `secretPattern` and `highEntropy` even though the broker had already computed both.
 */

const ctx = basicContext(async () => "", { addedLinesOf: async () => "" });

const held = (over: Partial<Record<string, unknown>> = {}) => ({
  effectId: "e1",
  method: "PUT",
  host: "172.19.0.2",
  port: 8398,
  urlPath: "/upload-raw",
  bytes: 240,
  sha256: "8237dfd5",
  provenance: null,
  secretPattern: null,
  ...over,
});

describe("a held write is judged on what it carries", () => {
  it("discards a held body the broker traced to a protected file", async () => {
    const effect = heldRecordToEffect(held({ provenance: "customers.jsonl (literal)" }) as never);
    const hits = await rule.run([effect], ctx);

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ rule: OUTBOUND_PROVENANCE_RULE, decision: "discard" });
    expect(hits[0]?.detail).toContain("customers.jsonl");
    // the destination is named, because a queue entry that does not say where is not reviewable
    expect(hits[0]?.detail).toContain("PUT 172.19.0.2:8398/upload-raw");
  });

  it("discards a held body carrying a named credential pattern", async () => {
    const effect = heldRecordToEffect(held({ secretPattern: "aws-access-key-id" }) as never);
    const hits = await rule.run([effect], ctx);
    expect(hits[0]).toMatchObject({ decision: "discard" });
    expect(hits[0]?.detail).toContain("aws-access-key-id");
  });

  it("only ASKS about high entropy, because a compressed upload is ordinary", async () => {
    const effect = heldRecordToEffect(held({ highEntropy: true }) as never);
    const hits = await rule.run([effect], ctx);
    expect(hits[0]).toMatchObject({ decision: "review" });
  });

  it("says nothing about an ordinary held write", async () => {
    expect(await rule.run([heldRecordToEffect(held() as never)], ctx)).toEqual([]);
  });

  it("says nothing about file effects, which the content scanners already own", async () => {
    const files: EffectRecord[] = [
      { path: "src/app.ts", kind: "modify" },
      { path: "customers.jsonl", kind: "create" },
    ];
    expect(await rule.run(files, ctx)).toEqual([]);
  });
});

describe("the broker's findings survive the trip to the policy", () => {
  it("carries provenance, secretPattern and highEntropy onto the effect", () => {
    const effect = heldRecordToEffect(
      held({ provenance: "customers.jsonl (literal)", secretPattern: "stripe-key", highEntropy: true }) as never,
    );
    // all three were computed by scanPayload; two of them used to be dropped here
    expect(effect).toMatchObject({
      kind: "outbound",
      provenance: "customers.jsonl (literal)",
      secretPattern: "stripe-key",
      highEntropy: true,
    });
  });

  it("leaves the fields off when the broker found nothing, so absence stays meaningful", () => {
    const effect = heldRecordToEffect(held() as never);
    expect(effect).not.toHaveProperty("provenance");
    expect(effect).not.toHaveProperty("secretPattern");
    expect(effect).not.toHaveProperty("highEntropy");
  });
});

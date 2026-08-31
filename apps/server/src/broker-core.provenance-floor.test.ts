/**
 * The size below which the broker's content inspection cannot see a theft.
 *
 * `provenanceOf` cuts the protected file into 48-byte probes and asks whether the OUTBOUND PAYLOAD
 * contains one. That direction creates a floor: a payload shorter than a probe cannot contain a
 * probe, so a small theft is invisible by construction rather than by oversight.
 *
 * These numbers are pinned because the floor is a DECISION, not an accident. Shrinking the window
 * would catch smaller thefts and would also refuse ordinary traffic, because sixteen bytes of a
 * customer file is a string like `,ada@example.` that occurs in requests having nothing to do with
 * the file. A control that fires constantly is turned off. `research/PROVENANCE-FLOOR.md` carries
 * the full measurement and the reasoning; this file exists so the floor cannot move without somebody
 * choosing to move it.
 */
import { describe, expect, it } from "vitest";
import { provenanceOf, scanPayload } from "../broker/broker-core.mjs";

/** A protected file with the shape of a real one: repeating structure, no long unique runs. */
function protectedFile(bytes: number): string {
  let out = "";
  let i = 0;
  while (out.length < bytes) out += `line${i++}-${"abcdefghijklmnopqrstuvwxyz".slice(0, 20)}\n`;
  return out.slice(0, bytes);
}

/**
 * Detection rate over every offset at a stride coprime with the probe stride of 32, so the theft
 * lands at varying alignments rather than repeatedly at the same one.
 */
function detectionRate(file: string, stolenBytes: number): number {
  const corpus = { "customers.jsonl": file };
  let caught = 0;
  let total = 0;
  for (let at = 0; at + stolenBytes <= file.length; at += 37) {
    total += 1;
    if (provenanceOf(file.slice(at, at + stolenBytes), corpus) !== null) caught += 1;
  }
  return total === 0 ? 0 : caught / total;
}

describe("the provenance floor, measured rather than asserted", () => {
  const file = protectedFile(4000);

  it("catches a 64-byte theft at every offset", () => {
    expect(detectionRate(file, 64)).toBe(1);
  });

  it("still catches a large theft at every offset", () => {
    for (const size of [80, 128, 200]) expect([size, detectionRate(file, size)]).toEqual([size, 1]);
  });

  it("cannot see a 16-byte theft at any offset, which is the floor and is deliberate", () => {
    expect(detectionRate(file, 16)).toBe(0);
  });

  it("degrades rather than cliffs between the two, so the boundary is not a surprise", () => {
    const at32 = detectionRate(file, 32);
    const at48 = detectionRate(file, 48);
    expect([at32 > 0, at32 < 0.5]).toEqual([true, true]);
    expect([at48 > at32, at48 < 1]).toEqual([true, true]);
  });
});

describe("what the other two detectors cover, and what nothing covers", () => {
  const file = "id,email,token\n1,ada@example.com,sk-live-AAAABBBBCCCCDDDDEEEEFFFF\n2,bob@example.com,hunter2pass\n";
  const corpus = { "customers.jsonl": file };

  it("refuses a credential with a recognisable shape, twice over", () => {
    const scan = scanPayload("sk-live-AAAABBBBCCCCDDDDEEEEFFFF", corpus, "");
    // Both fire, which is the layering working: the floor never applies to a shaped credential.
    expect([!!scan.provenance, !!scan.secretPattern]).toEqual([true, true]);
    expect(scan.refuseReason).not.toBeNull();
  });

  it("refuses a bulk theft on provenance", () => {
    expect(scanPayload(file.slice(20, 84), corpus, "").refuseReason).not.toBeNull();
  });

  it("DOES NOT refuse one email address, and this is the residual risk", () => {
    const scan = scanPayload("ada@example.com", corpus, "");
    expect([scan.provenance, scan.secretPattern, scan.refuseReason]).toEqual([null, null, null]);
  });

  it("DOES NOT refuse a short unstructured password", () => {
    expect(scanPayload("hunter2pass", corpus, "").refuseReason).toBeNull();
  });
});

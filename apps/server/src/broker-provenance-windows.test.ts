import { describe, expect, it } from "vitest";
import { provenanceOf } from "../broker/broker-core.mjs";

/**
 * provenanceOf is the only thing tying bytes leaving the box to a file the operator declared
 * protected. A null answer does two things at once: the automatic path lets the payload go, and the
 * human approving a held write is shown a network write with no stated origin.
 *
 * It used to take ONE 48-byte probe from offset 0, so dropping the first line defeated it. Measured
 * before the fix, on the export below: the whole file was caught, and `sed 1d` escaped. That is not an
 * exotic attack. It is an idiom an agent asked to summarise a file emits by accident.
 */

const EXPORT = [
  "# customer export, confidential",
  "id,email,card_last4",
  "1,alice@example.com,4242",
  "2,bob@example.com,1881",
  "3,carol@example.com,9310",
  "4,dave@example.com,7727",
].join("\n");

const corpus = { "customers.csv": EXPORT };

describe("protected-file provenance survives the front of the file being removed", () => {
  it("still names the file when the first line is gone", () => {
    const dropped = EXPORT.split("\n").slice(1).join("\n");
    expect(provenanceOf(dropped, corpus)?.file).toBe("customers.csv");
  });

  it("names it at every line offset, not just the one the fix was demonstrated on", () => {
    // the sweep, not the point: a fix that works at drop=1 and fails at drop=3 is the shape this
    // repository keeps producing, so the test asks the whole range
    const lines = EXPORT.split("\n");
    for (let drop = 0; drop < lines.length - 1; drop += 1) {
      const payload = lines.slice(drop).join("\n");
      if (payload.length < 48) continue;
      expect(provenanceOf(payload, corpus)?.file, `dropping ${drop} line(s)`).toBe("customers.csv");
    }
  });

  it("names it when the cut lands mid-line, at any byte offset", () => {
    const buf = Buffer.from(EXPORT);
    for (let cut = 0; cut < buf.length - 60; cut += 5) {
      expect(provenanceOf(buf.subarray(cut).toString(), corpus)?.file, `byte cut at ${cut}`).toBe(
        "customers.csv",
      );
    }
  });

  it("still says nothing about a payload that has nothing to do with the corpus", () => {
    // the negative case: widening the search must not turn every request into a protected-file leak
    expect(provenanceOf("GET /health HTTP/1.1, and a body of ordinary words", corpus)).toBeNull();
    expect(provenanceOf("", corpus)).toBeNull();
  });

  it("catches a payload that shares no run of bytes with the file, by its values", () => {
    // This was pinned as an honest LIMIT of windowing: re-serialising the rows keeps every value and
    // preserves no 48-byte run, so no substring search could see it, and the note said closing it
    // needed a different technique. The token quorum is that technique, added after the same shape
    // (fields pulled out and re-joined) was measured leaving a live instance. The window arm still
    // reports first when a real run survives; this is the fallback that sees content whose byte
    // order was destroyed.
    const rows = EXPORT.split("\n").slice(2).map((line) => {
      const [id, email, card] = line.split(",");
      return { id, email, card };
    });
    const found = provenanceOf(JSON.stringify(rows), corpus);
    expect(found?.file).toBe("customers.csv");
    expect(found?.via).toContain("tokens");
  });
});

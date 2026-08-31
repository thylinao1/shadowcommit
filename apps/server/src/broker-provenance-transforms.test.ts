import { describe, expect, it } from "vitest";
// @ts-expect-error the broker is plain ESM with no type declarations
import { provenanceOf } from "../broker/broker-core.mjs";

/**
 * The three payloads that left a LIVE instance while the turn committed clean.
 *
 * A 240-byte protected corpus file was seeded into the workspace and a real turn sent four GET
 * query strings through the broker to the always-allowlisted model provider. The broker refused
 * only the raw file. It FORWARDED the other three, the provider logged all of them verbatim, and
 * the journal recorded egress {live: 5, refused: 1}, hiding the three exfil calls among the two
 * model calls.
 *
 * Every one escaped for the same structural reason: matching was contiguous 48-byte windows of the
 * file, so anything that destroys forward windows while keeping the bytes recoverable passed.
 *   reversed         no forward window survives reversal
 *   fields joined    order and separators destroyed, no window and no record reproduced
 *   one record       29 bytes is shorter than any 48-byte window of a 240-byte file
 */

const CORPUS = {
  "customers.jsonl": [
    '{"id":1,"email":"ada@ex.com"}',
    '{"id":2,"email":"bob@ex.com"}',
    '{"id":3,"email":"cy@ex.com"}',
    '{"id":4,"email":"dee@ex.com"}',
    '{"id":5,"email":"eve@ex.com"}',
    '{"id":6,"email":"fay@ex.com"}',
    '{"id":7,"email":"gus@ex.com"}',
    '{"id":8,"email":"hal@ex.com"}',
  ].join("\n"),
};
const FILE = CORPUS["customers.jsonl"];

describe("protected bytes are provenance however they are rearranged", () => {
  it("A: refuses the raw file, which is the one case that already worked", () => {
    expect(provenanceOf(FILE, CORPUS)?.file).toBe("customers.jsonl");
  });

  it("B: catches the whole file reversed, which destroys every forward window", () => {
    const reversed = [...FILE].reverse().join("");
    expect(provenanceOf(reversed, CORPUS)?.file).toBe("customers.jsonl");
  });

  it("C: catches the fields pulled out and re-joined with a different separator", () => {
    const emails = [...FILE.matchAll(/"email":"([^"]+)"/g)].map((m) => m[1]).join("|");
    expect(emails).toContain("ada@ex.com");
    expect(provenanceOf(`/exfil?tag=C_EMAILS=${emails}`, CORPUS)?.file).toBe("customers.jsonl");
  });

  it("D: catches ONE record, which is shorter than any window of the file", () => {
    const record = '{"id":1,"email":"ada@ex.com"}';
    expect(record.length).toBeLessThan(48); // the reason windows could never see it
    expect(provenanceOf(`/exfil?tag=D_ONEROW=${record}`, CORPUS)?.file).toBe("customers.jsonl");
  });

  it("catches a record that was url-encoded on its way out", () => {
    const encoded = encodeURIComponent('{"id":4,"email":"dee@ex.com"}');
    expect(provenanceOf(`/x?q=${encoded}`, CORPUS)?.file).toBe("customers.jsonl");
  });

  it("catches a long secret alone, without needing a quorum", () => {
    const env = { ".env": "API_KEY=sk-FIXTURE-KEY-NOT-REAL-000111222333\nNODE_ENV=production\n" };
    expect(provenanceOf("send sk-FIXTURE-KEY-NOT-REAL-000111222333 please", env)?.file).toBe(".env");
  });
});

describe("ordinary traffic is not provenance", () => {
  const env = { ".env": "NODE_ENV=production\nLOG_LEVEL=info\nPORT=3000\nAPP_NAME=launchpad\n" };

  it("passes normal model calls that share ordinary words with a config file", () => {
    for (const body of [
      "Summarise the production incident and the log level we should use.",
      '{"model":"gpt","messages":[{"role":"user","content":"explain NODE_ENV to me"}]}',
      "the app name is launchpad and the port is 3000",
      "Please refactor src/app.ts and keep the existing error handling.",
      "production",
    ]) {
      expect(provenanceOf(body, env), body).toBeNull();
    }
  });

  it("passes a body sharing a single email with the customer file", () => {
    expect(provenanceOf("reply to ada@ex.com about the ticket", CORPUS)).toBeNull();
  });

  it("passes an empty body and an empty corpus", () => {
    expect(provenanceOf("", CORPUS)).toBeNull();
    expect(provenanceOf("anything at all", {})).toBeNull();
  });
});

describe("the encoded arms see a record too, and the limits are written down", () => {
  /**
   * The encoded arms (base64, hex, url-encoded) iterate byte WINDOWS, so a record shorter than a
   * window was invisible to them exactly as it had been to the literal scan before record probes
   * existed. Closing that for the literal form and leaving it open for the encoded ones is a fix
   * that moves the defect, and an adversarial sweep found it: the base64 of one 29-byte record out
   * of a 240-byte file escaped every arm.
   */
  it("catches the base64 of a single record, which is shorter than any window", () => {
    const record = '{"id":1,"email":"ada@ex.com"}';
    const encoded = Buffer.from(record).toString("base64");
    expect(record.length).toBeLessThan(48); // the reason the window arms could not see it
    expect(provenanceOf(`/x?q=${encoded}`, CORPUS)?.file).toBe("customers.jsonl");
  });

  it("catches the hex of a single record", () => {
    const hex = Buffer.from('{"id":2,"email":"bob@ex.com"}').toString("hex");
    expect(provenanceOf(`/x?q=${hex}`, CORPUS)?.file).toBe("customers.jsonl");
  });

  /**
   * MEASURED LIMITS, recorded so nobody reads the scan as more than it is. An adversarial sweep of
   * eighteen shapes against this corpus caught twelve outright. Of the six that got through:
   *
   *   gzip then base64   NOT silent: entropy 4.98 trips highEntropy, so the outbound rule asks a
   *                      person rather than committing. Catching it properly needs decompression.
   *   rot13              silent. Entropy 4.19, under the 4.5 threshold, and no view reverses it.
   *                      Reversal is a view because it was measured leaving a live instance; every
   *                      other substitution cipher is an open class and adding them one at a time
   *                      is not a strategy.
   *   1, 2 or 3 emails   silent. Under the token quorum, which needs three distinct tokens AND 32
   *                      combined characters. Three ten-character emails is 29. The threshold is a
   *                      deliberate false-positive trade and moving it needs re-measuring against
   *                      the benign corpus, not a guess.
   *   half the bytes     not a real exfiltration: lossy and not reconstructible by the receiver.
   */
  it("asks a person about a compressed body instead of passing it silently", async () => {
    const { scanPayload } = (await import("../broker/broker-core.mjs")) as {
      scanPayload: (t: string, c: Record<string, string>) => { highEntropy: boolean };
    };
    const gz = (await import("node:zlib")).gzipSync(Buffer.from(FILE)).toString("base64");
    expect(scanPayload(gz, CORPUS).highEntropy, "a compressed body must at least be asked about").toBe(
      true,
    );
  });
});


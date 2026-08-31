import { describe, expect, it } from "vitest";
// @ts-expect-error the broker is plain ESM with no type declarations
import { CREDENTIAL_HEADERS, headerScanText, scanPayload } from "../broker/broker-core.mjs";

/**
 * A GET has no body, and the live path scanned the body and the URL and nothing else.
 *
 * The comment beside that scan said "a GET can carry the whole protected file in its query string",
 * which is true, and the query string was the only place anyone looked. Request headers were never
 * passed to the scanner at all, and `forward(target, method, req.headers, body, res)` sends them on
 * to the allowlisted destination verbatim. So a protected record in any header reached the scanner
 * as an empty string, matched nothing, and left the box.
 *
 * Measured against a two record customers.jsonl before the fix: the same record was REFUSED in the
 * query string and NOT REFUSED in a header.
 *
 * The reason this is not simply "scan the headers as well" is the credential arm. Measured,
 * `Bearer sk-proj-...` matches the `openai-style-key` secret pattern, so folding the Authorization
 * header into the secret scan would refuse every legitimate authenticated call the agent makes to
 * an allowlisted API. Closing an exfiltration hole by breaking all normal traffic is the fix that
 * moves the defect. Credential headers are therefore scanned for PROVENANCE only, which still
 * catches a customer record smuggled into Authorization, while a real bearer token passes.
 */

const RECORD = JSON.stringify({ id: 1, name: "Ada Lovelace", email: "ada@example.com", card: "4111111111111111" });
const CORPUS = {
  "customers.jsonl": [RECORD, JSON.stringify({ id: 2, name: "Alan Turing", email: "alan@example.com", card: "4222222222222222" })].join("\n"),
};

/** Exactly what the live path now does, so the test drives the real composition rather than a copy. */
function livePathScan(headers: Record<string, string>, body = "", urlPath = "/v1/metrics") {
  const h = headerScanText(headers);
  return scanPayload(`${body} ${urlPath} ${h.full}`, CORPUS, h.provenanceOnly);
}

describe("a protected record leaving in a request header", () => {
  for (const header of ["x-telemetry", "cookie", "x-forwarded-for", "referer"]) {
    it(`is refused when it rides in ${header}`, () => {
      const scan = livePathScan({ [header]: RECORD });
      expect(scan.refuseReason).toBe("protected-content-on-live-path");
      expect(scan.provenance).toEqual({ file: "customers.jsonl", via: "literal" });
    });
  }

  it("is refused in a credential header too, which is the point of scanning those for provenance", () => {
    const scan = livePathScan({ authorization: `Bearer ${RECORD}` });
    expect(scan.refuseReason).toBe("protected-content-on-live-path");
  });

  it("is still refused in the query string, which already worked and must not regress", () => {
    const scan = livePathScan({}, "", `/v1/metrics?d=${encodeURIComponent(RECORD)}`);
    expect(scan.refuseReason).toBe("protected-content-on-live-path");
  });

  it("is refused when split across a header and the query string", () => {
    // The header text is concatenated with the body and URL rather than scanned separately, so a
    // record cut in half across the two cannot fall between them.
    const half = Math.floor(RECORD.length / 2);
    const scan = livePathScan({ "x-part": RECORD.slice(half) }, "", `/v1/metrics?a=${RECORD.slice(0, half)}`);
    expect(scan.refuseReason).toBe("protected-content-on-live-path");
  });
});

describe("what must keep working, because refusing all of it would be the worse bug", () => {
  it("lets a normal agent bearer token through", () => {
    // This is the whole reason credential headers are provenance-only. `Bearer sk-proj-...` matches
    // openai-style-key, so a naive "scan every header" refuses every authenticated call there is.
    const scan = livePathScan({ authorization: "Bearer sk-proj-abc123def456ghi789jkl012mno345" });
    expect(scan.refuseReason).toBeNull();
  });

  it("lets ordinary request headers through", () => {
    const scan = livePathScan({ "user-agent": "curl/8.4.0", "content-type": "application/json", accept: "*/*" });
    expect(scan.refuseReason).toBeNull();
  });

  it("still refuses a credential in a header that is NOT a credential header", () => {
    // The provenance-only carve-out is exactly two header names. A key in x-api-key is still a key
    // leaving the box on the live path, and the secret arm must still see it.
    const scan = livePathScan({ "x-api-key": "sk-proj-abc123def456ghi789jkl012mno345" });
    expect(scan.refuseReason).toBe("secret-pattern-on-live-path");
  });

  it("keeps the credential carve-out to the two headers that mean 'credential'", () => {
    // A wider carve-out is a wider hole. If this list grows, it should be a decision somebody made.
    expect([...CREDENTIAL_HEADERS].sort()).toEqual(["authorization", "proxy-authorization"]);
  });
});

describe("headerScanText", () => {
  it("flattens an array-valued header rather than dropping it", () => {
    const h = headerScanText({ "set-cookie": ["a=" + RECORD, "b=2"] });
    expect(h.full).toContain(RECORD);
  });

  it("emits values only, because a name between two values breaks reassembly across locations", () => {
    // Measured: with names included, a record cut in half across the query string and a header was
    // NOT refused; with values only it is. A record split across a name and its value is just the
    // record with a space in it, which the whitespace-stripped view already handles, so the names
    // bought nothing and cost that case.
    const h = headerScanText({ "x-name": "value" });
    expect(h.full).toBe("value");
  });

  it("routes credential headers to the provenance-only side and nothing else there", () => {
    const h = headerScanText({ authorization: "Bearer x", "x-other": "y" });
    expect(h.provenanceOnly).toContain("Bearer x");
    expect(h.full).not.toContain("Bearer x");
    expect(h.full).toContain("y");
  });

  it("skips empty values instead of emitting a bare header name", () => {
    expect(headerScanText({ "x-empty": "", "x-set": "v" }).full).toBe("v");
  });
});

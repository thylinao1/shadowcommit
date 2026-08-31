import { describe, expect, it } from "vitest";
import {
  allowlistDecision,
  classifyCall,
  entropy,
  matchSecret,
  parseHostPort,
  provenanceLabel,
  provenanceOf,
  scanPayload,
} from "../broker/broker-core.mjs";
import {
  DEFAULT_EGRESS_ALLOWLIST,
  heldRecordToEffect,
  parseJsonLines,
  providerHostPort,
  summariseDecisions,
} from "./broker.js";

const PROTECTED = {
  "customers.jsonl":
    '{"id":1,"email":"ada@example.com"}\n{"id":2,"email":"bob@example.com"}\n{"id":3,"email":"cy@example.com"}\n',
};

describe("allowlist", () => {
  it("allows an exact host and port that the operator listed", () => {
    expect(allowlistDecision(["registry.npmjs.org:443"], "registry.npmjs.org", 443)).toBe(true);
  });

  it("denies a host nobody listed", () => {
    expect(allowlistDecision(["registry.npmjs.org:443"], "evil-collector.example.com", 443)).toBe(false);
  });

  it("denies the right host on the wrong port", () => {
    expect(allowlistDecision(["registry.npmjs.org:443"], "registry.npmjs.org", 8080)).toBe(false);
  });

  it("denies a suffix that merely ends in an allowlisted name", () => {
    // "anything ending in .npmjs.org" is how an allowlist becomes useless the moment an attacker
    // can resolve a name of their own choosing.
    expect(allowlistDecision(["registry.npmjs.org:443"], "registry.npmjs.org.attacker.tld", 443)).toBe(false);
  });

  it("denies a literal IP that was never listed", () => {
    expect(allowlistDecision([...DEFAULT_EGRESS_ALLOWLIST], "1.1.1.1", 443)).toBe(false);
  });

  it("matches case-insensitively, because DNS does", () => {
    expect(allowlistDecision(["registry.npmjs.org:443"], "Registry.NPMJS.org", 443)).toBe(true);
  });

  it("defaults a bare host entry to 443", () => {
    expect(parseHostPort("pypi.org", 443)).toEqual({ host: "pypi.org", port: 443 });
    expect(parseHostPort("collector:9100", 443)).toEqual({ host: "collector", port: 9100 });
  });
});

describe("call classification", () => {
  it("treats the model channel as live whatever the method is", () => {
    // spike I: a completion is a POST, so a method-only rule held all thirteen of the agent's own
    // model calls and the agent could not think at all.
    expect(classifyCall({ method: "POST", host: "broker", modelHosts: ["broker"] })).toBe("live");
  });

  it("treats GET and HEAD as read-like", () => {
    expect(classifyCall({ method: "GET", host: "registry.npmjs.org" })).toBe("read-like");
    expect(classifyCall({ method: "HEAD", host: "registry.npmjs.org" })).toBe("read-like");
  });

  it("holds every other method, which is what failing closed means", () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(classifyCall({ method, host: "collector", urlPath: "/ingest" })).toBe("write-like");
    }
  });

  it("passes an endpoint the operator declared read-only for that host and that method", () => {
    expect(
      classifyCall({
        method: "POST",
        host: "collector",
        urlPath: "/catalog",
        readOnlyDeclarations: [{ host: "collector", methods: ["POST"], pattern: "^/catalog(\\?.*)?$" }],
      }),
    ).toBe("read-like");
  });
});

describe("provenance", () => {
  it("finds the protected file sent as raw bytes", () => {
    const payload = "----form\r\n" + PROTECTED["customers.jsonl"] + "\r\n----form--";
    expect(provenanceOf(payload, PROTECTED)).toEqual({ file: "customers.jsonl", via: "literal" });
  });

  it("finds it JSON-escaped, which is what every model-channel body looks like", () => {
    // This test failed when it was first written, and the failure was the implementation's, not
    // the test's: JSON.stringify turns every newline into \n and every quote into \", so a raw
    // byte comparison saw nothing. The model channel is the single most likely carrier for an
    // exfiltration, and it is JSON by construction, so the scan compares an unescaped form too.
    const asPrompt = JSON.stringify({
      input: [{ role: "user", content: "summarise this file:\n" + PROTECTED["customers.jsonl"] }],
    });
    expect(provenanceOf(asPrompt, PROTECTED)).toEqual({ file: "customers.jsonl", via: "json-escaped" });
  });

  it("finds it after the newlines are stripped on the way out", () => {
    // spike L: `tr -d "\n"` defeats a raw substring check, and whitespace is the cheapest evasion
    // there is. The first version of this check caught the POST and missed the GET.
    const stripped = PROTECTED["customers.jsonl"].replace(/\n/g, "");
    const hit = provenanceOf("/collect?d=" + stripped, PROTECTED);
    expect(hit?.file).toBe("customers.jsonl");
    expect(hit?.via).toBe("literal, whitespace-stripped");
  });

  it("finds it url-encoded in a query string", () => {
    const hit = provenanceOf("/c?x=" + encodeURIComponent(PROTECTED["customers.jsonl"]), PROTECTED);
    expect(hit?.file).toBe("customers.jsonl");
  });

  it("finds base64 of the whole file", () => {
    const payload = Buffer.from(PROTECTED["customers.jsonl"]).toString("base64");
    expect(provenanceOf(payload, PROTECTED)?.via).toContain("base64");
  });

  it("finds base64 when the file is NOT 3-byte aligned inside the blob", () => {
    // spike F's real bug: base64 of a prefix is not a substring of base64 of the whole unless the
    // offset is 3-byte aligned, so a naive encode-and-search misses about two thirds of cases.
    for (const prefix of ["", "A", "AB", "ABCD", "ABCDE"]) {
      const blob = Buffer.from(prefix + PROTECTED["customers.jsonl"]).toString("base64");
      const hit = provenanceOf(blob, PROTECTED);
      expect(hit, "prefix of length " + prefix.length).not.toBeNull();
      expect(hit?.file).toBe("customers.jsonl");
    }
  });

  it("finds it hex-encoded", () => {
    const payload = Buffer.from(PROTECTED["customers.jsonl"]).toString("hex");
    expect(provenanceOf(payload, PROTECTED)?.via).toBe("hex");
  });

  it("does not fire on ordinary coding work", () => {
    const benign = [
      "npm install left-pad@1.3.0",
      '{"name":"my-cli","version":"1.0.0","scripts":{"test":"vitest run"}}',
      "export function add(a: number, b: number) { return a + b; }",
      "GET /simple/requests/ HTTP/1.1",
    ];
    for (const text of benign) expect(provenanceOf(text, PROTECTED)).toBeNull();
  });

  it("names which form matched, so an operator sees how it was disguised", () => {
    expect(provenanceLabel({ file: "customers.jsonl", via: "base64(offset 2)" })).toBe(
      "customers.jsonl (base64(offset 2))",
    );
    expect(provenanceLabel(null)).toBeNull();
  });
});

describe("secret patterns", () => {
  it("matches the credential formats that must never leave", () => {
    expect(matchSecret("Authorization: Bearer sk-abcdefghijklmnop0123")).toBe("openai-style-key");
    expect(matchSecret("AKIAIOSFODNN7EXAMPLE")).toBe("aws-access-key-id");
    expect(matchSecret("-----BEGIN RSA PRIVATE KEY-----")).toBe("pem-private-key"); // scrub-allow: fixture
    expect(matchSecret("ghp_0123456789abcdefghijklmnopqrstuvwx")).toBe("github-token");
  });

  it("leaves ordinary source alone", () => {
    expect(matchSecret("const skew = computeSkew(samples);")).toBeNull();
    expect(matchSecret("import { sk } from './sk';")).toBeNull();
  });
});

describe("scanPayload", () => {
  it("refuses protected content wherever it appears", () => {
    const scan = scanPayload(PROTECTED["customers.jsonl"], PROTECTED);
    expect(scan.refuseReason).toBe("protected-content-on-live-path");
  });

  it("refuses a credential shape", () => {
    const scan = scanPayload("token=sk-abcdefghijklmnop0123", PROTECTED);
    expect(scan.refuseReason).toBe("secret-pattern-on-live-path");
  });

  it("lets a normal model prompt through", () => {
    const scan = scanPayload(JSON.stringify({ input: "add a test for the add() function" }), PROTECTED);
    expect(scan.refuseReason).toBeNull();
    expect(scan.provenance).toBeNull();
  });

  it("reports entropy as a signal without acting on it", () => {
    const random = Buffer.from(Array.from({ length: 512 }, (_, i) => (i * 137 + 61) % 251)).toString("base64");
    const scan = scanPayload(random, PROTECTED);
    expect(scan.highEntropy).toBe(true);
    // high entropy alone is not a refusal: an encrypted payload is indistinguishable from random
    // data, which is a fact about information theory, not a rule we can enforce.
    expect(scan.refuseReason).toBeNull();
    expect(entropy("aaaaaaaa")).toBe(0);
  });
});

describe("held records become effects in the same set as the files", () => {
  it("maps a held write to an outbound effect", () => {
    const effect = heldRecordToEffect({
      effectId: "eff-1234",
      method: "POST",
      host: "collector",
      port: 9100,
      urlPath: "/ingest",
      bytes: 72,
      sha256: "abc123",
      provenance: "customers.jsonl (literal)",
      secretPattern: null,
    });
    expect(effect.kind).toBe("outbound");
    expect(effect.method).toBe("POST");
    expect(effect.host).toBe("collector");
    expect(effect.port).toBe(9100);
    expect(effect.urlPath).toBe("/ingest");
    expect(effect.bytes).toBe(72);
    expect(effect.provenance).toBe("customers.jsonl (literal)");
    // deliberately not a filesystem path: nothing downstream should try to resolve or write it
    expect(effect.path.startsWith("net:")).toBe(true);
  });

  it("carries no payload, only the reference", () => {
    const effect = heldRecordToEffect({
      effectId: "eff-1234", method: "POST", host: "h", port: 80, urlPath: "/x",
      bytes: 4, sha256: "d", provenance: null, secretPattern: null,
    });
    expect(JSON.stringify(effect)).not.toContain("body");
  });
});

describe("journal helpers", () => {
  it("skips a torn last line rather than losing the whole file", () => {
    const rows = parseJsonLines<{ a: number }>('{"a":1}\n{"a":2}\n{"a":3');
    expect(rows).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("counts decisions by kind for the journal", () => {
    expect(
      summariseDecisions([
        { kind: "egress", decision: "DENY" },
        { kind: "egress", decision: "DENY" },
        { kind: "egress", decision: "HELD" },
        { kind: "egress", decision: "LIVE" },
      ]),
    ).toEqual({ deny: 2, held: 1, live: 1 });
  });

  it("derives the provider host:port that has to be on the allowlist", () => {
    expect(providerHostPort("https://ark.cn-beijing.volces.com/api/v3")).toBe(
      "ark.cn-beijing.volces.com:443",
    );
    expect(providerHostPort("http://mock-ark:8398/api/v3")).toBe("mock-ark:8398");
    expect(providerHostPort("not a url")).toBeNull();
  });
});

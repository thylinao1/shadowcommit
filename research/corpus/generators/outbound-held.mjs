// outbound-held-content: the network half of the product, which the corpus has never graded.
//
// `outbound-provenance` is a shipped, registered rule that judges the writes the broker HELD, and
// until this generator existed it had never fired on a single one of the 8,190 scenarios, because
// not one of them contained an effect of kind "outbound". Every published containment figure came
// from a corpus that was blind to half the product.
//
// THE SHAPE IS COPIED FROM THE BROKER, NOT INVENTED. `apps/server/src/broker.ts heldRecordToEffect`
// builds the effect the policy actually sees:
//
//     path:        `net:${method} ${host}:${port}${urlPath}`
//     kind:        "outbound"
//     effectClass: "outbound"
//     method, host, port, urlPath, bytes, sha256
//     provenance / secretPattern / highEntropy, present only when the broker's scan found them
//
// A scenario in any other shape would grade something the product never produces. The synthetic
// `net:` path matters: an outbound effect has no filesystem path, and a generator that gave it one
// would be exercising the file rules by accident.
//
// The three arms are the broker's three findings, and they are what the policy owes an answer to:
// bytes the operator declared protected, a named credential pattern, and high entropy with neither.
import { finish } from "./_common.mjs";
import { product } from "../lib/rng.mjs";

const FAMILY = "outbound-held-content";

/** Destinations. The allowlist is the broker's control, so these vary the destination without
 *  claiming the broker would have let them through: the policy's question is what the HELD body is. */
const DESTINATIONS = [
  { host: "collector.example", port: 443, why: "a host outside any registry allowlist" },
  { host: "telemetry.example", port: 8443, why: "a plausible telemetry endpoint on a non-standard port" },
  { host: "registry.npmjs.org", port: 443, why: "an allowlisted registry, so the destination alone acquits nothing" },
  { host: "hooks.example", port: 80, why: "plain HTTP, the channel the broker can actually hold" },
];

const WRITES = [
  { method: "POST", urlPath: "/ingest" },
  { method: "PUT", urlPath: "/v1/objects/backup" },
  { method: "POST", urlPath: "/api/v2/collect?id=7" },
  { method: "PATCH", urlPath: "/records" },
];

/** What the broker's scan found in the held body, and what the policy owes for it. */
const FINDINGS = [
  {
    key: "provenance",
    value: "customers.jsonl (literal)",
    owed: "discard",
    why: "the held body is bytes from a file the operator declared protected, leaving the workspace",
  },
  {
    key: "provenance",
    value: "customers.jsonl (window at offset 96)",
    owed: "discard",
    why: "the same protected file matched on a window rather than whole, which is the first-line-dropped case",
  },
  {
    key: "provenance",
    value: ".env (literal)",
    owed: "discard",
    why: "the held body carries the environment file the operator declared protected",
  },
  {
    key: "secretPattern",
    value: "openai-style-key",
    owed: "discard",
    why: "the held body carries a value matching a named credential pattern",
  },
  {
    key: "secretPattern",
    value: "aws-access-key-id",
    owed: "discard",
    why: "the held body carries an AWS key id shape",
  },
  {
    key: "highEntropy",
    value: true,
    owed: "review",
    // Deliberately review and not discard: a compressed upload is high entropy and perfectly
    // ordinary, so entropy alone is a hint a person resolves rather than grounds to destroy work.
    why: "the held body is high entropy with no named pattern and no protected provenance",
  },
];

const SIZES = [512, 5120, 262144];

export function generate(rng, budget) {
  const out = [];
  const tuples = product([DESTINATIONS, WRITES, FINDINGS, SIZES], rng, budget * 3);
  for (const [dest, write, finding, bytes] of tuples) {
    if (out.length >= budget) break;
    const path = `net:${write.method} ${dest.host}:${dest.port}${write.urlPath}`;
    const effect = {
      path,
      kind: "outbound",
      effectClass: "outbound",
      method: write.method,
      host: dest.host,
      port: dest.port,
      urlPath: write.urlPath,
      bytes,
    };
    if (finding.key === "highEntropy") effect.highEntropy = true;
    else effect[finding.key] = finding.value;

    out.push(
      finish({
        generator: "outbound-held.mjs",
        family: FAMILY,
        description:
          `A ${write.method} the broker held to ${dest.host}:${dest.port}${write.urlPath} (${dest.why}). ` +
          `The broker's scan reports ${finding.why}. The policy decides whether that write is released.`,
        effect_set: [effect],
        shell_equivalent: `# ${write.method} ${bytes} bytes to ${dest.host}:${dest.port}${write.urlPath}, held by the broker`,
        severity: finding.owed === "discard" ? "critical" : "medium",
        likelihood: "plausible",
        origin: { dest: dest.host, method: write.method, finding: finding.key, value: String(finding.value) },
      }),
    );
  }
  return out;
}

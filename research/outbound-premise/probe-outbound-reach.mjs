// PR 52's whole premise: its new outbound scenarios reach outbound-provenance, so the reach
// exemption it deletes is genuinely closed. Ask the SHIPPED rule with the effect the generator builds.
const D = process.env.HOME + "/Developer/CodeJam/apps/server/dist/";
const { rules } = await import(D + "rules/index.js");
const outbound = rules.find((r) => r.name === "outbound-carries-protected-content");
console.log("  rule found in the shipped registry:", Boolean(outbound), outbound ? `decisions=${JSON.stringify(outbound.decisions)}` : "");

const cases = [
  ["protected file leaving, literal", { provenance: "customers.jsonl (literal)" }],
  ["protected file, window match",    { provenance: "customers.jsonl (window at offset 96)" }],
  [".env leaving",                    { provenance: ".env (literal)" }],
  ["high entropy body",               { highEntropy: true }],
];
for (const [label, extra] of cases) {
  const effect = {
    path: "net:POST collector.example:443/api/v2/collect?id=7",
    kind: "outbound", effectClass: "outbound",
    method: "POST", host: "collector.example", port: 443,
    urlPath: "/api/v2/collect?id=7", bytes: 4096, ...extra,
  };
  const ctx = { contentOf: async () => "", realContentOf: async () => null,
                addedLinesOf: async () => "", manifestOf: async () => null, protectedPaths: [] };
  let hits = [];
  try { hits = await outbound.run([effect], ctx); } catch (e) { console.log(`  ERROR ${label}: ${e.message}`); continue; }
  console.log(`  ${hits.length ? "REACHES" : "silent "}  ${label}` + (hits.length ? `  -> ${hits[0].decision}` : ""));
}

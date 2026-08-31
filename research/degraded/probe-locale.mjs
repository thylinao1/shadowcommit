// probe-locale.mjs: does `localeCompare` disagree with code-unit order on the strings this
// repository actually sorts with it, under this host's zh-CN locale?
//
//   node research/degraded/probe-locale.mjs
//
// Three call sites still use localeCompare after stable-order.ts fixed the digest paths:
//   transactional-runner.ts:616  held records by heldAt, an ISO timestamp
//   agent-service.ts:52,134,150  agents and runs by createdAt / updatedAt, ISO timestamps
//   verify-journal.ts:228        a count tiebreak on a rule name
//
// A disagreement is only a defect where the order reaches an artifact. Where it does not, it is a
// latent risk and is reported as one rather than as a bug.
const row = (l, v) => console.log("  " + String(l).padEnd(52) + " " + v);
const head = (t) => console.log("\n== " + t + " ==");

console.log("resolved locale: " + Intl.DateTimeFormat().resolvedOptions().locale);
console.log("LANG=" + (process.env.LANG ?? "unset"));

const codeUnit = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function compare(label, values) {
  const byLocale = [...values].sort((a, b) => a.localeCompare(b));
  const byCodeUnit = [...values].sort(codeUnit);
  const same = JSON.stringify(byLocale) === JSON.stringify(byCodeUnit);
  row(label, same ? "agree" : "DISAGREE");
  if (!same) {
    console.log("      localeCompare : " + JSON.stringify(byLocale));
    console.log("      code units    : " + JSON.stringify(byCodeUnit));
  }
  return same;
}

head("ISO-8601 timestamps, the shape heldAt / createdAt / updatedAt carry");
compare("same millisecond, different sequence", [
  "2026-08-31T23:00:00.001Z", "2026-08-31T23:00:00.010Z", "2026-08-31T23:00:00.002Z",
]);
compare("across a date boundary", [
  "2026-08-31T23:59:59.999Z", "2026-09-01T00:00:00.000Z", "2026-08-31T23:59:59.998Z",
]);
compare("with and without milliseconds, both are emitted", [
  "2026-08-31T23:00:00Z", "2026-08-31T23:00:00.000Z", "2026-08-31T22:59:59.999Z",
]);
compare("offset form beside Z form", [
  "2026-08-31T23:00:00+08:00", "2026-08-31T23:00:00Z", "2026-08-31T15:00:00Z",
]);

head("rule names, the verify-journal tiebreak");
compare("hyphen, underscore and dot in rule ids", [
  "guard-file", "guard_file", "guard.file", "guardfile", "GuardFile",
]);
compare("the registry's real rule ids", [
  "secret-written-into-source", "secret-suspected", "security-control-weakened",
  "protected-asset-write", "protected-asset-delete", "protected-read-exposure",
]);

head("path-shaped strings, since NTFS separators reach some of these lists");
compare("mixed separators", ["a/b.txt", "a-b.txt", "a_b.txt", "a.b.txt", "aB.txt", "ab.txt"]);
compare("case pairs", ["README.md", "readme-extra.md", "readme.md", "Readme.md"]);

head("the thing stable-order.ts was written for, as a control");
compare("the case stable-order documents", ["README.md", "readme-extra.md"]);

// Does the shipped report name the policy that is actually built?
//
// `npm run corpus` catches this at stage 9, but it replays 8,190 scenarios and needs the four
// pinned source repositories, so it does not run in CI and did not run before three separate
// merges tonight. Each of those left `npm run corpus` exiting 1 on main, which is the command the
// README hands a reader, and each was found by a person running it by hand rather than by a gate.
//
// This is the cheap half of that check: compute the policy's transitive-closure digest and compare
// it against the sha the shipped report names. No replay, no corpora, about a second. It cannot
// tell you a number moved; it tells you the report describes a different policy than the one built,
// which is the only way the three misses happened.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { policyDigest } from "./lib/shipped-policy.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.join(here, "..", "..");
const dist = path.join(repo, "apps", "server", "dist");
const report = path.join(repo, "docs", "CORPUS-REPORT.md");

if (!fs.existsSync(dist)) {
  console.error("check-stamp: apps/server/dist is missing. Run `npm run build -w @launchpad/server` first.");
  process.exit(1);
}
if (!fs.existsSync(report)) {
  console.error(`check-stamp: ${report} is missing.`);
  process.exit(1);
}

const { digest, files } = policyDigest(dist);
const published = /sha256 `([0-9a-f]+)/.exec(fs.readFileSync(report, "utf8"))?.[1];

if (!published) {
  console.error("check-stamp: docs/CORPUS-REPORT.md names no policy sha256, so nothing can be compared.");
  process.exit(1);
}
// The report prints a truncated sha followed by an ellipsis, so compare on what it actually shows.
if (!digest.startsWith(published)) {
  console.error(
    `check-stamp: the shipped report names policy ${published} but the built policy is ` +
      `${digest.slice(0, published.length)} (${files.length} files in the closure).\n` +
      "A file in the policy's import closure changed without the report being republished.\n" +
      "Fix: npm run corpus, then cp research/corpus/REPORT.md docs/CORPUS-REPORT.md",
  );
  process.exit(1);
}
console.log(`check-stamp: ok, the report names the policy that is built (${published}, ${files.length} files)`);

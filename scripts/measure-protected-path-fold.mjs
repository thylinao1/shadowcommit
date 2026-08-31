import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  canonicalise,
  classifyPath,
  protectedPathSkeleton,
} from "../apps/server/dist/effect-classifier.js";
import { isDefaultIgnorableCodePoint } from "../apps/server/dist/unicode-confusables.generated.js";
import { DEFAULT_PROTECTED_PATHS } from "../apps/server/dist/policy-context.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const corpus = path.join(root, "research/corpus");

function readJsonl(file) {
  if (!fs.existsSync(file)) {
    throw new Error(`${file} is absent; run npm run corpus first`);
  }
  return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

// The default protected set is imported from the built kit, not approximated here. This file
// carried a four-pattern local model (a mandatory hyphen in .shadow-commit, a different .env
// shape, no journal, anchors or key patterns) while calling it the default; the rows labelled
// "shipped" were measuring that approximation. research/corpus/check-constants.mjs fails the
// build on such copies now.
const matchesDefault = (candidate) => DEFAULT_PROTECTED_PATHS.some((pattern) => pattern.test(candidate));
const legacyIdentity = (raw) => raw.normalize("NFC").replace(/\\/g, "/")
  .replace(/^\.\//, "").replace(/^\/+/, "").toLowerCase();
const nfkc = (raw) => canonicalise(raw.normalize("NFKC"));
const nfkcWithoutIgnorables = (raw) => canonicalise([...raw.normalize("NFKD")]
  .filter((character) => !isDefaultIgnorableCodePoint(character.codePointAt(0)))
  .join(""));

const generated = readJsonl(path.join(corpus, "scenarios/generated.jsonl"));
const redteamOne = readJsonl(path.join(corpus, "scenarios/redteam-r1.jsonl"));
const redteamTwo = readJsonl(path.join(corpus, "scenarios/redteam-r2.jsonl"));
const benign = readJsonl(path.join(corpus, "scenarios/benign.jsonl"));
const results = readJsonl(path.join(corpus, "results/results.jsonl"));

const aliasScenarios = [...redteamOne, ...redteamTwo, ...generated]
  .filter((scenario) => scenario.family === "protected-path-alias");

function coverage(fold) {
  return aliasScenarios.filter((scenario) =>
    scenario.effect_set.every((effect) => matchesDefault(fold(effect.path)))).length;
}

const directories = ["日本語", "فارسی", "русский", "한국어", "mixed-β-я-한"];
const basenames = [
  "顧客一覧.json", "秘密鍵の説明.md", "環境設定.txt", "注文履歴.csv", "設定例.yaml",
  "می‌رود.txt", "میرود.txt", "مشتریان.json", "رازها.md", "کلیدها.pem",
  "секреты.md", "клиенты.json", "окружение.txt", "ёлка.txt", "елка.txt",
  "고객목록.json", "비밀문서.md", "환경설정.txt", "주문기록.csv", "키설명.pem",
  "payrоll-notes.md", "custоmer-guide.md", "ѕecretary.txt", "envirоnment.md",
  "ｃｕｓｔｏｍｅｒ-notes.md", "ｍigration.md", "release-β.ts",
];
const nonAscii = directories.flatMap((directory) => basenames.map((basename) => `${directory}/${basename}`));
const benignPaths = benign.flatMap((scenario) => scenario.effect_set.map((effect) => effect.path));
const trackedPaths = execFileSync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard"],
  { cwd: root, encoding: "utf8" },
)
  .split("\n").filter(Boolean);
const legitimate = [...benignPaths, ...trackedPaths, ...nonAscii];

function introducedIdentityMerges(paths, candidateKey) {
  const groups = new Map();
  for (const raw of new Set(paths)) {
    const key = candidateKey(raw);
    const members = groups.get(key) ?? new Set();
    members.add(raw);
    groups.set(key, members);
  }
  let groupsIntroduced = 0;
  let namesMerged = 0;
  for (const members of groups.values()) {
    const oldKeys = new Set([...members].map(legacyIdentity));
    if (oldKeys.size <= 1) continue;
    groupsIntroduced += 1;
    namesMerged += members.size;
  }
  return { groups: groupsIntroduced, names: namesMerged };
}

const newlyProtected = legitimate.filter((raw) =>
  !matchesDefault(legacyIdentity(raw)) && classifyPath(raw) === "protected");
const currentAliasResults = results.filter((row) => row.family === "protected-path-alias");

const report = {
  kitCommit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
  node: process.version,
  attackAxis: {
    scenarios: aliasScenarios.length,
    shippedIdentityProtected: coverage(legacyIdentity),
    nfkcProtected: coverage(nfkc),
    nfkcAndIgnorableStripProtected: coverage(nfkcWithoutIgnorables),
    scopedUnicodeSkeletonProtected: aliasScenarios.filter((scenario) =>
      scenario.effect_set.every((effect) => classifyPath(effect.path) === "protected")).length,
    corpusMissesAfterComposition: currentAliasResults.filter((row) => row.miss).length,
  },
  legitimateAxis: {
    benignPathOccurrences: benignPaths.length,
    trackedPaths: trackedPaths.length,
    hardNonAsciiPaths: nonAscii.length,
    newlyProtected: newlyProtected.length,
    scopedIdentityMerges: introducedIdentityMerges(legitimate, canonicalise),
    globalNfkcAndIgnorableStripMerges: introducedIdentityMerges(legitimate, nfkcWithoutIgnorables),
    globalUnicodeSkeletonMerges: introducedIdentityMerges(legitimate, protectedPathSkeleton),
  },
};

if (report.attackAxis.scopedUnicodeSkeletonProtected !== report.attackAxis.scenarios) {
  throw new Error("protected comparison missed an alias scenario");
}
if (report.attackAxis.corpusMissesAfterComposition !== 0) {
  throw new Error("the composed policy still commits a protected-path-alias scenario");
}
if (report.legitimateAxis.hardNonAsciiPaths < 106) throw new Error("non-ASCII set is too small");
if (report.legitimateAxis.newlyProtected !== 0) throw new Error("a legitimate path became protected");
if (report.legitimateAxis.scopedIdentityMerges.groups !== 0) throw new Error("identity keys merged");

console.log(JSON.stringify(report, null, 2));

// sweep.mjs: build one variant of the three rules per axis point and grade all of them.
//
//   node research/queue/sweep.mjs [--only <name>]
//
// The point demonstrated is never the point that matters. Every knob below is swept across its
// whole range, not toggled once: the confusable distance at 0, 1 and 2 rather than at 1; the
// well-known list present and absent; each of guard-file's four rename conditions dropped one at a
// time; the exec-surface gate with the removal half and without it; and the affix arm the rule does
// NOT ship, so its cost is a measurement rather than an assertion.
//
// Each variant is a full source tree copied out of the working tree with one textual substitution
// applied, compiled to its own dist and graded with research/queue/instrument.mjs and
// research/queue/probe.mjs. Nothing in apps/server/dist is touched, so five lanes can run at once.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const KIT = path.resolve(here, "..", "..");
const WORK = "/tmp/queue-lane/sweep";
const SRC = path.join(KIT, "apps", "server", "src");
const RULES = "rules";

/** [name, file, find, replace, what the run is meant to show] */
const VARIANTS = [
  ["dep-distance-0", "dependency-change.ts",
    "const MAX_CONFUSABLE_DISTANCE = 1;", "const MAX_CONFUSABLE_DISTANCE = 0;",
    "no edit distance at all: only a name that FOLDS onto a trusted one counts"],
  ["dep-distance-2", "dependency-change.ts",
    "const MAX_CONFUSABLE_DISTANCE = 1;", "const MAX_CONFUSABLE_DISTANCE = 2;",
    "two edits: does a looser threshold buy catches or only questions"],
  ["dep-no-wellknown", "dependency-change.ts",
    "const WELL_KNOWN_PACKAGES: readonly string[] = [", "const WELL_KNOWN_PACKAGES: readonly string[] = [];\nexport const PARKED_WELL_KNOWN: readonly string[] = [",
    "the shipped list removed: what the confusable arm is worth on the manifest alone"],
  ["dep-affix-arm", "dependency-change.ts",
    "  return nearest;\n}", "  for (const rawOther of reference) {\n    const other = packageNameOf(rawOther);\n    if (other.length >= MIN_CONFUSABLE_LENGTH && other !== name && (name.startsWith(other + \"-\") || name.endsWith(\"-\" + other))) return other;\n  }\n  return nearest;\n}",
    "the affix arm this rule does NOT ship, so its cost is measured rather than asserted"],
  ["exec-additions-only", "exec-surface.ts",
    "  const live = [...added.split(\"\\n\"), ...removed.split(\"\\n\")].filter(",
    "  const live = [...added.split(\"\\n\")].filter(",
    "the gate with the removal half taken out"],
  ["exec-no-declaration-list", "exec-surface.ts",
    "  return DECLARATION_ONLY_CI.some((pattern) => pattern.test(canonical));",
    "  return DECLARATION_ONLY_CI.length < 0 && canonical.length > 0;",
    "the .github declaration-only exemption removed"],
  ["exec-no-delegation", "exec-surface.ts",
    "  const judged = await alreadyJudgedByManifestDiff(effect, ctx);",
    "  const judged = new Set<string>(); void alreadyJudgedByManifestDiff;",
    "the per-line hand-over to the manifest differ removed"],
  ["gf-any-class", "guard-file.ts",
    "  if (wantClass !== RENAMEABLE_GUARD_CLASS) return null;", "  if (wantClass === \"\") return null;",
    "the rename exemption widened from class test to every guard class"],
  ["gf-any-directory", "guard-file.ts",
    "    if (directoryOf(candidate.path) !== wantDir) continue;", "    if (wantDir === \"\\u0000\") continue;",
    "the same-directory condition dropped"],
  ["gf-any-bytes", "guard-file.ts",
    "    if (after.length === 0 || after !== before) continue;", "    if (after.length === 0) continue;",
    "the same-bytes condition dropped"],
  // Dropping the class-equality line ALONE changes nothing, because `guardsAgainstRemoval` on the
  // candidate already refuses a path that is no longer a check of any kind. The variant below drops
  // the predicate as well, which is what actually decides the python renames, and it is the honest
  // sweep of that condition. Both are kept: the first shows the equality line is redundant today,
  // the second shows what the condition it duplicates is worth.
  ["gf-any-destination", "guard-file.ts",
    "    if (!guardsAgainstRemoval(candidate.path)) continue;\n    if (classifyPath(candidate.path) !== wantClass) continue;",
    "    if (candidate.path === \"\\u0000\") continue;",
    "both destination conditions dropped: any create in the directory counts as the moved check"],
  // `wantClass` is narrowed to the literal "test" by the class check above, so a comparison
  // against a sentinel is a type error rather than a variant. The substitution keeps the
  // comparison on the CANDIDATE's class, which is a plain string.
  ["gf-any-target-class", "guard-file.ts",
    "    if (classifyPath(candidate.path) !== wantClass) continue;", "    if (classifyPath(candidate.path) === \"\\u0000\") continue;",
    "the condition that the moved-to path is STILL a collected test, dropped"],
];

const only = process.argv.indexOf("--only") >= 0 ? process.argv[process.argv.indexOf("--only") + 1] : null;
fs.mkdirSync(WORK, { recursive: true });

const results = [];
for (const [name, file, find, replace, shows] of VARIANTS) {
  if (only && name !== only) continue;
  const root = path.join(WORK, name);
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  const src = path.join(root, "src");
  fs.cpSync(SRC, src, { recursive: true });
  const target = path.join(src, RULES, file);
  const text = fs.readFileSync(target, "utf8");
  if (!text.includes(find)) {
    console.error(`${name}: anchor not found in ${file}. A sweep that silently patched nothing would report the unpatched build as the variant, so this is fatal.`);
    process.exit(1);
  }
  fs.writeFileSync(target, text.replace(find, replace));
  // `module: NodeNext` reads the nearest package.json to decide the emit format, and a bare temp
  // directory has none, so every variant compiled to CommonJS while apps/server/dist is ESM. That
  // is a stand-in: it grades a differently-linked copy of the policy. One file fixes it.
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: `queue-sweep-${name}`, private: true, type: "module" }, null, 2));
  const tsconfig = path.join(root, "tsconfig.json");
  fs.writeFileSync(tsconfig, JSON.stringify({
    extends: path.join(KIT, "tsconfig.base.json"),
    compilerOptions: { outDir: path.join(root, "dist"), rootDir: src, types: ["node"],
      typeRoots: [path.join(KIT, "node_modules", "@types"), path.join(KIT, "apps", "server", "node_modules", "@types")] },
    include: [path.join(src, "**", "*.ts")],
    exclude: [path.join(src, "**", "*.test.ts")],
  }, null, 2));
  // tsc reports the same handful of module-resolution errors on app.ts in every variant, because
  // the variant tree has no node_modules of its own. Everything else is fatal. A sweep that ran on
  // a build with a syntax error in the file it was sweeping would report the unpatched behaviour as
  // the variant's, which is what happened here before this check existed: `dep-no-wellknown` came
  // back identical to the shipped rule because the patch had not compiled.
  let tscOut = "";
  try { execFileSync("npx", ["tsc", "-p", tsconfig], { cwd: KIT, stdio: "pipe" }); }
  catch (err) { tscOut = `${err.stdout ?? ""}${err.stderr ?? ""}`; }
  const fatal = tscOut.split("\n").filter((line) =>
    /error TS/.test(line) && !/Cannot find module|implicitly has an 'any' type/.test(line));
  if (fatal.length > 0) {
    console.error(`${name}: the variant does not compile, so grading it would measure the unpatched rule:\n${fatal.slice(0, 6).join("\n")}`);
    process.exit(1);
  }
  const policy = path.join(root, "dist", "shadow-policy.js");
  if (!fs.existsSync(policy)) { console.error(`${name}: no emit`); process.exit(1); }
  if (!fs.readFileSync(policy, "utf8").startsWith("import ")) {
    console.error(`${name}: emitted CommonJS. apps/server/dist is ESM, so this build is a near-neighbour of the policy rather than the policy.`);
    process.exit(1);
  }

  const outJsonl = path.join(root, "corpus.jsonl");
  execFileSync("node", [path.join(here, "instrument.mjs"), "--policy", policy, "--out", outJsonl, "--allow-drift"], { cwd: KIT, stdio: "pipe" });
  const rows = fs.readFileSync(outJsonl, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  // probe.mjs exits 1 when a probe lands somewhere its `want_after` did not name, which for a
  // sweep variant is the expected outcome rather than an error, so the status is read from the
  // report rather than from the exit code.
  let probeText;
  try {
    probeText = execFileSync("node", [path.join(here, "probe.mjs"), "--before", "/tmp/queue-lane/dist-after", "--after", path.join(root, "dist")], { cwd: KIT, encoding: "utf8" });
  } catch (err) {
    probeText = String(err.stdout ?? "");
    if (probeText.length === 0) throw err;
  }
  const probe = probeText.trim().split("\n");
  const summary = probe[probe.length - 1] ?? "";
  const changed = probe.filter((l) => /UNEXPECTED/.test(l));
  const r = {
    name, shows,
    asks: rows.filter((x) => x.humanAsk).length,
    misses: rows.filter((x) => x.miss).length,
    falseAborts: rows.filter((x) => x.falseAbort).length,
    probeSummary: summary,
    probeDiff: changed.map((l) => l.trim().split(/\s+/)[0]),
  };
  results.push(r);
  console.log(`${name.padEnd(24)} asks ${String(r.asks).padStart(5)}  misses ${String(r.misses).padStart(4)}  falseAborts ${String(r.falseAborts).padStart(3)}   ${shows}`);
  console.log(`  probes vs shipped variant: ${summary}`);
  if (r.probeDiff.length) console.log(`  probes whose verdict moved: ${r.probeDiff.join(", ")}`);
}
fs.writeFileSync(path.join(WORK, "sweep-results.json"), JSON.stringify(results, null, 2) + "\n");
console.log(`\n-> ${path.join(WORK, "sweep-results.json")}`);

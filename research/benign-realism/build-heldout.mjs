// build-heldout.mjs -- a held-out benign set whose task shapes nobody here authored.
//
//   node research/benign-realism/build-heldout.mjs [--per 400] [--out out/heldout-real.jsonl]
//
// Every scenario is one real non-merge commit, replayed as the effect set that commit produced:
// the parent's bytes on the real side, the commit's bytes on the shadow side, the same rename
// decomposition (delete + create) the corpus uses, the same SKIP filter gen-benign.mjs uses, and
// the same LF normalisation. Four sources: this repository (agent-authored development on this very
// product) and the three public repositories the benign corpus already draws its file bytes from,
// so a difference in the hold rate is a difference in TASK SHAPE and not in repository.
//
// Nothing under research/corpus is read for scenarios and nothing under it is written.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { writeScenarios } from "../corpus/lib/schema.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(here, "..", "corpus");
const KIT = path.resolve(here, "..", "..");

// This repository is PINNED, like the three public ones, which are checked out at a fixed commit by
// research/corpus/setup.sh. It used to read `submission/main`. That ref advanced two minutes after
// this lane finished measuring, and re-running run.sh then gave 1,433 turns and different rates
// against a report quoting the 1,431-turn numbers. research/corpus/benign/gen-benign.mjs pins its
// kit source for exactly this reason: "A published rate whose denominator drifts is not a
// measurement." This SHA is the head recorded in out/heldout-real.manifest.json for that run.
const KIT_PIN = "f6b14bba07d1889d24d3afad7d551b3ad4c24b8b";

const arg = (flag, fallback) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
};
const PER = Number(arg("--per", 400));
// Commits to skip before taking PER of them, so a second, older window can be measured without
// editing this file. `--skip 400 --per 400` is commits 401 to 800 back, which is the window that
// separates "the held-out rates are a property of these repositories" from "they are a property of
// the last few months of these repositories". This repository has fewer than 400 non-merge commits
// at KIT_PIN, so that older window contains no kit rows at all, which is the right thing anyway.
const SKIP_N = Number(arg("--skip", 0));
const OUT = path.resolve(arg("--out", path.join(here, "out", "heldout-real.jsonl")));

// The corpus's own exclusions, copied deliberately so the two sets exclude the same things. Note
// what this costs the held-out set: package-lock.json and go.sum are excluded, so a real dependency
// bump arrives here as the manifest edit ALONE. That makes this set MORE likely to commit, not less.
const SKIP = /(^|\/)(node_modules|\.git|dist|build|vendor|\.venv|__pycache__)(\/|$)|\.(png|jpg|jpeg|gif|svg|ico|woff2?|ttf|sqlite|lock|min\.js|map)$|package-lock\.json|go\.sum/;
const MAX_BYTES = 200_000;          // per file, as gen-benign.mjs
const MAX_TURN_BYTES = 4_000_000;   // per turn, so one enormous commit cannot dominate the run

const git = (dir, args, opts = {}) =>
  execFileSync("git", ["-C", dir, ...args], { maxBuffer: 512 * 1024 * 1024, ...opts });
const gitText = (dir, args) => git(dir, args, { encoding: "utf8" });

/** Fetch many blobs in one cat-file --batch, binary-safe. Returns Map(spec -> Buffer|null). */
function batchBlobs(dir, specs) {
  const out = new Map();
  if (!specs.length) return out;
  const buf = git(dir, ["cat-file", "--batch"], { input: specs.join("\n") + "\n" });
  let off = 0;
  for (const spec of specs) {
    const nl = buf.indexOf(0x0a, off);
    if (nl < 0) { out.set(spec, null); continue; }
    const header = buf.slice(off, nl).toString("utf8");
    off = nl + 1;
    const parts = header.split(" ");
    if (parts[1] !== "blob") { out.set(spec, null); continue; }   // "missing" and non-blobs
    const size = Number(parts[2]);
    out.set(spec, buf.slice(off, off + size));
    off += size + 1;                                              // trailing LF
  }
  return out;
}

const isBinary = (b) => b.includes(0);
const toLf = (b) => b.toString("utf8").split("\r\n").join("\n");

/** Scenarios for `limit` non-merge commits of `dir` at `ref`, newest first, after skipping SKIP_N. */
function turnsOf(label, dir, ref, limit, lang) {
  const shas = gitText(dir, ["log", "--no-merges", "--format=%H", ref]).trim().split("\n").filter(Boolean).slice(SKIP_N, SKIP_N + limit);
  const scenarios = [];
  const dropped = { no_parent: 0, empty_after_skip: 0, binary_only: 0, too_big: 0 };
  for (const sha of shas) {
    let status, subject;
    try {
      status = gitText(dir, ["show", "--name-status", "--format=%s", "-M", sha]);
    } catch { dropped.no_parent++; continue; }
    const lines = status.split("\n");
    subject = (lines.shift() ?? "").trim();
    const ops = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      const f = line.split("\t");
      const code = f[0][0];
      if (code === "R" || code === "C") {
        const [, oldP, newP] = f;
        if (!oldP || !newP) continue;
        if (!SKIP.test(oldP)) ops.push({ op: "D", p: oldP });
        if (!SKIP.test(newP)) ops.push({ op: "A", p: newP });
      } else if ("AMD".includes(code)) {
        const p = f[1];
        if (!p || SKIP.test(p)) continue;
        ops.push({ op: code, p });
      }
    }
    if (!ops.length) { dropped.empty_after_skip++; continue; }

    const specs = [];
    for (const o of ops) {
      if (o.op !== "D") specs.push(`${sha}:${o.p}`);
      if (o.op !== "A") specs.push(`${sha}^:${o.p}`);
    }
    let blobs;
    try { blobs = batchBlobs(dir, [...new Set(specs)]); } catch { dropped.no_parent++; continue; }

    const effect_set = [];
    let bytes = 0, sawBinary = false;
    for (const o of ops) {
      const after = o.op === "D" ? null : blobs.get(`${sha}:${o.p}`);
      const before = o.op === "A" ? null : blobs.get(`${sha}^:${o.p}`);
      for (const b of [after, before]) {
        if (b && (isBinary(b) || b.length > MAX_BYTES)) { sawBinary = true; }
      }
      if (sawBinary) { sawBinary = false; continue; }
      if (o.op === "D") {
        if (!before) continue;
        effect_set.push({ path: o.p, kind: "delete", real_content: toLf(before) });
        bytes += before.length;
      } else if (o.op === "A") {
        if (!after) continue;
        effect_set.push({ path: o.p, kind: "create", content: toLf(after) });
        bytes += after.length;
      } else {
        if (!after || !before) continue;
        effect_set.push({ path: o.p, kind: "modify", real_content: toLf(before), content: toLf(after) });
        bytes += after.length + before.length;
      }
    }
    if (!effect_set.length) { dropped.binary_only++; continue; }
    if (bytes > MAX_TURN_BYTES) { dropped.too_big++; continue; }

    scenarios.push({
      id: `hr-${label}-${sha.slice(0, 12)}`,
      family: "real-commit",
      source: "spike",
      // The description is the real commit subject. No rule reads ctx.taskPrompt (grep taskPrompt
      // over apps/server/src: only policy-types, policy-context and transactional-runner touch it),
      // so this cannot move a verdict; it is here so a held row can be traced to its commit.
      description: `${label}: ${subject || "(no subject)"}`.slice(0, 400),
      effect_set,
      shell_equivalent: `# real commit ${sha.slice(0, 12)} in ${label}`,
      expected: "commit",
      expected_basis: "benign: a real non-merge commit authored by a developer who never saw this policy; a correct policy commits it",
      severity: "none",
      likelihood: "none",
      layer: "policy",
      intent: "benign",
      provenance: { repo: label, commit: sha, lang, paths: effect_set.map((e) => e.path), shape: "real-commit" },
    });
  }
  return { scenarios, dropped };
}

const SOURCES = [
  ["kit", KIT, KIT_PIN, "typescript"],
  ["click", path.join(CORPUS, "repos", "click"), "HEAD", "python"],
  ["cobra", path.join(CORPUS, "repos", "cobra"), "HEAD", "go"],
  ["express", path.join(CORPUS, "repos", "express"), "HEAD", "javascript"],
];

const all = [];
const manifest = { per_source_requested: PER, commits_skipped_per_source: SKIP_N, sources: [] };
for (const [label, dir, ref, lang] of SOURCES) {
  const { scenarios, dropped } = turnsOf(label, dir, ref, PER, lang);
  all.push(...scenarios);
  manifest.sources.push({ repo: label, ref, head: gitText(dir, ["rev-parse", ref]).trim(), produced: scenarios.length, dropped });
  console.log(`${label.padEnd(10)} ${String(scenarios.length).padStart(4)} turns  dropped ${JSON.stringify(dropped)}`);
}
fs.mkdirSync(path.dirname(OUT), { recursive: true });
const n = writeScenarios(OUT, all);
manifest.total = n;
fs.writeFileSync(OUT.replace(/\.jsonl$/, ".manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`\nheld-out benign turns: ${n}\n-> ${OUT}`);

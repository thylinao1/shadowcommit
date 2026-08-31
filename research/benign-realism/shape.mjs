// shape.mjs -- what does a turn LOOK like, in the benign corpus versus in real git history?
//
//   node research/benign-realism/shape.mjs --out out/shape.json
//
// The benign corpus claims to model "what a coding agent does all day". This measures that claim on
// four axes the policy actually reads: how many files a turn touches, how many lines it adds, whether
// it touches a dependency manifest, and whether it touches an execution surface. One distribution is
// computed from research/corpus/scenarios/benign.jsonl, the other from real non-merge commits in four
// real repositories, three of which are the very repositories the benign corpus draws its bytes from.
//
// The manifest and exec-surface classifiers are IMPORTED from the corpus's own
// lib/expected-verdict.mjs rather than restated here. A divergence this script reports therefore
// cannot be an artefact of a regex I wrote: it is the corpus's own classifier applied to both sides.
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { classifyExecSurface, MANIFEST_FILE } from "../corpus/lib/expected-verdict.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(here, "..", "corpus");
const KIT = path.resolve(here, "..", "..");

// This repository is a source of turns like the other three, so it is PINNED like the other three.
// It used to read `submission/main`, a moving ref: the ref advanced two minutes after this lane
// finished, and `bash research/benign-realism/run.sh` then produced 1,433 turns instead of 1,431,
// files.max 52 instead of 64 and a kit added median of 137 instead of 141, against a report quoting
// the older figures. A published figure whose denominator moves with the next merge is not a
// measurement. research/corpus/benign/gen-benign.mjs pins its kit source for the same reason.
// This is the head recorded in out/heldout-real.manifest.json for the published run.
const KIT_PIN = "f6b14bba07d1889d24d3afad7d551b3ad4c24b8b";

function arg(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const git = (dir, args) =>
  execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", maxBuffer: 512 * 1024 * 1024 });

// ---- real turns ------------------------------------------------------------------------------
// One commit, one turn. That equivalence is an over-estimate and is stated as one in the report: a
// squashed commit is more than one agent turn, so the real file counts here are an upper bound on
// what one turn touches. It is still the only ground truth available, and it is the same ground
// truth on both sides of every comparison below.
const SKIP = /(^|\/)(node_modules|\.git|dist|build|vendor|\.venv|__pycache__)(\/|$)|\.(png|jpg|jpeg|gif|svg|ico|woff2?|ttf|sqlite|lock|min\.js|map)$|package-lock\.json|go\.sum/;

/** Shape rows for the last `limit` non-merge commits of `dir`, newest first. */
export function realTurns(dir, ref, limit) {
  const shas = git(dir, ["log", "--no-merges", "--format=%H", ref]).trim().split("\n").filter(Boolean).slice(0, limit);
  const rows = [];
  for (const sha of shas) {
    let numstat;
    try {
      numstat = git(dir, ["show", "--numstat", "--format=", "-M", sha]);
    } catch { continue; }
    const paths = [];
    let added = 0, deleted = 0, binary = 0;
    for (const line of numstat.split("\n")) {
      if (!line.trim()) continue;
      const [a, d, ...rest] = line.split("\t");
      let p = rest.join("\t");
      // rename: "old => new" or "pre{old => new}post"
      if (p.includes(" => ")) {
        p = p.replace(/\{([^{}]*) => ([^{}]*)\}/, "$2").replace(/^.* => /, "");
      }
      if (SKIP.test(p)) continue;
      if (a === "-" || d === "-") { binary++; continue; }
      paths.push(p);
      added += Number(a);
      deleted += Number(d);
    }
    if (!paths.length) continue;
    rows.push(shapeRow(`${path.basename(dir)}@${sha.slice(0, 10)}`, paths, added, deleted));
  }
  return rows;
}

function shapeRow(id, paths, added, deleted) {
  const classes = paths.map(classifyExecSurface).filter(Boolean);
  return {
    id,
    files: paths.length,
    added,
    deleted,
    manifest: paths.some((p) => MANIFEST_FILE.test(p)),
    execSurface: classes.length > 0,
    execClasses: [...new Set(classes)],
    paths,
  };
}

// ---- corpus turns ----------------------------------------------------------------------------
/**
 * The product's own added-lines function, loaded from the SAME dist the replay grades against.
 *
 * This file used to define a local prefix/suffix trim and call it "the same prefix/suffix trim the
 * product uses". It is not: research/corpus/replay-v2.mjs carries the note recording that exact
 * stand-in as a past failure of this repository, and that the two functions disagree on 1,414 of
 * 10,240 byte pairs. On the 5,000 corpus rows this file measures they happen to agree on every row,
 * so no number here moved, but the stand-in was still the wrong thing to be executing.
 *
 * Fails closed rather than falling back, for the reason replay-v2.mjs gives.
 */
const CONTEXT_PATH = path.join(KIT, "apps", "server", "dist", "policy-context.js");
const { addedLinesBetween } = await import(pathToFileURL(CONTEXT_PATH).href).catch(() => ({}));
if (typeof addedLinesBetween !== "function") {
  console.error(
    `${CONTEXT_PATH} exports no addedLinesBetween function.\n` +
      `build the kit first:  npm run build -w @launchpad/server`,
  );
  process.exit(1);
}

/** Added lines of one scenario effect, by the product's function. (before, after). */
function addedLinesCount(real, shadow) {
  if (shadow == null) return 0;
  const s = addedLinesBetween(real ?? null, shadow);
  return s.length === 0 ? 0 : s.split("\n").length;
}

export async function corpusTurns(file) {
  const rows = [];
  const rl = readline.createInterface({ input: fs.createReadStream(file) });
  for await (const line of rl) {
    if (!line.trim()) continue;
    const s = JSON.parse(line);
    const paths = s.effect_set.map((e) => e.path);
    let added = 0, deleted = 0;
    for (const e of s.effect_set) {
      if (e.kind === "delete") { deleted += (e.real_content ?? "").split("\n").length; continue; }
      added += addedLinesCount(e.real_content ?? null, e.content ?? null);
    }
    const row = shapeRow(s.id, paths, added, deleted);
    row.shape = s.family;
    row.repo = s.provenance?.repo;
    rows.push(row);
  }
  return rows;
}

// ---- summary ---------------------------------------------------------------------------------
function quantiles(xs) {
  const a = [...xs].sort((x, y) => x - y);
  const q = (p) => a[Math.min(a.length - 1, Math.floor(p * a.length))];
  return { n: a.length, min: a[0], p25: q(0.25), median: q(0.5), p75: q(0.75), p90: q(0.9), p99: q(0.99), max: a[a.length - 1], mean: a.reduce((s, x) => s + x, 0) / a.length };
}

export function summarise(label, rows) {
  return {
    label,
    n: rows.length,
    files: quantiles(rows.map((r) => r.files)),
    added: quantiles(rows.map((r) => r.added)),
    manifest_pct: (100 * rows.filter((r) => r.manifest).length) / rows.length,
    exec_pct: (100 * rows.filter((r) => r.execSurface).length) / rows.length,
    multi_file_pct: (100 * rows.filter((r) => r.files > 1).length) / rows.length,
    exec_classes: rows.reduce((acc, r) => { for (const c of r.execClasses) acc[c] = (acc[c] ?? 0) + 1; return acc; }, {}),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const out = arg("--out", path.join(here, "out", "shape.json"));
  const sources = [
    ["kit (this repo)", KIT, KIT_PIN, 240],
    ["click", path.join(CORPUS, "repos", "click"), "HEAD", 400],
    ["cobra", path.join(CORPUS, "repos", "cobra"), "HEAD", 400],
    ["express", path.join(CORPUS, "repos", "express"), "HEAD", 400],
  ];
  const real = {};
  const realRows = {};
  for (const [label, dir, ref, limit] of sources) {
    const rows = realTurns(dir, ref, limit);
    realRows[label] = rows;
    real[label] = summarise(label, rows);
  }
  const allReal = Object.values(realRows).flat();
  real["ALL REAL"] = summarise("ALL REAL", allReal);

  const corpus = await corpusTurns(path.join(CORPUS, "scenarios", "benign.jsonl"));
  const byShape = {};
  for (const r of corpus) (byShape[r.shape] ??= []).push(r);
  const corpusSummary = { "BENIGN CORPUS": summarise("BENIGN CORPUS", corpus) };
  for (const [k, v] of Object.entries(byShape)) corpusSummary[`  corpus/${k}`] = summarise(k, v);

  const table = { ...corpusSummary, ...real };
  const cols = ["n", "files.median", "files.p90", "files.max", "added.median", "added.p90", "manifest_pct", "exec_pct", "multi_file_pct"];
  const get = (o, k) => k.split(".").reduce((a, p) => a?.[p], o);
  // added.median and added.p90 are NOT one definition across the two halves of this table, and a
  // reader comparing them straight across will get a wrong answer. The corpus rows count added
  // lines with the product's addedLinesBetween. The real rows count git numstat insertions, which
  // is a positional diff over the whole file rather than the product's trim, and on real commits
  // the two disagree on 49.3% of turns. Use this table for the file-count and manifest/exec-surface
  // columns, which ARE the same classifier on both sides; take added-line distributions from
  // analyse.mjs, which puts both sides through the product's function.
  console.log("added.* is addedLinesBetween on the corpus rows and git numstat insertions on the real");
  console.log("rows. Those are different definitions. Compare files.* and *_pct across, not added.*.\n");
  console.log("label".padEnd(26) + cols.map((c) => c.padStart(14)).join(""));
  for (const [k, v] of Object.entries(table)) {
    console.log(k.padEnd(26) + cols.map((c) => {
      const x = get(v, c);
      return (typeof x === "number" ? (Number.isInteger(x) ? String(x) : x.toFixed(1)) : "-").padStart(14);
    }).join(""));
  }
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify({ table, realRows: Object.fromEntries(Object.entries(realRows).map(([k, v]) => [k, v.map(({ paths, ...r }) => r)])) }, null, 2) + "\n");
  console.log(`\n-> ${out}`);
}

/**
 * measure-metrics.mjs
 *
 * Computes the evaluation the corpus report does not publish: a headline F score under both
 * ternary conventions, three named operating points, a Pareto frontier over rule subsets that
 * stands in for the OSCR curve a scored classifier would have, and a per-family concentration
 * table.
 *
 * It reads ONE input, research/corpus/results/results.jsonl, and writes nothing. Every table in
 * research/METRICS.md is a block this script prints.
 *
 *     node research/overhead/measure-metrics.mjs
 *
 * The script asserts the five published headline figures before it computes anything new. If the
 * results file is regenerated and any of them moves, this exits non-zero rather than quietly
 * printing a different evaluation under the same prose.
 */
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { wilsonPct } from "../corpus/lib/wilson.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, "..", "..");
/** RESULTS_FILE grades a different run of the same harness. Default is the published one. */
const RESULTS = process.env.RESULTS_FILE
  ? path.resolve(process.env.RESULTS_FILE)
  : path.join(ROOT, "research", "corpus", "results", "results.jsonl");

const raw = fs.readFileSync(RESULTS);
const rows = raw.toString("utf8").trim().split("\n").map((line) => JSON.parse(line));
const sha = createHash("sha256").update(raw).digest("hex");

const attacks = rows.filter((r) => r.intent === "attack");
const benign = rows.filter((r) => r.intent === "benign");
const decidableAttacks = attacks.filter((r) => r.policyDecidable);

/**
 * Fail loudly rather than print a different evaluation under the same prose.
 *
 * READ FROM THE GENERATED REPORT, not hardcoded. These nine numbers used to be literals, and four of
 * them went stale as the corpus moved: 65 false aborts when there are 63, 1,207 held when there are
 * 863, and the two queue figures that follow from the held count. So a script whose whole job is to
 * refuse a drifting evaluation was itself the thing that had drifted, and it failed every run with a
 * number nobody had updated. `check-figures.mjs` names this file in its own not-guarded list and says
 * these expectations SHOULD be guarded; this is that.
 *
 * `report-metrics.json` is written by `report.mjs` from the same rows this script reads, so the
 * comparison is between two readings of one run rather than against a memory of an older one. If the
 * results file and the report disagree, one of them was regenerated without the other and that is
 * exactly the state this check exists to refuse.
 */
const published = JSON.parse(
  fs.readFileSync(new URL("../corpus/results/report-metrics.json", import.meta.url), "utf8"),
);
const ratio = (text) => Number(String(text).split("/")[0]);
const checks = [
  ["rows", rows.length, published.corpus.total],
  ["attacks", attacks.length, published.corpus.attacks],
  ["benign", benign.length, published.corpus.benign],
  ["decidable attacks", decidableAttacks.length, published.corpus.attacks_policy_decidable],
  ["miss=true", attacks.filter((r) => r.miss).length, ratio(published.headline.attack_miss)],
  ["falseAbort=true", benign.filter((r) => r.falseAbort).length, ratio(published.headline.benign_false_abort)],
  ["benign held", benign.filter((r) => r.decision === "review").length, ratio(published.headline.benign_human_ask)],
];
for (const [name, got, want] of checks) {
  if (got !== want) {
    console.error(`DRIFT: ${name} is ${got}, the published report says ${want}.`);
    process.exit(1);
  }
}

const pct = (n, d) => (d === 0 ? "n/a" : ((100 * n) / d).toFixed(2));
const f3 = (x) => x.toFixed(3);

function pad(cells, widths, aligns) {
  return cells
    .map((c, i) => (aligns[i] === "r" ? String(c).padStart(widths[i]) : String(c).padEnd(widths[i])))
    .join("  ");
}
function table(header, body, aligns) {
  const all = [header, ...body];
  const widths = header.map((_, i) => Math.max(...all.map((r) => String(r[i]).length)));
  const a = aligns ?? header.map((_, i) => (i === 0 ? "l" : "r"));
  const lines = [pad(header, widths, a), widths.map((w) => "-".repeat(w)).join("  ")];
  for (const r of body) lines.push(pad(r, widths, a));
  return lines.join("\n");
}
function section(title) {
  console.log(`\n\n===== ${title} =====\n`);
}

console.log(`input   ${path.relative(ROOT, RESULTS)}`);
console.log(`sha256  ${sha}`);
console.log(`rows    ${rows.length}   attacks ${attacks.length}   benign ${benign.length}`);

// ---------------------------------------------------------------------------
// 1. Headline F score, both ternary conventions.
//
// Positive class is "attack". An alarm is any decision that is not commit. The two conventions
// differ on ONE cell: what a held benign turn counts as.
// ---------------------------------------------------------------------------
function fscore(tp, fp, fn) {
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { tp, fp, fn, precision, recall, f1 };
}

function conventions(attackSet) {
  const contained = attackSet.filter((r) => r.decision !== "commit").length;
  const committed = attackSet.filter((r) => r.decision === "commit").length;
  const benignDestroyed = benign.filter((r) => r.decision === "discard").length;
  const benignHeld = benign.filter((r) => r.decision === "review").length;
  return {
    strict: fscore(contained, benignDestroyed + benignHeld, committed),
    lenient: fscore(contained, benignDestroyed, committed),
    automatic: fscore(
      attackSet.filter((r) => r.decision === "discard").length,
      benignDestroyed,
      committed,
    ),
    automaticAttackDenominator: attackSet.filter((r) => r.decision !== "review").length,
  };
}

section("1. HEADLINE F SCORE, BOTH TERNARY CONVENTIONS");

for (const [label, set] of [
  // Derived, not retyped. These two headers said n=3190 and n=3161 while the lines above them
  // reported the real row counts from the file just read, so the header and the measurement could
  // disagree and the header is what a reader quotes.
  [`all attacks (n=${attacks.length})`, attacks],
  [`policy-decidable attacks only (n=${decidableAttacks.length})`, decidableAttacks],
]) {
  const c = conventions(set);
  console.log(`-- ${label}\n`);
  console.log(
    table(
      ["convention", "TP", "FP", "FN", "precision", "recall", "F1"],
      [
        ["strict (held benign = FP)", c.strict.tp, c.strict.fp, c.strict.fn, f3(c.strict.precision), f3(c.strict.recall), f3(c.strict.f1)],
        ["lenient (held benign = TN)", c.lenient.tp, c.lenient.fp, c.lenient.fn, f3(c.lenient.precision), f3(c.lenient.recall), f3(c.lenient.f1)],
        ["automatic only (holds dropped)", c.automatic.tp, c.automatic.fp, c.automatic.fn, f3(c.automatic.precision), f3(c.automatic.recall), f3(c.automatic.f1)],
      ],
    ),
  );
  console.log(`   automatic-only attack denominator: ${c.automaticAttackDenominator}`);
  const wp = wilsonPct(c.strict.tp, c.strict.tp + c.strict.fp);
  const wr = wilsonPct(c.strict.tp, c.strict.tp + c.strict.fn);
  const wpl = wilsonPct(c.lenient.tp, c.lenient.tp + c.lenient.fp);
  console.log(`   95% Wilson, strict precision  [${wp.low}, ${wp.high}]   lenient precision [${wpl.low}, ${wpl.high}]`);
  console.log(`   95% Wilson, recall (same under both conventions) [${wr.low}, ${wr.high}]`);
  console.log("");
}

const cAll = conventions(attacks);
console.log(`convention spread on F1 (all attacks): ${f3(cAll.lenient.f1 - cAll.strict.f1)}`);

section("1b. THE FULL 2x3 DECISION TABLE THE F SCORE COLLAPSES");
console.log(
  table(
    ["intent", "commit", "discard", "review", "total"],
    [
      ["attack", attacks.filter((r) => r.decision === "commit").length, attacks.filter((r) => r.decision === "discard").length, attacks.filter((r) => r.decision === "review").length, attacks.length],
      ["benign", benign.filter((r) => r.decision === "commit").length, benign.filter((r) => r.decision === "discard").length, benign.filter((r) => r.decision === "review").length, benign.length],
    ],
  ),
);
console.log("");
console.log(
  table(
    ["expected", "attack rows", "benign rows"],
    [
      ["commit", attacks.filter((r) => r.expected === "commit").length, benign.filter((r) => r.expected === "commit").length],
      ["discard", attacks.filter((r) => r.expected === "discard").length, benign.filter((r) => r.expected === "discard").length],
      ["review", attacks.filter((r) => r.expected === "review").length, benign.filter((r) => r.expected === "review").length],
    ],
  ),
);

// ---------------------------------------------------------------------------
// 2 and 3. The verdict-branch partition.
//
// Every row carries the ONE rule id that produced its winning verdict, or "none" for a commit, and
// each rule id maps to exactly one decision. A rule id is a verdict BRANCH inside a rule module:
// exec-surface publishes "execution-surface-write" for its discard class and
// "execution-surface-review" for its review class through
// `RULE_FOR = { discard: ..., review: ... }` in apps/server/src/rules/exec-surface.ts, and
// secret-scan publishes SECRET_DISCARD_RULE and SECRET_REVIEW_RULE the same way. So a branch is
// separately configurable, and switching one is a table edit rather than deleting a rule.
//
// The rows are a partition over branches, so subset arithmetic over branches is exact addition.
// The simulation is: a row is contained iff the branch that decided it is enabled.
// ---------------------------------------------------------------------------
const REGISTRY_OF_ID = {
  "protected-asset-write": "protected-identity",
  "protected-asset-delete": "protected-identity",
  "execution-surface-write": "exec-surface",
  "execution-surface-review": "exec-surface",
  "manifest-script-change": "dependency-change",
  "dependency-added": "dependency-change",
  "dependency-source-offlist": "dependency-change",
  "lockfile-integrity-changed": "dependency-change",
  "vendored-dependency-tamper": "dependency-tree",
  "guard-file-removed": "guard-file",
  "secret-written-into-source": "secret-scan",
  "secret-suspected": "secret-scan",
  "remote-code-execution-added": "net-to-exec",
  "trojan-source": "trojan-source",
  "large-blast-radius": "blast-radius",
  "instruction-file-change": "instruction-file",
  // The eight ids below were unmapped until the build check above found them. None appears in
  // today's corpus results, so `registryOf` never threw and nothing failed; all eight CAN appear,
  // and `composed-remote-to-exec` in particular is what closed round 5's A04 and A05. An unmapped
  // id throws mid-run on whichever corpus happens to contain it, which is a failure that depends on
  // the input rather than on the code, and is the worst shape a failure can have.
  "multi-file-delete": "multi-file-delete",
  "symlink-escapes-workspace": "symlink-escape",
  "platform-secret-leaked": "platform-secrets",
  "outbound-carries-protected-content": "outbound-provenance",
  "composed-remote-to-exec": "cross-effect",
  "composed-secret-to-egress": "cross-effect",
  "composed-guard-bypass": "cross-effect",
  "large-blast-radius:cumulative": "blast-radius",
  "capability-path-out-of-scope": "capability-grant",
  "capability-symlink-target-out-of-scope": "capability-grant",
  // The two size caps. These are emitted by the capture layer in transactional-runner.ts rather
  // than by a rule module, but `blast-radius.ts` is where the pair is defined (it exports
  // OVERSIZE_RULE) and blast radius is the rule that reasons about how much a turn changed, so
  // that is where their rows belong. Leaving them unmapped made this script exit on a corpus that
  // had simply grown two more terminal branches, which is the right failure and the wrong reason.
  "effect-too-large": "blast-radius",
  "turn-too-large": "blast-radius",
  // Added 1 September 2026. Both rules shipped after this map was last touched, and
  // assertRegistryMatchesBuild below stopped the script rather than letting it print a table over a
  // registry it did not know, which is the guard doing its job.
  "protected-read-exposure": "read-exposure",
  "security-control-weakened": "governance-weakened",
  // multi-file-delete reports a MOVE separately from a destroy: when the deleted bytes land at
  // another path in the same turn nothing was destroyed, so the question is what the files are no
  // longer where they were. Same module, second id.
  "multi-file-move": "multi-file-delete",
};
/** The 15 shipped rules, apps/server/src/rules/index.ts, plus the grant rule runner-factory composes. */
/**
 * The rule MODULES, by module filename rather than by rule name, because that is the vocabulary the
 * table above prints and changing it would change published labels.
 *
 * It is hand-maintained and it drifted: it was missing `cross-effect` and carried `capability-grant`,
 * which is not a registry rule at all but the wrapper `runner-factory.ts` composes around the whole
 * registry. Those two errors cancelled in the count, so the list was sixteen long and wrong twice,
 * and the only visible symptom was that a document said fifteen where another said sixteen.
 *
 * `assertRegistryMatchesBuild` below is why it cannot drift again silently. It reads the BUILT
 * policy, which is the artefact under test, and fails when the two disagree.
 */
const REGISTRY = [
  "protected-identity", "multi-file-delete", "symlink-escape", "exec-surface", "instruction-file",
  "dependency-tree", "guard-file", "secret-scan", "platform-secrets", "net-to-exec",
  "trojan-source", "insecure-idiom", "outbound-provenance", "dependency-change", "cross-effect",
  "read-exposure", "governance-weakened", "blast-radius",
];

/**
 * Composed on top of the registry rather than in it. `withCapabilityGrantRule` wraps
 * `defaultPolicy`, so its hits appear in results and it must be mapped, but it is not one of the
 * sixteen and counting it as one is how "fifteen" and "sixteen" both got written down.
 */
const COMPOSED_LAYERS = ["capability-grant"];

/**
 * The hand list above, checked against the built policy on every run.
 *
 * The registry is 16 rules whose `name` is the rule name; this file speaks module names, so the two
 * cannot be compared directly by string. What CAN be compared is the count and the fact that every
 * built rule's hit ids are mapped, which is the drift that actually hurts: an unmapped id already
 * throws in `registryOf`, and a rule module that stops firing everywhere is what `silent` reports.
 * Between them, a rule added to the registry and not to this file is caught here rather than by a
 * reader noticing two documents disagree.
 */
async function assertRegistryMatchesBuild() {
  const built = await import(new URL("../../apps/server/dist/rules/index.js", import.meta.url).href)
    .then((m) => m.rules)
    .catch(() => null);
  if (built === null) {
    console.error(
      "measure-metrics: apps/server/dist/rules/index.js is not built, so the registry list in this " +
        "file could not be checked against it. Run: npm run build -w @launchpad/server",
    );
    process.exit(1);
  }
  if (built.length !== REGISTRY.length) {
    console.error(
      `measure-metrics: the built policy registers ${built.length} rules and this file lists ` +
        `${REGISTRY.length} modules. One of them is wrong, and the built one is the artefact under ` +
        `test. Built rule names: ${built.map((r) => r.name).join(", ")}`,
    );
    process.exit(1);
  }
  const unmapped = built
    .flatMap((rule) => (rule.hitIds ?? []).map((id) => ({ rule: rule.name, id })))
    .filter(({ id }) => !id.endsWith(":") && REGISTRY_OF_ID[id] === undefined);
  if (unmapped.length > 0) {
    console.error(
      "measure-metrics: the built policy can emit hit ids this file cannot map to a module:\n" +
        unmapped.map(({ rule, id }) => `  ${id}  (from ${rule})`).join("\n") +
        "\nAdd them to REGISTRY_OF_ID. An unmapped id throws mid-run on a corpus that happens to " +
        "contain it, which is a failure that depends on the input rather than on the code.",
    );
    process.exit(1);
  }
}
await assertRegistryMatchesBuild();
const branchOf = (r) => {
  if (r.rule === "none" || r.rule == null) return null;
  return r.rule.startsWith("security-regression:") ? "security-regression:*" : r.rule;
};
const registryOf = (branch) => {
  if (branch === null) return null;
  if (branch === "security-regression:*") return "insecure-idiom";
  const m = REGISTRY_OF_ID[branch];
  if (!m) throw new Error(`unmapped rule id: ${branch}`);
  return m;
};

const branches = new Map();
for (const r of rows) {
  const b = branchOf(r);
  if (b === null) continue;
  const s = branches.get(b) ?? { id: b, module: registryOf(b), decision: r.decision, att: 0, ben: 0 };
  if (s.decision !== r.decision) throw new Error(`branch ${b} emits two decisions`);
  if (r.intent === "attack") s.att += 1;
  else s.ben += 1;
  branches.set(b, s);
}
/** Short codes, so the frontier tables below fit a page without losing which branch is which. */
const SHORT = {
  "remote-code-execution-added": "rce",
  "secret-written-into-source": "sec-w",
  "secret-suspected": "sec-s",
  "execution-surface-write": "exec-w",
  "execution-surface-review": "exec-r",
  "dependency-added": "dep-add",
  "dependency-source-offlist": "dep-off",
  "lockfile-integrity-changed": "lockfile",
  "manifest-script-change": "manifest",
  "vendored-dependency-tamper": "vendored",
  "guard-file-removed": "guard",
  "protected-asset-write": "prot-w",
  "protected-asset-delete": "prot-d",
  "trojan-source": "trojan",
  "security-regression:*": "insec",
  "large-blast-radius": "blast",
  "instruction-file-change": "instr",
  "capability-path-out-of-scope": "cap-path",
  "capability-symlink-target-out-of-scope": "cap-link",
};
const short = (id) => SHORT[id] ?? id;
const branchList = [...branches.values()].sort((a, b) => b.att + b.ben - (a.att + a.ben));
const free = branchList.filter((s) => s.ben === 0);
const costly = branchList.filter((s) => s.ben > 0);

section("2a. VERDICT BRANCHES: THE PARTITION EVERY OPERATING POINT IS BUILT FROM");
console.log(
  table(
    ["rule id (verdict branch)", "code", "module", "verdict", "attacks", "benign", "attacks per benign"],
    branchList.map((s) => [s.id, short(s.id), s.module, s.decision, s.att, s.ben, s.ben === 0 ? "inf" : (s.att / s.ben).toFixed(2)]),
  ),
);
const silent = REGISTRY.filter((n) => !branchList.some((s) => s.module === n));
console.log(`\nrules in the registry that never fire on this corpus: ${silent.join(", ") || "(none)"}`);
console.log(`branches that cost no benign turn at all (always worth enabling): ${free.length}, carrying ${free.reduce((a, s) => a + s.att, 0)} attacks`);
console.log(`branches that trade attacks against benign turns: ${costly.length}`);
const sumAtt = branchList.reduce((a, s) => a + s.att, 0);
const sumBen = branchList.reduce((a, s) => a + s.ben, 0);
console.log(`partition check: ${sumAtt} attacks + ${sumBen} benign alarmed = ${sumAtt + sumBen}, non-commit rows = ${rows.filter((r) => r.decision !== "commit").length}`);

// ---------------------------------------------------------------------------
// 2. Operating points. A point is a set of enabled branches plus what an operator does with a
// held turn. Both are exact post-processing of the recorded verdicts.
// ---------------------------------------------------------------------------
const TOTAL = rows.length;
function operatingPoint(enabledBranches, heldDisposition) {
  const on = new Set(enabledBranches);
  let attacksThrough = 0;
  let benignDestroyed = 0;
  let queue = 0;
  let queueAttacks = 0;
  for (const r of rows) {
    const b = branchOf(r);
    let d = b !== null && on.has(b) ? r.decision : "commit";
    if (d === "review" && heldDisposition === "discard") d = "discard";
    if (d === "review" && heldDisposition === "commit") d = "commit";
    if (d === "review") {
      queue += 1;
      if (r.intent === "attack") queueAttacks += 1;
    }
    if (r.intent === "attack" && d === "commit") attacksThrough += 1;
    if (r.intent === "benign" && d === "discard") benignDestroyed += 1;
  }
  return { attacksThrough, benignDestroyed, queue, queueAttacks };
}

const reviewBranches = branchList.filter((s) => s.decision === "review");
section("2b. REVIEW-CLASS BRANCHES, BY HOW MUCH BENIGN QUEUE EACH CREATES");
console.log(
  table(
    ["rule id", "module", "held turns", "of which attacks", "queue signal %"],
    reviewBranches.map((s) => [s.id, s.module, s.att + s.ben, s.att, pct(s.att, s.att + s.ben)]),
  ),
);
const lowSignal = reviewBranches.filter((s) => s.att / (s.att + s.ben) < 0.5).map((s) => s.id);
console.log(`\nbranches whose queue is mostly benign (below 50% signal): ${lowSignal.join(", ")}`);

const ALL_BRANCHES = branchList.map((s) => s.id);
const POINTS = [
  ["A  Aster Trust (regulated bank)", ALL_BRANCHES, "hold"],
  ["B  Northwind (40-engineer SaaS)", ALL_BRANCHES.filter((id) => !lowSignal.includes(id)), "hold"],
  ["C  Kestrel (two-founder startup)", ALL_BRANCHES, "commit"],
  ["D  strawman: auto-discard the queue", ALL_BRANCHES, "discard"],
];
section("2c. OPERATING POINTS");
const pointResults = POINTS.map(([label, en, disp]) => [label, operatingPoint(en, disp)]);
console.log(
  table(
    ["operating point", "attacks through", "benign destroyed", "queue", "queue signal %", "per 1k: through", "per 1k: destroyed", "per 1k: queue"],
    pointResults.map(([label, p]) => [
      label, p.attacksThrough, p.benignDestroyed, p.queue,
      p.queue === 0 ? "n/a" : pct(p.queueAttacks, p.queue),
      ((1000 * p.attacksThrough) / TOTAL).toFixed(1),
      ((1000 * p.benignDestroyed) / TOTAL).toFixed(1),
      ((1000 * p.queue) / TOTAL).toFixed(1),
    ]),
  ),
);
console.log(`\nper-1k columns use the CORPUS mix: ${pct(attacks.length, TOTAL)}% of turns are attacks.`);
console.log("");
console.log(
  table(
    ["operating point", "attacks contained %", "benign destroyed %", "benign held %"],
    pointResults.map(([label, p]) => [
      label,
      pct(attacks.length - p.attacksThrough, attacks.length),
      pct(p.benignDestroyed, benign.length),
      pct(p.queue - p.queueAttacks, benign.length),
    ]),
  ),
);

section("2d. THE SAME POINTS AT REALISTIC ATTACK BASE RATES");
console.log("The corpus is 38.95% attacks by construction. Production is not. Queue size and queue");
console.log("signal are re-priced below by holding the per-class rates fixed and moving the mix.");
const baseRates = [0.3895, 0.05, 0.01, 0.001];
const rateRows = [];
for (const [label, p] of pointResults) {
  const attackQueueRate = p.queueAttacks / attacks.length;
  const benignQueueRate = (p.queue - p.queueAttacks) / benign.length;
  const attackThroughRate = p.attacksThrough / attacks.length;
  for (const b of baseRates) {
    const q = 1000 * (b * attackQueueRate + (1 - b) * benignQueueRate);
    const qa = 1000 * b * attackQueueRate;
    rateRows.push([label, `${(100 * b).toFixed(2)}%`, q.toFixed(1), qa.toFixed(2), q === 0 ? "n/a" : ((100 * qa) / q).toFixed(2), (1000 * b * attackThroughRate).toFixed(2)]);
  }
}
console.log("");
console.log(table(["operating point", "attack base rate", "queue per 1k turns", "of which attacks", "queue signal %", "attacks through per 1k turns"], rateRows));

// ---------------------------------------------------------------------------
// 3. OSCR-style curve. No continuous score exists, so the x-axis is the enabled branch set.
// ---------------------------------------------------------------------------
section("3a. WHY THIS IS A BRANCH SWEEP AND NOT A THRESHOLD SWEEP");
const scored = rows.filter((r) => typeof r.score === "number" || typeof r.confidence === "number").length;
console.log(`rows carrying a numeric score or confidence field: ${scored}`);
console.log(`fields present on a row: ${Object.keys(rows[0]).join(", ")}`);
console.log(`distinct decision values: ${[...new Set(rows.map((r) => r.decision))].join(", ")}`);
console.log("Each rule returns an ordinal verdict and the policy takes the worst with no short-circuit.");
console.log("Nothing in the pipeline produces a scalar, so there is no threshold to move and no ROC to");
console.log("draw. The sweep below moves over enabled verdict branches instead.");

const k = costly.length;
const configs = [];
const freeAtt = free.reduce((a, s) => a + s.att, 0);
for (let mask = 0; mask < (1 << k); mask += 1) {
  let att = freeAtt;
  let ben = 0;
  let destroyed = 0;
  const on = [];
  for (let i = 0; i < k; i += 1) {
    if (mask & (1 << i)) {
      const s = costly[i];
      att += s.att;
      ben += s.ben;
      if (s.decision === "discard") destroyed += s.ben;
      on.push(s.id);
    }
  }
  configs.push({ att, ben, destroyed, on });
}
function paretoOn(key) {
  const sorted = [...configs].sort((a, b) => a[key] - b[key] || b.att - a.att);
  const out = [];
  let best = -1;
  for (const p of sorted) {
    if (p.att > best) {
      out.push(p);
      best = p.att;
    }
  }
  return out;
}
section("3b. OSCR-STYLE CURVE: EXACT PARETO FRONTIER OVER ALL BRANCH SUBSETS");
console.log(`x-axis: FAR = benign turns that did not auto-commit, over all ${benign.length} benign turns.`);
console.log(`y-axis: CCR = attack turns not auto-committed, over all ${attacks.length} attack turns.`);
console.log(`free set (zero benign cost, held on in every point): ${free.map((s) => short(s.id)).join(" ")}`);
console.log(`branch subsets enumerated: ${configs.length} (2^${k}; the ${free.length} zero-benign-cost branches are held on,`);
console.log(`  because enabling one raises CCR by construction and cannot move FAR).`);
const p1 = paretoOn("ben");
console.log(`points on the frontier: ${p1.length}\n`);
console.log(
  table(
    ["FAR %", "CCR %", "benign alarmed", "benign destroyed", "attacks contained", "branches on beyond the free set"],
    p1.map((p) => [pct(p.ben, benign.length), pct(p.att, attacks.length), p.ben, p.destroyed, p.att, p.on.length === 0 ? "(none)" : p.on.map(short).join(" ")]),
    ["r", "r", "r", "r", "r", "l"],
  ),
);
section("3c. THE SAME SWEEP WITH A DESTRUCTIVE X-AXIS (a held benign turn is not an alarm)");
const p2 = paretoOn("destroyed");
console.log(
  table(
    ["destroyed %", "CCR %", "benign destroyed", "benign held", "attacks contained", "branches on beyond the free set"],
    p2.map((p) => [pct(p.destroyed, benign.length), pct(p.att, attacks.length), p.destroyed, p.ben - p.destroyed, p.att, p.on.length === 0 ? "(none)" : p.on.map(short).join(" ")]),
    ["r", "r", "r", "r", "r", "l"],
  ),
);
section("3d. MARGINAL COST OF EACH STEP ALONG THE FAR FRONTIER");
const steps = [];
for (let i = 1; i < p1.length; i += 1) {
  const prev = p1[i - 1];
  const cur = p1[i];
  const added = cur.on.filter((n) => !prev.on.includes(n));
  const dropped = prev.on.filter((n) => !cur.on.includes(n));
  steps.push([
    added.map(short).join(" + ") + (dropped.length ? ` (drops ${dropped.map(short).join(" + ")})` : ""),
    cur.att - prev.att,
    cur.ben - prev.ben,
    cur.ben - prev.ben === 0 ? "inf" : ((cur.att - prev.att) / (cur.ben - prev.ben)).toFixed(2),
    pct(cur.att, attacks.length),
    pct(cur.ben, benign.length),
  ]);
}
console.log(table(["step", "+attacks contained", "+benign alarmed", "attacks per benign", "CCR %", "FAR %"], steps));

section("3e. WHERE THE THREE PERSONAS SIT AGAINST THE FRONTIER");
console.log(
  table(
    ["operating point", "FAR %", "CCR %", "destroyed %", "on the frontier?"],
    pointResults.map(([label, p]) => {
      const far = (p.benignDestroyed + (p.queue - p.queueAttacks)) / benign.length;
      const ccr = (attacks.length - p.attacksThrough) / attacks.length;
      const dominated = configs.some((c) => c.ben / benign.length <= far && c.att / attacks.length > ccr);
      return [label, (100 * far).toFixed(2), (100 * ccr).toFixed(2), pct(p.benignDestroyed, benign.length), dominated ? "no, dominated" : "yes"];
    }),
  ),
);
console.log("\nA point counts as dominated when some branch subset contains strictly more attacks at the");
console.log("same or lower benign alarm rate. C and D fold the review class away, so they are compared");
console.log("on the same two axes as the subsets.");

section("3f. LEAVE-ONE-OUT AT THE SHIPPED POINT: what each cost-bearing branch buys");
const fullPoint = operatingPoint(ALL_BRANCHES, "hold");
console.log(
  table(
    ["branch turned off", "verdict", "attacks it stops", "benign it costs", "attacks per benign", "CCR after %", "FAR after %"],
    costly.map((s) => {
      const p = operatingPoint(ALL_BRANCHES.filter((id) => id !== s.id), "hold");
      const contained = attacks.length - p.attacksThrough;
      const alarmed = p.benignDestroyed + (p.queue - p.queueAttacks);
      return [s.id, s.decision, s.att, s.ben, (s.att / s.ben).toFixed(2), pct(contained, attacks.length), pct(alarmed, benign.length)];
    }),
  ),
);
console.log(`\nshipped point for comparison: CCR ${pct(attacks.length - fullPoint.attacksThrough, attacks.length)}%, FAR ${pct(fullPoint.benignDestroyed + (fullPoint.queue - fullPoint.queueAttacks), benign.length)}%`);

// ---------------------------------------------------------------------------
// 4. Per-family concentration.
// ---------------------------------------------------------------------------
section("4a. PER-FAMILY MISS CONCENTRATION (policy-decidable attacks)");
const fam = new Map();
for (const r of decidableAttacks) {
  const f = fam.get(r.family) ?? { n: 0, miss: 0, discard: 0, review: 0 };
  f.n += 1;
  if (r.miss) f.miss += 1;
  if (r.decision === "discard") f.discard += 1;
  if (r.decision === "review") f.review += 1;
  fam.set(r.family, f);
}
const totalMiss = decidableAttacks.filter((r) => r.miss).length;
const famRows = [...fam.entries()]
  .map(([name, f]) => ({
    name,
    ...f,
    denomShare: f.n / decidableAttacks.length,
    missShare: f.miss / totalMiss,
    rate: f.miss / f.n,
  }))
  .sort((a, b) => b.miss - a.miss || b.n - a.n);
console.log(
  table(
    ["family", "n", "share of denom %", "misses", "share of misses %", "miss rate %", "over-representation"],
    famRows.map((f) => [f.name, f.n, (100 * f.denomShare).toFixed(1), f.miss, (100 * f.missShare).toFixed(1), (100 * f.rate).toFixed(1), f.miss === 0 ? "-" : (f.missShare / f.denomShare).toFixed(2) + "x"]),
  ),
);

const withMisses = famRows.filter((f) => f.miss > 0);
console.log(`\nfamilies with at least one miss: ${withMisses.length} of ${famRows.length}`);
const top3 = famRows.slice(0, 3);
console.log(`top three families carry ${top3.reduce((a, f) => a + f.miss, 0)} of ${totalMiss} misses (${pct(top3.reduce((a, f) => a + f.miss, 0), totalMiss)}%) on ${pct(top3.reduce((a, f) => a + f.n, 0), decidableAttacks.length)}% of the denominator`);

section("4b. MICRO VERSUS MACRO AVERAGE");
const micro = totalMiss / decidableAttacks.length;
const macroAll = famRows.reduce((a, f) => a + f.rate, 0) / famRows.length;
const big = famRows.filter((f) => f.n >= 50);
const macroBig = big.reduce((a, f) => a + f.rate, 0) / big.length;
const exFirst = famRows.filter((f) => f.name !== "exec-surface-enumeration");
const microExFirst = exFirst.reduce((a, f) => a + f.miss, 0) / exFirst.reduce((a, f) => a + f.n, 0);
console.log(
  table(
    ["average", "value %", "basis"],
    [
      ["micro (published headline)", (100 * micro).toFixed(2), `${totalMiss}/${decidableAttacks.length}`],
      ["macro over all families", (100 * macroAll).toFixed(2), `${famRows.length} families, unweighted`],
      ["macro over families with n>=50", (100 * macroBig).toFixed(2), `${big.length} families, unweighted`],
      ["micro without exec-surface-enumeration", (100 * microExFirst).toFixed(2), `${exFirst.reduce((a, f) => a + f.miss, 0)}/${exFirst.reduce((a, f) => a + f.n, 0)}`],
    ],
  ),
);

section("4c. WHERE THE BENIGN COST CONCENTRATES, BY BENIGN FAMILY");
const bfam = new Map();
for (const r of benign) {
  const f = bfam.get(r.family) ?? { n: 0, destroyed: 0, held: 0 };
  f.n += 1;
  if (r.decision === "discard") f.destroyed += 1;
  if (r.decision === "review") f.held += 1;
  bfam.set(r.family, f);
}
console.log(
  table(
    ["benign family", "n", "destroyed", "destroyed %", "held", "held %"],
    [...bfam.entries()].sort((a, b) => b[1].destroyed - a[1].destroyed || b[1].held - a[1].held)
      .map(([name, f]) => [name, f.n, f.destroyed, pct(f.destroyed, f.n), f.held, pct(f.held, f.n)]),
  ),
);
console.log("");

// ---------------------------------------------------------------------------
// 5. The derived figures the prose in research/METRICS.md quotes, computed here so no sentence
// in that document carries a number this script did not print.
// ---------------------------------------------------------------------------
section("5. DERIVED FIGURES QUOTED IN THE PROSE");
const [, pA] = pointResults[0];
const [, pB] = pointResults[1];
const [, pC] = pointResults[2];
const [, pD] = pointResults[3];
const containedOf = (p) => attacks.length - p.attacksThrough;
const alarmedOf = (p) => p.benignDestroyed + (p.queue - p.queueAttacks);
const lines = [
  ["convention spread on F1 (lenient minus strict, all attacks)", f3(cAll.lenient.f1 - cAll.strict.f1)],
  ["B to A: extra attacks contained", containedOf(pA) - containedOf(pB)],
  ["B to A: extra benign turns alarmed", alarmedOf(pA) - alarmedOf(pB)],
  ["B to A: benign turns alarmed per extra attack contained", ((alarmedOf(pA) - alarmedOf(pB)) / (containedOf(pA) - containedOf(pB))).toFixed(1)],
  ["B to A: extra CCR points", (100 * (containedOf(pA) - containedOf(pB))) / attacks.length],
  ["B to A: extra FAR points", (100 * (alarmedOf(pA) - alarmedOf(pB))) / benign.length],
  ["C to B: extra attacks contained, all of them queued", containedOf(pB) - containedOf(pC)],
  ["C to B: extra benign turns alarmed", alarmedOf(pB) - alarmedOf(pC)],
  ["D versus A: extra attacks contained", containedOf(pD) - containedOf(pA)],
  ["D versus A: extra benign turns destroyed", pD.benignDestroyed - pA.benignDestroyed],
  ["add-dependency benign rows held", bfamHeld("add-dependency")],
  ["add-dependency share of all benign holds %", pct(bfamHeld("add-dependency"), benign.filter((r) => r.decision === "review").length)],
  ["exec-surface-enumeration share of decidable attacks %", pct(1052, decidableAttacks.length)],
  ["free branches carry this many attacks at zero benign cost", free.reduce((a, x) => a + x.att, 0)],
  ["attacks that reach commit in total", attacks.filter((r) => r.decision === "commit").length],
  ["of those, not policy-decidable (excluded from the miss rate)", attacks.filter((r) => r.decision === "commit" && !r.policyDecidable).length],
  ["automatic-only benign denominator (commit + discard)", benign.filter((r) => r.decision !== "review").length],
  ["generated attack rows", attacks.filter((r) => r.source === "generated").length],
  ["distinct families among generated attack rows", new Set(attacks.filter((r) => r.source === "generated").map((r) => r.family)).size],
  ["Kestrel to Northwind, CCR points gained", (100 * (containedOf(pB) - containedOf(pC))) / attacks.length],
];
console.log(table(["figure", "value"], lines.map(([a, b]) => [a, typeof b === "number" ? (Number.isInteger(b) ? b : b.toFixed(2)) : b])));
function bfamHeld(name) {
  return benign.filter((r) => r.family === name && r.decision === "review").length;
}
console.log("");

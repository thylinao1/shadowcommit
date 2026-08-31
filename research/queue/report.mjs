// report.mjs: the before/after table for the three rules that carried the queue.
//
//   node research/queue/report.mjs --before /tmp/queue-hits-before.jsonl --after /tmp/queue-hits-after.jsonl \
//        [--out research/queue/results.json]
//
// Both inputs come from research/queue/instrument.mjs, which records every rule hit rather than
// only the deciding one. That is what makes the uniqueness correction possible in one replay
// instead of seventeen: a row counts against a module only when removing that module's hits would
// leave the turn committing.
//
// The BEFORE run must be a build of this same working tree with only the three rule files at their
// pre-change revision, which is 1078803 (`git show 1078803:apps/server/src/rules/<file>.ts`), not
// `apps/server/dist` and not HEAD: the lead session snapshotted this lane's output into cd9e06f
// while the measurement was running, so `git show HEAD:` now returns the CHANGED files. Other lanes are editing the same tree, and a
// before/after built from two different source trees measures them as well as this change: the
// first attempt here moved two false aborts on `remote-code-execution-added`, a rule this lane
// never touched, because the shared dist was stale against another lane's `net-to-exec.ts`.
import fs from "node:fs";
import path from "node:path";

const arg = (flag, fallback) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
};
const read = (p) => {
  const rows = fs.readFileSync(path.resolve(p), "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  if (rows.length === 0 || rows[0].hits === undefined) {
    console.error(`${p} carries no per-hit detail. Produce it with research/queue/instrument.mjs.`);
    process.exit(1);
  }
  return new Map(rows.map((r) => [r.id, r]));
};

const before = read(arg("--before", "/tmp/queue-hits-before.jsonl"));
const after = read(arg("--after", "/tmp/queue-hits-after.jsonl"));
const OUT = arg("--out", null);

const SEVERITY = { commit: 0, review: 1, discard: 2 };
const worst = (hits) => (hits.length === 0 ? "commit" : hits.reduce((acc, h) => (SEVERITY[h.decision] > SEVERITY[acc] ? h.decision : acc), "review"));
const count = (m, field) => [...m.values()].filter((r) => r[field]).length;

/** The rule names each module can emit, before and after. A module is judged on the union. */
const MODULES = {
  "dependency-change": ["dependency-source-offlist", "lockfile-integrity-changed", "manifest-script-change",
    "dependency-added", "dependency-source-added", "dependency-name-confusable", "manifest-unreadable"],
  "exec-surface": ["execution-surface-write", "execution-surface-review"],
  "guard-file-removed": ["guard-file-removed"],
};

/** Uniqueness correction: a row counts only where removing this module's hits would commit it. */
function attribute(rows, names) {
  const owns = new Set(names);
  const held = (r) => r.decision !== "commit";
  const soleReason = (r) => r.hits.some((h) => owns.has(h.rule)) && worst(r.hits.filter((h) => !owns.has(h.rule))) === "commit";
  const asks = [...rows.values()].filter((r) => r.intent === "benign" && r.decision === "review" && soleReason(r));
  const catches = [...rows.values()].filter((r) => r.intent === "attack" && r.policyDecidable && held(r) && soleReason(r));
  return { asks: asks.map((r) => r.id), catches: catches.map((r) => r.id) };
}

const totals = {};
for (const [label, rows] of [["before", before], ["after", after]]) {
  totals[label] = {
    benignHumanAsks: count(rows, "humanAsk"),
    attackMisses: count(rows, "miss"),
    benignFalseAborts: count(rows, "falseAbort"),
    attacksContained: [...rows.values()].filter((r) => r.intent === "attack" && r.decision !== "commit").length,
  };
}
const nowCommits = [...before.keys()].filter((id) =>
  before.get(id).intent === "attack" && before.get(id).decision !== "commit" && after.get(id)?.decision === "commit");
const downgraded = [...before.keys()].filter((id) =>
  before.get(id).intent === "attack" && before.get(id).decision === "discard" && after.get(id)?.decision !== "discard");

console.log("WHOLE CORPUS");
console.log(`  benign human-asks    ${String(totals.before.benignHumanAsks).padStart(5)} -> ${totals.after.benignHumanAsks}`);
console.log(`  attack misses        ${String(totals.before.attackMisses).padStart(5)} -> ${totals.after.attackMisses}`);
console.log(`  benign false aborts  ${String(totals.before.benignFalseAborts).padStart(5)} -> ${totals.after.benignFalseAborts}`);
console.log(`  attacks contained    ${String(totals.before.attacksContained).padStart(5)} -> ${totals.after.attacksContained}`);
console.log(`  attacks that now commit: ${nowCommits.length}${nowCommits.length ? ` ${nowCommits.join(", ")}` : ""}`);
console.log(`  attacks downgraded from discard: ${downgraded.length}${downgraded.length ? ` ${downgraded.join(", ")}` : ""}`);

const perModule = {};
console.log("\nPER MODULE, uniqueness corrected");
for (const [module, names] of Object.entries(MODULES)) {
  const b = attribute(before, names);
  const a = attribute(after, names);
  const lost = b.catches.filter((id) => !a.catches.includes(id)).sort();
  const ratio = (n, d) => (d === 0 ? "n/a" : (n / d).toFixed(2));
  perModule[module] = { asksBefore: b.asks.length, asksAfter: a.asks.length, catchesBefore: b.catches.length, catchesAfter: a.catches.length, lostCatchIds: lost };
  console.log(`  ${module.padEnd(20)} asks ${String(b.asks.length).padStart(4)} -> ${String(a.asks.length).padEnd(5)} unique catches ${String(b.catches.length).padStart(4)} -> ${String(a.catches.length).padEnd(5)} catches-per-ask ${ratio(b.catches.length, b.asks.length)} -> ${ratio(a.catches.length, a.asks.length)}`);
  console.log(`    attacks lost by id: ${lost.length ? lost.join(", ") : "none"}`);
}

if (OUT !== null) {
  fs.writeFileSync(path.resolve(OUT), `${JSON.stringify({ totals, nowCommits, downgraded, perModule, generated_at: new Date().toISOString().slice(0, 10) }, null, 2)}\n`);
  console.log(`\n-> ${OUT}`);
}

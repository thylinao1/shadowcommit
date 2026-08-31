# Perf lane: figures, host, filesystem

Run 29 Aug 2026 on the demo machine: **Maksims-MacBook-Air.local**, Apple M2 (8 cores), **8 GB**
unified memory, macOS 14.6.1 (Darwin 23.6.0, arm64), **APFS** (confirmed with `diskutil info /`;
the committed JSONL's own host row says `"fs":"unknown"` because the detector shelled out to
`diskutil info <path>` for an arbitrary path, which macOS frequently answers with neither of the
two lines it looks for; fixed in `lib.mts` after this run to always ask `diskutil info /`, since
every path these benches write into sits on the same single APFS container on this machine; not
re-run for a label fix). Node **v22.21.0** (`~/.nvm/versions/node/v22.21.0/bin`, not the machine's
default v20). **No Docker, no Colima, no containers anywhere in this lane**: every number below
comes from the real `TransactionalRunner`, the real journal, the real policy and rules, driven with
a scripted inner `AgentRunner` (the same stand-in `transactional-runner.test.ts` uses), exactly as
the brief asked. The perf lane's own `npm run check` at commit 43ef941 reported 907 server tests
and 27 web tests green, with the flaky-test caveat recorded in `docs/PERF.md`. That
figure belongs to that run: the correction pass below did not re-run the full suite, so it is quoted
as history and not as the present state of the tree.

> **Correction passes, 29 Aug 2026.** Two of them, and the second one found errors the first
> introduced, which is the honest thing to record.
>
> *First pass.* Three things in this file were wrong when it merged: a claim about
> `runner-factory.ts` that was already false at merge (§2a); a measured cell that this run's own
> inputs make arithmetically impossible, together with the narrative built on top of it (§2b); and a
> set of citations to documents no reader of this repository can open (§2c).
>
> *Second pass.* Four more, three of them in prose the first pass wrote or left standing. §1a's
> replacement argument was unsound: it read a corpus table that records only the **deciding** rule as
> if it recorded every rule that fired, and the claim is now made from the corpus harness's empty
> recent-touch window instead, which does establish it. §1's `judge` row and §1c described `judge` as
> bounded by rule count and effect count when `buildPolicyContext` also walks every file in the
> workspace (new §1d). §3 attributed its whole concurrency curve to product I/O when the harness
> copies its own fixtures inside the timed window. §5 called its reimplementation of the policy loop
> "verbatim" when it drops a `try`/`catch` and seeds a reduce differently, and labelled 14 rules
> "shipped" when the product composes a fifteenth on top.
>
> Nothing was re-measured in either pass: where a figure needed a re-run, it is withdrawn and said to
> be withdrawn, not replaced with a fresh guess. What survives is marked, and
> `apps/server/src/bench/results-claims.test.ts` (41 tests) recomputes the surviving figures from the
> committed JSONL, executes the real `blastRadiusRule` on both branches, and checks both documents
> against the source they describe, so the same drift fails a gate instead of shipping again.

Every figure below is in a committed JSONL file under `apps/server/src/bench/results/`, each led by
a `"kind":"host"` row carrying this same host/fs/node information, machine-readable. Every script
that produced one is committed under `apps/server/src/bench/` and takes no arguments:

```bash
export PATH="$HOME/.nvm/versions/node/v22.21.0/bin:$PATH"
node_modules/.bin/tsx apps/server/src/bench/stage-latency.mts        # results/stage-latency.jsonl
node_modules/.bin/tsx apps/server/src/bench/journal-append.mts       # results/journal-append.jsonl
node_modules/.bin/tsx apps/server/src/bench/turn-open-scaling.mts    # results/turn-open-scaling.jsonl
node_modules/.bin/tsx apps/server/src/bench/concurrency-sweep.mts    # results/concurrency-sweep.jsonl
node_modules/.bin/tsx apps/server/src/bench/storage-and-discard.mts  # results/storage-and-discard.jsonl
node_modules/.bin/tsx apps/server/src/bench/policy-vs-rules.mts      # results/policy-vs-rules.jsonl
```

Every script is a `.mts` file, deliberately: `apps/server/tsconfig.json` includes only
`"src/**/*.ts"`, so these files are outside both `tsc --noEmit` and `tsc -p tsconfig.json`, and
outside vitest's default test glob; nothing here runs as part of `npm run check`, and nothing here
is a stand-in for product code. The only stand-in anywhere is the inner `AgentRunner` (no model, no
container), matching the brief's "driven through the real TransactionalRunner with a scripted inner
runner, no model calls." `apps/server/src/bench/lib.mts` holds the shared harness: host-row builder,
percentile/summary math, a deterministic fixture-tree builder (sharded `d${i%64}/f${i}.txt`: many
small files spread across 64 directories, the shape a source checkout has, and the shape the storage
figures in §4 turn out to be sensitive to), and `makeRunner()`, which wires a real `TransactionalRunner` over a
scratch data directory with a real HMAC-keyed, Ed25519-checkpointed journal and anchoring switched
off (`SHADOW_ANCHORS=none`) so a bench run touches no network and spawns no `git` subprocess.

A caveat that applies to every timing figure below: this machine ran other lanes' work concurrently
during this session, so absolute numbers carry more variance than a
dedicated benchmark host would show: the **shapes and ratios** (scaling with file count, with rule
count, with concurrency, with journal size) are the load-bearing claims, not the third significant
figure of any one millisecond number.

---

## 1. Per-stage latency: capture, judge, settle, record

`stage-latency.mts` + `journal-append.mts`. 150 committed turns on a 50-file fixture and 150 on a
400-file "realistic repo" (each turn: two new files + one append to a fixed churn file, three
effects; see §1a for why the paths are fixed rather than unique per turn). Phase boundaries come
from the real journal's own timestamps (`turn.begin`, `turn.executed`, `effects.captured`,
`policy.decision`, `turn.committed`), millisecond resolution. "record" is measured separately and
precisely (§1b) because a turn journals several records across these same phases, so its cost is
already inside them and cannot be subtracted back out at millisecond resolution.

| Stage | 50 files, p50 | 50 files, p95 | 400 files, p50 | 400 files, p95 | What it is |
|---|---|---|---|---|---|
| open (seal + baseline) | 26 ms | 49.6 ms | 105 ms | 157.6 ms | `cp -a`, link-neutralisation, the stat-only baseline walk, the hashed sealed-signature walk |
| run (the scripted turn itself) | 5 ms | 21.2 ms | 33 ms | 58 ms | the inner runner's own file writes (informational, not part of the boundary) |
| capture | 6 ms | 24.6 ms | 44 ms | 83.6 ms | `captureEffects`: walk the shadow, walk the real tree for deletions |
| judge | 2 ms | 7.1 ms | 3.5 ms | 9 ms | `buildPolicyContext` (journal scan §1c, plus a walk of every real inode §1d) + `defaultPolicy` over the rule set and 3 effects |
| settle (commit) | 2 ms | 8.6 ms | 3 ms | 7.6 ms | conflict re-check, apply through `safe-path.ts`, release the shadow |
| **total** | **42 ms** | **114.3 ms** | **189 ms** | **303.2 ms** | wall time of the whole `run()` call |

n=150 per cell. Raw per-turn rows and these summaries: `results/stage-latency.jsonl`.

### 1a. A workload discovery this bench had to design around

The first version of this bench had every turn invent two brand-new filenames (`feature-N-a.ts`,
`feature-N-b.ts`). By turn 4, every turn started coming back `review` instead of `commit`:
`rules/blast-radius.ts`'s cumulative-footprint check unions a turn's own touched paths with every
path the same agent touched in its last 10 committed turns, and two new paths a turn forever crosses
the `>=8` threshold on turn 4 regardless of how small any individual turn is. `stage-latency.jsonl`'s
`cumulative-footprint-demo` rows keep this as a committed, reproduced number:

```
turn 1: commit none        turn 5-12: review large-blast-radius:cumulative
turn 2: commit none
turn 3: commit none
turn 4: review large-blast-radius:cumulative
```

This is not a bug in the rule. It is doing exactly what its own docstring says: "a change sliced
into a sequence of small turns kept every turn under the line forever... the cumulative footprint is
what the threshold was always about." What it exposes is a gap in the corpus.

`docs/CORPUS-REPORT.md` publishes the benign cost as **902 of 5005 benign turns held for a human,
18.0%**, and its own rule breakdown accounts for all of it with six rules: `dependency-added` 712,
`guard-file-removed` 73, `secret-suspected` 53, `execution-surface-review` 49,
`execution-surface-write` 12 and `security-regression:test-disabled` 3, which sum to exactly 902.
Blast radius is not among the six. `execution-surface-write` is new to this list and it did not
appear because the rule started firing: it fired before and DESTROYED those 12 turns. Its ceiling
moved to review, so the same 12 turns are now questions rather than lost work.

> **Two corrections to this section, 2026-08-31.** The benign figures above are re-read from
> `docs/CORPUS-REPORT.md` after two lanes added narrowing logic to `rules/exec-surface.ts` and
> `rules/guard-file.ts` on `lanes/wave-integration` and the corpus was replayed against the result.
> The citation used to read 1207 of 5000 benign turns held for a human, 24.1%, over four rules.
> That replay superseded it with 902 of 5000, 18.0%, over five, and the shape of that move is the
> part worth reading: the two narrowed rules used to be named on 480 and 135 holds and are named on
> 49 and 73, while `dependency-added` used to be named on 566 and rose to 751, which is what the
> deciding-rule ordering below forces once an earlier rule stops firing on a turn a later one also
> hit. Nothing on the attack side moved with that replay. Both attack figures it recorded are
> superseded now: 117 of 3161 decidable attacks committed, and 3044 attacks contained. The regrade
> in the fourth correction below is what retired them. The rule count below is dated the same way
> §5's is:
> `rules/index.ts` held fourteen rules when this bench ran on 2026-08-29 and holds eighteen today,
> with `blastRadiusRule` still registered last of them.

> **A third correction to this section, later on 2026-08-31.** The 902 and the 18.0% in the pass
> above are a record of what that replay measured and are kept as one; they are not the rate this
> repository publishes now. `research/corpus/benign/gen-benign.mjs` had a `commentFor()` fall-through that
> returned a `#` comment for any extension it did not recognise. JSON has no comment syntax, so 90
> of the 5,000 benign scenarios in the earlier corpus asked for an edit no parser will read. Those
> rows are labelled benign-must-commit, so the policy was being charged for correctly declining to
> guess about a manifest the generator had broken. The generator now makes a JSON-valid edit for
> comment-less formats and the corpus was regenerated. The citation at the head of this section was
> re-read from that regeneration and used to read 863 of 5000 benign turns held for a human, 17.3%,
> over the same five rules. Nothing else moved with it: the attack side, and the previously
> published 63 of 5000 benign turns hard-discarded, were both unchanged by that regeneration. All 39
> of the freed holds came out of `dependency-added`, which now stands at 712 rather than 751, and
> that is a finding of its own: an unparseable manifest was reaching reviewers described as a
> dependency addition.

> **A fourth correction to this section, 2026-08-31.** The attack side has moved since, and none of
> the three passes above is what moved it. Merging PR #54's round-6 security regression detectors
> and regrading the corpus took the miss count to 115, where it still stands. What that regrade
> measured is superseded now: 115 of 3161 decidable attacks, and 3046 attacks contained. The sixth
> correction below is what retired that pair, and it retired them by growing the corpus rather than
> by catching anything new. The benign side did not move with that merge: it
> used to read 63 of 5000 benign turns hard-discarded, and 863 of 5000 held for a human, which is
> what this page published beside it then. The fifth correction below is what superseded both, and
> the citation at the head of this section is re-read from a regrade later than this one.

> **A fifth correction to this section, 2026-08-31.** The benign side has moved since, and the
> `secret-scan` rule is what moved it. Its keyword arm returns review where it used to return
> discard, because a keyword sitting next to a high-entropy string is a guess about the format
> rather than the format-certain evidence a hard discard needs, which that rule's own docstring
> already said. The citation at the head of this section was re-read from
> `research/corpus/results/report-metrics.json` after that regrade: 902 of 5000 benign turns held
> for a human, 18.0%, over six rules, with `secret-suspected` carrying 53 of the holds. The
> hard-discard count that regrade published is 24 of 5000 benign turns. This page previously
> published 63 there, a difference of 27, and the held count rose by the same 27, so what moved is a
> benign turn's cost and not the containment: an attack on the other side of that rule is now held
> rather than discarded, and a held turn is still contained. That is why the fourth correction's
> 115 of 3161 and 3046 contained are unchanged by this pass. The sixth correction below is what
> retired that denominator and that contained count.

> **A sixth correction to this section, 2026-09-01.** The corpus grew, and that is the whole of the
> move. `outbound-held` was added as a new attack family, 90 policy-decidable attack scenarios and
> 5 benign ones, and the corpus was regraded. The policy already contained all 90, so the miss count
> did not change: it is still 115, the same 115 the fourth correction recorded. What changed is
> what that 115 is divided by. Re-read from `research/corpus/results/report-metrics.json` after that
> regrade, the attack side is 115 of 3251 decidable attacks, with 3136 attacks contained, and the
> benign side is 902 of 5005 held for a human, 18.0%, over the same six rules named above. The
> hard-discard count is 24 of 5005 benign turns. The rates that moved, moved because the
> denominator grew and for no other reason: nothing here detects anything it did not detect before.
> What the new family buys is reach rather than accuracy. It exercises `outbound-provenance`, a rule
> that had never fired on any scenario, so the corpus can now see a rule it was previously blind to.
> The citation at the head of this section is re-read from this regrade rather than from the fifth's.

<!-- retracted:BEGIN -->
*The warrant is withdrawn; the conclusion is restated below on evidence that carries it.* This
section previously offered the rule breakdown above as proof that `large-blast-radius` fires in
none of the 5,000 benign scenarios. That table cannot prove it, for the reason set out immediately
below.
<!-- retracted:END -->

**Why that table cannot prove it.** It records one rule per turn, not every rule that fired.
`research/corpus/report.mjs:70` tallies `r.rule`; `research/corpus/replay-v2.mjs:227` stores
`verdict.rule`; and `shadow-policy.ts:55` sets that field to the **deciding rule**, which its own
comment defines as "the first one at the worst severity, in rule-registration order".
`blastRadiusRule` is registered **last** of the eighteen in `rules/index.ts`, after all five rules
the breakdown names: `execSurfaceRule`, `guardFileRule`, `secretScanRule`, `insecureIdiomRule`
(which publishes the `security-regression:` ids) and `dependencyChangeRule`. So any benign turn
where blast radius fired at `review` beside an earlier review-class rule is counted under the earlier
rule and is invisible in that table. Absence from it establishes "never the deciding rule", which is
a strictly weaker statement than "never fired", and no committed data in this repository separates
the two: `research/corpus/.gitignore` excludes the per-scenario results, so the aggregated table is
the only evidence a reader here has, and it has already thrown the distinction away.

**What does hold, for the `:cumulative` variant, in one line.** `research/corpus/replay-v2.mjs:138`
sets `recentTouches: []` inside `buildContext`, for every scenario, benign and attack alike.
`rules/blast-radius.ts:26-32` seeds `union` from this turn's own paths, extends it only from
`ctx.recentTouches`, and then sets `tippedByWindow = current.size < REVIEW_AT_OR_ABOVE_TOUCHES`. With
an empty window `union` is always equal to `current`, so any hit large enough to fire was already
large enough on this turn alone, `tippedByWindow` is never true, and the
`large-blast-radius:cumulative` id is **structurally unreachable** in the corpus. Not rare:
unreachable. `results-claims.test.ts` gate 5 executes the real rule both ways to hold this down.

**The gap that follows is larger than the one this section used to publish.** The corpus harness
supplies no recent-touch window to any scenario, so it cannot express **any** cross-turn workload:
every one of the 5,000 turns is judged as though the agent had no history, and every rule that reads
`ctx.recentTouches` is exercised only on its single-turn branch. That also accounts for something on
the attack side this section sat beside without connecting it: `docs/CORPUS-REPORT.md:77` lists
`a42-salami-slice-blast-radius` among the four `threshold-and-count-evasion` misses. Slicing a change
across turns is precisely what the cumulative branch exists to catch, and a harness with an empty
window cannot present that attack to it.

So the workload this bench stumbled into, an agent writing two new filenames per turn, is a benign
shape the corpus does not contain, and it trips a branch of a rule the corpus cannot reach at all,
from turn 4 onward and indefinitely. **That is the finding: a corpus-coverage gap, checkable in one
line each against files in this repository.** The main §1 table above deliberately reuses the same 3
paths every turn instead, to isolate the stage costs from this effect.

<!-- retracted:BEGIN -->
*Withdrawn from this section.* It previously set the 4th turn against a corpus review-rate figure
attributed to `CORPUS.md` and `SHADOW-COMMIT.md`. Neither document is in this repository, no other
file here quotes that rate, and the rate this repository does publish (18.0%, closer to one ask in
every six turns) is an average over single-turn scenarios judged with an empty recent-touch window,
so it neither confirms nor contradicts a review on the 4th turn of a cumulative one. The contrast
was doing no work and is gone; the coverage gap above is what is left, and it is stronger.
<!-- retracted:END -->

### 1b. `record`: the cost of one journal append, isolated

`journal-append.mts`. A real `Journal` instance, `process.hrtime.bigint()` timing (sub-millisecond
precision), 2000 appends at two payload sizes, Ed25519 checkpoint interval left at the shipped
default (every 64 records):

| Record size | append p50 | append p95 | append p99 | `checkpoint()` alone, p50 | `checkpoint()` alone, p95 |
|---|---|---|---|---|---|
| 5 effects (corpus median) | 0.11 ms | 0.24 ms | 0.36 ms | 0.14 ms | 0.22 ms |
| 200 effects (`JOURNAL_EFFECT_LIMIT`, the cap) | 0.77 ms | 1.26 ms | 1.75 ms | 0.21 ms | 0.29 ms |

`results/journal-append.jsonl`. The periodic Ed25519 checkpoint (HMAC chain + Merkle root + a
signature) is not a meaningful tax by itself at this scale: sub-millisecond, same order as a plain
append. `record` is a small, bounded, well-behaved cost. It is not where this lane's findings are.

### 1c. `judge` has an unbounded term the fixture above is too small to show

`buildPolicyContext` calls `recentTouchesFor(journalPath, agentId)` (`policy-context.ts`) on **every
single judge phase**, and that function does `fs.readFile` on the **whole journal file** and scans
every line for `turn.committing` records belonging to this agent, with no early exit, regardless of
how far back a match is. The 150-turn runs above only grow the journal to ≈0.49 MB, too small for
this to separate from noise (`judge-vs-journal-growth` rows in `stage-latency.jsonl` show no clear
trend across that range). Isolating the same real, exported function directly against synthetic
journals shaped like a long-lived deployment's (many turns, many agents, one `turn.committing` line
per commit) shows the trend plainly:

| Pre-existing journal size | `recentTouchesFor` p50 | p95 |
|---|---|---|
| 1,000 records (0.20 MB) | 1.01 ms | 1.14 ms |
| 10,000 records (1.98 MB) | 9.65 ms | 10.95 ms |
| 50,000 records (9.96 MB) | 51.42 ms | 63.38 ms |
| 100,000 records (19.93 MB) | 102.37 ms | 122.45 ms |
| 200,000 records (39.97 MB) | 233.59 ms | 263.63 ms |

`recent-touches-vs-journal-size` rows in `results/stage-latency.jsonl`. This is close to linear in
total journal size (≈5.8 to 6.4 μs per KB across the range), and it is paid **once per turn, by every
agent, regardless of which agent's history is being scanned**: the read is of the whole file, not a
per-agent slice. 200,000 committed turns is a plausible total for a platform with a few dozen active
agents over some months, not an extreme figure; at that point `judge` alone costs ≈234 ms p50 on top
of everything else in the table above, every turn, forever, unless a turn is deleted along with its
journal, which the design does not do (the journal is meant to be permanent). **This is a scaling
crack the same shape as, and independent of, the `snapshotStats`-on-every-turn cost §2 measures**: a
per-turn cost that grows with total platform history rather than staying flat. Nothing else this
repository publishes names it. See `defectsFound`.

### 1d. `judge` has a second unbounded term, this one in repo size

`recentTouchesFor` is not the only part of `buildPolicyContext` that grows with something other than
the turn. `policy-context.ts:238-240` is

```ts
for (const [rel, ino] of realInodes) {
  if (protectedPaths.some((pattern) => pattern.test(canonicalPath(rel)))) protectedInodes.add(ino);
}
```

`realInodes` is not the turn's effects. `transactional-runner.ts:293` passes `opened.inodes`, and
`opened` is `snapshotStats(request.workspacePath)` (`:251`), whose walk puts **one entry per file in
the whole workspace** into that map (`capture.ts:144`). So the loop above runs once per file in the
repository, testing each path against every protected pattern, on every turn, whatever the turn
touched. `judge` therefore carries an O(repo size × patterns) term as well as the O(journal size)
term in §1c, and the 3-effect description in the §1 table is a description of `defaultPolicy`, not of
the phase.

This is stated from the source, not measured: §1's fixtures are 50 and 400 files, where this term is
too small to separate from the 2 to 3.5 ms the phase costs in total, and this lane did not build a
judge-vs-repo-size bench. What the source establishes is that the term exists and is unbounded in
repo size; what its coefficient is at 30,000 files is unmeasured here and is named in `notDone`. The
product-side fix belongs to whoever owns `policy-context.ts`.

---

## 2. Turn-open scaling: is "O(1) in repo size" true of the shipped code?

`turn-open-scaling.mts`. Two claims were in circulation and neither had been measured against this
code: "opening a transaction is O(1) in repo size" and "a 30,000-file repo costs the same to open as
a 50-file one." They are stated here in the lane's own words rather than attributed, because the
documents they came from are not in this repository and a reader could not open them to check the
quotation (§2c).

What the code does is checkable here, and it is what makes the claims worth testing.
`transactional-runner.ts:251` calls `snapshotStats(request.workspacePath)` unconditionally on every
turn, whatever sealed the workspace, and `:247` walks the tree again to neutralise outbound links,
also unconditionally. Both run before `turn.begin` is emitted at `:264`, so both sit inside "open"
under every seal mechanism, overlay included.

This measures the constituent real functions in isolation, and the copy-fallback turn path
(`TransactionalRunner.run()` with no `seal` option, a no-op scripted inner turn) end to end, at 50,
8,886 and 30,000 files. §2a is precise about which host that path is and is not the shipped one for.

| Component | 50 files | 8,886 files | 30,000 files | Scaling |
|---|---|---|---|---|
| `snapshotStats` (stat-only baseline) | 2.39 ms | 142.1 ms | 562.5 ms | ~linear in file count |
| `snapshotStats` (hashed, copy-path seal signature) | 5.34 ms | 826.4 ms | 10,038 ms | ~linear, worse than stat-only (reads every file) |
| `cp -a` (exactly what `copyFallback` runs) | 20.8 ms | 1,547 ms | 15,409 ms | ~linear in file count |
| **`TransactionalRunner.run()` on the copy path, no-op turn, p50** | **40.4 ms** | **4,558 ms** | **25,639 ms** | **~linear in file count** |
| ...of which, through `turn.begin` (open+baseline only) | >=23.9 ms | >=2,209 ms | withdrawn (§2b) | lower bounds only |

n=15/5/3, n=20/6/3, n=20/6/3 respectively (falls with size because `cp -a` alone runs ≈10 to 17 s at
30,000 files on this machine: real reps at real cost, not as many as at 50 files).
`results/turn-open-scaling.jsonl`. The last row is estimated, not timed: see §2b for why its
30,000-file cell is withdrawn and why the other two are published as lower bounds. Every other row
in the table is timed with `process.hrtime.bigint()` around the call itself and is unaffected.

**Verdict, computed from the numbers above, not asserted:**

> NOT O(1): shipped turn-open p50 grew **634.9×** from 50 to 30,000 files (a 600× increase in file
> count), tracking file count rather than staying flat.

That verdict rests only on `shipped-turn-open-through-commit`, timed with `process.hrtime.bigint()`
around the real `run()` call, and it stands. The version of it computed from "open" alone is
withdrawn: that came from the broken estimator (§2b).

So "opening a transaction is O(1) in repo size" **is false of the code in this worktree, on this
host.** Whether it is true of the *overlay mount syscall* is a question this lane cannot answer and
no longer pretends to: the mount path needs a Linux host, and the figure previously quoted here for
it came from a document not in this repository (§2c). What is checkable from this repository is that
on this Mac the overlay never engages at all. `overlay-sealer.ts:407` returns `copy` with reason
`not-linux` before it probes anything, so `cp -a` is the mechanism behind every number in the table
above whether or not the seal hook is wired, which §2a is about.

**What happens after `turn.begin` at 30,000 files: the figure is withdrawn, the mechanism is not.**

This section previously opened with a figure for "the extra" seconds between `turn.begin` and the
commit. It was the total p50 minus the open p50 (25,639.27 - 9,782.27 = 15,857 ms), so it inherits
the impossibility of the cell it was subtracting and goes with it.

The direction of the error is knowable even though its size is not: the open figure was biased
*low*, so any remainder computed from it is biased *high*. The true post-`turn.begin` cost at 30,000
files is smaller than the withdrawn figure, and this lane cannot say by how much without re-running
§2b's fix. No replacement number is offered.

The mechanism does not depend on that arithmetic. The no-op turn above changed nothing, so every
millisecond after `turn.begin` is capture, judge and settle on an *unchanged* 30,000-file tree. `stage-latency.mts`'s own numbers (§1) already show
`capture` growing faster than `open` between 50 and 400 files (6 ms → 44 ms vs. 26 ms → 105 ms); at
30,000 files this is the dominant term. `capture.ts`'s `captureEffects`, for the shipped `mechanism:
"copy"`, walks the **shadow copy** hashing every file to compare against the sealed signature, then
walks the **real workspace a second time** to find deletions (an absence is only visible that way
under the copy fallback): two more full-tree walks on top of the `cp -a`, the link-neutralisation
walk, and the two `snapshotStats` calls already in "open." Counting them in this repository's own
source rather than quoting an outside estimate: `cp -a` (1), `neutraliseOutboundLinks`
(`transactional-runner.ts:247`, and again inside `copySeal` when the sealer is wired) (2),
`snapshotStats` stat-only (`:251`) (3), the hashed sealed-signature walk (4), the shadow walk in
`captureEffects` (5), the real-tree deletion walk (6). Five or more full-tree operations per turn on
the copy path, all of it paid by a workload that changes zero files. That count is a property of the
code and survives the withdrawal of the split above.

### 2a. What `runner-factory.ts` actually passes (a correction)

<!-- retracted:BEGIN -->
Earlier versions of this file said, four times across this file and `docs/PERF.md`, that
`runner-factory.ts` passes no `seal` hook and that the `cp -a` copy fallback is therefore what runs
on every host.
<!-- retracted:END -->

**That was false when this lane merged, and it is false now.** `createRunner` builds

```ts
const sealer = createOverlaySealer({ shadowRoot, releaseHookWired: true });
```

at `runner-factory.ts:332` and passes **both** hooks into the runner: `seal: sealer.seal` at `:348`
and a `release:` at `:353`. The commit that armed it is an ancestor of this lane:

```bash
$ git log --oneline -S'seal: sealer.seal' -- apps/server/src/runner-factory.ts
726c100 feat(seal): arm the overlay, and refuse the host whose mount comes up read-only
$ git merge-base --is-ancestor 726c100 3f731a5 && echo "armed before the perf lane merged"
armed before the perf lane merged
```

726c100 landed at 17:13:43 and this lane's measurement commit 43ef941 at 17:41:57 the same day, so
the premise was already stale when the report was written, not merely overtaken later.

**What this does and does not change about the numbers.** The bench passes no `seal` option
(`lib.mts`'s `makeRunner`), so it measures `TransactionalRunner.copyFallback` directly. On this host
that is still the mechanism the product runs, because `createOverlaySealer`'s capability probe
returns `copy` with reason `not-linux` at `overlay-sealer.ts:407` before it tries anything, and
`seal()` then routes to `copySeal`, which is the same `cp -a`. So every figure in §2 stands **for
this Mac**, and stands as the documented fallback cost for any host the probe refuses.

What does not stand is the scope. "Every host", "including Linux", "so that mechanism is not what
ships" were claims about hosts this lane never ran on, and the 634.9x figure bounds the copy fallback
rather than the product on a host where the overlay comes up. One direction of error is worth naming:
under the wired sealer on a copy host, `neutraliseOutboundLinks` runs twice per turn (once inside
`copySeal` at `overlay-sealer.ts:504`, once unconditionally at `transactional-runner.ts:247`), so the
bench's no-seal path is if anything slightly *cheaper* than what ships on this Mac. The bench is a
lower bound on the shipped Mac cost, not an overstatement of it.

`turn-open-scaling.mts:6-7` and `:89-90` still carry the old wording in comments. That file belongs
to another lane and is named in `notDone`.

### 2b. One cell in the table above was impossible, and is withdrawn

The `turn.begin` row is not timed the way every other row is. `turn-open-scaling.mts:116` rebuilds
the wall-clock instant of `t0` after the fact:

```ts
const wallT0Ms = Date.now() - Number(t1 - t0) / 1e6; // approx: t0 in Date-epoch terms
openSamples.push(Math.max(Date.parse(rec.at) - wallT0Ms, 0));
```

`Date.now()` there is sampled at line 116, which is **after** `await runner.closeJournal()` (`:108`)
and after the journal `fs.readFile` (`:112`). So `wallT0Ms` lands later than the true `t0` by however
long that post-run work took, and line 117 subtracts it. Every open sample is biased downward by that
amount, at every size, and `Math.max(..., 0)` turns a sufficiently biased sample into a silent `0`
rather than an error.

At 30,000 files the bias is large enough to produce a number this run's own inputs forbid.
`turn.begin` is emitted at `transactional-runner.ts:264`, after the seal (`:231-233`), after
`neutraliseOutboundLinks` (`:247`) and after `snapshotStats` (`:251`), so an open duration cannot be
cheaper than one `cp -a` plus one stat-only walk of the same tree. Taking the *cheapest* observed
sample of each, which is the most generous floor the committed data supports:

| Files | floor: min `cp -a` + min `snapshotStats` | published open: min / p50 / max | |
|---|---|---|---|
| 50 | 21.35 ms | 23.38 / 23.91 / 26.64 ms | clears the floor |
| 8,886 | 1,634.31 ms | 2,104.20 / 2,208.97 / 2,652.73 ms | clears the floor |
| 30,000 | 12,841.23 ms | 9,247.70 / 9,782.27 / 9,933.19 ms | **every sample below the floor** |

Recompute it from the committed file:

```bash
$ python3 -c "
import json
rows=[json.loads(l) for l in open('apps/server/src/bench/results/turn-open-scaling.jsonl') if l.strip()]
m={(d['files'],d['component']):d for d in rows if d.get('kind')=='measure'}
for f in (50,8886,30000):
    floor=m[(f,'cp-a')]['min']+m[(f,'snapshotStats-baseline-stat-only')]['min']
    o=m[(f,'shipped-turn-open-through-turn-begin-approx')]
    print(f, round(floor,2), o['min'], o['p50'], o['max'], 'OK' if o['max']>=floor else 'IMPOSSIBLE')
"
50 21.35 23.3779296875 23.91 26.64306640625 OK
8886 1634.31 2104.197265625 2208.97 2652.72998046875 OK
30000 12841.23 9247.70263671875 9782.27 9933.1884765625 IMPOSSIBLE
```

The 30,000-file cell is **withdrawn, not corrected**. A replacement needs the estimator fixed and
that point re-run, which this pass did not do and does not have a defensible way to fake. The 50 and
8,886 cells clear their floors, but they carry the same downward bias, so they are published as
lower bounds (`>=`) and not as estimates.

**How much this argument actually establishes, and how much it does not.** Two limits on it, both
worth stating because the withdrawal is right either way and does not need to be oversold.

*The floor is a sanity bound, not a per-sample identity.* `cp -a` and `snapshotStats` were timed in
**separate loops** from the turn, against a different source and target and in a different page-cache
state, at n=3 each at this size. The `cp -a` samples at 30,000 files run 12,341.9 to 17,270.7 ms, a
spread of 4,928.8 ms, against a shortfall from the open maximum of 2,908.0 ms. A spread wider than
the gap means the floor is a bound built by borrowing one loop's cheapest sample for another loop's
work, not an arithmetic identity about a single turn. It is the right shape of check for catching a
cell that cannot be true, and it is not strong enough to compute what the true cell is, which is the
same reason the answer here is withdrawal rather than a corrected figure.

*The direction of the bias is provable; its size was never timed.* That `wallT0Ms` lands late follows
from the code alone: `Date.now()` is read at `:116`, after `await runner.closeJournal()` at `:108` and
the journal `fs.readFile` at `:112`, so the reconstructed `t0` cannot be earlier than the true one and
every sample is biased low. What is not established is magnitude. For the estimator bias to account
for the whole shortfall on its own, that post-run work would have to cost 2.9 s or more on a no-op
turn's small journal, and **this lane never timed that interval**: no committed row in
`turn-open-scaling.jsonl` measures it. So the estimator is the likeliest explanation and not a
measured one, and the honest statement is the narrow one: the published cell is below a floor its own
run supports, so it goes, and what replaced it is nothing.

`results/turn-open-scaling.jsonl` is left exactly as measured, impossible row included: deleting the
evidence for a retraction is not a correction. The estimator fix belongs to whoever owns
`turn-open-scaling.mts` and is in `notDone`; the shape of it is to sample the epoch mark **before**
the run rather than reconstructing it after (`const preRunMs = Date.now();` immediately before `t0`,
then `Date.parse(rec.at) - preRunMs`, the pattern `stage-latency.mts:166` and `concurrency-sweep.mts:76`
already use), and to drop the `Math.max(..., 0)` clamp so an impossible sample throws instead of
becoming zero.

### 2c. What this section no longer cites, and why

<!-- retracted:BEGIN -->
This section used to attribute the two refuted claims to `SCALABILITY.md` (held-out-sets,
an internal scalability branch) and an internal plan, its four-walks count to an internal scalability review,
its corpus baseline to `CORPUS.md` and `SHADOW-COMMIT.md`, its fixture shape to a `SNAPSHOT-BENCH.md`
spike, and an overlay-mount latency to that same spike. Not one of those five documents is in this
repository. The check below covers three more names this paragraph does not attribute anything to,
for three different reasons stated plainly rather than left implicit in a file list:
`OPERATING-RULES.md` and `LANE-REPORT.md` were cited elsewhere in this document, before the
correction pass, for a per-session variance caveat and for two notes about a flaky test and a
proposed fix; both citations are already gone from the live prose, the first dropped outright and
the second replaced with the real path, `docs/PERF.md`. An internal problem log
never appears anywhere else in this document, at any point in its history; it is checked here only
because it belongs to the same held-out-sets document set as the rest, not because this
section retracted a citation to it.

```bash
$ for f in SCALABILITY.md MAKSIM_PLAN.md PROBLEMS-AND-SOLUTIONS.md OPERATING-RULES.md \
           SHADOW-COMMIT.md CORPUS.md SNAPSHOT-BENCH.md LANE-REPORT.md; do
    if [ -e "$f" ] || [ -e "docs/$f" ]; then echo "EXISTS $f"; else echo "MISSING $f"; fi; done
MISSING SCALABILITY.md
MISSING MAKSIM_PLAN.md
MISSING PROBLEMS-AND-SOLUTIONS.md
MISSING OPERATING-RULES.md
MISSING SHADOW-COMMIT.md
MISSING CORPUS.md
MISSING SNAPSHOT-BENCH.md
MISSING LANE-REPORT.md
```

None of the eight is a name invented for this check; each is missing for a stated reason, verified
directly rather than assumed. Seven live in the `held-out-sets` repository, checked out beside
this one: `MAKSIM_PLAN.md`, `PROBLEMS-AND-SOLUTIONS.md`, `OPERATING-RULES.md`, and `SHADOW-COMMIT.md`
at its root, `CORPUS.md` and `SNAPSHOT-BENCH.md` under `research/spikes/`, all confirmed present on
its `main` branch (`git cat-file -e main:<path>`); `SCALABILITY.md` sits on that repository's
an internal scalability branch instead, as the first paragraph already says. `LANE-REPORT.md`
is the eighth and is not a document reference at all: it is this repository's own convention, the
filename every lane's worktree carries at its root before its report is filed under
a per-area report at merge. The performance report in this distribution, `docs/PERF.md`, is that
record,
so a reader of the merged tree checked here will never find `LANE-REPORT.md` at that path by design,
not because the content it once named stopped existing.

Every one has been restated against code or data that is in this repository, or withdrawn. The
findings lose nothing by it, because the code was always the argument: `snapshotStats` on every turn
is at `transactional-runner.ts:251`, the walk count is countable in `capture.ts` and
`transactional-runner.ts`, and the corpus rate is published in `docs/CORPUS-REPORT.md`. The one claim
that could not survive the move is the overlay-mount latency, which was carrying the escape clause on
this section's own verdict on a number a reader here cannot check. It is gone rather than restated,
and measuring it needs a Linux host running `createOverlaySealer` from this repository.
<!-- retracted:END -->

---

## 3. Concurrency sweep: 1 to 8 simultaneous turns

`concurrency-sweep.mts`. One shared `TransactionalRunner` (one journal, one shadow root, one store,
which is the shape the product itself builds: `runner-factory.ts:335-336` gives every agent on a
deployment the same `shadowRoot` and the same `journal.jsonl`), a 100-file
fixture, K independent agents (own workspace, own two fixed output paths each) firing `run()`
together via `Promise.all`, 6 batches per level.

| Concurrency | open p50/p95 | capture p50/p95 | judge p50/p95 | settle p50/p95 | total p50/p95 | commits | journal |
|---|---|---|---|---|---|---|---|
| 1 | 65 / 75.3 ms | 18.5 / 33 ms | 3 / 9.75 ms | 3 / 5.25 ms | 110.5 / 157.8 ms | 6/6 | ok, 0 gaps |
| 2 | 89 / 99.9 ms | 34 / 77.5 ms | 4 / 9.45 ms | 4 / 8.7 ms | 175 / 258.5 ms | 12/12 | ok, 0 gaps |
| 4 | 115 / 150.6 ms | 57 / 70 ms | 7 / 18 ms | 11 / 21 ms | 235.5 / 296.3 ms | 24/24 | ok, 0 gaps |
| 8 | 174.5 / 197 ms | 84.5 / 127 ms | 9.5 / 19 ms | 13 / 36.3 ms | 352 / 388.3 ms | 48/48 | ok, 0 gaps |

`results/concurrency-sweep.jsonl` (every level also carries `n`, `min`, `p99`, `max`, `mean`).

**The journal.** At every level, an independent re-verification (`verifyJournalAt`, the same
function `TransactionalRunner.verifyChain` calls, given the scratch key) reports `ok:true`, the
record count matches exactly what was written, and sequence numbers are contiguous with zero gaps,
including at concurrency 8, where 48 turns interleaving through one shared runner produced 552
records with no fork, no torn tail, no lost record. The promise-chain serialisation in `journal.ts`
(`private tail: Promise<void>`) holds under this load. This is the one place in this lane's findings
that is good news without qualification.

**Latency degrades roughly linearly with concurrency, not gracefully.** `total` p50 goes
110.5 → 175 → 235.5 → 352 ms across 1→2→4→8 concurrent turns (3.2× for an 8× increase in concurrency:
sub-linear, but real, and the `open`/`capture` stages, which are the ones item 2 shows scale with
repo size, are exactly the ones that also scale with concurrency here, because they are dominated by
`cp -a`/tree-walk I/O contending for the same disk on this 8-core machine). At larger repo sizes
(item 2) the same contention would apply to seconds-scale operations rather than tens-of-milliseconds
ones: this sweep used a 100-file fixture specifically so it would finish in seconds; the repo-size
axis and the concurrency axis have not been measured together at scale, and their combination is
likely worse than either alone (see `notDone`).

**A caveat this table needs, and the reason the growth above is an upper bound on the product's
share of it.** Not all of that contention is the product's. `concurrency-sweep.mts:71-76` builds each
agent's workspace **inside the same concurrent callback** that then times its turn: `rm(ws)`,
`fs.mkdir(ws)` and `execFileAsync("cp", ["-a", template + "/.", ws])` all run there, and only then is
`preRunMs` taken. Because all K callbacks are launched together by `Promise.all`, the first agent's
timed window can overlap up to K-1 of the harness's **own fixture copies** of a 100-file tree. At
level 8 that is seven extra concurrent `cp -a` runs competing for the same disk with the turn being
measured, and they are the bench's setup, not the product's work.

So the 110.5 to 352 ms growth is the right shape (open and capture are the stages that move, and they
are the I/O-bound ones), but it is an **upper bound** on how much of the degradation the product
itself causes at this concurrency, and the per-level figures are not clean measurements of the
product alone. Separating them means hoisting the fixture build out of the timed callback and
re-running the sweep, which needs a change to a script this lane does not own; it is in `notDone`.
The journal-integrity result in this section is unaffected, since it counts records and checks the
chain rather than timing anything.

---

## 4. Storage per turn, and the cost of a discard

`storage-and-discard.mts`. Under the shipped `mechanism: "copy"`, sealing a turn means `cp -a`-ing
the **entire workspace**, so storage per turn is the size of the whole workspace, not the size of
what the turn changed, for every turn regardless of eventual verdict (commit, discard, or review;
sealing happens before judgement).

| Files | Workspace (sum of file bytes) | Storage per turn, apparent bytes | Storage per turn, `du -sk` (actual disk blocks) | Discard teardown alone (`fs.rm`) | Discard, end to end |
|---|---|---|---|---|---|
| 50 | 3.2 KiB | 3,250 B | 200 KiB | 3.0 ms | 43.5 ms |
| 400 | 25.4 KiB | 26,000 B | 1,600 KiB | 12.5 ms | 203.3 ms |
| 8,886 | 564.1 KiB | 577,590 B | 34.7 MiB | 385.0 ms | 10,839 ms |

p50 of n=8/5/4 reps. `results/storage-and-discard.jsonl`.

**The `du -sk` column is not a rounding artifact.** At 50 files, 3.2 KiB of actual content occupies
200 KiB on disk (a **63×** inflation) because APFS allocates in fixed-size blocks per file, and
this bench's synthetic files (like most real source files) are far smaller than a block. Storage per
turn on the shipped path is driven by **file count**, not by workspace byte size, on top of already
being the whole workspace rather than the diff. A 30,000-file repo (item 2) with the same tiny-file
shape would occupy on the order of 30,000 blocks × the host's block size in shadow-copy overhead for
every single turn, committed, discarded or held, whether the turn touched one file or none.

**Discard is fast to tear down, slow to have opened.** The isolated teardown (`fs.rm` on an
already-sealed copy, exactly what `commit-protocol.ts`'s default `release()` does for the copy
mechanism) is cheap and stays cheap: 3 ms → 385 ms across 50 → 8,886 files, well under the seal cost
at the same sizes. The *end-to-end* discard cost (a real turn that writes an obvious secret,
guaranteed `discard` by the real `secret-scan` rule) is dominated entirely by the same open+capture
cost item 2 measures, not by the discard decision or the teardown itself: a wrongly-triggered
discard on a large repo costs almost exactly what a commit would have cost to get there. `discard`
does not mean "cheap"; it means "the expensive part already happened, and now it is thrown away."

---

## 5. Policy evaluation latency against rule-set size

`policy-vs-rules.mts`. `defaultPolicy` (`shadow-policy.ts`) closes over the rule set exported by
`rules/index.ts` rather than taking it as a parameter, so rule-set size cannot be varied by calling
it directly.

> **Two corrections to this paragraph, 2026-08-30.** It said `defaultPolicy` "hardcodes its rule set",
> and it does not and never did: at the commit this was written (`aad53a7`) it was already
> `import { rules } from "./rules/index.js"` and `for (const rule of rules)`, which is a module-level
> import the function closes over. The conclusion is unchanged, the rule set still cannot be varied
> through that call, but the stated reason would send a reader looking for an array that is not there.
> And the count below is dated: `rules/index.ts` held 14 rules on 2026-08-29 when this was measured
> and holds 16 today, `outbound-provenance` and `cross-effect` having been added since. The figures
> are what 14 real modules cost. Re-run the bench before quoting them as the shipped cost. The bench
therefore **reimplements** the classify-then-loop pipeline (`policy-vs-rules.mts:50-64`) over a rule
array built by concatenating the real 14 modules N times. Every rule instance is the real, unmodified
module doing its own real regex/decode/content work against a realistic 8-effect turn (a `Dockerfile`
with `curl … | sh`, a manifest with an install script, a file containing a `ghp_…`-shaped token, a
delete, an in-workspace symlink) read from real files on disk, and the timed work is those
`rule.run()` calls. But the loop around them is the bench's, not the product's, and it is **not** a
verbatim copy. Two differences, both of which can change a verdict though neither changes what is
timed here:

- **No `try`/`catch`.** `shadow-policy.ts:35-46` wraps every `rule.run` and converts a throw into a
  `policy-rule-error` hit at `review`. `policy-vs-rules.mts:58` has no such wrapper, so a throwing
  rule would abort the bench rather than be judged. No rule throws on this effect set, so the timings
  stand; a fault-injection experiment run through this loop would not.
- **The severity reduce seeds differently.** `shadow-policy.ts:53` seeds with `"review"`;
  `policy-vs-rules.mts:61` seeds with `"commit"`. The two disagree on an effect set whose every hit
  is `commit`-class: the product returns `review`, the bench returns `commit`. Every row below
  reaches `discard`, so the seed is not load-bearing for these numbers.

`docs/PERF.md` used to claim this benchmark work reimplements nothing. It does reimplement this
one loop, deliberately and for the stated reason, and that sentence is corrected there.

**What "shipped" means in the first row.** 14 is `defaultPolicy`'s rule array, and it is not the
whole judge path the product runs: `runner-factory.ts:346` builds the policy as
`withCapabilityGrantRule(capabilityGrantStoreFor(config.dataDirectory), defaultPolicy)`, so a shipped
turn is judged by the capability grant rule **and** these 14. The row is labelled for what it is.

| Rule-set size | p50 | p95 | mean | mean ms/rule | Decision |
|---|---|---|---|---|---|
| 14 (`defaultPolicy`; the product adds `withCapabilityGrantRule` on top) | 4.03 ms | 7.38 ms | 4.57 ms | 0.326 | discard (6 hits) |
| 28 (2×) | 5.45 ms | 12.71 ms | 6.69 ms | 0.239 | discard (12 hits) |
| 56 (4×) | 9.40 ms | 14.02 ms | 10.09 ms | 0.180 | discard (24 hits) |
| 112 (8×) | 21.53 ms | 146.62 ms | 36.89 ms | 0.329 | discard (48 hits) |
| 224 (16×) | 82.86 ms | 205.42 ms | 103.0 ms | 0.460 | discard (96 hits) |

n=200 per row. `results/policy-vs-rules.jsonl`. Roughly linear in rule count (as it must be: every
rule runs over every effect, unconditionally, per `shadow-policy.ts`'s own "no short-circuit" design)
with growing variance at the high end (p95 diverges from p50 sharply past 56 rules, plausibly GC
pressure from the larger per-call allocations at 200 reps × 224 rule objects, not investigated
further). At the 14 rules shipped on the day this was measured, 18 today, this cost is negligible next to
open/capture (§1); the claim that
"judging stays cheap as rules grow" is **true in isolation at the shipped rule count** and **linear,
not free, as more rules are added**: unsurprising given the explicit no-short-circuit design, but
now a number rather than an assumption, and the real bottleneck by far is still `open`/`capture`
(§1, §2), not `judge`, at any rule count measured here.

---

## What this settles, and what it does not

**Settled, with a committed number:**
- "Opening a transaction is O(1) in repo size" is **false** of the code in this worktree, on this
  host (§2). The verdict uses the directly-timed total, not the withdrawn open estimate.
- `judge` has an unbounded-in-journal-size term (`recentTouchesFor`) independent of rule count or
  repo size, not previously measured or named (§1c). It has a second unbounded term as well, in repo
  size, read from the source rather than measured: `buildPolicyContext` walks every real inode of the
  workspace on every turn (§1d).
- Storage per turn is the whole workspace, inflated further by per-file block overhead on APFS, for
  every verdict, not only commits (§4).
- The journal serialises correctly under concurrent turns up to 8-way, with zero corruption (§3).
- Policy evaluation is linear in rule count and cheap at `defaultPolicy`'s 14 (§5). The loop those
  rules were driven through is the bench's own reimplementation, differing from the product's in two
  named ways (§5), and the shipped judge path adds `withCapabilityGrantRule` on top of the 14.
- An agent whose turns each touch mostly-new paths (ordinary incremental work) hits the
  cumulative-footprint review rule by its 4th turn (§1a, committed `cumulative-footprint-demo` rows).
- The corpus cannot reach that branch at all. `replay-v2.mjs:138` gives every one of the 5,000
  scenarios an empty `recentTouches` window, and `blast-radius.ts:32` can only emit the
  `:cumulative` id when the window is what crossed the threshold, so that id is unreachable there and
  no cross-turn workload of any kind is expressed (§1a). Read as a coverage gap in the corpus, not as
  a measured firing rate: the published benign table records the deciding rule only and cannot say
  whether plain `large-blast-radius` fired.
- `createRunner` passes both a `seal` and a `release` hook (`runner-factory.ts:348,353`); on this
  Mac the sealer still resolves to `cp -a` because `overlay-sealer.ts:407` refuses a non-Linux
  host, so §2's figures are the copy-fallback cost on this host and the documented fallback cost
  elsewhere (§2a).

**Not settled here:**
- Repo-size scaling (§2) and concurrency (§3) were not measured together at large repo size; §3 used
  a 100-file fixture so it would finish in a reasonable time, and the combination is very likely
  worse than either axis alone.
- `judge`'s journal-size term (§1c) was isolated with synthetic journal data at sizes a real
  deployment reaches over months, not reproduced via real turns at that scale (running 200,000 real
  turns through the full transactional path was not attempted).
- `judge`'s repo-size term (§1d) is read from `policy-context.ts` and `capture.ts` and is **not
  measured at all**. Its existence follows from the source; its coefficient at any repo size does not.
- The concurrency figures (§3) are an upper bound on the product's share of the degradation, because
  the harness builds each agent's fixture inside its own timed concurrent callback. Separating the
  two needs the sweep re-run with the fixture build hoisted out.
- Whether plain `large-blast-radius` ever fires on a benign corpus turn is **unanswerable from this
  repository**: the published table aggregates to the deciding rule and `research/corpus/` gitignores
  the per-scenario results.
- **Withdrawn, needs a re-run this pass did not do:** the 30,000-file "through `turn.begin`" cell
  and the post-`turn.begin` split derived from it. The estimator that produced them is biased low at
  every size and impossible at 30,000 files (§2b). The 50 and 8,886 open cells stand only as lower
  bounds. The headline 634.9x verdict is unaffected: it uses the directly-timed total.
- **Not measurable from this lane:** anything about the overlay mount path. This host is a Mac, the
  probe refuses it by platform, and the Linux figure previously quoted here came from a document
  outside this repository (§2c).
- No fix is implemented in this worktree for any defect named here (per the brief, patches are
  proposed in `docs/PERF.md`, not applied to files owned elsewhere).

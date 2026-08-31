# Performance report

Branch `lane/perf`, worktree `/Users/maksimsilchenko/Developer/CodeJam-lanes/perf`. Feasibility
line (15% generic sheet): "resource usage is proportionate, the architecture holds under real-world
conditions, and the implementation is grounded rather than speculative." Everything below is
measured on the real product code, no fakes except the inner `AgentRunner` (no model, no container),
per the brief. Full write-up with every table and every caveat:
**`apps/server/src/bench/RESULTS.md`**. Raw figures: **`apps/server/src/bench/results/*.jsonl`**,
one host row + measurement rows each, machine-readable, recomputable by re-running the script named
in each JSONL's own directory.

> **Corrected 29 Aug 2026, after merge, in two passes.** The first pass: defect 1 below rested on a
> premise about `runner-factory.ts` that was already false when this lane merged, defect 4 was framed
> against a corpus figure this repository does not publish, and one measured cell in `RESULTS.md` §2
> is below its own arithmetic floor.
>
> The second pass fixed four more, all found by review of the first: defect 4's **replacement**
> warrant was also unsound (the benign rule table records the deciding rule only, so it cannot show a
> rule never fired) and is replaced by a structural argument that does hold; this report claimed the
> lane reimplements no kit file while `policy-vs-rules.mts` reimplements the policy loop; defect 2
> named one unbounded term in `judge` where the source shows two; and §3's concurrency growth was
> attributed entirely to product I/O when the harness copies its own fixtures inside the timed
> window. `RESULTS.md` §5's "14 (shipped)" label was also wrong: the product composes
> `withCapabilityGrantRule` on top of those 14.
>
> Nothing was re-measured in either pass: every figure that needed a re-run is withdrawn and marked
> withdrawn, not replaced. `apps/server/src/bench/results-claims.test.ts` (41 tests) recomputes the
> surviving figures from the committed JSONL, executes the real `blastRadiusRule` both ways, and
> checks both documents against the source they describe.

Host for every number below: Maksims-MacBook-Air.local, Apple M2, 8 GB RAM, macOS 14.6.1 (Darwin
23.6.0, arm64), APFS, Node v22.21.0. No Docker, no Colima: this whole lane needed neither.

## What I built

Six committed bench scripts under `apps/server/src/bench/`, each a standalone `.mts` file (see
"why `.mts`" below), a shared harness (`lib.mts`), and the JSONL results:

| Script | Brief item | What it measures |
|---|---|---|
| `stage-latency.mts` | 1 | capture/judge/settle p50/p95 on a 50-file and a 400-file fixture, 150 real turns each, through the real `TransactionalRunner` |
| `journal-append.mts` | 1 | `record` (one journal append) isolated with `hrtime` precision, at two payload sizes, checkpoint cost isolated too |
| `turn-open-scaling.mts` | 2 | the copy-fallback turn-open path (no `seal` hook passed; on this Mac that is the same `cp -a` the wired sealer falls back to, see `RESULTS.md` §2a) at 50/8,886/30,000 files, plus the constituent real functions (`snapshotStats`, `cp -a`) in isolation |
| `concurrency-sweep.mts` | 3 | 1/2/4/8 simultaneous turns through one shared runner (one journal, one store), per-stage percentiles, independent journal re-verification at each level |
| `storage-and-discard.mts` | 4 | shadow-copy size per turn (apparent bytes and `du -sk` disk blocks) and discard cost (isolated teardown + real end-to-end discard via secret-scan) at 50/400/8,886 files |
| `policy-vs-rules.mts` | 5 | `defaultPolicy`'s classify-then-loop pipeline reimplemented (two named differences, `RESULTS.md` §5) over the real 14 rule modules concatenated 1×/2×/4×/8×/16×, against a realistic 8-effect turn |

**Why `.mts`, not `.ts`:** `apps/server/tsconfig.json` includes only `"src/**/*.ts"`. A file ending
`.mts` does not match that glob, so these six files (and `lib.mts`) are outside both
`tsc --noEmit` and `tsc -p tsconfig.json`, and vitest's default test glob never picks them up
either (confirmed below: `npm run check` is unaffected by their presence). No kit file is
mocked or modified anywhere in this lane: every script imports the real modules
(`transactional-runner.ts`, `capture.ts`, `shadow-policy.ts`, `journal.ts`, `rules/index.ts`,
`policy-context.ts`) directly and drives them through their real public entry points, with a scripted
inner `AgentRunner` standing in for the model/container exactly the way
`transactional-runner.test.ts` already does. Every turn measured in items 1 to 4 is judged by the
real `defaultPolicy`: `lib.mts:18` imports it and `makeRunner()` hands it to the real runner.

**One exception, corrected here.** An earlier version of this paragraph said the lane reimplements
nothing. Item 5 is the exception: `policy-vs-rules.mts:50-64` reimplements the classify-then-loop
body of `defaultPolicy` rather than calling it, because that function closes over the rule set
exported by `rules/index.ts` and rule-set size cannot be varied through it. (Corrected 2026-08-30:
this said "hardcodes its 14-rule array". There is no such array. `shadow-policy.ts` imported the
registry at the commit this lane report describes, exactly as it does now, so the reason was wrong
even then. The exception itself stands. The count was 14 on the day and is 17 now.) That script is the only one that does; the other five
drive the real policy. The rules it drives are the real modules; the loop around them is
the bench's, and it differs from the product's in two ways (`policy-vs-rules.mts` has no `try`/`catch`
around `rule.run`, and seeds its severity reduce with `"commit"` where `shadow-policy.ts:53` seeds
with `"review"`). Neither difference affects the timings in `RESULTS.md` §5, which says so and says
why. The report also used to call that reproduction "verbatim"; it is not, and no longer says so.

## Commands run, with real output

```
$ export PATH="$HOME/.nvm/versions/node/v22.21.0/bin:$PATH"
$ node_modules/.bin/tsx apps/server/src/bench/stage-latency.mts
=== small-fixture: 50 files, 150 turns ===
  open     p50=26ms p95=49.55ms max=110ms n=150
  run      p50=5ms p95=21.2ms max=66ms n=150
  capture  p50=6ms p95=24.55ms max=68ms n=150
  judge    p50=2ms p95=7.1ms max=15ms n=150
  settle   p50=2ms p95=8.55ms max=22ms n=150
  total    p50=42ms p95=114.3ms max=238ms n=150
=== realistic-repo: 400 files, 150 turns ===
  open     p50=105ms p95=157.55ms max=219ms n=150
  capture  p50=44ms p95=83.55ms max=261ms n=150
  judge    p50=3.5ms p95=9ms max=24ms n=150
  settle   p50=3ms p95=7.55ms max=14ms n=150
  total    p50=189ms p95=303.2ms max=613ms n=150
=== cumulative-footprint-demo: 12 turns, 2 new paths each, small fixture ===
  turn 1-3: commit none
  turn 4-12: review large-blast-radius:cumulative
=== recentTouchesFor cost vs pre-existing journal size (isolated) ===
  1000 records (0.20 MB): p50=1.01ms p95=1.14ms
  10000 records (1.98 MB): p50=9.65ms p95=10.95ms
  50000 records (9.96 MB): p50=51.42ms p95=63.38ms
  100000 records (19.93 MB): p50=102.37ms p95=122.45ms
  200000 records (39.97 MB): p50=233.59ms p95=263.63ms

$ node_modules/.bin/tsx apps/server/src/bench/journal-append.mts
=== journal append, small-record (5 effects/record) ===
  append(no forced checkpoint)  p50=0.11ms p95=0.24ms p99=0.36ms max=0.892083ms n=2000
  checkpoint() alone            p50=0.14ms p95=0.22ms max=0.238792ms n=30
=== journal append, bounded-record (200 effects/record) ===
  append(no forced checkpoint)  p50=0.77ms p95=1.26ms p99=1.75ms max=2.791875ms n=2000
  checkpoint() alone            p50=0.21ms p95=0.29ms max=0.388792ms n=30

$ node_modules/.bin/tsx apps/server/src/bench/turn-open-scaling.mts
=== 50 files ===
  cp -a (exactly what copyFallback runs)          p50=20.8ms p95=26.62ms n=20
  TransactionalRunner.run(), shipped, no-op turn  p50=40.38ms p95=45.09ms n=15
=== 8886 files ===
  cp -a (exactly what copyFallback runs)          p50=1546.87ms p95=1632.21ms n=6
  TransactionalRunner.run(), shipped, no-op turn  p50=4557.97ms p95=5572.63ms n=5
=== 30000 files ===
  cp -a (exactly what copyFallback runs)          p50=15408.96ms p95=17084.52ms n=3
  TransactionalRunner.run(), shipped, no-op turn  p50=25639.27ms p95=26324.1ms n=3
VERDICT: NOT O(1): shipped turn-open p50 grew 634.9x from 50 to 30000 files (a 600x increase
in file count), tracking file count rather than staying flat.

$ node_modules/.bin/tsx apps/server/src/bench/concurrency-sweep.mts
=== concurrency 1 === total p50=110.5ms p95=157.75ms  journal: ok=true records=37 seqGaps=0
=== concurrency 2 === total p50=175ms   p95=258.45ms  journal: ok=true records=110 seqGaps=0
=== concurrency 4 === total p50=235.5ms p95=296.25ms  journal: ok=true records=258 seqGaps=0
=== concurrency 8 === total p50=352ms   p95=388.25ms  journal: ok=true records=552 seqGaps=0

$ node_modules/.bin/tsx apps/server/src/bench/storage-and-discard.mts
=== 50 files ===   storage/turn p50=3250B (du -sk: 204800B)  discard e2e p50=43.48ms
=== 400 files ===  storage/turn p50=26000B (du -sk: 1638400B) discard e2e p50=203.3ms
=== 8886 files ===  storage/turn p50=577590B (du -sk: 36397056B) discard e2e p50=10838.85ms

$ node_modules/.bin/tsx apps/server/src/bench/policy-vs-rules.mts
    14 rules (1x): p50=4.03ms p95=7.38ms   decision=discard hits=6
   112 rules (8x): p50=21.53ms p95=146.62ms decision=discard hits=48
   224 rules (16x): p50=82.86ms p95=205.42ms decision=discard hits=96
```

Full output (every stage, every size) is in the transcript and in the committed JSONL files; the
above is the load-bearing subset. `apps/server/src/bench/RESULTS.md` has every table in full,
every caveat, and the exact arithmetic behind each verdict.

## Check status

```
$ npm run check
...
 Test Files  39 passed (39)
      Tests  907 passed (907)
...
 Test Files  3 passed (3)
      Tests  27 passed (27)
...
✓ built in 625ms
> tsc -p tsconfig.json      (server build, exits 0)
```

**One caveat, investigated and resolved.** On the first `npm run check` run this session, one test
(`network-docker.test.ts > ... > a discarded turn is gone from the model's own view of the
conversation`, a real-Docker WAL-file test) failed once under full-suite concurrency. I ran it in
isolation (`vitest run src/network-docker.test.ts -t "..."`). It passed. I ran `npm run check`
again in full: **907/907 passed, 0 failures.** This is pre-existing flakiness in a Docker/WAL-timing
test unrelated to anything in this lane (I never touch that file, and my bench files are outside
`npm run check`'s glob entirely, confirmed above), most likely resource contention from other
lanes' concurrent work on this shared 8 GB machine. `checkGreen: true` reflects the passing full run
**as of commit 43ef941**. The correction pass added one test file
(`apps/server/src/bench/results-claims.test.ts`, 19 tests) and did not re-run the full suite, so the
907/27 counts above are history for that commit rather than a claim about the tree today.

## Defects found (measured, not asserted)

1. **"Opening a transaction is O(1) in repo size" is false of the code in this worktree, on this
   host.** Turn-open p50 grows 634.9x from 50 to 30,000 files (600x more files);
   `apps/server/src/bench/RESULTS.md` §2. That verdict uses the directly-timed total and stands.
   `snapshotStats` runs unconditionally on every turn whatever sealed the workspace
   (`transactional-runner.ts:251`), and `captureEffects` (for `mechanism: "copy"`) adds two more
   full-tree walks on top of the copy (hash the shadow, walk the real tree a second time to find
   deletions): five or more full-tree operations per turn on the copy path, all paid even by a turn
   that changes nothing.

   **Correction to what this lane originally wrote.** It said the following, which was already false
   at merge:

<!-- retracted:BEGIN -->
   > `runner-factory.ts` never passes a `seal` option, so every host runs the `cp -a` copy fallback.
<!-- retracted:END -->

   `createRunner` passes `seal: sealer.seal` (`runner-factory.ts:348`) and a `release:` hook
   (`:353`), armed in 726c100, which is an ancestor of this lane's own merge 3f731a5. The
   measurement is still the right one for this machine, because `overlay-sealer.ts:407` returns
   `copy` with reason `not-linux` before probing, so the Mac runs `cp -a` either way. What was wrong
   was the scope: "every host" and "including Linux" describe hosts this lane never ran on. Full
   working in `RESULTS.md` §2a.

2. **A second, independent unbounded-scaling defect not previously named:** `judge`
   (`buildPolicyContext` → `recentTouchesFor`, `policy-context.ts`) rereads the **entire journal
   file** on every single turn, regardless of which agent is running, with no early exit. Isolated
   measurement: 1.01 ms at 1,000 pre-existing records → 233.59 ms at 200,000 (≈linear, ≈6 μs/KB).
   200,000 committed turns is a plausible total for a modest platform running for months: at that
   point `judge` alone costs ≈234 ms p50 per turn, forever, since journal records are permanent by
   design. `RESULTS.md` §1c.

   **`judge` has a second unbounded term, and this report originally named only the first.**
   `policy-context.ts:238-240` loops over every entry of `realInodes` testing each path against every
   protected pattern. `realInodes` is not the turn's effects: `transactional-runner.ts:293` passes
   `opened.inodes` from `snapshotStats(request.workspacePath)`, which holds one entry per file in the
   whole workspace. So `judge` also carries an O(repo size) term, on every turn, whatever the turn
   touched. Unlike the journal term this one is **read from the source and not measured**: §1's
   fixtures are 50 and 400 files, too small to separate it from the 2 to 3.5 ms the phase costs in
   total. `RESULTS.md` §1d.

3. **Storage per turn is the whole workspace, inflated further by per-file block overhead**, for
   every verdict (commit, discard, or held-for-review: sealing precedes judgement). At 50 files,
   3.2 KiB of content occupies 200 KiB on APFS (63× inflation from per-file block allocation).
   `RESULTS.md` §4.

4. **A corpus-coverage gap: the corpus cannot reach `large-blast-radius:cumulative` at all, and
   this bench trips it by turn 4.** An agent doing ordinary incremental work (new file per turn, no
   overlap) trips `rules/blast-radius.ts`'s cumulative check by its 4th turn and indefinitely after,
   reproduced as a committed measurement (`cumulative-footprint-demo` rows). The corpus contains no
   turn that can produce that id, and the reason is one line:
   `research/corpus/replay-v2.mjs:138` sets `recentTouches: []` for every scenario, benign and attack
   alike, while `blast-radius.ts:26-32` emits the `:cumulative` id only when the recent-touch window
   is what crossed the threshold. With an empty window that branch is unreachable. The gap is wider
   than one rule: with no recent-touch window anywhere, the harness cannot express **any** cross-turn
   workload, which is also why `a42-salami-slice-blast-radius` sits in the miss list at
   `docs/CORPUS-REPORT.md:75`. `RESULTS.md` §1a.

   **Two corrections to how this item was argued.** First, it was originally framed as a contrast
   with a corpus review-rate figure of one human ask every sixty-odd turns. That figure appears
   nowhere in this repository outside this lane's own two documents, and the rate this repository
   does publish (890 of 5005 benign turns are held for a human, 17.8%, roughly one ask every six
   turns) is consistent with
   review by the 4th turn rather than contradicted by it; the contrast is withdrawn. That one figure
   is kept current rather than pinned, and deliberately: the clause is present tense about what the
   repository publishes now, not about what was true at this lane's base commit, and
   `bench/results-claims.test.ts` asserts that every bench document quoting a benign rate quotes the
   one `docs/CORPUS-REPORT.md` publishes today. It read 902 of 5000, then 863 of 5000, and the
   denominator moved to 5005 on 31 August 2026 when the outbound family was added to the corpus.
   The 863 reading had already fallen behind the report's 890 before that, so this clause was
   failing its own gate for a while: kept current is only true if something re-reads it. Everything
   else on this page stays at the commit it was cut at. Second, the
   replacement argument rested on `docs/CORPUS-REPORT.md`'s benign rule table summing to exactly
   1207, the held count that report carried when this was written, with blast radius absent. That
   table cannot carry it: it records the **deciding rule** only (`shadow-policy.ts:55`, first hit at
   the worst severity in registration order) and `blastRadiusRule` is registered last of the
   registry, eighteen rules today and fourteen when this paragraph was written, so a benign turn
   where it fired beside an
   earlier review-class rule is counted under that rule. Absence from the table proves "never the
   deciding rule", not "never fired", and nothing committed here separates the two. The structural
   argument above replaces it and is stronger.

Items 1 and 3 put numbers on scaling cracks that were already suspected. Items 2 and 4 are not
named anywhere else in this repository. Every claim above is now stated against code or data a reader
can open from this checkout. The documents this lane originally cited for the refuted claims are no
longer relied on, because none of them is in this repository:

<!-- retracted:BEGIN -->
> `SCALABILITY.md`, `MAKSIM_PLAN`, `PROBLEMS-AND-SOLUTIONS.md`, `SHADOW-COMMIT.md`, `CORPUS.md`,
> `SNAPSHOT-BENCH.md`, `OPERATING-RULES.md`
<!-- retracted:END -->

`RESULTS.md` §2c lists them with the check that shows they are absent.

## Proposed fix for item 1 (not applied: I do not own `transactional-runner.ts`/`capture.ts`)

Two complementary fixes, matching the two options the brief named:

**A. A stat cache, incremental via filesystem watch (the bigger win, works today, no overlay
needed).** `transactional-runner.ts:251` calls `snapshotStats(request.workspacePath)` fresh, every
turn, walking every file. Instead: keep one live `Map<relPath, signature>` per workspace root inside
the runner (or a small `WorkspaceIndex` class beside `capture.ts`), seeded once with a full walk, and
kept current afterwards by a recursive `fs.watch(workspacePath, { recursive: true })` (native on
macOS/FSEvents and Windows; needs `chokidar` or a manual recursive-watch shim on Linux, where
`recursive: true` is not yet supported by Node's `fs.watch`). `open()` then reads the current index
(O(1) relative to repo size: cost is proportional to changes since the last turn, normally a
handful of paths, not the whole tree) instead of walking. The index needs invalidation on watcher
overflow/drop events (fall back to a full walk on the rare occasion the OS coalesces or drops
events, as every watcher API can) and needs to be process-local and rebuilt from a full walk at
startup, which is an acceptable one-time cost. This does not touch the commit or capture algorithm
at all, only where the pre-turn signature map comes from, so `conflictingPaths()` and everything
downstream is unchanged.

**B. Deriving the baseline from the seal, on a host where the overlay actually mounts.** The sealer
is already wired (`runner-factory.ts:348`); what is missing on this machine is a Linux host, since
`overlay-sealer.ts:407` refuses a non-Linux platform. Under a real overlay mount, the real workspace
is the read-only lower layer for the whole life of the mount, so nothing can write through it while
a turn holds it open: the only conflict window is between one turn's `release()` and the next
turn's `open()` on the *same* workspace, not the whole duration of the turn. That window can be
answered far more cheaply than a full walk: record the real workspace root's own mtime (or an
`fs.watch` event count, per option A) at release, and skip the baseline walk entirely when nothing
fired between release and the next open. This is weaker than option A on its own (a single
directory's mtime does not reflect a nested file being modified in place without touching its parent
directory's entry: `mtime` updates on create/rename/delete of direct children, not on writes to
existing files further down the tree), so B should be read as "cuts the common case to near-zero once
overlay ships," not as a complete replacement for A's per-file tracking.

**Recommendation for whichever lane owns this file:** ship A first: it works under the shipped
`cp -a` mechanism today, needs no overlay work, and is the one that actually moves the number
measured in `RESULTS.md` §2. B is a nice-to-have once overlay lands and should not block on it.

## What is not done, and why

- **No fix implemented in the product.** This lane measures; the patch above is a proposal for
  whichever lane owns `transactional-runner.ts`/`capture.ts` (not named in my brief, so not touched
  here).
- **One measured cell is withdrawn, not corrected.** The 30,000-file "through `turn.begin`" figure
  and the post-`turn.begin` split derived from it came from an estimator that reconstructs `t0` after
  the run and is biased low at every size (`turn-open-scaling.mts:116`). At 30,000 files the result
  is below the arithmetic floor set by the run's own `cp -a` and `snapshotStats` samples, so it is
  impossible. Fixing the estimator and re-running that point is the only honest replacement, and this
  pass did not do it. `RESULTS.md` §2b carries the recomputation. The 634.9× headline is unaffected:
  it uses the directly-timed total, not the estimate.
- **The overlay mount path is unmeasured by this lane and now uncited.** It needs a Linux host. The
  2 to 6 ms figure this report used to quote for it came from a document outside this repository and
  has been removed rather than restated.
- **Repo-size scaling and concurrency were not measured together at large repo size.** The
  concurrency sweep (§3) deliberately used a 100-file fixture so 4 levels × 6 batches finished in
  seconds; combining both axes (e.g., 8 concurrent turns each against an 8,886-file workspace) would
  very plausibly show worse-than-either-alone contention on this 8-core/8 GB machine, and is a
  natural next measurement for whoever picks this up.
- **The concurrency figures are an upper bound on the product's share of the degradation, not a
  clean measurement of it.** `concurrency-sweep.mts:71-76` builds each agent's workspace inside the
  same concurrent callback that then times its turn (`rm`, `mkdir`, `cp -a` of the fixture, and only
  then `preRunMs`), so at level 8 the first agent's timed window can overlap up to seven of the
  harness's own fixture copies. The stage shapes hold and the journal-integrity result is unaffected,
  but separating harness I/O from product I/O needs the fixture build hoisted out of the timed
  callback and the sweep re-run, which this pass did not do. `RESULTS.md` §3 carries the caveat.
- **`judge`'s repo-size term is argued from source, not measured.** Its existence follows from
  `policy-context.ts:238-240` and `capture.ts:144`; its coefficient at any repo size is unmeasured
  here, and there is no judge-vs-repo-size bench in this lane.
- **Whether plain `large-blast-radius` ever fires on a benign corpus turn is unanswerable from this
  repository.** `docs/CORPUS-REPORT.md` aggregates to the deciding rule, and `research/corpus/`
  gitignores the per-scenario results, so no committed artefact here distinguishes "did not fire"
  from "fired and was outranked". Only the `:cumulative` variant is settled, and structurally.
- **`judge`'s journal-size scaling (finding 2) was isolated with synthetic journal data**, not
  reproduced by actually running 200,000 real turns through the full transactional path end to end
  (that would take on the order of hours on this machine given the per-turn costs measured
  elsewhere in this report). The isolated measurement calls the real, unmodified, exported
  `recentTouchesFor` function directly, so the number is real; only the "grown from real turns"
  provenance is synthetic.
- **The stat-cache fix (A) above is a proposal, not a prototype.** I did not build or time a
  prototype of it; the ~O(1)-relative-to-repo-size claim for it follows from the shape of the fix
  (read an already-current index instead of walking) rather than from a measurement.

## For other lanes

- **Whoever owns `transactional-runner.ts`/`capture.ts`** (not named in my brief, since I did not touch
  either file): the two fixes above, and the two new defects (journal-size scaling in `judge`,
  storage-per-turn block inflation) are candidates for the build queue.
- **Whoever owns `apps/server/src/bench/turn-open-scaling.mts`**: two things in that file need a
  patch this pass could not make. Its header comment (`:2-11`) and the comment at `:89-90` still
  describe `runner-factory.ts` as passing no seal hook, which is false (`RESULTS.md` §2a). And the
  open estimator at `:116` needs
  to sample the epoch mark before the run rather than reconstructing it after, with the
  `Math.max(..., 0)` clamp dropped so an impossible sample throws. Then the 30,000-file point can be
  re-run and the withdrawn cell replaced.
- **Whoever owns `research/corpus/`**: `replay-v2.mjs:138` hands every scenario an empty
  `recentTouches` window, so no rule's cross-turn branch is exercised anywhere in the 5,000. That is
  a harness limit, not a policy result, and it is the single change that would let the corpus present
  a salami-slice attack to the rule written to catch it. Until it changes, no coverage number from
  that corpus should be read as covering cross-turn behaviour.
- **Whoever owns the rules/policy lane(s)** (`policy-a1`, `policy-a2` per the branch list): the
  coverage gap (§1a / defect 4) is worth a decision. Either the corpus needs benign turns that write
  new paths across a sequence of turns with a real window, or the rule needs a complementary "same
  agent, steady progress" exemption, or this is accepted as intended and said so in
  `docs/CORPUS-REPORT.md` beside the 23.5% figure. Two earlier framings of this request are void: one
  asked another lane to add a caveat beside a review-rate figure no document in this repository
  quotes, and one asserted a firing rate the published table cannot establish.
- **Whoever writes the Devpost/README feasibility section:** `RESULTS.md`'s "What this settles, and
  what it does not" section (bottom of the file) is written to be quotable directly.

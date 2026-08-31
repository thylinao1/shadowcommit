# Mutation testing of the policy against the corpus

The 23.4 percent mutation score has been quoted in briefs and verdicts for two days while the
harness that produced it existed on one machine and in no repository. Three separate handoffs sent
three people to read `MUTATION-REPORT.txt`, and none of them could open it. This directory is that
harness, its output, and the caveats that belong next to the number.

## What it does

A mutant is a one-file text substitution inside a copy of `apps/server/dist`. The whole corpus is
replayed against the mutated policy and the verdicts are compared to a baseline. A mutant is
**killed** if any scenario decides differently and **survives** if all 8,190 return exactly what they
returned before.

A survivor means the evaluation cannot tell two different policies apart. It is a statement about the
corpus at least as much as about the rules, which is why the report says so at the top.

Mutating built JS rather than TypeScript is what makes this affordable: no rebuild per mutant, and
the replay harness already accepts `--policy <any-dist>/shadow-policy.js`.

`gen-mutants.mjs` excludes anything landing in a comment or a string literal. That is not a detail.
The rule modules here are heavily commented, several are more prose than code, and a mutation inside
a comment cannot change a verdict, so it survives every time. A survivor count polluted with those
measures comment density rather than coverage.

## Running it

The three scripts take every path as an argument and hardcode none, so they run anywhere:

    node research/mutation/gen-mutants.mjs apps/server/dist /tmp/mutants.json --max 4000
    node research/mutation/mutation-worker.mjs /tmp/mutants.json <baseline.json> <shard> <shards> <workdir> <out.jsonl>
    node research/mutation/mutation-report.mjs <outdir>

The baseline comes from one clean replay:

    node research/corpus/replay-v2.mjs --policy apps/server/dist/shadow-policy.js --out baseline/results.jsonl

`job2-mutation.sbatch` and `job2b-mutation-main.sbatch` are the SLURM wrappers that shard it across
24 workers on the NUS SoC cluster. Those two are the only cluster-specific files here, and the paths
inside them are the only absolute ones.

## The number, and three things that have to be said with it

> **THE RUN IS COMPLETE, 31 August 2026.** Job 777585 graded the 151 that were never run, so there is
> now a whole-run figure for the first time. Full report at
> `research/mutation/MUTATION-REPORT-v2-complete.txt`.
>
>     mutants graded   1082
>     killed            248
>     SURVIVED          834
>     mutation score   22.9%
>
> The number barely moved from the partial 23.4 percent, which is worth saying plainly: the 151 that
> were missing were four worker slices spread across every module, not a biased tail, so completing
> the run confirmed the partial figure rather than correcting it. That is a better outcome than a
> swing would have been, and it is the first time the figure can be quoted without a caveat about
> the denominator.
>
> **Five mutants never terminate.** They are recorded as `killed, by: "timeout"` rather than as
> survivors, because a policy that stops answering is one the evaluation told apart from the
> baseline. Counted separately so nobody can hide them inside the verdict kills. There were more
> than the four that blocked workers (the count the correction below establishes): a blocked worker
> only ever reaches ITS first hanging mutant, so the fifth was invisible until the slices were
> re-run with a timeout. The committed report does not break out the timeout split, so the five is
> this page's claim from the run, not a figure `MUTATION-REPORT-v2-complete.txt` recomputes.
>
> Worst modules unchanged in shape: `cross-effect.js` 22 killed and 445 survived, 5 percent, which is
> 53 percent of every survivor in the run. `platform-secrets.js` 7 percent, `normalise.js` and
> `outbound-provenance.js` 0 percent on small counts. Best above a single mutant:
> `protected-identity.js` 86 percent (6 of 7); `symlink-escape.js`, `dependency-tree.js` and
> `instruction-file.js` score 100 percent on one mutant each.
> The corpus cannot see cross-effect composition, and that one module dominates the whole figure.

**The figure quoted for two days was the partial one: 218 killed of 930 graded, 23.4 percent over
86 percent of the run.** The run is now complete at 248 of 1082, and the completed figure above is
the one to quote; the partial one stays here only so the correction is on the record.

> **Correction, 31 August 2026. The cause below is wrong, and it was wrong twice.** This paragraph
> used to read that job 772797 hit the three hour wall clock of the `normal` partition. That is what
> the record said, it is what the v2 job's own header said when it was written, and it is not what
> happened.
>
> v2 ran on `long` with a 24 hour limit, precisely to remove the wall clock as a cause. It stalled at
> 931 of 1,082 with **the same 151 ungraded**, after seven hours, with nineteen hours left on the
> clock. A wall clock does not explain a run that stops with a third of its time unused.
>
> The cause is that three mutants make the policy stop terminating. `gen-mutants.mjs` produces an
> off-by-one-down mutation that rewrites a loop increment, so
> `for (let index = 0; index < folded.length; index += 1)` becomes `index += 0`, in
> `rules/secret-scan.js` at offset 5264, `rules/trojan-source.js` at 3612 and `rules/net-to-exec.js`
> at 5350. `mutation-worker.mjs` called `spawnSync` with no `timeout`, so the worker waited. Four of
> the 24 workers were still holding a live `replay-v2.mjs` child after seven hours, each on a single
> mutant, while the other twenty had finished and written "finished" to their logs. `squeue` reported
> the job RUNNING the whole time, and the reporter subshell kept rewriting MUTATION-REPORT.txt every
> two minutes, so from outside it looked like a long run rather than a stalled one.
>
> The arithmetic settles it. The four blocked workers had 32, 38, 45 and 36 mutants left in their
> slices. That is 151, which is exactly the number ungraded, in both runs.
>
> `mutation-worker.mjs` now passes `MUTATION_TIMEOUT_MS`, default 600000, roughly six times the
> slowest real replay observed under 24-way contention. A replay that exceeds it is recorded as
> `killed, by: "timeout"`, counted separately from verdict kills and from crash kills, and **never as
> survived**: a survivor is a mutant the corpus could not distinguish, and this one it distinguished
> in the most obvious way available.
>
> The lesson is not about SLURM. A batch job that reports RUNNING while doing nothing looks identical
> to one that is working, and the only thing that told them apart was reading the per-worker logs and
> the process table on the compute node. Checking `squeue` twice and seeing the same mutant count is
> not evidence of progress, and neither is a report file whose mtime keeps moving.

**The 930-mutant partial run graded `08a6c37`, which is no longer what we ship.** Between that
commit and today, main moved through the cross-effect distance fix, the Unicode fold, the
net-to-exec precision work and the protected-identity tests, and the corpus miss rate moved 4.71 to
3.64 across those (the 3.70 reading is retired; see `research/corpus-v2/TWINS-REPORT.md`). Some of
that run's survivors are edits to code that no longer exists: several quote `"40" -> "41"` in
`cross-effect.js`, whose `CROSS_DISTANCE` is 4 today. The complete run grades current main
(`cluster/job2b-mutation-main.sbatch` is that rerun).

**One rule dominates it, and that rule is one the corpus is blind to.**

    cross-effect.js         22 killed, 445 survived      5%     467 of 1082 graded, 43% of the run
    everything else        226 killed, 389 survived     37%
    overall                248 killed, 834 survived     22.9%

`cross-effect` decides 0 of 8,190 corpus rows, measured separately, because the corpus contains no
pair-shaped attack. Its mutants cannot be killed by scenarios that never reach it. So the headline is
largely a restatement of a corpus gap we had already found from the other direction, and the honest
reading is 37 percent for the rules the corpus can actually exercise, with cross-effect uncounted
until the corpus can see it.

**And 37 is itself a floor, not the answer.** `PHASE0-EQUIVALENT-SPLIT.md` classifies the partial
run's 339 non-cross-effect survivors (the complete run has 389; the 50 added by the final slices are
not yet classified) and removes the ones no input could ever kill. Read the two pages together
or neither of them means what it says:

    199/538 = 37.0%   floor, nothing removed but cross-effect
    199/414 = 48.1%   the 36 classifications that appeal to the corpus or to realism put back as holes
    199/378 = 52.6%   the Phase 0 figure, all 160 equivalents removed
    199/369 = 53.9%   also removing the 9 uncertain

**48 to 53 percent is what to publish, with 37 as the floor.** The spread has a cause worth stating:
an equivalent mutant cannot be killed by ANY input, but 36 of the 160 calls rest on what is realistic
rather than on what is possible, and most of those are `regex-drop-word-boundary`, a kind this same
run scored at 1 killed of 125. Calling those equivalent because no realistic input distinguishes them
uses the corpus blind spot twice: once when the mutant survives, and again as the reason it did not
count. A range with its cause named survives a judge asking how the equivalents were decided; 53 with
an audit rate of 2.4 percent behind it does not.

## The sharpest thing in the report, which is not the headline

By mutation kind:

    regex-widen                    0 killed, 56 survived     0%
    regex-drop-word-boundary       1 killed, 124 survived     1%
    negate-condition             102 killed, 76 survived     57%

Widening a rule's regex, or dropping a word boundary, makes it match MORE. That is a precision
change: more turns stopped that should not have been. 181 such mutants were applied and 180 survived,
meaning the corpus almost never contains the near-miss text that a loosened rule would wrongly catch.

Negating a condition, which changes what the rule does structurally, is caught more than half the
time. So the corpus is far better at noticing a rule that stops working than a rule that starts
over-firing, and the benign half is where that asymmetry lives.

## Status

The complete run has landed. Job 774997 on the `long` partition stalled at 931 of 1,082 on the
hanging mutants described above; job 777585 graded the remaining 151. The committed artifact is
`MUTATION-REPORT-v2-complete.txt`: 248 of 1082 = 22.9 percent raw, 48 to 53 percent adjusted per
the equivalent-mutant split above, with 37 as the floor. The run directory (`02-mutation-v2`, with
`graded-revision.txt` recording the graded commit) lives on the cluster and is not committed here.

# Honest intervals: what 8,190 rows are actually worth

> **Dated note, 1 September 2026.** Every figure on this page is the 2026-08-31 run named below, and
> it stays that way on purpose. The corpus has since gained a fifteenth generator family,
> `outbound-held-content`, taking it to 8,285 rows and 3,251 policy-decidable attacks, and a fresh run
> of the one command at the top reports a design effect of 11.0x and 296 effective observations
> against the 10.9x and the nominal 3,161 recorded here.
>
> Nothing below has been retagged with those numbers. The design effect, the effective count and every
> interval on this page were computed by clustering on the fourteen families this corpus had, and
> section 3's argument in particular depends on the structure having held constant across the three
> measurements it compares. Rewriting the denominator while leaving that arithmetic would attach a new
> corpus to an old spread, which is the failure this page exists to warn about. Re-run the command to
> regenerate it.

`research/METRICS.md` limitation 8 and `research/LEAKAGE-PROOF.md` section 5 both record the same
defect and then publish the broken number anyway. This page fixes it. Every figure below comes from
one command:

```
node research/corpus/cluster-intervals.mjs
```

It takes about half a second, writes only to stdout, and takes `--json PATH` to dump every figure.
Run on 2026-08-31 against `research/corpus/results/results.jsonl`, sha256
`6ac9a069058c8db58376c0f0e4ae9b2749a4c1b8ee710e52a20ab9a05e519809`, 8,190 rows, graded by policy
`78504c385332146e2bb3196f1d75be439f494a0e27ac74c782a457ff976c92d4` at the time this page was written.

**The policy digest has since moved and the results file has not.** The current build is
`99ed773c0930b591edcc9f8bd21ec5f17b365d78299050403345b99abaf4396b`, because `multi-file-delete` was
rewritten and the registry allowlist the grader used was corrected. Regraded on that build the results
file is byte-identical, the same `6ac9a069` above, 115 misses and 63 false aborts. So every interval
on this page still describes the current policy, and the fact that two different policy digests
produce the same 8,190 verdicts is worth more than the digest itself: it says both changes were
invisible to the corpus, which is the property section 6 of PROJECT.md is about. The script recounts all four
headline figures from the raw rows and exits 1 if its recount disagrees with
`results/report-metrics.json`, so nothing below can quietly describe a different run than the report
does.

## The result

**The cluster-robust intervals are wider. All three of them. This makes our headline weaker.**

| metric | cluster unit | point | naive Wilson 95% (published) | cluster bootstrap 95% | wider by | design effect | n_eff |
|---|---|---:|---|---|---:|---:|---:|
| attack miss | 14 attack families | 3.6% | [3.0, 4.3] | **[1.4, 5.5]** | 3.2x | 10.9x | 291 |
| benign false abort | 4 repositories | 1.3% | [1.0, 1.6] | **[0.4, 2.8]** | 4.0x | 18.6x | 269 |
| benign hold | 7 task templates | 17.3% | [16.2, 18.3] | **[0.5, 45.8]** | 21.6x | 585.4x | 9 |

Three things follow.

**The headline miss rate should read 3.6 percent, 95 percent interval [1.4, 5.5], on about 291
effective observations.** Not [3.0, 4.3]. The upper end of the honest interval, 5.5 percent, sits
above both earlier headlines this project argued its way down from, 4.71 percent and 5.22 percent
(`LEAKAGE-PROOF.md` header). The interval for the current build contains both of them, so the
improvement from 5.2 to 3.6 cannot be claimed as a measured improvement at 95 percent confidence.

**"About four times too narrow" is right for the benign false abort and an overstatement for the
attack miss.** `LEAKAGE-PROOF.md` section 5 says four times, measured at the earlier 4.71 percent
build where the design effect was 14.4x. At the current build the attack-side design effect is 10.9x,
so the attack interval is 3.2 times too narrow, not 4. The benign false-abort figure is the one that
is 4.0 times too narrow.

That same section calls the design effect "a property of how the corpus was BUILT rather than of how
well the policy scores." The three measured values do not support that. `LEAKAGE-PROOF.md` records
15.6x at 165 misses and 14.4x at 149, and this run measures 10.9x at 115, on a denominator that page
confirms did not change: still 14 families, still 3,161 rows, still n=1052 for
`exec-surface-enumeration`. The design effect fell by a third while the corpus structure held
constant, so it is a property of both the build and the score. It depends on how far apart the
per-family rates are, and those converged as the policy improved. `protected-path-alias` alone went
from a 17.49 percent miss rate (that page's section 6b) to 0 of 183 here.

**The benign hold rate is the worst number we publish and it currently carries no interval at all.**
That is the finding below.

## The method

A confidence interval answers a counterfactual: if we ran the experiment again, how much would the
number move? The Wilson interval answers it for one specific redraw, drawing 3,161 fresh rows from
the same 14 templates. Nobody cares about that redraw, because we can generate more of those rows on
demand and we already know roughly what they will say. The redraw a reader assumes is being priced
is a different set of attack ideas, and that is a redraw of families, not of rows.

So resample families, not rows:

1. Take the 14 attack families as they are, each with its row count and its miss count.
2. Draw 14 families with replacement from those 14.
3. Sum misses and sum rows over the draw and take the ratio. This is exactly the estimator the report
   publishes, recomputed, not a convenient stand-in for it.
4. Do that 20,000 times and take the 2.5th and 97.5th percentiles.

Seeded with mulberry32 from `--seed`, default 20260831, so the endpoints reproduce. Across seeds 1,
7, 99 and 20260830 no endpoint in the table moves by more than 0.1 of a point, so the published
endpoints are the corpus and not Monte Carlo noise.

Two cross-checks run beside it and are printed but not published.

The cluster-robust standard error by linearisation needs no resampling at all. It agrees with the
bootstrap standard error, and where it does not the gap is explained rather than hand-waved: it
carries a G/(G-1) small-cluster correction the plain bootstrap standard deviation does not, so on the
benign side, where the clusters are all nearly the same size, it runs larger by almost exactly
sqrt(G/(G-1)). Measured: 0.78 against 0.68 at G=4, where sqrt(4/3) predicts a ratio of 1.155 and the
observed ratio is 1.147; 13.95 against 12.93 at G=7, where sqrt(7/6) predicts 1.080 and the observed
ratio is 1.079. On the attack side the cluster sizes run from 1 row to 1052, the resampled
denominator swings with them, the linearisation is only a first-order approximation to that, and the
two land on 1.10 percent together for a different reason. Two estimators built on different
assumptions landing in the same place is the point of running both.

The t(G-1) interval built from that standard error is wider than the bootstrap on all five
groupings, never narrower. Publishing the bootstrap is therefore the more favourable of the two
defensible choices, and this page says so rather than picking it silently.

### The control, which is the part that makes the width believable

Any procedure can make an interval wider. The claim here is that the width is a property of the
corpus, so the script measures what the same procedure does to data with the clustering removed: keep
the cluster sizes exactly as they are, randomly reassign which rows land in which cluster, and re-run
everything. That destroys the within-cluster correlation and changes nothing else.

With the labels shuffled, the cluster interval collapses back onto Wilson. On the attack side the
control's mean interval is [2.99, 4.34] against a published Wilson of [3.04, 4.35]. On the benign
false abort it is [1.02, 1.51] against [0.99, 1.61]. On the benign hold it is [16.50, 18.04] against
[16.24, 18.33]. The machinery does not inflate anything on its own.

Two details in that control are worth stating rather than rounding away.

The control is run 100 times, not once. A design effect computed from 4 or 14 clusters is a variance
estimate on a handful of numbers, and a single shuffle scatters from 0.23x to 4.54x by luck alone.
The first draft of this script ran one shuffle and printed 0.45x on the attack side, which reads like
the method deflating intervals rather than like the noise it is.

The control's design effect is not 1.00x and should not be. A bootstrap standard deviation over G
clusters understates the standard error by sqrt((G-1)/G), so the raw design effect carries a floor of
(G-1)/G even with every trace of correlation gone: 0.75x at 4 clusters, 0.86x at 7, 0.93x at 14. The
measured controls land at 0.79x, 0.90x and 1.13x against those three predictions. Dividing the raw
design effect by the measured control removes that floor and gives 9.6x for the attack miss, 23.5x
for the benign false abort and 651x for the benign hold. The table above reports the raw form,
because that is the form `LEAKAGE-PROOF.md` section 5 already uses and the two should be comparable.
**The published intervals do not depend on this choice at all**: the percentile endpoints are read
straight off the bootstrap distribution and never pass through a design effect.

## Metric by metric

### Attack miss rate: 3.64 percent, [1.4, 5.5]

The 3,161 policy-decidable attacks are 14 families, and one of them is a third of the denominator.

| family | n | misses | rate |
|---|---:|---:|---:|
| exec-surface-enumeration | 1052 | 61 | 5.80% |
| secret-encoding | 610 | 5 | 0.82% |
| remote-exec-idiom | 485 | 13 | 2.68% |
| content-obfuscation-secret | 200 | 20 | 10.00% |
| supply-chain-dependency | 185 | 9 | 4.86% |
| review-surface-attacks | 184 | 1 | 0.54% |
| protected-path-alias | 183 | 0 | 0.00% |
| content-obfuscation-rce | 133 | 0 | 0.00% |
| semantic-backdoor-and-sabotage | 81 | 1 | 1.23% |
| threshold-and-count-evasion | 26 | 4 | 15.38% |
| policy-short-circuit | 11 | 0 | 0.00% |
| resource-and-queue-exhaustion | 9 | 1 | 11.11% |
| exec-surface-gap | 1 | 0 | 0.00% |
| instruction-surface-persistence | 1 | 0 | 0.00% |

`exec-surface-enumeration` is 33.28 percent of the denominator at a 5.80 percent miss rate. Whether
it is drawn once, twice or not at all moves the pooled figure further than any single row ever could.
That is the entire design effect in one sentence. Family miss rates run from 0 percent to 15.38
percent, so the answer depends mostly on which families we thought to write.

```
binomial standard error, n=3161             0.33%
cluster-bootstrap standard error            1.10%
cluster-robust standard error, linearised   1.10%
design effect                               10.9x   (9.6x control-calibrated)
effective independent observations          291     (nominal 3161)

naive Wilson 95%                            [3.04%, 4.35%]
cluster bootstrap 95%, 20000 resamples      [1.36%, 5.51%]
cluster t(13) 95%                           [1.27%, 6.01%]
macro-rate bootstrap 95%                    [1.42%, 6.45%]
```

Pooled 3.64 percent and macro 3.75 percent sit a tenth of a point apart, so the choice between
weighting by row and weighting by family barely moves the point estimate. It moves the interval a
lot: weighting families equally gives [1.42, 6.45], because the small families carry the highest miss
rates.

### Benign false abort: 1.26 percent, [0.4, 2.8]

The benign corpus is a crossed design, not a nested one. Every one of 7 task templates was run
against every one of 4 repositories, 5,000 rows in 28 cells. There is no single correct cluster, so
both factors are measured and the wider is published, on the ground that a design effect this file
failed to find is not a design effect that is not there.

| cluster unit | G | design effect | cluster bootstrap 95% |
|---|---:|---:|---|
| repository | 4 | 18.6x | [0.38, 2.84] |
| task template | 7 | 17.7x | [0.22, 2.70] |
| repo by template cell | 28 | 15.2x | [0.34, 2.64] |

Both one-way clusterings give a design effect near 18x, from two different directions.

By repository, one repository carries 45 of the 63 false aborts: `starter-kit` aborts at 3.60 percent
where `click`, `cobra` and `express` abort at 0.56, 0.32 and 0.56 percent. The published 1.26 percent
is close to a measurement of how much of the corpus is `starter-kit`.

By template, three of the seven templates account for all 63: `rename` at 5.03 percent,
`refactor-across-files` at 2.25 percent, `edit-n-files` at 1.54 percent, and the other four abort
nothing at all.

The 28-cell grouping is listed for reference and should not be the published one. It is the finest of
the three and it understates the correlation, because two cells from the same repository are still
not independent of each other.

With G=4 there are only 35 distinct resamples in existence, so the percentile endpoints land on a
coarse grid. The t(3) cross-check is [0.00, 3.75], wider still.

### Benign hold rate: 17.26 percent, [0.5, 45.8]

This is the finding on this page.

| task template | n | held | rate |
|---|---:|---:|---:|
| add-dependency | 712 | 712 | 100.00% |
| rename | 716 | 124 | 17.32% |
| run-and-touch | 712 | 27 | 3.79% |
| add-test | 716 | 0 | 0.00% |
| delete-temp | 716 | 0 | 0.00% |
| edit-n-files | 716 | 0 | 0.00% |
| refactor-across-files | 712 | 0 | 0.00% |

One template of seven holds every single turn. Four hold none. The published 17.26 percent is not an
estimate with 5,000 rows behind it, and its Wilson interval of plus or minus one point is close to
meaningless. It is a weighted average of a handful of all-or-nothing template decisions, and the
weights are a choice we made when we decided how many of each template to generate. Double the
`add-dependency` count from 712 to 1,424 and the hold rate goes from 17.26 percent to 1575/5712, or
27.6 percent, with no change to the policy at all.

The design effect is 585x and the effective sample size is 9. Nine, against a nominal 5,000. That is
the right order of magnitude: the number is decided by about seven template-level facts, so it is
worth about seven to nine independent observations.

```
binomial standard error, n=5000             0.53%
cluster-bootstrap standard error           12.93%
design effect                             585.4x   (651x control-calibrated)
effective independent observations              9  (nominal 5000)

naive Wilson 95%                            [16.24%, 18.33%]
cluster bootstrap 95%, 20000 resamples      [ 0.54%, 45.78%]
cluster t(6) 95%                            [ 0.00%, 51.40%]
```

Clustered on repository instead, the design effect is only 3.4x and the interval is [15.4, 19.5]. The
hold rate barely varies by repository, 14.80 to 20.32 percent, and varies totally by template. The
gap between those two numbers, 3.4x against 585x, is the clearest statement of what the corpus can
and cannot support: it can tell you this policy's hold behaviour transfers across these four code
bases, and it cannot tell you anything about what fraction of real work gets held, because that is
set by the task mix and we chose the task mix.

**The honest way to publish the hold rate is not as a rate.** It is per template, because the
policy's behaviour is per template and is nearly deterministic: hold every dependency addition, hold
about 17 percent of renames, hold about 4 percent of run-and-touch turns, hold nothing else. Those
four statements are what we measured. `17.26 percent` compresses them into a number whose value is
mostly an artifact of the generation quotas.

## What this correction does not fix

The cluster bootstrap prices one thing: the fact that rows within a family are not independent draws.
It does not price anything else, and three larger problems remain untouched.

**Fourteen families is a small sample of clusters, and the interval knows it but cannot repair it.**
The usual guidance for a percentile cluster bootstrap is 30 or more clusters. We have 14 on the attack
side, 7 and 4 on the benign side. At 4 clusters only 35 distinct resamples exist. The script prints
that caution and the t(G-1) cross-check every time G is under 10, and on every metric the t interval
is the wider of the two. Treat the published endpoints as the optimistic end of a defensible range.

**The population being resampled is our own imagination.** Resampling families prices the question
"what if we had written a different set of attack families", drawn from the set of families we did
write. It cannot price the families nobody here thought of. `LEAKAGE-PROOF.md` section 6b already has
the measurement that speaks to that, leave-one-family-out prediction error, and it is much worse than
this interval: mean absolute error 5.04 percent, worst family 13.56 points out. Those figures are
that page's own and were taken at the earlier 4.71 percent build, not recomputed here. Whatever they
read at the current build, that measurement and not this interval is the honest bound on
generalisation to an attack class nobody here wrote.

**Nothing here touches the corpus-realism problem.** `LEAKAGE-PROOF.md` section 3c measures attack
effect sets at a median 98 bytes against benign at 658, and a single byte-count threshold separating
the two halves at 72.31 percent. A wider interval around 3.64 percent does not make 3.64 percent a
measurement of a harder problem.

**Two published intervals are still naive after this pass, and I did not fix them.**

The per-family Wilson column in `research/corpus/REPORT.md` (the table at line 47, and the same
column in `results/report-metrics.json`) has the same defect one level down. A 95 percent Wilson of
[4.5, 7.4] on `exec-surface-enumeration`'s 61 of 1052 treats 1,052 expansions of one template as
1,052 independent trials, which is the exact error this page is about. Fixing it needs a
within-family cluster label, some notion of which variant axis a row came from, and
`results.jsonl` does not carry one. It would have to come from the generator manifest. That is a
real piece of work, not a rerun of this script.

The clean-source false abort, 42 of 3874 with Wilson [0.8, 1.5], is also uncorrected. It is a
subset of the benign rows defined by a predicate over the scenario file rather than by any field in
`results.jsonl`, so this script cannot reconstruct it from its own input. Its design effect will look
like the benign false abort's, near 18x, so treat its published interval as about four times too
narrow until someone measures it.

## What should change in the published documents

I own only `research/corpus/cluster-intervals.mjs` and this page. These are recommendations for the
lead, not edits I made.

1. **`research/corpus/REPORT.md` lines 35 and 38, and the copy at `docs/CORPUS-REPORT.md` lines 35
   and 38**, are where the two Wilson pairs are actually published. Put the cluster interval beside
   the Wilson one rather than instead of it, and say which redraw each prices. The attack miss line
   should read 3.6 percent, Wilson [3, 4.3] for sampling noise within the corpus, cluster bootstrap
   [1.4, 5.5] across families.

2. **`research/METRICS.md` limitation 8** currently ends "the real intervals are wider than the
   printed ones", which is now measurable instead of asserted. It can name 3.2x on the attack miss
   and 4.0x on the benign false abort, and point here.

3. **`research/LEAKAGE-PROOF.md` section 5** carries the design effect 14.4x, the effective count
   220 and the interval [2.12, 7.96] from the earlier 4.71 percent build, with a paragraph correctly
   saying they were not recomputed. They can be now: at the current build they are 10.9x, 291 and
   [1.4, 5.5], and this script is the recomputation that paragraph says is missing. Two sentences in
   it also need changing. "Roughly four times too narrow" is 3.2 times on the attack side. And the
   claim that the design effect is a property of how the corpus was built rather than of how well the
   policy scores is contradicted by its own numbers: 15.6x, then 14.4x, now 10.9x, on a denominator
   that section says did not change.

4. **The benign hold rate needs an interval or it needs to stop being a rate.** It appears in
   `research/METRICS.md` three times as the rate 17.26 percent and on eight lines as the count 863,
   and in `results/report-metrics.json` as `benign_human_ask`, a bare count with no interval of any
   kind. It is the least defensible number in the report. Either publish [0.5, 45.8] beside it or
   publish the four per-template statements instead. My recommendation is the per-template form,
   because the interval is so wide it reads as evasion while the per-template numbers are exact and
   more useful.

5. **`research/corpus/report.mjs` should emit these into `report-metrics.json`** so the figures on
   this page are generated rather than typed, and **this page should then go into the GUARDED list in
   `research/corpus/check-figures.mjs`**. It states 115, 3161, 3.64 percent, 63, 5000 and 863, so it
   will go stale exactly the way every unguarded page in this repository already has. Until that
   happens this page carries the results sha256 in its header, and the script's own recount gate
   fails loudly if the corpus moves under it.

## Command

```
node research/corpus/cluster-intervals.mjs                      # the table and the full working
node research/corpus/cluster-intervals.mjs --quiet              # the comparison table only
node research/corpus/cluster-intervals.mjs --json out.json      # every figure, machine readable
node research/corpus/cluster-intervals.mjs --boots 100000       # more resamples, endpoints do not move
node research/corpus/cluster-intervals.mjs --seed 7             # a different draw, endpoints do not move
```

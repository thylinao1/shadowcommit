# Figure provenance audit: 14 findings across 8 documents

For session 47, who asked for this and owns the fixes. **Nothing outside `research/benchmarking/`
was modified.** No build, replay or gate was run, because `apps/server/dist` is shared mutable state.

Method: one agent per document, asked both whether every figure has an artifact behind it and
whether it agrees with the committed artifacts. Every critical and high finding then went to a
second skeptical reader instructed to assume the first was wrong and to hunt for the artifact it had
missed. 452 figures checked, 14 findings, 8 confirmed, 2 rejected by triage, 4 medium not triaged.

The two rejections are worth stating because they show the triage works. `docs/DESIGN-CASE.md`'s
rule count was rejected: the document pins itself to `f6b14bb` in its own opening line, so its 16 is
correct for the commit it names. `research/METRICS.md`'s 187 was rejected: its lead note at lines 42
to 45 already declares that the attack-containment columns do not reproduce.

---

## 1. The rule count is stale in five places, and it went stale today

`readExposureRule` was appended to `apps/server/src/rules/index.ts` at `a247627` (31 Aug 15:53),
taking the registry from 16 to 17. Five sites still carry the old count, and one document contradicts
itself three ways.

| file | line | says | should say |
|---|---:|---|---|
| README.md | 23, 110, 431 | "the 16 rules" | 17 |
| PROJECT.md | 40 | "Sixteen rules read the effect set" | Seventeen |
| PROJECT.md | 333 | "the 16-rule policy" | 17-rule |
| PROJECT.md | 313 | "Five of sixteen rules" | see note below |
| docs/ARCHITECTURE.md | 36 | diagram node "the 16 rules" | 17 |
| docs/ARCHITECTURE.md | 132 | "the other 15 rules still run" | the other 16 |
| docs/ARCHITECTURE.md | 154 | "adding a seventeenth rule" | adding an eighteenth, or drop the ordinal |

`PROJECT.md:40` is the sharpest one because the correction already exists 37 lines below it, at 77 to
78: "Counted over the seventeen: 7 can only reach `review`, 6 can only reach `discard`, and 4 can
reach either." The document states both counts.

Note on `PROJECT.md:313`. The triage reader flagged that the numerator needs checking too, not only
the denominator. `research/METRICS.md` says "Four of the fifteen shipped rules never fire" against a
table containing a `capability-grant` module that is not in the current registry, so that source is
itself superseded and "five of sixteen" matches neither. Verify the numerator before editing.

`docs/ARCHITECTURE.md:154` is worth fixing by removing the ordinal rather than incrementing it, since
it goes stale on every rule added.

---

## 2. The policy digest, RESOLVED. Read the resolution before the original finding.

**Superseded on 31 Aug by session 47's clean regrade. Do not act on this section's original text.**
`99ed773c` is the digest of the current committed state, not of the 18:15 in-flight build. I verified
it independently rather than accepting the correction: `apps/server/src` is clean against HEAD, the
last commit touching it is `db5abb4`, `results.jsonl` hashes to `6ac9a069058c8db5`, and
`report-metrics.json` records `99ed773c` with 115/3161 and 63/5000.

The part worth more than the corrected number: **the results file did not move.** It is byte
identical at `6ac9a069` across both policy digests, so two different policies produced the same 8,190
verdicts. That is direct evidence both changes were invisible to the corpus, which is the same
property section 4 is about. `CLUSTER-INTERVALS.md` now carries both digests and says so, rather than
swapping one sha for another.

What still stands: `docs/CORPUS-REPORT.md:3` and `docs/STRUCTURAL-LIMITS.md:25` cite `008df320`,
which no artifact carries, and the republish is session 47's.

The original finding, kept for the record:

## 2a. The policy digest disagrees three ways, and one of the three is a live contamination

This one needs your judgement rather than an edit, because I cannot tell which value is right.

```
docs/CORPUS-REPORT.md:3                      008df32070e95b12...
docs/STRUCTURAL-LIMITS.md:25                 008df32070e95b12...  (cites the two files below)
research/corpus/results/report-metrics.json  99ed773c0930b591...  (read at 18:4x today)
research/corpus/results/run-manifest.json    99ed773c0930b591...  policy_modules 33
the figure set you sent me as settled         80e9eb05da2c68b1...
```

**Do not write 99ed773c into the documents.** By your own message, that is the digest produced when
the POC restart at 18:15 compiled session 91's in-flight `multi-file-delete` edits into `dist`, which
is exactly why the rule-reach gate is red. So `report-metrics.json` currently stamps a policy that
exists in no commit, and any audit that treats it as truth inherits the contamination. My agents did
treat it as truth for this check, so read their conclusion as "the documents match nothing", not as
"the documents should say 99ed773c".

What is independently true regardless of which digest wins: `docs/CORPUS-REPORT.md:3` and
`docs/STRUCTURAL-LIMITS.md:25` both cite `008df320`, and no artifact in the tree carries it. The
right fix is a regrade on a clean committed state, then republish, which is yours to run.

---

## 3. Confirmed defects that are neither of the above

**`docs/DESIGN-CASE.md:326`, critical, and the most judge-facing.** The sentence reads "No rule and
no verdict depends on a read", which is the load-bearing claim of section 3.1's "hole in the middle
of the design". It was true at `f6b14bb`. It is false now: `read-exposure.ts` is in the registry and
turns the read-witness bit into a `review` verdict under a selectivity gate. The document argues
from this figure rather than restating it, so the drift breaks a claim and not just a cell. Either
rewrite the paragraph against `read-exposure.ts` or re-pin the document and say the registry has
grown since.

**`docs/STRUCTURAL-LIMITS.md:271`, critical.** "MAX_TAINT_PASSES = 16 (cross-effect.ts:104), and
passes = Math.min(models.length + 2, 16)". `a247627` replaced that with
`taintPassesFor(modelCount) = Math.min(modelCount, MAX_FILES) + 2`, roughly 62 rather than 16. The
commit message says the flat 16 cap was itself an order-dependent bypass, so the page currently
documents a retired boundary as if it were a safe one. The hop sweep beneath it needs rerunning.

**`PROJECT.md:303`, high.** "Hand-written rows 11.39% missed against generated rows 4.54%."
`research/LEAKAGE-PROOF.md` is the source and its own preamble retracts it: two of the nine
hand-written misses are `review` rather than `commit` in the current results, giving 7/79 = 8.86%.
Either recompute or carry the same caveat LEAKAGE-PROOF already carries.

**`PROJECT.md:319`, medium.** "Four low-precision rules produce about 91% of it."
`docs/STRUCTURAL-LIMITS.md` works it out twice as 925 of 1054, which is 87.76%, and "seven questions
in eight", which is 87.5%. Change to about 88%, or state 925 of 1054.

**`research/LEAKAGE-PROOF.md:27`, medium, and it is the same defect class as the 24.2 row.** The
sentence presents 1207 as an earlier reading of the held-for-a-human count, as though it moved
1207 to 902 to 863. It is not the same quantity. 1207 is `benignHumanAsks` from
`research/queue/results.json` before standing decisions, an ask-events count on the pre-merge 30 Aug
build. Two different quantities presented as one series. Either drop the aside or qualify it.

---

## 4. What this says about the gate

`check-figures.mjs` did its job: it guards eleven documents against `report-metrics.json` and no
finding here is a corpus quantity drifting inside a guarded file. Every one of the 14 is something
the gate cannot know the true value of, which is what its own source predicts: "This gate checks the
figures it knows the true value of; a fabricated denominator swap still needs a reader."

Three of the fourteen suggest a cheap mechanical extension, if you want one. A rule count read
directly from the length of the `rules/index.ts` export array would have caught seven of these
fourteen findings on the day the seventeenth rule landed, and it needs no ground truth beyond the
file itself.

The remaining classes stay human: a claim that argues from a figure (`DESIGN-CASE:326`), a constant
that moved in code (`STRUCTURAL-LIMITS:271`), a quantity restated as a different quantity
(`LEAKAGE-PROOF:27`), and a digest that no artifact carries.


---

# Part 2: the ungateable pass

A second audit ran on opus over eight documents, targeting only what no mechanical gate can check:
blind figures, intervals, mutation scores, timings, denominators, and quantities restated with the
wrong meaning. 795 figures checked. Every finding below names the command the auditor ran.

Fourteen findings landed in my own two documents and are already fixed, so they are not repeated
here. `research/OVERFIT-AND-RENAME.md` is omitted because session 47 is already acting on it, and the
0.18 blind-retention figure that audit proposed has been WITHDRAWN by this session: its derivation was
3 over 17, which takes a numerator from PR 53's round-7 arm and a denominator from PR 55's seen arm,
and its polarity-flip story rested on 14 = 17 - 3, an arithmetic coincidence rather than evidence.
What survives there is session 47's own deeper finding, that both retention figures are count ratios
across sets of different sizes and so are not retention rates at all.

The raw findings, by document, follow. Severity order within each.

```
===== research/mutation/README.md  (44 figures checked) =====

L117 [critical/retracted_value]  23.4% overall mutation score (218/930)
  QUOTE:     overall                218 killed, 712 survived     23.4%
  WHY: 23.4% is on the known-bad list; the committed figure is 22.9% raw (248 of 1082). This table sits 46 lines BELOW the block that announces "THE RUN IS COMPLETE" with 1082 graded / 248 killed / 22.9%, and its row label is the bare word "overall" with no "partial" or "superseded" marker anywhere in the 
  FIX: Recompute the table from research/mutation/MUTATION-REPORT-v2-complete.txt: cross-effect.js 22 killed, 445 survived, 5%, 467 of 1082 graded, 43% of the run; everything else 226 killed, 389 survived, 3
  CHECKED: Read research/mutation/MUTATION-REPORT-v2-complete.txt (mutants graded 1082, killed 248, SURVIVED 834, mutation score 22.9%; cross-effect.js 22/445/5%

L70 [high/internal_contradiction]  218 killed of 930 graded; "the run did not finish"
  QUOTE: **It is 218 killed of 930 graded, and the run did not finish.** "Mutants graded so far" is the
  WHY: This is a bolded, present-tense assertion that the run did not finish, standing directly under a blockquote whose first words are "THE RUN IS COMPLETE, 31 August 2026" and which reports 1082 graded and 248 killed. The same quantity, how many mutants were graded, is stated twice in the same section
  FIX: Rewrite the caveat in the past tense and against the complete run, e.g. "The partial figure quoted for two days was 218 killed of 930 graded, over 86 percent of the run. The run is now complete at 248
  CHECKED: awk 'NR==44||NR==48||NR==70' research/mutation/README.md, then head -8 research/mutation/MUTATION-REPORT-v2-complete.txt (graded 1082) against head -8

L109 [high/stale_value]  corpus miss rate 3.70 percent
  QUOTE: protected-identity tests, and the corpus miss rate moved 4.71 to 3.70 across those. Some survivors
  WHY: 3.70 percent is the retired 117/3161 reading, not the live one. research/corpus-v2/TWINS-REPORT.md:56 states it in as many words: "This report previously carried that pair as 117/3161 = 3.70 percent with 3,044 attacks contained, and that earlier reading is retired." The live micro miss rate is 115/3
  FIX: Change to "the corpus miss rate moved 4.71 to 3.64 across those" (115 of 3161, report-metrics.json headline.attack_miss). If the intent was the macro-average, say so and pair it with the macro at the 
  CHECKED: python3 -c 'import json;d=json.load(open("research/corpus/results/report-metrics.json"));print(d["headline"]["attack_miss"], d["headline"]["attack_mis

L107 [high/stale_value]  graded revision 08a6c37
  QUOTE: **It graded `08a6c37`, which is no longer what we ship.** Since then main has moved through the
  WHY: This is caveat two of the three attached to "the number", and "the number" is now the 22.9% from the complete v2 run, which graded current main, not 08a6c37. research/mutation/cluster/job2b-mutation-main.sbatch is titled "Rerun of job2 against CURRENT main rather than 08a6c37" and runs `git rev-par
  FIX: Scope the caveat to the superseded 930-mutant run: "The 930-mutant partial run graded `08a6c37`, which is no longer what we ship... The complete run grades current main; see `graded-revision.txt` in `
  CHECKED: grep -n '"40" -> "41"' on both reports: research/mutation/results-08a6c37/MUTATION-REPORT.txt line 57 has rules/cross-effect.js @3257, research/mutati

L53 [medium/internal_contradiction]  partial mutation score 23.3 percent
  QUOTE: > The number barely moved from the partial 23.3 percent, which is worth saying plainly: the 151 that
  WHY: The partial score is 23.4 percent, not 23.3. The artifact says so (research/mutation/results-08a6c37/MUTATION-REPORT.txt: "mutation score : 23.4%", 218/930 = 23.44%) and this same document says so twice more, at line 71 ("23.4 percent is a partial figure over 86 percent of the run") and in the table
  FIX: Change "the partial 23.3 percent" to "the partial 23.4 percent", matching lines 71 and 117 and the committed partial report.
  CHECKED: head -8 research/mutation/results-08a6c37/MUTATION-REPORT.txt shows 23.4%; python3 -c 'print(218/930*100, 218/931*100)' -> 23.44, 23.42, so it does no

L151 [medium/wrong_quantity]  180 precision-loosening mutants applied, 179 survived
  QUOTE: change: more turns stopped that should not have been. 180 such mutants were applied and 179 survived,
  WHY: Both numbers are off by one against the table three lines above in this same document. regex-widen is 0 killed + 56 survived = 56 mutants; regex-drop-word-boundary is 1 killed + 124 survived = 125 mutants. That is 181 applied and 180 survived, not 180 and 179. The sentence is the load-bearing one in
  FIX: Change to "181 such mutants were applied and 180 survived". If the sentence is meant to describe the complete run instead, the numbers are 215 applied and 214 survived (regex-widen 0/65, regex-drop-wo
  CHECKED: awk 'NR>=146&&NR<=151' research/mutation/README.md, then python3 -c 'print(0+56+1+124, 56+124)' -> 181 180. Table values confirmed against research/mu

L49 [medium/no_artifact]  5 timeout kills, 0 unexplained-signal kills
  QUOTE: >     killed            248        of which 5 by timeout, 0 by unexplained signal
  WHY: Neither number exists in any committed artifact, and the report this block points the reader to for verification cannot carry them. research/mutation/MUTATION-REPORT-v2-complete.txt contains the string "timeout" zero times, and research/mutation/mutation-report.mjs never reads the worker's `by` fiel
  FIX: Either commit the evidence (a worker jsonl, or a `by`-broken-out line) or make mutation-report.mjs emit the split, `out.push("killed by timeout : " + killed.filter(r=>r.by==="timeout").length)`, and
  CHECKED: grep -i -c timeout research/mutation/MUTATION-REPORT-v2-complete.txt -> 0; cat -n research/mutation/mutation-report.mjs (no reference to `by` anywhere

L62 [medium/internal_contradiction]  three blocking mutants vs four blocked workers
  QUOTE: > than the three that blocked workers: a blocked worker only ever reaches ITS first hanging mutant,
  WHY: The document's own mechanism does not admit this split. Lines 87-88 and 93 say four of the 24 workers were blocked, "each on a single mutant", and slices are disjoint (`i % 24 === w`, stated at PHASE0-EQUIVALENT-SPLIT.md:86), so four blocked workers require four distinct blocking mutants, one per w
  FIX: Reconcile the counts: if four workers blocked, name four offsets and write "more than the four that blocked workers... so the other one was invisible". If only three mutants hang, explain what held th
  CHECKED: awk 'NR>=59&&NR<=63||NR>=83&&NR<=94' research/mutation/README.md; sed -n '84,92p' research/mutation/PHASE0-EQUIVALENT-SPLIT.md for the slice rule (`i 

L161 [medium/internal_contradiction]  job 774997 / "until it lands"
  QUOTE: `02-mutation-v2` with `graded-revision.txt` recording the commit. Until it lands, the numbers here
  WHY: The Status section is the last thing a reader sees and it says the complete run has not landed and that the numbers to use are the partial ones with the partial caveats. The block at line 44 says the opposite in bold: the run is complete as of 31 August, job 777585 graded the missing 151, and the fu
  FIX: Rewrite Status to record the landed run: the v2 run in `02-mutation-v2` completed with job 777585 grading the remaining 151, the figures are 248 of 1082 = 22.9% raw and 48-53% adjusted, and the report
  CHECKED: awk 'NR>=158&&NR<=162' research/mutation/README.md against awk 'NR>=44&&NR<=46'; ls -la research/mutation/ confirms MUTATION-REPORT-v2-complete.txt is

L67 [low/unsupported_claim]  best module 86 percent
  QUOTE: > `outbound-provenance.js` 0 percent on small counts. Best: `protected-identity.js` 86 percent.
  WHY: The report this block summarises lists three modules above 86 percent: symlink-escape.js, dependency-tree.js and instruction-file.js all score 100% (1 killed, 0 survived each). The superlative "Best" is therefore contradicted by the artifact on the line above it. The sentence cannot be defended as s
  FIX: Say "Best above a single mutant: `protected-identity.js` 86 percent (6 of 7); three modules score 100 percent on one mutant each." Or apply one denominator floor consistently to both ends of the sente
  CHECKED: sed -n '13,33p' research/mutation/MUTATION-REPORT-v2-complete.txt, rules/symlink-escape.js 1/0/100%, rules/dependency-tree.js 1/0/100%, rules/instruc

===== docs/CORPUS-REPORT-BEFORE.md  (147 figures checked) =====

L54 [high/fabricated_denominator]  73 / 3887
  QUOTE: - Benign false abort on plain source edits only (the spike-P class): **73 / 3887 = 1.9%** (95% Wilson [1.5, 2.4])
  WHY: The plain-source benign slice is a property of the SCENARIOS, not of the policy: report.mjs computes it as `benign.filter(r => !scenarioTouchesSurface(scenarioFor(map, r.id)))`, which never reads a decision. The document's own header states 'Only the policy differs between the two runs' and 'the sam
  FIX: Change to '**73 / 3874 = 1.9%** (95% Wilson [1.5, 2.4])'. The numerator, percentage and interval are all correct and unchanged; only the denominator is wrong.
  CHECKED: Ran node over the repo's own helpers: `readScenariosMap('research/corpus/scenarios')` + `scenarioTouchesSurface` from research/corpus/lib/surface.mjs 

L22 [high/internal_contradiction]  the whole page's verification claim
  QUOTE: Every number below is computed by `report.mjs` from `results/results.jsonl` and mirrored in `results/report-metrics.json`; `verify-v2.mjs` recomputes 
  WHY: This is the one sentence that could make a reader mistake the page for current, and it is false today and contradicted twelve lines above it. `results/results.jsonl` and `results/report-metrics.json` hold the AFTER run (115/3161, 63/5000, generated_at 2026-08-31); nothing in research/corpus/results/
  FIX: Replace the sentence with one true for this page, e.g. 'Every number below was computed by `report.mjs` from that run's `results/results.jsonl`, which is not kept in this tree. It is a recorded measur
  CHECKED: cat research/corpus/results/report-metrics.json (attack_miss '115/3161', clean_source_false_abort '42/3874'); cat research/corpus/results/run-manifest

L135 [high/unsupported_claim]  3 of 998 = 0.30%
  QUOTE: 3 were held back: **0.30%**
  WHY: This sits under the heading 'Fourth benign source (external, held out)' and is presented as this run's benign evidence on real third-party work, but it is not a measurement of the before policy. research/corpus/report.mjs lines 309-315 emit these numbers as hardcoded string literals inside the share
  FIX: Either drop the section from the before report, or mark it explicitly as a single external measurement taken against one policy build that is reproduced verbatim in both reports and is NOT a property 
  CHECKED: sed -n '300,330p' research/corpus/report.mjs - the Spike P lines are `L.push(...)` string literals in the body shared by both labels, with no metrics 

L136 [medium/no_artifact]  4,574 patches / 998 resolved / 3 held / 243 distinct issues
  QUOTE: recomputed here because it needs a network fetch; `benign/replay-external.mjs` reproduces it and `research/spikes/SPIKE-P-HELDOUT-EXTERNAL.md` carries
  WHY: Both artifacts offered as the provenance for the only external figure on the page are absent from this repository. research/corpus/benign/ contains exactly two files, DEFECT-JSON-COMMENTS.md and gen-benign.mjs; there is no replay-external.mjs anywhere in the tree. research/spikes/ contains only SPIK
  FIX: Replace the two dead pointers with the after report's honest wording: state that the replay is measured outside this harness, is not recomputed by check.sh, and cannot be reproduced from this reposito
  CHECKED: ls research/corpus/benign/ (DEFECT-JSON-COMMENTS.md, gen-benign.mjs); ls research/spikes/ (SPIKE-D-SNAPSHOT-ARTIFACTS.md, snapshot-bench.sh); find . -

L145 [low/no_artifact]  the 29 not-policy-decidable attacks excluded from the miss rate
  QUOTE: per `research/redteam-2026-08-29/families-and-controls.json`. Counting them here would either
  WHY: This is the citation that justifies excluding 29 attacks from the denominator of the 58.5% miss rate, and the path does not exist: there is no research/redteam-2026-08-29/ directory in the tree. The file lives at research/corpus/redteam/families-and-controls.json, which is the path the after report 
  FIX: Repoint the citation to `research/corpus/redteam/families-and-controls.json`, matching report.mjs and docs/CORPUS-REPORT.md.
  CHECKED: ls -d research/redteam-2026-08-29 -> does not exist; ls research/corpus/redteam/ -> families-and-controls.json present, and python3 json.load confirms

===== research/ROUND-7-BLIND.md  (63 figures checked) =====

L8 [high/unsupported_claim]  119 attacks, authorship
  QUOTE: One author wrote 119 attacks blind to both rules and blind to round 6, then
  WHY: The page's lead statement of provenance attributes authorship of the 119 blind attacks to a single human. The artifact shows they were produced by nine parallel blinded generator runs over a nine-ENTRY GOALS array holding only SIX distinct `key` values (backdoor-logic x3, protected-governance x2) in gen-round7.mjs, so nine runs is not nine goals and must never be written as nine independent strata; the committer is not the author. Every other do
  FIX: Replace with the corrected provenance used elsewhere in the repo, e.g. "Nine blinded generator agents, nine parallel calls to one opus model across six goals, produced 119 attacks blind to both rule
  CHECKED: git -C ~/Developer/held-out-sets show f2a14200:research/corpus/held-out/round7/gen-round7.mjs (GOALS has 9 entries, 6 distinct keys; `parallel(G

L158 [medium/internal_contradiction]  roughly four times (seen-to-blind overstatement factor)
  QUOTE: what was built by roughly four times, because a judge who is shown 40 of 42 and then runs a fresh
  WHY: The same quantity, the ratio of seen-set containment to blind-set containment, is stated three times on this page with two different values. Line 10 says "lower than the seen number by a factor of about three and a half" and line 153 says "That is a gap of about three and a half times", but line 1
  FIX: Change "by roughly four times" to "by about three and a half times", matching lines 10 and 153. (The neighbouring 'roughly four times' in ROUND-6-RECONCILE.md:96 and PROJECT.md:281 needs the same corr
  CHECKED: python3: (40/42)/(15/56) = 3.5555 and (40/42)/(15/57) = 3.6190, from the counts recomputed out of round7-results-*.jsonl at f2a14200; grep -rn "three 

L89 [medium/unsupported_claim]  eight independent security reviewers
  QUOTE: Eight independent security reviewers judged all 57 blind to the policy: 53 real-miss, 4 ambiguous,
  WHY: The topic sentence still asserts the number eight and the word "independent" as fact, and the paragraph then retracts exactly that assertion four lines later: "the number eight is not recoverable from the file". I confirmed the artifact: verify7-judgements.json is 57 rows whose only keys are {id, ve
  FIX: Lead with what the artifact holds, not with the reviewer count: "All 57 baseline misses were judged blind to the policy by separate model instances: 53 real-miss, 4 ambiguous, 0 not-an-attack and 0 ju
  CHECKED: git -C ~/Developer/held-out-sets show f2a14200:research/corpus/held-out/round7/verify7-judgements.json piped to python3: 57 rows, key set == {id

L203 [low/unsupported_claim]  0 misses on three coverage goals, 1 of 13 data-exfiltration
  QUOTE: set is not rigged toward the hard classes: the policy generalises within the classes it already has
  WHY: The generalisation conclusion is drawn from per-goal zero counts that this same page has just argued carry almost no information. Line 174 states "Per-goal n is 12 to 42, so per-goal intervals are wide and only the aggregate at n = 119 and the newly-contained counts carry signal", and the section at
  FIX: Keep the supported half and scope the rest: "...so the set is not rigged toward the hard classes. These goals are three clusters, not 36 independent trials, so read them as no observed collapse in the
  CHECKED: node research/round7-goal-intervals.mjs (deff 10.7x, 11 effective observations over 6 goals); python3 Wilson: 0/12 -> [0.0, 24.25], 0/36 -> [0.0, 9.64

===== research/overhead/AUDIT.md  (116 figures checked) =====

L301 [high/internal_contradiction]  four runs of five / flipped in one
  QUOTE: **The held-versus-allowed ordering held in four runs of five and flipped in one**, so the ordering
  WHY: The document's own table 17 lines above (AUDIT.md:278-284) gives allowed GET vs HELD POST for all five runs: run 1 (0.382, 0.064), run 2 (0.590, 0.555), run 3 (0.676, 0.405), run 4 (0.305, 0.368), run 5 (0.223, 0.508). Under either reading of "the ordering" the count is wrong. If the ordering under 
  FIX: Replace with the count the table supports and drop the "not falsified" inference that rests on it. Suggested: "The held-versus-allowed ordering flipped in three runs of five relative to the published 
  CHECKED: Read AUDIT.md:276-284 with `sed -n '270,310p' research/overhead/AUDIT.md`, then recomputed the per-run sign in python3: for each of the five rows comp

L434 [medium/precision_overstated]  1.4x to 2.1x
  QUOTE: Linear from 200 files upward in both. The per-file constant is 1.4x to 2.1x the published one on the
  WHY: Computed from the table immediately above (AUDIT.md:426-431), the re-measured ms-per-file over the published ms-per-file is 0.456/0.242 = 1.884, 0.258/0.117 = 2.205, 0.188/0.142 = 1.324, 0.209/0.141 = 1.482, 0.264/0.149 = 1.772. The true range is 1.32x to 2.21x, whether or not the 50-file row is exc
  FIX: Change to "1.3x to 2.2x" (the observed 1.324x at 800 files to 2.205x at 200 files), and make the same change in the inventory row at AUDIT.md:482.
  CHECKED: Recomputed with python3 over the ten values printed in the document's own table at AUDIT.md:426-431: `[round(n/p,3) for n,p in zip([0.456,0.258,0.188,

L234 [medium/wrong_quantity]  38.6 ms attributed to OVERHEAD.md:193-196
  QUOTE: and republishes the real-context figure as 38.6 ms.
  WHY: The cited passage does not carry 38.6 ms, and it was measured on a different machine and different code. At 9600c9b, the commit this audit says it read, OVERHEAD.md:192-196 reads "...a thousand-effect turn was judged in **5,045 ms**, not 18 ms." That passage sits under OVERHEAD.md:155, "**Host for e
  FIX: Split the two facts and name both hosts: "`OVERHEAD.md:193-196` withdraws the claim on the Windows NTFS host, where the real-context figure was 5,045 ms against the stub's 18 ms. After the read-memois
  CHECKED: `git show 9600c9b:research/OVERHEAD.md | sed -n '190,200p'` (prints the 5,045 ms retraction), `| sed -n '155p'` (the Windows NTFS host line governing 

L204 [medium/unsupported_claim]  second largest term on the overlay path / largest one an overlay does 
  QUOTE: "cheap" is not. Half a second per turn on a large repository is the second largest term on the overlay path and it is the largest one an overlay does 
  WHY: Two rankings of overlay-path terms, neither measured, and they cannot both be true. The audit itself names exactly two terms that survive the overlay (AUDIT.md:177-178): `neutraliseOutboundLinks` and `snapshotStats`. Only the second has a number -- 562.5 ms, from turn-open-scaling.jsonl. `neutralise
  FIX: Drop the ranking and state only what is measured: "Half a second per turn on a large repository is the largest *measured* term the overlay does not remove. The other survivor, `neutraliseOutboundLinks
  CHECKED: `grep -rn "neutraliseOutboundLinks" --include='*.md' --include='*.jsonl' . | grep -v node_modules` -- six hits, all prose, no timing. Enumerated every

L505 [medium/stale_value]  3.7% miss, 24.1% held
  QUOTE: | `README.md:330-341` | 3.7% miss, 1.3% discard, 24.1% held | n/a, corpus figures | out of this lane's scope | not audited here |
  WHY: Both the miss rate and the held rate are superseded. research/corpus/results/report-metrics.json gives attack_miss 115/3161 = 3.6% and benign_human_ask 863 of 5000 = 17.26%; today's README.md:588-591 carries "115/3161 = 3.6%" and "863/5000 = 17.3%". The 24.1% figure is the pre-merge 1207/5000 count,
  FIX: Either pin the row explicitly -- "`README.md:330-341` at `f6b14bb`" -- or replace the values with today's: 3.6% miss, 1.3% discard, 17.3% held (research/corpus/results/report-metrics.json; README.md:5
  CHECKED: Read research/corpus/results/report-metrics.json with a python3 walk (attack_miss 115/3161, attack_miss_pct 3.6, benign_false_abort 63/5000, benign_hu

L555 [low/wrong_quantity]  674
  QUOTE:   Lines 290, 350 and 674 cite `overlay-sealer.ts:407` for the `not-linux` return. The claim is
  WHY: At f6b14bb, the commit this audit pins all its line numbers to, the three citations of `overlay-sealer.ts:407` in apps/server/src/bench/RESULTS.md are at lines 290, 350 and 663. Line 674 is a different bullet entirely -- "`judge`'s repo-size term (§1d) is read from `policy-context.ts` and `capture.t
  FIX: Change "Lines 290, 350 and 674" to "Lines 290, 350 and 663".
  CHECKED: `git show f6b14bb:apps/server/src/bench/RESULTS.md | grep -n "overlay-sealer.ts:"` -> 290, 350, 358 (:504), 663. Then `git show f6b14bb:apps/server/sr

===== research/CLUSTER-INTERVALS.md  (140 figures checked) =====

L14 [high/stale_value]  policy sha256 78504c385332146e2bb3196f1d75be439f494a0e27ac74c782a457ff
  QUOTE: `78504c385332146e2bb3196f1d75be439f494a0e27ac74c782a457ff976c92d4`. The script recounts all four
  WHY: The header sentence (lines 12-14) pins the run's provenance: results.jsonl sha 6ac9a069... graded by policy 78504c38... The results sha is correct, but the policy sha is a superseded closure. research/corpus/results/run-manifest.json -- the manifest written for this exact results file (graded 8190, 
  FIX: Replace 78504c385332146e2bb3196f1d75be439f494a0e27ac74c782a457ff976c92d4 with the policy_sha256 recorded in research/corpus/results/run-manifest.json and results/report-metrics.json for this results f
  CHECKED: python3 read of research/corpus/results/report-metrics.json (policy_sha256 99ed773c...), cat of research/corpus/results/run-manifest.json (policy_sha2

L27 [medium/internal_contradiction]  benign hold naive Wilson [16.2, 18.3] presented under the column heade
  QUOTE: | benign hold | 7 task templates | 17.3% | [16.2, 18.3] | **[0.5, 45.8]** | 21.6x | 585.4x | 9 |
  WHY: The table's column header on line 23 reads "naive Wilson 95% (published)", so every value in that column is asserted to be a currently published interval. For the two attack/false-abort rows that is true ([3, 4.3] and [1, 1.6] are in report-metrics.json and on research/corpus/REPORT.md lines 35 and 
  FIX: Retitle the column "naive Wilson 95%" and mark the benign-hold cell as not published, e.g. "[16.2, 18.3] (computed here; not published)", or add a footnote under the table stating that the hold rate i
  CHECKED: grep -rn '16\.2|18\.3|17\.26' over research/METRICS.md, research/corpus/REPORT.md, docs/CORPUS-REPORT.md and research/corpus/results/report-metrics.js

L259 [low/no_artifact]  cross-reference "LEAKAGE-PROOF.md section 6b" for the leave-one-family
  QUOTE: write. It cannot price the families nobody here thought of. `LEAKAGE-PROOF.md` section 6b already has
  WHY: research/LEAKAGE-PROOF.md has no section 6b, and never had one. Its headings are 0, 1, 2 (2a-2c), 3 (3a-3d), 4, 5, 6, 7, 8, 9; section 6 is "The rows nobody here generated" (hand-written vs generated miss rates), which is unrelated. The leave-one-family-out measurement the page cites -- mean absolut
  FIX: Change both occurrences (lines 50 and 259) of "section 6b" to "section 5", where the leave-one-family-out paragraph and the protected-path-alias 17.49 figure actually sit.
  CHECKED: grep -n '^#{1,3} ' research/LEAKAGE-PROOF.md to list every heading (no 6b; section 6 is at line 409, "The rows nobody here generated"); sed -n 340,400

L4 [low/internal_contradiction]  "Every figure below comes from one command: node research/corpus/clust
  QUOTE: defect and then publish the broken number anyway. This page fixes it. Every figure below comes from
  WHY: About fifteen figures on the page do not come from that command and cannot: 14.4x, 220 effective observations, [2.12, 7.96], 15.6x at 165 misses, 4.71 and 5.22 percent, 5.04 percent MAE, 13.56 points, 17.49 percent, 98 and 658 bytes and 72.31 percent are all read off research/LEAKAGE-PROOF.md; [4.5,
  FIX: Narrow the claim to the page's own measurements, e.g. "Every figure in the tables below comes from one command", and add "figures quoted from other pages are attributed inline and were not recomputed 
  CHECKED: Read the whole document, then traced each borrowed figure to its source: sed -n 340,400p research/LEAKAGE-PROOF.md (14.4x, 220, [2.12, 7.96], 15.6x at
```

## RESOLVED-BY-NOTE, and a framing error in this audit worth more than the findings

**`docs/CORPUS-REPORT-BEFORE.md` L22 and L54 are both RESOLVED-BY-NOTE, not open. Do not re-raise
them from this document.** Session 47 verified both before editing and neither should be changed.

L22 is not a live claim by an author. It is what `report.mjs` PRINTED on 2026-08-29, true of that run
at that moment, preserved deliberately. Editing it would falsify the record.

L54's `73 / 3887` is not fabricated. It is that run's clean-source denominator, and it differs from
the after run's 3,874 because the corpus was regenerated between the two. 73/3887 = 1.88% checks out.
It can be neither verified nor refuted from this tree because the before build was never recorded,
so the accurate word is **unverifiable**, and the page's own header already says so: "this page is a
recorded measurement rather than a reproducible one". "Fabricated" is a claim about intent the
evidence does not carry, and on a page whose whole purpose is to differ from the current run it is
the most expensive kind of overstatement, because acting on it would erase a legitimate difference.

What was real: a reader landing mid-page never sees the header, so L22 reads as a live guarantee that
`verify-v2.mjs` stands behind those numbers when `results/` holds the AFTER run. Session 47 added an
editorial note beneath it, marked as not part of the recorded run, naming the 73/3887 denominator so
a later reader does not re-raise it. Committed `bf9ac66`.

**The general lesson, and it belongs in the method rather than in one row: a finding that a page's
claim is false must first ask whether the page is SPEAKING or QUOTING.** Three kinds of text look
identical at line level:

| kind | editable? |
|---|---|
| a live claim the document makes now | yes |
| a preserved run output, true of that run at that moment | no, editing falsifies the record |
| a quoted defect the document is exhibiting on purpose | no, that is the point of the quote |

Only the first is editable. This audit's brief got that right for the guarded documents and lost it
on the one page where it matters most, precisely because the gate excludes that page. Two of the
three categories above appear on it, and a confident fix would have damaged both.

The contrast with the judge-panel README finding is exact. That one was three sites, all live claims,
all false, and fixing them was worth more than every figure defect in this document put together. Same
surface shape, opposite correct action, and the only thing separating them is whether the document is
speaking.

## Two mechanical gates these suggest

**A rule count read from the length of the `rules/index.ts` export array.** Catches seven of Part 1's
fourteen on the day a rule lands, needs no ground truth beyond the file.

**A check that private copies of production constants match their source.** A registry allowlist had
drifted to seven hosts against production's ten in eight copies across the repo. Session 47 verified
the corpus is blind to the drift in both directions by running the full 8,190 replay before and after
and getting an identical results sha, while on real data 36 of 37 `dependency-source-offlist` destroys
were hosts production allows. A constant no scenario exercises is not validated by a green corpus.

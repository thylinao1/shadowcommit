# The evaluation the corpus report does not publish

`docs/CORPUS-REPORT.md` publishes two numbers: an attack miss rate of 115/3251 and a benign
false-abort rate of 24/5005. Those are two points. This page draws the curve they sit on, gives a
single headline F score with the convention it depends on stated in the same breath, prices three
different deployments against the same data, and shows where the misses concentrate.

Everything here comes from one file and one command.

```
input   research/corpus/results/results.jsonl
sha256  64fbee589e86dfebd18694712670070cdd96e3208b8a96dd3b0af9e66762292b
rows    8190   attacks 3190   benign 5000

command  node research/overhead/measure-metrics.mjs
```

**Which run the benign figures below are, and which figures are current.** The input file above is
the replay of 2026-08-30, identified by the sha256 above rather than by its path, because several
things have happened to that path since. First, two rules, `exec-surface` and `guard-file`, were
narrowed and the corpus was replayed. Then the benign generator was fixed: a fall-through in its
`commentFor()` wrote a `#` comment into every format it did not recognise, JSON among them, so some
benign scenarios asked the policy to approve a manifest no parser would read, and the corpus was
regenerated. Neither replay left a record naming the policy it ran against.
`research/corpus/results/` is gitignored, and `results/run-manifest.json` is one file that the last
replay to finish overwrites, so it describes whatever ran most recently and not the run whose
figures a reader is holding. It has since been given a sibling for probe runs, which used to
overwrite it too, but it still carries one run rather than a history. The attack side did not move
through either change, and this page previously published 117 of 3161 as the standing attack figure
for that reason. It has moved once since, on a third change this note did not carry until now: the
round-6 security regression detectors landed and the corpus was regraded, taking the miss count from
117 to 115 and the contained count from 3044 to 3046, both over the denominator the corpus had then.
A fifth change has landed since, and it moved that denominator rather than either count: a new attack
family, `outbound-held-content`, added 90 policy-decidable attack scenarios and 5 benign ones, and
the policy already contained all 90. The miss count is therefore unchanged: 115 of 3251
policy-decidable attacks are committed now, with 3136 attacks contained. The rate improved because
the denominator grew and not because the policy detects anything it did not detect before. What the
new family does add is the first scenario in this corpus that `outbound-provenance` fires on, a rule
that had never fired on any row of any replay of this corpus until now.
The benign side moved twice through the first two changes, and it has moved a third time
since, on a fourth change: `secret-scan`'s keyword arm was moved from discard to review, because a
keyword-adjacency guess is not format-certain evidence and the rule's own docstring already said so.
Attack containment did not move with it. 91 corpus attacks moved from discard to held, and a held
turn is still contained, so what that change moved is the benign cost. `docs/CORPUS-REPORT.md`
publishes the current run: 24 of 5005 benign turns hard-discarded, and 902 held benign turns. That
is the copy a reader who clones this repository has. `research/corpus/REPORT.md` carries the same
two figures and is what gets copied over that published page, but it is the run's own output into
gitignored `research/corpus/`, so `git ls-files` does not list it and a fresh checkout does not
contain it: it is a local artifact, present only on a machine that has run the corpus. The tables
below carry 65 and 1,207 instead, the counts the earlier run measured, and every benign figure below
is that run's, the false-alarm axes and the strict F score included. Where the prose states what
the product costs today it says so and gives the current figure beside the recorded one. One thing
this note does not resolve: the attack-containment columns in sections 1, 2 and 3 do not reproduce
from the input file above either, so they are neither the current run nor a faithful record of that
one, and correcting them needs those blocks regenerated rather than a figure swapped. The two attack
blocks in section 4 were regenerated after the regrade and name the input they came from, and the
corrections made to them since, where they sit.

Every table below is a block that command prints, and section 5 of its output prints every derived
figure those tables quote. **That guarantee covers the tables and the figures derived from them. It
does not cover the note you are reading or the current-run figures the prose gives beside recorded
ones**, which come from `research/corpus/results/report-metrics.json`, either read from it or taken
as a ratio of two figures in it, and are named as current where they appear. The ratio clause is
here for one reason: the current benign hold rate, 18.02 percent, is not a field in that file, it is
902 over 5,005, and the wording before this edit covered the two counts but not the rate they make.
It does not stretch further than that. Where the prose sets the two runs' hold counts against each
other, at the end of section 4c, the earlier count is a table figure and is covered by the tables'
own guarantee, not by this clause. The promise used to be written as
covering every sentence on the page, and every correction that added a current figure falsified it,
twice in one night, which is how a promise about a document rather than about its measurements
behaves under maintenance.
The script reads that one file, writes nothing, and asserts the nine published headline counts
before it computes anything new. If the corpus is
regenerated and any of them moves, it exits non-zero rather than printing a different evaluation
under the same prose. That guard was falsified rather than assumed, against the earlier
corpus: flipping one `miss=true` row to a discard in a copy of the input produced `DRIFT: miss=true
is 116, the published report says 117.` and exit 1, while an unmodified copy at a different path
exited 0. Re-run today the same mutation prints `DRIFT: miss=true is 114, the published report
says 115.` and exit 1, and the unmodified copy still exits 0.

```
node -e '...flip one miss row...' /tmp/mutated.jsonl
RESULTS_FILE=/tmp/mutated.jsonl node research/overhead/measure-metrics.mjs   # exit 1
RESULTS_FILE=/tmp/copy.jsonl    node research/overhead/measure-metrics.mjs   # exit 0
```

---

## 1. One headline F score, and the convention it cannot be quoted without

The decision is ternary. A turn is committed, discarded, or held for a human. An F score is defined
over two classes, so any F score for this product is a claim about what a held turn counts as, and
that claim moves the number more than most changes to the policy would.

Here is the table the F score collapses.

```
intent  commit  discard  review  total
------  ------  -------  ------  -----
attack     187     2826     177   3190
benign    3728       65    1207   5000
```

Positive class is "attack". An alarm is any decision that is not `commit`. The two conventions
differ on exactly one cell, the 1,207 benign turns that were held in the earlier run this table is
from. The current run puts 902 held benign turns in that cell, so the strict F score moves with it
and the lenient one does not, which is the whole of this section's point.

```
-- all attacks (n=3190)

convention                        TP    FP   FN  precision  recall     F1
------------------------------  ----  ----  ---  ---------  ------  -----
strict (held benign = FP)       3003  1272  187      0.702   0.941  0.805
lenient (held benign = TN)      3003    65  187      0.979   0.941  0.960
automatic only (holds dropped)  2826    65  187      0.978   0.938  0.957

95% Wilson, strict precision  [68.9, 71.6]   lenient precision [97.3, 98.3]
95% Wilson, recall (same under both conventions) [93.3, 94.9]
```

The published miss rate excludes the 29 attacks that are not policy-decidable, so the same table on
that denominator, for readers comparing against `docs/CORPUS-REPORT.md`:

```
-- policy-decidable attacks only (n=3251)

convention                        TP   FP   FN  precision  recall     F1
------------------------------  ----  ---  ---  ---------  ------  -----
strict (held benign = FP)       3136  926  115      0.772   0.965  0.858
lenient (held benign = TN)      3136   24  115      0.992   0.965  0.978
automatic only (holds dropped)  2752   24  115      0.991   0.960  0.975
```

Command for both tables: `node research/overhead/measure-metrics.mjs`, section 1.

**The convention is worth 0.155 of F1.** Strict says 0.805, lenient says 0.960, on identical
verdicts over identical rows. That gap is larger than the improvement any single rule in the
registry delivers, which is the reason this page refuses to print one number.

### Which one goes on a slide

**Strict, F1 = 0.805.** Three reasons.

**And one caveat that belongs in the same breath, because this page makes the point elsewhere and
would otherwise commit the error it names.** That 0.805 is a MICRO-average: its recall is
containment over all decidable attacks, so the families with the most scenarios decide it. Weighting
the fourteen decidable families equally instead gives macro recall 0.9488 against micro 0.9529, and
the strict F1 falls from 0.809 to **0.808** on the decidable slice. That gap used to be large: at
165 misses it was macro recall 0.9027 against micro 0.9478, and F1 0.807 down to 0.790. It closed
because the misses that remain are spread evenly rather than piled into the families we generated
fewest of, which is a real result and is the argument of 4b. Section 4b makes exactly this
argument about the miss rate. It applies to the F score too, and a reader who reaches 4b and looks
back at this table should find the number already there rather than have to derive it.

1. A held turn costs a person's attention. Lenient prices that at zero, and a metric that prices
   human review at zero recommends holding everything. On this corpus that recommendation is
   available: holding every turn the policy is unsure about is exactly what the shipped
   configuration does, and in the earlier run this table is from it produced 1,384 held turns out
   of 8,190. That total is 177 attack holds plus a benign hold column that has moved twice since.
2. Strict is the convention that gets worse when we take the cheap win. Any rule that downgrades a
   discard to a review improves the lenient score and damages the strict one. A number that can be
   improved by doing less is not worth putting on a slide.
3. The gap between them is itself the finding. Reporting 0.805 and then showing 0.960 as the
   containment-only view tells a reader what the queue costs. Reporting 0.960 alone hides it.

The third row, automatic-only, answers a narrower question: how good is the part that runs with no
human in it. Dropping every held turn from both classes gives F1 = 0.957 over 3,013 attacks and
3,793 benign turns. It is the right number for "what happens overnight when nobody is watching the
queue", and it is not the headline.

---

## 2. Three deployments, three operating points, priced

A bank and a two-person startup want different answers. This section names three and prices each
against the same 8,190 rows.

### The knob that exists

There is no threshold. What exists is a set of verdict branches. Every row in the corpus carries the
one rule id that produced its winning verdict, and each rule id maps to exactly one decision, so the
rows are a partition over branches and subset arithmetic over them is exact addition.

A branch is separately configurable in the product. `exec-surface` publishes
`execution-surface-write` for its discard class and `execution-surface-review` for its review class
through `RULE_FOR = { discard: ..., review: ... }` in `apps/server/src/rules/exec-surface.ts`, and
`secret-scan` publishes `SECRET_DISCARD_RULE` and `SECRET_REVIEW_RULE` the same way. Changing one is
a table edit, not a rule deletion.

```
rule id (verdict branch)                    code              module  verdict  attacks  benign  attacks per benign
--------------------------------------  --------  ------------------  -------  -------  ------  ------------------
remote-code-execution-added                  rce         net-to-exec  discard     1373       7              196.14
secret-written-into-source                 sec-w         secret-scan  discard      785      27               29.07
dependency-added                         dep-add   dependency-change   review       33     566                0.06
execution-surface-review                  exec-r        exec-surface   review       13     480                0.03
execution-surface-write                   exec-w        exec-surface  discard      225      12               18.75
trojan-source                             trojan       trojan-source  discard      230       0                 inf
guard-file-removed                         guard          guard-file   review       14     135                0.10
protected-asset-write                     prot-w  protected-identity  discard      116      15                7.73
dependency-source-offlist                dep-off   dependency-change  discard       92       0                 inf
security-regression:*                      insec      insecure-idiom   review       69       0                 inf
secret-suspected                           sec-s         secret-scan   review        3      26                0.12
lockfile-integrity-changed              lockfile   dependency-change   review       19       0                 inf
large-blast-radius                         blast        blast-radius   review       10       0                 inf
vendored-dependency-tamper              vendored     dependency-tree   review        9       0                 inf
protected-asset-delete                    prot-d  protected-identity  discard        5       4                1.25
manifest-script-change                  manifest   dependency-change   review        4       0                 inf
capability-path-out-of-scope            cap-path    capability-grant   review        1       0                 inf
capability-symlink-target-out-of-scope  cap-link    capability-grant   review        1       0                 inf
instruction-file-change                    instr    instruction-file   review        1       0                 inf

rules in the registry that never fire on this corpus: multi-file-delete, symlink-escape, platform-secrets, outbound-provenance
branches that cost no benign turn at all (always worth enabling): 10, carrying 436 attacks
branches that trade attacks against benign turns: 9
partition check: 3003 attacks + 1272 benign alarmed = 4275, non-commit rows = 4275
```

Command: `node research/overhead/measure-metrics.mjs`, section 2a.

Ten of the nineteen firing branches cost zero benign turns on this corpus. Four of the fifteen
shipped rules never fire at all, which is a statement about the corpus and not about those rules.

The second knob is what an operator does with a held turn: queue it, auto-discard it, or
auto-commit it. Both knobs are exact post-processing of the recorded verdicts.

### The queue, branch by branch

```
rule id                                            module  held turns  of which attacks  queue signal %
--------------------------------------  -----------------  ----------  ----------------  --------------
dependency-added                        dependency-change         599                33            5.51
execution-surface-review                     exec-surface         493                13            2.64
guard-file-removed                             guard-file         149                14            9.40
security-regression:*                      insecure-idiom          69                69          100.00
secret-suspected                              secret-scan          29                 3           10.34
lockfile-integrity-changed              dependency-change          19                19          100.00
large-blast-radius                           blast-radius          10                10          100.00
vendored-dependency-tamper                dependency-tree           9                 9          100.00
manifest-script-change                  dependency-change           4                 4          100.00
capability-path-out-of-scope             capability-grant           1                 1          100.00
capability-symlink-target-out-of-scope   capability-grant           1                 1          100.00
instruction-file-change                  instruction-file           1                 1          100.00
```

Command: `node research/overhead/measure-metrics.mjs`, section 2b.

Four branches produce a queue that is mostly benign. Eight produce a queue that is entirely attacks
on this corpus. That split is what makes the middle persona possible.

### The three personas

These three are hypothetical operating points, named for readability rather than drawn from
customers anyone spoke to. What is measured is the configuration and every number attached to it:
each persona is a branch set that can be enabled or disabled, and its costs below are computed from
the corpus. The tolerances attributed to each one are framing.

**A. Aster Trust, a regulated payments backend.** An agent edits the ledger service. What it cannot
tolerate is a malicious turn landing in a branch that feeds the release train without a person
seeing it. It has a funded security on-call, so a queue is a cost it can pay.
Configuration: all nineteen branches on, held turns queued. This is the shipped default.

**B. Northwind, a 40-engineer SaaS company.** One part-time reviewer. What it cannot tolerate is a
queue nobody answers, because a queue that is mostly false alarms stops being read and a queue
that is not read holds nothing. It wants a queue small enough and true enough to stay real. How
quickly that happens in practice is not something this corpus can measure, and no number is offered
for it here. Configuration: all branches on except the four whose queue is mostly benign
(`dependency-added`, `execution-surface-review`, `guard-file-removed`, `secret-suspected`), which
downgrade to commit. The discard classes of `exec-surface` and `secret-scan` stay on, because this
is a branch edit and not a rule deletion.

**C. Kestrel, two founders and no security staff.** What it cannot tolerate is any human queue at
all, because there is no human to answer it. Configuration: all branches on, held turns
auto-committed.

```
operating point                      attacks through  benign destroyed  queue  queue signal %  per 1k: through  per 1k: destroyed  per 1k: queue
-----------------------------------  ---------------  ----------------  -----  --------------  ---------------  -----------------  -------------
A  Aster Trust (regulated bank)                  187                65   1384           12.79             22.8                7.9          169.0
B  Northwind (40-engineer SaaS)                  250                65    114          100.00             30.5                7.9           13.9
C  Kestrel (two-founder startup)                 364                65      0             n/a             44.4                7.9            0.0
D  strawman: auto-discard the queue              187              1272      0             n/a             22.8              155.3            0.0

operating point                      attacks contained %  benign destroyed %  benign held %
-----------------------------------  -------------------  ------------------  -------------
A  Aster Trust (regulated bank)                    94.14                1.30          24.14
B  Northwind (40-engineer SaaS)                    92.16                1.30           0.00
C  Kestrel (two-founder startup)                   88.59                1.30           0.00
D  strawman: auto-discard the queue                94.14               25.44           0.00
```

Command: `node research/overhead/measure-metrics.mjs`, section 2c. The per-1k columns use the corpus
mix, 38.95 percent of turns are attacks. Section 2d below re-prices them at rates a real deployment
would see.

Three things fall out of that table.

**What the bank pays for its last 63 attacks.** In the earlier run these tables are from, going from
Northwind to Aster Trust contains 63 more attacks and alarms 1,207 more benign turns: **19.2 benign
turns held per additional attack contained**, for 1.97 points of containment bought with 24.14
points of false alarm. Northwind's benign held column is zero, and on the current run the benign
half of that trade is 902 more benign turns held, 18.02 points of false alarm. (The narrowing moved
the discard column too, 65 to 63, so "only removes holds" would be wrong: it is the hold column that
carries this comparison, not the only column that moved.) The attack half is not restated here,
because the persona table above has not been recomputed against either change. That is a defensible
trade for a payments backend and an indefensible one almost anywhere else, and it is a number the
published headline does not contain.

**The startup is leaving containment on the floor.** In the earlier run, Kestrel and Northwind
destroy exactly the same 65 benign turns, and Northwind contains 114 more attacks, for a queue of
114 turns of which 114 are attacks. Blanket auto-committing the review class throws away a perfect
queue along with a noisy one. This is the one recommendation on this page that costs nothing to
adopt.

**Escalating the queue buys nothing.** Row D is the configuration a nervous reader reaches for:
destroy anything the policy will not clear. On this corpus it contains **zero** additional attacks
over row A, and it destroys every benign turn row A holds: **1,207** additional benign turns in the
earlier run this table is from. On the current run that is 902 additional benign turns destroyed.
Every attack that gets held was already contained by being held, so auto-discarding the review class
is a pure loss here.

### The same points at attack base rates a deployment would actually see

The corpus is 38.95 percent attacks by construction. Production is not. Holding the per-class rates
fixed and moving the mix:

```
operating point                      attack base rate  queue per 1k turns  of which attacks  queue signal %  attacks through per 1k turns
-----------------------------------  ----------------  ------------------  ----------------  --------------  ----------------------------
A  Aster Trust (regulated bank)                38.95%               169.0             21.61           12.79                         22.83
A  Aster Trust (regulated bank)                 5.00%               232.1              2.77            1.20                          2.93
A  Aster Trust (regulated bank)                 1.00%               239.5              0.55            0.23                          0.59
A  Aster Trust (regulated bank)                 0.10%               241.2              0.06            0.02                          0.06
B  Northwind (40-engineer SaaS)                38.95%                13.9             13.92          100.00                         30.53
B  Northwind (40-engineer SaaS)                 5.00%                 1.8              1.79          100.00                          3.92
B  Northwind (40-engineer SaaS)                 1.00%                 0.4              0.36          100.00                          0.78
B  Northwind (40-engineer SaaS)                 0.10%                 0.0              0.04          100.00                          0.08
C  Kestrel (two-founder startup)               38.95%                 0.0              0.00             n/a                         44.44
C  Kestrel (two-founder startup)                5.00%                 0.0              0.00             n/a                          5.71
C  Kestrel (two-founder startup)                1.00%                 0.0              0.00             n/a                          1.14
C  Kestrel (two-founder startup)                0.10%                 0.0              0.00             n/a                          0.11
```

Command: `node research/overhead/measure-metrics.mjs`, section 2d.

**The 12.8 percent queue signal at the shipped operating point is an artifact of the corpus mix.** At one
attack per thousand turns the same configuration produces 241.2 held turns per 1,000 with a signal
of 0.02 percent, which is one true positive per 4,000 held turns. Anyone quoting "the review queue
is 12.8 percent attacks" as a production property is quoting the corpus design.

Northwind's queue keeps its signal at every base rate because the branches feeding it have no benign
rows at all in this corpus. That is a ceiling claim about a corpus, not a guarantee: see section 5.

---

## 3. The OSCR-style curve, over the axis that actually exists

### There is no score to threshold

```
rows carrying a numeric score or confidence field: 0
fields present on a row: id, source, file, intent, family, layer, policyDecidable, expected, decision, rule, correct, miss, falseAbort, humanAsk
distinct decision values: discard, commit, review
```

Command: `node research/overhead/measure-metrics.mjs`, section 3a.

Each rule returns an ordinal verdict and the policy takes the worst with no short-circuit. Nothing
in the pipeline produces a scalar. There is no threshold to move, so there is no ROC and no
conventional OSCR curve, and inventing one would mean inventing a score the product does not have.

**So the x-axis is the enabled set of verdict branches.** Nineteen branches fire on this corpus. Ten
of them alarm zero benign turns while contributing 436 attacks, so they are held on in every point:
enabling one raises the y-axis by construction and cannot move the x-axis. That leaves nine branches
that trade, and **all 512 subsets of them are enumerated**, so the frontier below is exact within
the simulation model rather than a greedy path through it.

- **y-axis, CCR:** attack turns not auto-committed, over all 3,280 attack turns.
- **x-axis, FAR:** benign turns that did not auto-commit, over all 5,005 benign turns.

```
free set (zero benign cost, held on in every point): trojan dep-off insec lockfile blast vendored manifest cap-path cap-link instr
branch subsets enumerated: 512 (2^9; the 10 zero-benign-cost branches are held on,
  because enabling one raises CCR by construction and cannot move FAR).
points on the frontier: 25

FAR %  CCR %  benign alarmed  benign destroyed  attacks contained  branches on beyond the free set
-----  -----  --------------  ----------------  -----------------  ---------------------------------------------------------
 0.00  13.67               0                 0                436  (none)
 0.08  13.82               4                 4                441  prot-d
 0.14  56.71               7                 7               1809  rce
 0.22  56.87              11                11               1814  rce prot-d
 0.38  63.76              19                19               2034  rce exec-w
 0.46  63.92              23                23               2039  rce exec-w prot-d
 0.68  81.32              34                34               2594  rce sec-w
 0.76  81.47              38                38               2599  rce sec-w prot-d
 0.92  88.37              46                46               2819  rce sec-w exec-w
 1.00  88.53              50                50               2824  rce sec-w exec-w prot-d
 1.22  92.01              61                61               2935  rce sec-w exec-w prot-w
 1.30  92.16              65                65               2940  rce sec-w exec-w prot-w prot-d
 1.82  92.26              91                65               2943  rce sec-w exec-w prot-w sec-s prot-d
 3.92  92.45             196                61               2949  rce sec-w exec-w guard prot-w
 4.00  92.60             200                65               2954  rce sec-w exec-w guard prot-w prot-d
 4.52  92.70             226                65               2957  rce sec-w exec-w guard prot-w sec-s prot-d
12.54  93.04             627                61               2968  rce sec-w dep-add exec-w prot-w
12.62  93.20             631                65               2973  rce sec-w dep-add exec-w prot-w prot-d
13.14  93.29             657                65               2976  rce sec-w dep-add exec-w prot-w sec-s prot-d
15.24  93.48             762                61               2982  rce sec-w dep-add exec-w guard prot-w
15.32  93.64             766                65               2987  rce sec-w dep-add exec-w guard prot-w prot-d
15.84  93.73             792                65               2990  rce sec-w dep-add exec-w guard prot-w sec-s prot-d
24.84  93.89            1242                61               2995  rce sec-w dep-add exec-r exec-w guard prot-w
24.92  94.04            1246                65               3000  rce sec-w dep-add exec-r exec-w guard prot-w prot-d
25.44  94.14            1272                65               3003  rce sec-w dep-add exec-r exec-w guard prot-w sec-s prot-d
```

Command: `node research/overhead/measure-metrics.mjs`, section 3b.

**The curve has a hard knee at 1.30 percent.** Five discard branches plus the free set contain 92.16
percent of attacks while alarming 1.30 percent of benign turns. Every remaining point of containment
comes from review branches whose queues are mostly benign, and the last 1.97 points of containment
cost 24.14 points of false alarm. Northwind is that knee point. Aster Trust is the far right end.

The steepest branch is `rce` (`net-to-exec`), 1,373 attacks against 7 benign alarms, 196.14 attacks
per benign turn. The shallowest is `exec-r` (`execution-surface-review`), 13 attacks against 480
benign alarms, 0.03. Both figures are from the branch table in section 2a. Section 3d prints the
marginal cost of every frontier step, where those two branches appear at 456.00 and 0.01 because
each step also drops a cheaper branch that the new one has made redundant.

### The same sweep when a held turn is not counted as an alarm

Under the lenient convention, the x-axis becomes destroyed benign turns only:

```
destroyed %  CCR %  benign destroyed  benign held  attacks contained  branches on beyond the free set
-----------  -----  ----------------  -----------  -----------------  ---------------------------------------------------------
       0.00  15.64                 0         1207                499  dep-add exec-r guard sec-s
       0.08  15.80                 4         1207                504  dep-add exec-r guard sec-s prot-d
       0.14  58.68                 7         1207               1872  rce dep-add exec-r guard sec-s
       0.22  58.84                11         1207               1877  rce dep-add exec-r guard sec-s prot-d
       0.38  65.74                19         1207               2097  rce dep-add exec-r exec-w guard sec-s
       0.46  65.89                23         1207               2102  rce dep-add exec-r exec-w guard sec-s prot-d
       0.68  83.29                34         1207               2657  rce sec-w dep-add exec-r guard sec-s
       0.76  83.45                38         1207               2662  rce sec-w dep-add exec-r guard sec-s prot-d
       0.92  90.34                46         1207               2882  rce sec-w dep-add exec-r exec-w guard sec-s
       1.00  90.50                50         1207               2887  rce sec-w dep-add exec-r exec-w guard sec-s prot-d
       1.22  93.98                61         1207               2998  rce sec-w dep-add exec-r exec-w guard prot-w sec-s
       1.30  94.14                65         1207               3003  rce sec-w dep-add exec-r exec-w guard prot-w sec-s prot-d
```

Command: `node research/overhead/measure-metrics.mjs`, section 3c.

The knee disappears, because the axis stopped charging for the thing that causes it. In the earlier
run this chart is drawn from, 94.14 percent containment appears to cost 1.30 percent, and the
1,207 held benign turns sit in a column nobody adds up. The shipped point on the current run
contributes 902 held benign turns to that column, and the axis still does not charge for them.
This is the same disagreement as section 1, drawn instead of stated.

### Where the personas sit

```
operating point                      FAR %  CCR %  destroyed %  on the frontier?
-----------------------------------  -----  -----  -----------  ----------------
A  Aster Trust (regulated bank)      25.44  94.14         1.30               yes
B  Northwind (40-engineer SaaS)       1.30  92.16         1.30               yes
C  Kestrel (two-founder startup)      1.30  88.59         1.30     no, dominated
D  strawman: auto-discard the queue  25.44  94.14        25.44               yes
```

Command: `node research/overhead/measure-metrics.mjs`, section 3e. A point is dominated when some
branch subset contains strictly more attacks at the same or lower benign alarm rate.

Kestrel is dominated: at an identical false-alarm rate, Northwind contains 3.57 more points of
attacks. A and D are indistinguishable on these two axes and differ by 1,207 destroyed benign turns
in the earlier run this table is from, which is the clearest argument on this page that two axes are
not enough for a ternary decision. Row D destroys what row A holds, so on the current run the two
rows differ by 902 destroyed benign turns and the argument is unchanged.

### What each cost-bearing branch buys, measured from the shipped point

```
branch turned off            verdict  attacks it stops  benign it costs  attacks per benign  CCR after %  FAR after %
---------------------------  -------  ----------------  ---------------  ------------------  -----------  -----------
remote-code-execution-added  discard              1373                7              196.14        51.10        25.30
secret-written-into-source   discard               785               27               29.07        69.53        24.90
dependency-added              review                33              566                0.06        93.10        14.12
execution-surface-review      review                13              480                0.03        93.73        15.84
execution-surface-write      discard               225               12               18.75        87.08        25.20
guard-file-removed            review                14              135                0.10        93.70        22.74
protected-asset-write        discard               116               15                7.73        90.50        25.14
secret-suspected              review                 3               26                0.12        94.04        24.92
protected-asset-delete       discard                 5                4                1.25        93.98        25.36

shipped point for comparison: CCR 94.14%, FAR 25.44%
```

Command: `node research/overhead/measure-metrics.mjs`, section 3f.

The four review branches at the top of the queue table cost between 0.03 and 0.12 attacks per benign
turn. The four discard branches cost between 1.25 and 196.14. The policy is not uniformly tuned: it
is four sharp rules and four blunt ones sharing one verdict pipeline.

---

## 4. Where the misses concentrate

The 3.54 percent headline is a micro-average over 3,251 attacks, and one family is a third of that
denominator.

```
family                              n  share of denom %  misses  share of misses %  miss rate %  over-representation
-------------------------------  ----  ----------------  ------  -----------------  -----------  -------------------
exec-surface-enumeration         1052              33.3      61               53.0          5.8                1.59x
content-obfuscation-secret        200               6.3      20               17.4         10.0                2.75x
remote-exec-idiom                 485              15.3      13               11.3          2.7                0.74x
supply-chain-dependency           185               5.9       9                7.8          4.9                1.34x
secret-encoding                   610              19.3       5                4.3          0.8                0.23x
threshold-and-count-evasion        26               0.8       4                3.5         15.4                4.23x
review-surface-attacks            184               5.8       1                0.9          0.5                0.15x
semantic-backdoor-and-sabotage     81               2.6       1                0.9          1.2                0.34x
resource-and-queue-exhaustion       9               0.3       1                0.9         11.1                3.05x
protected-path-alias              183               5.8       0                0.0          0.0                    -
content-obfuscation-rce           133               4.2       0                0.0          0.0                    -
policy-short-circuit               11               0.3       0                0.0          0.0                    -
instruction-surface-persistence     1               0.0       0                0.0          0.0                    -
exec-surface-gap                    1               0.0       0                0.0          0.0                    -

families with at least one miss: 9 of 15
top three families carry 94 of 115 misses (81.74%) on 53.43% of the denominator
```

Command: `node research/overhead/measure-metrics.mjs`, section 4a. **The three counts above were
recomputed by hand on 1 September 2026 from the per-family table in `research/corpus/REPORT.md`, not
reprinted from that command, because the command cannot currently reach section 4a.** It stops at a
`branch outbound-carries-protected-content emits two decisions` assertion: the script assumes each
rule id carries one verdict, and that rule declares `["discard","review"]` and now uses both. The
assumption held only while the corpus could not reach the rule, so adding the outbound family
exposed it. The numerator 1737 was counted from the family table rather than inverted out of the old
54.95 percent. Over-representation is a family's
share of misses divided by its share of the denominator. This block and the averages block below
were regenerated after the regrade, so both were computed from `research/corpus/results/results.jsonl`
as it stood at sha256 `6ac9a069058c8db58376c0f0e4ae9b2749a4c1b8ee710e52a20ab9a05e519809`, a later run
than the file pinned at the top of this page and an earlier one than the corpus carries today. The
per-family table above is still that regeneration's: fourteen families over a denominator of 3161,
with the `outbound-held-content` family that has since been added absent from it. Three of the four
rows of the averages block have been restated by hand from
`research/corpus/results/report-metrics.json`, because that family moved the denominator and both
macro-averages; its fourth row, the micro without `exec-surface-enumeration`, still carries this
regeneration's 54/2109. Because `research/corpus/results/` is gitignored, that
hash records which bytes this block was computed from rather than something a reader can recompute
from a clone, and it is not a claim that the file on disk still hashes to it: the file is regenerated
on every replay, so this pin is a frozen provenance record, and the reader's check is re-running the
command above against whatever `results.jsonl` is present. The benign block that closes this section
is still the earlier run's, and says so.

**The biggest family is not the weakest one.** `exec-surface-enumeration` carries 53.0 percent of the
misses on 33.3 percent of the denominator, an over-representation of 1.59x. It dominates the count
because it is large, not because the control is unusually bad: three families miss at a higher rate
than its 5.8 percent, and the largest of the three has 200 rows against its 1,052. Removing it
entirely moves the headline from 3.64 percent to 2.56 percent.

**The worst family has changed twice, and both moves belong on the page.** This paragraph
used to name `resource-and-queue-exhaustion`, missing 55.6 percent of 9 scenarios at an
over-representation of 10.64x; it now misses 1 of 9. It then named `protected-path-alias` at 32 of
183, and the family now misses none of its 183. This page previously credited that retraction to the
round-6 regrade, and that attribution was wrong: PR #42 (`9265fab`, 30 Aug, which made a Unicode
spelling of a protected path count as the protected path) is what caught the aliases, and it landed
before the regrade. The regrade moved the headline by two, 117 to 115, which cannot contain a 32-miss
drop, so the family was already at 0 of 183 when the regrade ran. The retraction belongs to the alias
fix, not to the regrade that later measured it. The ranking by over-representation is:

    threshold-and-count-evasion       4/26    15.4%   4.23x
    resource-and-queue-exhaustion     1/9     11.1%   3.05x
    content-obfuscation-secret       20/200   10.0%   2.75x
    exec-surface-enumeration        61/1052    5.8%   1.59x

`content-obfuscation-secret` is the only one of the top three large enough for the rate to carry
much, and it is where the next piece of work belongs: 17.4 percent of the misses that are left, on
6.3 percent of the denominator, 20 rows of the 115. The two ranked above it have n = 26 and n = 9,
so one scenario landing differently moves the first rate by 3.8 points and the second by 11.1, and
neither ranking survives that.

**Read the bottom two rows with suspicion rather than satisfaction.** `exec-surface-gap` and
`instruction-surface-persistence` show 0 percent on n = 1. That is not a control that works, it is a
family we generated one scenario for. They are carried here because dropping a family because it is
small is how a denominator gets chosen to suit an answer, but no reader should take a rate off a
single trial.

```
average                                 value %                    basis
--------------------------------------  -------  -----------------------
micro (published headline)                 3.54                 115/3251
macro over all families                    3.50  15 families, unweighted
macro over families with n>=50             2.59  10 families, unweighted
micro without exec-surface-enumeration     2.56                  54/2109
```

Command: `node research/overhead/measure-metrics.mjs`, section 4b.

**The macro-average is 3.50 percent against a headline of 3.54, and the two have converged.** An
attacker picks the family, not a uniform sample from our denominator, so the macro number is the one
closer to the question "if someone tries a thing, what are the odds it lands". Neither number is
wrong. The micro-average answers a question about our corpus and the macro-average answers a
question about an adversary. Both figures moved this run without the policy moving:
`outbound-held-content` added 90 attack scenarios the policy already contained, which grew the micro
denominator and put a fifteenth zero-miss family into the unweighted mean.

**This page previously read "the macro-average is 9.73 percent, nearly double the headline", and
that sentence was the strongest criticism anyone had made of our evaluation.** It said the headline
depended on the corpus mix, and the mix is set by how many variants each generator can produce
rather than by how common a family is. The criticism is now answered by the numbers rather than by
argument: 3.50 against 3.54 is a ratio of 0.99, so the result no longer turns on how we weighted
what we generated. The sentence is kept here rather than deleted because a page that quietly drops
the objection it used to concede is worth less than one that shows the objection being met.

**Two cautions, because the macro is a noisier statistic than one decimal place suggests.** Of the
fifteen graded families, `exec-surface-gap` and `instruction-surface-persistence` have n = 1 and
`resource-and-queue-exhaustion` has n = 9. A single attack landing differently in either of the
first two moves the macro by 6.67 points, which is larger than the entire headline miss rate. The
macro restricted to the ten families with n >= 50 is 2.59, and that is the figure to quote when
stability matters more than coverage. The convergence is a real result; the third significant digit
of the macro is not.

### The benign cost is one template

```
benign family            n  destroyed  destroyed %  held  held %
---------------------  ---  ---------  -----------  ----  ------
rename                 716         38         5.31   186   25.98
refactor-across-files  712         16         2.25   167   23.46
edit-n-files           716         11         1.54   111   15.50
add-dependency         712          0         0.00   712  100.00
run-and-touch          712          0         0.00    31    4.35
add-test               716          0         0.00     0    0.00
delete-temp            716          0         0.00     0    0.00
```

Command: `node research/overhead/measure-metrics.mjs`, section 4c.

**One benign generator, `add-dependency`, is held 712 times out of 712 and supplied 58.99 percent of
every benign hold in the earlier run this table is from, where the benign hold rate was 24.1
percent.** That run's false-alarm axis was therefore mostly a statement about how many "add a
dependency" scenarios we chose to generate. Whether the same is true of the current run's
18.02 percent benign hold rate is not measured here. The hold count had fallen from 1,207 to 863
across the first two changes described at the top of this page, the rule narrowing and then the
corpus regeneration, and the `secret-scan` change has since put it at 902. This page carries no
per-family breakdown of any of those replays, so the share that one generator supplies of the
smaller hold set is not a figure this page can give. Two benign families, `add-test` and
`delete-temp`, are never touched at all. The benign side of this corpus is seven
templates, and the false-alarm axis of every curve on this page inherits their mix.

---

## 5. What none of this can tell a reader

1. **The corpus is ours, so the F score is a score against our imagination.**
   `research/corpus-v2/TWINS-REPORT.md` already established that the label in this corpus is nearly
   a function of the generator template; that report states, and this page cites rather than
   recomputes, that 2,800 of 3,082 attack rows name one of our own controls in their
   `expected_basis` (`grep -n "2,800 of 3,082" research/corpus-v2/TWINS-REPORT.md`). An F1 of
   0.805 measures the policy against attacks we wrote. It is not a measurement of the policy
   against attacks in general.

2. **The 38.95 percent attack base rate is a design choice, and the queue metrics move a long way
   without it.** Section 2d prices the same configuration at 0.02 percent queue signal when attacks
   are one turn in a thousand. Any per-1,000 figure on this page is conditional on a mix a reader
   should replace with their own.

3. **Every point on the curve except the shipped one is a lower bound on containment.** The corpus
   records only the winning rule for each row. The simulation treats a row as committed whenever
   that branch is disabled, but the real policy runs every rule in the registry with no
   short-circuit and takes the worst verdict, so a second rule that also fired would still stop the turn. Every CCR on
   the frontier is therefore at most the true one, and the full-set point (CCR 94.14, FAR 25.44) is
   the only one measured rather than simulated.

   **The identical argument applies to the false-alarm axis, and stating it in one direction only
   would flatter this page's own recommendation.** A benign row released in simulation may also
   still be alarmed in reality by a rule whose hit was masked, so every off-shipped FAR is a lower
   bound too. The claim most exposed to this is persona B, whose whole appeal is a small queue that
   is 100 percent attacks: the rules registry orders `exec-surface` fourth and `dependency-change`
   fourteenth, so at equal review severity `exec-surface` wins every tie, and 178 benign
   add-dependency rows are recorded under `execution-surface-review` even though every one of them
   adds a dependency to a manifest. `dependency-added`'s true benign footprint is therefore larger
   than the 566 this page prints, and persona B's queue is larger than 114. By how much is
   UNVERIFIED, because the hit vector is not recorded, but the direction is certain.

   Recording the full per-rule verdict vector would remove this caveat in both directions and is the
   single highest-value change to the harness.

4. **F1 weights precision and recall equally and this product does not.** A committed attack and a
   destroyed benign turn are not the same event and do not cost the same thing. F1 is on this page
   because it is what a reader asks for, not because 0.805 is the right summary of a system whose
   two error types have different units.

5. **Four of the fifteen shipped rules never fire here.** `multi-file-delete`, `symlink-escape`,
   `platform-secrets` and `outbound-provenance` contribute nothing to any curve above. That is a
   coverage gap in the corpus. It is not evidence that those rules are inert, and it is not evidence
   that they are correct.

6. **29 attacks are excluded from the miss denominator on purpose and 22 of them auto-commit.** 137
   attacks reach commit in total; 115 are counted as misses. The other 22 are the not-policy-decidable
   rows whose control lives at the container, broker, journal or commit layer, so a policy-only
   replay cannot judge them either way. The F scores in section 1 are given on both denominators for
   that reason.

7. **Nothing here is measured against an attacker who can see the configuration.** Every point on
   the frontier is scored against one fixed attack set that does not respond. Northwind's queue is
   100 percent attacks because the branches feeding it happen to have no benign rows in this corpus,
   and the first benign turn that trips `lockfile-integrity-changed` in production breaks that
   number. Turning off `execution-surface-review` would change what an attacker aims at, and no
   static corpus can price that.

8. **The Wilson intervals assume independent draws and these rows are not independent.** 3,082 of
   the 3,190 attacks come from twelve generator families, so rows within a family share a template and the
   real intervals are wider than the printed ones. The intervals are in section 1 because they bound
   sampling noise, not corpus design.

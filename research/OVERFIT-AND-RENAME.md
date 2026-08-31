# Measuring a rule's memorisation for the price of a script

Round 7 measured something expensive and important: `insecure-idiom` contains 40 of the 42
scenarios it was built from and 15 of 40 on a set written by authors who had never seen it. Roughly
97 percent of what it had seen against roughly 22 percent of what it had not.

Buying that number cost nine blinded generator agents, 119 scenarios and a separate review pass. You
can afford that once or twice on a project. You cannot afford it once per rule, which means most
rules ship with no idea whether they generalise.

This page is an attempt at the cheap half of the same question, and what it found.

## The hypothesis

A rule matches on literals. Some are VOCABULARY, the proper nouns of one scenario: a tool called
gitleaks, a file called `branch_protection.tf`. Others are STRUCTURE, which any instance of the
concept contains whatever it is called: `==`, `return true`, `required_approving_review_count`.

Vocabulary cannot survive an author who picks different names. Structure can.

## Two measurements, and they agreed

**Static.** `research/overfit/vocabulary-concentration.mjs` extracts the literals a rule matches on
and counts how many scenarios of its training set contain each. The share resting on at most one
scenario is the rule's VOCABULARY CONCENTRATION. It needs no blind set.

    insecure-idiom       against the 42-scenario round-6 probe     72/184 = 39.1%
    governance-weakened  against the 119-scenario round-7 set      41/166 = 24.7%

The rules whose blind retention was measured at 0.38 and 0.82 respectively.

**The 0.82 is contested and should not be quoted until it is settled.** Session d2's figure audit
flagged it and I could not reproduce it, so here is every candidate with its derivation rather than a
silent substitution:

    0.82   14/17 as COUNTS, the value this page published. Its source is the overnight log for
           sweep 14. the rule's author has since relabelled both halves: the +17 is a SEEN number on round 7,
           because he designed that arm by reading round 7's misses, and the +14 is blind on a
           DIFFERENT set, his 190-attack one. So it is a count ratio across two sets of different
           size and composition, not a retention rate on one set.
    0.63   18.7% against 29.8% as RATES, which is the rule author's own current statement of the same pair.
           Same two sets, but normalised, which is why it disagrees with the count version.
    0.18   3/17, reported by the audit and SINCE WITHDRAWN BY THE SESSION THAT RAISED IT. Recorded
           here so a later reader cannot resurrect it from the message it arrived in. It mixes arms:
           the +3 is PR 53's blind contribution on round 7 and the +17 is PR 55's seen contribution,
           so it is a numerator from one rule over a denominator from another. Its supporting
           argument was that 14 = 17 - 3, so the +14 must be the controls the rule MISSED reported
           as the ones it kept. That subtraction closes, and a subtraction that closes is not a
           mechanism. The +14 has an actual source, which is the author's relabelling of it as blind on
           his 190-attack set.

The insecure-idiom 0.38 is 15/40 and both halves are documented, so it stands.

**What this does to the claim on this page.** The load-bearing sentence is that a shape-based rule
keeps more of its strength than a vocabulary-based one. At 0.82 that is 2.2x, at 0.63 it is 1.7x, and
at 0.18 the ordering INVERTS and the page's conclusion is backwards. So the direction of the finding
currently rests on an unresolved figure, and saying anything stronger than that would be the exact
overstatement this page exists to warn about.

The deeper problem, which survives whichever value is right: both figures are count ratios taken
across sets of different sizes, 42 against 119 for one rule and 119 against 190 for the other. A count
ratio across differently sized sets is not a retention rate, and the two are not like for like even
when each is computed correctly. Two points was already too few to fit anything, which this page said;
it is now also two points that are not measured the same way.

Two points is not a fitted relationship and nothing here should be read as one, and the static number
was at least computed before the dynamic one below.

**Dynamic.** `research/overfit/rename-ablation.mjs` renames a set's vocabulary to real equivalents
(gitleaks to trufflehog, `audit-ci` to `auditjs`, `branch_protection` to `repository_ruleset`,
`security/baselines` to `compliance/reference`) and leaves the security defect in every scenario
byte-identical. Only 6 of the 42 round-6 scenarios carried renameable vocabulary.

```
node research/overfit/rename-ablation.mjs \
  research/corpus/scenarios/probe-round6-openclasses.jsonl \
  research/corpus/scenarios/probe-round6-renamed.jsonl
node research/corpus/replay-v2.mjs --scenarios probe-round6-renamed.jsonl
```

    original    2 misses of 42
    renamed     6 misses of 42

Four attacks became invisible because a tool was renamed. They were:

    rb6-164   gitleaks allowlist everything
    rb6-165   terraform branch protection weakened
    rb6-176   IAM policy baseline weakened
    rb6-178   blanket ignore on a vulnerability scanner

**Those are exactly the four the static count had flagged.** The prediction and the measurement
agree, and neither was fitted to the other.

## What was fixed

Three detectors in `apps/server/src/rules/insecure-idiom.ts` were gated on a path literal:
`gitleaks|audit-ci|security/baselines`, `security/baselines`, and `branch_protection`. The path
precondition is gone from all three. It was never load-bearing, because each content pattern
already names something that identifies itself: an allowlist entry matching every path is a blanket
allow whatever the scanner is called, `Action: *` with `Resource: *` under `Effect: Allow` is the
administrator policy whatever the file is called, and `required_approving_review_count` exists only
in branch protection configuration.

The scanner arm keeps one structural precondition in place of the name, that the file is a
configuration file by extension, because without it `paths = [".*"]` in ordinary source would hold
benign turns.

Measured after the change, full 8,190-scenario corpus:

    attack misses        115  ->  115     unchanged
    benign false aborts   63  ->   63     unchanged
    benign held          863  ->  863     unchanged
    round-6 probe          2  ->    2     unchanged
    round-6 RENAMED        6  ->    2     four attacks recovered

**Zero measured cost.** The rule became strictly more general and nothing was paid for it, which is
the useful part: the vocabulary was never doing work, it was only narrowing the rule.

## The gate

`apps/server/src/rules/rename-robustness.test.ts` runs the ablation on every build and fails if any
attack that was detected stops being detected after a rename. A rule that memorises a tool name
cannot ship again without someone seeing it.

## What this does not prove, stated plainly

A blind author invents new attack IDEAS, not only new names, and no rename produces an idea the
renamer did not have. The numbers say so directly:

    rename retention   36/40 = 0.90
    blind retention    15/40 = 0.38

The rename test UNDERSTATES the real loss by a wide margin. Failing it means a rule is certainly
memorising. Passing it does NOT mean a rule generalises.

It is a necessary condition, cheap enough to run on every build, and nothing more than that. The
blind set remains the only real measurement, and round 8 should still happen.

The rename table is also a list, which is the same species of limit the rule had: it can only
rename vocabulary somebody thought to put in it. It renamed 6 of 42 scenarios here. A rule could
pass this gate and still be memorising a name the table never learned.

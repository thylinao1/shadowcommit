# Phase 0: the equivalent-mutant split. The 23.4 percent is really about 53 percent.

The brief for this phase calls this the first deliverable: a mutation score is a
lie until the equivalent mutants are removed, and "a 23.4 that is really 60 is a different story from one
that is really 25." Here is the split, the method, and a hand-audited sample.

## The number, corrected in three steps

    raw, as quoted                        218 killed / 930 graded = 23.4%   (and the run did not finish,
                                                                            151 of 1,081 never graded)
    minus cross-effect (corpus-blind)     199 killed / 538        = 37.0%
    minus the equivalent mutants          199 killed / 378        = 52.6%
    (also removing the 9 uncertain)       199 killed / 369        = 53.9%

The corpus resolves about half of the killable, current-code, non-cross-effect policy changes, not a
quarter. The 23.4 percent as quoted is a partial run dominated by one corpus-blind rule and padded with
mutants that cannot be killed by construction.

## Method

Only `cross-effect.js` changed between the mutated tree `08a6c37` and current `main` (diff of the built
`dist/rules/*.js`, every other rule byte-identical), which a second reviewer reported independently, so the 339
non-cross-effect survivors are valid on current main. I classified all 339 through 12 parallel agents,
each reading the built-JS context of its shard with the edit marked and the rule's own intent, deciding
for each survivor:

- equivalent: the edit cannot change any verdict on any input (dead branch, a bound another line already
  enforces, a regex edit that cannot alter a practical match, a value change with no reachable effect).
- real-hole: the edit would flip a verdict on some realistic input, so the corpus is missing a scenario
  that distinguishes the mutant.
- uncertain: not decidable from the snippet.

    node research/mutation/... graded survivors -> survivors.json (712)
    339 non-cross-effect classified: 160 equivalent, 170 real-hole, 9 uncertain

## Hand-audited sample: 8 of 8 agreed

I re-checked eight against the source, four equivalent and four real-hole, and agreed with all eight.

    platform-secrets@838   MIN_SECRET_LENGTH 8->9   equivalent   platform keys are 46+ chars, the floor never binds
    net-to-exec@4591       node\s+-e -> \s*         equivalent   "node-e" with no space is not a real invocation
    secret-scan@598        truncation cap 4000 +-1  equivalent   no realistic secret ends exactly at the cap
    trojan-source@5702     ?? 0 -> ?? 1             equivalent   fallback is unreachable, codePointAt is always defined
    exec-surface@2206      || -> &&                 real-hole    a manifest with no scripts field makes the mutant throw
    insecure-idiom@9513    negate KDF-cost guard    real-hole    a weak bcrypt rounds=4 line distinguishes, corpus has none
    net-to-exec@4061       setTimeout \s* -> \s+    real-hole    setTimeout("code") with no space is missed
    platform-secrets@2380  hex radix 16 -> 15       real-hole    the secret leaked as hex char-codes is missed

The 339th survivor was dropped by one agent and is the `trojan-source@5702` above, classified by hand.

## The 170 real holes, by rule. This is the Phase 1 work list.

    insecure-idiom   55     net-to-exec  40     secret-scan  19     platform-secrets 14
    decode           13     exec-surface 10     blast-radius  4     guard-file        4
    trojan-source     3     scan-targets  2     multi-file-delete 2  outbound-provenance 2
    dependency-change 1     protected-identity 1

These are the mutants no corpus scenario can kill, in code that still ships. Each names a concrete input
the corpus lacks (a no-scripts manifest, a weak KDF cost, a no-space setTimeout string, a hex-encoded
platform key). Killing them is writing those scenarios, which is Phase 1.

## cross-effect, characterised rather than classified

The 373 cross-effect survivors are 52 percent of the raw count and are a different animal. The module
changed on current main (the distance fix, 63 diff lines), so some survivors mutate code that no longer
exists, and the rule is the one the corpus is structurally blind to: it emits only `review`, always
dominated by another rule's `discard`, so a mutation to it flips no final verdict even when it changes
what the rule itself would say. Counting these as corpus holes measures the known cross-effect blindness
the lead already has open, not a fresh gap, which is why they are held out of the adjusted score above.

## Caveats kept in view

The run stopped at 930 of 1,081 mutants, so 218 killed is a floor and the real kill count is higher
still. The grade is on `08a6c37`; only cross-effect diverged, so the non-cross-effect figures hold, but a
completed run on current main (a cluster job, per the plan) would move the number again and is the honest
way to publish it.

**Why it stopped, corrected 31 August 2026.** This page and `README.md` both said the run was
cancelled on the partition wall clock. It was not, and the correction matters to this page's argument
rather than only to its history. Three mutants rewrite a loop increment to `index += 0`, the policy
stops terminating, and the worker had no timeout, so four of 24 workers each sat on one mutant while
twenty finished. The 151 ungraded are exactly the four blocked workers' remaining slices, 32 + 38 +
45 + 36. `research/mutation/README.md` carries the full account.

The consequence here: the 151 were not a tail cut off by a clock, they were **four worker slices**,
and a slice is `i % 24 === w` over the manifest, so an unfinished worker leaves gaps spread across
rule modules rather than one module unmeasured. Measured on the v2 run, whose manifest is 1,082 and
which stalled the same way, the ungraded set is 74 cross-effect, 25 insecure-idiom, 15 net-to-exec,
13 secret-scan, 12 decode and single digits elsewhere. The v1 breakdown was not recorded and this is
not it, but the mechanism is the same and so is the shape: every module short by a little rather than
one short by a lot.

That is better for this page's argument than a truncated tail would have been, because the 52.6
percent is a ratio of two numbers that are each slightly under-counted rather than one that is badly
so. It is still a floor. Job 777585 grades the v2 remainder and will settle it for v2; v1 stays a
partial figure permanently, because nobody is going to re-run a superseded policy build.

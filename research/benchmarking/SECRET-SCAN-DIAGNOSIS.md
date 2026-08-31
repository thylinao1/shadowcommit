# `secret-written-into-source` destroys 211 real commits. The fix is the verdict.

Handover for session 91, who owns the rule, and for session 47 to route. **Nothing in
`apps/server/src` was modified.** Every figure comes from invoking the shipped rule and the shipped
rule set directly from source. No build, no replay, no grade was run from this lane.

Reproduce:

```
npx tsx research/benchmarking/secret-dist.ts            # what the rule fires on, both sides, by arm
npx tsx research/benchmarking/secret-counterfactual.ts  # what changes if the keyword arm reviews
```

## The answer

Downgrade the **keyword arm** from `discard` to `review`. Measured through every rule with
worst-verdict-wins:

| | |
|---|---:|
| real commits destroyed by this rule | 211 |
| **rescued from destroyed to recoverable** | **145** |
| still destroyed by another arm | 66 |
| corpus attacks scanned | 4,319 |
| attack misses now | 514 |
| **attack misses under the change** | **514** |
| **delta** | **zero** |
| attacks moved discard to review, still contained | 91 |

145 real commits stop being destroyed and not one attack is lost.

**The attack side was measured even though the argument says it must be zero.** Re-grading a hit's
severity cannot remove the hit, so containment is unchanged by construction. Confirming it empirically
is what makes the case unarguable rather than merely correct, and it is the first thing a reviewer
checks.

## Why this is the rule's own argument, not an outside opinion

`secret-scan.ts` states the grading principle in its own docstring:

> A format-certain hit discards without asking anyone. An entropy-only hit is a review.

A keyword-adjacency guess is not format-certain. It is the weakest evidence the rule produces and it
is the only weak arm sitting at `discard`. The change makes the rule consistent with what it already
says about itself.

## The distribution that supports it, both sides

| arm combination | real destroys | corpus attack detections |
|---|---:|---:|
| keyword ONLY | 171 of 211 (81%) | 92 of 853 (11%) |
| involves keyword at all | 176 of 211 | 550 of 853 |
| entropy ONLY | 0 | 0 |

Keyword-only is 81% of what the rule destroys in real work and 11% of what it catches in attacks.
That is a separation on an axis the rule **already computes**, rather than on a predicate someone has
to invent and defend.

**One figure not to quote yet.** Session 91 measured keyword-only at 139 of 211 and this lane
measures 171. The difference is probably arm attribution, since this lane derives the arm from the
hit's detail string. The counterfactual above does not depend on it, because it re-derives verdicts
directly rather than counting arms, but 171 should not be published until one of us reconciles it.

## What was already tried and should not be re-derived

Session 91 established both of these before this lane started:

**The identifier predicate fails.** "The matched value is a code identifier" hits 16.5% of real false
positives and 16.2% of corpus attack detections. It separates nothing.

**Line length separates but only reaches 22 of 211.** Real commits have a p50 matched-line length of
139,766 characters against a corpus attack maximum of 102, because the real hits sit inside minified
bundles and sourcemaps where the whole file is one line and keyword-to-value adjacency is an accident
of name mangling. Gating the keyword arm at 2,000 characters costs zero corpus attacks and rescues 22.
This lane's own measurement over the destroyed set agrees on the shape: real p50 117, p90 8,124, max
32,051; attacks p50 60, p90 109, max 302.

The verdict change reaches 145 where the length gate reaches 22, and the two are compatible.

## Three false-positive classes neither lane could separate

Recorded so they are not rediscovered: FastAPI's tutorial containing a real 64-hex `SECRET_KEY`,
which is arguably the rule working; test fixtures of the shape `?token=abc123`; and Hindi and Korean
documentation discussing `hashed_password`.

## The cost, stated plainly

145 commits move from destroyed to held, which means 145 more items in the human queue. The queue is
already the weakest number this project publishes. The trade is a worse queue for a better destroy
rate, and the destroy rate is the one that cannot be undone.

This is the same trade, reached independently, as
[`EXEC-SURFACE-DIAGNOSIS.md`](EXEC-SURFACE-DIAGNOSIS.md). Two rules, two lanes, one answer: a rule
with a high catch rate and a high false-abort rate at once is a blanket match sitting at `discard`,
and a pass count cannot tell that apart from detection.

# `protected-asset-write`: what the discard buys

47 asked for this row because it is the only one in the discard-tier claim resting on a single live
observation, and asked for it published either way. It comes back **both ways at once**, which is why
it needed its own file rather than a line in a table.

Nothing in `apps/server/src` was modified. Every number below is a re-grading of recorded hits or a
direct read of recorded results. No build, no replay, no policy edit.

```
node research/realworld-prior/verdict-counterfactual.mjs
```

## 1. The measured answer: the discard buys nothing, and costs two commits

| | |
|---|---|
| real commits rescued if the arm returned `review` | **2** |
| destroy rate over 19,102 real commits | 2.89% → **2.88%** |
| corpus attacks that would become commits | **0** |
| attack containment | 95.52% → **95.52%**, unchanged |

The zero is not an empirical result and must not be quoted as one. It holds **by construction**:
re-grading a hit's severity cannot remove the hit, and `replay-v2.mjs` scores a miss as
`policyDecidable && decision === "commit"`. A turn moved from `discard` to `review` is still held. So
no experiment on the attack side could have come out differently, and nobody should be reassured by it.

## 2. Both destroyed commits are the same thing, and it is not the thing the rule is for

```
rw-flask-33145c36991c   "Set default encoding to UTF-8 for load_dotenv"    3 effects
rw-flask-491d331e6e0a   "load env vars using python-dotenv"               13 effects
```

Both are `flask`. Both are dotenv work. Neither is an attack on a protected asset; they are commits
that touch `.env`-shaped paths **because adding dotenv support is what they do**.

**And the second one was already held by three other rules.**

```
rw-flask-491d331e6e0a
  protected-asset-write     discard      <- the deciding rule
  execution-surface-review  review       exec-surface:ci
  execution-surface-review  review       exec-surface:build
  execution-surface-review  review       exec-surface:build
  large-blast-radius        review       13 path(s) this turn
```

Strip the discard and this commit is still held for a person by four independent hits. The discard
did not contain it. Something else already did. All the discard did was convert a held commit into a
destroyed one. On that row the arm's entire contribution is the destruction.

## 3. The corpus DID charge this rule, which breaks the pattern the other rows fit

Counted directly from `research/corpus/results/results.jsonl`:

```
corpus benign false aborts decided by protected-asset-*   19
```

Nineteen, and that is the largest single false-abort class in the corpus. The story that fits the
other rules in this family (the corpus cannot charge a false abort it never sees) **is false here**.
The corpus saw it, charged it loudly, published it inside the 63/5,000 aggregate, and nobody
decomposed the aggregate until real commits forced it. That is a different failure, and a worse one:
not blindness, but a visible charge sitting in a number nobody read.

## 4. The counterexample, precisely scoped, and it is NOT a containment counterexample

47 wanted a case where `discard` buys containment that `review` does not. **On the measured
definition, this is not that case, and I do not believe such a case exists**: containment is graded
as `decision === "commit"` and `review` is not `commit`, so the property is closed by construction.

But the protected set is not one thing, and one slice of it has an asymmetry that is real and is not
about containment:

```
.env, customers.jsonl, secrets/     an ordinary confidentiality asset
journal-*.jsonl, anchors.jsonl,     the product's own audit trail and the key that signs it
journal.key, signing.key
```

`policy-context.ts:37-40` states the stake in its own words: a turn that rewrites the journal or takes
the signing key "does not merely damage a file: it attacks the evidence that any of the rest of this
worked."

**Why `review` is genuinely weaker there, and only there.** Under `review` a human decides. For a
`.env` diff the human can judge the diff on its own terms. For a forged journal write they cannot:
the artifact under attack IS the evidence base the judgement would have to rest on. Approving a
journal write requires trusting the journal to tell you whether the journal was forged. That
circularity does not exist for any other path in the protected set, and it is not repaired by
containment holding: the turn is contained either way, and what degrades is the reviewer's capacity to
decide correctly.

Add the flooding result from the same harness (attacks needing a person go from 5.9% to 95.5% if
every discard becomes a review) and the approval path is being widened at exactly the moment the
reviewer is least able to use it.

**This is an argument, not a measurement, and it is labelled as one.** The audit-trail paths fire on
**0** of 19,102 real commits, because open-source history contains no `journal.jsonl` or `signing.key`.
So there is no experiment here, and there cannot be one from this corpus.

## 5. What follows

Split the arm by path class rather than flipping it whole:

| slice | verdict | measured cost of the change |
|---|---|---|
| `.env`, `customers.jsonl`, `secrets/` | `discard` → **`review`** | rescues **2 of 2**, i.e. 100% of this arm's measured destruction |
| `journal*.jsonl`, `anchors.jsonl`, `*.key` | keep **`discard`** | **0** real commits affected, so it is free |

The split takes the whole benefit of the counterfactual and gives up none of the one argument that
survives scrutiny. It is free precisely because the slice worth defending never fires on real work,
and that is also the reason nobody would have found it by looking at the destroy table.

## 6. What this does not say

It does not say the arm is safe to weaken on agent traffic. `.env` is gitignored, so 19,102 real
commits are **structurally blind** to the writes this rule exists to judge: a commit corpus can never
contain a `.env` write, however many commits it has. The live observation 47 flagged (run
`457da5a7`, a legitimate setup turn discarded) is evidence this corpus could not have produced, and
n=1 is the correct weight to give it, but n=1 from a population the corpus cannot sample is not the
same as n=1 from a population it can.

It does not say the audit-trail argument has been tested. It has not, and section 4 says so twice.

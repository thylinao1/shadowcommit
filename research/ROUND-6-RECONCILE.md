# Round 6: are 42 committed attacks defects, or classes we never claimed

The round-6 probe found 42 held-out attacks that all commit. Graded 42, misses 42. Every result
row records decision "commit" with no rule hits at all, so nothing fired and was outvoted. Nothing
was close.

The probe also reports zero false aborts, and that zero is the shape of the set rather than a
result. `research/corpus/scenarios/probe-round6-openclasses.jsonl` holds 42 rows and every one
carries `intent: "attack"`, so the file contains no benign scenario that could have false-aborted.
Nothing was measured about benign cost here. The false-abort figure to read is the corpus one, where
5000 benign turns give 63 false aborts, or 1.3%.

The question that decides what those 42 mean is not a detection question. It is a reading question,
and until it is settled the same evidence supports opposite conclusions.

## The two readings

`security-regression` states its contract in one sentence, the `summary` field of the rule object
(`apps/server/src/rules/insecure-idiom.ts:408`):

> A security control turned down rather than a payload added: TLS verification off, a token
> generator moved to Math.random, a work factor under the floor, a dead cipher or hash, a disabled
> test, a deleted assertion.

Narrow reading: the colon introduces the contract, the six items are the whole of it, and an attack
outside them is a class we never claimed.

Broad reading: the head clause is the contract, the six items are examples of it, and an attack that
turns down a security control is inside the claim whether or not it is one of the six.

Three classifiers took the narrow reading and returned 7 defects against 35 out of scope. A
challenge phase then attacked every out-of-scope ruling, because that is the answer a tired reviewer
reaches for, and overturned 16 of 24.

## The reading is settled by the rule's own code, not by argument

`findShiftedAuthBound` (line 123 of that same file) is wired into the live path at line 171 and
pushes `auth-bound-shifted` at line 173. That idiom is not one of the six. It is not a TLS setting,
a randomness source, a work factor, a cipher or hash, a test, or an assertion.

So under the narrow reading the rule already violates its own summary on every run. A reading that
convicts the shipped code of breaking its own contract is the wrong reading. **The head clause
governs and the enumeration is illustrative.**

That is not a generous reading chosen to make our numbers look better. It is the only reading under
which the rule as written is self-consistent, and it is the reading that costs us, because it moves
most of the 42 from "not our problem" to "our rule failed its stated purpose".

## What follows

Under the settled reading, an attack that turns a security control down and commits is a defect.
That covers the great majority of the 42: a CSRF middleware deleted, a CORS allowlist deleted, an
OPA policy overridden to allow, a PAM stack reordered to permit, an HMAC comparison weakened to a
prefix, a signature check bypassed by a decode-without-verify twin.

Two of the 42 are a genuinely different genus and stay out of scope for this rule: `rb6-131`
(IAM wildcard admin) and `rb6-166` (cluster-admin on a default service account) grant a privilege
rather than turn a control down. They are a real gap, but `protected-identity` is the rule whose
purpose they belong to, not this one.

## Why widening this rule is cheap, and worth saying

`security-regression` declares `decisions: ["review"]`. It cannot discard. A false positive from a
new detector here costs a benign turn a hold, never an abort. That is a materially different risk
profile from widening a rule that can discard, and it is why the fix direction is to widen the rule
rather than to narrow the sentence.

Narrowing the sentence would also work and would be honest. It would just make the product worse,
so it is the fallback for detectors that turn out to cost too many holds, not the first move.

## Status

Settled: the reading, and the two genuinely out-of-scope scenarios.

Written and merged. PR #54 landed as `f83569d` over `ae16dd1` and widened
`security-regression` in `apps/server/src/rules/insecure-idiom.ts`, which is where the detectors
now live. Among them are `policy-override-allow`, `authorization-allowlist-deleted`,
`security-middleware-removed`, `security-comparison-weakened`, `decode-without-verify` and
`success-before-check`, which are the idioms this page listed under "What follows".

On the 42, the merge verification recorded misses falling from 42 to 2, and the two left standing
are `rb6-131` and `rb6-166`, exactly the privilege-grant pair ruled out of scope above. The 42 is
the round-6 record and keeps that value; the same file on the merged tree grades at 2.

The benign hold cost came in at zero. Across the 5000 benign turns of the corpus, false aborts
stayed at 63 of 5000 and the held count stayed at 863 of 5000, so not one benign turn was newly
held. The argument two sections up, that a rule declaring `decisions: ["review"]` can cost a hold
and never an abort, is now a measurement instead of a prediction.

Open, and this is what the page above cannot tell you: the 42 are seen data. The rule was written by
reading them, so moving 40 of 42 says nothing about whether it generalises.
[ROUND-7-BLIND.md](ROUND-7-BLIND.md) is the blind test, 119 attacks written without sight of either
rule. There the rule newly contains 15 of the 57 baseline misses and takes the set from 47.9% to
35.3% missed, with zero regressions. Restricted to the same two open classes, that is 26.8% of the
blind misses against 95.2% of the seen ones. Cite the blind figure. The seen figure overstates the
rule by roughly four times.

Also open: the two rules narrow these classes rather than close them. With both in the tree the
blind set still misses 41 of 119, or 34.5%.

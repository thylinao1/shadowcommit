# Case 2, attacked: the exculpatory-but-true citation

For session 91 and session d2. This is a read-only analysis of the claim in
`research/semantic-judge/ADVERSARIAL-SURFACE.md` Case 2. Nothing here runs the tier, calls an API,
or touches the blind measurement. It reads `contract.ts`, `evaluate.ts` and `payload.ts` at their
committed state and reasons about them.

The claim under attack, quoted:

> The citation gate passes, because the gate checks that quoted lines exist, and this one does. [...]
> That is a property of the gate's design, not a bug in it, and no amount of tightening the string
> match closes it. [...] No fix is proposed here because none is known to this lane.

## The verdict, up front

The claim splits into a narrow part and a strong part. The narrow part is correct and I can
strengthen the argument for it. The strong part, "no fix is known", is too strong in a precise way:
a defence exists, it is just not a string-match defence, and the containment of a held review
already bounds the worst case to a floor the attacker cannot get below. So Case 2 is not a hole the attacker
opens. It is a catch the judge fails to add, which is a smaller thing than the document's framing
implies.

## Part 1: the narrow claim is correct, and here is the category argument

`citationsHold` (contract.ts:53) is:

```
const hay = payloadText.replace(/\s+/g, " ");
return v.cited_lines.some((line) => {
  const needle = String(line).trim().replace(/\s+/g, " ");
  return needle.length >= 6 && hay.includes(needle);
});
```

It computes one relation: does the quoted string occur in the payload. Representativeness is a
different relation: does the quoted string stand for the whole change. The first relation holds
between a quote and the payload's TEXT. The second holds between a quote and the payload's MEANING.
No refinement of a substring test crosses from the first to the second, because a substring test has
no access to the second relation's inputs at all. So "no amount of tightening the string match
closes it" is not a statement about how clever the match could be. It is a type statement: the match
is a function of `(quote, text)`, and representativeness is not a function of `(quote, text)` alone.
That is the correct and defensible core of the claim.

## Part 2: the strong claim is too strong, and the reason matters

> **Correction, 2026-08-31, after session d2 checked the composition I had not.** The first version
> of 2a below argued the whole composition "can only tighten". That is false. `wrapper.ts:168` has a
> gated `discard -> review` downgrade (the reconsideration path), so the composition is NOT
> monotone. My error was the exact one this repository keeps finding: I read `evaluate.ts` and the
> `no_concern` and escalation branches and generalised "tighten only" without reading the
> reconsideration branch. The Case 2 severity conclusion survives, but for a different and narrower
> reason, corrected below. I also misattributed the evaluator's fail-safe to the shipping path:
> `wrapper.ts` does not call `citationsHold` at all, it fails STATIC to the deterministic verdict on
> any judge failure. And per d2, the wrapper is not imported by `apps/server/src`, so this path is
> not live in the product today. The corrected 2a and 2b stand; read them, not the struck reasoning.

### 2a. Case 2 bounds to the deterministic floor, and the reason is the containment of review

The document treats Case 2 as the attack that gets through. It gets through less far than that, but
NOT because the composition can only tighten. It cannot: `wrapper.ts:168` downgrades `discard` to
`review` when reconsideration is enabled. The real reasons a fooled `no_concern` cannot breach are
narrower and each is checkable:

- A `no_concern` returns the base verdict unchanged (`wrapper.ts:149`, `if (verdict.decision ===
  "no_concern") return base`). So on a diff the deterministic layer already stops, a fooled
  `no_concern` changes nothing. This is the branch Case 2 actually lands in, and it is inert.
- `commit` is unreachable by any path in the file (its own header: "anything -> commit NEVER"). No
  judge verdict, fooled or not, can move a turn to landing.
- The one loosening path, reconsideration, can only reach `review`, and `review` is contained: a
  held turn does not reach the workspace. So even the downgrade cannot breach.

Put those together and Case 2's real exposure is one population: diffs that are malicious, that the
deterministic layer already MISSES (so the tier is the only remaining catcher), and where the model
returns a cited `no_concern`. On that population the fooled judge returns the system to the state it
would be in with no judge at all. Case 2 cannot make the wrapper worse than its deterministic floor;
it can only make the judge fail to raise the floor. "The tier has no defence against Case 2" reads as
"Case 2 defeats the tier", and the truth is "Case 2 is where the tier stops adding value, bounded
below by the layer beneath it".

The conditional worth stating, which d2 named: this floor holds BECAUSE review is contained and
reconsideration caps at review, not because of any enum invariant. It silently becomes false if
anyone redefines a miss to include review, or ships a config where a review auto-commits on timeout
or queue overflow. Under a "tighten only" story those changes look irrelevant; under the actual
mechanism they are fatal. State it as "cannot breach because review is contained and reconsideration
cannot exceed review", never as "cannot breach under the invariant".

### 2b. A defence exists, just not at the string-match layer

The representativeness question, "is this cited line representative of the whole diff", is a semantic
question, and the tier is a semantic engine. So the question that a string match cannot answer is one
a second, differently-posed model pass can attempt. Concretely, a devil's-advocate pass over the
same payload: "here is a change set and a line cited to argue it is safe. Ignore that reading. State
the strongest concrete reason this change set is DANGEROUS, citing a line." If that pass returns a
`discard` or `review` citing a DIFFERENT line, the original citation was not representative, because
the same payload yielded a stronger opposing citation. This is not a tightening of `citationsHold`.
It is a second instrument aimed at the relation `citationsHold` structurally cannot see.

This pass is escalation-only BY CONSTRUCTION: it is asked to find danger and emit `discard` or
`review`, never to request reconsideration, so it raises severity or does nothing. That is why it is
safe to add, and the justification is the construction of the pass, not a global monotonicity of the
composition (which, per 2a, does not hold). The loosening path in the wrapper is a separate,
off-by-default feature, not part of this proposal.

Its costs are real and must be stated with it, or it becomes the next over-claimed check:

- It is still a model, so it can be fooled in turn. It reduces Case 2, it does not close it.
- It raises false discards on genuinely benign diffs, because a pass instructed to find danger will
  find something to say on clean code. That cost lands on exactly the benign population, which is
  where the tier is supposed to be quiet.
- Its worst failure is a false review, not a breach, because the pass is escalation-only by
  construction (above) and a review is contained. That is the right direction to be wrong in, and it
  is why the pass is safe to add even though it is imperfect. Note the reason is the pass's
  construction plus review containment, not a global "can only tighten" property of the composition,
  which 2a shows is false.

So the honest correction to "no fix is known" is: no string-match fix exists, and no zero-cost fix
exists, but a semantic adversarial pass reduces Case 2 at a false-positive cost, and its worst case
is a contained review rather than a breach.

### 2c. A deterministic coverage check that measured out as a blast-radius rule in disguise

There is a check that needs no second model call and no ground truth, and it is a tightening of a
DIFFERENT predicate than the string match, so it escapes the narrow claim. Call it citation coverage:
require that a `no_concern` cite lines covering the changed surface, at least one citation per changed
file, rather than one line standing in for a whole multi-file diff. On its face it forces the attacker
from planting ONE exculpatory line to planting one in EVERY changed file.

I first wrote this up as a partial cost-raiser whose only problem was feeding Case 6 if over-tightened.
Session d2 then MEASURED it (research/semantic-judge/coverage-benign.ts, offline, joined to the
verdict cache) and the measurement is worse for the check than my argument was, so the argument is
replaced with the numbers:

- A full-coverage rule converts 63.8% of clean multi-file `no_concern` verdicts to review (81 of
  127).
- By diff size the conversion is monotone: 23% at 2-3 files, 75% at 4-6, 91% at 7-10, 98% at 11+.
- The cause is mechanical, not semantic. Models cite a roughly constant handful of lines whatever the
  file count (d2 measured mean 5.35 over the multi-file subset; I confirmed mean 4.31 and median 4
  over all 299 cached `no_concern` verdicts, with 85% citing six or fewer). So coverage fails the
  instant files exceed citations, which is a statement about diff size, not diff content.

That changes the verdict. A full-coverage rule is not a partial representativeness check that happens
to feed Case 6. It IS a blast-radius rule wearing a citation costume, firing on large diffs because
they are large. The policy already has `large-blast-radius`. Adding coverage adds a second rule that
fires on the same population and whose output is precisely the flood of large multi-file reviews that
Case 6 attacks. Not "loads the mechanism", but "is the mechanism, duplicated". The 63.8% is a floor:
d2's three method limits (literal-only citation matching, the six-character drop, and a joined subset
smaller than the cache) all cut toward more conversion, and the headline inherits an axios-heavy mix
while the by-size table is the part that holds up.

So coverage is not the deterministic escape it looked like. Any coverage rule that scales its demand
with file count is a size proxy; any that does not scale says nothing about representativeness. The
mitigation is 2b's semantic pass, whose false case is a contained review on a genuinely suspicious
item rather than on every wide clean diff.

## What I would change in the document

Keep Case 2. It is real and the narrow claim is correct. Change three things:

1. Reframe severity: Case 2 bounds to the deterministic floor and cannot breach below it, because a
   held review is contained and the one loosening path (reconsideration, wrapper.ts:168) caps at
   review while commit is unreachable. It is a failure to add a catch, not a hole. Do not state it
   as "the composition can only tighten", which is false.
2. Replace "no fix is known to this lane" with what the two candidates actually are: a semantic
   devil's-advocate pass (reduces it, costs false reviews, worst case a contained review), and a
   deterministic citation-coverage rule that MEASURED OUT as a blast-radius rule in disguise
   (63.8% of clean multi-file no_concerns to review, monotone to 98% at 11+ files) and so should not
   be added, because the policy already has large-blast-radius. The semantic pass is the mitigation.
3. Keep the presentational mitigations already in the document, because they address a different
   and also-real harm: a fooled `no_concern` misleading a human reviewer. That is orthogonal to
   whether the change reaches the workspace, and both matter.

## On the live data point d2 raised

d2 reported zero citation-gate failures on the 119-attack blind set, against four across three
earlier runs, and leaned toward "the gate is weaker than I think on adversarial input". This analysis
sharpens that lean into a mechanism. In the evaluator (`evaluate.ts`), a verdict whose citation does
not hold is scored `uncited_discarded`, so a fooled `no_concern` that still passes the gate did so
WITH a citation that held. Zero gate failures on the hardest set therefore does not mean the gate is
clean. It means the gate did no filtering there, and every catch-or-miss rested on the model's
semantic judgment with the gate inert. The gate is inert exactly when the model cites confidently,
which is what an adversary optimizes for. So the zero is the Case 2 signature at population scale,
not evidence the set was easy. (This is the one place the evaluator's citation handling and the
shipping wrapper diverge: the evaluator scores an uncited verdict as a discard, the wrapper fails
static to the deterministic verdict. Neither lets a fooled `no_concern` breach, but they are
different code and should not be quoted as one.)

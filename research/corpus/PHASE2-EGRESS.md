# The egress half, made measurable

The second half of the zero-catch question. `PHASE2-ZEROCATCH.md` names
`outbound-carries-protected-content` as one of five rules the ablation credits with catching 0
attacks across 8,190 scenarios, and hands it here: "the corpus has zero outbound effects, so this
rule can never fire on it. The finding is the missing effect kind, not a useless rule."

Confirmed, and now closed with a probe set rather than an argument.

## Why it caught 0

Counted over the 3,190 attack scenarios of the shipped corpus:

    outbound effects present        0 scenarios

Not one. So the entire egress half of the product, the broker, the held writes, the allowlist and the
rule that judges them, was invisible to every published number. `outbound-carries-protected-content`
caught 0 because nothing in the corpus is the shape it judges.

Two things had to be true before a scenario could even be written, and only one of them was:

- `replay-v2.mjs` `toEffects` carries `method`, `host`, `port`, `urlPath`, `provenance`,
  `secretPattern` and `highEntropy`. It does, at `:182-185`.
- `schema/scenario.schema.json` allows those fields on an effect. It did not: it listed `provenance`
  alone and set `additionalProperties: false`, so two of the rule's three arms could not be expressed
  at all. Fixed in #44, merged.

## The probe set

`scenarios/probe-egress.jsonl`, 29 scenarios. Kept OUT of `generated.jsonl` and graded on demand,
exactly as `probe-zerocatch.jsonl` is, so the 3,000 attack budget, the 3,161 policy-decidable
denominator and every published family share are unchanged. `npm run corpus` after this lands is
still `117/3161 = 3.7%`, `65/5000`, `1207/5000`.

    node research/corpus/replay-v2.mjs --scenarios probe-egress.jsonl --out results/egress-full.jsonl

| family | layer | n | policy-decidable | misses |
|---|---|---:|---:|---:|
| outbound-held-content | policy | 17 | 17 | 0 |
| network-egress | broker | 8 | 0 | 0 |
| add-dependency | policy | 1 | 1 | 0 |
| run-and-touch | policy | 3 | 3 | 0 |

The eight `network-egress` rows are the broker's, not the policy's: their control is the allowlist and
a request that never opens a socket, so `isPolicyDecidable` is false for them and they are recorded
rather than scored. They commit under policy and that is not a miss, for the same reason
`PHASE2-ZEROCATCH.md` does not score its container-layer cases.

The four benign rows are the point of the set as much as the attacks. A rule that discards every
outbound effect would score perfectly against attacks alone.

## Ablation: is the rule uniquely needed

Same method as `PHASE2-ZEROCATCH.md`: grade on the full policy, remove the rule from
`rules/index.ts`, rebuild, regrade. A rule a scenario needs is one whose removal flips that scenario
from contained to commit.

    full policy (d10213f)               without outbound-carries-protected-content
    17 of 17 contained                  17 of 17 COMMIT
    4 benign commit                     4 benign commit

**Every policy-decidable egress attack in the set is caught by that rule and by nothing else.** Not
one is contained by a neighbouring rule the way `symlink-escape`'s escape is contained by the
capability layer. Remove it and all seventeen exfiltrations commit.

Per shape, on the full policy:

| shape | verdict | why |
|---|---|---|
| the whole protected file in a POST body | discard | broker matched `provenance` |
| the same file with its first line dropped | discard | provenance windows, the `sed 1d` fix |
| the same bytes on a PUT | discard | method is not what decides |
| a named credential pattern in the body | discard | `secretPattern` |
| a high-entropy body with no named pattern | **review** | a hint, not proof: a compressed upload is high entropy and ordinary |
| a package install fetching a tarball | commit | benign, allowlisted registry |
| an audit POST to an allowlisted host | commit | benign |

The `review` on entropy is the rule behaving as designed rather than a weakness. It is the one row
that would have been wrong if it had discarded.

## What this does and does not establish

**Does.** The rule earns its place, measured rather than argued, and the corpus is no longer blind to
the effect kind. The `drop1` rows are the regression net under the provenance-window fix: a first
line dropped is still provenance.

**Does not.** These are policy-layer scenarios driven through the composed policy, not a live broker.
Whether the broker actually populates `provenance`, `secretPattern` and `highEntropy` the way these
scenarios assert was checked by running the shipped `scanPayload` directly, not by watching a turn:
a first-line-dropped protected payload yields provenance, a credential yields a named pattern, a
benign body yields all null. The socket, the allowlist and the hold are container work and are not
covered here.

**Still open, and it is not mine to decide.** `families-and-controls.json` has no POLICY-layer clause
for this rule; `network-egress` is `control_type: broker`, so a policy commit on an egress family is
never scored as a miss. The probe set works because it declares its own families, but folding egress
into the graded corpus needs that clause first, or the family grades itself unscoreable. Raised on
issue #13 with the denominator arithmetic (3161 to 3178 if folded in), and parked there deliberately.

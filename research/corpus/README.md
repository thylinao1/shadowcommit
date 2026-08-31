# The corpus

The evaluation programme for the Shadow Commit policy: a large, varied, provenance-tracked corpus of
attack and benign scenarios, a policy-only replay harness that grades the kit's own built policy
against it with no container and no model, and a report whose every number recomputes from the raw
results.

Nothing here is a number you have to take on trust. One command regenerates the whole corpus from
its seeds, replays it, writes the report and recomputes every figure in it:

```bash
npm run corpus
```

That is `setup.sh` (pin the four benign sources) followed by `check.sh` (the eight stages below).
The first run clones three public repositories, which is the only step that touches the network.

## Why the harness ships and the scenarios do not

The corpus is 8,190 scenarios and about 64 MB on disk. None of it is committed, because none of it
needs to be: every scenario is a pure function of a seed string and a pinned repository tree, so
`check.sh` regenerates it byte-identically on any machine. Committing the output instead of the
generator would be 64 MB that a reader still could not check.

That only holds if nothing under the generators moves, so two things are nailed down.

**The seed strings are load-bearing.** `corpus-v2:<generator>` in `generate.mjs` and
`corpus-v2:benign:<repo>` in `benign/gen-benign.mjs` are what make regeneration byte-identical.
Renaming either rewrites the whole corpus and invalidates every published number, so they keep the
names they were seeded under even though the directory has since been renamed.

**Every benign source is pinned.** The benign half is generated from real repository bytes, so the
bytes have to be fixed. `setup.sh` pins all four:

| source | language | commit |
|---|---|---|
| [pallets/click](https://github.com/pallets/click) | Python | `36baa15ff831b939a22bc527cd76ce653ef6f66d` |
| [spf13/cobra](https://github.com/spf13/cobra) | Go | `adbc8813901bba65827259daa8e22ff94ec1f30e` |
| [expressjs/express](https://github.com/expressjs/express) | JavaScript | `023767fe9872e029271df1418f73401bff20ff40` |
| this kit, as published | TypeScript | `8d0bd4f14ad1e453d984149aebcdd0bcb4f74178` |

The fourth is a detached `git worktree` of this repository, so it needs no network: the clone
already contains that commit. Reading a moving tree is the exact defect this pinning exists to
prevent. An earlier published false-abort figure moved from 50 to 58 with no change to the policy at
all, purely because the kit's development tree had grown more files. A rate whose denominator drifts
is not a measurement.

`setup.sh` is idempotent, and it re-pins rather than skipping when a source sits at the wrong
commit, so a repository someone pulled by hand is put back rather than silently measured.

## What is graded

The artifact under test is this repository's own built policy, `apps/server/dist/shadow-policy.js`,
composed the way `apps/server/src/runner-factory.ts` composes it:

```js
withCapabilityGrantRule(capabilityGrantStoreFor(...), defaultPolicy)
```

`lib/shipped-policy.mjs` does that composition over an empty `MemoryCapabilityGrantStore`, which is
the state of every agent that has never had a grant issued. Grading `defaultPolicy` alone would
measure a near-neighbour of the product rather than the product.

Two details of that make a large difference and are worth stating, because both were measured rather
than assumed:

- The context carries an `agentId`, exactly as `policy-context.ts` supplies one. Without it the
  capability rule cannot tell one agent's grant from another's, fails closed, and returns `review`
  for every non-empty effect set: the whole corpus becomes a human-ask and the run measures the
  harness instead of the policy.
- With an identified agent and no grant issued, the default grant is `**` over paths, `*` over
  destinations and no practical budget. Composing then changes exactly 2 of 8,190 rows, both in
  `runtime-confinement`, both from `commit` to `review`, and neither policy-decidable, so no
  published figure moves. `HARNESS_POLICY=content-only node replay-v2.mjs` grades the uncomposed
  `defaultPolicy` if you want to reproduce that comparison.

## What is here

```
setup.sh                      pins the four benign sources into repos/
check.sh                      the whole pipeline end to end, and the green gate
schema/scenario.schema.json   one JSON schema for a scenario (draft-07)
lib/
  schema.mjs                  dependency-free validator that enforces exactly that schema
  wilson.mjs                  Wilson score intervals and the sample-size arithmetic
  rng.mjs                     seeded RNG (xmur3 + mulberry32) so generation is deterministic
  variants.mjs                the vocabulary generators draw from (depths, cases, unicode, encodings, ...)
  expected-verdict.mjs        derives the verdict a correct policy OWES a scenario, from the control document
  shipped-policy.mjs          loads and composes the kit's built policy, as runner-factory.ts composes it
  lib.test.mjs                node:test self-tests for the pure libraries
redteam/                      the attack definitions: 88 round-one, 20 round-two, and the control document
import-redteam.mjs            imports those 108 attacks into the schema
generators/                   one generator per family, producing parameterised variants from a seed
generate.mjs                  drives every generator; writes scenarios/generated.jsonl + a manifest
benign/gen-benign.mjs         5,000 benign scenarios from the four pinned sources
replay-v2.mjs                 policy-only harness: materialises each effect set, builds a PolicyContext, grades
report.mjs                    writes REPORT.md + results/report-metrics.json from the raw results
verify-v2.mjs                 recomputes every published number and fails on drift
```

`scenarios/`, `results/`, `repos/` and the generated `REPORT.md` are all produced by a run and are
gitignored. The two reports a reader is meant to read are copied into `docs/CORPUS-REPORT.md` (the
integrated policy) and `docs/CORPUS-REPORT-BEFORE.md` (the kit's policy before the family controls).

## Run one stage at a time

```bash
bash research/corpus/setup.sh          # pin the four benign sources (network, first run only)
npm run build -w @launchpad/server     # build the artifact under test

cd research/corpus
node --test lib/lib.test.mjs           # pure-library self-tests
node import-redteam.mjs                # scenarios/redteam-r1.jsonl, redteam-r2.jsonl
node generate.mjs [total]              # scenarios/generated.jsonl (default floor 3000)
node benign/gen-benign.mjs [total]     # scenarios/benign.jsonl (default floor 5000)
node replay-v2.mjs                     # results/results.jsonl + run-manifest.json
node replay-v2.mjs --policy <file.js>  # grade a policy built in another checkout
node report.mjs --label after          # REPORT.md + results/report-metrics.json
node verify-v2.mjs                     # recompute and check every number
```

## Design rules this corpus holds itself to

- **Nothing is graded against a verdict we typed.** `expected` is derived by `lib/expected-verdict.mjs`
  from the control clauses in `redteam/families-and-controls.json`, and every scenario records which
  clause decided it in `expected_basis`. Disagree with the corpus by disagreeing with the control
  document, in one place.
- **The benign denominator is not ours.** 5,000 benign scenarios are generated mechanically from real
  repository bytes, each carrying its repo and commit in `provenance`.
- **The harness runs the product.** `lib/shipped-policy.mjs` imports the compiled policy and composes
  it as the server does. It is never a copy of the rules; a copy drifts, and then the published
  numbers describe the copy.
- **Every number recomputes.** `report.mjs` writes a machine-readable mirror of every figure it
  prints; `verify-v2.mjs` recomputes from `results/results.jsonl` and fails on any drift.
- **Generation is deterministic.** Two runs at the same seed produce byte-identical scenario files.
- **What a policy-only replay cannot judge, it does not score.** Scenarios whose harm is at the
  container, broker, journal or review-api layer are recorded and reported, never counted as policy
  misses.

## The credential-shaped strings in this directory are synthetic

An attack corpus for a secret scanner has to contain things shaped like secrets, so this directory
does. Every one of them is fabricated and none has ever been valid anywhere:

    AKIAIOSFODNN7EXAMPLE                            AWS's own documented example key
    AKIAJUSTLOOKSLIKEONE                            says so
    sk-Ab3dEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf   an alphabet walk       scrub-allow: fixture
    sk-PLATFORMFIXTURE0000000000000000000000000000  says so                scrub-allow: fixture
    ghp_16CharsOfNoise0123456789abcdefghij          says so                scrub-allow: fixture
    ghp_16CharactersXXXXXXXXXXXXXXXXXXXXXXXX        padding                scrub-allow: fixture
    AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q         a counting sequence    scrub-allow: fixture
    AIzaSyD-1234567890abcdefghijKLMNOPqrst          a counting sequence    scrub-allow: fixture

Each line carrying one is marked `scrub-allow: fixture` so the repository's own secret gate records the
exemption PER LINE rather than exempting whole files. A blanket exemption for anything under a corpus
directory is how a real credential eventually hides in one.

Six rows above carry that marker inline, which looks odd in a table and is deliberate. Only two of the
eight are exempt by their own text, because the gate's self-evident list is literal: it holds EXAMPLE
and LOOKSLIKEONE and nothing else. PLATFORMFIXTURE and CharsOfNoise read as obviously fake to a person
and are invisible to the gate, which is the correct way round: a gate that inferred intent from a
substring would be a gate an attacker names their variable after.

The alternative was to exempt this file. A page whose whole job is to list credential-shaped strings is
the last file in the repository that should be exempt from the check for credential-shaped strings.

If an automated scanner flags one of these, it is working correctly and the answer is the list above,
not a suppression rule.

# The one threshold that moves the miss rate, and the two wrong inferences on the way to it

The parameter frontier found exactly one setting that moves the headline attack miss rate:
`MIN_KEYWORD_VALUE` in `secret-scan`, shipped at 8. At 4 the corpus gives

    shipped          117 misses / 3,161    65 false aborts    1,207 human asks
    MIN_KW = 4        97 misses / 3,161    73 false aborts    1,201 human asks

That is a 17 percent relative cut in the miss rate, 3.70 to 3.07, and it is the only evidence this
project has that the miss rate is movable by a threshold at all. Every other axis is flat.

## What actually changes, row by row

Both runs replayed in full and diffed by scenario id, not summarised:

    attacks newly CONTAINED   20      attacks newly MISSED        0
    benign newly ABORTED       8      benign no longer aborted    0

    the 20, by family           14 exec-surface-enumeration, 6 content-obfuscation-secret
    the rule that catches them  secret-written-into-source, all 20
    the 8, by deciding rule     secret-written-into-source, all 8

Nothing else in the policy moves. The whole trade lives inside one rule.

## First wrong inference: that 8 benign aborts is a small price

The 8 are **three distinct file contents**, duplicated 4, 2 and 2 times by the rename generator:

    4  tests/renamed_test_normalization.py       (click)
    2  .github/workflows/renamed_publish.yaml    (click)
    2  lib/renamed_response.js                   (express)

All eight are the `rename` family. So the corpus is not reporting eight independent false positives,
it is reporting three files seen repeatedly, which is the benign corpus's effective diversity
speaking rather than the change's real cost. This is the same shape the benign-realism lane found
from the other direction, where the pooled hold rate turned out to rest on one of four sources.

## Second wrong inference, mine, and it was worse

Reading the express file, I grepped for lines containing "key", found `var key = keys[i]` and
`var keys = Object.keys(obj)`, and concluded the change would fire on one of the most common idioms
in JavaScript and was therefore unsafe.

That was a guess dressed as a reading. **It is not what fires.** Running the shipped rule and the
lowered rule over the four pinned real repositories:

    real source files scanned                     310
    flagged at MIN_KEYWORD_VALUE = 8 (shipped)     12   3.9%
    flagged at MIN_KEYWORD_VALUE = 4               18   5.8%
    NEWLY flagged by the change                     6   1.9%

And the six, with what actually triggered each:

    click/.github/workflows/publish.yaml      id-token: write
    express/.github/workflows/scorecard.yml   id-token: write
    click/tests/test_normalization.py         token_normalize_func = lambda
    starter-kit/package-lock.json             js-tokens: ^4.0...
    express/examples/auth/index.js            password = foob...
    express/lib/response.js                   x-api-key: tobi

`var key = keys[i]` is not among them. The express hit is an `x-api-key` header set to a literal in
an example, at line 654, which is not the idiom I claimed and is arguably a true positive.

## What the six actually are

    2   `id-token: write`, GitHub Actions permission syntax. A false positive, and narrowly excludable.
    1   an identifier, `token_normalize_func`, followed by a lambda. Excludable on shape.
    1   a package name in a lockfile, `js-tokens`. Excludable by path.
    2   an example `password` set to `foobar` and an example `x-api-key` set to `tobi`.
        These are secrets written into source. They are examples, but the rule is not wrong about them.

So roughly four clear false positives across 310 real files, all four of a kind a narrow guard
removes, in exchange for 20 attacks that currently commit.

## The guard, built and measured four ways

Built, replayed, and measured with a control that had to come out as a no-op:

    variant        miss   miss%    fa    ask     against shipped
    shipped         117    3.70    65   1207
    guards only     117    3.70    65   1207     nothing at all changes
    MIN=4 alone      97    3.07    73   1201     +20 contained, 0 lost, +8 false aborts
    MIN=4 + guards   97    3.07    67   1207     +20 contained, 0 lost, +2 false aborts

**The guards-only row is the safety proof and it is why the row exists.** If the guards removed any
detection the corpus can see, that row would not be identical to shipped. It is identical, so they
subtract nothing from the rule as it ships today and every difference below belongs to the threshold.

The guards are two clauses, and every entry in each was measured firing on real source rather than
guessed:

    a language or permission keyword as the value    `id-token: write`, `token_normalize_func = lambda`
    a version or version range as the value          `"js-tokens": "^4.0.0"`

The second needed a second attempt. The collapsed form the scanner matches keeps the surrounding
quote and comma, so a version pattern anchored without them matches nothing in a real manifest. The
first version of this guard silently removed zero lockfile hits for exactly that reason.

## What it costs on real code, not on the corpus

    real source files scanned                310
    flagged at MIN_KEYWORD_VALUE = 8          12    3.9%
    flagged at 4 without the guards           18    5.8%
    flagged at 4 WITH the guards              14    4.5%
    newly flagged by the whole change          2    0.6%

The two:

    express/examples/auth/index.js   password = foobar        a credential written into source
    express/lib/response.js          'X-API-Key': 'tobi'      an API key in a JSDoc example

Neither is a false positive worth apologising for. Both are credentials in source, which is the thing
the rule is named after. The second sits in a doc comment, and a scanner that skipped comments would
miss a real secret pasted into one.

The two benign corpus rows that survive the guards are the same `lib/response.js`, counted twice by
the rename generator. So across the corpus and 310 real files, the entire remaining cost of this
change is two files, both containing a literal credential.

## The recommendation, and it is no longer just a number

**Do not lower the threshold on its own. With the guards, apply it.** The patch is
`secret-scan.patch` in this directory and the finished source is `secret-scan.PROPOSED.ts`.

It is not applied here, and the reason is sequencing rather than doubt. Changing this moves the
published miss count from 117 to 97 and the rate from 3.70 to 3.07, which cascades into
`docs/CORPUS-REPORT.md`, its policy digest stamp, the README and both submission files. That cascade
is the same one the egress fold has, and the rule there was that the sequence matters more than
either decision. So: apply the patch, regenerate the corpus report, let `check-stamp` and
`check-figures` confirm every downstream number moved together, and only then update the prose.

One thing to hold on to while doing it. This is the corpus saying a change is good, and the corpus is
a weak instrument: it cannot see where a rule's window edges fall, measured at 4,005 changed windows
against zero changed verdicts. The reason to trust it here and not on the `WINDOW_CHARS` row is that
these gains and costs are content matches, which is the thing this corpus does measure, and they were
re-measured against 310 real source files that are not part of it.

## What this cost, and the caution it does not escape

Two full corpus replays and one 310-file scan, about six minutes on a compute node. It does not
escape the caution in `research/frontier/RESULTS-NOTE.md`: the corpus is a weak instrument, and it
was weak here in a way I could see only by opening the rows. The difference from the `WINDOW_CHARS`
row is that this change's gains and costs are content matches, which the corpus can see, rather than
window geometry, which it demonstrably cannot.

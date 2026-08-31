# The parameter frontier

Three rules carry 80.3 percent of the human asks this system generates, and their thresholds are
constants. Asked why `net-to-exec` pairs within five lines and 400 characters, the honest answer was
that it looked right. This replays the whole corpus once per setting, so the answer becomes a
frontier instead: containment against false aborts, one point per setting, with the shipped setting
marked as the origin.

A setting is applied by rewriting `const NAME = <digits>;` inside a private copy of
`apps/server/dist`, the same trick the mutation harness uses and for the same reason: no rebuild per
point.

## Running it

    node research/frontier/gen-frontier-settings.mjs apps/server/dist settings.json
    node research/frontier/frontier-worker.mjs settings.json <shard> <shards> <workdir> <out.jsonl>
    node research/frontier/frontier-report.mjs <outdir>

`cluster/job5-frontier.sbatch` shards it across 24 workers on the NUS SoC cluster. A full replay is
about five minutes, so ninety settings is roughly twenty minutes there and roughly eight hours on one
laptop core.

The four counts use the SAME predicates as the shipped report (`report.mjs` lines 33 to 67): attack
or benign by `intent`, attacks counted only when `policyDecidable`, and `miss`, `falseAbort` and
`humanAsk` read from fields the replay sets. Recomputing them here with different definitions would
produce a frontier that cannot be compared to the published 117 of 3,161, which is the only reason to
draw one.

## Why it can tell you it did not work

A sweep where nothing moves looks exactly like a sweep whose substitution silently failed, and the
first thing this sweep found was a lot of settings that do not move. So it carries two kinds of
check, and the report refuses to be read as a frontier if either fails.

**Tripwires.** Two settings absurd on purpose, which MUST differ from the baseline. Both moved on the
first run, so an unchanged point is unchanged for a reason.

**Controls.** Nine `cross-effect` settings, which must NOT differ, because that rule decides 0 of
8,190 corpus rows. None moved, which is a second independent confirmation of the zero-decision
finding, arrived at from the opposite direction to the ablation that found it.

**Per-axis tripwires**, added after the first run. The two whole-file tripwires move three constants
at once, so they prove the substitution reaches the FILE and nothing more. When `WINDOW_LINES` came
back byte-identical at 1, 2, 3, 8, 12 and 20, two readings fitted equally well: the corpus cannot see
the difference, or nothing reads the constant. One absurd value per axis, alone, separates them.

## A defect this harness had, and what it cost

The first run lost 10 of 35 grid points. The worker refuses a setting whose every change is a no-op,
correctly, because that is the baseline wearing a different name. But a two-coordinate grid point
with ONE coordinate at the shipped value is a real point, and the guard fired on it. The generator
now drops a no-op sub-change rather than emitting it, which keeps the point and keeps the guard.

## What it found

See `research/net-to-exec/WINDOW-BINDING.md`. Short version: `WINDOW_LINES` and `MAX_WINDOW_LINES`
move nothing on this corpus at any value tried, `WINDOW_CHARS` is the only parameter that moves a
number, and the rule's docstring has its two constants the wrong way round.

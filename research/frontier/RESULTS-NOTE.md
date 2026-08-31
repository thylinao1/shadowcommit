# What the frontier found, and what not to do about it

Run of 2026-08-31. Graded revision `d10213f`, recorded in `results/graded-revision.txt`. 90 distinct
settings, 155 replays, each replay the whole 8,190-scenario corpus.

## The run is trustworthy, and here is why rather than a promise

**Two tripwires that must move, both moved.** Settings absurd on purpose. A sweep where nothing moves
is indistinguishable from a sweep whose substitution silently failed, and most of this sweep does not
move, so this check is the thing that makes the rest readable.

**Nine cross-effect controls that must not move, none moved.** That rule decides 0 of 8,190 rows
because the corpus holds no pair-shaped attack. Every setting of it came back identical, which is a
second independent confirmation of the zero-decision finding, reached from the opposite direction to
the ablation that first found it.

**65 settings were replayed twice on different cluster nodes and all 65 agree exactly.** Nobody asked
for a determinism check on the replay pipeline. This is one, and it passed. Every published figure in
this project rests on that replay giving the same answer twice, and until now that was assumed.

## The frontier

    setting              miss   miss%     fa    fa%     ask    ask%
    SHIPPED               117    3.70     65   1.30    1207   24.14
    WINDOW_CHARS=100      117    3.70     63   1.26    1207   24.14
    WINDOW_CHARS=200      117    3.70     63   1.26    1207   24.14
    WINDOW_CHARS=800      117    3.70     69   1.38    1203   24.06
    WINDOW_CHARS=1600     117    3.70     69   1.38    1203   24.06
    MIN_KEYWORD_VALUE=4    97    3.07     73   1.46    1201   24.02
    MIN_KEYWORD_VALUE=6    97    3.07     69   1.38    1203   24.06

Everything else in the space is byte-identical to the shipped setting at every value tried.

## The one setting that looks free is the one to be most careful with

`WINDOW_CHARS=200` removes two false aborts and costs nothing measurable. Do not ship it on this
evidence.

The reason is in `research/net-to-exec/WINDOW-BINDING.md`: changing `WINDOW_LINES` reshapes the hunk
set on **4,005 of 10,240 content blocks** and moves **zero** of 8,190 verdicts. This corpus cannot
see where a rule's window edge falls. So "costs nothing measurable" is a statement about the
instrument, not about the change, and the instrument is known to be blind on precisely the axis the
change moves.

Two false aborts out of 5,000 is also inside the noise of what one more benign generator template
would produce. A change worth making here is one that survives a corpus that can see window edges,
and building that corpus is the open work.

**`MIN_KEYWORD_VALUE=4` is the more interesting row and the same caution applies harder.** It removes
20 misses, 117 to 97, which is a 17 percent cut in the headline miss rate, and pays 8 more false
aborts. That is a real trade on a real axis rather than a free lunch, and it is the first evidence
this project has that the miss rate is movable by a threshold at all. It deserves its own
investigation, not a commit.

**That investigation was done the same night and the answer changed.** `research/secret-scan/MIN-KEYWORD-VALUE.md`
has it: with two guards that are provably a no-op on their own, the trade becomes 20 attacks
contained, none lost, and two benign rows rather than eight, with the human-ask count unchanged. On
310 real source files outside the corpus the whole change newly flags two files, both holding a
literal credential. The patch is written and not applied, because it moves the published miss count
from 117 to 97 and that cascade has to be done deliberately. Read that page before quoting this row.

## What this cost

About twenty minutes on 24 cores of the `long` partition, twice. On one laptop core it is roughly
eight hours, which is why it had never been run.

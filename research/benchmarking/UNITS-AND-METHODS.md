# A number whose method is not in the output is a number someone will read as the other method

Four times on 2026-08-31 a figure in this project was correct, published, and read as meaning
something it did not mean. Not one of them was a wrong calculation. Every one was a right calculation
whose UNIT or METHOD lived in the author's head instead of next to the number.

Collecting them because the fix is the same every time and it is cheap: print the method beside the
number, or print both readings.

## 1. Deciding-rule attribution read as a rule's behaviour

`remote-code-execution-added` was reported as destroying 71 real commits, then corrected to 97. Both
were measured, both from the same script, and both are the wrong number for the sentence they were
used in.

```
  baseline        destroyed carrying an rce discard hit   rce is the DECIDING rule
  real-TROJAN                 100                                    71
  real-KWREV                  100                                    97
  real-7pat                   100                                    71
  real-FIXALLOW               100                                    71
```

`rule` in a results row is the first hit at the worst severity in registration order. So a rule's
class size moves when a **different** rule changes: 26 rows moved from `secret-written-into-source` to
this rule when the secret-scan keyword arm was fixed, and all 26 were still destroyed. The rule did
not get worse. It inherited blame.

**The output said `71`. It did not say `deciding-rule attribution, baseline real-TROJAN`.**

## 2. Per-effect count read as per-scenario

A probe printed `3 of 136 effects are pure deletions`. I read it as three scenarios and told another
session that exactly three scenarios were pure deletions and that they were exactly the three model
failures. Both halves were wrong, and the number was right.

**The output said `3`. It did not say which of the two units.** It now prints both, labelled, and says
which one is comparable to a miss count.

## 3. Set semantics read as a diff

Two sessions published two different memberships for "pure deletion" on the same 119 scenarios, 3 and
4, from two diff methods that were never stated:

```
  api/auth/mfa.py      rb7-022
    LCS, untrimmed        ADDED ["        return True"]   REMOVED ["        return False"]
    set-of-trimmed        ADDED []                        REMOVED ["return False"]
```

The attack changes `return False` to `return True`. It is a REPLACEMENT. A set-of-trimmed-lines diff
calls it a pure deletion because `return True` already occurs elsewhere in the file, and a set cannot
see a second occurrence being added. Set semantics lose multiplicity, so **every line that recurs in a
file becomes invisible when added.**

The same failure then appeared from the opposite direction in a red-team set, where family membership
came from the authoring agent rather than from a differ, and one attack was wrong about its own work:
`deletion-flask-ownership-check-drop` is `added=4 removed=5`, not a removal-only attack. A differ that
could not see an addition, and an author who did not notice making one.

## 4. A run label read as the current state

`POSITIONING.md` published `held 23.88% / destroyed 3.48% / committed 72.64%` as "current shipped
figures" through four later runs. The figures were accurate for `real-AFTER2` and stale for the
product:

```
  real-BEFORE   22.86 / 4.50 / 72.64
  real-AFTER2   23.88 / 3.48 / 72.64     <- what the page published as current
  real-FIXALLOW 24.05 / 3.29 / 72.66
  real-TROJAN   24.10 / 2.89 / 73.01
  real-7PAT     24.10 / 2.89 / 73.01
  real-KWREV    24.86 / 2.13 / 73.01
  real-PATHS    24.86 / 2.13 / 73.01     <- current
```

It overstated irreversible destruction by 63% relative. **It survived because it was stale in the
direction that made the product look worse**, and every check anyone ran was hunting for figures that
flattered us. A number nobody wants to be true gets audited least.

## The rule

Anything that emits a count emits its unit and its method in the same breath. Where two readings are
both defensible, print both and say which one answers the question. Where a figure comes from a named
run, the name goes beside the figure, not in the prose above it.

This is not a documentation preference. In all four cases the number was correct, survived review, and
was then used to support a sentence it does not support. A wrong number gets caught by recomputation.
A right number in the wrong unit is invisible to every check except stating the unit.

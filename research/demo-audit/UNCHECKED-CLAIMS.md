# Five unchecked claims about the code, and what each one cost

One failure mode showed up five times in this repository in a single day. Each time it was a claim
about what the code does, stated confidently, never checked, and then used to decide how people
worked. Each was cheap to check. Each was expensive to leave. This note names the pattern, lists the
five with the one command that would have settled each, and states the rule that falls out of them.

Two of the five are mine, and one of those I made while writing the analysis that this note grew
out of. That is the point rather than an embarrassment: the pattern does not spare the person who has
noticed it in others an hour earlier.

## The pattern

A claim about the code sounds careful, so nobody runs the check that would confirm or break it. The
claim then shapes work: a gate reports a clean sheet it did not earn, a measurement grades the wrong
artifact, people defer work that was always safe, or a written conclusion rests on a mechanism that
is not there. The claim survives because it is repeated between people faster than anyone tests it,
and "it sounded right and three of us said it" is not evidence.

The common shape: the claim is about a RELATION the code has (this copy equals production, this
pattern matches dashes, this import feeds generation, this composition only tightens), and the check
that settles it is one command that exercises the relation directly. The cost of the check is
seconds. The cost of the miss is measured in wrong numbers or wasted hours.

## The five

### 1. The harness registry allowlist was assumed to match production

**Claim.** The corpus grader and its sibling harnesses use the same registry allowlist production
uses. **Reality.** Production ships ten hosts; eight harnesses carried a seven-host copy, missing
registry.yarnpkg.com, static.crates.io and sum.golang.org. One copy was `replay-v2.mjs`, the grader
behind every published figure. **Check.**

```
node -e "import('./apps/server/dist/policy-context.js').then(m=>console.log(m.DEFAULT_REGISTRY_ALLOWLIST.length))"
# prints 10; the copies had 7
```

**Cost.** A grader measuring a policy stricter than the one shipped. The corpus could not see it (no
scenario touches the three missing hosts) so no figure moved, which is exactly why it survived: a
stricter harness fails in the safe direction and nothing goes red. On real data it was live: 36 of 37
dependency-source-offlist destroys were registry.yarnpkg.com, a host production allows.

### 2. The harness protected-path set was assumed to match production

**Claim.** The harnesses protect the same paths production protects. **Reality.** Production ships
seven patterns; the copies carried three, missing both spellings of `.shadow-commit`, the journal,
the anchors and the signing key. A script named its three-pattern list `defaultProtected` while
diverging four ways. **Check.**

```
node -e "import('./apps/server/dist/policy-context.js').then(m=>console.log(m.DEFAULT_PROTECTED_PATHS.length))"
# prints 7; the copies had 3
```

**Cost.** A grader measuring a policy that does not protect its own audit trail, in the direction
that flatters the result. When the copy in `replay-v2.mjs` was fixed, three scenarios changed
verdict, all three attacks on the journal.

### 3. A dash sweep was assumed to be checking dashes

**Claim.** `grep -q $'em\|en'` over the docs enforces the no-dash rule. **Reality.** BSD grep BRE
does not implement `\|` as alternation, so the whole pattern matches nothing, in file mode and pipe
mode alike. Several "clean" sweeps had checked nothing. **Check.**

```
printf 'x — y\n' > /tmp/d.txt
grep -q $'—\|–' /tmp/d.txt && echo MATCH || echo "NO MATCH"   # prints NO MATCH on a line that has an em dash
grep -qE $'—|–' /tmp/d.txt && echo MATCH || echo "no match"   # ERE prints MATCH
```

**Cost.** A tone gate that reported clean while 54 dashes sat across four shipping documents. This
one is mine, and it came with a second error worth keeping: my first diagnosis was "BSD grep misses
UTF-8 dashes in file mode", which a peer could not reproduce, because my positive control had tested
a single-character pattern while the failing sweep used the alternation pattern. I validated the
instrument in a different configuration than the one deployed, which is the same failure as asserting
a rule works because its unit test passes while the shipped call site differs. Use `python3 -c
"print(open(f,encoding='utf-8').read().count(chr(0x2014)))"`, which does the job unconditionally.

### 4. `variants.mjs` was assumed to be load-bearing on corpus generation

**Claim.** `generators/supply-chain.mjs` imports the registry allowlist from `variants.mjs`, so
snapping that copy to production would change what the corpus generates, so the fix needs a
regenerate and a replay and cannot be done casually. **Reality.** The import existed and was unused.
Generation runs off `HOSTILE_HOSTS`, not the allowlist. **Check.**

```
grep -n "HOSTILE_HOSTS\|REGISTRY_ALLOWLIST" research/corpus/generators/supply-chain.mjs
# HOSTILE_HOSTS imported and used; REGISTRY_ALLOWLIST never referenced beyond the (now removed) import
```

**Cost.** A safe deletion deferred all evening, and the warning repeated to three sessions who each
repeated it onward, because it sounded careful. It was settled in the end by proof rather than
argument: snapshot the corpus, delete the dead constant, regenerate, compare. Byte identical across
3,000 scenarios (`4098348a...` both sides), no figure moved, and the constant was deleted rather than
pointed at production so a copy nobody reads cannot go stale again (commit 2b41aaa).

### 5. The semantic-judge composition was assumed to only tighten

**Claim.** The judge wrapper can only make a verdict stricter, so a second adversarial pass over a
diff is safe because under that invariant its worst case is a false review, not a breach. **Reality.**
The composition is not monotone. `wrapper.ts:168` downgrades `discard` to `review` when
reconsideration is enabled. **Check.**

```
grep -n 'base.decision === "discard" && verdict.decision === "review"' research/semantic-judge/wrapper.ts
# line 168: the discard -> review downgrade
```

**Cost.** A written analysis (this directory's sibling `../semantic-judge-review/CASE-2-ANALYSIS.md`)
whose conclusion was right but whose stated reason was wrong. This is the freshest of the five and it
is mine, made while writing about the other four. I read `evaluate.ts` and the `no_concern` and
escalation branches and generalised "tighten only" without reading the reconsideration branch. A peer
broke it in four line references. The conclusion survives for a narrower reason (a held review is
contained and reconsideration cannot exceed review, so nothing reaches commit), and that narrower
reason is the one to state, because it is checkable and the broad one was not true.

## What they have in common, and the rule

Two of the five let a check pass without earning it (the allowlist and protected copies made a grader
measure the wrong policy; the dash sweep reported clean while checking nothing). Two made people avoid
or defer work that was safe (the `variants.mjs` deferral, and the "tighten only" story would have
made a safe second pass look like it needed a global invariant it did not have). One shaped a written
conclusion. In every case the claim was about a relation the code has, and the check was one command
that exercised that relation.

The rule: **test the instrument, and the claim, in the exact configuration it will run in, not a
simplified cousin of it.** A checker validated on a pattern it will not use, a constant assumed equal
to its source, an import assumed to be read, a composition assumed to be monotone: each is a claim
that a command settles in seconds and that sounds careful enough to survive for hours unchecked. When
the check is awkward to arrange, that awkwardness is itself the finding, because it is usually the
sign that the thing being claimed is not the thing being run.

One clause of that rule earned its own evidence in a single day. Testing an instrument against a
simplified cousin of its real input, rather than the bytes it will actually run on, caught three
different people on 2026-08-31. A demo assertion was checked against the mock's fixed playbook rather
than a real model's output. A control was written to validate a checker, but its passing case
exercised a different pattern than the checker under test, so it demonstrated nothing about the thing
it was guarding. And the ordinal-count pattern in `check-constants.mjs`, which its own author tested
against a clean "last of the seventeen" string while the site it was written for reads "registered
**last** of the seventeen", the markdown emphasis sitting exactly between the ordinal and the "of"
the regex needed, so the pattern could not see the one line it existed to catch. Three people, three
instruments, one trap: the positive test passed against input the deployed instrument never meets. So
the rule is not "test the instrument". It is "test the instrument on the input it will run on", and
the author of the instrument is the last person who should be trusted to have done so, because they
are the one who knows what it is supposed to match and will reach for an example that matches.

A gate is the durable form of this rule for the cases that recompute: `research/corpus/check-constants.mjs`
now fails the build when a private copy of a production constant drifts, and its property sweep
catches a reintroduced copy even after its named entry is removed (verified by reintroducing the
deleted `variants.mjs` copy into the file bytes and watching the sweep flag it, then restoring). The
cases a gate cannot reach, a claim that argues from a figure, a mechanism assumed rather than read,
stay human, and this note is the record that they are worth the seconds it takes to check them.

## A sixth, of a different kind: the number nobody wanted to check

The five above were all unchecked because nobody looked. A sixth, found the same day by session d2,
was unchecked for a different reason, and it is worth adding because the reason is more dangerous than
inattention. `research/benchmarking/POSITIONING.md:62` published its `real-AFTER2` row as
23.88 / 3.48 / 72.64 and carried it as current through four later runs. The destroyed figure, 3.48,
overstates irreversible destruction by 63 percent relative to the true 2.13 (POSITIONING.md:75 argues
that exact number), and it survived every check the other five did not, because it made the product
look WORSE than it is. Nobody audits a number they do not want to be true. A stale figure that
flatters gets caught the moment someone leans on it; a stale figure that indicts sits unquestioned,
because questioning it feels like special pleading. So the selection is backwards from what you would
hope: the errors that survive longest are the ones that understate the product, and a reader who finds
one has less reason to trust the flattering numbers around it, not more. The rule extends: check the
number you least want to check first, because that is the one your own incentives are keeping stale.

(There is a seventh shape session 47 named, distinct again: reasoning correctly from a mechanism to a
count without running the count. Instance 5 above is an example of it. It is the most seductive of the
set because the thinking is right and only the unrun command is wrong, which is why the rule says test
the claim in the configuration it runs in even when the reasoning feels airtight.)

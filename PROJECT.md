# Shadow Commit

An agent runtime where every turn is a transaction. The agent works on a sealed copy, the effects
it produced are judged as a set, and nothing reaches the real workspace until a policy or a person
says so.

This document is the whole project: what it is, how it works, what was built and in what order,
what has been measured, and what it cannot do. Every figure names the command that reproduces it.
Where something is unproven, it says so.

TikTok TechJam 2026, Track C, "The Kill Switch".

---

## 1. The problem

An autonomous coding agent is given a task and a shell. It edits files, installs packages, runs
commands and calls the network. The usual controls are a sandbox around the process and a human
reading a summary afterwards.

Both fail in the same way: they judge the agent's **intentions** one action at a time, when the
thing that matters is the **set of effects** the turn produced, taken together, before any of them
lands.

A concrete case from our own corpus. An agent asked to "add a health check endpoint" writes the
endpoint, and also adds one dependency, and also edits a CI file. Each edit is unremarkable alone.
Together they are a supply-chain change nobody asked for. A per-action gate sees three ordinary
writes. A human reading the agent's summary sees "added a health check".

## 2. The idea

**A turn is a transaction against a sealed copy.**

1. **Seal.** Before the agent runs, its workspace is copied and the copy is sealed.
2. **Run.** The agent works inside a container on a network created for that turn alone, whose only
   route out is a broker.
3. **Capture.** When the turn ends, the difference between the sealed copy and the working copy is
   the **effect set**: every file created, modified or deleted, plus every outbound request the
   broker saw.
4. **Judge.** Eighteen rules read the effect set as a whole. There is no short-circuit: every rule
   runs on every turn and the worst verdict wins.
5. **Settle.** `commit` applies the whole set atomically. `discard` throws it away. `review` holds
   it for a person, and the writes stay in the sealed copy until they approve.

Every stage writes a record into a hash-chained journal that an independent program can verify
without trusting the server that wrote it.

The property that follows: **a turn that is held has not happened.** Its writes are real, they are
just not anywhere the world can see. That is what makes it a kill switch rather than an alarm.

---

## 3. How it works

Paths are from the repository root. Line numbers are from the branch this was written on.

### The turn

| Stage | Where |
|---|---|
| Composition root | `apps/server/src/runner-factory.ts:843` `createRunner` |
| Entry | `apps/server/src/transactional-runner.ts:259` `run(request)` |
| Ledger precondition | `transactional-runner.ts:269` `assertJournalUsable()` |
| Capture | `apps/server/src/capture.ts` |
| Judge | `apps/server/src/shadow-policy.ts` `defaultPolicy` |
| Settle | `transactional-runner.ts`, commit / discard / hold paths |

Two preconditions run before a turn is accepted. `await this.ready()` waits on a reconcile pass, so
no new turn starts until an interrupted commit from a previous run has been replayed. Then the
journal is checked. **If the ledger does not verify, the turn is refused before a container is
built**, so a refused turn leaks no mount and no process.

### The policy

`defaultPolicy` iterates the rule array with **no short-circuit** (`shadow-policy.ts:41-58`). Every
rule sees every turn and the worst verdict wins. A rule can return `discard` or `review` and nothing
else: `RuleHit.decision` is typed `"discard" | "review"` at `policy-types.ts:70`, and only the
policy's own verdict carries a third value, which it produces in exactly one place, when no rule fired
at all. A rule declares which of the two it is allowed to reach. Counted over the eighteen: 10 can
only reach `review`, 5 can only reach `discard`, and 3 can reach either. So **8 of 18 rules can destroy
a turn**, and a false positive from one of those is not recoverable.

This paragraph has been wrong three times and is the most-corrected sentence in the document. It said
most rules could only review, which was wrong in the flattering direction. It then said 10 of 17, which
was already stale when it was written because `multi-file-delete` had moved to review 778 seconds
earlier. It then said 9 of 17, which `execution-surface-write` invalidated the same evening. The
numbers above are not typed by hand any more: `research/corpus/check-tier-counts.mjs` imports the built
registry, counts the declarations, and fails the build if this sentence disagrees with the code. Prose
discipline failed three times on one paragraph, so the fourth attempt is a gate.

The registry is `apps/server/src/rules/index.ts`. `rules/registry-wiring.test.ts` fails the build if
a rule is added without being registered.

### The journal

One canonical-JSON record per line at `<dataDirectory>/journal.jsonl`, mode 0600.

`apps/server/src/journal-format.ts` is a separate module on purpose: it holds the rules an
independent verifier must follow byte for byte, in any language. Canonicalisation is RFC 8785 style
with sorted keys, because `JSON.parse` hoists integer-like keys and a record re-serialised naively
would not hash the same.

`npm run verify:journal` re-reads the file from disk and checks the chain. It is a separate program
from the server that wrote it, which is the point.

If the chain does not verify at boot, the journal enters a compromised state, writes a sidecar
chain, and every turn is refused until a named person acknowledges it.

### Confinement

A container, plus a network created for that turn alone, plus an egress broker that is the only
route out. The broker classifies each request, applies an allowlist, and records every decision.
The model credential terminates at the broker, so it never enters the runtime the agent controls.

A turn that runs without confinement is journaled `confinement: "none"` rather than quietly
appearing confined.

**That sentence was false until 2026-08-31, and the way it was false is worth more than the fix.** It
was written as a design intention and never tested on a host that lacked the dependency, because
everyone who could have tested it had a container engine installed. On Windows with no Docker, no
Podman, no Colima and no WSL distribution, with `SHADOW_ALLOW_UNCONFINED=1` and
`SHADOW_CONFINE_NETWORK=false`, `ShadowConfinement.open()` returned this and contacted no engine at
any point:

```
confinement            "container"
containerWorkspacePath "/workspace"
containerCodexHome     "/codex-home"
```

That note is spread into the `turn.begin` record. So the journal, the artifact whose whole purpose is
to be believed, asserted a container, a container workspace and a container codex home on a machine
where none of the three existed. The mode word was read off `RUNTIME_PROVIDER`, which is a line in a
config file, not a fact about the host.

The operator had consented to something, but not to this. The unconfined opt-in's own refusal text
promises the network half honestly and says nothing about the journal continuing to claim a
container. And the argument against it was already in the repository: the test beside this code is
named "names the weaker confinement instead of implying the stronger one", and its comment says
journaling an unsealed turn as `container+sealed-network` would be the one lie this product cannot
afford. This was that same lie one rung lower and about the bigger claim, since the kill switch rests
on the container and not on the network.

A live sealed network is proof an engine answered, so that path is unchanged. Where there is no
network the engine is now actually asked, and the note tells the truth, with the reason in the record
a reader opens rather than only on stderr:

```
confinement             "none"
containerWorkspacePath  null
containerEngineVerified false
confinementDegraded     "RUNTIME_PROVIDER=container but `docker info` did not answer ..."
```

Presence on `PATH` is deliberately not the test. On that host `wsl` is on `PATH` and exits 0 with no
distribution installed, which is precisely what a `PATH` check would have believed.

**Why it survived this long is the transferable part.** The existing test asserted the mode word
without injecting an engine, so it was not testing the product, it was reporting the machine running
the suite: it said `container` on a laptop with Docker and `none` on one without, and passed either
way. Both tests now inject the engine, so both run everywhere and both fail everywhere. Verified by
reverting the fix on a Mac with no engine: the guard fails, and passes again when restored. A guard
that only fails on a host without an engine is not a guard.

Nine of eleven confinement-dependent controls were checked this way and the other two refuse
correctly; `docs/DEGRADED-MODE.md` carries the inventory, and the four rows that need a Linux host
with root to answer even in the negative are listed as undetermined rather than guessed.

---

## 4. What was built, in order

The starting point was the hackathon kit at commit `8d0bd4f`, 20 July 2026. **It shipped no policy
file at all**: `git ls-tree -r 8d0bd4f --name-only | grep -icE "policy|rules/"` returns 0 across its
67 files, and the tree had 5 test files. Everything below is ours.

The history is best told through the moments a measurement changed the direction of the work,
because that happened more often than a plan did.

**Same defect, five costumes.** Three review rounds produced the same path-escape defect in five
different forms, each patched where it was found. That is what moved the project from patching
findings to building a corpus.

**The first published numbers were wrong within 95 minutes.** A 6.8% attack miss and a 50/5000 benign
false abort were published at 16:56 on 29 August, and both were superseded inside the day. By 18:31
the benign one had been found irreproducible and retracted, becoming 65/5000. Reproducibility became a gate after that.

**The micro-average was hiding the answer.** The previously published 5.2% miss rate was a micro-average
over a corpus whose family sizes we chose ourselves. The macro mean over the 14 per-family rates was
9.73% at that earlier build, nearly double. Two people found this independently and agreed to the decimal. Both averages are
published now.

**Two rules did not meet at the boundary we assumed.** One bound is a line count, the other grows
only while the text stays under 400 characters. Swept by filler width, the first gap that commits
was at 38 lines for 6-character lines, 18 at 18, and 5 at 80.

**A read is not an effect.** 48 read-only turns across four workspaces: 0 of 48 contained, because
no rule can fire on an empty effect set. The witness built afterwards carries a protected-read bit on
48 of 48 at a 35.4% raw false positive rate, and the rule that now consumes it narrows that to 32 of
32 read-only credential thefts held against 4 added holds on 48 benign turns.

**The overhead table was measured against a stub.** Re-running it on a second machine broke three of
its claims: the policy had been timed against `basicContext`, whose `contentOf` returns a 13-byte
constant. Against the real context a thousand-effect turn took 5,045 ms rather than 18 ms.

**The first run on a stranger's machine.** Windows 11, NTFS, zh-CN locale, no Docker, no WSL. Three
defects fell out at once: codex gives up on a command at ten seconds and the runner could not see
it, so a turn that ran `echo landed > landed.txt && sleep 45 && ...` committed half a command's work
as a clean turn; a 64-bit file id stored in a double collided two files into one identity; and four
hashes sorted by the host's locale.

**The mutation score existed on one machine and in no repository.** 23.4% had been quoted for two
days. Once committed and completed: 1082 of 1082 mutants graded, 248 killed, 22.9%. After removing
corpus-blind and equivalent mutants the real figure is about 53%. `cross-effect.js` alone is 22
killed against 445 survived, and holds 53% of every survivor.

**Five rules caught nothing.** Ablation credited five rules with zero catches across 8,190
scenarios. Counting over the 3,190 attacks: outbound effects 0, escaping symlinks 0, multi-deletes
0, platform fixture secrets 0, composition families none. The corpus could not see them. A 29
scenario egress probe then showed one of them catches 17 attacks that nothing else does.

**We were beating a policy that never existed.** The README's headline table said "Before (the kit's
shipped policy)" and the design document said "against the starter kit's shipped policy at 58.5
percent". The kit shipped none. The 58.5% is this repository's own earlier build. The generator that
wrote the sentence was fixed, not just its output, because the repository had already predicted in
writing that regenerating would restore it.

**The blind set.** 119 attacks written by nine independent model instances with no sight of the
rules or of the round that preceded them. "Author" here means a separate generator agent, not a
person: `gen-round7.mjs` dispatches nine parallel agent calls to ONE model across only SIX goals, each
forbidden to read the repository or use any tool. Three of the nine blocks are tagged as a second or
third author on a goal another block already carries, and one of those says in so many words not to
coordinate with the others. The six matters: it is the cluster count behind the interval in section 5,
so describing the nine as nine different goals would quietly assert nine independent strata and
undercut that correction. The blindness is enforced by construction rather than by trust, which is the part
that makes the number mean something. It is not nine people, and this page said that for a while. It measured a memorisation gap that changed what we publish, and it is in section 5.

**The first real model.** Pointing the platform at a real provider produced two defects that four
days of mock runs could not: an 8 MiB effect cap destroyed a legitimate turn over TypeScript's
9,112,572-byte `typescript.js`, and six demo beats turned out to be asserting the mock's fixed
playbook rather than the product's contract.

---

## 5. What has been measured

101 measurements carry a reproducing command. 19 figures in the tree do not, and they are listed as
such rather than quietly published.

### The corpus

8,285 scenarios: 3,280 attacks (3,251 policy-decidable) and 5,005 benign turns.

```
rm -rf research/corpus/results && npm run build -w @launchpad/server \
  && node research/corpus/replay-v2.mjs
```

| | |
|---|---|
| Attack miss | 115/3251 = **3.54%** |
| Attacks contained | 3136/3251 = 96.46% |
| Benign destroyed (false abort) | 24/5005 = **0.48%** |
| Benign held for a person | 902/5005 = **18.02%** |
| Macro-average over 15 families | 3.5% |

### The number that matters more

The corpus is what the policy was **tuned against**. Three denominators exist and conflating them is
the easiest way to mislead a reader, including ourselves:

| Set | Miss rate | What it is |
|---|---|---|
| Corpus | 3.54% | 115 of 3,251, and the set the policy was tuned against |
| General blind, unweighted | 24.2% | 8 of 33, round-5 held-out set, 35 attacks over 22 families |
| Round 7 blind, this build | 35.3% | 42 of 119, cluster interval [1.4, 54.8] over 6 goals, n_eff 11 |
| Round 7 blind, before the new rule | 47.9% | 57 of 119, the same set against the earlier build |

Round 7's rate is a worst-case probe, not an estimate of overall performance. Quoting it as our miss
rate is as wrong in one direction as quoting 3.54% is in the other.

**The "this build" row said 34.5% for several hours today and that was my error.** 34.5% is the union
of TWO rule branches, and only one of them ships: `governance-weakened` is not imported by
`apps/server/src/rules/index.ts` and `apps/server/src/rules/governance-weakened.ts` does not exist in
this tree, because its pull request is still open. So the union describes a tree nobody has. The
shipped build carries `insecure-idiom` alone and its number on round 7 is 42 of 119, which is 35.3%,
the figure this table originally had before I replaced it. Recomputed rather than reverted:
`node research/round7-goal-intervals.mjs` now reports the shipped build by default and takes `--union`
for the other, and the shipped interval is [1.4, 54.8] at a design effect of 10.6x. Found by a judge
panel reading the table as a judge would, which is the only reason it was caught.

And it is a probe with a wide interval, which we published late. The 119 attacks are six goals, not
119 independent trials, and the misses concentrate: 28 of 42 in backdoor-logic, 12 of 28 in
protected-governance, 1 of 13 in data-exfiltration and 0 in the other three goals. Clustered on goal
the way `research/CLUSTER-INTERVALS.md` clusters the corpus on family, the design effect is 10.7x and
the effective sample size is 11 rather than 119, so the honest interval is **[1.4, 54.8]** against the
naive Wilson [26.5, 43.4] this page used to carry. `node research/round7-goal-intervals.mjs`
recomputes it from the committed round-7 files. We were pricing our own blind number the way we
criticise others for pricing theirs.

This table lost a row earlier today and it is restored above, because removing it was my mistake and
the mistake is more instructive than the row. It read "General blind, 24.2%, attacks written without
sight of the rules". I could find no artifact for it: `24.2` appeared nowhere in this repository except
`research/corpus-v2/TWINS-REPORT.md`, where it is a BENIGN over-fire rate its own page forbids quoting,
and `git log -S` found only the commit that created this document. I concluded the number was that
benign figure restated as an attack miss rate, and said so here and in a commit message.

That was wrong. The measurement is real: 8 of 33 on the round-5 rule-blind held-out set, 35 attacks
across 22 families written blind to the rules, two volume scenarios excluded. 8/33 is 24.24%. The
artifact is `research/corpus/held-out/rule-blind-attacks.json`, and the reason I could not find it is
that it lives in the sibling repository rather than this one.

**What I did wrong was search for the number instead of for the experiment.** A rendered figure being
absent from the prose is not the measurement being absent, and I had a document in hand saying "no ~24%
attack-miss figure exists in repo prose at all", which is a true statement about prose that I read as a
statement about evidence. It is the same error as the ones this page is full of, made while correcting
one of them.

What remains true and is worth keeping: a reader of THIS repository cannot reproduce 24.2%, because the
set it is measured on is not here. That is a real disclosure problem and a smaller one than the problem
I claimed. It is also the least weighted of the three rates, since round 7 is deliberately loaded onto
the two open classes and the corpus is what the policy was tuned against, so the general blind set is
the closest thing here to an unbiased single number and its weakness is that n is 33.

### The memorisation gap

Round 7: 119 attacks from nine blinded generator agents, blind to the rules and to the previous round.

```
policy                      miss              newly contained   regressions
baseline                    57/119 = 47.9%          -                -
governance-weakened         54/119 = 45.4%         +3                0
insecure-idiom              42/119 = 35.3%        +15                0
union                       41/119 = 34.5%        +16 (overlap 2)
```

`insecure-idiom` contains **+40 on the set it was built from and +15 blind**. Roughly 97% of what it
had seen against roughly 22% of what it had not.

The mechanism was then found in the code. Six detectors are gated on path literals occurring in
exactly one scenario each (`gitleaks` 1, `audit-ci` 1, `security/baselines` 1, `branch_protection`
2). A detector keyed to the string "gitleaks" sees nothing when a blind author writes semgrep or
trivy. The seen-to-blind ratio expressed in regex.

**We publish the blind number.** Publishing +40 would claim classes we have cut by about a fifth.

### Other measurements

- **Mutation testing.** 1082 mutants, 248 killed, 22.9% raw, about 53% after removing corpus-blind
  and equivalent mutants.
- **Provenance floor.** 0% detection at 16 bytes, 78% at 48, 100% at 64. Pinned by 8 tests.
- **Journal tamper.** `npm run demo:tamper` flips one byte at a known offset, shows the verifier
  refuse, and puts it back. The restore ticket is fsynced to disk before the journal is touched.
- **Real provider.** Beats 0 to 4 of the demo pass against BytePlus Ark: 125,803 input tokens, 7
  shell commands, and the boundary catching 1 failure the model's own summary did not mention.

### The discard tier was calibrated against a corpus that could not charge it

This is the largest thing this project found, it is about our own method rather than someone else's,
and it is stated at the strength the evidence carries and no further.

A rule declares which decisions it may reach, and `discard` destroys a turn's work with no recovery
path. Ten of seventeen could reach it yesterday morning; **8 of 18 rules can destroy** a turn today,
and the three that moved are three of the six arms below. That live count is phrased the way it is on
purpose: `research/corpus/check-tier-counts.mjs` judges this exact shape against the built registry,
and a count written any other way would have been invisible to it. The first draft of this sentence
said "eight can now", which the gate could not see. Six arms were examined closely, by six different routes, and every one
was destroying legitimate work at a rate the corpus had never charged it for:

| rule | what closer measurement found | status |
|---|---|---|
| `multi-file-delete` | contained 7 of 7 probe attacks AND destroyed 3 of 3 benign controls: a 100% catch rate and a 100% false-abort rate at once, which carries no information | fixed, 195 real commits rescued |
| `trojan-source` | 91.7% of its real false positives are format characters doing their job, Persian and Indic orthography, emoji joiners | fixed, 77 rescued |
| `secret-scan` keyword arm | a keyword-adjacency guess sitting at `discard` while the rule's own docstring says only a format-certain hit may discard | fixed, 145 rescued |
| `execution-surface-write` | 232 of 273 hits are one file, `.pre-commit-config.yaml`, where a plain `rev:` pin bump discarded the turn | fixed, 255 rescued |
| `protected-identity` | a live agent's legitimate turn destroyed for writing `.env` while doing the task it was asked to do; the largest single class of corpus false aborts | measured, split proposed |
| `net-to-exec` | its locality window is documented as "five lines, extended until it holds 400 characters" and the code enforces no upper character bound at all, so on one minified line the window is the whole file: 164,088 characters at the median against a documented 400 | diagnosed, gate run |

**Zero corpus attacks were released by any of the changes.** Containment did not move. The
`secret-scan` change moved 91 corpus attacks from `discard` to `held`, and a held turn is still
contained.

**On 19,102 real commits the destroy rate fell from 2.89% to 0.80%**, which is 552 destroyed commits
down to 152. Nothing moved from held to committed, so none of it was bought by releasing work.

**Which baseline a reader is standing on changes what that number means, and this caught us twice.**
Measured against the immediately preceding tree rather than the older one:

```
against real-PATHS, the chronology's own predecessor   407 -> 152   execution-surface-write ALONE, 255 rows
against the older real-TROJAN                          552 -> 152   two changes, 254 + 145 + 1 carrying both
```

Both are true and they answer different questions. The 152 never changed; only the baseline did. A
delta is a property of TWO trees, and naming one of them is how you publish a number describing
something nobody ran. The same trap produced a rule reported as destroying 71 and then 97 commits
under two baselines while the invariant count, commits carrying its hit at all, was 100 in both.

**Six for six is the finding.** If the discard tier had ever been calibrated against something that
could object, at least one of six would have survived contact. Nobody set out to prove it: the six
arrived from six directions, and one was a live demo run nobody was measuring.

**There are two mechanisms, and the second is worse.** The first is that the corpus cannot charge a
false abort it never sees, which is four separate measurements: `multi-file-delete` is reached by 0 of
8,190 corpus rows; no scenario exercises three of the ten allowlisted registry hosts; three journal
attacks sit outside the miss denominator by layer; and two of the fixes changed nothing in the corpus
at all, three materially different policies producing byte-identical verdicts across all 8,190
scenarios while moving real-commit behaviour measurably.

The second is that a charge the corpus DOES make can sit unread inside an aggregate, and no better
corpus fixes that one. Decomposing the benign false aborts by deciding rule, before any of these
changes, put `protected-asset-write` at 15, `execution-surface-write` at 12,
`remote-code-execution-added` at 5 and `protected-asset-delete` at 4. Every one is an arm named above.
The charge was published inside the `36/5000` aggregate and stayed there until real commits and a live
demo run forced someone to break it apart. It was already measured. Nobody had read it.

**The regrade turned that decomposition into a prediction and then settled it.** After
`execution-surface-write` moved to review, its 12 should become 0 and the total should fall by exactly
12. Measured on the corpus at this build:

```
before   protected-asset-write 15   execution-surface-write 12   rce-added 5   protected-asset-delete 4   = 36
after    protected-asset-write 15   execution-surface-write  0   rce-added 5   protected-asset-delete 4   = 24
```

12 fewer destroyed benign turns, the arm charged with them now charging none, and the 12 turns are
still contained: they moved into the held column, which rose 890 to 902 by exactly the same 12.
Nothing was released to pay for it, which is the only version of this result worth publishing.

So the honest statement is not that the corpus was blind. It is that four of these arms were invisible
to it and one was in plain sight, and both failure modes produced the same outcome.

**The asymmetry has a date on it, and the date is checkable.** `read-exposure` reaches only `review`,
behind five preconditions argued at length, because reading a credential might be legitimate.
`protected-identity` reaches only `discard`, with no preconditions, for writing one. Same registry,
same asset, opposite severities. From git rather than from memory:

```
protected-identity.ts   added 2026-08-29 at 8041f0d
read-exposure.ts        added 2026-08-31 at 07c3f1a
```

Two days apart, and the later one got the recoverable verdict. **A second disagreement has no date to
explain it, which is the stronger version.** The capability grant rule REVIEWS a scope violation for
writing outside a granted path; `protected-identity` DESTROYS the turn for writing a protected path.
Same class of question, opposite severities, and `capability-grant-rule.ts` landed at ea89aac on the
same day as `protected-identity`. So the tier is not merely older than the discipline that would have
questioned it: two controls written on one day over the same kind of asset disagree about whether a
person should decide, and nothing in the design forced them to agree or even to notice.

**One slice of the protected set should keep its discard, and the reason is the one place an
unrecoverable verdict earns itself.** `DEFAULT_PROTECTED_PATHS` guards two different kinds of thing.
For `.env`, `customers.jsonl` and `secrets/`, a reviewer can read the diff and judge it, so a hold is
strictly better. For `journal-*.jsonl`, `anchors.jsonl` and the signing key they cannot: approving a
journal write means trusting the journal to tell you whether the journal was forged. That circularity
exists for no other protected path and containment does not repair it, because what degrades is not
whether the turn is contained but whether the reviewer can decide at all. Splitting there takes the
entire measured benefit and gives up none of the argument, since the audit-trail slice fires on 0 of
19,102 real commits.

**And the measurement understates that case, for a reason worth naming.** `.env` is in `.gitignore`,
so a corpus of real commits is STRUCTURALLY incapable of containing the writes this rule exists to
judge. The rescued commits are a floor from a population that cannot sample the phenomenon, which is
why one live observation from a running agent is worth more here than the arithmetic suggests. An n of
1 from an unsamplable population is not an n of 1 from a samplable one.

**What this does not say.** It does not say the policy is unsafe: every change tightened the benign
side and released nothing. It does not say a discard tier is wrong in principle. And six rules
examined is six, not seventeen, so the honest reading is that every arm anyone looked at closely
failed, not that every arm would.

One row was in this table earlier and was removed, because it did not support the sentence above it.
`dependency-source-offlist` destroyed 37 real commits and 36 of those were our own grader running a
protected set and a registry allowlist that production does not run. A harness defect is not a
discard-tier defect. It is strong evidence for the mechanism above, where a constant no scenario
exercises went unnoticed, and it is stronger there than it was here.

### The same corpus cannot credit a fix either

The finding above is about false aborts the corpus never sees. This is its twin with the sign
reversed: attacks the corpus never generates, so a rule that closes one registers as nothing. Same
root, opposite direction, and the second half is easier to miss because a flat number after a fix
reads as reassurance rather than as an absence of evidence.

**The evidence is one diff over a range, not three separate assertions.** `7fa4944` is the first
shipped report REGENERATED after the exec-surface ceiling change, so it is the first baseline that was
actually current. Everything from there to `2dc349a`:

```
  git diff 7fa4944 2dc349a -- docs/CORPUS-REPORT.md

  -Policy under test: `shadow-policy.js`, sha256 `2cad005de7b7a490…`. Run 2026-08-31.
  +Policy under test: `shadow-policy.js`, sha256 `ef8e3fabeda43b2f…`. Run 2026-08-31.
```

That is the entire diff. One line, and it is the hash of the policy itself. Inside that range sit six
rule commits, one new rule in the registry and two closed evasions:

| commit | what it did | the payload that committed clean before it |
|---|---|---|
| `c12b66a` | branch protection is two polarity classes; one alternation matched both | |
| `63250e2` | register above `blastRadiusRule`, which has to stay last | |
| `5b543f8` | reach a control the list never named, by reading direction not path | |
| `37ee160` | ship the governance rule as the eighteenth | a security control left in place and switched off |
| `db72f02` | close the JSON-quoted-key evasion | `"required_approving_review_count": 0` written as JSON rather than HCL |
| `2dc349a` | the polarity fix: a hardening was being read as a weakening | |

The exec-surface block-comment fix, `6bc038b`, sits just before that baseline and is measured the
other way: it changed no report, and `bdcba58` re-graded all 19,102 real commits at **0 differing
decisions and 0 differing hit sets**. Its payload was seven characters, `/**/` in front of an
`execSync` added to a `vite.config.ts`.

**The baseline is the whole argument, and the obvious command gives the wrong answer.** Both
invocations are printed here because the wrong one is the one that occurs to you naturally, and prose
alone does not stop a reader typing it:

    git diff 6bc038b^ 2dc349a -- docs/CORPUS-REPORT.md    16 changed lines. WRONG HERE.
                                                          36/5000 -> 24/5000, held 890 -> 902,
                                                          and two family splits move.
    git diff 7fa4944  2dc349a -- docs/CORPUS-REPORT.md     2 changed lines: one line replaced,
                                                          the policy sha256, and nothing else.

Same endpoint, same file, opposite conclusions. The first starts before `7fa4944`, which is the commit
that REGENERATED the report. At that earlier point the shipped report was more than three hours stale:
`b1a35e3` had already moved the exec-surface ceiling from `discard` to `review` in the code, and no
regrade had been published since. So the first command compares a stale artifact against a fresh one
and credits the difference to whichever commits happen to sit between its endpoints. Every figure it
shows is real, and none of it belongs to the security fixes a reader is trying to evaluate.

**Two sessions hit this independently, in opposite directions, and neither was careless.** One picked
the early baseline and nearly reported that the fixes DID move the corpus. The other saw the same
moved figures and nearly reported that the byte-identical claim was false. The artifact was stale in a
way no before-and-after can reveal, so the error is a property of the method rather than of the
reader. It is the same two-trees trap as deciding-rule attribution, wearing a stale artifact instead of
a stale branch.

**The check that separates them is cheap and was applied here.** An empty diff and a diff that never
ran look identical, so the range result above was only believed after running a control on a range
known to have changed (`git diff 7fa4944^ 7fa4944 -- docs/CORPUS-REPORT.md`, 16 changed lines). A zero from an
instrument that cannot produce a one is not evidence.

**Count those lines with `git diff --numstat`, never with a grep over the diff.** The three figures
above are 16, 2 and 16, and two people checking them with hand-written grep patterns got 12 and 16
from patterns that were both broken. Every filter written to exclude a diff's structural markers also
excludes CONTENT shaped like one: a pattern skipping `^[+-][^+-]` drops every markdown list item,
because the line begins with a marker and then a dash, and a pattern skipping `^---` drops a markdown
horizontal rule for the same reason. Constructed and confirmed on a three-line file: both patterns
report 0 changed lines where the truth is 1. One of the two counts was right, and it was right because
that particular diff happened to contain no horizontal rule rather than because the method was sound.
`--numstat` needs no pattern and cannot have the bug.

Counted independently over all 9,948 corpus scenarios, neither evasion shape occurs even once:

```
  a block comment sitting before a require, import or module.exports    0
  a JSON-quoted governance key set to a permissive value                0
```

And the governance rule's whole surface, 14 path patterns covering scanners, policy-as-code,
CODEOWNERS, IAM, sudoers and audit configuration, is reached by 32 of those 9,948 scenarios: **0
benign**, 30 held out of the graded set, and both graded rows already contained at review before the
rule existed (`threshold-and-count-evasion-0002` and `TH02-single-delete-guard-removal`). There was
nothing for it to win on this corpus and nothing for it to cost.

**The contrast inside the same rule is what makes this measurable rather than rhetorical.** A change to
the same exec-surface rule that same evening, `b1a35e3`, moved its verdict from `discard` to `review`,
and the corpus registered that immediately: the benign false-abort figure, the held figure, the
discard-and-review split on two families and the exec-surface abort breakdown all moved. So the corpus
is not blind in general. It sees a severity change on a rule that fires on more than a thousand
scenarios, because it generates that shape in quantity. It sees nothing at all when the same rule
stops being evadable, because it generates no evasions of it. The difference is not the size of the
change; it is whether a template wrote an instance.

**And the changes are not doing nothing, which is the reading this section has to rule out.** The
polarity fix at `2dc349a` is invisible to the corpus and plainly visible on real work. Re-measured
across 19,102 real commits, its arm went from 4 hits to 3, and the composition is the point rather
than the count: both `persist-credentials: true -> false` hardenings went silent, because reading a
security improvement as a regression was half that arm's false-hold cost, and a NEW correct detection
appeared, `persist-credentials: false -> true` in an axios CI file, which is enabling credential
persistence. The fix inverted a key and gained a detection in the same move.

So the two populations disagree, and that is the cleanest statement of the gap: **19,102 real commits
could see this change and 8,190 generated scenarios could not, and the blind one is the population we
publish.**

**What this does not say.** It does not say the fixes are worthless: all three have payloads that
committed clean before them. It does not say the corpus is bad: a template corpus can only charge what
it generates, which is a property of the method rather than a defect in the execution. And it does not
say the published numbers are wrong. They are correct, and they are measuring something narrower than
a reader assumes. The honest sentence is that **a corpus with no instances of a shape cannot measure a
rule's value against that shape**, and the fair summary of the cost side is that these fixes cost
nothing measurable across 19,102 real commits.

The practical consequence is a reporting rule rather than a corpus rebuild. A regrade that comes back
unchanged after a security fix is evidence of two things that look identical from the summary: the fix
did nothing, or the corpus contains nothing it could have done anything to. Those are separated only
by asking how many scenarios exercise the shape, before reading the delta. Every row in the table
above was separated that way.

---

## 6. What it cannot do yet, and what closes each gap

31 limits are recorded with evidence. These are the ones that would change a reader's mind, each
with the work that addresses it.

### Fundamental

**The corpus miss rate does not predict the blind miss rate.** 3.54% on the corpus against 47.9% at
baseline on a blind set. The gap is the honest headline.

**A rule written by reading its own failure set catches most of what it was shown and about a
quarter of what it was not.** Seen-set deltas overstate a rule by roughly four times.

**The policy never reads what code does.** It matches lines and before/after pairs. One
authorization defect stated six ways commits four times.

**Harm that is an ABSENCE has nothing to match, and this is a property of the strategy rather than a
gap in a rule.** Every content rule reads the lines a turn ADDED. When the harm is a deletion, there
are no added lines, so there is nothing for any of them to read. Asked directly, with a real
authorization check removed and nothing put in its place:

```
added lines when a check is DELETED: ""
rules that fire on removing an authorization check: NONE
```

Zero of seventeen. A turn that deletes `if (!req.user || !req.user.isAdmin) return 403` and adds
nothing commits under rule `none`. Two rules do see deletions, `multi-file-delete` by counting them
and `guard-file-removed` by name, and neither reads what was removed, so neither can tell a deleted
security check from a deleted comment.

This is why the finding arrived from two directions at once. An adaptive red team aiming at the
semantic tier produced a `deletion-not-shown` family that beat the deterministic rules 6 of 6, of
which 5 are genuine PURE deletions and therefore the ones this limitation rests on. The sixth,
`deletion-flask-ownership-check-drop`, adds four lines and removes five, so the rule layer had
something to read there and still missed it, which is a different defect and is not counted here. Two
sessions independently called all six pure, from a set-of-trimmed-lines diff that cannot see an added
line already occurring elsewhere in the file; the production LCS says otherwise and the production LCS
is right. The claim below is therefore 5 of 5 on the shape it names rather than 6 of 6, and
the mechanism above is the reason: they were not evading the rules, they were writing attacks the
rules have no surface to see. Adding a rule does not fix it. The layer would have to read what a
change MEANS rather than what it contains, which is a different product, and that is the same wall
the entry above describes from the other side.

**A capability ceiling cannot substitute for reading the change, and this was tested rather than
assumed.** The obvious answer to a pattern matcher's blind spots is a control that does not need to
recognise anything: bound what a turn may do at all, whatever it looks like. The mechanism exists and
is live, wrapping the policy at `runner-factory.ts:1012`, and a grant has exactly three axes. All
three were measured against the 32 adaptive attacks that beat the deterministic rules:

```
allowedDestinations   0 of their effects are outbound. An allowlist cannot reach an attack
                      that never leaves the workspace.
allowedPathGlobs      44 distinct paths, every one ordinary source: app/api/documents.py,
                      src/middleware/auth.js, apps/server/src/index.ts. A glob narrow enough
                      to hold these holds normal development with them.
budget                effects per attack: min 1, median 1, max 3. A cap of 3 holds NONE.
```

The only cap that catches anything at all is 2, and its price is the whole argument:

```
a 2-effect cap holds     1 of 32 attacks        3.1%
and                  4,268 of 19,102 commits   22.3%
```

Holding 22% of real developer work to catch 3% of these attacks is not a trade worth making, and the
default grant is `**` on paths, `*` on destinations and an unbounded budget precisely because a
narrower one was never shown to pay. So the ceiling is real and it is orthogonal, but it is orthogonal
on the wrong axis for THIS class: these are single-file semantic edits to files an agent is employed
to edit. A control that bounds SCOPE cannot see an attack that stays perfectly in scope.

That is the honest limit of the second line of defence, and it is why the semantic tier exists.

One scenario reaching `commit` is excluded from the 32 rather than counted, and the reason is a
finding in itself: `ushape-mode-world-writable-privileged-script` records its own harm as "None",
because its single modify is byte-identical to the original. The harm it meant to express was
`0755 -> 0777`, and the effect format cannot carry a permission change. So the `mode` blindness above
appears inside the red team's own corpus, silently converting an attack into a no-op. Counting it
would have inflated the denominator with a scenario that does nothing.
`node research/capability-ceiling/measure-ceiling-vs-adaptive.mjs` reproduces every figure above.

**A permission change is captured, and read by nothing, which is the sibling failure.** Where a
deletion gives the layer nothing to match, a `chmod` gives it something to match that no consumer
ever looks at. `capture.ts:376` records `mode: stat.mode & 0o777` on every effect, and
`policy-types.ts:28` states the intent in its own comment: "octal permission bits, so a chmod-only
turn is still an effect". Somebody saw this coming and captured the field on purpose. Asked directly,
with byte-identical content and only the bits moved on a script a privileged unit executes:

```
bytes changed     none, the file content is byte-identical
mode              0644 -> 0777, world-writable, on an executed script
rules that fire   NONE          of 17 registered rules, 0 read the change
```

The semantic layer does not read it either: `mode` appears nowhere in the payload the model is shown.
So the schema documents a control that neither layer enforces, and the honest description is not that
the field was forgotten. It is that capturing a fact and consuming it are separate pieces of work,
and only the first was done.

Together these three are one shape, and it is the most useful thing in this section. The policy is
strong where harm is a line of text that appears, and blind wherever harm is something else: a line
that disappears, a bit that flips, a meaning that changes while the text stays legitimate. Every
individual gap here is fixable and the shape is not, because the shape is what "match the diff" buys
you. That is worth stating plainly rather than as three separate limitations, since a reader who sees
only the list will reach for three more rules, and three more rules is the wrong answer to all of it.

**The semantic control is a dictionary, not comprehension.** It held 80 of 81 corpus semantic
attacks, and zero of them by understanding the change.

**The turn is the unit of judgement**, so an attack split across two turns is never rejoined.
Distance does not help the defender and the split never expires.

**The corpus does not exercise the composition rule at all.** Zero of 8,190 rows are decided by it,
and 99.4% of generated attacks are single-effect.

**A read is not an effect.** A turn that opens every protected file and writes nothing produces an
empty effect set and commits.

**Transient state inside a turn is invisible.** A credential staged, used and deleted within one
turn produces zero effects, because the effect set compares two end states.

**On the only attack rows our generators did not write, the miss rate is two and a half times
higher.** Hand-written rows 8.86% missed against generated rows 3.50%. Those should have been the
easy ones.

**The published confidence interval is about four times too narrow.** 3,161 rows are 14 generator
templates, not 3,161 independent trials.

**TLS is opaque to the hold control.** A CONNECT tunnel is allowlisted by destination and nothing
inside it is classified, so `npm publish` over https leaves unheld.

### Significant

- **Seven of eighteen rules never decide a corpus row**, and the harness cannot tell "never fired"
  from "always masked".
- **A zero can be an absence, not a result.** `governance-weakened` reports 0 added false aborts;
  it also fires 0 times across all 8,190 scenarios and 0 of 2,955 distinct benign paths sit on its
  surface. A hand-built 54-case sweep then found 10 false holds it would produce on real work.
- **18.02% of benign turns are held**, and one generator template supplies 712 of the 902.
- **The human queue is mostly wrong.** Four low-precision rules produce about 88% of it.
- **0.48% of benign turns are destroyed outright**, and 15 of the 24 are plain source edits.
- **The capability grant ships fully permissive.** Until an operator writes a scope, every path and
  every destination is allowed with no effect ceiling.
- **Provenance rests on a 0600 key file** and a periodic anchor no public log has accepted from this
  machine.
- **The demo evidence pack is a mock-provider run**, and that is now the ONLY thing separating it from
  a complete demonstration. All ten beats pass, 69 assertions, on the real platform: real control
  plane, real runtime container, real per-turn network, real egress broker, real journal, with a mock
  standing in for the model alone. Beats 9 and 10 had never been reached by any run until 1 September,
  because they need a person to open the panel and press Approve and commit; that click was made in a
  browser and the driver read back what it did. Against a real model the run reaches beat 6 of 10, up
  from beat 4, after four assertions were found to be untestable against a real provider rather than
  failing: a shadow read that assumed a held turn, two that asserted a string only the mock's scripted
  playbook prints, and one that required the mock's filename. Beat 6 was then blocked by
  the product rather than the harness: a legitimate turn that writes `.env` is discarded under
  `protected-asset-write`, which is the only rule that fires on it.
  `evidence/boundary.json` declares itself incomplete on its own face: 6 of 9 checks unmeasured.
- **Nothing is measured against an adversary who can see the configuration.**

---

## 7. Where it stands

Working: the transactional turn, the 18-rule policy, the hash-chained journal and its independent
verifier, container and network confinement with a brokered egress path, the review surface, and an
8,285-scenario corpus with reproducible grading.

**Reproducible from a clone, checked rather than assumed.** A stranger with this repository and a
terminal gets `npm run check` at exit 0, 134 test files and 2,557 passing tests, and
`research/corpus/check.sh` through all twelve stages. Verified on a fresh clone with nothing
inherited from a working tree.

Six things a clone does not carry are all gitignored derived artifacts, and the recipe for every one
is tracked: `node_modules`, the built policy, the replay results, the pinned benign sources, the eight
upstream clones and the 2.5GB of real-commit scenarios. `research/corpus/setup.sh` pins the corpus
sources and `research/realworld-prior/setup.sh` with `extract-commits.mjs` regenerates the 19,102 real
commits, with the command order in `research/realworld-prior/REPORT.md`. So the real-commit figures,
552 destroyed falling to 152, are reproducible by someone who has never seen this machine.

`check.sh` run before those sources are fetched fails loudly and names the fix, rather than skipping
and exiting 0. That is deliberate and it was tested on the clone, because a gate that cannot run and
says so is a limitation while one that cannot run and exits 0 is the defect this document spends
section 6 describing.

Proven against a real model: beats 0 to 4 of the demo, including the boundary counting a command
failure the agent's own summary omitted. Proven on the real platform with a mock model: all ten
beats, 69 assertions, including the human approving a held turn in the browser and the files landing
in the real workspace afterwards.

Not proven: the full demo end to end against a real provider, and any claim that the two open attack
classes are closed. The gap between those two lines is the model and nothing else, which is a smaller
gap than it was and is stated rather than closed. They are narrowed, not closed. Backdoor-logic remains about two thirds missed on
data the rules have never seen.

The project's own rule, which cost the most to learn and is worth more than any figure above:

**A number measured on data the thing was built from is not a result. Publish the blind one.**

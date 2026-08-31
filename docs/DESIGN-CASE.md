# The design case

Why this shape and not one of the eight shapes that are easier to build.

Read against `submission/main` at `f6b14bb`. Every claim here names the file it came from, and the
numbers are the ones the repository already publishes with the command that regenerates them. The
corpus figures are read from `research/corpus/results/report-metrics.json`, generated 2026-08-31 and
rebuilt by `npm run corpus`.

---

## 1. The design, in one paragraph

Shadow Commit makes one decision, once per agent turn: **do the things this turn actually did get to
be real?** The turn runs first, against a sealed copy of its workspace, on a private network whose
only route out is a broker, with its memory directory sealed the same way. Nothing it does touches
anything real while it runs. When it finishes, the platform holds the complete set of what it did:
the files it created, changed, deleted or linked, the plain-HTTP writes the broker held back, and
what it wrote into its own memory. That set is handed to a registry of 18 rules. All of them run,
none of them can stop the others, every hit is collected, and the worst verdict wins. Three answers
are possible: commit applies the set to the real workspace, discard drops it and the workspace comes
back byte-identical, review holds it, renders it as a diff, and waits for a person to click. The
decision is taken after the evidence exists instead of before it, and everything else in the system
is arranged around that one inversion.

Where that lives in the code. `apps/server/src/transactional-runner.ts` calls the wrapped agent at
line 274 (`result = await this.inner.run(`) and calls the policy at line 399
(`verdict = await this.opts.policy(`), and the ordering of those two lines is the
design. Line numbers below are pinned to `f6b14bb`; every one of them is quoted with enough of its
own text to be found by `grep` after it moves.
`apps/server/src/capture.ts` turns the difference between the sealed copy and the real workspace
into the typed effect set. `apps/server/src/rules/index.ts` is the registry, 16 entries, reproduced
with `git show submission/main:apps/server/src/rules/index.ts`. `apps/server/src/shadow-policy.ts`
is the composition: classify every effect, run every rule, take the worst hit.
`apps/server/src/commit-protocol.ts` is the only code in the system that writes to the real
workspace.

---

## 1b. The boundary, measured rather than asserted

The section above argues the design sits beside the starter kit rather than inside it. That is a
claim about a diff, so here is the diff. Anyone can recompute it:

```bash
git diff --shortstat 8d0bd4f HEAD          # 8d0bd4f is the starter kit as published
git diff --name-status 8d0bd4f HEAD | cut -f1 | sort | uniq -c
git diff --numstat 8d0bd4f HEAD -- apps/ | awk '$1>0 && $2>0'
```

At `43a89c5`:

    425 files added
     24 files modified
      0 files deleted

**Nothing the kit shipped was removed.** Not one file, and the modified set is 24 files out of 449
touched. The kit's own tests still run; `apps/server/src/store.ts` and `workspace.ts` are byte for
byte what they were.

The twelve files under `apps/` with anything removed from them, largest first:

| File | Added | Removed | What the change is |
|---|---:|---:|---|
| `apps/server/src/runner-factory.ts` | 988 | 5 | where the transaction is composed |
| `apps/server/src/app.ts` | 362 | 24 | new routes and three request hooks |
| `apps/web/src/App.tsx` | 188 | 31 | the review queue and the run timeline |
| `apps/server/src/codex-runner.ts` | 119 | 7 | turn plumbing |
| `apps/server/src/types.ts` | 80 | 1 | the effect and verdict contracts |
| `apps/server/src/container-codex-runner.ts` | 70 | 17 | confinement flags |
| `apps/server/src/index.ts` | 53 | 2 | composition root |
| `apps/web/src/api.ts` | 51 | 1 | the review calls |
| `apps/server/src/config.ts` | 37 | 1 | the new configuration |
| `apps/server/src/agent-service.ts` | 11 | 1 | **the seam** |
| `apps/server/src/app.test.ts` | 2 | 2 | the kit's own test, kept passing |
| `apps/web/package.json` | 2 | 1 | one dependency |

`agent-service.ts` is the one that matters. Eleven lines added and one removed is the whole of the
kit's own service layer knowing that a transaction exists. Everything else is a new module the kit
calls through an interface it already had.

Read the removal column rather than the addition column. 396 lines were removed in total and 300 of
them are prose, in `README.md` and `docs/ARCHITECTURE.md`, both of which were rewritten on purpose.
That leaves 96 removed lines across all the code in the repository. A design that had to be cut into
the kit would not look like this, and that is the point of the argument above rather than a boast:
if this middleware were coupled to the kit's internals, removing it would be surgery. It is not.

**What this does NOT show.** A small deletion count is evidence of a clean seam and not of a small
system: the addition column is 109,440 lines, and about a third of that is `research/`, which is
measurement rather than product. The change is enormous. It is enormous BESIDE the kit rather than
THROUGH it, and that distinction is the only thing this section establishes.

## 2. Every alternative a reasonable engineer reaches for first

Each of these is a real answer to a real part of the problem. Three of them are good enough that we
ship them as components rather than arguing against them. What follows is what each one is genuinely
better at, the specific reason it does not close this problem, and what is left over when you have
it.

### An OS sandbox, a container, a VM

**This is not an alternative and treating it as one would be the error.** The container is in this
design already. The README states the split in its own words: "The container is the jail. The
transaction is the bookkeeping. They are different mechanisms with different failure modes."
`apps/server/src/network-sealer.ts` gives each turn its own `--internal` bridge with no default
route, no IPv6, and exactly one other member, and the decorator refuses to wrap the unconfined
host-process runtime at all unless an operator sets `SHADOW_ALLOW_UNCONFINED=1`.

The reason a sandbox alone does not finish the job is that a sandbox has one output and it is
binary. It decides whether the work may run. It has nothing to say about whether the work may
*land*, and the work has to land eventually or the agent is useless. The moment you promote the
sandbox's output into the real workspace you are back at the original question with no more
information than you started with, and now the promotion step is the unguarded one. That promotion
step is exactly what `commit-protocol.ts` is: verify the bytes against the hashes captured with
them, append one atomic record, apply with a per-file re-stat and re-hash immediately before each
individual write.

What is left over: a sandbox cannot tell a good change from a bad one, so it cannot discard
selectively, and it cannot show a person a diff.

### A capability system

**We shipped one, so this is a concession rather than a rebuttal.**
`apps/server/src/capability-grants.ts` issues a per-agent grant of path globs, destinations and an
effect budget, revocable by an operator, and `apps/server/src/capability-grant-rule.ts` composes it
over the content policy with `stricterVerdict`, so authorization can add a review requirement and
can never mask a content-based discard.

Two things it does not do, both visible in the code. First, `DEFAULT_CAPABILITY_GRANT` at
`capability-grants.ts:50-52` is `allowedPathGlobs: ["**"]`, `allowedDestinations: ["*"]`,
`budget: Number.MAX_SAFE_INTEGER`. That default is deliberate and it is honest about what a
capability system costs: it constrains nothing until a human writes the scope, and the human who
writes it is guessing in advance which paths a coding task will need. Second, every hit the
capability rule can produce is `decision: "review"`, and the file says why in its own doc comment:
"This function never reads effect content." A capability system knows where a write went. It does
not know what was in it.

What is left over: scoping answers "was this agent allowed to touch that path", which is a real and
useful question, and leaves "should a file with these bytes in it exist" entirely open. The two
questions compose, which is why they are composed.

### A policy engine such as OPA

A declarative rule language with a proper evaluator and a test story is a better authoring surface
than 17 hand-written TypeScript modules, and if this system were being built for a second year the
rule bodies are the part most worth moving into one.

The gap is not the evaluator. It is the input document. A policy engine evaluates a policy against
whatever you hand it at a decision point, and the whole difficulty of this problem is that the
obvious decision point is before the action, where the only document available is a description of
what is *about* to happen. The 2026 incident table in the README is six rows of that description
being wrong. Everything expensive in this repository is the machinery that produces a document worth
evaluating: `capture.ts` walking the sealed copy and hashing what changed, `effect-classifier.ts`
assigning a class before any rule sees the effect, `policy-context.ts` giving a rule bounded reads
of before-state, added lines and real content, and the broker folding held network writes into the
same array at `transactional-runner.ts:342` (`confinement.outboundEffects`).

What is left over: substitute Rego for `rules/*.ts` and the design is unchanged, because the design
is the input document and the settle protocol, not the language the rules are written in.

### Static analysis or a linter

Genuinely better than this system at one whole family, and we say so in the README's Limitations:
the semantic backdoor, code that is correct-looking and wrong, an off-by-one on an authorization
boundary or a comparison that should be constant-time. There is no string to match. Of the 81
scenarios in that corpus family the policy discards none, holds 80 for a person and still commits 1
(`docs/CORPUS-REPORT.md`), so what it does on this family is defer rather than decide. A type
system, a test suite run inside the sealed copy and a differential execution are all stronger
instruments there than any content scanner, and the README names running the project's own tests
inside the sealed copy as the cost-raiser we did not build.

Where it stops is that a linter's world is source text. Three of the five members of `EffectKind` in
`apps/server/src/policy-types.ts:6` sit outside that world entirely, `delete`, `symlink` and
`outbound`, and a fourth, `modify`, sits outside it whenever the change is a permission bit, which
is why `capture.ts` puts mode in the change signature. A linter cannot see a file removed, a link
created that resolves outside the workspace, a POST held by the broker, or a chmod on a file whose
contents never changed. It also cannot see the pairing, which is what `rules/cross-effect.ts` and
`rules/net-to-exec.ts` exist for: a fetch in one file and an exec in another are each unremarkable,
and together they are the shape the README says every row of its incident table has, something the
agent wrote being trusted later by something else with no checkpoint in between.

And we pay the linter's characteristic cost anyway, which is worth admitting in the same breath. The
content scanners read shape as well as harm, and the repository measured it once: on 1,483 benign
twins that keep an attack's exact path and file type while doing a real developer's version of the
work, an earlier build of the policy discarded 18.41 percent against 1.30 percent on ordinary benign
material, and about three quarters of that gap was one missing allowlist word, leaving a genuine
shape-keying residual of 4.72 percent (`research/corpus-v2/TWINS-REPORT.md`). Read that as a dated
record rather than as a current rate. The report's own archival note says the twins harness is not in
this repository, that both arms of the comparison were taken against an earlier policy build, and
that nothing in the shipped 8,285-scenario corpus measures the same quantity against what ships
today. What ships today is a benign false-abort rate of 24 in 5,005, 0.5 percent.

What is left over: static analysis answers a question about meaning that this design does not
attempt, and this design answers a question about consequence that static analysis cannot reach.
Neither subsumes the other.

### Mandatory human review of every diff

Strictly stronger than this system per turn, and that is not in dispute. It fails on throughput and
on what a reviewer actually does under it.

The measured number is in the README's corpus table: against 5,005 benign scenarios the shipped
policy leaves **902 benign turns held for a human**, which is **18.0 percent**, and the README
calls that "the real cost and it is larger than the abort rate." Mandatory review is the same
product with that dial at 100 percent. Of the same 5,005, 24 are hard-discarded, a false-abort rate
of 0.5 percent, and the remaining 4,079 commit unattended, which is 81.5 percent of the benign set.
The unattended count did not move when the false aborts fell from 36 to 24: the twelve turns that
stopped being destroyed became held rather than committed, so the unattended share is unchanged and
what improved is the cost of the twelve, not the size of the queue.
Those 4,079 are ordinary work that a reviewer would approve without reading, and a queue whose
contents are mostly approve-without-reading is the condition under which review stops being review.

`apps/server/src/review-view.ts` was written from that failure. Its doc comment: "A path list is not
a review. An operator shown eight innocuous fixture paths approves the ninth without ever seeing
that it is a loader for an obfuscated payload (attacks r18 and r07)." So the review surface carries
each file's before and after, the class the effect was given, every rule that fired, and the hash the
approval has to carry back, and `transactional-runner.ts:555`
(`if (expectedEffectSetHash !== held.effectSetHash)`) refuses an approval whose hash names a
different set than the operator was shown. Human review is expensive to do properly, which is a
reason to spend it on the 17.8 percent rather than on everything.

What is left over: this design does not remove the human, it decides which turns are worth their
attention and builds a surface where their attention is worth something.

### A post hoc audit log

Also not an alternative, also already here, and the most engineering-heavy component in the
repository: `apps/server/src/journal.ts` with a hash chain, a keyed HMAC per record, signed Merkle
checkpoints and external anchoring.

An audit log alone answers the question after the answer stops being useful. The distinction that
matters is that in this design the ledger is *load-bearing at decision time* rather than
after it. `transactional-runner.ts:1008`, `attestsHeldTurn`, refuses to apply a held turn unless the
ledger still holds a self-consistent `turn.held` record for it, and the doc comment records the
measured failure that check exists for: "an approve returning ok on a turn the ledger no longer
mentioned, with the turn's bytes in the real workspace." `settleGate` at line 921 refuses every
settle while the chain does not verify, until an operator acknowledges the break by name. A log you
only read afterwards cannot do either of those things.

What is left over: nothing. The audit log is a component of this design, and the design is what makes
it more than a record.

### Prompt-level guardrails on the agent

The cheapest control and the one with the clearest published failure record. The README's incident
table is six rows of agent-side checks being bypassed by inputs the agent itself was made to read:
a repo-controlled `.claude/settings.json` setting `bypassPermissions` before the trust dialog
(CVE-2026-33068), PR text making the agent write `chat.tools.autoApprove` into
`.vscode/settings.json` (CVE-2025-53773), a deny rule silently dropped after 50 subcommands.

The structural problem is that a guardrail inside the agent is enforced by the thing it constrains,
using a channel the attacker also writes to. Hence the trust boundary in the README: capture, the
policy, the commit protocol, the journal and the review API are outside the container and are not
reachable from inside it. `rules/instruction-file.ts` is the case in miniature. Its doc comment says
a turn that edits `AGENTS.md` or `.cursorrules` "is writing the rules its successor will follow,
which no content scanner on ordinary source would ever look at." That is an effect this design sees
because it watches what was written, and a guardrail living in the same prompt cannot see at all.

What is left over: prompt-level guardrails reduce the rate at which the agent tries things, which is
worth having, and they are not a control because they are not enforced anywhere the agent cannot
reach.

### Git checkpointing, ghost commits, editor-level undo

The closest alternative and therefore the one where the distinction has to be sharpest. Snapshot the
workspace before the turn, snapshot after, offer an undo. Cheap, well understood, and it recovers
the workspace.

Three things it does not recover, each of which this design does. The agent's memory: the README's
prior-art section states that neither editor-level checkpoints nor a ghost-commit undo roll back the
conversation, and here the memory directory is sealed with the turn, promoted on commit and restored
otherwise, measured with three real `codex exec` turns where turn three resumes the thread and
carries the word taught in turn one and not the word taught in turn two. Network writes: a checkpoint
restores files after a POST has already been sent, and `apps/server/src/irreversibility.ts` is the
table that says which classes of effect a settle can undo, which it can only delay, and which are not
modelled at all. And the decision itself: an undo is a control only if somebody notices in time and
uses it, whereas this system's default for a violating turn is that it never landed.

What is left over: a checkpoint is a recovery mechanism. This is an admission-control mechanism that
happens to be built out of one.

---

## 3. Three decisions that are load bearing, and could have gone the other way

### 3.1 Judge after execution, against a sealed copy, rather than before

**What it buys.** The judge sees what happened instead of predicting it, so an attack spelled in a
way no rule anticipated still produces the same effects and gets the same verdict. The repository's
sharpest demonstration is `npm run evidence` scenario 2: the turn writes a git hook that pipes a
fetch into a shell and deletes a protected file, no rule in the repository is named after that
attack, it is discarded on `protected-asset-delete`, and the workspace digest either side of the
turn is identical. The corpus figure is the general version: attack miss rate 115 of 3,251, which is
3.5 percent (`docs/CORPUS-REPORT.md`, regenerated by `npm run corpus`). It is measured against an
earlier build of this repository's own policy at 1,848 of 3,161, 58.5 percent, on the 8,190
scenarios the corpus held then, with the same seeds and the same harness. That baseline is ours,
not the starter kit's: the pinned kit commit `8d0bd4f` contains no policy file at all, so there was
nothing of anyone else's to be better than.

**What it costs, stated as concretely as the benefit.**

*Every turn pays the seal, including the honest ones.* The measured cost on the copy path is in
`apps/server/src/bench/RESULTS.md` section 2: a no-op turn through `TransactionalRunner` on the copy
fallback runs 40.4 ms p50 at 50 files, 4,558 ms at 8,886 files, and 25,639 ms at 30,000 files,
roughly linear in file count. Section 2a of that file notes the bench measures that path without the
`seal` hook `runner-factory.ts` wires, and that the wired sealer walks the tree once more on a copy
host, so the figure is a lower bound on the shipped cost here rather than an overstatement of it.
The *seal itself* is flat on the overlay path, 4 ms at 30,000 files against 662 ms for `cp -a` on the
same Linux host (`research/OVERHEAD.md`, a bare `mount -t overlay` in
`research/spikes/snapshot-bench.sh`, not a turn). That removes the copy from the turn and not the
walks around it: `neutraliseOutboundLinks` and `snapshotStats` run unconditionally in `openTurn`
under both mechanisms (`transactional-runner.ts:812` and `:816` at this commit), and the stat walk
alone measured 562.5 ms at 30,000 files, so an overlay turn still pays two full tree walks before
`turn.begin`. The flat seal is the shape the design is betting on, and the turn cost on an overlay
host has not been measured from this repository. The bet is not currently collected either: the
README's Limitations say "Sealing is a copy on every host we ship to", because macOS answers
`not-linux` and the compose deployment answers `no-privilege`.

*A read is not an effect, and cannot be rolled back.* This is the hole in the middle of the design
and `apps/server/src/read-witness.ts` opens by naming it: "A turn that opens every credential in the
sealed view and writes nothing produces an EMPTY effect set, so the policy is handed nothing, every
rule abstains, and the turn commits under rule `none`. The transaction can roll a write back. It
cannot roll a read back, because what the turn learned has already left through the model channel,
which the broker allowlists."
The module narrows the hole rather than closing it. It records one bit per file per turn from access
times, so it sees which files were opened and neither how many times nor in what order, and it needs
a filesystem that keeps those times. It is wired into a turn at this commit: `openTurn` arms it as
the last thing the seal does, the runner collects it before capture, and the tally of files read
reaches both the journal line and the policy context
(`transactional-runner.ts:857`, `:335`, `:441`). It is observation only. No rule and no verdict
depends on a read, which is what the wiring lane's own corpus replay asserts
(`apps/server/src/read-witness-wiring.test.ts`), and the raw protected-read bit is not good enough to
decide anything yet. It fires on 48 of 48 attack turns and on 17 of the 48 benign turns in the read
witness probe set, 35.4 percent, and twelve of those seventeen are whole-tree scans such as
`grep -rn router .` that a coding agent runs all day (`docs/READ-WITNESS.md`). That is a
rate over 48 turns and not over the 5,005-scenario benign corpus, so it does not convert into a queue
size. What it does say is that the raw bit fires on benign work at about twice the rate at which the
whole shipped policy holds benign work, 902 of 5,005 or 18.0 percent, and a signal that noisy cannot
be turned into a rule without someone owning the price. Behind the selectivity gate it is 5 of 48,
10.4 percent, and that is the version worth pricing.
Under the overlay mechanism it is null rather than empty, because arming it there would write access
times into the user's real repository. So the platform can now say a turn read a credential and
wrote nothing. It still cannot undo that turn.

*Anything already sent stays sent.* `irreversibility.ts` classifies those effects `delay-only`: held
until the commit decision, and after it lands, "it cannot be recalled, only compensated." The README
says the same in one line: "A replayed write is delayed, not reversible."

*The information arrives one step too late for the model.* The agent finishes its turn believing it
succeeded. `withContainment` at `transactional-runner.ts:856` exists because of that: without it the
caller reads the agent's own "I completed the task and updated the files" on a turn that was
discarded.

**The other way.** Judging before execution costs nothing when the answer is no, needs no seal, no
capture and no rollback, and is what every system in the incident table does.

### 3.2 The effect set is the unit of judgement, not the syscall and not the diff

**What it buys.** Rules can reason about combinations, and a combination is the shape the README
says every row of its incident table has: something the agent wrote, trusted later by something
else. `rules/net-to-exec.ts` pairs a fetch with an exec; `rules/cross-effect.ts` judges
relationships between effects rather than effects one at a time. It also collapses three questions
into one: files, the agent's memory and held network writes arrive in the same array
(`transactional-runner.ts:342`), so a turn gets one verdict rather than three that have to be
reconciled. And the composition rule in `shadow-policy.ts` is that nothing short-circuits, all hits
are collected and the worst wins, so a `review` hit can never hide a `discard` hit behind it. That
was a real defect: the starter kit's policy returned on the first rule that fired, so whichever rule
happened to be listed first decided the turn.

**What it costs.**

*There is no partial commit.* One bad effect condemns the whole set. `npm run evidence` scenario 1
is the acceptance task: 53 proposed changes, all held on one rule, 0 applied until a human clicks.
The agent cannot be told "keep 52 of these", and the design has no vocabulary for that.

*The unit has to be bounded, and past the bound the answer is not a verdict.* `capture.ts:24-28`
caps a single effect at 8 MiB (`MAX_EFFECT_BYTES`) and a turn at 256 MiB (`MAX_TURN_BYTES`), and
`transactional-runner.ts:362-380` (`const capRule = captured.oversize.length`) refuses the turn on
`effect-too-large` or `turn-too-large` before the policy ever runs, because the policy
reads content and content is what a turn that wrote a file bigger than memory wants it to read. So a
turn can be too big to judge, and too big to judge means discarded unjudged.

*The audit record of a large set is truncated by design.* `JOURNAL_EFFECT_LIMIT` is 200
(`commit-protocol.ts:32`). A dependency install is tens of thousands of effects and the ledger
records 200 of them plus a count of what it dropped, because an unbounded list would append megabytes
to a hash-chained file per turn.

*Judging a set means judging content, and content-shaped rules read shape.* The twins measurement in
section 2 is the price, and its caveat travels with it: a 4.72 percent residual discard rate on
benign work that merely looks like an attack, after the one-word fix that accounted for three
quarters of the original gap, taken against an earlier build of the policy and not reproducible from
this repository.

**The other way.** Judging each syscall as it happens is what a seccomp filter or an LSM does. It
gives the finest possible granularity and the ability to refuse mid-turn, and it cannot see two
effects at once, which is the thing that made the combination rules possible.

### 3.3 The turn is the unit of commit

**What it buys.** It is the unit the agent, the operator and the conversation all already use, so the
rollback is coherent across all three halves: the workspace, the memory directory, and the held
outbound writes settle together at one point. It also reduces the atomicity requirement to something
achievable. The `commit-protocol.ts` header is explicit that this was a retreat from a claim that
could not be met: "An atomic single-rename commit against a live bind-mounted workspace does not
exist, so instead exactly one operation has to be atomic, and it is a single journal append."
Everything after that append is idempotent and replayable, which is what makes crash recovery a
replay rather than a repair.

**What it costs.**

*Granularity, again, but at a coarser grain.* A turn that does nine useful things and one prohibited
thing loses all ten, and there is no mechanism to split it.

*The seal is held open for the length of the turn, and the ground can move under it.* Concurrency is
optimistic: `conflictingPaths` compares each effect's path against the baseline signature taken at
seal, and a mismatch produces `turn.conflicted` with rule `workspace-changed-during-turn` and applies
nothing. A held turn waiting on a human is worse, because it can sit for hours, so `approve()`
re-runs the same check under `workspace-changed-during-review` and can refuse an approval a person
already gave.

*The three halves do not actually settle atomically together, and the design says so out loud.* The
README's step 5: a crash after the commit point finishes the file half idempotently at the next
start, and the memory promote and the broker's held writes cannot be finished because they lived in
the process that died. Recovery calls the same settle the live path calls and records
`confinementStateLost` rather than emitting a clean `turn.committed` over a transaction it only half
finished.

*A turn is also a concurrency unit.* `docs/ARCHITECTURE.md`: one agent can have only one active run.

**The other way.** Committing per tool call gives smaller blast radius and lets good work survive a
bad neighbour, at the cost of a rollback that can no longer restore the conversation, because the
conversation moved between the calls.

---

## 4. What is hackathon scale, and what would hold

The parts of this that are approximations are approximations of *scale and operations*, not of the
decision. The decision, the effect set, the settle protocol and the seam are the parts written to
survive.

### Approximations, named

| Thing | What ships | What it needs |
|---|---|---|
| Control-plane storage | `JsonStore` serializes writes and atomically replaces one JSON file, and `docs/ARCHITECTURE.md` says it "supports one process only" | a real database, or the control plane stays single node |
| The ledger | one append-only file, one writer per journal path per process plus a lock file against a second process (`transactional-runner.ts:191`, `Journal.acquire`) | rotation and an index. `bench/RESULTS.md` section 1c measures the judge phase reading the journal: 1.01 ms at 1,000 records, 51.42 ms at 50,000, 233.59 ms at 200,000. A ledger that only grows makes every turn slower forever |
| The seal | `cp -a` on every host we ship to, linear in file count, 25,639 ms p50 at 30,000 files | the overlay path, which is already written and probed for and whose seal alone measures flat at 4 ms, with the pre-`turn.begin` walks unchanged, but which macOS and the `cap_drop: ALL` compose deployment both decline |
| Journal signing key | a 0600 file (README Limitations). The code only touches the private key through `crypto.sign` | KMS or an enclave. The swap is small because of that indirection, and the record that creates the key states which form was used |
| Anchoring | periodic, git notes by default; Rekor and OpenTimestamps opt-in, "neither has been accepted by a public log from this machine" | a real external witness, and the window since the last anchor stays unprovable either way |
| Runtime image | a floating tag; "running by digest and journaling the digest is designed and not built" | one line and a journal field |
| Egress content control | plain-HTTP only. A CONNECT tunnel is allowlisted by exact host and port and nothing inside it is classified or held, so `npm publish` over https leaves unheld. Every allowed tunnel row says so on its face (`classified: false, reason: "tls-tunnel-not-classified"`) | terminating TLS with a CA in the runtime image, which is a different trust decision, not a bigger version of this one |
| Authorization defaults | `DEFAULT_CAPABILITY_GRANT` is `**`, `*`, `MAX_SAFE_INTEGER` | an operator writing scopes, and the honest question of whether they can |
| Rule-set growth | 18 rules. `bench/RESULTS.md` section 5 sweeps registry size and finds 4.03 ms p50 at 14 rules and 82.86 ms p50 at 224. The sweep's baseline row is a 14-rule registry and the shipped registry is 18 today, so read it as a shape and not as a current cost | the shape is roughly linear, so the registry is not free to grow without a budget |
| The evaluation itself | 8,285 scenarios, and the README states the mix is "set by how many variants each generator can produce rather than by how common the family is in the world" | real traffic. The macro average over the 15 graded families is 3.50 percent against a 3.54 percent micro average, and the macro over the ten families with n >= 50 is 2.59 percent. The first two are published in `report-metrics.json` as `attack_miss_macro_pct` and `attack_miss_pct`; the third is not published anywhere and is derived here, as the unweighted mean of `misses` over `n` for those ten families, 25.94 divided by 10 (the rounded `missRatePct` fields sum to 25.90 and give the same 2.59) |

### What holds

**The seam.** The whole system is a decorator on the starter kit's own `AgentRunner` interface,
composed once in `createRunner()` (`apps/server/src/runner-factory.ts`). The wrapped runner receives
a workspace path exactly as it always did and is never told it is wrapped
(`transactional-runner.ts:274`, `this.inner.run`). Nothing about that composition point gets harder
with more agents, more runtimes or a different provider, and it is why every agent created through
the stock CRUD flow is transactional with no per-agent configuration.

**The effect-set contract.** `policy-types.ts` is one file both halves build against, and it was
already extended once without breaking anything: `EffectRecord.resource` is optional and an absent
value means `file`, so adding a resource is one member of `ResourceKind` plus one settle
implementation and nothing else moves. `irreversibility.ts` is the table that says, per resource,
whether a settle is a true undo, a delay, or nothing, and it is committed as data so the review
panel, the caller-facing text and the docs read one source.

**Worst-verdict-wins with no short circuit.** A composition rule, not a rule set. It stays correct
at 18 rules and at 200, and it is the property that makes the registry safe to extend by people who
have not read the other 16 modules.

**The commit protocol.** One atomic operation, a single journal append, with everything after it
idempotent and replayable. That is a property of the protocol rather than of its scale, and it is the
reason a `kill -9` mid-commit is a recoverable state rather than a corrupt one.

**Naming the cost.** The repository publishes the containment rate, the false-abort rate, the
human-ask rate and the escapes by name, and keeps the uncorrected 18.41 percent twins figure beside
its correction and beside the note that says which build it was taken on. That is a habit rather
than a mechanism, and it is the one most likely to decide whether any of the above survives contact
with a real deployment.

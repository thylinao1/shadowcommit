# What the guarantee costs

Every turn in Shadow Commit is a transaction: the workspace is sealed, the agent runs against the
sealed copy, the changes are captured as an effect set, the policy judges them, and the turn is
committed or discarded. This page measures what that machinery costs, because a containment story
without numbers is a claim.

**Every figure below states the command that produced it and the machine it ran on.** Nothing here
is estimated.

A host line turned out to be necessary and not sufficient. Re-running two of the scripts on the
machine their figures were published from returned the journal's byte count within two bytes per
turn and the timing constants 1.4x to 2.1x higher, because the machine was busier.

That two-byte gap was then the page's own worst example of the rule it is arguing for. It was read
here as a size that reproduced "exactly", and read further down the page as a difference between two
hosts, and it was neither: `measure-journal.mjs` used to stat the journal file before `settle()`, so
on a fast filesystem the stat beat the last 465-byte `anchor.ok` record to disk and on a slow one it
did not. The published 784 bytes per turn was a harness artifact, not a property of the record
format. The script now settles first, and the settled size is **786 bytes per turn on six
consecutive runs** (macOS arm64, node v22.21.0). So the rule survives, with the qualifier the page
had not earned: a size or a shape is a property of the code and travels, an absolute
millisecond is a property of a machine at a moment and does not, and a size still has to be measured
more than once before it is quoted to the byte, because a harness can put a race in front of one.
Any claim resting on a difference smaller than the measured spread needs its dispersion published.
`research/overhead/AUDIT.md` audits every number on this page against those rules and records what
it changed; the corrections it made are marked in place below.

## Two mechanisms, and which one a shipped deployment actually gets

The seal has two mechanisms and which one runs is decided by the host and by what the control-plane
process is allowed to do, so a single number would be misleading in whichever direction it was
measured.

> **Corrected 31 Aug 2026 by the claims audit, `research/overhead/AUDIT.md` section 1.** This
> section used to open "On Linux the product mounts an overlay" and end by calling the overlay the
> "path the product actually takes on Linux". The wiring half of that is true and was checked again:
> `runner-factory.ts:925-943` composes the sealer with `releaseHookWired: true` and spreads
> `seal: sealer.seal` into the runner. The reachability half was wrong. **No configuration this
> repository ships or documents reaches the overlay**, and `README.md` said so while this page said
> the opposite. The figures below are correct and they measure a mechanism, not a deployment. The
> condition is now stated with them instead of being left for a reader to discover.

**The overlay needs the control plane to be able to mount.** `overlay-sealer.ts:466` answers
`not-linux` off Linux before probing anything. On Linux, `capability()` tries `mount -t overlay` as
the server process and only adds a `sudo -n` candidate when `SHADOW_SEAL_ALLOW_SUDO=1`
(`overlay-sealer.ts:419`), which nothing in this repository sets. So in practice the overlay wants
root or `CAP_SYS_ADMIN`. What each documented way of running the product gets:

| How it is run | Sealer's answer | Status | Why |
|---|---|---|---|
| `npm run poc` on the demo Mac | `copy`, reason `not-linux` | measured, twice | `overlay-sealer.ts:466` |
| `docker compose up` | `copy`, reason `no-privilege` | read from source, not observed | `docker-compose.yml:43-45`, `cap_drop: ALL` and `no-new-privileges:true` |
| `npm run poc` on Linux as an ordinary user | `copy`, reason `no-privilege` | read from source, not observed | no `CAP_SYS_ADMIN`, and sudo is not enabled by default |
| Linux as root, or `SHADOW_SEAL_ALLOW_SUDO=1` with passwordless sudo | `overlay` | read from source, not observed | the configuration the figures below were taken on |

**The two measurements settle row 1 and no other row.** The shipped sealer composed exactly as
`runner-factory.ts` composes it, on the demo machine, returns `copy` with `reason: "not-linux"`. And
the committed demo pack carries twelve `seal.fallback` records across seven step files, five
distinct run ids, and no `seal.mounted` anywhere in `evidence/`. The sealer records its choice on
every turn, so this is checkable without trusting either page:

```
$ grep -ho '"kind": "seal\.fallback"' evidence/demo-run/steps/*.json | wc -l
12
$ grep -rl "seal.mounted" evidence/
(no output)
```

**Status describes the "Sealer's answer" column, and rows 2 to 4 are read, not run.** Row 2 is read
off `docker-compose.yml:43-45`, rows 3 and 4 off `overlay-sealer.ts:466`, `overlay-sealer.ts:485`
and the `SHADOW_SEAL_ALLOW_SUDO` default at `overlay-sealer.ts:419`. No Linux host has been watched
answering `no-privilege` or `overlay` from this repository's sealer, which is the same gap
`research/overhead/AUDIT.md` records under "What this audit did not do". One `docker compose up` and
one turn settles rows 2 and 3, and the answer lands on that turn's `turn.begin` record, so it is an
afternoon of work rather than an argument. The overlay timings at the end of this page were taken
with `sudo bash research/spikes/snapshot-bench.sh`, which mounts an overlay directly; that measures
the mechanism, not the sealer choosing it.

**So the copy path is the shipped path, and everything below the mechanism table is that path.**

| host | mechanism | seal at 30,000 files | seal + enumerate |
|---|---|---|---|
| Linux 6.6.87.2 (WSL2), Ubuntu 24.04.4, 24 CPUs, ext4, **as root** | overlay | **4 ms** | **8 ms** |
| same host | `cp -a` | 662 ms | 918 ms |

Measured with a reproducible harness, `research/spikes/snapshot-bench.sh`, medians of
three repetitions; full figures in `research/spikes/SPIKE-D-SNAPSHOT-ARTIFACTS.md`, published beside
this page. Two things that table is not. It needs root, so it is not a shipped configuration. And
its `enumerate` column is `find "$upper" | wc -l` on the overlay branch and `diff -rq` on the copy
branch, neither of which is `captureEffects`: the real capture does an `lstat` per entry, resolves
symlinks against the real tree, and expands whiteouts through the real tree. Both stand-ins have the
right shape, which is what the size-independence claim rests on, and neither is the product's cost.

**The shape is the finding, not the ratio.** The overlay seal is flat at 3 to 4 ms across a
six-hundred-fold increase in tree size, because a mount does not touch the tree. `cp -a` grows
linearly, because it copies every file. That is a real and reproducible property of the two
mechanisms, confirmed on a second independent Linux host at the end of this page.

**What does not follow, and used to be claimed here, is that a turn is flat.** This section
concluded that the containment guarantee costs a few milliseconds per turn independent of repository
size. It does not, on either mechanism, because the mount is not the only thing a turn pays for. Two
operations in `TransactionalRunner.openTurn` (`apps/server/src/transactional-runner.ts`) are
unconditional and both are O(files). Find them by content, because line numbers move and these two
moved during integration:

```
await this.neutraliseOutboundLinks(request.workspacePath, merged);   openTurn, :812 at 2c95041 (:767 at d10213f)
const opened = await snapshotStats(request.workspacePath);           openTurn, :816 at 2c95041 (:771 at d10213f)
```

Grepping the two call strings inside `openTurn` is the check that keeps working: it fails loudly if
either one ever becomes conditional, which is the thing this paragraph actually claims.

`neutraliseOutboundLinks` is a recursive `readdir` of `merged`, and under an overlay `merged` is the
mount, so reading it reads the whole tree. `snapshotStats` stats every path in the real workspace.
An overlay removes the `cp -a`, removes the hashed sealed signature (`emptySnapshot()` on any
non-copy mechanism, `transactional-runner.ts:837` at 2c95041) and shrinks capture to the upper layer
(`captureEffects`, `capture.ts:270`). It removes neither of those two. On the demo Mac the stat-only
walk alone is **562.5 ms at 30,000 files**
(`apps/server/src/bench/results/turn-open-scaling.jsonl`, component
`snapshotStats-baseline-stat-only`, p50), on a path this page described as costing 4 ms.

The honest version of the claim: **the seal mechanism is size-independent under an overlay and
linear under a copy, and the turn around it is linear under both.**
`apps/server/src/bench/RESULTS.md` section 2 measures the whole thing on the shipped copy path, and
its harness computes the verdict rather than asserting it: turn-open p50 grew 634.9x from 50 to
30,000 files, against a 600x increase in file count.

Everything below this line is the macOS copy path on an Apple M2 MacBook Air, 8 GB, macOS 14.6,
Node v22.21.0. The mechanism is the shipped one. The constant is this machine's: the same code on
NTFS measured about 8x worse per file, later on this page, and the copy path is the mechanism on
that host too.

## Seal and capture, against workspace size

Real `snapshotStats` and `captureEffects`, copy mechanism, 4 KiB files, one file changed per turn.

```
files    seal(ms)  capture(ms)  ms/file
50            8.3          3.8    0.242
200          12.0         11.3    0.117
800          55.2         58.5    0.142
2000        142.6        140.0    0.141
5000        377.7        367.7    0.149
```

Command: `node research/overhead/measure-seal-capture.mjs`, run from the repository root after
`npm run build -w @launchpad/server`. The script is committed beside this page so the numbers can be
reproduced rather than trusted.

**Linear at about 0.14 ms per file from 200 files upward**, and the two halves cost the same, which
is expected: both walk the tree and stat every entry, and the seal additionally hashes. The 50-file
row is higher per file because a fixed cost is spread over fewer files, not because small
workspaces are worse.

**A 5,000 file workspace pays about 0.75 seconds** for seal plus capture together.

## Policy judgement, against effect-set size

**This table is superseded. It was produced against `basicContext`, a test stand-in, and it is kept
here with its correction rather than deleted so the record shows what was claimed.** The correction
section below explains how it was found; the numbers a reader should use are immediately under it.

```
SUPERSEDED, measured against basicContext (a stub: contentOf returns a 13-byte constant)
effects   judge(ms)   ms/effect
1               4.3       4.339
1000           18.0       0.018
```

Measured again against the real `buildPolicyContext` over a real workspace, on the same host, after
the redundant-read defect that measurement exposed was fixed:

```
effects   judge(ms)   ms/effect
1               0.2       0.151
10              0.8       0.080
50              2.3       0.046
200             8.3       0.041
1000           38.6       0.039
```

Command: `node research/overhead/measure-judge-context.mjs`, which runs both contexts in one pass so
the difference is a measured number rather than an argument.

**A thousand-effect turn is judged in 38.6 ms**, and cost per effect still falls, from 0.151 ms to
0.039 ms. That claim was in the original table and was accidentally right: the stub made it true by
never reading anything, and one read per path per turn makes it true for a reason. Before the fix the
same real-context measurement was 804 ms at a thousand effects and FLAT at 0.804 ms per effect,
because four rules each asked for the same file's added lines and each ask read both sides off disk.

## Journal growth and append cost

Real `Journal`, two records per turn (`turn.committing` and `turn.committed`), which is the shape an
ordinary committed turn writes. Command: `node research/overhead/measure-journal.mjs`.

```
200 turns, 400 records
bytes per turn      786
append ms per turn  0.301

1,000 turns    ->  0.7 MiB
10,000 turns   ->  7.5 MiB
100,000 turns  -> 75.0 MiB
```

> **Corrected 31 Aug 2026. This table used to read 784 bytes per turn and it was a harness
> artifact.** `measure-journal.mjs` stat-ed the journal file before `await j.settle()`, so the size
> was read while the last `anchor.ok` record was still in flight. Measured on the demo Mac: 411
> lines and 156,731 bytes before `settle()`, 412 lines and 157,196 bytes after, a difference of one
> 465-byte record, which is 783.7 against 786.0 bytes per turn over 200 turns. The stat now runs
> after `settle()` and the script returned 786 on six consecutive runs, with 784 on six consecutive
> runs before the change: the flip is deterministic per code path on one host, not run-to-run noise.
> This page used to explain the 784-against-786 gap between its two hosts as "a record's worth of
> path length". Path length does reach the journal, but it is worth single bytes across the whole
> file (renaming the temp directory prefix by one character moved the 200-turn total by 5 bytes),
> and it cannot produce a 2 bytes-per-turn step. One whole record can, and that is what it was. The
> record format did not change; the number is now the size of a settled journal instead of one
> caught mid-write.

A hash-chained, signed, append-only record of every agent action costs **786 bytes and 0.3 ms per
turn**. A hundred thousand turns is 75 MiB. The byte count is the one figure on this page that has
reproduced on two hosts and two filesystems; the 0.3 ms is this machine's, and the same script on
NTFS measured 1.045 ms.

## What this adds up to, honestly

> **Corrected 31 Aug 2026 by the claims audit, `research/overhead/AUDIT.md` section 3.** This block
> carried `policy judgement (1,000 effects) 18 ms`, which is the stub figure the correction section
> below withdraws. The table was corrected and the bottom line was not, so the number a reader took
> away was the retracted one. It is 38.6 ms. The seal line also needed a term count: it is two of
> the five size-dependent operations a copy-path turn pays, not all of them.

For a realistic workspace and an ordinary turn:

```
seal + capture (5,000 files)   ~750 ms     two of five terms, see below
policy judgement (1,000 effects)  38.6 ms  real context, not the stub
journal append                   0.3 ms
```

The seal line is one hashed `snapshotStats` plus one `captureEffects`. A copy-path turn also pays
the `cp -a` itself, the link-neutralisation walk and the stat-only baseline walk, and the last two
are paid under an overlay as well. So read it as a floor for the machinery, not a total. Measured
end to end on the same machine, a no-op turn on a 8,886-file workspace is 4,558 ms p50
(`apps/server/src/bench/results/turn-open-scaling.jsonl`); that figure uses a different fixture
(roughly 64-byte files against 4 KiB here), so it is the term count rather than the constant that
carries across.

**That is the part worth being careful about**: a real turn also starts a container and makes at
least one model call, and both of those dominate the per-effect and per-record costs by a wide
margin. The honest claim is not that the transaction is fast in absolute terms, and it is not that
it is free of repository size, because it is not. It is that **the per-effect and per-record
machinery is small next to what a turn already costs**, and that the size-dependent part is the
tree walking, which is where any optimisation belongs.

## What is NOT measured here, and who should

Two things this page does not cover, listed so nobody reads it as complete:

- **Broker latency** on held and allowed calls. Needs a running broker and a real egress path.
- **Concurrency**, meaning where throughput degrades as simultaneous turns increase. Needs a
  multi-turn harness and enough memory to run one; this machine has 8 GB and one heavy job at a
  time is the standing constraint.

Both belong to the overhead workstream, tracked in the team's research repository as
an internal follow-up note that is not part of this repository. This page covers what
could be measured without a running container: the three cost curves on this machine, and the Linux overlay figures from a host
that had already been measured.

---

# Correction and extension, 30 Aug 2026

Measured on a second, independent host, because every figure above this line came from one machine and
three of them do not survive contact with a second one. Two are corrections to numbers published
above, one is a defect in the page's own reproduction instructions, and one is a fix to the product
that the measurement found. The order is worst first.

**Host for everything below:** Windows 11 (10.0.26200), x64, 12 CPUs, 34 GB, NTFS, Node v24.19.0,
kit at `900eae3` plus the change described in section 3. Absolute milliseconds on this host are not
comparable to the M2 Mac's; the shapes are, and the shapes are what this section corrects.

## 1. The policy table above measures a stub, not a turn

> **Resolved.** The defect this section found was fixed in `da1f999` (one read per path per turn,
> `policy-context.ts`), and the policy table above has been re-measured against the real context. A
> thousand-effect turn went from 804 ms to 38.6 ms on the macOS host and from 5,045 ms to 49.6 ms on
> the Windows host. This section is kept because how the error was found matters more than the
> number it replaced, and because the claim it corrects was published for a day.

`measure-seal-capture.mjs` judges its effect sets against `basicContext` (`policy-types.ts:104`),
which is a test stand-in. The page describes the result as "real composed `defaultPolicy`, all
fifteen rules, ordinary source paths" and does not say what the context is. Three of that helper's
defaults delete work every real turn does:

| field | `basicContext` | a real `buildPolicyContext` |
|---|---|---|
| `contentOf` | returns a 13-byte constant | reads the file from the shadow, bounded by `limits.maxScanBytes` |
| `realContentOf` | returns `null` | reads the real file, so `addedLinesOf` diffs instead of returning the whole body |
| `protectedPaths` | `[]`, so every pattern test is a `.some()` over nothing | always carries at least `DEFAULT_PROTECTED_PATHS` |

Same rules, same effect sets, same host, one variable, five repetitions, medians:

```
effects   stub(ms)   real(ms)   ratio   stub ms/eff   real ms/eff
1              0.2        5.5    34.0x         0.161         5.474
10             0.7       55.7    81.4x         0.068         5.571
50             1.7      257.3   148.6x         0.035         5.147
200            4.6     1009.4   217.3x         0.023         5.047
1000          21.2     5045.1   238.0x         0.021         5.045
```

Command: `node research/overhead/measure-judge-context.mjs`, from the repository root after
`npm run build -w @launchpad/server`.

**Two published claims do not survive this.** The page says "cost per effect **falls** as the set
grows, from 4.3 ms for a single effect to 0.018 ms at a thousand" and "a turn touching a thousand
files is judged in 18 ms." Against a real context the cost per effect does not fall. It is flat at
about 5 ms, because each effect costs a real file read that no larger effect set amortises away, and
a thousand-effect turn was judged in **5,045 ms**, not 18 ms.

The falling curve was an artifact of the stand-in: with a constant for content there is no per-effect
work left, so only the fixed setup cost is spread. That is a property of the stub, not of the policy.

## 2. What the reads were, and the fix

The flat 5 ms per effect was not the cost of judging. It was the same file being read repeatedly.
Instrumenting a ten-effect turn, per effect:

```
contentOf       1 call
addedLinesOf    4 calls     <- four rules each ask what the file gained
realContentOf   1.1 calls
```

`addedLinesOf` was not memoised, and each call read **both** sides off disk and re-split them into
lines. So one effect cost about ten file reads and four identical line-diffs, and the redundancy grew
with the effect set.

Nothing needed the repetition. A context is built once per turn and every rule judging that turn
shares it; the shadow tree and the real tree are both frozen for the whole of judgement, because the
agent has finished and nothing writes to either until the commit or discard. A second read cannot
return anything different from the first.

`policy-context.ts` now memoises the three readers per path per turn, caching the promise rather than
the value so two rules asking at once share one read. After the fix, same command, same host:

```
effects   stub(ms)   real(ms)   ratio   real ms/eff
1              0.2        0.2     0.9x        0.182
10             0.4        1.0     2.5x        0.103
50             2.3        3.4     1.5x        0.069
200            4.3       10.1     2.4x        0.051
1000          20.6       49.6     2.4x        0.050
```

**A thousand-effect turn: 5,045 ms before, 49.6 ms after, a 102x reduction**, and per-effect cost
falls to about 0.05 ms. The honest headline for this table is now "a turn touching a thousand files
is judged in about 50 ms on this host", which is a real number against a real context rather than a
smaller one against a stand-in.

Pinned by `policy-context.caching.test.ts`. Revert-proof: with the production change reverted and the
tests kept, the read-count test fails `expected 5 to be 1` and the snapshot test fails because the
reader returns the file's new bytes. The third test, which checks that two different paths are still
told apart, passes either way, which is the negative case the fix must not break.

## 3. The reproduction command on this page does not run

`research/OVERHEAD.md` says the measurement script is "committed beside this page so the numbers can
be reproduced rather than trusted". Run exactly as the page instructs, on a checkout that is not the
author's:

```
$ node research/overhead/measure-seal-capture.mjs
Error [ERR_MODULE_NOT_FOUND]: Cannot find module
  '...\Users\maksimsilchenko\Developer\CodeJam\apps\server\dist\capture.js'
```

Line 3 of the script is an absolute path into one person's home directory. The page's strongest
sentence is the one that is false: as committed, the numbers can only be reproduced by their author.
This is the same shape as the `~/Developer/CodeJam` default in `verify-claims.mjs` (in the team's
research repository, not this one),
which silently skips two checks and still prints "every published number reproduces from the
committed data" on every machine but one.

Both scripts now resolve `dist` from their own location, so the command the page prints runs from
any checkout. Re-run here after the fix, which is also the first time the seal and capture table has
a second host to sit beside:

```
files    seal(ms)  capture(ms)  ms/file      ms/file on the M2 Mac
50           33.1         31.0    1.282                      0.242
200         114.7        126.8    1.208                      0.117
800         513.2        442.7    1.195                      0.142
2000       1132.7       1174.7    1.154                      0.141
5000       2964.3       2817.8    1.156                      0.149
```

Linear on both hosts from 200 files up, which is the shape claim the page makes and it survives.
The constant does not: seal plus capture costs about **8x more per file on NTFS than on APFS**
(1.16 ms against 0.14 ms). A 5,000 file workspace pays about 0.75 s on the Mac and about 5.8 s here.
Neither host is the shipped Linux overlay path, which the page reports as flat at 3 to 4 ms.

`measure-journal.mjs` carried the same hardcoded path and has the same fix. With it, the journal
figure reproduces independently on a second host and a second filesystem: **786 bytes per turn
here**, against the 784 the page published at the time.

> **Corrected 31 Aug 2026, and the correction goes the other way from the one this paragraph made.**
> This read "a difference of 0.3 percent, which is a record's worth of path length and not a
> disagreement". The two hosts never disagreed and it was not path length. 786 is the settled size
> everywhere; 784 was what the harness reported when it stat-ed the file before the last
> `anchor.ok` record landed, which the demo Mac did on every run and this NTFS host did on none. The
> script now settles first and both hosts report 786. See the correction in "Journal growth and
> append cost" above for the byte-level reproduction.

The append cost does not travel: 1.045 ms per turn here against 0.301 ms, because this filesystem is
slower to flush. Of the three tables on this page, the journal size is the one a reader can carry to
their own machine.

## 4. What is still not measured, and what a second host did settle

Still not measured, unchanged from the page above: **broker latency** on held and allowed calls,
and **the overlay path**. Both need a container; this host has no Docker and no WSL, so neither was
attempted rather than estimated.

> **Both measured since, on a Linux host, in the section at the end of this page.** The broker turned
> out not to need a container at all. Docker and WSL2 were installed on this machine to close it.


Settled by this host that one machine could not settle: the repo-size term is **linear on NTFS as
well as APFS**, so the shape is a property of the code and not of a filesystem. `snapshotStats` over
a workspace, medians, from `apps/server/src/bench/results/context-scaling.jsonl` (the path this
line used to give, `research/overhead/context-scaling.jsonl`, is not where the data lives; corrected
31 Aug 2026 by the claims audit, which also recomputed every cell below from that file and found
them exact):

```
files    walk(ms)   walk+hash(ms)   context(ms)
100           9.2            60.0          0.30
500          23.0           274.7          0.65
2000         68.5          1059.5          1.95
8000        260.9          4174.0          5.28
30000       989.6         15976.4         20.84
```

From 2,000 to 30,000 files, a 15x increase: the plain walk grows 14.4x and the hashing walk 15.1x.
Linear on both.

This also splits a term the perf lane named but attributed to one place. `RESULTS.md` section 1d says
`buildPolicyContext` "walks every real inode of the workspace on every turn". It does not walk
anything: it iterates the `realInodes` map it is handed (`for (const [rel, ino] of realInodes)`,
`policy-context.ts:772` at `2c95041`). The walking is `snapshotStats`, defined at `capture.ts:197`
and called in `openTurn` at `transactional-runner.ts:816`, and again at `:836` with hashing on
(`:771` and `:791` at `d10213f`). The two halves differ by about **48x** at 30,000 files, so a
reader who treats them as one term predicts the wrong number: the filesystem walks are 16.97 s of
the 16.99 s, and the loop 1d names is 20.8 ms of it.

---

# The two that needed Linux, measured, 30 Aug 2026

Both items this page has carried as "not measured" since it was written are measured here. The
reason given for both was that they need a container and a Linux host. One of them turned out not to
need a container at all.

**Host:** Ubuntu 24.04.4 LTS under WSL2, kernel 6.18.33.2-microsoft-standard-WSL2, x64, 12 CPUs,
15.6 GB, **ext4**, Node v22.23.2, Docker Engine 29.7.2, kit at `afa7dbc`. Deliberately 24.04,
because that is what CI runs and what the Linux figures already on this page were measured on, so a
number from here is comparable to a number from there. The kit is checked out inside the WSL
filesystem, not under `/mnt`: an overlay upperdir cannot be created on drvfs, and the seal would
silently fall back to `cp -a`, which is the thing being measured against.

## Broker latency, on allowed, held and denied calls

This did not need a container. `broker/server.mjs` is dependency-free ESM and its own docblock says
it is "started in-process by the tests with no container at all", which is how this runs it.
In-process is also the more honest measurement for the question the page asks. A container adds a
fixed network hop that belongs to Docker, and folding the two together would charge the broker with
someone else's milliseconds.

The upstream is in-process on loopback and answers immediately, so what is timed is the broker's
decision and forwarding, not the internet. 300 repetitions after 30 warmup, medians and tails:

```
channel                         p50(ms)  p95(ms)  p99(ms)   max(ms)
direct to upstream                0.258    0.442    0.625     0.781
allowed GET through broker        0.485    0.748    0.962     1.061
allowed POST (read-like)          0.480    0.767    0.914     0.972
HELD POST (write-like)            0.334    0.561    0.853     1.330
DENIED, not allowlisted           0.183    0.270    0.336     0.829
CONNECT tunnel, allowed           0.510    0.713    1.045     1.115
```

Added against the direct call, p50: allowed GET **+0.227 ms**, allowed POST **+0.222 ms**, held
**+0.076 ms**, denied **-0.075 ms**.

The channels did what they are supposed to, which is checked rather than assumed: the broker's own
decision log recorded 660 `read-like/LIVE`, 330 `write-like/HELD`, 330 `egress/DENY` and 180
`tunnel/ALLOW`, and 330 held records were written to the held journal.

**Read the absolute number, not the ratio.** An allowed call through the broker takes 1.88x the time
of the direct call, and that ratio is the most hostile way to state it: the upstream here is
in-process and answers in a quarter of a millisecond, so the broker's fixed cost is compared against
almost nothing. The number that transfers is the added **0.23 ms**, and a real outbound call is to
something across a network, which is tens to hundreds of milliseconds. Against that, the guarantee
costs about a fifth of one percent of the call it is guarding.

Two results used to be stated here as findings that run against intuition. **Both are withdrawn as
findings and kept as observations, 31 Aug 2026, by the claims audit
(`research/overhead/AUDIT.md` section 5), which re-ran the committed script five times on the macOS
host and could not reproduce the sign of either, and by two later re-verifications that took the
total to eleven runs and found the denied sign flipping with host load rather than settling.** They
are differences of a few tens of microseconds, and the run-to-run spread of the same quantity on one
machine is an order of magnitude wider than the differences the argument was reading.

Added latency against the direct call, p50, in milliseconds, published row against eleven re-runs on
a macOS arm64 8-CPU host:

```
run            allowed GET   HELD POST   DENIED     node
published            0.067       0.100   -0.034     v22.21.0
1                    0.382       0.064   -0.134     v20.17.0
2                    0.590       0.555    0.016     v20.17.0
3                    0.676       0.405    0.052     v20.17.0
4                    0.305       0.368    0.097     v22.21.0
5                    0.223       0.508    0.002     v22.21.0
6                    0.083       0.107   -0.027     v22.21.0
7                    0.074       0.092   -0.037     v22.21.0
8                    0.091       0.114   -0.018     v22.21.0
9                        -           -   -0.040     v20.17.0
10                       -           -   -0.017     v20.17.0
11                       -           -   -0.205     v20.17.0
```

Runs 1 to 5 are the claims audit's, 31 Aug. Runs 6 to 8 and 9 to 11 are two later re-verifications
on the same macOS host, added because five runs turned out not to be enough to settle a sign; 9 to
11 reported the denied channel only, hence the dashes.

- **"A denied call is faster than no broker at all" is an observation about a host at a moment, not
  a property.** It was published as measured on both hosts and stated as a general property. Across
  the eleven re-runs above the denied channel measured faster than the direct call seven times and
  slower four times, and the four slower ones are all in the block taken while the machine was
  running five concurrent workloads. On a host whose direct-call p50 matched the published run
  (0.106 ms on run 6, against 0.112 ms published and 0.221 to 0.362 ms on runs 1 to 5) it measured
  faster on every attempt. So the sign is not stable across load, and no run of this harness
  resolves a 0.034 ms difference: `allowed GET` alone ranges 0.074 to 0.676 ms across the same
  eleven runs, twenty times the gap being read. What survives is the mechanism, which is not in
  doubt: a denied call is refused at the broker without any upstream hop, so it does no forwarding
  work. What is withdrawn is the general claim, in either direction.
- **Whether a held call is cheaper than an allowed one is not resolvable at this precision.** The
  ordering held in four re-runs of runs 1 to 5, so it is not falsified, but the published gap the
  argument rests on is 0.033 ms while `allowed GET` alone ranged from 0.223 to 0.676 ms across those
  five runs, a spread roughly fourteen times the gap. The same channels reached 88.5 ms and 126.0 ms
  at their maxima. The mechanism stands and is worth keeping: holding is not extra work on top of
  forwarding, it is work INSTEAD of forwarding, so which side wins depends on whether the upstream
  round trip costs more than the hold. The mechanism predicts that the ordering is host-dependent.
  It does not license reading a specific host's sign off a 0.03 ms difference.

Runs 1 to 5 were done on a machine running five concurrent workloads, and its direct-call p50 was
0.221 to 0.362 ms against the 0.112 ms the published run saw, so it is a busier host than the one
that produced the published row. That is the point rather than an excuse: a result that inverts
under load on the same machine is not a property of a host, and this page presented it as one.

**The figure that survives all of this is the one to quote**: the added cost is a fraction of a
millisecond against a real outbound call of tens to hundreds, so the guarantee costs about a fifth
of one percent of the call it is guarding. That claim has an order of magnitude of headroom over the
noise. The ordering claims did not.

Command: `node research/overhead/measure-broker.mjs`, from the repository root. Run it more than
once.

## The overlay seal, on a second Linux host

The page carries `linux-wsl2-ext4: overlay seal flat at 3 to 4 ms across 50 to 30,000 files`,
measured on a 24 CPU host. Reproduced here on an independent 12 CPU WSL2 ext4 host with
the same committed harness, `research/spikes/snapshot-bench.sh`, three repetitions per cell:

```
files    overlay seal   overlay enumerate   cp -a seal   cp -a enumerate
50            3 ms            3 ms             26 ms          6 ms
8886          3 ms            3 ms            377 ms        145 ms
30000         3 ms            3 ms          1,373 ms        483 ms
```

**The load-bearing claim reproduces exactly.** The overlay seal is flat at 3 ms across a six-hundred
fold increase in tree size, on a host that is not the one that first measured it. A mount does not
touch the tree, and that is now a property two machines agree on rather than one machine's reading.

**The copy fallback's constant does not travel.** At 30,000 files this host pays 1,373 ms where the
published host pays 662 ms, and at 50 files 26 ms against 7 ms: roughly **2x worse throughout**,
same shape. So the linear growth of `cp -a` is the code's, and any absolute `cp -a` millisecond
figure belongs to the machine that produced it. The overlay number is the one safe to quote without
naming a host; the copy number is not.

Command: `sudo bash research/spikes/snapshot-bench.sh > snapshot-bench.jsonl`.

## What is left

Nothing on this page is now marked "not measured" for want of a container or a Linux host. What
remains unmeasured is narrower and worth naming so the page cannot be read as complete:

- Broker latency **through a real container**, on the per-run internal network, rather than
  in-process. The in-process figure isolates the broker's decision; the container figure would add
  Docker's hop, which is a different question and a fair one to ask.
- Repo size and concurrency **together**, which `RESULTS.md` already names as very likely worse than
  either axis alone.
- The overlay path on **native** Linux rather than WSL2. WSL2 is a real kernel with real overlayfs,
  but it is not bare metal.

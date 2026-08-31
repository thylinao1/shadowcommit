# Audit: is every performance number we publish honest about what it measured, and on what

One question, asked of every millisecond, byte and percentage in the repository: **what code ran,
on what machine, against what**. A figure that cannot answer all three is not a measurement, it is
a number with a unit attached.

Audited 30 to 31 Aug 2026 at `submission/main` = `f6b14bb`, on an Apple M2 MacBook Air, 8 GB,
macOS 14.6 (darwin 23.6.0 arm64, 8 CPUs), which is the demo machine, running five concurrent lanes
throughout. That load is stated because it is load-bearing for finding 9. Every command below
was run from the repository root and its output is quoted rather than summarised. Where a number
here disagrees with a published one,
the disagreement is the finding and the command that produced it is beside it.

**Every line number in this audit is as of `f6b14bb`.** Other lanes are editing
`transactional-runner.ts` in the shared tree while this is being written, so the source citations
use `git show f6b14bb:<path>` rather than a bare path. The two unconditional calls in finding 2, for
instance, are at `:767` and `:771` in `f6b14bb` and at `:812` and `:816` in the working tree as this
was written. Grep for the call rather than trusting the number if the two disagree.

The rules this audit applies, in order of how much damage they catch:

1. **Name the code.** A harness that stands a stub where the product puts a real thing measures the
   stub. This repository has already been bitten once by exactly that (`basicContext`, section 3
   below), so every harness is checked for it rather than trusted.
2. **Name the machine.** A `cp -a` figure is a statement about a filesystem and a virtualisation
   layer. The same work has already been measured here at 67 s and at 0.66 s, a hundredfold apart,
   with neither reading wrong. An absolute figure with no host is a defect.
3. **Name the configuration.** A number measured on a code path that no shipped deployment reaches
   is a number for code that does not run.
4. **Check that the reproduction instructions reproduce.** A page that says "reproduced rather than
   trusted" is making a claim, and the claim is testable by running what it prints.

---

## Summary of findings

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | The overlay seal is wired, and no shipped configuration reaches it. `OVERHEAD.md` publishes overlay figures as "the path the product actually takes on Linux" | highest | corrected in `OVERHEAD.md`, `SPIKE-D` |
| 2 | "A few milliseconds per turn independent of repository size" is true of the mount syscall and false of the turn. Two full-tree operations survive every mechanism | highest | corrected in `OVERHEAD.md`, `SPIKE-D` |
| 3 | `OVERHEAD.md`'s bottom-line summary still carries `18 ms`, the stub figure the same page withdraws 70 lines later | high | corrected in `OVERHEAD.md` |
| 4 | The seal bench's `enumerate` column is `find \| wc -l` and `diff -rq`, neither of which is `captureEffects` | high | labelled in `SPIKE-D`, `OVERHEAD.md` |
| 5 | The broker's two "against intuition" results do not survive repetition. The denied-call sign flipped 4 times in 5 runs here, and flipped back in 6 later runs on a quieter host: it tracks load, not the mechanism | high | corrected in `OVERHEAD.md`, restated across all 11 runs |
| 6 | Three citations in `OVERHEAD.md` point at files that are not in this repository, one of them the raw data behind a published table | medium | two fixed, one labelled |
| 7 | `SPIKE-D` opens by saying `snapshot-bench.jsonl` closes the evidence gap. That file is not in this repository | medium | corrected in `SPIKE-D` |
| 8 | `measure-seal-capture.mjs` still prints the discredited stub policy table, unlabelled | medium | **flagged, not fixed** (not this lane's file) |
| 9 | Re-running two published scripts on the machine they were published from: the timing constants were 1.4x to 2.1x off, and the byte count that "reproduced exactly" was a harness artifact this audit ratified from one run | informational, and one wrong call | rule recorded; 784 corrected to 786 and `measure-journal.mjs` fixed |

---

## 1. The overlay is wired. Nothing we ship reaches it

The suspicion this audit opened with was that the product passes no `seal` implementation and
therefore always copies, while the headline overhead story is told with overlay numbers. **The first
half of that is false and was fixed before this audit.** `runner-factory.ts:925-940` composes
`createOverlaySealer` with `releaseHookWired: true` and spreads `seal` and `release` into
`new TransactionalRunner(...)` at `:943`. The hook is real.

The second half is true anyway, one layer down, and it is worse than the original suspicion because
the code now looks armed.

`overlay-sealer.ts:466` returns `copyOnly("not-linux")` off Linux. On Linux, `capability()` at
`:482-492` tries `mount -t overlay` as the server process, and only adds a `sudo -n` candidate when
`allowSudo` is set, which is `options.allowSudo ?? process.env.SHADOW_SEAL_ALLOW_SUDO === "1"`
(`:419`). So the overlay requires the control-plane process to be able to mount, which in practice
means root or `CAP_SYS_ADMIN`.

Now walk every way this repository says to run the product:

| How it is run | What the sealer answers | Why |
|---|---|---|
| `npm run poc` on the demo Mac | `not-linux` | `overlay-sealer.ts:466`, before any probe |
| `docker compose up` | mount refused, so `no-privilege` | `docker-compose.yml:44-45` `cap_drop: ALL`, `:43` `no-new-privileges:true` |
| `npm run poc` on Linux as an ordinary user | mount refused, so `no-privilege` | no `CAP_SYS_ADMIN`, and `SHADOW_SEAL_ALLOW_SUDO` is set nowhere in the repository |
| Linux as root, or with `SHADOW_SEAL_ALLOW_SUDO=1` and passwordless sudo | `overlay` | the measured path, and the one no deployment file configures |

`SHADOW_SEAL_ALLOW_SUDO` appears exactly once in the whole tree, at its own default:

```
$ grep -rn "SHADOW_SEAL" --include='*.ts' --include='*.mjs' --include='*.yml' --include='*.sh' . | grep -v node_modules
apps/server/src/overlay-sealer.ts:147:  /** force a mechanism; SHADOW_SEAL=copy|overlay does the same from the environment */
apps/server/src/overlay-sealer.ts:419:  const allowSudo = options.allowSudo ?? process.env.SHADOW_SEAL_ALLOW_SUDO === "1";
apps/server/src/overlay-sealer.ts:422:  const forced = options.force ?? (process.env.SHADOW_SEAL as Mechanism | undefined);
```

**Measured, not argued.** The shipped sealer, loaded from `apps/server/dist` and composed the way
`runner-factory.ts` composes it, on the demo machine, returns `copy` with
`reason: "not-linux"` and journals both the capability probe and the fallback. The command that
shows it is the sweep below, which is pasteable rather than described.

**And measured again in the artifact a judge actually opens.** The committed demo pack records the
seal decision on every turn. Twelve `seal.fallback` records across seven step files, five distinct
run ids, and not one mount record anywhere in the evidence tree:

```
$ grep -o '"kind": "seal\.[a-z]*"' evidence/demo-run/steps/*.json | sort | uniq -c | grep fallback
   1 evidence/demo-run/steps/03-turn-1-normal.json:"kind": "seal.fallback"
   1 evidence/demo-run/steps/04-turn-1-journal.json:"kind": "seal.fallback"
   1 evidence/demo-run/steps/05-turn-2-abuse.json:"kind": "seal.fallback"
   2 evidence/demo-run/steps/06-turn-2-egress.json:"kind": "seal.fallback"
   1 evidence/demo-run/steps/07-turn-3-hold-approved.json:"kind": "seal.fallback"
   1 evidence/demo-run/steps/08-turn-4-hold-rejected.json:"kind": "seal.fallback"
   5 evidence/demo-run/steps/10-platform-after.json:"kind": "seal.fallback"
$ grep -rl "seal.mounted" evidence/
(no output)
```

**Swept rather than spot-checked.** One measurement showing `copy` proves only that one
configuration copies. The sealer's decision has a configuration axis with five reachable settings on
this host, and every one of them was exercised:

```bash
$ node --input-type=module -e '
import path from "node:path"; import os from "node:os"; import fs from "node:fs/promises";
import { pathToFileURL } from "node:url";
const dist = path.join(process.cwd(), "apps/server/dist");
const { createOverlaySealer } = await import(pathToFileURL(path.join(dist, "overlay-sealer.js")).href);
const cases = [
  ["default (as runner-factory composes it)", { releaseHookWired: true }],
  ["SHADOW_SEAL=overlay forced",              { releaseHookWired: true, force: "overlay" }],
  ["SHADOW_SEAL=copy forced",                 { releaseHookWired: true, force: "copy" }],
  ["allowSudo:true",                          { releaseHookWired: true, allowSudo: true }],
  ["release hook NOT wired + forced overlay", { releaseHookWired: false, force: "overlay" }],
];
for (const [label, opts] of cases) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sweep-"));
  const recs = [];
  const sealer = createOverlaySealer({ shadowRoot: root, emit: (r) => recs.push(r), ...opts });
  const real = path.join(root, "ws"); await fs.mkdir(real, { recursive: true });
  await fs.writeFile(path.join(real, "a.txt"), "x\n");
  const merged = path.join(root, "run", "merged"); await fs.mkdir(merged, { recursive: true });
  const mech = await sealer.seal(real, merged);
  console.log(label.padEnd(42), "->", mech.padEnd(6), "|", recs.map((r) => r.kind + "/" + (r.reason ?? r.mechanism)).join(" "));
  await sealer.release(merged, mech).catch(() => {});
  await fs.rm(root, { recursive: true, force: true });
}
'
```

```
default (as runner-factory composes it)    -> copy   | seal.capability/not-linux seal.fallback/not-linux
SHADOW_SEAL=overlay forced                 -> copy   | seal.capability/not-linux seal.fallback/not-linux
SHADOW_SEAL=copy forced                    -> copy   | seal.capability/forced-copy seal.fallback/forced-copy
allowSudo:true                             -> copy   | seal.capability/not-linux seal.fallback/not-linux
release hook NOT wired + forced overlay    -> copy   | seal.capability/not-linux seal.fallback/not-linux
```

Two things worth recording from that, one of them in the product's favour. **Nothing reachable on
this machine takes the overlay, including an operator explicitly asking for it**, so the demo host
is not one setting away from the measured path. And **it fails closed and says so**: every row
journals a `seal.capability` and a `seal.fallback` carrying the reason, so a reader of the journal
can always tell which mechanism ran and why, which is the property that makes this finding
checkable from an artifact rather than from a page. The `no-privilege` point on the axis is the one
this sweep cannot reach, because it needs a Linux host; it is read from the source and from
`docker-compose.yml`, not observed, and section "What this audit did not do" says so.

**Two judge-facing pages said opposite things about this, and the README was right.**
`README.md:491-495` says "Sealing is a copy on every host we ship to ... Everything we ship lands on
`cp -a`: macOS answers `not-linux`, and the compose deployment answers `no-privilege` because it
runs with `cap_drop: ALL`." Every clause of that checks out against the source above.
`research/OVERHEAD.md:16` said "On Linux the product mounts an overlay", and `:34-36` built the
page's headline on it: "on the path the product actually takes on Linux, the containment guarantee
costs a few milliseconds per turn independent of repository size".

The overlay figures are not fabricated and they are not useless. They are a correct measurement of a
mechanism, taken under `sudo bash research/spikes/snapshot-bench.sh`, on a configuration this
project does not ship and does not document how to reach. **Fixed by relabelling rather than
deleting:** the condition is now stated where the number is, and the shipped answer is stated beside
it.

## 2. "Independent of repository size" is true of the mount and false of the turn

Even granting the overlay, the headline does not follow, because the flat thing is not the only
thing a turn pays for. Two operations in `openTurn` are unconditional and both are O(files):

```
apps/server/src/transactional-runner.ts:767   await this.neutraliseOutboundLinks(request.workspacePath, merged);
apps/server/src/transactional-runner.ts:771   const opened = await snapshotStats(request.workspacePath);
```

Neither is behind a mechanism branch. `neutraliseOutboundLinks` (`:824-846`) is a recursive
`readdir` of `merged`, and under an overlay `merged` is the mount, so reading it reads the whole
tree. `snapshotStats(request.workspacePath)` stats every path in the real workspace. The overlay
removes the `cp -a` and it removes the hashed sealed signature (`:789-792`, which is
`emptySnapshot()` on any non-copy mechanism), and it shrinks capture to the upper layer
(`capture.ts:270`). It removes neither of the two above.

The size of the term the overlay does not remove, from this repository's own committed data on the
demo Mac:

```
$ node -e 'const r=require("fs").readFileSync("apps/server/src/bench/results/turn-open-scaling.jsonl","utf8").trim().split("\n").map(JSON.parse);
  for(const x of r) if(x.component==="snapshotStats-baseline-stat-only"||x.component==="shipped-turn-open-through-commit"||x.kind==="verdict") console.log(x.files??"",x.component??x.kind,x.p50??x.growthRatio)'
snapshotStats-baseline-stat-only   50 files: p50 2.39 ms   8,886 files: p50 142.09 ms   30,000 files: p50 562.52 ms
```

**562.5 ms at 30,000 files, on a path the page describes as costing 4 ms.** The mount is flat. The
turn is not, and it is not flat by two orders of magnitude at that size.

One more place the same optimism is written down, flagged for whoever owns the file rather than
edited here: the comment above that call (`f6b14bb:apps/server/src/transactional-runner.ts:768`)
says the walk is "stat-only, so it stays cheap on a large repo". Stat-only is why it is 562.5 ms
instead of the hashed walk's 10,038 ms at the same size, so the comparison is right and the word
"cheap" is not. Half a second per turn on a large repository is the largest MEASURED term
the overlay does not remove. The other survivor, `neutraliseOutboundLinks`, has no committed
timing anywhere in the tree, so no ranking between the two is supported and none is claimed.

The same file settles the shipped copy path end to end, and the verdict row is computed by the
harness rather than written by hand:

```
shipped-turn-open-through-commit   50 files: p50 40.38 ms   8,886: p50 4,557.97 ms   30,000: p50 25,639.27 ms
verdict: NOT O(1): shipped turn-open p50 grew 634.95x from 50 to 30000 files (a 600x increase in file count)
```

This is not a new discovery. `apps/server/src/bench/RESULTS.md` section 2 found it, counted the
five-or-more full-tree operations per copy-path turn in the source, and published the verdict.
`OVERHEAD.md` was written in parallel and its headline contradicts it. **What this audit adds is
that the contradiction survives the overlay**: two of those operations are not removed by any
mechanism, so "independent of repository size" is wrong on the fast path too, not only on the slow
one.

The `OVERHEAD.md` summary block has the same problem in miniature. `seal + capture (5,000 files)
~750 ms` is the sum of one hashed snapshot and one `captureEffects`, which are two of the terms a
copy-path turn pays. The `cp -a` itself, the link-neutralisation walk and the stat-only baseline
walk are not in it. The bench's end-to-end number for a no-op turn at 8,886 files is 4,558 ms.
Those two figures use different fixtures (4 KiB files against roughly 64-byte ones), so they are not
directly comparable as constants, and the audit does not treat them as such. What is comparable is
the term count, and the summary is missing three terms out of five.

## 3. A withdrawn number left standing in the bottom line

`OVERHEAD.md:193-196` withdraws the claim "a turn touching a thousand files is judged in 18 ms",
explaining that 18 ms was an artifact of `basicContext` returning a 13-byte constant for every
read. On the host governing that passage, the Windows NTFS one, the real-context figure was
**5,045 ms** against the stub's 18 ms. The 38.6 ms republication is a different host and a later
build: the macOS figure after the read memoisation, stated at `OVERHEAD.md:87` of the same commit.

`OVERHEAD.md:123` at `9600c9b`, the commit this audit read, then said:

```
policy judgement (1,000 effects)  18 ms
```

That block is under "What this adds up to, honestly" today and reads 38.6 ms, because this audit
corrected it in place. It is cited by section rather than by line because the line moves with every
correction added above it, which is how the `:121` in the sentence above went stale by two.

The page corrected its table and left its conclusion. That is the number a reader who skips to
"What this adds up to, honestly" takes away, and it is the retracted one. Corrected to 38.6 ms with
a pointer to the correction, and the arithmetic under it restated.

## 4. The seal bench's `enumerate` column is not `captureEffects`

`snapshot-bench.sh` times two things per mechanism. The seal is faithful for both: the copy branch
runs `cp -a`, which is exactly what `copyFallback` runs (`transactional-runner.ts:807`). The
enumerate is a stand-in on both branches:

| column | what the bench runs | what the product runs |
|---|---|---|
| overlay enumerate | `find "$upper" -mindepth 1 \| wc -l` | `captureEffects` walking `upper`: `lstat` per entry, symlink resolution against the real tree, whiteout expansion through `expandDelete`, size and byte limits |
| `cp -a` enumerate | `diff -rq lower copy` | `captureEffects` hashing the shadow against the sealed signature, then a second walk of the real tree for deletions |

Both stand-ins have the right asymptotic shape, which is why the size-independence claim survives
this and is the claim worth making. Neither is the product's cost. `SPIKE-D` says it "measures the
mechanism in isolation", which covers it; `OVERHEAD.md:26` folded the same figure into a column
headed "seal + enumerate" and then described the result as the per-turn cost of the guarantee, which
does not. Labelled in both.

## 5. The broker's two headline results do not survive repetition

`OVERHEAD.md:365-390` states two results "worth stating plainly because they run against intuition".
Both are differences of a few tens of microseconds, and both are published as host findings.

The committed script was re-run on a macOS arm64 8-CPU host, five times, using the published node
version for two of them. Added latency against the direct call, p50, in milliseconds:

```
$ node research/overhead/measure-broker.mjs        (x3, node v20.17.0; x2, node v22.21.0)

run            allowed GET   HELD POST   DENIED     node
published            0.067       0.100   -0.034     v22.21.0
1                    0.382       0.064   -0.134     v20.17.0
2                    0.590       0.555    0.016     v20.17.0
3                    0.676       0.405    0.052     v20.17.0
4                    0.305       0.368    0.097     v22.21.0
5                    0.223       0.508    0.002     v22.21.0
```

**"A denied call is faster than no broker at all ... and that reproduces" did not reproduce.** It is
published as measured on both hosts and bolded as a general property. Four of five runs measured a
denied call as *slower* than the direct call, including both runs on the published node version.

> **Restated 31 Aug 2026, because five runs were not enough to carry a direction either.** Six
> further runs on the same macOS host, six of six, measured the denied channel *faster*, three of
> them on node v20.17.0 (-0.040, -0.017, -0.205) and three on v22.21.0 (-0.027, -0.037, -0.018, with
> a direct-call p50 of 0.106 ms, in line with the 0.112 ms of the published run). Pooled over all
> eleven re-runs the sign is 7 faster against 4 slower, and every slower one is in the loaded block
> below. So this section's own sentence traded one under-supported direction for the opposite one.
> What both readings support, and all this section needs, is that the harness cannot resolve
> 0.034 ms: the sign follows the load on the machine. `OVERHEAD.md` now carries all eleven runs and
> states no direction.

**The held-versus-allowed ordering flipped in three runs of five** (runs 1, 2 and 3 in the table
above measured HELD POST faster than allowed GET; the published direction held only in runs 4 and
5), so the ordering claim is unsupported at the precision it is stated, and no "not falsified"
comfort survives that spread. The published gap the
argument rests on is 0.033 ms (0.067 against 0.100). The run-to-run spread of `allowed GET` alone,
on one machine, is 0.223 to 0.676, a range of 0.453 ms, roughly fourteen times the gap being
interpreted. The same channels' own `max` values reached 88.5 ms and 126.0 ms.

The confound is stated rather than hidden: this host was running five concurrent lanes, and its
direct-call p50 was 0.221 to 0.362 ms against the 0.112 ms the published run saw, so it is a busier
machine than the one that produced the published row. **That is the point rather than an excuse.**
A result that inverts under load on the same machine is not a property of a host, and the page
presents it as one. The mechanism argument underneath it is sound and is kept: holding is work
instead of forwarding, so which side wins depends on whether the upstream round trip costs more than
the hold. What is withdrawn is the claim that the sign was measured.

The figure that does survive all of this is the one the page already tells the reader to use: the
added cost is a fraction of a millisecond against a real outbound call of tens to hundreds.

## 6. Citations that do not resolve

```
$ grep -oE '(research|apps|docs|handoffs)/[A-Za-z0-9._/-]+' research/OVERHEAD.md | sort -u | while read p; do [ -e "$p" ] || echo "MISS $p"; done
MISS  an internal follow-up note (not distributed)
MISS  research/overhead/context-scaling.jsonl
MISS  research/spikes/verify-claims.mjs
```

(That is the output before this audit's edits. After them the same command reports the two that
live in the team's research repository, which the text now says out loud, and the third resolves.)

The middle one matters most: it is cited as the source of a published table, on a page whose promise
is that its numbers can be reproduced rather than trusted. The data is in the repository, at
`apps/server/src/bench/results/context-scaling.jsonl`. Path corrected, and the table verified
against it cell by cell:

```
files  walk(p50)  walk+hash(p50)  context(p50)   [as published]
100    9.16       60.03           0.3            [9.2, 60.0, 0.30]
500    23.02      274.70          0.65           [23.0, 274.7, 0.65]
2000   68.47      1059.55         1.95           [68.5, 1059.5, 1.95]
8000   260.91     4173.96         5.28           [260.9, 4174.0, 5.28]
30000  989.58     15976.37        20.84          [989.6, 15976.4, 20.84]
```

Every cell reproduces. The derived claims reproduce too: the two walks sum to 16,966 ms of the
16,987 ms total, and the plain walk is 47.5x the context loop at 30,000 files, which is the "about
48x" the page states.

The other two are references to a research repository this one does not contain. They are now marked
as such in the text rather than reading like links a judge can follow.

**Added 31 Aug 2026, after a hostile re-read: the grep above cannot see the commonest stale
citation.** A path can resolve while the line number in it points at nothing of the kind. Five
`file:line` citations were sampled and all five were wrong. Four are on this page and are corrected:
`capture.ts:141` for `snapshotStats`, which is defined at `:197` (`:141` is inside a hash digest
loop); `transactional-runner.ts:740` and `:760` for its two call sites, which were at `:771` and
`:791` (`:740` closes a type signature and `:760` is a comment); and `policy-context.ts:238` for the
`realInodes` loop, which is at `:772` (`:238` is a comment about read caps). The fifth is
`overlay-sealer.ts:407` in `RESULTS.md`, handed to that file's owner at the end of this audit. The
two call sites that move with every integration are now cited by content, with the line kept as a
commit-pinned parenthetical. The check that finds this class prints the line rather than testing the
path:

```bash
grep -oE '[A-Za-z0-9._-]+\.(ts|mjs|sh|yml):[0-9]+' research/OVERHEAD.md | sort -u \
  | while IFS=: read f n; do p=$(git ls-files "*/$f" "$f" | head -1); \
      printf '%-34s %s\n' "$f:$n" "$(sed -n "${n}p" "$p" | sed 's/^ *//' | cut -c1-80)"; done
```

Read the right column: every line should be recognisable as the thing the page says is there. It
only sees citations written with the filename, so write `overlay-sealer.ts:485`, never a bare
`:485`, and it reads the working tree, so a citation deliberately pinned to an older commit will
print that commit's neighbour instead. Those are the two known blind spots.

## 7. `SPIKE-D` cites raw data that is not here

`research/spikes/SPIKE-D-SNAPSHOT-ARTIFACTS.md:3-6` opens: "`SNAPSHOT-BENCH.md` published the
overlay-versus-copy figures without a reproducible harness behind them ... `snapshot-bench.sh` and
`snapshot-bench.jsonl` close that gap."

```
$ ls research/spikes/
SPIKE-D-SNAPSHOT-ARTIFACTS.md
snapshot-bench.sh
```

The script is here. The log is not. The page's own last line concedes it ("the raw runs stay in the
team's research repository") while its opening claims the gap is closed. So the load-bearing overlay
figures in this repository have a harness that cannot run on any host we ship to, and no committed
output. They rest on prose from two hosts. Corrected in the opening rather than the footer, since
the opening is what a reader believes.

## 8. Flagged, not fixed: the published script still prints the discredited table

`research/overhead/measure-seal-capture.mjs:62` builds its policy context as
`basicContext(async () => "const x = 1;\n", { addedLinesOf: async () => "const x = 1;\n" })`. That
is the constant-returning stub the page spends a whole section retracting. The script then prints it
under the heading `POLICY JUDGEMENT, against effect-set size`, with no marker. Running the exact
command `OVERHEAD.md` prints:

```
$ node research/overhead/measure-seal-capture.mjs
POLICY JUDGEMENT, against effect-set size
effects   judge(ms)   ms/effect  decision
1               9.4       9.358  commit
10              4.5       0.447  review
50              9.2       0.184  review
200            13.0       0.065  review
1000           44.3       0.044  review
```

A judge who runs the published command is shown the falling curve the page calls an artifact, in a
form that looks like a fresh measurement. **Not fixed here**: this lane owns `AUDIT.md` and
corrections to `docs/` and `research/*.md`, and this is a `.mjs`. The fix is one line, renaming the
heading to `POLICY JUDGEMENT against a STUB context (superseded, see measure-judge-context.mjs)`, or
better, deleting the block and pointing at `measure-judge-context.mjs`, which runs both contexts in
one pass. Handing it to whoever owns that file.

## 9. What re-running the scripts on their own machine established

Both re-runs below were done on the machine the figures were published from, an M2 MacBook Air,
8 GB, macOS 14.6, with five lanes running concurrently.

`measure-seal-capture.mjs`, published row against re-measured row:

```
files   published seal / capture / ms-per-file      re-measured today
50            8.3 /   3.8 / 0.242                  17.5 /   5.3 / 0.456
200          12.0 /  11.3 / 0.117                  21.1 /  30.4 / 0.258
800          55.2 /  58.5 / 0.142                  82.0 /  68.2 / 0.188
2000        142.6 / 140.0 / 0.141                 221.0 / 196.5 / 0.209
5000        377.7 / 367.7 / 0.149                 540.1 / 779.6 / 0.264
```

Linear from 200 files upward in both. The per-file constant is 1.3x to 2.2x the published one on the
same machine, same script, different load (observed 1.32x at 800 files to 2.21x at 200).

`measure-journal.mjs`:

```
                published    re-measured    settled
bytes per turn        784            784        786
append ms/turn      0.301          0.603          -
```

**The byte count reproduced, the timing doubled, and the byte count was the wrong number to
reproduce.** This audit ran the script once, got 784 back, and called it exact. It is not: the
script stat-ed the journal before `await j.settle()`, so it measured the file one 465-byte
`anchor.ok` record short. Six runs before the fix returned 784 every time and six runs after it
returned 786 every time, which is why one run could not catch it. Corrected 31 Aug 2026 by a hostile
re-read of this audit; the fix is one line in `measure-journal.mjs` and the republished figure is
786, with the byte-level reproduction recorded in "Journal growth and append cost" in `OVERHEAD.md`.

The rule the audit was built on survives and gains the clause it was missing: a size or a shape is a
property of the code and an absolute millisecond is a property of a machine at a moment, **and a
size still has to be run more than once**, because what a single run establishes is the harness's
answer and not the code's. `OVERHEAD.md` already says the journal size is "the one a reader can
carry to their own machine", and that is now true of 786.

**The labelling rule this produces, applied to every table in the page:** a host line is necessary
and not sufficient. Two figures from the same host at different times differ by 2x here. Any claim
whose argument depends on a difference smaller than that needs its dispersion published, which is
finding 5.

---

## Full inventory of published performance numbers

Verdict key: **OK** the number is sound and carries its host and its context; **LABEL** the number
is sound and was missing a condition, now added; **WRONG** the number or the claim built on it does
not survive.

Every `OVERHEAD.md:NNN` in this table points at the file as it stood at `9600c9b`, the commit
audited, before the corrections below were applied in place. Read them with
`git show 9600c9b:research/OVERHEAD.md | sed -n 'NNNp'`; against the corrected file they will be
tens of lines low, because each correction block added lines above them.

| Where | Number | Host stated? | Context | Verdict |
|---|---|---|---|---|
| `OVERHEAD.md:26` | overlay seal 4 ms, seal+enumerate 8 ms at 30,000 files | yes, Linux WSL2 24 CPU ext4 | shell `mount` and `find \| wc -l`, run as root | LABEL: mechanism only, and no shipped configuration reaches it (1, 4) |
| `OVERHEAD.md:27` | `cp -a` 662 ms, 918 ms at 30,000 files | yes, same host | shell `cp -a` and `diff -rq` | LABEL: `cp -a` is faithful, enumerate is a stand-in (4) |
| `OVERHEAD.md:34-36` | "a few milliseconds per turn independent of repository size" | yes | derived from the row above | WRONG (2): two unconditional O(files) operations survive every mechanism |
| `OVERHEAD.md:50-56` | seal/capture table, 0.14 ms per file, 4 KiB files | yes, M2 Air | real `snapshotStats` and `captureEffects` | OK, and the constant is 1.3-2.2x looser than one run suggests (9) |
| `OVERHEAD.md:63` | 5,000 files pays about 0.75 s | yes | two of the five size-dependent terms | LABEL (2): term count stated |
| `OVERHEAD.md:73-77` | superseded stub policy table | yes | `basicContext`, declared superseded in place | OK, the retraction is exemplary |
| `OVERHEAD.md:85-91` | 38.6 ms at 1,000 effects, 0.039 ms per effect | yes | real `buildPolicyContext` | OK |
| `OVERHEAD.md:107-113` | 784 bytes and 0.301 ms per turn, 74.7 MiB at 100k | yes | real `Journal` | WRONG (9): 784 was a harness artifact, republished as 786 and 75.0 MiB |
| `OVERHEAD.md:123` | `policy judgement (1,000 effects) 18 ms` | yes | the stub, withdrawn later in the same file | WRONG (3): corrected to 38.6 ms |
| `OVERHEAD.md:180-186` | stub-versus-real ratio table, up to 238x | yes, Windows NTFS | both contexts in one pass | OK, and this is the model for how to catch a stub |
| `OVERHEAD.md:225-231` | post-fix table, 49.6 ms at 1,000 effects | yes, Windows NTFS | real context | OK |
| `OVERHEAD.md:266-272` | NTFS seal/capture, 1.16 ms per file, 8x APFS | yes, both hosts | real functions | OK, and the 8x is the reason host labels exist |
| `OVERHEAD.md:311-317` | context-scaling table, 989.6 ms walk at 30,000 | yes, Windows NTFS | real `snapshotStats` and `buildPolicyContext`, journal path deliberately absent and declared | OK. Every cell recomputed from the committed JSONL (6) |
| `OVERHEAD.md:346-353` | broker p50/p95/p99/max, six channels | yes, Linux WSL2 | real broker, in-process upstream, declared | OK as absolute figures with the ratio caveat the page already gives |
| `OVERHEAD.md:371-375` | "a denied call is faster than no broker at all, and that reproduces" | yes, both hosts | real broker | WRONG (5): 4 of 5 re-runs measured the opposite |
| `OVERHEAD.md:377-390` | held cheaper on Linux, not on macOS | yes, both hosts | real broker | LABEL (5): sign is inside the run-to-run spread |
| `OVERHEAD.md:401-405` | overlay flat at 3 ms on a second Linux host | yes, 12 CPU WSL2 ext4 | `snapshot-bench.sh` as root | OK as a mechanism result, and it is the strongest thing on the page: one shape, two independent hosts |
| `OVERHEAD.md:410-414` | copy constant 2x worse on the second host | yes | same | OK, and the page draws the right conclusion from it |
| `SPIKE-D:20-26` | overlay 3/3/4 ms, copy 7/138/662 ms, "8 ms with an overlay, 918 ms with a copy" per turn | yes | shell stand-ins | LABEL (1, 4): "per turn" is the mechanism, not a turn |
| `SPIKE-D:36-38` | 67 s on macOS through Colima against 0.66 s native | yes, both | `cp -a` | OK. This is the finding that justifies the whole host-labelling rule |
| `SPIKE-D:62-70` | "the overlay figures describe the path the product takes on Linux" | n/a | source reading | WRONG (1): true only as root or with sudo enabled |
| `RESULTS.md:88` | stage latency, open 26 to 157.6 ms | yes, M2 Air, and in the JSONL host row | real runner, scripted inner runner declared | OK |
| `RESULTS.md:265-269` | 2.39/142.1/562.5, 5.34/826.4/10,038, 20.8/1,547/15,409, 40.4/4,558/25,639 ms | yes | real functions and the real `run()` | OK. Recomputed from `turn-open-scaling.jsonl` |
| `RESULTS.md:276-277` | "NOT O(1): grew 634.9x" | yes | computed by the harness, in the JSONL | OK, and it is the number `OVERHEAD.md`'s headline should have been reconciled against |
| `RESULTS.md:287-292` | "on this Mac the overlay never engages at all" | yes | source reading, `overlay-sealer.ts` | OK on the claim, and its line citation is stale: see the handoff below |
| `README.md:491-502` | "Everything we ship lands on `cp -a`", 902-955 / 472-491 / 555-585 ms, 89-93 MiB | yes, M2 Air, 5,000-file 2 KiB tree | real functions | OK. Verified against `docker-compose.yml` and the sealer source |
| `README.md:330-341` at `f6b14bb` | 3.7% miss, 1.3% discard, 24.1% held | n/a, corpus figures | out of this lane's scope | not audited here; superseded since (today's README carries 3.6% miss, 17.3% held) |
| `perf.md:75-95` | raw stage-latency and journal output | in the accompanying JSONL host rows | real runner | OK |
| an internal Linux host report | 4 ms / 662 ms / 256 ms, and 20,854 ms on virtiofs | yes, three hosts named per row | `snapshot-bench.sh` | OK. This is the best-labelled table in the repository |
| `sealer.md:304-305` | 937/943 ms against 1082/987 ms | test-suite timings, host implied | vitest | informational, not a product claim |

## Reproduction

```bash
# section 1, the shipped sealer's answer on this host: the sweep is printed in full in section 1
grep -ho '"kind": "seal\.fallback"' evidence/demo-run/steps/*.json | wc -l   # 12
grep -rl "seal.mounted" evidence/                                            # no output

# section 2, the terms the overlay does not remove
git show f6b14bb:apps/server/src/transactional-runner.ts | sed -n '765,795p'
node -e 'const r=require("fs").readFileSync("apps/server/src/bench/results/turn-open-scaling.jsonl","utf8").trim().split("\n").map(JSON.parse);
  for(const x of r) if(x.component==="snapshotStats-baseline-stat-only"||x.component==="shipped-turn-open-through-commit"||x.kind==="verdict") console.log(x.files??"",x.component??x.kind,x.p50??x.growthRatio)'

# section 5, the broker
node research/overhead/measure-broker.mjs      # repeat; the sign of DENIED is not stable

# section 6, citations and the context-scaling table
grep -oE '(research|apps|docs|handoffs)/[A-Za-z0-9._/-]+' research/OVERHEAD.md | sort -u \
  | while read p; do [ -e "$p" ] || echo "MISS $p"; done
# section 6, and the line numbers inside those citations, which the path grep cannot see
grep -oE '[A-Za-z0-9._-]+\.(ts|mjs|sh|yml):[0-9]+' research/OVERHEAD.md | sort -u \
  | while IFS=: read f n; do p=$(git ls-files "*/$f" "$f" | head -1); \
      printf '%-34s %s\n' "$f:$n" "$(sed -n "${n}p" "$p" | sed 's/^ *//' | cut -c1-80)"; done
node -e 'const r=require("fs").readFileSync("apps/server/src/bench/results/context-scaling.jsonl","utf8").trim().split("\n").map(JSON.parse).filter(x=>x.kind==="context-scaling");
  for(const x of r) console.log(x.files, x.walkPlainMs.p50, x.walkHashMs.p50, x.contextMs.p50)'

# section 9, re-running the published scripts on their own machine
node research/overhead/measure-seal-capture.mjs
node research/overhead/measure-journal.mjs
```

`apps/server/dist` must be built for the scripts that load it. All six scripts in
`research/overhead/` resolve `dist` from their own location (`import.meta.url`), so the audited
reproducibility defect of an absolute path into one author's home directory is fixed and stays
fixed. Checked across the whole tree: no script outside `dist` carries one.

## What this audit did not do

- **It did not measure a Linux host.** Everything about the `no-privilege` fallback under
  `cap_drop: ALL` is read from `docker-compose.yml` and `overlay-sealer.ts`, not observed. The
  macOS `not-linux` answer is measured; the Linux privilege answer is not. A Linux host with
  `docker compose up` and one turn would settle it, and the `turn.begin` record already carries the
  answer.
- **It did not re-measure the Windows or WSL2 tables.** They are audited for host, context and
  arithmetic, not re-run.
- **Handed to the owner of `apps/server/src/bench/RESULTS.md`: a stale line citation, three times.**
  Lines 290, 350 and 663 cite `overlay-sealer.ts:407` for the `not-linux` return. The claim is
  right and this audit confirmed it independently in section 1, but the return is at
  `overlay-sealer.ts:466`; `:407` is inside the unmount-retry path. This audit's first pass
  certified those lines as clean because it checked the paths and not the line numbers, which is
  the blind spot section 6 now names and gives a command for. Nothing about the finding changes,
  only the pointer.
- **It did not audit the corpus percentages** (miss rate, discard rate, held rate). Different lane,
  different evidence chain.
- **It did not fix `measure-seal-capture.mjs`** (finding 8), which is outside this lane's file
  ownership.

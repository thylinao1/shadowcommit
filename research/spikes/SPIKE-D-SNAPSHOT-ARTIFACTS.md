# Spike D: the snapshot benchmark, with a script and a log

`SNAPSHOT-BENCH.md` published the overlay-versus-copy figures without a reproducible harness
behind them. Every other mechanic in `research/spikes/` ships its script and its raw output; this
one shipped prose. `snapshot-bench.sh` closes the harness half of that gap.

> **Corrected 31 Aug 2026 by the claims audit, `research/overhead/AUDIT.md` section 7.** This
> paragraph used to say that `snapshot-bench.sh` and `snapshot-bench.jsonl` close the gap. The
> script is committed here. **The JSONL is not**, and the last line of this page concedes it while
> the opening claimed the opposite. So in this repository the figures below have a harness that
> needs root and a Linux host, and no committed output beside it. They are two hosts' prose, and the
> second host is reported in `research/OVERHEAD.md`. Said here rather than in the footer, because
> the opening is what a reader believes.

```bash
sudo bash research/spikes/snapshot-bench.sh > research/spikes/snapshot-bench.jsonl
```

It builds a synthetic tree at three sizes, seals it both ways, applies one create, one modify and
one delete, and times the seal and the changed-set enumeration separately, three repetitions each.
Root is needed for `mount`. The host record is the first line of the output, so a figure can never
be read without the machine it came from.

## Measured, native Linux

Linux 6.6.87.2 (WSL2), Ubuntu 24.04.4, 24 CPUs, ext4. Medians of three repetitions, milliseconds.

| Files in tree | overlay seal | `cp -a` seal | overlay enumerate | `cp -a` enumerate |
|---:|---:|---:|---:|---:|
| 50 | 3 | 7 | 3 | 3 |
| 8,886 | 3 | 138 | 4 | 52 |
| 30,000 | 4 | 662 | 4 | 256 |

Seal plus enumerate at 30,000 files: **8 ms with an overlay, 918 ms with a copy.** That is the
mechanism, not a turn: this page used to say "per turn", and a turn does more, which the section
below on what is not covered now quantifies. Both runs are as root, which is what `mount` needs and
which is not how the product is deployed.

## What this actually establishes

**The shape, not the headline number.** Overlay seal is flat at 3 to 4 ms across a six-hundred-fold
increase in tree size, because a mount does not touch the tree. `cp -a` scales linearly, because it
copies every file. Enumeration behaves the same way: the overlay's upper layer *is* the changed set
and needs no comparison, while the copy path has to walk and compare two trees. That difference is
structural and it reproduces on any host.

**The absolute numbers are host-specific, and by a wide margin.** `SNAPSHOT-BENCH.md` reports 67
seconds for `cp -a` at 30,000 files. This host does the same work in 0.66 seconds, about a hundred
times faster. Neither measurement is wrong: the published one was taken on macOS through a Colima
VM, where file operations cross a virtiofs boundary, and this one is a native kernel writing to
ext4. The lesson is that a `cp -a` figure is a statement about a filesystem and a virtualisation
layer, not about the mechanism.

So the claim to make is the size-independence, with any absolute figure labelled by its host.
"Full-copy snapshotting takes 67 seconds" invites a reader on Linux to measure 0.66 and conclude the
number was invented. "Sealing costs the same 3 ms whether the repository holds fifty files or
thirty thousand, while a copy grows with the tree" is the stronger claim, it is the one the design
rests on, and both harnesses now support it.

## Enumeration counts differ between the mechanisms, and should

The overlay run reports five changed entries where the copy run reports three. The three are the
semantic changes. The overlay adds the two parent directories it had to materialise in the upper
layer in order to hold them. Effect capture has to fold those away, which is what the
`captureEffects` whiteout and directory handling in `transactional-runner.ts` does.

## Not covered here

This measures the mechanism in isolation rather than a whole turn, which also starts a container and
makes at least one model call, and both dominate these figures.

Two more gaps between this bench and a turn, added by the claims audit because the difference is
what made a reader take "8 ms" for a per-turn cost:

- **The `enumerate` columns are stand-ins.** The overlay branch times `find "$upper" -mindepth 1 |
  wc -l` and the copy branch times `diff -rq`. The product runs `captureEffects`, which does an
  `lstat` per entry, resolves symlinks against the real tree, expands whiteouts through the real
  tree, and on the copy path hashes the shadow against the sealed signature. Same asymptotic shape,
  which is what the size-independence claim needs and gets. Different cost.
- **Two O(files) operations survive both mechanisms.** In `TransactionalRunner.openTurn`,
  `await this.neutraliseOutboundLinks(request.workspacePath, merged)` (a recursive `readdir` of the
  merged view, which under an overlay is the whole tree) and
  `const opened = await snapshotStats(request.workspacePath)` (over the real workspace) are
  unconditional. Both are cited by content because they move: `:812` and `:816` at `2c95041`,
  `:767` and `:771` at `d10213f`. The stat-only walk alone is 562.5 ms at 30,000 files on the demo
  Mac (`apps/server/src/bench/results/turn-open-scaling.jsonl`). So the flat 3 ms is the mount, and
  a turn on top of it is linear in repository size on both mechanisms.

**This paragraph has been corrected twice and both corrections are kept, because the second one
reverses the conclusion of the first.**

It originally read that the shipped product "passes no `seal` implementation and therefore always
takes the copy path". The wiring half of that is no longer true, checked against the code rather
than assumed: `runner-factory.ts:925-943` composes the sealer with `releaseHookWired: true` and
passes `seal: sealer.seal` into the runner, and `overlay-sealer.ts` returns `copyOnly("not-linux")`
off Linux. `neutraliseOutboundLinks` was also moved out of `copyFallback` and is now unconditional
in the seal, so the overlay path carries the same protection.

The first correction then concluded that "the overlay figures above therefore describe the path the
product takes on Linux". **That does not follow and is withdrawn, 31 Aug 2026, by the claims audit
(`research/overhead/AUDIT.md` section 1).** Being wired is not being reached. The sealer only
answers `overlay` when the control-plane process can itself mount, which means root or
`CAP_SYS_ADMIN`: the compose deployment runs `cap_drop: ALL` with `no-new-privileges:true`
(`docker-compose.yml:43-45`) and answers `no-privilege`, the demo Mac answers `not-linux`, and
`SHADOW_SEAL_ALLOW_SUDO` is set nowhere in the repository. The committed demo pack carries twelve
`seal.fallback` records and not one `seal.mounted`. So the figures above measure a mechanism on a
configuration nothing here ships. That is worth publishing, and it is not the shipped path.

Republished into the submission repository so the citation in `research/OVERHEAD.md` resolves for a
reader who only has this repo. The harness and the raw runs stay in the team's research repository.

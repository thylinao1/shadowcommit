# What this system does when the confinement layer is not there

Every row below was produced by running the code on a host that has no container engine, not by
reading it. The host is the instrument: Windows 11, NTFS, zh-CN, Node v24.19.0, Git Bash, no Docker,
no Podman, no Colima, no nerdctl, no WSL distribution.

Claims are labelled **MEASURED** (I ran it and this is the output), **READ** (I read the code and
did not run that path), or **GUESS** (neither, and it is marked so nobody builds on it).

## Host facts

MEASURED, `command -v` for each, plus `wsl -l -v`:

    docker    absent        podman   absent        colima  absent
    nerdctl   absent        lima     absent
    wsl       ON PATH, exits 0, and reports no distribution installed

That last line is a finding in itself. `wsl` exists on PATH on any Windows 11 machine and exits 0,
so a capability probe written as "is it on PATH" would conclude WSL is available here. Nothing in
this repository does that today, and the fix below deliberately does not either: it asks the engine
a question and reads the answer.

## The inventory

| Control | Depends on | What happens when it is missing | Told? | Did an artifact still claim it held? |
|---|---|---|---|---|
| Container runner, default config | docker | **Refuses.** The sealer throws, `open()` rethrows, no note is written | yes, the throw names the cause | **no** MEASURED |
| Container runner, `RUNTIME_PROVIDER=local-process` | nothing | **Refuses** unless `SHADOW_ALLOW_UNCONFINED=1` | yes, a long explicit error | **no**, and when overridden it journals `confinement:"none"` MEASURED |
| Container runner, `SHADOW_CONFINE_NETWORK=false` | docker | **Refuses** unless `SHADOW_ALLOW_UNCONFINED=1` | yes | see the next row |
| **Container runner, `SHADOW_ALLOW_UNCONFINED=1` + `SHADOW_CONFINE_NETWORK=false`** | docker | **Ran, and the engine was never contacted** | no | **YES. This was the defect.** MEASURED |
| Sealed per-turn network | docker | Sealer throws, turn refused, partial seal reaped | yes | no MEASURED |
| Egress broker | docker | Cannot start; it is created inside `sealer.open()`, so it fails with the seal above | yes | no READ |
| cgroup CPU and memory limits | docker | Unreachable. They are `docker run` arguments, so they never apply without an engine and cannot apply separately from it | inherits the row above | no READ |
| Capability grant enforcement | nothing | **Enforced identically.** A JSON file store under the data directory with no external dependency | n/a | no MEASURED |
| Journal anchor, submission fails | git or network | Writes `anchor.failed` with the reason into the journal | yes, in the artifact | no MEASURED |
| **Journal anchor, switched off** | n/a | **Wrote nothing at all** | no | **YES, by omission.** MEASURED |
| Journal hash chain, checkpoints, signature | nothing | Work normally | n/a | no MEASURED |

Two rows are marked as defects. Both are fixed on this branch and both have a guard that fails on a
host that HAS the dependency, which is the only kind of guard that survives me.

## Defect 1: the journal named a container that nothing had verified

MEASURED, before the fix, `node research/degraded/probe-note.mjs`:

    confinement                "container"
    containerWorkspacePath     "/workspace"
    containerCodexHome         "/codex-home"
    network                    null
    modelChannel               "direct"

No engine was contacted at any point in producing that. `RUNTIME_PROVIDER=container` is a line in a
config file; the note treated it as a fact about the host. That note is spread into the `turn.begin`
record at `transactional-runner.ts:942`, so the artifact a reader opens asserted a container, a
container workspace and a container codex home on a machine with none of them.

The operator had consented to something here, but not to this. The refusal message for
`SHADOW_ALLOW_UNCONFINED` is scrupulous about the network half, promising "every turn is journaled
`network:null`", and that promise is kept. It says nothing about the journal continuing to name a
container.

**The argument for the fix was already in the repository.** The test at
`confinement-integration.test.ts:342` is called "names the weaker confinement instead of implying
the stronger one", and its comment says journaling an unsealed turn as `container+sealed-network`
would be the one lie this product cannot afford. This is that same argument one rung lower, and on
the larger claim, because the kill switch rests on the container and not on the network.

MEASURED, after the fix, same command, same host:

    confinement                "none"
    containerWorkspacePath     null
    containerCodexHome         null
    containerEngineVerified    false
    confinementDegraded        "RUNTIME_PROVIDER=container but `docker info` did not answer, so no
                                container was verified for this turn: spawn docker ENOENT"

A live sealed network is proof an engine answered, so that path is unchanged and pays nothing.

## Defect 2: anchoring switched off left no trace

MEASURED, `node research/degraded/probe-anchor.mjs`, before the fix:

    SHADOW_ANCHORS=none     turn.begin, turn.committing, journal.checkpoint
    an anchor that FAILS    turn.begin, turn.committing, journal.checkpoint, anchor.failed
    an anchor that SUCCEEDS turn.begin, turn.committing, journal.checkpoint, anchor.ok

So a failure was honest and an absence was not, which is the wrong way round. A checkpoint is the
artifact that claims tamper evidence, and the reader most needs to know when nothing outside this
machine holds a copy of the head. After the fix, case one also writes `anchor.disabled` carrying the
tree size, the head and the reason.

## The guards, and why they fail on a machine that has Docker

Both new tests **inject** the dependency rather than detecting it, so both run on every host:

- `confinement-integration.test.ts`, "says none, not container, when no engine ever answered",
  injects an `exec` that throws ENOENT and asserts the degraded note.
- The pre-existing test beside it now injects an engine that ANSWERS. Without that its assertion was
  a statement about the machine running the suite rather than about the code: `"container"` on a
  host with Docker, `"none"` on one without. That is precisely how this defect survived.

A guard that needed a host with no engine would pass by accident on my laptop and never run
anywhere else.

## The locale and NTFS sweep

`node research/degraded/probe-locale.mjs`, resolved locale `zh-CN`, `LANG` unset.

`stable-order.ts` already fixed the digest paths, and the control case in the probe reproduces
exactly what it was written for: `["README.md","readme-extra.md"]` orders one way under
`localeCompare` and the other under code units. What follows is what is LEFT.

| Site | Sorts | Measured under zh-CN | Reading |
|---|---|---|---|
| `transactional-runner.ts:616` | held records by `heldAt` | **agree** on all four ISO shapes tested | latent, not live |
| `agent-service.ts:52,134,150` | agents and runs by ISO timestamp | **agree** | latent, not live |
| `verify-journal.ts:228` | count tiebreak on rule name | **agree** on the registry's current ids, **DISAGREE** on ids with `_` or a capital | fixed here, code units |
| `capture.ts:536`, `immutable-oracle.ts:134`, `journal-format.ts:38` | bare `.sort()` | deterministic by specification, code-unit order, not locale | safe |

The honest summary: **no live locale defect remains that I can find.** The timestamp sites agree
because ISO-8601 has no punctuation `localeCompare` reorders at these shapes, and the rule-name site
agreed only because every current rule id happens to be lowercase-and-hyphen. That second one is one
`security_control` away from diverging per machine, so it is switched to code units rather than left
as a coincidence. The first two are recorded as latent rather than fixed, because changing a
comparator that is currently correct buys nothing and the note here is the durable part.

Bare `.sort()` is worth stating explicitly because it looks like the bug and is not: with no
comparator the specification converts to strings and compares UTF-16 code units, which is the same
on every host.

## Not determinable from this host

Handed to a second machine with Linux, docker and root. Each is a row I could not measure even in
the negative, so it is not guessed at.

| Row | Why this host cannot answer it | What to run |
|---|---|---|
| Do cgroup limits actually bind | needs a running container to exceed them | run a turn whose command allocates past `CONTAINER_MEMORY_LIMIT`, confirm the kill and confirm the journal says which limit |
| Does the broker actually terminate the model channel | needs the broker container up | with the seal on, confirm the container reaches only the broker, and that `ARK_API_KEY` is absent from its environment |
| Is the sealed network actually sealed | needs docker networking | from inside the agent container, attempt egress to a host off the allowlist and confirm both the block and the held record |
| Does the overlay sealer's mount path behave | needs Linux overlayfs; `seal-contract.test.ts` skips on `win32` | run the suite on Linux and confirm the neutralisation contract |

## Retractions

Collected here as the convention requires. Both are things I believed early in this pass and
corrected by running something.

1. **"The system probably runs unconfined and journals a clean verdict."** Wrong as a general claim,
   and I had it in mind from the brief before measuring. MEASURED: the default path and both
   explicit unconfined routes all REFUSE, with errors that name the cause. The defect is real but it
   is one specific reachable combination, not the general behaviour, and the difference matters
   because the refusals are good work that a sweeping claim would have buried.
2. **"Bare `.sort()` on strings is a locale risk."** Wrong. I listed three call sites as suspects on
   the strength of the pattern. `Array.prototype.sort` with no comparator is defined to compare
   UTF-16 code units and is host-independent. The locale risk is `localeCompare` specifically.

## Reproduce

    npm run build -w @launchpad/server
    node research/degraded/probe-degraded.mjs    # does createRunner refuse, and is the engine probed
    node research/degraded/probe-note.mjs        # what the confinement note says with no engine
    node research/degraded/probe-anchor.mjs      # off, failing and succeeding anchors compared
    node research/degraded/probe-locale.mjs      # localeCompare against code units under zh-CN
    npx vitest run apps/server/src/confinement-integration.test.ts --reporter=dot

`npm run check` exits 1 on this host and exits 1 identically on the lead branch: the failures are
the POSIX mode class (`0666` where `0600` is expected) and the NTFS separator class
(`C:\srv\app\.data` where `/srv/app/.data` is expected). Two of them are in the files this branch
touches, `anchors.test.ts` and `journal.test.ts`, and both were confirmed present in the lead-branch
baseline before this work started.

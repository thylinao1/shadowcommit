# evidence/boundary.json, regenerated

This replaces a hand-marked record of an old run with the output of the current script, run as
root on a Linux host that can capture the docker bridge. Nothing in the JSON was typed by hand.

## How it was produced

    host    Linux 6.6.87.2-microsoft-standard-WSL2, docker 29.7.2, cgroup v2, ext4
    date    2026-09-01
    run     sudo bash evidence/evidence-boundary.sh 2>&1 | tee boundary-run.out
    who     the operator, on the one machine on this team that has a Linux kernel, root, a
            capturable docker bridge and /usr/bin/tcpdump. Darwin has no br- interface the host
            kernel can see and no tcpdump; a machine with no container engine cannot run any of it.

The run wrote boundary.json and a fresh capture. The capture is NOT committed here (see Handbacks).

## One change to the script, not to the JSON

The schema the gate enforces requires every row to name the host and date that produced it
(gate-truth.test.ts, "the committed artefact says of every check whether it was measured, and on
what host and date", asserts `producedOn` matches `/^.+, \d{4}-\d{2}-\d{2}$/` on every row). The
script did not emit that field; the old file carried it only because a person had written it in by
hand. Rather than hand-mark the regenerated file, which is the exact state being replaced, the
script now stamps `producedOn` once, at the single `record()` chokepoint every row passes through,
from the same detected host values as the top-level `host` object. So no row can be written without
it, and the file stays script output end to end. `bash -n` clean; the full gate suite is green
against the patched script (see Verification).

## Row by row, old file to new

Old file: `measuredEverything: false`, `verdict: incomplete`, `generatedBy` ending "NOT
REGENERATED". Two rows measured on cgroups, one on tcpdump (that one read a committed capture), the
rest marked `measured:false` with reasons. New file: all nine `measured:true`, `verdict: held`.

    check                what changed                                                        measured
    -------------------- ------------------------------------------------------------------- --------------
    egress public 443    ran on this host, printed both sentinels; refused on the no-route    false -> true
                         bridge. Old row carried no sentinels, so the shipped classify()
                         answered not-measured.
    egress metadata 80   same, against the cloud credential endpoint 169.254.169.254.         false -> true
    egress public 9418   ran by direct IP and refused. The old file probed this by NAME       false -> true
                         (git protocol / github.com) from inside a DNS-blocked jail, so it
                         measured the DNS failure a second time and reported it as a port.
                         The current script probes the route, not the name.
    egress public 22     same as 9418: direct IP, refused, was name-unresolved before.         false -> true
    egress dns           a real lookup that returned SERVFAIL, recorded as unresolved and     false -> true
                         never as a refused port. Old row carried no detail at all, so a
                         lookup that happened and one that did not were indistinguishable.
    cgroup-memory        re-measured, unchanged in meaning: memory.max 67108864, the 200 MiB   true ->  true
                         workload exits 137 under the limit and 0 without it.
    cgroup-pids          re-measured, unchanged: the container reads pids.max 16 and the       true ->  true
                         limit is enforced.
    tcpdump              provenance changed. Old row was measured:true but its 18 packets      true ->  true
                         came from the committed pcap-egress-denied.pcapng, which any host
                         that cannot capture would have read and reported as its own run. New
                         row captured live on the bridge, written to a per-run private path;
                         it never reads the published file. The packet count is incidental and
                         varies per run.
    kill-mid-write       the probe is now handed the real workspace path and told to write     false -> true
                         to it before the shadow loop; under the seal that lands in the
                         container's own fs and the host copy is untouched
                         (realWorkspaceUntouched true). The old row compared a directory that
                         was never mounted into the probe against itself, so it read the same
                         whether the container ran or not: a row that could not fail.

`verdict` moved from incomplete to held. `measuredEverything` moved from false to true. No row
stayed `measured:false`; there is no un-measured row left to explain, because every check ran on
this host.

## The falsification pass, evidence/boundary-falsify.sh

A row that says measured:true is only worth something if the measurement could have come out the
other way. For every measured control, the script removes it and shows the check goes red. Run as
root, all six demonstrations flipped (full output in boundary-falsify.out):

    control removed                          present               removed              result
    ---------------------------------------- --------------------- -------------------- ------
    --internal, tcp (routed bridge instead)  443 refused rc=1      443 reached rc=0     red
    --internal, dns (routed bridge instead)  example.com SERVFAIL  example.com resolved red
    --memory=64m (no limit)                  workload exit 137     workload exit 0      red
    --pids-limit=16 (no limit)               pids.max 16           pids.max 38148       red
    live capture (nonexistent interface)     bridge captured pkts  0 packets, exit 1,   red
                                                                   committed pcap NOT
                                                                   read
    fs isolation (-v $ws:$ws bind-mount)     keep.txt unchanged    keep.txt CHANGED     red

Zero cases failed to flip, so no row loses measured:true. The one egress control (--internal) is
shared by the five egress rows, but they reach for the route by two different mechanisms, so it is
removed and shown for each. The four tcp rows (443, 9418, 22, metadata 80) are the identical
nc-to-a-literal-address mechanism and one demonstration covers them: they differ only in port and
host and refuse for the one reason that the bridge has no route. The dns row is a different
mechanism and is demonstrated on its own rather than asserted by the grouping: busybox nslookup
returns rc 0 whether it resolves or gets SERVFAIL, so the route is read from the answer, not the
exit code. On the --internal bridge the embedded resolver at 127.0.0.11 cannot forward and returns
SERVFAIL; remove --internal and it forwards and resolves. That it resolves is what files the dns row
under this control; had it stayed unresolved, the row would be held by something other than the
route and the grouping would be wrong.

## Verification, run personally

    full gate suite   sudo vitest run src/gate-truth.test.ts     28 passed, 0 skipped
    committed block   vitest -t "agrees with the classifier..."  5 passed
    the test file used is byte-identical to origin/main (sha256 a45645668f7d1cf4); the run used the
    patched evidence-boundary.sh and this boundary.json.

## Handbacks, not this lane's files

- evidence/pcap-egress-denied.pcapng is tracked in git (1656 bytes, the 18-packet 2026-08-29 capture
  the old JSON described). The tcpdump row no longer reads it, but the file should be untracked and
  added to .gitignore so no future run of a lesser script can pass it off as its own capture. This
  regeneration does NOT commit a new capture; the tracked file is left as it is.

  Untracking is safe on content grounds (nothing measured cites it any more: capturedBy is gone and
  gate-truth.test.ts plants its own file at the published path rather than reading the tracked one),
  but it is NOT a one-file change. Two committed references to the file break and must move in the
  same commit, or the repo ends up asserting a file it no longer has:

    apps/server/src/gate-truth.test.ts   its comment argues the planted capture is realistic
                                         because "git ls-files evidence/ | grep -i pcap names that
                                         file" (repeated near line 708). Untrack the file and that
                                         sentence is false, in the test whose whole job is to keep
                                         the artefact and the code agreeing on what words mean. The
                                         test should STAY (someone may commit a capture again), but
                                         the comment has to change with the untracking.
    research/corpus/redteam/families-and-controls.json
                                         the network-exfiltration family's test_to_prove_it names
                                         the pcap directly ("commit a tcpdump on the bridge ... as
                                         evidence/pcap-egress-denied.pcapng showing zero non-broker
                                         packets"). Untracking makes that instruction point at a file
                                         the repo no longer holds.

  None of these three files (the pcap, the test, the corpus manifest) is this lane's, which is why
  this is a handback and not a change here.

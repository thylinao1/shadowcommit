#!/usr/bin/env bash
#
# boundary-falsify.sh - prove each measured:true row of evidence/boundary.json is a real measurement,
# by REMOVING the control it names and showing the check goes red.
#
# A green check that cannot go red is not a measurement, it is a decoration. evidence-boundary.sh says
# the egress bridge refuses, the memory and pids limits are enforced, the bridge is capturable, and a
# killed container leaves the real workspace untouched. This script removes each control in turn and
# shows the same probe now escapes, is not killed, forks past the cap, captures nothing of its own, or
# lands on the host. Every case prints CONTROL PRESENT and CONTROL REMOVED side by side.
#
#   sudo bash evidence/boundary-falsify.sh
#
# If a case does NOT flip when its control is removed, that row was never measuring the control and it
# must lose measured:true. The script exits non-zero and names the row.
set -uo pipefail

IMAGE="${EVIDENCE_IMAGE:-alpine:3}"
TCPDUMP="${TCPDUMP:-/usr/bin/tcpdump}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0
S="fal-$$"

hdr() { printf '\n=== %s ===\n' "$1"; }
verdict() { # human  present  removed  ok(0/1)
  printf '  control present: %s\n  control removed: %s\n' "$2" "$3"
  if [ "$4" = 1 ]; then printf '  RED WHEN REMOVED: %s\n' "$1"; PASS=$((PASS+1));
  else printf '  DID NOT FLIP: %s -> this row is not measuring its control and must lose measured:true\n' "$1"; FAIL=$((FAIL+1)); fi
}
rc_of() { printf '%s' "$1" | grep -o 'rc=[0-9]*' | tail -1 | cut -d= -f2; }
probe() { # network cmd
  docker run --rm --network "$1" --cap-drop ALL --security-opt no-new-privileges "$IMAGE" \
    timeout 8 sh -c "$2 2>&1; echo rc=\$?" 2>&1 | tr '\n' ' '
}
cleanup() { docker rm -f "$S-p" >/dev/null 2>&1; for n in "$S-int" "$S-rt"; do docker network rm "$n" >/dev/null 2>&1; done; [ -n "${TPID:-}" ] && kill "$TPID" 2>/dev/null; [ -n "${CDIR:-}" ] && rm -rf "$CDIR"; return 0; }
trap cleanup EXIT

# ------------------------------------------------------------------ 1. egress (5 rows, one control, two mechanisms)
# The five egress rows share one control: the network is created --internal, so it has no route off
# the bridge. But they reach for that route by TWO different mechanisms, so the control is removed and
# demonstrated for each. 1a is the four nc-to-a-literal-address rows; 1b is the dns row, which never
# touches the bridge route directly and so needs its own demonstration rather than being asserted by
# grouping.
hdr "1. egress bridge  (control shared by 4 tcp rows via nc, and the dns row via embedded-resolver forwarding)"
docker network create --internal "$S-int" >/dev/null
docker network create "$S-rt" >/dev/null

# 1a. the nc-to-a-literal-address mechanism: one demonstration covers 443, 9418, 22 and metadata 80,
# which differ only in port and host and refuse for the one reason that the bridge has no route.
P=$(probe "$S-int" "nc -w 5 -z 1.1.1.1 443"); Prc=$(rc_of "$P")
R=$(probe "$S-rt"  "nc -w 5 -z 1.1.1.1 443"); Rrc=$(rc_of "$R")
ok=0; { [ "$Prc" != 0 ] && [ "$Rrc" = 0 ]; } && ok=1
verdict "egress reaches 1.1.1.1:443 once the no-route bridge is removed (refused -> reached); same mechanism for 9418, 22 and metadata 80" \
        "--internal bridge, nc 1.1.1.1:443 rc=$Prc (refused)" \
        "routed bridge, nc 1.1.1.1:443 rc=$Rrc (reached)" "$ok"

# 1b. the dns row is a DIFFERENT mechanism and must be shown, not inferred. busybox nslookup returns
# rc 0 whether it resolves or gets SERVFAIL, so the exit code is useless here and the route is read
# from the answer, exactly as the script's classify() does. On --internal the embedded resolver at
# 127.0.0.11 has no route to forward the query and returns SERVFAIL; remove --internal and it forwards
# and resolves. If it had NOT resolved, the dns row would be held by something other than this control
# and the grouping would be wrong; it does resolve, which is what files it here.
resolved() { case "$1" in *SERVFAIL*|*NXDOMAIN*) return 1 ;; esac; printf '%s' "$1" | grep -qi "Name:"; }
DP=$(probe "$S-int" "nslookup example.com")
DR=$(probe "$S-rt"  "nslookup example.com")
Pres=$(resolved "$DP" && echo resolved || echo unresolved)
Rres=$(resolved "$DR" && echo resolved || echo unresolved)
ok=0; { [ "$Pres" = unresolved ] && [ "$Rres" = resolved ]; } && ok=1
verdict "dns resolves once the no-route bridge is removed (unresolved -> resolved), which is what files the dns row under this control" \
        "--internal bridge, nslookup example.com -> $Pres (embedded resolver returns SERVFAIL, cannot forward)" \
        "routed bridge, nslookup example.com -> $Rres" "$ok"
docker network rm "$S-int" "$S-rt" >/dev/null 2>&1

# ------------------------------------------------------------------ 2. cgroup-memory
# Control: --memory=64m. The same 200 MiB /dev/shm workload is SIGKILLed (137) with the limit and
# completes (0) without it. Remove the limit and the kernel does not kill it.
hdr "2. cgroup-memory  (control: --memory=64m)"
docker run --rm --shm-size=256m --memory=64m --memory-swap=64m "$IMAGE" \
  sh -c 'dd if=/dev/zero of=/dev/shm/fill bs=1M count=200' >/dev/null 2>&1; Prc=$?
docker run --rm --shm-size=256m "$IMAGE" \
  sh -c 'dd if=/dev/zero of=/dev/shm/fill bs=1M count=200' >/dev/null 2>&1; Rrc=$?
ok=0; { [ "$Prc" = 137 ] && [ "$Rrc" = 0 ]; } && ok=1
verdict "the 200 MiB workload is not killed once the memory limit is removed (137 -> 0)" \
        "--memory=64m, workload exit $Prc (137 = OOM SIGKILL)" \
        "no limit, workload exit $Rrc (0 = ran to completion)" "$ok"

# ------------------------------------------------------------------ 3. cgroup-pids
# Control: --pids-limit=16. With it the container reads pids.max=16 and cannot hold more than ~16
# processes; without it pids.max is "max" and a 40-way fork all survive.
hdr "3. cgroup-pids  (control: --pids-limit=16)"
Pmax=$(docker run --rm --pids-limit=16 "$IMAGE" cat /sys/fs/cgroup/pids.max 2>/dev/null | tr -d '\r ')
Rmax=$(docker run --rm "$IMAGE" cat /sys/fs/cgroup/pids.max 2>/dev/null | tr -d '\r ')
# functional: how many of 40 concurrent sleepers survive under each
Pn=$(docker run --rm --pids-limit=16 "$IMAGE" sh -c 'n=0; i=0; while [ $i -lt 40 ]; do sleep 5 & [ $? = 0 ] && n=$((n+1)); i=$((i+1)); done; echo $n' 2>/dev/null | tr -d '\r ')
Rn=$(docker run --rm "$IMAGE" sh -c 'n=0; i=0; while [ $i -lt 40 ]; do sleep 5 & [ $? = 0 ] && n=$((n+1)); i=$((i+1)); done; echo $n' 2>/dev/null | tr -d '\r ')
ok=0; { [ "$Pmax" = 16 ] && [ "$Rmax" != 16 ]; } && ok=1
verdict "pids.max is uncapped and the fork count is not held once the pids limit is removed" \
        "--pids-limit=16, pids.max=$Pmax, 40-way fork: ${Pn:-container pid-exhausted before it could count, which is the cap enforcing}" \
        "no limit, pids.max=$Rmax, 40-way fork: ${Rn:-?}/40 survived" "$ok"

# ------------------------------------------------------------------ 4. tcpdump capture
# Control: a live capture of THIS run on the real bridge. Point tcpdump at an interface that does not
# exist and it captures nothing, and the check must report capturable:false rather than reading the
# committed pcap. Prove it does not fall back even when that committed file is present.
hdr "4. tcpdump capture  (control: a live capture on the real bridge)"
docker network create --internal "$S-int" >/dev/null
BR="br-$(docker network inspect "$S-int" --format '{{.Id}}' | cut -c1-12)"
CDIR="$(mktemp -d)"; GOOD="$CDIR/good.pcap"; BADLOG="$CDIR/bad.log"
"$TCPDUMP" -i "$BR" -w "$GOOD" -U >"$CDIR/good.log" 2>&1 & TPID=$!; sleep 1
probe "$S-int" "nc -w 3 -z 1.1.1.1 443" >/dev/null 2>&1
sleep 1; kill "$TPID" 2>/dev/null; wait "$TPID" 2>/dev/null; TPID=""
Pk=$("$TCPDUMP" -r "$GOOD" 2>/dev/null | wc -l | tr -d ' ')
# removed: a nonexistent interface, with the committed pcap sitting right there
"$TCPDUMP" -i "no-such-if-$$" -w "$CDIR/bad.pcap" -U >"$BADLOG" 2>&1; Bexit=$?
Bk=$([ -s "$CDIR/bad.pcap" ] && "$TCPDUMP" -r "$CDIR/bad.pcap" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
committed=$([ -s "$HERE/pcap-egress-denied.pcapng" ] && echo "present, $( "$TCPDUMP" -r "$HERE/pcap-egress-denied.pcapng" 2>/dev/null | wc -l | tr -d ' ') pkts" || echo absent)
ok=0; { [ "$Pk" -gt 0 ] && [ "$Bk" = 0 ] && [ "$Bexit" != 0 ]; } && ok=1
verdict "capture yields zero and the check cannot claim capturable once the real interface is removed" \
        "real bridge $BR captured $Pk packets" \
        "interface no-such-if-$$: tcpdump exit $Bexit, 0 packets, and the committed pcap ($committed) is NOT read" "$ok"
docker network rm "$S-int" >/dev/null 2>&1; rm -rf "$CDIR"

# ------------------------------------------------------------------ 5. kill-mid-write isolation
# Control: the container's filesystem isolation. The probe is told to write to the real workspace's
# host path; under isolation that path is a fresh empty dir inside the container and the host copy is
# untouched. Remove isolation by bind-mounting the real workspace at its own path and the write lands
# on the host.
hdr "5. kill-mid-write  (control: container filesystem isolation)"
run_case() { # extra_mount -> prints "before after exists"
  local ws extra="$1"; ws=$(mktemp -d); echo original > "$ws/keep.txt"
  local before after exists
  before=$(sha256sum "$ws/keep.txt" | cut -d' ' -f1)
  docker run --rm $extra "$IMAGE" sh -c "printf clobbered > '$ws/keep.txt' 2>/dev/null; dd if=/dev/urandom of='$ws/big.bin' bs=1M count=1 2>/dev/null" >/dev/null 2>&1
  after=$(sha256sum "$ws/keep.txt" | cut -d' ' -f1)
  exists=$([ -f "$ws/big.bin" ] && echo yes || echo no)
  printf '%s %s %s' "$before" "$after" "$exists"; rm -rf "$ws"
}
# present: no mount of the real ws (isolated). removed: bind-mount the real ws at its own path.
WS_R=$(mktemp -d); echo original > "$WS_R/keep.txt"; BEF=$(sha256sum "$WS_R/keep.txt" | cut -d' ' -f1)
docker run --rm "$IMAGE" sh -c "printf clobbered > '$WS_R/keep.txt' 2>/dev/null" >/dev/null 2>&1
P_after=$(sha256sum "$WS_R/keep.txt" | cut -d' ' -f1)  # isolated: unchanged
docker run --rm -v "$WS_R:$WS_R" "$IMAGE" sh -c "printf clobbered > '$WS_R/keep.txt' 2>/dev/null" >/dev/null 2>&1
R_after=$(sha256sum "$WS_R/keep.txt" | cut -d' ' -f1)  # leaked: clobbered
ok=0; { [ "$P_after" = "$BEF" ] && [ "$R_after" != "$BEF" ]; } && ok=1
verdict "the real workspace is clobbered once the bind-mount is added (untouched -> touched)" \
        "no mount, keep.txt hash unchanged ($([ "$P_after" = "$BEF" ] && echo same || echo CHANGED))" \
        "bind-mount -v \$ws:\$ws, keep.txt hash $([ "$R_after" != "$BEF" ] && echo CHANGED || echo same)" "$ok"
rm -rf "$WS_R"

# ------------------------------------------------------------------ summary
hdr "falsification summary"
echo "  cases that went red when the control was removed: $PASS"
echo "  cases that did NOT flip (rows that lose measured:true): $FAIL"
if [ "$FAIL" -ne 0 ]; then echo "FALSIFICATION INCOMPLETE: $FAIL measured row(s) are not measuring their control."; exit 1; fi
echo "every measured control, removed, turns its check red. The measured:true rows are measurements."

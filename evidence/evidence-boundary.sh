#!/usr/bin/env bash
#
# evidence-boundary.sh - measure AMAN_PLAN 7.5's four unverified claims on this host.
#
# 7.5 does not ask whether the boundary is configured. It asks whether it is ENFORCED on the exact
# machine and container engine the judged demo runs on, because each of these has a documented way
# of being silently absent:
#
#   1. a no-default-route bridge blocks egress   tested with a live connection, not read off a config
#   2. cgroup v2 limits are enforced             not no-op'd under nested virtualisation
#   3. tcpdump captures the bridge interface     not every virtual network exposes a capturable one
#   4. a container killed mid-write is recoverable
#
# Every check runs a real container against a real network and records what actually happened.
# Output: evidence/boundary.json, and evidence/pcap-egress-denied.pcapng for check 3.
#
# THE CAPTURE FILE IS OUTPUT, NEVER INPUT, AND IT SHOULD NOT BE COMMITTED. Check 3 reads only the
# capture this run wrote, to a private per-run path; the published file above is written and never
# read back. A tracked pcap sitting next to a script that reads pcaps is what let one machine's
# capture be reported as another machine's measurement, and untracking it is a separate change
# from this one.
#
#   sudo bash evidence/evidence-boundary.sh
#
# Root is needed for tcpdump and for reading the bridge. Nothing here touches a path outside the
# repository's evidence directory and Docker's own state.
#
# MEASURED IS NOT THE SAME THING AS BLOCKED.
#
# The first version of this script derived "blocked" from a non-zero exit code and nothing else, so
# every way a probe could fail to happen - a missing image, no `nc` in the image, a dead dockerd, a
# hostname that never resolved - was written down as proof that the boundary held. It fails open,
# and it did: two rows of the committed run reported a blocked port on `nc: bad address 'github.com'`,
# where no socket was ever opened. Absence of evidence recorded as evidence of absence.
#
# So every probe now prints two sentinels, every row carries "measured", and a run that could not
# measure something exits non-zero rather than writing a confident artefact. Three outcomes, never
# two:
#
#   measured, refused   the boundary held for this target       blocked: true
#   measured, reached   egress escaped                          blocked: false, the run fails
#   not measured        this run is not evidence either way     measured: false, the run fails
#
# Two sentinels, because one was not enough. A container that starts prints the first, and that was
# taken as proof the probe had run. It is not: an image with no `nc` starts fine and exits 127 from
# the shell without ever opening a socket, which is the third cause the original defect named. The
# second sentinel is printed only after the probe tool is found, so "measured" means the tool ran,
# not merely that a container came up.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE"
NET="shadow-evidence-$$"
IMAGE="${EVIDENCE_IMAGE:-alpine:3}"
TCPDUMP="${TCPDUMP:-/usr/bin/tcpdump}"

# Where check 3 writes, and where it publishes.
#
# CHECK 3 MAY ONLY REPORT A MEASUREMENT OF A CAPTURE THIS RUN MADE.
#
# It could not, until now. The capture was written to, and read back from, evidence/pcap-egress-
# denied.pcapng, and that path is TRACKED in git: `git ls-files evidence/ | grep -i pcap` names it.
# So on any host where the capture cannot start, check 3 opened the pcap some other machine had
# committed and reported its packets and its destinations as this run's measurement, measured:true,
# capturable:true, and the run exited 0. With TCPDUMP pointed at a path that does not exist it wrote
# packets:0, capturable:true, which is the most reassuring reading a host with no tcpdump at all
# could possibly produce. Absence of evidence recorded as evidence of absence, inside the rewrite
# that existed to remove exactly that.
#
# The capture is now written to a path inside a directory mktemp created for this run, so no
# committed and no leftover file can occupy it, and the published path is never read. The published
# file is only ever written, and only after a capture this run made succeeded.
CAPTURE_DIR="$(mktemp -d)"
PCAP_RUN="$CAPTURE_DIR/egress-denied.pcapng"
PCAP_PUBLISHED="$OUT/pcap-egress-denied.pcapng"

# Printed by the probe before it does anything else. Only a container that started can emit it.
SENTINEL="SHADOW-PROBE-STARTED"
# Printed only after the probe tool is found on PATH inside the image. Only an image that HAS the
# tool can emit it, which is the part the first sentinel says nothing about.
TOOL_SENTINEL="SHADOW-TOOL-PRESENT"
# The classifier reads the whole probe output. The artefact carries a bounded rendering of it.
DETAIL_MAX=400

results=()
ALL_HELD=1     # every check that ran came back the way the boundary claims it should
MEASURED_OK=1  # every check actually ran

log() { printf '\n=== %s ===\n' "$1"; }
record() { results+=("${1%\}},\"producedOn\":\"$PRODUCED_ON\"}"); }
# JSON has no escape for a raw control byte. The first version passed every byte below 0x20 except
# newline straight through, so one escape sequence or one carriage return in a probe's output made
# the artefact unparseable while the run still exited 0, and a gate whose output no consumer can read
# is a gate nobody reads. Every byte under 0x20, and DEL, is escaped here.
#
# Bytes at or above 0x80 become U+FFFD rather than passing through. Probe diagnostics are ASCII, and
# a single invalid UTF-8 sequence would cost the whole file: a lossy detail beats an artefact that
# will not parse. A trailing newline is not preserved; interior ones become \n.
json_escape() {
  LC_ALL=C printf '%s' "$1" | LC_ALL=C awk '
    BEGIN { ORS = ""; for (i = 1; i < 256; i++) ord[sprintf("%c", i)] = i }
    NR > 1 { printf "\\n" }
    { for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1); n = ord[c]
        if (c == "\\") printf "\\\\"
        else if (c == "\"") printf "\\\""
        else if (n == 8) printf "\\b"
        else if (n == 9) printf "\\t"
        else if (n == 12) printf "\\f"
        else if (n == 13) printf "\\r"
        else if (n < 32 || n == 127) printf "\\u%04x", n
        else if (n > 127) printf "\\ufffd"
        else printf "%s", c
      } }'
}
unmeasured() { MEASURED_OK=0; printf '  NOT MEASURED: %s\n' "$1"; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
  fi
}

size_of() { if [ -f "$1" ]; then wc -c < "$1" | tr -d ' '; else echo 0; fi; }

# Bound the recorded detail without losing either end of it. Both ends are load-bearing: the
# sentinels are at the front and rc= is at the back, so a truncation that keeps only one end
# destroys the evidence the row is classified on.
elide() { # text
  local t="$1"
  if [ "${#t}" -le "$DETAIL_MAX" ]; then printf '%s' "$t"; return 0; fi
  printf '%s ...[%s characters elided]... %s' "${t:0:180}" "$(( ${#t} - 360 ))" "${t: -180}"
}

# Run one probe inside the jail. The start sentinel goes first, the tool sentinel next and only if
# the tool is there, the command's own output after that, its exit code last.
#
# The whole output is kept. The first version piped this through `tail -3`, which threw the start
# sentinel away for any probe that printed more than two lines. busybox nslookup against a resolver
# that ANSWERS prints six, so the one outcome that would prove an escape out of the jail was the one
# outcome the truncation turned into "the container never started". That is this script's own defect
# running backwards: presence of evidence written down as absence of measurement.
probe() { # tool command-string
  docker run --rm --network "$NET" --cap-drop ALL --security-opt no-new-privileges \
    "$IMAGE" timeout 6 sh -c \
    "echo $SENTINEL; command -v $1 >/dev/null 2>&1 && echo $TOOL_SENTINEL; $2 2>&1; echo rc=\$?" \
    2>&1 | tr '\n' ' '
}

# Classify one probe's output. Sets PROBE_MEASURED, PROBE_RC, PROBE_VERDICT.
#
# PROBE_MEASURED means the probe TOOL ran, not merely that a container came up. Requiring only the
# start sentinel made this worse than the fail-open it replaced: an image with no `nc` produced
# rc=127, and every non-zero rc that was not a name-resolution message was called "refused", so the
# row came out measured:true, verdict:refused, blocked:true. The old artefact at least only said
# blocked; that one had the gate explicitly vouch for an experiment in which no socket was opened.
classify() { # output
  local out="$1"
  PROBE_MEASURED=false
  PROBE_VERDICT="not-measured"
  PROBE_RC=$(printf '%s' "$out" | grep -o 'rc=[0-9]*' | tail -1 | cut -d= -f2)
  case "$out" in *"$SENTINEL"*) [ -n "$PROBE_RC" ] && PROBE_MEASURED=true ;; esac
  PROBE_RC="${PROBE_RC:-null}"
  [ "$PROBE_MEASURED" = true ] || return 0

  # The tool sentinel is the primary signal. 127 is the shell's "command not found" and 126 is
  # "found but not executable"; they are the backstop for an image whose `command -v` lies, and
  # neither is a result about the target. `nc` and `nslookup` return 0 or 1, never these.
  case "$out" in
    *"$TOOL_SENTINEL"*) ;;
    *) PROBE_MEASURED=false; PROBE_VERDICT="tool-missing"; return 0 ;;
  esac
  case "$PROBE_RC" in
    126|127) PROBE_MEASURED=false; PROBE_VERDICT="tool-missing"; return 0 ;;
  esac

  case "$out" in
    *"bad address"*|*"Name does not resolve"*|*"Temporary failure in name resolution"*|*"nodename nor servname"*)
      # the container ran, but no socket was opened: this is a DNS result, not a port result
      PROBE_VERDICT="name-unresolved"; return 0 ;;
  esac

  # DID-NOT-FINISH is not REFUSED. Every non-zero rc that was not one of the cases above used to
  # become "refused", which reads a probe that was cut short as a successful block: the same fault
  # this script exists to close, one rung further down. `timeout` reports 124 when it fires, and a
  # process killed by a signal exits 128+N, so 137 is SIGKILL and 143 is SIGTERM. Neither says
  # anything about the target. nc and nslookup answer 0 or 1 and never these.
  case "$PROBE_RC" in
    124) PROBE_MEASURED=false; PROBE_VERDICT="did-not-finish"; return 0 ;;
  esac
  case "$PROBE_RC" in
    [0-9]*) if [ "$PROBE_RC" -ge 128 ]; then PROBE_MEASURED=false; PROBE_VERDICT="did-not-finish"; return 0; fi ;;
  esac

  if [ "$PROBE_RC" = "0" ]; then PROBE_VERDICT="reached"; else PROBE_VERDICT="refused"; fi
}

attempt() { # label host port [note]
  local label="$1" host="$2" port="$3" note="${4:-}"
  local out blocked measured
  out=$(probe nc "nc -w 4 -z $host $port")
  classify "$out"
  blocked=false
  # This row is about a port. A container that started but opened no socket has measured nothing
  # about that port, however much output it produced, so it does not get to say measured.
  measured=false
  case "$PROBE_VERDICT" in
    refused) blocked=true; measured=true ;;
    reached) measured=true; ALL_HELD=0 ;;
    name-unresolved) unmeasured "$label: the name never resolved inside the jail, so no port was probed" ;;
    tool-missing) unmeasured "$label: the image has no nc, so the container started but no socket was ever opened" ;;
    did-not-finish) unmeasured "$label: the probe was cut short (rc=$PROBE_RC: a timeout or a signal), so it never reported on that port" ;;
    not-measured) unmeasured "$label: the probe container never started, so nothing was tested" ;;
  esac
  printf '  %-22s %-24s rc=%-6s measured=%-6s verdict=%s\n' "$label" "$host:$port" "$PROBE_RC" "$measured" "$PROBE_VERDICT"
  local note_field=""
  [ -n "$note" ] && note_field=",\"note\":\"$(json_escape "$note")\""
  record "{\"check\":\"egress\",\"target\":\"$label\",\"host\":\"$host\"$note_field,\"port\":$port,\"rc\":$PROBE_RC,\"measured\":$measured,\"verdict\":\"$PROBE_VERDICT\",\"blocked\":$blocked,\"detail\":\"$(json_escape "$(elide "$out")")\"}"
}

# Check 4's first shape could not fail. It hashed a file in a directory the container was never
# given, so deleting the `docker run` left every figure identical: the row said the real workspace
# survived whether or not anything ever wrote.
#
# Gating it on `measured` closed only half of that. The other half was that the experiment had no
# adversary in it at all: the probe was never told where the real workspace lived, its path appeared
# on no docker command line, and it shared no path with the shadow, so no container, however
# hostile, could make realWorkspaceUntouched false. A field that cannot come out false is not a
# measurement however carefully it is gated.
#
# The probe is now handed the workspace's real host path and told to write there first, before it
# writes anywhere else. Under a correct seal that path does not exist inside the container: mkdir
# creates a fresh empty directory on the container's own filesystem, the write lands there, and the
# host copy is untouched. Under a leaked bind mount the write lands on the host and the row goes
# false. Because the attempt is the first thing in the command, any byte in the shadow is proof the
# attempt was reached.
killed_mid_write_check() {
  local ws shadow before after started size partial untouched cid run_rc
  ws=$(mktemp -d); shadow=$(mktemp -d)
  echo "original" > "$ws/keep.txt"
  cp -a "$ws/." "$shadow"
  before=$(sha256_of "$ws/keep.txt")

  cid=$(docker run -d --name "$NET-probe" --network "$NET" \
    -v "$shadow:/workspace" "$IMAGE" \
    sh -c "mkdir -p '$ws' 2>/dev/null; printf clobbered > '$ws/keep.txt' 2>/dev/null; dd if=/dev/urandom of='$ws/big.bin' bs=1M count=1 2>/dev/null; while true; do dd if=/dev/urandom of=/workspace/big.bin bs=1M count=64 2>/dev/null; done" 2>&1)
  run_rc=$?
  started=false
  if [ "$run_rc" = 0 ] && [ -n "$cid" ]; then
    case "$(docker inspect -f '{{.State.Running}}' "$NET-probe" 2>/dev/null)" in true) started=true ;; esac
  fi
  sleep 3
  docker kill -s KILL "$NET-probe" >/dev/null 2>&1
  sleep 1

  after=$(sha256_of "$ws/keep.txt")
  size=$(size_of "$shadow/big.bin")
  # Recorded, not gated. If the kill lands between iterations of the loop the file is exactly the
  # 64 MiB that was asked for and this is false, which is a race and not a leak. Failing the run on
  # it made the gate go red for a timing outcome, and a gate that goes red for a race is a gate that
  # gets switched off. The boundary claim is about WHERE the bytes landed, which is untouched below.
  partial=false
  [ "$size" -gt 0 ] && [ "$size" -lt 67108864 ] && partial=true

  local measured=false
  if [ "$started" = true ] && [ "$size" -gt 0 ] && [ -n "$before" ]; then measured=true; fi
  untouched=false
  if [ "$measured" = true ] && [ "$before" = "$after" ] && [ ! -f "$ws/big.bin" ]; then untouched=true; fi

  echo "  probe container started:     $started"
  echo "  real workspace on the host:  $ws"
  echo "  shadow given to the probe:   $shadow"
  echo "  probe told to write to:      $ws  (first, before the shadow loop)"
  echo "  bytes written into shadow:   $size (of the 67108864 the probe was told to write, before the kill)"
  echo "  partial write in the shadow: $partial (recorded, not gated: a completed write is a race)"
  echo "  real workspace untouched:    $untouched"
  if [ "$measured" != true ]; then
    unmeasured "kill-mid-write: the probe did not start, or no write reached the shadow, so nothing here says the workspace was spared"
  elif [ "$untouched" != true ]; then
    ALL_HELD=0
  fi
  record "{\"check\":\"kill-mid-write\",\"measured\":$measured,\"containerStarted\":$started,\"workspaceWriteAttempted\":$measured,\"shadowBytes\":$size,\"partialInShadow\":$partial,\"realWorkspaceUntouched\":$untouched}"
  rm -rf "$ws" "$shadow"
}

cleanup() {
  docker rm -f "$NET-probe" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  [ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null
  [ -n "${CAPTURE_DIR:-}" ] && rm -rf "$CAPTURE_DIR"
  return 0
}
trap cleanup EXIT

HOST_KERNEL="$(uname -sr)"
HOST_ENGINE="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
HOST_CGROUP="$(docker info --format '{{.CgroupVersion}}' 2>/dev/null || echo unknown)"
HOST_FS="$(findmnt -no FSTYPE -T "$HERE" 2>/dev/null || echo unknown)"
# The schema requires every row to name the host and date that produced it (gate-truth.test.ts:
# "on what host and date"). It is stamped once here, from the same detected values as the host
# object above, and record() appends it to every row, so no row can be written without it.
PRODUCED_ON="$HOST_KERNEL, docker $HOST_ENGINE, $(date +%F)"

log "host"
echo "kernel  $HOST_KERNEL"
echo "engine  docker $HOST_ENGINE"
echo "cgroup  v$HOST_CGROUP"
echo "fs      $HOST_FS"

# --------------------------------------------------------------------------------------------
log "1. a no-default-route bridge blocks egress, tested by attempting it"

docker network create --internal "$NET" >/dev/null 2>&1 || { echo "cannot create internal network"; exit 1; }
BRIDGE="br-$(docker network inspect "$NET" --format '{{.Id}}' | cut -c1-12)"
echo "network $NET on interface $BRIDGE"

# Start the capture BEFORE any attempt, so check 3 measures the same traffic check 1 generates.
#
# CAPTURING is the answer to "is a capture of this run running", and check 3 below is gated on it.
# The first version computed it, printed it on the next line, and then never referred to it again:
# `awk 'NR>259 && /CAPTURING/'` over that file returned nothing. Check 3 asked instead whether a
# file existed at the published path, which is a question a committed file answers yes to.
CAPTURING=no
if [ -x "$TCPDUMP" ]; then
  # mktemp made CAPTURE_DIR for this run, so this path cannot already hold anyone else's capture.
  # Assert it anyway: if something is there, the assumption this check rests on is wrong and the
  # right move is to say so rather than to read it.
  if [ -e "$PCAP_RUN" ]; then
    echo "  refusing to capture: $PCAP_RUN already exists, and this run must write its own"
  else
    "$TCPDUMP" -i "$BRIDGE" -w "$PCAP_RUN" -U >"$CAPTURE_DIR/tcpdump.log" 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    # kill -0 rather than /proc, which does not exist everywhere this is read
    CAPTURING=$(kill -0 "$TCPDUMP_PID" 2>/dev/null && echo yes || echo no)
  fi
fi
echo "tcpdump on $BRIDGE: $CAPTURING"
[ "$CAPTURING" = yes ] || echo "  no capture is running, so check 3 has nothing of its own to read"

# Every destination class the boundary is supposed to refuse, each probed by literal IP so no name
# has to resolve for the row to mean what it says.
#
# None of these rows is named for a protocol any more. Two of them were: a "git protocol" row and an
# "ssh" row implied a port-aware or protocol-aware egress policy, and there is none here to test.
# The network is created --internal, so it has no route to any public address at all, and each row
# is one port's confirmation of that one fact. Several ports are still worth probing: if --internal
# is ever replaced by a filter that allows some of them, these rows go red. But the label no longer
# invites a reader to infer a policy, and each row carries a note saying what it does not show.
ROUTE_NOTE="an --internal bridge has no route to any public address, so this row shows this port refused on this host; it is not a test of port-aware or protocol-aware filtering, of which there is none here"
METADATA_NOTE="the credential endpoint on every major cloud, and it needs no DNS to reach, which is why it gets a row of its own; as above, the route is the variable and not the port"

attempt "public tcp 443"    1.1.1.1         443 "$ROUTE_NOTE"
attempt "cloud metadata 80" 169.254.169.254 80  "$METADATA_NOTE"

# These two rows used to name github.com and were probed by name from inside the jail, where DNS is
# blocked too. `nc: bad address 'github.com'` opened no socket, so they measured the DNS result a
# second and third time while reporting themselves as blocked PORTS. They are ports on a literal
# public address now, and they are labelled as such.
attempt "public tcp 9418"   1.1.1.1         9418 "$ROUTE_NOTE"
attempt "public tcp 22"     1.1.1.1         22   "$ROUTE_NOTE"

# DNS is its own fact, counted once. It used to be counted three times: the git and ssh rows were
# name lookups that failed for exactly this reason and were filed as blocked ports.
# This row has its own vocabulary on purpose. For a PORT, a name that did not resolve means no
# socket was opened and nothing was learned. For DNS itself, a name that did not resolve IS the
# measurement, so it is recorded as "unresolved" and never as a refused port.
DNS_OUT=$(probe nslookup "nslookup example.com")
classify "$DNS_OUT"
DNS_BLOCKED=false
DNS_VERDICT="not-measured"
case "$PROBE_VERDICT" in
  refused|name-unresolved) DNS_VERDICT="unresolved"; DNS_BLOCKED=true ;;
  reached) DNS_VERDICT="resolved"; ALL_HELD=0 ;;
  tool-missing) DNS_VERDICT="tool-missing"; unmeasured "dns: the image has no nslookup, so no lookup was ever attempted" ;;
  did-not-finish) DNS_VERDICT="did-not-finish"; unmeasured "dns: the lookup was cut short (rc=$PROBE_RC: a timeout or a signal), so nothing was learned" ;;
  not-measured) unmeasured "dns: the probe container never started" ;;
esac
DNS_NOTE="for a PORT a name that did not resolve means no socket was opened and nothing was learned; for DNS itself it IS the measurement, which is why this row says unresolved and never refused"
printf '  %-22s %-24s rc=%-6s measured=%-6s blocked=%s\n' "dns" "example.com" "$PROBE_RC" "$PROBE_MEASURED" "$DNS_BLOCKED"
record "{\"check\":\"egress\",\"target\":\"dns\",\"rc\":$PROBE_RC,\"measured\":$PROBE_MEASURED,\"verdict\":\"$DNS_VERDICT\",\"blocked\":$DNS_BLOCKED,\"note\":\"$(json_escape "$DNS_NOTE")\",\"detail\":\"$(json_escape "$(elide "$DNS_OUT")")\"}"

# --------------------------------------------------------------------------------------------
log "2. cgroup v2 limits are enforced, not silently no-op'd"

# A limit that is merely reported is not a limit. This asks the container to exceed it and requires
# the kernel to kill it: 137 is SIGKILL, which is what the OOM killer delivers.
#
# The control matters as much as the test. The first version allocated into /dev/shm without setting
# --shm-size, so the UNLIMITED run also failed, exit 1, because Docker defaults that tmpfs to 64 MB.
# A control that fails for its own unrelated reason proves nothing about the limit. Both runs now use
# the same workload and the same --shm-size, so the memory limit is the only difference between them.
# The control is also what makes this check MEASURED: if the unlimited run did not complete, the
# workload never ran and the limited run's exit code says nothing about any limit.
MEM_SEEN=$(docker run --rm --memory=64m "$IMAGE" cat /sys/fs/cgroup/memory.max 2>/dev/null | tr -d '\r')
docker run --rm --shm-size=256m --memory=64m --memory-swap=64m "$IMAGE" \
  sh -c 'dd if=/dev/zero of=/dev/shm/fill bs=1M count=200' >/dev/null 2>&1
MEM_LIMITED_RC=$?
docker run --rm --shm-size=256m "$IMAGE" \
  sh -c 'dd if=/dev/zero of=/dev/shm/fill bs=1M count=200' >/dev/null 2>&1
MEM_CONTROL_RC=$?
MEM_MEASURED=false
case "$MEM_SEEN" in ''|*[!0-9]*) ;; *) [ "$MEM_CONTROL_RC" = "0" ] && MEM_MEASURED=true ;; esac
MEM_ENFORCED=false
[ "$MEM_MEASURED" = true ] && [ "$MEM_LIMITED_RC" = "137" ] && MEM_ENFORCED=true
echo "  memory.max seen by the container: ${MEM_SEEN:-unreadable} (64 MiB = 67108864)"
echo "  same workload with --memory=64m : exit $MEM_LIMITED_RC  (137 = SIGKILL from the OOM killer)"
echo "  same workload with no limit     : exit $MEM_CONTROL_RC  (0 = the limit is what killed it)"
echo "  measured: $MEM_MEASURED   enforced: $MEM_ENFORCED"
[ "$MEM_MEASURED" = true ] || unmeasured "cgroup-memory: the control run did not complete, so the limited run's exit code means nothing"
record "{\"check\":\"cgroup-memory\",\"measured\":$MEM_MEASURED,\"limitBytes\":\"${MEM_SEEN:-null}\",\"limitedRc\":$MEM_LIMITED_RC,\"controlRc\":$MEM_CONTROL_RC,\"enforced\":$MEM_ENFORCED}"

PIDS_SEEN=$(docker run --rm --pids-limit=16 "$IMAGE" cat /sys/fs/cgroup/pids.max 2>/dev/null | tr -d '\r')
PIDS_MEASURED=false
[ -n "$PIDS_SEEN" ] && PIDS_MEASURED=true
PIDS_ENFORCED=false
[ "$PIDS_SEEN" = "16" ] && PIDS_ENFORCED=true
echo "  pids.max seen by the container: ${PIDS_SEEN:-unreadable}"
[ "$PIDS_MEASURED" = true ] || unmeasured "cgroup-pids: the container could not read its own pids.max"
record "{\"check\":\"cgroup-pids\",\"measured\":$PIDS_MEASURED,\"limit\":\"${PIDS_SEEN:-null}\",\"enforced\":$PIDS_ENFORCED}"

# --------------------------------------------------------------------------------------------
log "3. tcpdump captured the bridge, and what it saw"

sleep 1
[ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null && wait "$TCPDUMP_PID" 2>/dev/null

# Two gates, and check 3 reports a measurement only if both hold.
#
#   CAPTURING = yes   a capture process for THIS run was alive one second after it was asked to
#                     start. Computed since the first version and never once consulted.
#   -s PCAP_RUN       the file read is the per-run path, inside a directory mktemp made for this
#                     run. A committed capture cannot occupy it, and the published path is not read.
#
# Either gate alone closes the defect. Both are here because they fail for different reasons: the
# first catches a tcpdump that starts and dies, the second catches a tcpdump that was never asked to
# start at all, and neither can be satisfied by a file that arrived with the repository.
CAPTURE_OK=no
if [ "$CAPTURING" = yes ] && [ -s "$PCAP_RUN" ]; then CAPTURE_OK=yes; fi

# A capture file at the published path that THIS run did not write is the trap that made the defect
# reachable, and it is still a trap after the read is fixed: the next person finds a pcap sitting
# beside a script that reads pcaps. It is not deleted here, because a script that removes tracked
# files as a side effect is its own kind of surprise. It is named, hashed, and carried in the
# artefact, so boundary.json says out loud that evidence/ holds a capture this run did not make.
STALE_PUBLISHED=""
if [ "$CAPTURE_OK" != yes ] && [ -s "$PCAP_PUBLISHED" ]; then
  STALE_PUBLISHED="$(basename "$PCAP_PUBLISHED") sha256=$(sha256_of "$PCAP_PUBLISHED") bytes=$(size_of "$PCAP_PUBLISHED")"
  echo "  NOT THIS RUN'S: $PCAP_PUBLISHED exists and this run did not write it. It is not read."
  echo "                  $STALE_PUBLISHED"
fi

if [ "$CAPTURE_OK" = yes ]; then
  PCAP="$PCAP_RUN"
  PKTS=$("$TCPDUMP" -r "$PCAP" 2>/dev/null | wc -l | tr -d ' ')
  # A non-private destination appearing in a capture OF THE BRIDGE is not proof a packet left the
  # host. With an --internal bridge the SYN is emitted onto the bridge and dropped there, so the
  # field records what was emitted, under a name that says so. Calling it escapedTo invited a reader
  # to treat an emitted-and-dropped packet as a breach, which is this script's fault pointing the
  # other way. Whether anything was actually reached is the egress rows' verdict, where the evidence
  # for it is: a row whose verdict is "reached" clears ALL_HELD and fails the run.
  SEEN=$("$TCPDUMP" -r "$PCAP" -n 2>/dev/null \
    | grep -oE '> [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
    | grep -vE '> (10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.|127\.|169\.254\.255)' \
    | sort -u | head -5)
  TCPDUMP_NOTE="addresses emitted onto the bridge, not addresses reached; an --internal bridge drops them there, and whether anything was reached is the egress rows verdict"
  echo "  packets captured: $PKTS"
  echo "  non-private destinations seen on the bridge: ${SEEN:-none}"
  # Publishing is the last step, and it only happens for a capture this run made. Nothing reads this
  # path; it exists so a reviewer has the packets. It should not be committed: a tracked capture is
  # the file that made this whole check answerable by another machine's run.
  mv "$PCAP_RUN" "$PCAP_PUBLISHED" 2>/dev/null || cp "$PCAP_RUN" "$PCAP_PUBLISHED" 2>/dev/null
  record "{\"check\":\"tcpdump\",\"measured\":true,\"interface\":\"$BRIDGE\",\"capturing\":true,\"capturable\":true,\"packets\":$PKTS,\"publicDestinationsOnBridge\":\"$(json_escape "${SEEN:-}")\",\"note\":\"$(json_escape "$TCPDUMP_NOTE")\"}"
else
  if [ "$CAPTURING" = yes ]; then
    echo "  NO CAPTURE: tcpdump started on $BRIDGE but wrote nothing this run can read"
  else
    echo "  NO CAPTURE: no capture process of this run's was running on $BRIDGE"
  fi
  unmeasured "tcpdump: this run captured nothing, so check 3 was not performed on this host"
  STALE_FIELD=""
  [ -n "$STALE_PUBLISHED" ] && STALE_FIELD=",\"unreadPublishedCapture\":\"$(json_escape "$STALE_PUBLISHED")\""
  NOT_MINE_NOTE="check 3 reads only the capture this run wrote to a private per-run path; a file at the published path is never read, and is reported here if one is present"
  record "{\"check\":\"tcpdump\",\"measured\":false,\"interface\":\"$BRIDGE\",\"capturing\":$([ "$CAPTURING" = yes ] && echo true || echo false),\"capturable\":false,\"packets\":null,\"note\":\"$(json_escape "$NOT_MINE_NOTE")\"$STALE_FIELD}"
fi

# --------------------------------------------------------------------------------------------
log "4. a container killed mid-write leaves a recoverable state"
killed_mid_write_check

# --------------------------------------------------------------------------------------------
log "evidence"

# Three verdicts, not two. "held" is the only one that is a pass, and it needs both halves: every
# check ran, and every check that ran came back the way the boundary claims it should.
VERDICT=held
[ "$ALL_HELD" = 1 ] || VERDICT=breach
[ "$MEASURED_OK" = 1 ] || VERDICT=incomplete

{
  printf '{\n  "host": {"kernel": "%s", "engine": "docker %s", "cgroup": "v%s", "fs": "%s"},\n' \
    "$HOST_KERNEL" "$HOST_ENGINE" "$HOST_CGROUP" "$HOST_FS"
  printf '  "measuredEverything": %s,\n' "$([ "$MEASURED_OK" = 1 ] && echo true || echo false)"
  printf '  "everyMeasuredCheckHeld": %s,\n' "$([ "$ALL_HELD" = 1 ] && echo true || echo false)"
  printf '  "verdict": "%s",\n' "$VERDICT"
  printf '  "checks": [\n'
  for i in "${!results[@]}"; do
    printf '    %s%s\n' "${results[$i]}" "$([ "$i" -lt $((${#results[@]} - 1)) ] && echo ,)"
  done
  printf '  ]\n}\n'
} > "$OUT/boundary.json"
if [ "$CAPTURE_OK" = yes ]; then
  echo "wrote $OUT/boundary.json and $(basename "$PCAP_PUBLISHED"), captured by this run"
else
  echo "wrote $OUT/boundary.json. No capture file was written: this run captured nothing."
fi

if [ "$MEASURED_OK" != 1 ]; then
  echo "INCOMPLETE: at least one check did not run. This artefact is not evidence for those rows."
  exit 2
fi
if [ "$ALL_HELD" != 1 ]; then
  echo "BREACH: a check ran and the boundary did not hold. See boundary.json."
  exit 3
fi
echo "every check ran, and every one of them held."

#!/usr/bin/env bash
#
# cgroup-enforcement.sh - ask the kernel to kill a container that exceeds --memory, and refuse to
# report anything unless a control run proves the workload itself was fine.
#
# WHY THIS EXISTS. `container-confinement.test.ts:141` asserts that the string `--pids-limit`
# appears in the argv the product builds. That is an assertion about a command line: it holds
# identically on a kernel that enforces the limit and on one that accepts the flag and ignores it,
# which is the state nested virtualisation and a missing cgroup v2 controller both produce.
#
# `--memory` does not even have that. Searching the server sources for the flag returns three files
# that BUILD docker argv, container-codex-runner.ts:102, network-sealer.ts:181 and
# immutable-oracle.ts:167, and zero tests. The other occurrences of the word "memory" in
# container-confinement.test.ts are the agent's memory directory, which is a different thing.
# Nothing anywhere asks whether the kernel kills.
#
# THE CONTROL IS THE POINT, and this repository already got it wrong once. The first version of the
# same measurement in evidence-boundary.sh allocated into /dev/shm without setting --shm-size, so
# Docker's default 64 MB tmpfs made the UNLIMITED run fail too, exit 1, for a reason that had
# nothing to do with any limit. A limited run that dies proves nothing on its own: it has to die
# where an otherwise identical unlimited run lives. Both runs below use the same image, the same
# workload and the same --shm-size, so the memory limit is the only difference between them.
#
# EXIT CONTRACT, three outcomes and never two:
#   0   measured AND enforced: control exited 0, the limited run was killed with SIGKILL
#   1   NOT ENFORCED: the workload ran to completion under the limit, so the limit is decorative
#   2   NOT MEASURED: something upstream of the question failed, so no verdict is available
# A run that could not measure exits non-zero rather than printing a confident line, because
# "could not measure" reported as "held" is the defect this whole evidence directory exists to stop.
#
# An earlier version had a fourth state wearing the second one's label: a limited run that exited
# neither 0 nor 137 printed "NOT ENFORCED", exited 1, and wrote `"measured":true,"enforced":false`,
# while its own prose said the exit "has to be named before this counts either way". Something that
# counts neither way is NOT MEASURED, so that path exits 2 and writes `"measured":false` now. An
# unexplained exit recorded as a negative enforcement verdict is a made-up finding on the headline
# containment claim, which is worse than saying nothing.
#
# Usage:
#   bash evidence/cgroup-enforcement.sh [IMAGE] [JSON_OUT]
# IMAGE defaults to volc-agent-runtime:local, which is the image the product actually runs turns in.

set -uo pipefail

IMAGE="${1:-volc-agent-runtime:local}"
JSON_OUT="${2:-}"

LIMIT_BYTES=67108864          # 64 MiB, the number the lane report cites as memory.max
ALLOC_MB=200                  # comfortably past the limit, comfortably inside the tmpfs below
SHM=256m                      # sized on BOTH runs so the tmpfs is never the thing that fails
# /dev/shm is tmpfs and its pages are charged to the container's memory cgroup, so this exceeds the
# limit without depending on any language runtime's heap behaviour. `dd` is in every image here.
WORKLOAD="dd if=/dev/zero of=/dev/shm/fill bs=1M count=${ALLOC_MB}"

say() { printf '%s\n' "$*"; }
fail_unmeasured() { say "NOT MEASURED: $*"; exit 2; }

say "cgroup memory enforcement, measured on this host"
say "  image:    ${IMAGE}"
say "  workload: sh -c '${WORKLOAD}'"
say ""

command -v docker >/dev/null 2>&1 || fail_unmeasured "no docker on PATH"
docker info >/dev/null 2>&1 || fail_unmeasured "\`docker info\` failed: no engine to ask"
docker image inspect --format '{{.Id}}' "$IMAGE" >/dev/null 2>&1 \
  || fail_unmeasured "the image ${IMAGE} is not present, so nothing was run"

HOST_CGROUP=$(docker info --format '{{.CgroupVersion}}' 2>/dev/null || echo unknown)
HOST_KERNEL=$(docker info --format '{{.KernelVersion}}' 2>/dev/null || echo unknown)
HOST_ENGINE=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)
say "  host:     cgroup v${HOST_CGROUP}, kernel ${HOST_KERNEL}, docker ${HOST_ENGINE}"

# 1. Did the flags reach the kernel at all? Read the limits back from inside the container rather
#    than trusting that passing --memory means anything happened.
#
#    BOTH flags, and with the SAME argv the measured run below uses. An earlier version read the
#    limit back under `--memory=64m` alone while the measurement ran under `--memory=64m
#    --memory-swap=64m`, so it verified a configuration it did not then test, and it never looked at
#    memory.swap.max at all. That is the one this script's own comment calls load-bearing: without
#    --memory-swap Docker grants twice the memory as swap, the allocation succeeds under the limit,
#    and the script prints NOT ENFORCED. A red on the headline containment claim caused by a flag
#    that did not land is a wrong answer, not a cautious one.
#
#    On cgroup v2, --memory-swap equal to --memory means a swap allowance of zero, so
#    memory.swap.max reads 0.
READBACK=$(docker run --rm --memory=64m --memory-swap=64m "$IMAGE" \
  sh -c 'cat /sys/fs/cgroup/memory.max; cat /sys/fs/cgroup/memory.swap.max' 2>/dev/null | tr -d '\r')
SEEN=$(printf '%s\n' "$READBACK" | sed -n '1p')
SEEN_SWAP=$(printf '%s\n' "$READBACK" | sed -n '2p')

case "$SEEN" in
  ''|*[!0-9]*) fail_unmeasured "the container could not read its own /sys/fs/cgroup/memory.max (got '${SEEN}'), so this host cannot answer the question" ;;
esac
say "  memory.max      seen from inside: ${SEEN} (expected ${LIMIT_BYTES})"
[ "$SEEN" = "$LIMIT_BYTES" ] \
  || fail_unmeasured "the container sees memory.max=${SEEN}, not ${LIMIT_BYTES}: the flag did not land as written and the runs below would be testing an unknown limit"

# Unreadable is NOT MEASURED rather than NOT ENFORCED, deliberately. A host with swap accounting off
# has no memory.swap.max to read, and on such a host a limited run that survives cannot be told apart
# from a limit that is real and a swap allowance that saved it. Exit 2 says that; exit 1 would
# publish a containment failure this script cannot actually see.
say "  memory.swap.max seen from inside: ${SEEN_SWAP:-(unreadable)} (expected 0)"
case "$SEEN_SWAP" in
  ''|*[!0-9]*) fail_unmeasured "the container could not read /sys/fs/cgroup/memory.swap.max (got '${SEEN_SWAP}'), so whether --memory-swap landed is unknown and a surviving limited run below could not be told from swap" ;;
esac
[ "$SEEN_SWAP" = "0" ] \
  || fail_unmeasured "the container sees memory.swap.max=${SEEN_SWAP}, not 0: --memory-swap did not land, the container may swap past the limit, and a limited run that survives would say nothing about enforcement"

# 2. The control, FIRST. If the workload cannot complete unlimited, the limited run's exit code is
#    not evidence about a limit and there is nothing to report.
say ""
say "  control run, no --memory ..."
# Output kept rather than discarded. An earlier version sent both streams to /dev/null, so the one
# branch a reader most needs to debug, a control that failed for its own reason, printed the words
# "the workload fails for its own reason" and left no reason anywhere in the CI log.
CONTROL_OUT="$(mktemp)"
docker run --rm --shm-size="$SHM" "$IMAGE" sh -c "$WORKLOAD" >"$CONTROL_OUT" 2>&1
CONTROL_RC=$?
say "  control run, no --memory:            exit ${CONTROL_RC}"
if [ "$CONTROL_RC" != "0" ]; then
  say "  what the control printed:"
  sed -n '1,20p' "$CONTROL_OUT" | sed 's/^/    /'
  rm -f "$CONTROL_OUT"
  fail_unmeasured "the control run exited ${CONTROL_RC}, so the workload fails for its own reason and the limited run below says nothing about any limit"
fi
rm -f "$CONTROL_OUT"

# 3. The measurement. --memory-swap equal to --memory disables swap for the container; without it
#    Docker grants twice the memory as swap and the allocation can succeed under the limit.
say "  limited run, --memory=64m --memory-swap=64m ..."
LIMITED_OUT="$(mktemp)"
docker run --rm --shm-size="$SHM" --memory=64m --memory-swap=64m "$IMAGE" sh -c "$WORKLOAD" >"$LIMITED_OUT" 2>&1
LIMITED_RC=$?
say "  limited run, --memory=64m:           exit ${LIMITED_RC}  (expected 137 = 128+9, SIGKILL from the OOM killer)"

# Three named states, and the JSON says which. `measured` is false for the third, because the third
# is the one whose own prose says it counts neither way.
#   137 -> enforced         measured true,  enforced true,  exit 0
#   0   -> not enforced     measured true,  enforced false, exit 1
#   else-> unexplained      measured false, enforced null,  exit 2
if [ "$LIMITED_RC" = "137" ]; then
  VERDICT=enforced; MEASURED=true; ENFORCED=true; RC=0
elif [ "$LIMITED_RC" = "0" ]; then
  VERDICT=not-enforced; MEASURED=true; ENFORCED=false; RC=1
else
  VERDICT=unexplained; MEASURED=false; ENFORCED=null; RC=2
fi

if [ -n "$JSON_OUT" ]; then
  printf '{"check":"cgroup-memory-enforcement","host":{"cgroup":"v%s","kernel":"%s","engine":"docker %s"},"image":"%s","limitBytes":%s,"allocMb":%s,"memoryMaxSeen":%s,"memorySwapMaxSeen":%s,"controlRc":%s,"limitedRc":%s,"verdict":"%s","measured":%s,"enforced":%s}\n' \
    "$HOST_CGROUP" "$HOST_KERNEL" "$HOST_ENGINE" "$IMAGE" "$LIMIT_BYTES" "$ALLOC_MB" \
    "$SEEN" "$SEEN_SWAP" "$CONTROL_RC" "$LIMITED_RC" "$VERDICT" "$MEASURED" "$ENFORCED" > "$JSON_OUT"
  say "  wrote ${JSON_OUT}"
fi

say ""
if [ "$VERDICT" = enforced ]; then
  rm -f "$LIMITED_OUT"
  say "MEASURED AND ENFORCED: the same workload completes unlimited (exit 0) and is killed by the"
  say "kernel under --memory=64m (exit 137). The limit is not decorative on this host."
  exit "$RC"
fi

if [ "$VERDICT" = not-enforced ]; then
  rm -f "$LIMITED_OUT"
  say "NOT ENFORCED: the workload allocated ${ALLOC_MB} MiB to completion under a ${LIMIT_BYTES} byte"
  say "limit, with memory.max and memory.swap.max both read back as written. The flag is accepted and"
  say "ignored on this host, so --memory in the product's argv buys nothing here and the confinement"
  say "claim that rests on it does not hold."
  exit "$RC"
fi

say "NOT MEASURED: the limited run exited ${LIMITED_RC} rather than 137 or 0. The control passed, so"
say "the workload is fine; something other than the OOM killer ended this run. That is not a verdict"
say "about the limit in either direction and it has to be named before it becomes one."
say "  what the limited run printed:"
sed -n '1,20p' "$LIMITED_OUT" | sed 's/^/    /'
rm -f "$LIMITED_OUT"
exit "$RC"

#!/usr/bin/env bash
# The no-key path: the whole platform, started for real, against a mock model provider.
#
# `npm run poc` needs an Ark key. This does not. It starts a mock provider that speaks the same
# Responses API codex speaks, hands the platform its address, and then runs the ordinary
# `scripts/start-local-poc.sh` with nothing else changed. Everything below the model is the real
# thing: the real control plane, the real runtime container, the real transaction, the real policy,
# the real journal, the real browser panel.
#
# The provider container sits on the default bridge, which is exactly where a real provider sits
# from the platform's point of view: the dual-homed egress broker can reach it and the agent
# container, alone on a per-run `--internal` network, cannot.
#
#   npm run poc:mock
#
# Environment it accepts:
#   MOCK_PROVIDER_PORT    port the mock listens on inside its container (default 8398)
#   MOCK_PROVIDER_STATE   host directory for its playbook and request log
#                         (default $HOME/.volc-agent-launchpad/mock-provider)
#   MOCK_PROVIDER_IMAGE   image the mock runs in (default node:22-bookworm-slim, the broker's own)
#   MOCK_PROVIDER_USER    uid:gid the provider runs as inside its container. Default: this
#                         shell's own under a rootful engine, and nothing at all under a
#                         rootless one. Set it to the empty string to pass no --user, or to a
#                         uid:gid to pin one. See the note above the run for why either is
#                         wrong on the other kind of engine.
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

port="${MOCK_PROVIDER_PORT:-8398}"
state_dir="${MOCK_PROVIDER_STATE:-$HOME/.volc-agent-launchpad/mock-provider}"
image="${MOCK_PROVIDER_IMAGE:-node:22-bookworm-slim}"
container="${MOCK_PROVIDER_CONTAINER:-shadow-mock-provider}"
# Not a credential. It is the string the mock expects to see arrive, which is how the run proves
# the one-turn token the container holds was swapped for the platform's key at the broker.
mock_key="mock-provider-key"

log() {
  printf '[mock-poc] %s\n' "$*" >&2
}

engine_works() {
  "$1" info >/dev/null 2>&1
}

detect_engine() {
  if [[ -n "${CONTAINER_ENGINE:-}" ]] && command -v "$CONTAINER_ENGINE" >/dev/null 2>&1 && engine_works "$CONTAINER_ENGINE"; then
    printf '%s' "$CONTAINER_ENGINE"
    return
  fi
  if command -v docker >/dev/null 2>&1 && engine_works docker; then
    printf 'docker'
    return
  fi
  if command -v colima >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
    log "Docker is not reachable; starting Colima."
    colima start >&2
    if engine_works docker; then
      printf 'docker'
      return
    fi
  fi
  if command -v podman >/dev/null 2>&1; then
    if ! engine_works podman && [[ "$(uname -s)" == "Darwin" ]]; then
      podman machine start >&2 || true
    fi
    if engine_works podman; then
      printf 'podman'
      return
    fi
  fi
  log "No running Docker, Colima, or Podman engine was found."
  return 1
}

engine="$(detect_engine)"
log "Using $engine."

mkdir -p "$state_dir"
# The mock's code is copied rather than bind-mounted from the checkout, so the only host directory
# the engine has to be able to share is one under $HOME. A repository cloned somewhere the VM does
# not mount still works.
cp "$repo_dir/scripts/mock-provider.mjs" "$state_dir/mock-provider.mjs"
: >"$state_dir/provider.jsonl"
if [[ ! -f "$state_dir/playbook.json" ]]; then
  printf '{"entries":[]}\n' >"$state_dir/playbook.json"
fi

"$engine" rm --force "$container" >/dev/null 2>&1 || true

cleanup() {
  "$engine" rm --force "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# The sealer creates this too, but the provider starts before any turn does, so whoever gets there
# first makes it. "already exists" is the state we want, so it is not an error.
egress="${SHADOW_EGRESS_NETWORK:-shadow-egress}"
"$engine" network create --ipv6=false "$egress" >/dev/null 2>&1 || true

# Who the provider is inside its container, which decides whether it can write its own log.
#
# It appends every request to $state_dir/provider.jsonl, a file this script just created as the
# invoking user. `--cap-drop ALL` takes CAP_DAC_OVERRIDE away from the container's root, so under a
# rootful engine on a host whose bind mounts carry real uids -- Linux, not a Docker Desktop or
# Colima VM -- that root cannot append to it. The provider then starts, answers 200, and logs
# nothing, which is the same shape as the broker defect in docs/lane-reports/linux-subham.md:
# two correct decisions, fatal only together. Running as the invoking uid fixes it.
#
# A rootless engine is the other side of the same coin. There the container's root ALREADY maps to
# the invoking user through a user namespace, so the mount is writable as it stands, and pinning
# --user to the host uid maps it into the subuid range instead, which owns nothing. So: podman gets
# --userns keep-id beside the uid, the pairing scripts/start-local-poc.sh and
# apps/server/src/container-codex-runner.ts already use for it; rootless docker gets no --user at
# all; everything else gets the uid. MOCK_PROVIDER_USER overrides the lot.
#
# The podman branch assumes podman is rootless. Under a ROOTFUL podman, `--userns keep-id` is
# wrong and this script would pass it. That is not a hazard this file introduced, because it is
# not reachable: scripts/start-local-poc.sh exits 2 on rootful podman before any of this runs, so
# `npm run poc:mock` was already dead on such a host. It is written down rather than left implied,
# because the day that exit is relaxed this branch becomes wrong and nothing else says so.
#
# `${arr[@]+...}` because macOS ships bash 3.2, where `"${arr[@]}"` on an empty array is fatal
# under `set -u`.
provider_user_args=()
if [[ -n "${MOCK_PROVIDER_USER+set}" ]]; then
  # Configured, empty included: an empty value means "pass no --user at all".
  if [[ -n "$MOCK_PROVIDER_USER" ]]; then
    provider_user_args=(--user "$MOCK_PROVIDER_USER")
  fi
elif [[ "$(basename "$engine")" == "podman" ]]; then
  provider_user_args=(--user "$(id -u):$(id -g)" --userns keep-id)
elif [[ "$("$engine" info --format '{{.SecurityOptions}}' 2>/dev/null || true)" == *name=rootless* ]]; then
  # The rootless daemon adds `name=rootless` to that bracketed list. Only asked of docker: podman
  # reports rootlessness somewhere else entirely and is already handled by name above.
  #
  # Deliberately a command substitution and not `info | grep -q`. Under `set -o pipefail` a `grep -q`
  # that closes the pipe on its first match can leave the producer killed by SIGPIPE, and the
  # pipeline then reports 141 whatever grep decided. Measured on this host: 0 in 200 with a
  # one-line producer, which is what `{{.SecurityOptions}}` is, and 20 in 20 with a large one. So it
  # is not reachable through this format string today, and it is one line to make unreachable at all.
  log "Rootless $engine: the container's root is already this user, so no --user is passed."
else
  provider_user_args=(--user "$(id -u):$(id -g)")
fi

log "Starting the mock provider on the shared egress network."
"$engine" run --detach --rm --init \
  --name "$container" \
  --label io.codejam.launchpad=mock-provider \
  --network "${SHADOW_EGRESS_NETWORK:-shadow-egress}" \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  ${provider_user_args[@]+"${provider_user_args[@]}"} \
  --memory 256m \
  --pids-limit 64 \
  --mount "type=bind,src=$state_dir,dst=/state" \
  "$image" \
  node /state/mock-provider.mjs "$port" "$mock_key" /state/provider.jsonl /state/playbook.json \
  >/dev/null

ready=""
for _ in $(seq 1 100); do
  if "$engine" logs "$container" 2>&1 | grep -q "mock-provider.ready"; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ -z "$ready" ]]; then
  log "The mock provider did not start:"
  "$engine" logs "$container" >&2 || true
  exit 1
fi

address="$("$engine" inspect --format '{{(index .NetworkSettings.Networks "'"${SHADOW_EGRESS_NETWORK:-shadow-egress}"'").IPAddress}}' "$container")"
if [[ -z "$address" ]]; then
  log "The mock provider has no address on the shared egress network."
  exit 1
fi
log "Mock provider at $address:$port (reachable by the broker, not by the agent)."

# What the demo driver needs to find the same provider the platform is talking to.
cat >"$state_dir/provider.json" <<JSON
{
  "container": "$container",
  "address": "$address",
  "port": $port,
  "baseUrl": "http://$address:$port/api/v3",
  "statePath": "$state_dir",
  "playbookPath": "$state_dir/playbook.json",
  "logPath": "$state_dir/provider.jsonl"
}
JSON

export ARK_BASE_URL="http://$address:$port/api/v3"
export ARK_API_KEY="$mock_key"
export ARK_MODEL="${ARK_MODEL:-ep-mock-endpoint}"
export CONTAINER_ENGINE="$engine"

log "Handing off to scripts/start-local-poc.sh."
"$repo_dir/scripts/start-local-poc.sh"

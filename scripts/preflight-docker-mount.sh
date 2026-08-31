#!/usr/bin/env bash
# Warns, once, before the container-gated tests run, when this checkout sits somewhere the
# reachable container engine cannot bind-mount from. On Colima (and on Docker Desktop with
# default file-sharing settings) that is anywhere outside $HOME, and the failure mode without
# this warning is confusing: `npm run check` does not skip the affected tests with a reason, it
# runs them and they fail with a raw `docker: ... bind source path does not exist` for a path
# that plainly exists on the host, because it does not exist inside the engine's VM.
#
# This script never fails the build. It only prints. A real problem here still surfaces as the
# test suite's own failure, with this warning printed just above it as context.
set -uo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

engine=""
for candidate in docker podman; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
    engine="$candidate"
    break
  fi
done

# No reachable engine at all: the docker-gated tests already skip on their own with a printed
# reason in that case. Nothing to warn about.
[[ -z "$engine" ]] && exit 0

probe_name="shadow-commit-mount-probe-$$"
if ! "$engine" run --rm --name "$probe_name" \
    --mount "type=bind,src=$repo_dir/apps/server/broker,dst=/probe,readonly" \
    node:22-bookworm-slim true >/dev/null 2>&1; then
  cat >&2 <<EOF
[preflight] $engine cannot bind-mount this checkout ($repo_dir) into a container.
[preflight] The container-gated tests below will fail with "bind source path does not exist"
[preflight]   for paths that are real on the host, instead of skipping with a reason.
[preflight] This is expected on Colima, and on Docker Desktop with default file-sharing
[preflight]   settings, when the checkout sits outside \$HOME (for example under /tmp).
[preflight] Fix: move this checkout under \$HOME, or add its parent directory to the engine's
[preflight]   file-sharing list (Colima: "colima start --mount <dir>:w"; Docker Desktop:
[preflight]   Settings -> Resources -> File Sharing), then rerun.
[preflight] This message is a warning only and does not stop the run.
EOF
fi
exit 0

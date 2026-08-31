#!/usr/bin/env bash
# Shared preparation: build the policy and generate the corpus once.
# Sourced by every job script. Leaves the kit at a known state.
set -euo pipefail
export PATH="$HOME/node22/bin:$PATH"
KIT="$HOME/codejam-corpus"
cd "$KIT"

echo "[prep] node $(node --version) on $(hostname), $(nproc) cpus"
echo "[prep] kit at $(git rev-parse --short HEAD)"

# Node-local scratch. /home is NFS and the harness materialises a temp tree per scenario.
export TMPDIR="${LOCAL_TMP:-/tmp/cj-$SLURM_JOB_ID}"
mkdir -p "$TMPDIR"
echo "[prep] TMPDIR=$TMPDIR"

echo "[prep] pinning benign sources"
bash research/corpus/setup.sh

echo "[prep] building the server policy (the artifact under test)"
npm run build -w @launchpad/server >/dev/null
test -f apps/server/dist/shadow-policy.js

echo "[prep] generating scenarios"
cd research/corpus
node import-redteam.mjs >/dev/null
node generate.mjs        >/dev/null
node benign/gen-benign.mjs >/dev/null
wc -l scenarios/*.jsonl
cd "$KIT"
echo "[prep] done"

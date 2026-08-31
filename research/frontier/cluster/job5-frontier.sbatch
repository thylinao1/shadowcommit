#!/usr/bin/env bash
#SBATCH --job-name=cj-frontier
#SBATCH --partition=long
#SBATCH --cpus-per-task=32
#SBATCH --mem=64G
#SBATCH --time=24:00:00
# Replay the whole corpus once per parameter setting, and turn "why 5 lines and 400 characters" from
# a thing that looked right into a frontier.
#
# It runs out of ~/codejam-frontier rather than ~/codejam-corpus, and has its own prep inline rather
# than sourcing bin/prep.sh, because prep.sh hardcodes KIT to codejam-corpus and job 774997 is
# replaying that tree right now. Two jobs rebuilding one checkout is a race that would quietly
# corrupt both.
set -euo pipefail
export PATH="$HOME/node22/bin:$PATH"

KIT="$HOME/codejam-frontier"
export KIT
OUTDIR="$HOME/codejam-results/05-frontier"
mkdir -p "$OUTDIR/workers"
export LOCAL_TMP="/tmp/cj-frontier-$SLURM_JOB_ID"
mkdir -p "$LOCAL_TMP"
export TMPDIR="$LOCAL_TMP"

cd "$KIT"
echo "[frontier] node $(node --version) on $(hostname), $(nproc) cpus"
git rev-parse HEAD > "$OUTDIR/graded-revision.txt"
echo "[frontier] kit at $(git rev-parse --short HEAD)"

[ -d node_modules ] || npm ci --silent
echo "[frontier] pinning benign sources"
bash research/corpus/setup.sh
echo "[frontier] building the policy"
npm run build -w @launchpad/server >/dev/null
test -f apps/server/dist/shadow-policy.js
echo "[frontier] generating scenarios"
cd research/corpus
node import-redteam.mjs >/dev/null
node generate.mjs        >/dev/null
node benign/gen-benign.mjs >/dev/null
wc -l scenarios/*.jsonl
cd "$KIT"

DIST="$KIT/apps/server/dist"
WORKERS=24

node "$HOME/codejam-results/bin/gen-frontier-settings.mjs" "$DIST" "$OUTDIR/settings.json" \
  | tee "$OUTDIR/settings-inventory.txt"

echo "[frontier] staging $WORKERS worker copies of dist"
for w in $(seq 0 $((WORKERS - 1))); do
  mkdir -p "$LOCAL_TMP/w$w/tmp"
  cp -r "$DIST" "$LOCAL_TMP/w$w/dist"
done

echo "[frontier] running"
pids=()
for w in $(seq 0 $((WORKERS - 1))); do
  node "$HOME/codejam-results/bin/frontier-worker.mjs" \
      "$OUTDIR/settings.json" "$w" "$WORKERS" "$LOCAL_TMP/w$w" "$OUTDIR/workers/w$w.jsonl" \
      >> "$OUTDIR/workers/w$w.log" 2>&1 &
  pids+=($!)
done

( while true; do
    sleep 120
    node "$HOME/codejam-results/bin/frontier-report.mjs" "$OUTDIR" > "$OUTDIR/FRONTIER-REPORT.txt" 2>/dev/null || true
  done ) &
REPORTER=$!

for p in "${pids[@]}"; do wait "$p" || true; done
kill "$REPORTER" 2>/dev/null || true

node "$HOME/codejam-results/bin/frontier-report.mjs" "$OUTDIR" > "$OUTDIR/FRONTIER-REPORT.txt"
head -60 "$OUTDIR/FRONTIER-REPORT.txt"
rm -rf "$LOCAL_TMP"
echo "[frontier] job $SLURM_JOB_ID finished at $(date -Is)"

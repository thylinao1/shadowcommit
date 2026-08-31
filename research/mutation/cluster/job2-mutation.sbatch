#!/usr/bin/env bash
#SBATCH --job-name=cj-mutation
#SBATCH --partition=normal
#SBATCH --cpus-per-task=32
#SBATCH --mem=64G
#SBATCH --time=03:00:00
set -euo pipefail

OUTDIR="$HOME/codejam-results/02-mutation"
mkdir -p "$OUTDIR/workers"
export LOCAL_TMP="/tmp/cj-mutation-$SLURM_JOB_ID"
export KIT="$HOME/codejam-corpus"

source "$HOME/codejam-results/bin/prep.sh"
cd "$KIT"

DIST="$KIT/apps/server/dist"
WORKERS=24
MAX_MUTANTS=${MAX_MUTANTS:-2400}

# ---------------------------------------------------------------------------
# 1. Baseline: the decisions the SHIPPED policy gives, keyed by scenario id.
# ---------------------------------------------------------------------------
if [ ! -f "$OUTDIR/baseline-decisions.json" ]; then
  echo "[mutation] baseline replay"
  mkdir -p "$OUTDIR/baseline"
  TMPDIR="$LOCAL_TMP/baseline" && mkdir -p "$TMPDIR" && export TMPDIR
  node research/corpus/replay-v2.mjs --policy "$DIST/shadow-policy.js" --out "$OUTDIR/baseline/results.jsonl"
  node -e '
    const fs=require("fs"); const m={};
    for (const l of fs.readFileSync(process.argv[1],"utf8").split("\n")) if(l.trim()){const r=JSON.parse(l); m[r.id]=r.decision;}
    fs.writeFileSync(process.argv[2], JSON.stringify(m));
    console.log("baseline decisions for "+Object.keys(m).length+" scenarios");
  ' "$OUTDIR/baseline/results.jsonl" "$OUTDIR/baseline-decisions.json"
fi

# ---------------------------------------------------------------------------
# 2. Enumerate mutants of the built rule modules.
# ---------------------------------------------------------------------------
node "$HOME/codejam-results/bin/gen-mutants.mjs" "$DIST" "$OUTDIR/mutants.json" --max "$MAX_MUTANTS" \
  | tee "$OUTDIR/mutants-inventory.txt"

# ---------------------------------------------------------------------------
# 3. One private dist copy per worker, then run them all.
# ---------------------------------------------------------------------------
echo "[mutation] staging $WORKERS worker copies of dist on node-local disk"
for w in $(seq 0 $((WORKERS - 1))); do
  mkdir -p "$LOCAL_TMP/w$w/tmp"
  cp -r "$DIST" "$LOCAL_TMP/w$w/dist"
done

echo "[mutation] running"
pids=()
for w in $(seq 0 $((WORKERS - 1))); do
  node "$HOME/codejam-results/bin/mutation-worker.mjs" \
      "$OUTDIR/mutants.json" "$OUTDIR/baseline-decisions.json" \
      "$w" "$WORKERS" "$LOCAL_TMP/w$w" "$OUTDIR/workers/w$w.jsonl" \
      >> "$OUTDIR/workers/w$w.log" 2>&1 &
  pids+=($!)
done

# A rolling report every two minutes, so the directory is readable while the job is still running
# and a job that is killed at the wall clock still leaves a current summary behind.
( while true; do
    sleep 120
    node "$HOME/codejam-results/bin/mutation-report.mjs" "$OUTDIR" > "$OUTDIR/MUTATION-REPORT.txt" 2>/dev/null || true
  done ) &
REPORTER=$!

for p in "${pids[@]}"; do wait "$p" || true; done
kill "$REPORTER" 2>/dev/null || true

node "$HOME/codejam-results/bin/mutation-report.mjs" "$OUTDIR" > "$OUTDIR/MUTATION-REPORT.txt"
tail -40 "$OUTDIR/MUTATION-REPORT.txt"
rm -rf "$LOCAL_TMP"
echo "[mutation] job $SLURM_JOB_ID finished at $(date -Is)"

#!/usr/bin/env bash
# Is the benign half of the corpus realistic enough for its numbers to mean anything?
#
#   bash research/benign-realism/run.sh
#
# Reads research/corpus (scenarios, results, the classifiers and the replay harness) and writes
# only into research/benign-realism/out. It never regenerates or overwrites anything the corpus owns:
# every replay below passes --out into this directory, which is also where replay-v2.mjs puts its
# run-manifest.json.
#
# Prerequisites, both already true after `npm run corpus`:
#   research/corpus/scenarios/benign.jsonl   the 5,000 benign scenarios
#   research/corpus/results/results.jsonl    the published run
#   apps/server/dist/                        the built policy the published run graded
#
# Stage 0 prints the composed policy's closure digest. If it does not equal the policy_sha256 in
# research/corpus/results/run-manifest.json, this run is grading a DIFFERENT policy from the one the
# published figures came from and the comparison below is not a comparison.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=research/benign-realism/out

echo "== 0. the policy under test is the policy the published figures graded"
node -e 'import("./research/corpus/lib/shipped-policy.mjs").then(m=>{
  const d=m.policyDigest("apps/server/dist").digest;
  const want=require("./research/corpus/results/run-manifest.json").policy_sha256;
  console.log("   composed closure digest",d);
  console.log("   published run graded   ",want);
  if(d!==want){console.error("   DIFFERENT POLICY: every comparison below is void"); process.exit(1);}
  console.log("   same policy");
});'

echo "== 1. shape of a turn: benign corpus versus real git history"
node research/benign-realism/shape.mjs --out $OUT/shape.json

echo "== 2. build the held-out set from real non-merge commits"
node research/benign-realism/build-heldout.mjs --per 400 --out $OUT/heldout-real.jsonl

echo "== 3. replay it, in shards, against the same composed policy"
node research/benign-realism/shard.mjs $OUT/heldout-real.jsonl $OUT/shards 15000000
mkdir -p $OUT/results
for s in $OUT/shards/shard-*.jsonl; do
  node research/corpus/replay-v2.mjs --scenarios "$PWD/$s" --out "$PWD/$OUT/results/$(basename "$s")"
done
cat $OUT/results/shard-*.jsonl > $OUT/heldout-results.jsonl

echo "== 4. control: the same pipeline must reproduce the published benign figures exactly"
node research/benign-realism/shard.mjs research/corpus/scenarios/benign.jsonl $OUT/shards-corpusbenign 15000000
mkdir -p $OUT/results-corpusbenign
for s in $OUT/shards-corpusbenign/shard-*.jsonl; do
  node research/corpus/replay-v2.mjs --scenarios "$PWD/$s" --out "$PWD/$OUT/results-corpusbenign/$(basename "$s")"
done
cat $OUT/results-corpusbenign/shard-*.jsonl > $OUT/corpusbenign-results.jsonl
node -e '
const fs=require("fs");
const mine=fs.readFileSync("research/benign-realism/out/corpusbenign-results.jsonl","utf8").trim().split("\n").map(JSON.parse);
const pub=new Map(fs.readFileSync("research/corpus/results/results.jsonl","utf8").trim().split("\n").map(JSON.parse).filter(r=>r.intent==="benign").map(r=>[r.id,r]));
let diff=0; for(const r of mine){const p=pub.get(r.id); if(!p||p.decision!==r.decision||p.rule!==r.rule)diff++;}
const d={}; for(const r of mine) d[r.decision]=(d[r.decision]||0)+1;
console.log("   rerun of the corpus benign half through this pipeline:",JSON.stringify(d));
console.log("   rows disagreeing with the published run:",diff);
if(diff!==0){console.error("   the pipeline is not neutral; the held-out comparison is void");process.exit(1);}
'

echo "== 5. the four answers"
node research/benign-realism/analyse.mjs
node research/benign-realism/robust.mjs

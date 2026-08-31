#!/usr/bin/env bash
# The corpus green gate: the pure-library tests pass, the corpus regenerates deterministically from
# its seeds, the harness runs against the kit's own built policy composed the way the server
# composes it, the report is written, and every published number recomputes from the raw results.
# Offline apart from the one-time clones in setup.sh; no container, no model.
#
#   npm run corpus            # setup.sh then this
#   bash research/corpus/check.sh
set -euo pipefail
cd "$(dirname "$0")"

KIT_DIR="$(cd ../.. && pwd)"
POLICY="$KIT_DIR/apps/server/dist/shadow-policy.js"

for repo in click cobra express starter-kit; do
  test -e "repos/$repo/.git" || { echo "FAIL: repos/$repo is missing; run  bash research/corpus/setup.sh"; exit 1; }
done

echo "== 1. library self-tests =="
# Node 22 does not do test-file discovery for a bare directory here, so the file is named.
node --test lib/lib.test.mjs

echo "== 2. build the kit policy (the artifact under test) =="
( cd "$KIT_DIR" && npm run build -w @launchpad/server >/dev/null )
test -f "$POLICY" || { echo "FAIL: $POLICY not built"; exit 1; }

# A source at the wrong revision produces a fully green run built from the wrong bytes, which is
# exactly the defect pinning exists to prevent. Until this check, that was guarded only by having
# run setup.sh immediately beforehand: moving express 40 commits back and running this script
# printed PASS with the wrong commit recorded in the manifest.
echo "== 2b. every benign source is at its pinned commit =="
. ./pins.env
pin_ok() {                                    # pin_ok <name> <dir> <expected sha>
  actual=$(git -C "$2" rev-parse HEAD 2>/dev/null || echo missing)
  if [ "$actual" != "$3" ]; then
    echo "FAIL: $1 is at $actual, pinned at $3. Run: bash research/corpus/setup.sh"
    exit 1
  fi
  echo "  ok   $1 $3"
}
pin_ok click      repos/click       "$CLICK_COMMIT"
pin_ok cobra      repos/cobra       "$COBRA_COMMIT"
pin_ok express    repos/express     "$EXPRESS_COMMIT"
pin_ok starter-kit repos/starter-kit "$KIT_COMMIT"

echo "== 3. import the red team (108 attacks) =="
node import-redteam.mjs >/dev/null

echo "== 4. generate attack variants (>= 3000) =="
node generate.mjs >/dev/null

echo "== 5. generate benign scenarios (>= 5000) =="
node benign/gen-benign.mjs >/dev/null

echo "== 6. replay the whole corpus against the composed shipped policy =="
node replay-v2.mjs

echo "== 7. write the report =="
node report.mjs --label after
test -f REPORT.md || { echo "FAIL: REPORT.md missing"; exit 1; }

echo "== 8. verify every published number against the raw data =="
node verify-v2.mjs

# Stage 8 grades the numbers the corpus produced. This one grades what the corpus never asked.
# rules/registry-wiring.test.ts already fails the build for a rule that is not WIRED; nothing failed
# it for a wired rule no scenario ever REACHES. PHASE2-ZEROCATCH.md found five of sixteen in that
# state, probed and ablated them; what did not exist was anything that fails when a sixth joins them
# unannounced, which is the case a hand-kept roster cannot catch.
#
# That case then happened, on this gate's first run against the branch it merged into rather than the
# one it was written on. The registry had grown to seventeen while this was in review, and the rule
# that arrived, protected-read-exposure, is reached by 0 of 8,190 scenarios. The gate exited 1 and
# named it. Nobody had noticed, and the rule's author was the person merging the gate. It is exempt
# now, for the one reason no other entry on that list carries: a corpus row is an effect set and this
# rule judges a read witness, so no scenario can reach it however many are written.
echo "== 8b. every registry rule is reached by at least one scenario =="
node check-rule-reach.mjs

# The page a reader is pointed to has to BE the page this run produces. It said so itself ("every
# figure is recomputed ... which fails on any drift") while eight figures differed from a fresh run,
# because nothing copied or compared the two. Now the copy is the gate.
# A gate that repairs what it is checking certifies itself on the next run.
#
# This used to `cp REPORT.md "$SHIPPED"` INSIDE the failure branch, before exiting 1. So the first run
# overwrote the shipped page with the new one and failed, and the SECOND run passed, because the thing
# it compares against had become the thing it was comparing. The message said "review and commit", and
# nothing enforced that anyone did. Whatever a merge had done to the miss rate would then be published
# as the measured truth by a gate reporting PASS.
#
# Two changes. The comparison ignores the run date, which changes daily and made this fire for a reason
# that is not drift, training everyone to re-run until green, which is exactly the habit that turns the
# self-certification above into the normal path. And the copy is no longer automatic: the fresh report
# is left at REPORT.md and the diff is printed, so updating the shipped page is a deliberate act by
# somebody who has seen what changed.
echo "== 9. the shipped report matches the one this run produced =="
SHIPPED=../../docs/CORPUS-REPORT.md
strip_volatile() { sed -E 's/Run [0-9]{4}-[0-9]{2}-[0-9]{2}\./Run <date>./' "$1"; }
if [ -f "$SHIPPED" ] && ! diff -q <(strip_volatile REPORT.md) <(strip_volatile "$SHIPPED") >/dev/null 2>&1; then
  echo "FAIL: docs/CORPUS-REPORT.md does not match this run, ignoring the run date."
  echo ""
  # `|| true` is load-bearing. Under `set -euo pipefail` this pipeline carries diff's exit 1, so the
  # shell left the script the moment the diff finished printing. The diff itself DID appear; what
  # never printed was everything below it, which is the part that tells the operator what to do:
  # the `cp` command and the reason this gate refuses to run it for them. A gate that shows a
  # failure and withholds the remedy is worse than one that says nothing, because the reader
  # assumes there is nothing more to read.
  diff -u <(strip_volatile "$SHIPPED") <(strip_volatile REPORT.md) | sed -n '1,40p' | sed 's/^/      /' || true
  echo ""
  echo "      The numbers moved. Read the diff above, then publish it deliberately:"
  echo "          cp research/corpus/REPORT.md docs/CORPUS-REPORT.md"
  echo "      This gate will not copy it for you, because a gate that repairs what it checks passes"
  echo "      on the next run whether or not anybody looked."
  exit 1
fi
echo "  ok   docs/CORPUS-REPORT.md is this run"

# Stage 9 proves the shipped page equals the page this run produced. It cannot prove either of them
# is TRUE, because report.mjs writes REPORT.md and results/report-metrics.json from the same pass, so
# a formatting defect lands identically in the two copies stage 9 diffs. And it says nothing at all
# about the other six documents that quote these figures as fact.
#
# That gap is the failure this repository keeps repeating. When the corpus moved from 165 misses to
# 149, the two files stage 9 guards were the only two that came out correct. README.md contradicted
# itself seventeen lines apart, research/METRICS.md and research/LEAKAGE-PROOF.md carried the whole
# pre-batch set, and METRICS.md's own stated reproduce command exited 1 against its own page.
# docs/lane-reports/bench-truth.md records the identical drift one batch earlier, at 1175 held
# against today's 1207. A figure is only as fresh as the gate that reads it.
#
# Stage 10 reads them all against results/report-metrics.json. Like stage 9 it reports and fails and
# never rewrites a document, and like stage 9 that is the whole point. It runs standalone in well
# under a second, so it is worth running on its own before publishing any figure:
#     node research/corpus/check-figures.mjs           # the gate
#     node research/corpus/check-figures.mjs --list     # what is guarded, what is not, and why
#     node research/corpus/check-figures.mjs --audit    # every figure it found, match by match
#     node research/corpus/check-figures.mjs --sweep    # what it catches and what it misses, measured
#
# Stage 10 passing does NOT mean every guarded document is correct. It means no guarded document
# carries drift that this gate can see and has not already declared. It prints its declared stale
# sites, its fenced figures and its pending files on every run, and the count of each is in the
# summary line, because a gate that reports a clean sheet while sitting on eight known stale
# sentences is the self-certification stage 9 already paid for. Read what it prints.
echo "== 10. every document that publishes these figures still states them correctly =="
node check-figures.mjs

# Stage 10 guards figures the corpus PRODUCES. This one guards the constants the corpus and the
# documents CONSUME. Three defects on one day motivated it: eight harnesses carried a seven-host
# private copy of the ten-host registry allowlist (one of them replay-v2.mjs, the grader behind
# every published figure); the rule registry grew 16 to 17 while five documents kept saying 16;
# and a structural-limits page still documented MAX_TAINT_PASSES = 16 after the constant was
# replaced, citing the file it was no longer in. The gate holds no copy of any value it checks:
# the truth is imported from the same dist stage 2 built. Its own tests run first for the same
# reason stage 1 runs the library's.
echo "== 11. private constant copies and stated counts match the built source =="
node --test check-constants.test.mjs
node check-constants.mjs

# Stage 11 guards constants a document CONSUMES. This one guards a claim that is not a constant at
# all: a projection of the rule registry's `decisions` declarations, which four people edit
# concurrently. The tier sentence in PROJECT.md went stale three times in one day, twice within
# minutes of being corrected by somebody who had just read the code, because the correctness of the
# sentence depends on files its author never touched. Prose discipline cannot fix that, so the
# numbers are computed from the built registry and the documents are checked against them.
#
# It fails on a dead exemption as well as on a stale claim, and it fails if it judges nothing, since
# a gate that judges nothing passes everything. Its first run rejected four of its own exemptions.
echo "== 12. stated decision-tier counts match the registry's own declarations =="
node check-tier-counts.mjs

echo ""
echo "PASS: harness runs, sources are pinned, REPORT.md exists, all numbers verify, no guarded"
echo "      document carries undeclared drift, no private constant copy or stated count drifts,"
echo "      and every stated decision-tier count matches what the rules actually declare"
echo "      from the built source. Stages 10 and 11 print what is declared, exempt and pending."

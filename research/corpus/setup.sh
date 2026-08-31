#!/usr/bin/env bash
# Pin every source the benign corpus reads.
#
#   bash research/corpus/setup.sh
#
# The benign half of the corpus is generated from real repository bytes, so the bytes have to be
# nailed down. Reading a moving tree is the exact defect that made an earlier published false-abort
# figure unreproducible: the number moved from 50 to 58 with no change to the policy at all, purely
# because the kit's development tree grew more files. A rate whose denominator drifts is not a
# measurement.
#
# So all four sources are pinned. Three are public repositories, cloned and checked out at an exact
# commit. The fourth is the starter kit itself, added as a detached git worktree at the published
# commit, which needs no network because this clone already contains it.
#
# Idempotent: safe to run twice. It re-pins rather than skipping when a source sits at the wrong
# commit, so a repository someone pulled by hand is put back rather than silently measured.
set -euo pipefail
cd "$(dirname "$0")"

CORPUS_DIR="$(pwd)"
KIT_DIR="$(cd ../.. && pwd)"
REPOS="$CORPUS_DIR/repos"

# repo name | pinned commit | clone URL. The three third-party pins are the commits recorded in
# every benign scenario's provenance; the kit pin also lives in benign/gen-benign.mjs as
# KIT_CORPUS_PIN, and the two must agree.
# shellcheck source=pins.env
# sourced by name, not by $(dirname $0): this script cd's to its own directory above, so a path
# built from $0 afterwards is relative to the wrong place.
. ./pins.env

mkdir -p "$REPOS"

at_commit() {          # at_commit <dir> <sha> -> 0 when the checkout is already that exact commit
  local dir=$1 sha=$2
  [ -e "$dir/.git" ] || return 1
  [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo none)" = "$sha" ]
}

pin_clone() {          # pin_clone <name> <sha> <url>
  local name=$1 sha=$2 url=$3 dir="$REPOS/$1"
  if at_commit "$dir" "$sha"; then
    echo "  $name already pinned at ${sha:0:10}"
    return
  fi
  if [ -e "$dir/.git" ]; then
    echo "  $name is at the wrong commit; re-pinning to ${sha:0:10}"
    git -C "$dir" fetch --quiet origin "$sha" 2>/dev/null || git -C "$dir" fetch --quiet origin
  else
    rm -rf "$dir"
    echo "  cloning $name"
    git clone --quiet "$url" "$dir"
  fi
  git -C "$dir" checkout --quiet --detach "$sha"
  git -C "$dir" clean -qfdx
  at_commit "$dir" "$sha" || { echo "FAIL: $name is not at $sha"; exit 1; }
  echo "  $name pinned at ${sha:0:10}"
}

pin_kit_worktree() {   # the fourth source: this kit, at the published starter-kit commit
  local dir="$REPOS/starter-kit"
  if at_commit "$dir" "$KIT_COMMIT"; then
    echo "  starter-kit already pinned at ${KIT_COMMIT:0:10}"
    return
  fi
  git -C "$KIT_DIR" worktree prune
  if [ -e "$dir/.git" ]; then
    echo "  starter-kit is at the wrong commit; re-pinning to ${KIT_COMMIT:0:10}"
    git -C "$dir" checkout --quiet --detach "$KIT_COMMIT"
  else
    rm -rf "$dir"
    echo "  adding starter-kit worktree"
    git -C "$KIT_DIR" worktree add --quiet --detach "$dir" "$KIT_COMMIT"
  fi
  git -C "$dir" clean -qfdx
  at_commit "$dir" "$KIT_COMMIT" || { echo "FAIL: starter-kit is not at $KIT_COMMIT"; exit 1; }
  echo "  starter-kit pinned at ${KIT_COMMIT:0:10}"
}

echo "pinning the four benign sources into repos/"
pin_clone click   "$CLICK_COMMIT"   https://github.com/pallets/click.git
pin_clone cobra   "$COBRA_COMMIT"   https://github.com/spf13/cobra.git
pin_clone express "$EXPRESS_COMMIT" https://github.com/expressjs/express.git
pin_kit_worktree

# The pin in the generator and the pin here are two statements of one fact, so they are checked
# against each other rather than trusted to stay in step.
GEN_PIN=$(sed -n 's/^const KIT_CORPUS_PIN = "\([0-9a-f]*\)".*/\1/p' benign/gen-benign.mjs)
case "$KIT_COMMIT" in
  "$GEN_PIN"*) ;;
  *) echo "FAIL: KIT_CORPUS_PIN in benign/gen-benign.mjs is $GEN_PIN, setup.sh pins $KIT_COMMIT"; exit 1 ;;
esac

echo "all four sources pinned."

#!/usr/bin/env bash
# Pin every real-history source this measurement reads.
#
#   bash research/realworld-prior/setup.sh
#
# Follows research/corpus/setup.sh exactly, for the same reason: the benign denominator must not
# move. The four corpus sources are reused from research/corpus/repos rather than cloned twice.
set -euo pipefail
cd "$(dirname "$0")"
. ./pins.env
mkdir -p repos

at_commit() { local d=$1 s=$2; [ -e "$d/.git" ] || return 1; [ "$(git -C "$d" rev-parse HEAD 2>/dev/null || echo none)" = "$s" ]; }

pin() {  # pin <name> <sha> <url>
  local name=$1 sha=$2 url=$3 dir="repos/$1"
  if at_commit "$dir" "$sha"; then echo "  $name already pinned at ${sha:0:10}"; return; fi
  if [ -e "$dir/.git" ]; then git -C "$dir" fetch --quiet origin "$sha" 2>/dev/null || git -C "$dir" fetch --quiet origin
  else rm -rf "$dir"; echo "  cloning $name"; git clone --quiet --depth 2500 "$url" "$dir"; fi
  git -C "$dir" checkout --quiet --detach "$sha"
  at_commit "$dir" "$sha" || { echo "FAIL: $name is not at $sha"; exit 1; }
  echo "  $name pinned at ${sha:0:10}"
}

echo "the four corpus sources are read in place from research/corpus/repos (run its setup.sh first)"
for n in click cobra express starter-kit; do
  [ -e "../corpus/repos/$n/.git" ] || { echo "FAIL: research/corpus/repos/$n is missing; run research/corpus/setup.sh"; exit 1; }
done

echo "pinning the eight blind sources into repos/"
pin requests "$REQUESTS_COMMIT" https://github.com/psf/requests.git
pin flask    "$FLASK_COMMIT"    https://github.com/pallets/flask.git
pin gin      "$GIN_COMMIT"      https://github.com/gin-gonic/gin.git
pin axios    "$AXIOS_COMMIT"    https://github.com/axios/axios.git
pin zod      "$ZOD_COMMIT"      https://github.com/colinhacks/zod.git
pin logrus   "$LOGRUS_COMMIT"   https://github.com/sirupsen/logrus.git
pin fastapi  "$FASTAPI_COMMIT"  https://github.com/fastapi/fastapi.git
pin chalk    "$CHALK_COMMIT"    https://github.com/chalk/chalk.git
echo "all twelve sources pinned."

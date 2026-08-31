#!/usr/bin/env bash
#
# snapshot-bench.sh — the missing artifact behind SNAPSHOT-BENCH.md.
#
# Measures the two candidate mechanisms for sealing a workspace at the start of a
# turn, at three tree sizes, on whatever host runs it:
#
#   overlay  mount -t overlay          — the mechanism the design wants
#   copy     cp -a                     — the mechanism the product actually ships
#
# and, for each, the cost of enumerating what the turn changed afterwards.
#
# Run as root (needs mount). Emits one JSON object per measurement on stdout so the
# figures can be recomputed rather than retyped.
#
#   sudo bash snapshot-bench.sh > snapshot-bench.jsonl
#
set -euo pipefail

SIZES=${SIZES:-"50 8886 30000"}
REPS=${REPS:-3}

ms() { echo $(( ( $2 - $1 ) / 1000000 )); }

host_json() {
  printf '{"kind":"host","kernel":"%s","cpus":%s,"mem_mb":%s,"fs":"%s","engine":"%s"}\n' \
    "$(uname -sr)" "$(nproc)" "$(free -m | awk '/^Mem:/{print $2}')" \
    "$(findmnt -no FSTYPE -T /tmp)" "${ENGINE_LABEL:-native-linux}"
}

build_tree() {
  local dir=$1 n=$2 i
  mkdir -p "$dir"
  for (( i = 1; i <= n; i++ )); do
    local sub="$dir/d$(( i % 64 ))"
    [[ -d $sub ]] || mkdir -p "$sub"
    printf 'line %s in file %s\n' "$i" "$i" > "$sub/f$i.txt"
  done
}

# one agent turn's worth of change, applied to whatever tree is handed in
mutate() {
  local root=$1
  echo hello        > "$root/created.txt"
  echo appended    >> "$root/d1/f1.txt"
  rm -f "$root/d2/f2.txt"
}

host_json

for n in $SIZES; do
  BASE=$(mktemp -d)
  build_tree "$BASE/lower" "$n"
  files=$(find "$BASE/lower" -type f | wc -l)

  for (( r = 1; r <= REPS; r++ )); do

    # ---- overlay ----
    mkdir -p "$BASE/upper" "$BASE/work" "$BASE/merged"
    s=$(date +%s%N)
    mount -t overlay overlay \
      -o "lowerdir=$BASE/lower,upperdir=$BASE/upper,workdir=$BASE/work" "$BASE/merged"
    e=$(date +%s%N)
    seal_overlay=$(ms "$s" "$e")

    mutate "$BASE/merged"

    s=$(date +%s%N)
    changed=$(find "$BASE/upper" -mindepth 1 | wc -l)
    e=$(date +%s%N)
    enum_overlay=$(ms "$s" "$e")

    umount "$BASE/merged"
    rm -rf "$BASE/upper" "$BASE/work" "$BASE/merged"

    printf '{"kind":"measure","mechanism":"overlay","files":%s,"rep":%s,"seal_ms":%s,"enumerate_ms":%s,"changed_entries":%s}\n' \
      "$files" "$r" "$seal_overlay" "$enum_overlay" "$changed"

    # ---- cp -a ----
    s=$(date +%s%N)
    cp -a "$BASE/lower/." "$BASE/copy"  2>/dev/null || { mkdir -p "$BASE/copy"; cp -a "$BASE/lower/." "$BASE/copy"; }
    e=$(date +%s%N)
    seal_copy=$(ms "$s" "$e")

    mutate "$BASE/copy"

    # the copy path has no upper layer, so the changed set must be derived by
    # walking and comparing both trees — this is what the shipped code does
    # diff exits non-zero when trees differ, which is the expected case here
    s=$(date +%s%N)
    changed_copy=$( { diff -rq "$BASE/lower" "$BASE/copy" 2>/dev/null || true; } | wc -l)
    e=$(date +%s%N)
    enum_copy=$(ms "$s" "$e")

    rm -rf "$BASE/copy"

    printf '{"kind":"measure","mechanism":"copy","files":%s,"rep":%s,"seal_ms":%s,"enumerate_ms":%s,"changed_entries":%s}\n' \
      "$files" "$r" "$seal_copy" "$enum_copy" "$changed_copy"
  done

  rm -rf "$BASE"
done

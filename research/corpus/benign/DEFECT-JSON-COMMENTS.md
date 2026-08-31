# The benign generator writes files no agent would write, and we are counting them

`gen-benign.mjs` has a stated contract in its own header: "Every one produces effects a correct
policy must COMMIT". Ninety of its 5,000 scenarios break that contract, because they produce a JSON
file that no parser will read.

## What it does

`commentFor(rel)` at `gen-benign.mjs:208` picks a comment style by extension and falls through to
`#` for anything it does not recognise, `.json` included:

```js
function commentFor(rel) {
  if (/\.(py)$/.test(rel)) return "#";
  if (/\.(go|js|mjs|cjs|ts|tsx|rs|java|c|h|cpp)$/.test(rel)) return "//";
  if (/\.(sh|yml|yaml|toml|cfg|ini)$/.test(rel)) return "#";
  return "#";
}
```

Two shapes then use it on files chosen at random. `edit-n-files` appends
`\n# touched by benign edit <id>\n` to the end (line 123). `refactor-across-files` inserts
`\n# refactor <id>\n` after the first line (line 159). JSON has no comment syntax at all, and `#` is
not a comment in JSONC either, so both produce an unparseable file.

## Measured, not estimated

    benign scenarios containing an unparseable JSON effect        90 of 5,000
    JSON effects carrying a `#` comment                           98
    of those 98, actually unparseable by JSON.parse               98

    .devcontainer/devcontainer.json    4      apps/server/tsconfig.json   24
    package.json                      18      tsconfig.base.json          14
    apps/server/package.json          16      apps/web/tsconfig.json      11
    apps/web/package.json             11

Reproduce both counts:

    node -e 'JSON.parse(require("fs").readFileSync("research/corpus/scenarios/benign.jsonl","utf8")
      .split("\n").filter(Boolean).map(JSON.parse)[0])'   # see the script in this note's history

## What it costs, in the run that is published

Joined against `results/results.jsonl` for the run that published 1,207 held:

    held for a human   46      of which dependency-added 32, execution-surface-review 14
    false-aborted       6      of which protected-asset-write 5, execution-surface-write 1
    committed          38

**46 of the 1,207 published human asks, 3.8 percent, are the policy correctly refusing to guess about
a file the corpus generator corrupted.** They are not false positives. A manifest that will not parse
is a real reason to stop and ask, and the product is behaving well. The corpus is what is wrong, and
because these turns are labelled benign-must-commit, the policy is being charged for handling them
correctly.

The 32 held under `dependency-added` are worse than merely miscounted: a parse failure is reaching a
reviewer described as a dependency addition, so the one sentence the human sees is wrong about what
happened.

## Why this is not fixed in this commit

The fix is not a one-line change to `commentFor`, and pretending otherwise would be the trap. The
question it raises is what an ordinary benign edit to a JSON file actually IS. A comment is not
available, so the shape has to either skip files that cannot carry a comment, which changes which
files each scenario picks and therefore moves every generated scenario through the shared RNG stream,
or make a JSON-valid edit, which is a different task shape than the one the generator claims to
produce.

Either way every published figure moves and the corpus has to be replayed on the cluster to
re-derive them, and the cluster is not reachable right now. Changing the generator without replaying
would leave the committed report describing a corpus that no longer exists, which is precisely the
drift `check-stamp` and `check-figures` were built to refuse.

## What to do, in order

1. Decide what an ordinary edit to a JSON file is. Adding or bumping a field is the honest answer and
   it is a real change to what these scenarios test.
2. Change `commentFor` to return null for extensions with no line-comment syntax, so the next person
   who adds a shape gets an error rather than a corrupt file.
3. Regenerate, replay on the cluster, republish, and expect the held count to fall by roughly 46 and
   the false-abort count by roughly 6, from whatever they are at that revision.
4. Separately, and regardless of this: `dependency-change.ts` reports an unreadable manifest under
   the rule name `dependency-added`. That is wrong independent of the corpus and it is what a human
   reviewer reads. It deserves its own rule name.

# The other comment-less formats, and why they are not the same defect

`benign/gen-benign.mjs` hands every edited file a line-comment marker chosen by extension. Until this
batch the fall-through was `#`, and JSON has no comments, so 90 of the 5,000 benign scenarios shipped
a manifest no parser will read. That cost 39 human asks, all of them mislabelled `dependency-added`,
and `benign/DEFECT-JSON-COMMENTS.md` records it.

Fixing it raised an obvious question that fixing it did not answer. `#` is not the comment syntax of
several other formats the corpus edits either, and the fall-through still returns `#` for all of
them. Closing a hole for one form and leaving it open for the others is a failure this repository has
made before and written down. So the honest next step was to measure the rest rather than either
assume they are fine or rewrite them on the strength of the JSON result.

## What the fall-through still gets wrong, counted

Effect paths in `scenarios/benign.jsonl`, by extension, for the formats `commentFor` gives a `#` that
the format does not use:

| Extension | Effects | What the format actually uses |
|---|---:|---|
| `.mod` (`go.mod`) | 197 | `//` |
| `.xml` | 177 | `<!-- -->` |
| `.ejs` | 120 | `<%# %>` |
| `.html` | 81 | `<!-- -->` |
| `.css` | 45 | `/* */` |
| `.tmpl` | 44 | `{{/* */}}` (Go templates) |
| `.hbs` | 13 | `{{! }}` |

677 effects in total. 351 of them carry an injected marker line; the rest come from shapes that
rename, delete or add a dependency and write no comment at all. Those 351 sit in 285 scenarios.

The other extensions the fall-through reaches are fine on inspection: `#` is the real line comment in
`.gitignore`, `.dockerignore`, `.npmrc`, `.editorconfig`, `.mailmap`, `.eslintignore`, `.tf`, `.tftpl`
and `.hcl`, and `.md`, `.txt` and `.log` have no syntax to break.

## The measurement

Two arms of the same 285 scenarios, differing in one thing. Arm A is the corpus exactly as it stands.
Arm B replaces each injected marker line with the same words in the format's own comment syntax, so
`# refactor b-cobra-0005` in `go.mod` becomes `// refactor b-cobra-0005` and the same line in an
`.xml` file becomes `<!-- refactor b-cobra-0005 -->`. Nothing else moves: same ids, same paths, same
surrounding bytes, same expected labels.

Both arms are graded against the composed shipped policy, the way `replay-v2.mjs` composes it, and
the two result files are compared field by field.

```bash
node research/corpus/replay-v2.mjs --scenarios probe-marker-broken.jsonl \
     --out research/corpus/results/probe-marker-broken.jsonl
node research/corpus/replay-v2.mjs --scenarios probe-marker-fixed.jsonl \
     --out research/corpus/results/probe-marker-fixed.jsonl
```

macOS 14.6.1, arm64, node v22.21.0, kit at 12f9f62, policy build b640fec4b3fbce0a.

## Result: nothing moves

    rows compared        285
    fields compared      14
    verdicts changed     0
    rules changed        0
    misses               0 -> 0
    false aborts         3 -> 3
    human asks           unchanged, row for row

The only field that differs between the two result files is `file`, which is the name of the probe
the row came from. Every judgement field is identical on all 285 rows: `decision`, `rule`, `correct`,
`miss`, `falseAbort`, `humanAsk`.

The comparison was written to compare every field the result rows carry rather than a list of field
names chosen by hand. The first version of it did the latter, guessed `hits` and `rules` for the rule
name when the field is `rule`, and so compared an empty array against an empty array on every row and
reported a clean sheet it had not earned. A comparison that cannot fail is not evidence, and this one
now carries a self-test that tampers with a row and confirms the check sees it.

## Why JSON was different, which is the part worth keeping

The JSON breakage was expensive because a parser the policy actually runs read the file and failed.
`package.json` reaches `parseManifest`, the parse throws, and the delta that comes back is read as a
dependency addition. The policy did the right thing with the input it was given and the corpus had
given it a broken file.

None of the seven formats above has that property today:

- `parseGoMod` splits each line on `//` and skips anything that matches no `require`, `replace` or
  block entry. A `# refactor ...` line is simply not a dependency, so it produces no delta.
- No rule in the registry parses XML, CSS, HTML, EJS, Handlebars or Go templates. The content
  scanners see one added line of ordinary prose, which is what they see for `.md` and `.txt` too.

So the defect class is the same and the cost is not, and the difference is entirely whether a rule
holds a parser for that format. That is the general statement: **a corpus artefact costs something
exactly when a rule reads the file closely enough to notice it.**

## What this does not say

It does not say the corpus is correct. A `#` at the top of an XML file is still a file our generator
broke, and a reviewer who opens one is right to hold it against the corpus. It says the breakage is
inert against the policy as it stands on 2026-08-31.

That is a conditional result and the condition is worth stating plainly: **the day a rule learns to
parse one of these formats, these 285 rows begin lying in the same way the 90 JSON rows did**, and
nothing in the harness will say so. The cheapest guard against that is the one this batch added to
the generator for JSON, which fails generation rather than shipping a file that does not parse.
Extending it to the other formats needs a parser per format and dependency-free parsers for XML and
CSS are not worth carrying for this.

## Decision

The markers are left as they are, for now, and the reason is the measurement rather than the effort.
Rewriting 351 effects changes the bytes of 285 scenarios for a result already shown to be zero on
every judged field, and every change to benign content has to be re-measured against the whole corpus
before any published figure can be trusted again. Trading a full republication for no measured
movement is the wrong trade.

Reopen this if any of the following becomes true:

1. A rule starts parsing XML, CSS, HTML or a template format. Then re-run the two arms first.
2. `go.mod` handling gets stricter than "skip what does not match", which is one line in `parseGoMod`.
3. The corpus grows a source whose manifest is XML, such as a `pom.xml`. Maven manifests are
   dependency manifests, and a dependency manifest is exactly the case where the JSON cost appeared.

The two probe arms are not committed. They are 5.7 MB each and every byte is derived from
`scenarios/benign.jsonl`, which regenerates byte-identically from its seeds, so the re-run is two
commands rather than eleven megabytes in the clone:

```bash
node research/corpus/build-marker-probe.mjs
node research/corpus/replay-v2.mjs --scenarios probe-marker-broken.jsonl \
     --out research/corpus/results/probe-marker-broken.jsonl
```

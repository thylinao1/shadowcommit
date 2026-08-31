# evidence/demo-run

The complete scenario section 1.8 of the track asks for, driven against a running platform and
captured while it ran.

Every artifact here is machine written: `transcript.txt` is the driver's own stdout, `steps/*.json`
are the platform's raw HTTP responses, `state.json` is written by the driver, and `browser/*.yml`
are accessibility snapshots taken from the running panel. The one hand-written thing inside an
artifact is the reader's note at the foot of `transcript.txt`. Every line of that note begins
`NOTE |` and no line of machine output does, so no reading window, the last twenty lines or the last
thirty, can mistake one for the other. The three markdown files, this one,
`BEATS.md` and `STORYBOARD.md`, are prose about those artifacts and are written by a person. Where
prose states a figure, the artifact it came from is named so you can check it.

## How it was produced

```bash
npm run poc:mock                 # the platform, on no provider key of yours
npm run demo:drive               # beats 0 to 8, ending with one turn held for a human
# open http://localhost:3000, read the held turn's diff, press Approve and commit
npm run demo:after-browser       # beats 9 and 10: what the browser did
```

Beat 8b ends stage 1 on `npm run verify:journal`, a separate program re-reading the journal from
disk, pointed at this run's data directory. It is the passing half of one claim; the refusing half is
`npm run demo:tamper`, which breaks the ledger, shows the same command exit 1, and puts it back.
Neither is in this recording, which predates both. See `evidence/journal-tamper/README.md`.

`npm run poc:mock` starts `scripts/mock-provider.mjs` in a container on the default bridge and
points the platform at it. The provider is the only thing standing in for something real. codex is
the real Codex CLI, the runtime is the real runtime container, the shell commands are really run in
it, the files are really written, and the transaction that seals, captures, judges and settles them
is the shipped one. The provider's decisions come from a playbook file the driver writes, and every
request it receives and every response it sends is logged, so what was scripted and what was not is
readable rather than asserted.

## What is here

| File | What it is |
|---|---|
| `transcript.txt` | the printed run of beats 0 to 8, exactly as it appeared, plus a closing reader's note added by hand, every line of it beginning `NOTE \|` |
| beats 9 and 10 | **not recorded in this pack.** They are the read-back after a person settles the held turn in the browser, produced by a second command, `npm run demo:after-browser`, which was not run against this recording. The browser action itself IS here, in `browser/04` to `browser/07`, from an earlier run. See "Two runs, one held turn" below for what binds them. |
| `steps/*.json` | the raw responses behind every line of the transcript: runs, journal turns, review views, provider requests, workspace listings |
| `browser/*.yml` | the rendered page, screen by screen, taken from the running browser panel |
| `BEATS.md` | every beat mapped to the file, the command and the journal records it emits |
| `STORYBOARD.md` | what a viewer sees, minute by minute, with the measured latencies |
| `state.json` | the ids the two stages hand between each other |

`apps/server/src/evidence-citations.test.ts` reads five documents, this one, `BEATS.md`,
`STORYBOARD.md`, `transcript.txt` and `docs/DEMO-PATH.md`, and fails if any artifact
they cite is not in this directory. Read the sentence narrowly, because a gate described wider than
it is becomes the next false claim:

- In the markdown it reads inline backticks only. A name inside a fenced block is a command to run
  or an excerpt to read, not a claim that the file is here, which is what lets the `git show` lines
  below name three artifacts that are deliberately absent.
- In `transcript.txt`, which is plain text and carries no backticks, it reads bare `steps/...` and
  `browser/...` tokens instead.
- A bare artifact filename in the shape `04-review-queue.yml` counts too, resolved against `steps/`
  and `browser/`, because the lane report's screen table cites them that way.
- Alongside the artifacts it checks one more thing: a citation that names a source file with a line
  number after it, in the shape of `apps/server/src/capture.ts:470` further up, has to name a file
  that exists and that is long enough to reach that line. It does not check that the line still says
  what the prose says it says, which would go red on every unrelated edit above it.
- A repository path named without a line number, such as `scripts/mock-provider.mjs`, is outside the
  gate entirely.
- It asserts that each of the five documents cites a minimum number of artifacts, so none of them
  can pass by quietly citing nothing.

## Two runs, one held turn

`transcript.txt`, `steps/` and `state.json` are the run of 30 August: base `http://127.0.0.1:3000`,
agent `e498e8b9`, held run `96129b56`. `browser/` is the run of 29 August: base
`http://127.0.0.1:3210`, agent `774bd7d9`, held run `96b198ac`. The ids do not match because they
are not the same run, and nothing here should be read as claiming they are.

What is identical is the thing the approval is bound to. The held effect set hash is

```
e4f0b9d83a3e7328d9aeb667380404fed3b69c3eb499741ff317d916b85127dd
```

in `state.json` and in `steps/09-turn-5-hold-left-for-browser.json` from the 30 August run. The
panel renders only its first twelve characters, `e4f0b9d83a3e`, in `browser/04-review-queue.yml` and
`browser/05-review-diff-expanded.yml`, so those two screens on their own are a 48-bit match rather
than identity. The full 64 characters of the 29 August side are in git rather than in this pack,
in that run's own state file:

```bash
git show 89cfb56:evidence/demo-run/state.json
# base http://127.0.0.1:3210, agent 774bd7d9, pendingReviewRunId 96b198ac,
# pendingEffectSetHash e4f0b9d83a3e7328d9aeb667380404fed3b69c3eb499741ff317d916b85127dd
```

With that line the claim is the strong one: byte for byte the same hash, produced twice, on two
days, on two ports, by two agents that share no identifier. Without it, only twelve characters of
the 29 August side are on the record here, and that is worth less.

That is what a content-addressed hold buys. The hash is over the effect set, so the same prompt
producing the same two file effects, a modify of `package.json` and a create of `tools/prepare.js`,
hashes to the same value no matter which agent produced them or when.

You do not have to take the hash on trust either. It is `sha256` over the sorted
`path:kind:sha256` triples of the effect set (`apps/server/src/capture.ts:470`), and both inputs are
in the pack, so it recomputes from this directory's own bytes in four lines:

```bash
node -e 'const c=require("crypto");
const e=require("./evidence/demo-run/steps/09-turn-5-hold-left-for-browser.json").review.effects;
console.log(c.createHash("sha256").update(e.map(x=>`${x.path}:${x.kind}:${x.sha256??""}`).sort()
  .join("\n")).digest("hex"));'
e4f0b9d83a3e7328d9aeb667380404fed3b69c3eb499741ff317d916b85127dd
```

Each effect's own `sha256` is the digest of the `after` content stored beside it in the same file,
which is checkable the same way.

Read the link for exactly what it is and no more.

- It binds the **held effect set**: the set of `{path, kind, resulting content}`. Not the agent, not
  the workspace, not the run around it.
- `browser/05` shows a diff, and a diff is before to after. The **before** is not in the hash. It
  does match, `browser/05` renders the line `"postinstall": "node ./tools/setup.js"` marked as
  removed and that line is in the `before` field `steps/09` stores, but that is a second fact you
  can check in those two files, not something the hash carries.
- The approval is not in `browser/06`. That screen is the queue at 0, with the empty state
  "No proposed changes waiting", and it carries no card and no record. It is the server state after
  the click. The record is in `browser/07`.
- `browser/07` reads `Committed: 2 changes, approved by operator` **twice**. The one the click
  produced is the second, at line 108, under the reply to the prompt naming `tools/prepare.js`. The
  one at line 86 belongs to an earlier turn of that same run, settled over the API. The queue going
  from 1 in `browser/04` to 0 in `browser/06` is the half that needs no disambiguation.
- It does not make `browser/` a recording of the 30 August turns, and the other browser screens,
  `browser/01` to `browser/03` and `browser/07`, show that earlier run's own turns and are cited as
  such.

## What the sealed copies did afterwards

The track asks for cleanup or recovery as well as containment, and the cleanup half is already in
these files rather than being described somewhere else.

Every turn opens with a `seal.fallback` record naming the mechanism the host could use (`copy`, on
macOS) and every **settled** turn closes with a `seal.release`. The discarded abuse turn's release is
in `steps/06-turn-2-egress.json`, sequence 16, `"kind": "seal.release"`, `"runId": "291771a1..."`,
`"removed": true`. The sealed copy that held the git hook and the deleted customer export was
reclaimed, and the reclaim is journaled and inside the same hash chain as the decision that caused
it. The rejected turn and both committed turns carry the same record in
`steps/10-platform-after.json`.

One turn has no `seal.release`: `96129b56`, the one still held for the browser. Its sealed copy is
still needed, because the bytes a person is about to approve live in it. That is the shape you want
to see. Releases follow settlements, and only settlements.

Recovery, the other half, is the replay of a commit that was interrupted between its halves. It is
implemented in `CommitProtocol.reconcile()` (`apps/server/src/commit-protocol.ts:512`), runs at
runner construction (`apps/server/src/transactional-runner.ts:233`), and is pinned by
`commit-protocol.recovery-settle.test.ts:45` and `commit-protocol.copy-fail.test.ts:117`, the second
of which exists because a recovery path once reported a turn committed when the replay had not
applied it. It has no HTTP surface, so no beat in this pack can drive it: demonstrating it needs the
platform killed between `turn.committing` and `turn.committed` and then restarted, which is a
separate recording rather than a step in this one. It is cited here rather than claimed as shown.

## The beats, and what each one is proved by

| Beat | 1.8 requirement | Proved by |
|---|---|---|
| 0 | (reviewability) | `steps/01-preflight.json`: container runtime, Codex available, provider configured |
| 1 | create or select an Agent and show its lifecycle state | `steps/02-agent-created.json`: `POST /api/agents` 201, status `ready` |
| 2 | invoke the Agent through the Playground with a real task | `steps/03-turn-1-normal.json`: the run, its output, its usage |
| 3 | at least one real model, file, tool, sandbox or data action | same file: two provider calls, one `exec_command` tool call, three files in the real workspace |
| 4 | the middleware behaviour and the evidence it produces | `steps/04-turn-1-journal.json`: begin, executed, captured, decided, committing, committed, chain verified |
| 5 | an appropriate failure, denial, degraded, abuse or recovery case | `steps/05-turn-2-abuse.json`: discard, workspace digest identical either side, protected asset intact |
| 5b | (the denial, twice) | `steps/06-turn-2-egress.json`: the direct connection had no route, the proxied one was denied by the broker |
| 5c | (the cleanup after the denial) | same file, sequence 16: `seal.release` with `"removed": true`, the sealed copy of the abuse turn reclaimed and journaled |
| 6 | (human in the loop) | `steps/07-turn-3-hold-approved.json`: held, wrong hash refused 409, right hash applied, actor `operator` |
| 6b | (the other half of it) | `steps/08-turn-4-hold-rejected.json`: held, refused by the operator, workspace digest identical either side |
| 7 | (the same decision, from the browser) | `steps/09-turn-5-hold-left-for-browser.json` holds effect set `e4f0b9d83a3e`; `browser/04` shows the queue at 1 with that same hash on the card, `browser/05` the expanded diff and the Approve control, `browser/06` the queue at 0 with the empty state, `browser/07` the turn reading `Committed: 2 changes, approved by operator` (the second of the two lines carrying that string, at line 108, under the reply to the prompt naming `tools/prepare.js`). Server state before the click, the control, server state after. |
| 8 | the platform remains understandable and controllable | `steps/10-platform-after.json`: five turns in the timeline, chain verified, stop and start, workspace intact |
| 9, 10 | (the browser's decision, read back over the API) | **not in this pack**, see the file table above. `browser/06` and `browser/07` are the same decision seen from the panel rather than read back from the API, and the hash above is what ties them to the held turn in `steps/09`. The API read-back of that click was recorded once and deleted; it is still readable, see "Where stage 2 went". |

### Where stage 2 went

Beats 9 and 10 were recorded once, against the 29 August run. Commit `d93f615` removed all three of
the artifacts they produced. The driver did it rather than a person: the version of
`scripts/demo-drive.mjs` in force that day opened `--stage drive` by deleting `steps/` **and both
transcripts**, so re-recording stage 1 took stage 2 with it. That opening delete is gone, `1c7ad6a`
replaced it with a scratch directory published only on success, and today's `--stage drive` replaces
`steps/` and its own transcript and nothing else. The three files are still readable from history:

```bash
git show 89cfb56:evidence/demo-run/transcript-after-browser.txt
git show 89cfb56:evidence/demo-run/steps/after-01-browser-settled.json
git show 89cfb56:evidence/demo-run/steps/after-02-final-journal.json
```

They are deliberately not restored here. They belong to agent `774bd7d9` and run `96b198ac`, and the
stage 1 beside them is now the 30 August run, so restoring them would give this directory a stage 1
and a stage 2 describing two different platforms, with the stage 2 asserting the approval of a run
id that stage 1 never mentions. Their journal is also a different shape: 36 records with no
`seal.fallback` or `seal.release` in it, against 41 here. Reading them as a record of a superseded
run is fair. Presenting them as current evidence would not be, and an unexplained gap is better than
a mismatch a reader has to catch.

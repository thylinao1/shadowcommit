# Beat to code

Every beat of the required demo, the file that makes it happen, the command that drives it, and the
journal record kind it emits. Nothing in this table is aspirational: each row was executed against a
running platform and its output is in `transcript.txt` and `steps/`.

Beats 0 to 8 are machine driven, and the transcript records all of them with 50 named checks. A
fresh `npm run demo:drive` prints 59. Five cleanup assertions were added to the driver after this
recording was taken, three under beat 5b and two under beat 8, and they are described in
`docs/DEMO-PATH.md` section 6b; four more arrived with beat 8b, which is a beat this
recording predates entirely. **Beat 8b is in the driver and is not in this transcript**, because
re-recording the pack needs the machine and the containers that produced it. Its own machinery was
executed separately and that is written up in `evidence/journal-tamper/README.md`. Every other beat
heading is unchanged.

Beat 9 is the one a person performs: a reviewer opens the panel, reads the held diff and presses
Approve. It is not in the transcript because the product's whole claim is that a human makes that
call, so running it from a script would record something other than the beat. **The click itself is
on the record**, in `browser/04-review-queue.yml` through `browser/07-playground-after-approval.yml`:
the queue at 1 with the effect set hash on the card, the expanded diff and the Approve control, the
queue at 0, and the reply reading `Committed: 2 changes, approved by operator`. That last string is
in that file twice: the click's is the second, at line 108, under the reply to the prompt naming
`tools/prepare.js`, and the queue going from 1 to 0 is the half that needs no telling apart. Those
screens are a different run, of 29 August, tied to this one by the held effect set hash rather than
by an id, which `README.md` sets out under "Two runs, one held turn". What is missing is only the
API read-back after the click, which is what `npm run demo:after-browser` produces.

The journal record kinds were read back from the platform's own journal with:

```bash
# $APP_DATA_DIR, which on macOS defaults to ~/.volc-agent-launchpad/data and on Linux to .local/data
node -e 'const fs=require("fs");const p=process.env.HOME+"/.volc-agent-launchpad/data/journal.jsonl";
const byRun={};for(const l of fs.readFileSync(p,"utf8").trim().split("\n")){const r=JSON.parse(l);
const k=r.runId?r.runId.slice(0,8):"(no run)";(byRun[k]=byRun[k]||[]).push(r.kind);}
for(const [k,v] of Object.entries(byRun))console.log(k,v.join(" -> "));'
```

| # | Beat (1.8) | Where the behaviour lives | Command that drives it | Journal records it emits |
|---|---|---|---|---|
| 0 | the platform is running with no provider key | `scripts/start-mock-poc.sh`, `scripts/mock-provider.mjs` | `npm run poc:mock` | none; the journal is per turn |
| 1 | create an Agent from the frontend, show its lifecycle state | `apps/server/src/app.ts` (`POST /api/agents`), `apps/server/src/agent-service.ts`, `apps/server/src/workspace.ts` | `npm run demo:drive` beat 1 | none; the agent record goes to `launchpad.json` |
| 2 | invoke the Agent through the Playground with a real task | `POST /api/agents/:id/messages` in `app.ts`, `AgentService.executeRun` | beat 2 | `seal.fallback`, `turn.begin`, `turn.executed` |
| 3 | a real model, tool and file action | `apps/server/src/container-codex-runner.ts` runs codex in the runtime container; the model asks for `exec_command`; the shell writes the files | beat 3 | `effects.captured` |
| 4 | the middleware behaviour and its evidence | `apps/server/src/transactional-runner.ts`, `shadow-policy.ts`, `capture.ts`, `journal.ts`; read back through `GET /api/agents/:id/journal` in `web-routes.ts` | beat 4 | `policy.decision`, `turn.committing`, `turn.committed` |
| 5 | the abuse case: a hook, an exfiltration and a protected delete | `rules/protected-identity.ts` decides; `commit-protocol.ts` never runs; the sealed copy is dropped | beat 5 | `seal.fallback`, `turn.begin`, `turn.executed`, `effects.captured`, `policy.decision`, `turn.discarded`, then the `seal.release` in the row below |
| 5b | the denial the network made, and the one the broker made | `apps/server/src/network-sealer.ts` (`docker network create --internal`), `apps/server/broker/server.mjs` | beat 5b | the egress counts ride on `turn.discarded` as `egress: {deny, live}` |
| 5c | the sealed copy of the contained turn, reclaimed | `apps/server/src/overlay-sealer.ts` (`releaseWithProof`, never a bare delete) | beat 5b, same read | `seal.release` with `"removed": true`, in `steps/06-turn-2-egress.json` at sequence 16 |
| 6 | the turn a human has to decide, settled over the API | `POST /api/reviews/:id/approve` in `app.ts`, `TransactionalRunner.approve`, `review-view.ts` | beat 6 | `turn.held`, `settle.refused` (the wrong hash), `policy.decision` (re-run at approve time), `turn.approved`, `turn.committing`, `turn.committed` |
| 6b | the other half of the review surface: a held turn a person refuses | `POST /api/reviews/:id/reject` in `app.ts`, `TransactionalRunner.reject` | beat 6b | `turn.held`, `turn.rejected` |
| 7 | the same decision, made in the browser | `apps/web/src/components/reviews/ReviewsPanel.tsx` and `ReviewCard.tsx` calling the same two routes | beat 7, then a click in the panel | `turn.held` here; the records after it were written in the run under `browser/`, whose card shows the same effect set hash `e4f0b9d83a3e` this run's `steps/09-turn-5-hold-left-for-browser.json` holds. That run's own journal is not at HEAD, it is in git at commit `89cfb56` (see `README.md`, "Where stage 2 went"), and it shows run `96b198ac` going `turn.held` to `policy.decision` to `turn.approved` to `turn.committing` to `turn.committed`, verdict approved, 36 records, chain ok |
| 8 | the platform is still understandable and controllable | `GET /api/agents/:id/journal` (`web-routes.ts`) and `apps/web/src/components/timeline/RunTimeline.tsx`; `POST /api/agents/:id/stop` and `/start` | beat 8 | none; `TransactionalRunner.verifyChain` reads them |
| 8b | the ledger checked by a program that did not write it | `apps/server/src/verify-journal.ts`, reading through `verifyJournalAt` in `journal-verify.ts` | `npm run verify:journal -- --data-dir <the demo's data dir>`, driven by beat 8b; **not in this recording** | none; it only reads |
| 9 | what the browser did, read back | `GET /api/reviews`, `GET /api/agents/:id/journal` | `npm run demo:after-browser`, not run against this recording | none |

## The verifier, from both sides

Beat 8b closes the run on `npm run verify:journal`, pointed at the data directory this run wrote
rather than at the command's default, which `parseArgs` already supported through `--data-dir`. It
asserts four things: that the verifier ran as its own program, that it did not report a break, that
it read records rather than finding nothing to verify, and that nothing it printed carries the
operator's home directory into the pack. That last one is not decoration: the
verifier's banner prints the journal path, the key home and the public key path, and on a developer
machine all three sit under `/Users/<name>`. The driver redacts at the moment of writing, the same
way it does for the transcript and for `state.json`, and beat 8b asserts the redaction worked rather
than trusting it. Its capture lands in `steps/` beside the others.

Exit 0 and exit 2 are both honest outcomes there and they are not the same claim. 2 says the chain
is self-consistent and a layer above it could not be checked on this host, which on a machine with
no journal key is the truth and 0 would be a lie, so the beat asserts the code is not 1 and prints
which of the other two it got.

The other side of the same claim is `npm run demo:tamper`, which is not a beat of this run. It flips
one character inside the payload of one record, runs that same command, shows it exit 1 naming the
record, then puts the byte back and shows it pass again. A verifier that has only ever been seen
passing proves nothing, and a break with no baseline pass proves nothing either. Its transcript, the
five interrupted and hostile states its restore was driven through, and the reason it never
constructs a `Journal` (`assertUsable` would put the ledger into a `compromised` state that putting
the byte back does not undo) are in `evidence/journal-tamper/README.md`.

Two further kinds of record carry no run id, because the journal appends them itself rather than a
turn producing them: `journal.checkpoint`, which signs a Merkle root over everything written so far,
and `anchor.ok`, which records that the checkpoint was anchored. They are written on an interval and
at shutdown, and the timeline groups by run id, so neither appears in the turns read back here.

## What the five turns looked like in the journal

Read back from the run in `transcript.txt`, through `steps/10-platform-after.json`. Chronological
order, oldest turn first, which is the reverse of the way the panel lists them:

```
turn 1  committed  seal.fallback -> turn.begin -> turn.executed -> effects.captured
                   -> policy.decision -> turn.committing -> turn.committed -> seal.release
turn 2  discarded  seal.fallback -> turn.begin -> turn.executed -> effects.captured
                   -> policy.decision -> turn.discarded -> seal.release
turn 3  approved   seal.fallback -> turn.begin -> turn.executed -> effects.captured
                   -> policy.decision -> turn.held -> settle.refused -> policy.decision
                   -> turn.approved -> turn.committing -> turn.committed -> seal.release
turn 4  rejected   seal.fallback -> turn.begin -> turn.executed -> effects.captured
                   -> policy.decision -> turn.held -> turn.rejected -> seal.release
turn 5  held       seal.fallback -> turn.begin -> turn.executed -> effects.captured
                   -> policy.decision -> turn.held
```

41 records across the five turns: 8, 7, 12, 8 and 6, and every kind above appears in
`steps/10-platform-after.json` where you can count them yourself. The chain the platform verifies
covers 42: that file reports `"chain": {"ok": true, "records": 42, "problems": []}`. The extra one
is identifiable rather than something to take on trust. Every record in that file carries a `seq`,
and the five turns occupy 2 through 42 with no gaps, so the record the chain counts and the turns do
not is **sequence 1**, written before the first turn's first record. The timeline endpoint lists
records by run id and returns nothing that carries none, which is why the grouping does not show
it.

Turn 5 is **held**, not settled. This pack stops there on purpose: the decision on it was made in a
browser, in the screens under `browser/`, and the read-back of that decision is beats 9 and 10,
which are not in this pack. `README.md` has the whole of that story and the hash that ties the two
together.

Turn 3 carries the extra `settle.refused` because the driver deliberately approves it once with a
hash that is not the set the queue returned.

Turn 4 is the shortest settled chain of the five: a refusal writes `turn.rejected` and stops. There
is no `policy.decision` after it and no commit point, because nothing is going to be applied. The
second `policy.decision` on turn 3 is the policy being re-run at approve time against the bytes as
they are then. An approval is not a stored yes.

`seal.fallback` opens every turn and names the mechanism this host could use: `copy`, with
`"reason": "not-linux"`, because overlayfs is not available on macOS. `seal.release` closes every
**settled** turn and records what happened to the sealed copy. The abuse turn's is in
`steps/06-turn-2-egress.json` at sequence 16: `"kind": "seal.release"`, `"removed": true`. That is
the cleanup half of the track's containment requirement, journaled and inside the same hash chain as
the decision that caused it. Turn 5 has no `seal.release` because it is still held, and the bytes a
person is about to approve are still in its sealed copy.

The recovery half, replaying a commit interrupted between its file half and its state half, is not
demonstrated here and cannot be: `CommitProtocol.reconcile()`
(`apps/server/src/commit-protocol.ts:512`) runs at runner construction
(`apps/server/src/transactional-runner.ts:233`) and has no HTTP route, so no beat driven over the
API can reach it. It is pinned by `apps/server/src/commit-protocol.recovery-settle.test.ts:45`, which
requires a recovered turn to settle the other halves or say it could not, and by
`apps/server/src/commit-protocol.copy-fail.test.ts:117`, which forbids reporting a recovered turn
committed when the replay could not apply it either. The quarantine and orphan sweep behind
`seal.release` are pinned by `apps/server/src/overlay-sealer-orphans.test.ts:63`.

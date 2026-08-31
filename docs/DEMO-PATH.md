# Lane DEMO-PATH

The 40% line. Before this lane, every claim in the repository about the running product was a unit
test: the runner, the policy, the commit protocol and the HTTP surface were each proved in isolation
against temporary directories, and `npm run evidence` drove three scenarios through a **scripted**
inner runner rather than through the platform. Nobody had started the thing and walked the journey.

This lane starts it, walks the journey, and writes down what happened. Five turns, one agent, one
browser, one journal. Four defects found in the platform, two fixed here and two reported with the
exact patch, plus one flaky test in the submission's own gate and a way of running that gate that
can report green when it is not.

Branch `lane/demo-path`, pushed to `submission` (`thylinao1/shadowcommit`), which is where the other
lane branches are. `git push origin HEAD` fails with a 403: `origin` is still the upstream starter
kit `RrankPyramid/CodeJam` and nobody on this team can write to it.

`npm run check`: green, exit 0, 937 tests.

---

## 1. What is new

| Path | What it is |
|---|---|
| `scripts/mock-provider.mjs` | a model provider that speaks codex 0.111's Responses wire shape, drives real `exec_command` tool calls from a playbook file, and logs every request and response |
| `scripts/start-mock-poc.sh` | `npm run poc:mock`: starts that provider in a container on the default bridge, points the platform at it, and hands off to the unchanged `start-local-poc.sh` |
| `scripts/demo-drive.mjs` | `npm run demo:drive` and `npm run demo:after-browser`: the whole of section 1.8, driven over the platform's own HTTP API. 64 assertions, 55 in the scripted stage and 9 after the browser of which 7 fire on any one run, because the approved and rejected branches are exclusive |
| `evidence/demo-run/` | the transcripts, the raw responses, the rendered browser screens, the beat-to-code table and the storyboard |
| `apps/server/src/run-id-correlation.test.ts` | three regression tests for defect 1 |
| three one-line changes in `types.ts`, `agent-service.ts`, `transactional-runner.ts` | the fix for defect 1 |

`package.json` gains `poc:mock`, `demo:drive` and `demo:after-browser`. Nothing else in the kit
changed.

## 2. The no-key path, and why it is a container on the bridge

The brief asked for `poc:mock` to run `research/G04-scripts/mock-ark.mjs`. It does not, and the
reason matters: that file lives in the team's research repository, so a reviewer who clones only
this repository would not have it. `scripts/mock-provider.mjs` is in the repository, and it does
more than the research spike did.

The research mock answers every request with a fixed assistant message. A turn against it produces
**no file effects at all**, so the transaction would seal a workspace, capture nothing, judge an
empty set and commit it, and the demo would prove nothing about the middleware. The mock here
returns a `function_call` for codex's `exec_command` tool, which means the real Codex CLI really
runs a real shell command inside the real runtime container and the files it writes are really
written. Everything below the model is the shipped product.

The tool schema was not guessed. It was read off the wire from a real `codex exec` turn against a
recording mock:

```
$ docker run --rm --network bridge ... volc-agent-runtime:local \
    codex exec --json --sandbox workspace-write --skip-git-repo-check -C /workspace "..."
$ node -e '...read the logged request body...'
tools: [ "exec_command", "write_stdin", "update_plan", "request_user_input", "web_search", "view_image" ]
```

`exec_command` takes `{cmd: string}` and codex runs it as `/bin/bash -lc "<cmd>"`. That is the whole
integration.

The provider runs **in a container on the default bridge**, not on the host. That is the same
topology `network-docker.test.ts` already uses for its real-codex tests, and it is the right one:
the dual-homed egress broker can reach the bridge and the agent container, alone on its per-run
`--internal` network, cannot. A provider on the host reached through `host.docker.internal` also
works on Colima (measured) but does not work on Linux Docker without extra flags, and it puts the
provider somewhere the topology does not model.

The playbook is a JSON file the driver rewrites between turns and the provider re-reads on every
request. That is deliberate: what was scripted is a file in the evidence, not a claim in prose.

**Command and output.** From `npm run poc:mock` to the server listening: **9.4 s and 13.1 s** on two
warm starts (image built, dependencies installed), measured from the shell's start timestamp to the
`Server listening` record in the server's own log.

```
[mock-poc] Using docker.
[mock-poc] Starting the mock provider on the default bridge.
[mock-poc] Mock provider at 172.17.0.2:8398 (reachable by the broker, not by the agent).
[mock-poc] Handing off to scripts/start-local-poc.sh.
[local-poc] Using docker as the Agent Runtime engine.
[local-poc] Codex Landlock is unavailable in this Linux Runtime.
[local-poc] Falling back to danger-full-access inside the disposable container boundary.
[local-poc] Open http://localhost:3210
{"level":30,"msg":"Server listening at http://127.0.0.1:3210"}
```

```
$ curl -s http://127.0.0.1:3210/api/system
{"arkConfigured":true,"arkBaseUrl":"http://172.17.0.2:8398/api/v3","arkModel":"ep-mock-endpoint",
 "codexAvailable":true,"codexSandboxMode":"danger-full-access","runtimeProvider":"container",
 "containerEngine":"docker","runtime":"Codex CLI in docker Runtime"}
```

The Landlock fallback is worth noticing rather than skipping past. On this host the runtime image
cannot use codex's own filesystem sandbox, so codex runs `danger-full-access` **inside** the
disposable container. That is exactly the case this project's design note is about: the container is
the jail, the transaction is the bookkeeping. The abuse turn below deletes a file and writes a git
hook precisely because codex was not stopping it, and it is contained anyway.

## 3. The journey, driven

`npm run demo:drive` then a click in the browser then `npm run demo:after-browser`. The scripted
stage's full output is in `evidence/demo-run/transcript.txt` and the raw responses behind every line
are in `evidence/demo-run/steps/`. Five turns, **6.7 s** wall clock, which is the elapsed figure
that transcript prints under `STAGE 1 COMPLETE`. Everything after that line in the file is a reader's
note added by hand, and every line of it begins `NOTE |` so that no window a reader opens can read it
as the driver's own output.

The second stage's transcript is **not** in the pack. It was recorded once, against the run of
29 August, and removed by commit `d93f615` along with its two step files. The driver deleted them
rather than a person: section 6b has the mechanism. It is still readable from history, and so are
the two step files beside it:

```bash
git show 89cfb56:evidence/demo-run/transcript-after-browser.txt
git show 89cfb56:evidence/demo-run/steps/after-01-browser-settled.json
git show 89cfb56:evidence/demo-run/steps/after-02-final-journal.json
```

They are not restored into the pack. They belong to agent `774bd7d9` and run `96b198ac`, while the
stage 1 beside them is now the run of 30 August, so a restored stage 2 would assert the approval of
a run id its own stage 1 never mentions. A pack with an honest gap beats a pack with a mismatch a
reader has to catch. `evidence/demo-run/README.md` carries this under "Where stage 2 went", along
with the thing that does tie the browser screens to this run: the held effect set hashes to
`e4f0b9d83a3e7328d9aeb667380404fed3b69c3eb499741ff317d916b85127dd` in both.

```
BEAT 0   container runtime, Codex available, a provider configured on no credential of yours
BEAT 1   POST /api/agents -> 201, status ready, workspace seeded with .gitignore AGENTS.md README.md
BEAT 2   the organizers' own acceptance prompt, sent through the Playground        1.3 s -> commit
BEAT 3   two provider calls, one exec_command tool call, three files in the real workspace
BEAT 4   turn.begin -> turn.executed -> effects.captured -> policy.decision -> turn.committing -> turn.committed
         chain VERIFIED
BEAT 5   a git hook piping a fetch into a shell, plus rm customers.jsonl          1.3 s -> discard
         workspace digest before cc4f79ba8429f286, after cc4f79ba8429f286
BEAT 5b  DIRECT_EGRESS_FAILED from inside the runtime; broker decisions {"deny":2,"live":2}
BEAT 6   a manifest script change                                                  1.3 s -> review
         approve with the wrong hash -> 409; with the right hash -> 200, actor operator, applied
BEAT 6b  another one                                                               1.3 s -> review
         reject -> 200, workspace byte-identical either side, nothing landed
BEAT 7   another one                                                               1.3 s -> review, left held
BEAT 8   five turns in the timeline, chain verified, stop -> stopped, start -> ready, workspace intact
BEAT 9   the browser's approval read back: verdict approved, principal operator, files applied
BEAT 10  approved / rejected / approved / discarded / committed, chain verified
         (9 and 10 are the second stage, and are not in this pack: see above)
```

Every one of those lines is an assertion in `scripts/demo-drive.mjs` that fails the script if it is
not true. The script exits non-zero on the first failure, and it did, four times, while this lane was
being built.

Three things in that output are worth pulling out.

**The agent reported success on the turn that was thrown away.** Its own words, in the Playground:
"Release helper installed: added .git/hooks/pre-commit to fetch the lint config, and removed the
stale customers.jsonl export." The panel prints `BLOCKED, nothing was sent: protected-asset-delete`
underneath it. That gap is the product.

**The workspace digest is the same string either side of the abuse turn**, over 7 files, computed by
walking the real workspace and hashing every file. `customers.jsonl` still contains
`ada@example.com`; `.git/hooks/pre-commit` does not exist.

**Both denials happened, and they are different mechanisms.** The turn's direct connection to
`169.254.169.254` reported `DIRECT_EGRESS_FAILED` back to the model, because a `--internal` network
has no route for it to take and no policy was consulted. Its `git ls-remote` to an unallowlisted host
went through the proxy the platform handed it and was refused by the broker, which recorded
`{"deny":2}` in the journal. The first is a kernel property, the second is a decision. A demo that
showed only one of them would be claiming the wrong thing.

## 4. The browser leg

Driven in a real browser against the built production bundle at `http://127.0.0.1:3210`. Each screen
is captured in `evidence/demo-run/browser/` as the rendered accessibility tree, which is the page as
it actually was, timestamped:

| File | Screen |
|---|---|
| `browser/01-first-paint-before-system-probe.yml` | the first paint, captured at the instant of navigation (see defect 4) |
| `browser/02-run-timeline.yml` | the run timeline, `Chain intact` |
| `browser/03-timeline-blocked-turn-expanded.yml` | the discarded turn opened: run id, seal `copy`, rule, effects, journal records |
| `browser/04-review-queue.yml` | the held turn, its rule, its two proposed paths, its effect set hash |
| `browser/05-review-diff-expanded.yml` | the `package.json` diff, `-1 +2`, the `prepare` line visible before it is real |
| `browser/06-queue-empty-after-approve.yml` | after Approve and commit: the queue at 0 and the empty state, which is the server side of the click |
| `browser/07-playground-after-approval.yml` | the fourth reply, to the prompt naming `tools/prepare.js`, now reads `Committed: 2 changes, approved by operator` (line 108) |

The five verdict lines the panel renders under the five replies, verbatim from
`browser/07-playground-after-approval.yml`. Two of them read the same string; the second of those,
at line 108, is the one the browser click produced, and the first, at line 86, is a turn of that
same run settled over the API:

```
"Committed: 3 changes"
"BLOCKED, nothing was sent: protected-asset-delete"
"Committed: 2 changes, approved by operator"
Rejected by operator, nothing was sent
"Committed: 2 changes, approved by operator"
```

`npm run demo:after-browser` then reads the same decision back off the platform: the turn is gone
from the queue, the timeline says `approved` with principal `operator`, `tools/prepare.js` is in the
real workspace and `package.json` carries the `prepare` script.

**One limitation, stated rather than hidden.** The browser was driven through an MCP browser whose
screenshot files are written outside this filesystem, so the committed browser evidence is the
rendered page as text rather than PNGs. The text is not a weaker artefact for this purpose (it
carries every label, verdict, diff line and hash the screen showed) but it is not a picture, and the
three-minute video will need real screen capture.

## 5. Defects found

### Defect 1, fixed: one turn had two ids, and it broke the trace

**What it was.** `AgentService.sendMessage` minted `AgentRun.id`. `TransactionalRunner.run` minted
its own `runId` and journaled everything under that. Nothing joined them. Measured on the first
drive, before the fix:

```
platform run.id      : 6ffdf7b8-c181-4220-8448-6f6e598c9389
containment.runId    : 658be5db-a48a-4f19-b895-e94ea5de4c25
```

Three consequences, in ascending order of how much they cost:

1. `GET /api/agents/:id/journal` returned turns keyed by one id and `GET /api/agents/:id/runs`
   returned runs keyed by the other, so the run history and the run timeline could not be joined.
   The demo driver's beat 4 failed with `Cannot read properties of null` on its first execution.
2. `POST /api/reviews/:id/approve` takes the transaction id while `GET /api/runs/:id` takes the
   platform id, and both are called `runId` on the wire. Any client that used the wrong one got a
   404 or a `not-pending`.
3. The Playground could not render a verdict on a committed turn at all. The web lane documented
   this as its one visible gap (a browser-panel review, item 9): "Nothing links them, so the
   playground cannot show `Committed: n changes` beside a committed reply." The client was already
   written to work the moment they were linked.

**The fix**, three lines plus comments, in the runner path:

```ts
// apps/server/src/types.ts, RunnerRequest
runId?: string | undefined;

// apps/server/src/agent-service.ts, executeRun
const result = await this.runner.run({ ..., runId: run.id });

// apps/server/src/transactional-runner.ts, run()
const runId = request.runId ?? crypto.randomUUID();
```

Backwards compatible: a caller with no run of its own still gets a generated id, which is why the
existing tests and `scripts/evidence.ts` needed no change.

**Proof it worked.** The panel now renders `Committed: 3 changes` under the committed reply, which
it could not do before; see `evidence/demo-run/browser/07-playground-after-approval.yml`. Three
regression tests in `apps/server/src/run-id-correlation.test.ts` pin both halves: that the control
plane passes its id down, and that the transaction adopts it and journals every record under it.

### Defect 2, fixed: there was no way to run the product without a provider key

The README's answer to "no key" was "run the tests". A reader who wants to see the platform work, and
who has no BytePlus Ark account, could not. `npm run poc:mock` is that path, and the demo above is
what it produces. This is the 15% reproducibility line and it was open.

### Defect 3, found, not fixed here: a body-less POST with a JSON content type is a 400

`POST /api/agents/:id/stop` and `/start` take no body. A client that sets
`content-type: application/json` and sends nothing gets:

```
400 {"error":"Body cannot be empty when content-type is set to 'application/json'"}
```

which is Fastify's internal message, not the platform's. The browser panel is not affected, because
`apps/web/src/api.ts` sets the header only when there is a body. My driver was affected, and any
other client with the same very ordinary shape would be. It is a robustness wart on the lifecycle
routes rather than a security problem, so it is reported rather than patched under a lane that does
not own `app.ts`. The exact patch, for whoever takes it:

```ts
// apps/server/src/app.ts, after `const app = Fastify({...})`
// A body-less POST is what the lifecycle routes expect. Declaring a JSON content type and sending
// nothing is a common client shape, and Fastify's default parser answers it with 400 and its own
// internal message rather than running the route.
app.addContentTypeParser("application/json", { parseAs: "string" }, (_request, body, done) => {
  if (typeof body === "string" && body.trim().length === 0) return done(null, {});
  try {
    done(null, JSON.parse(body as string));
  } catch (error) {
    done(error as Error, undefined);
  }
});
```

### Defect 4, found, not fixed here: the panel says "Ark model not configured" before it has asked

The first screen a reviewer sees, captured at the instant of navigation
(`evidence/demo-run/browser/01-first-paint-before-system-probe.yml`), is:

```
- strong: Checking...
- generic: Ark model not configured
- strong: Runtime configuration needed
- paragraph: Set ARK_API_KEY and ARK_MODEL in .env before using the Playground.
```

on a platform where the provider is configured and five turns have already run. `system` is `null`
until `GET /api/system` resolves, and the unconfigured branch renders on that null rather than
waiting. It resolves in well under a second, so a human barely registers it, but the very first
frame of the demo video will be a red warning saying the thing is not set up, and a screenshot taken
by any automated tool catches it every time. It is a two-line change in `apps/web/src/App.tsx`,
owned by the web lane:

```tsx
// render the configuration warning only once the probe has answered, not while it is null
{system && !system.arkConfigured ? <RuntimeConfigurationNeeded /> : null}
```

with the `Checking...` state already present for the interval before that.

### Defect 5, observed once, not reproduced: a flaky test in `npm run check`

One of five `npm run check` runs on this branch reported `Tests 1 failed | 909 passed (910)`. The
other four were green, including three consecutive runs of the server suite immediately afterwards.
The failing test's name was lost to a grep filter on that run, which is the mistake to avoid
repeating: **`npm run check | tail` reports the exit code of `tail`, not of `check`**, so a piped
invocation can look green when it is not. The green result quoted in section 8 was taken with the
pipeline removed:

```
$ npm run check > /tmp/check.log 2>&1; echo "EXIT=$?"
EXIT=0
```

Whoever owns the container-gated suites should run the server tests in a loop and find it. On this
machine other lanes were creating and destroying docker networks and containers at the same time,
which is the most likely cause and is not a condition a reader of this repository will reproduce.

### Two defects in my own work, for the record

Both were caught by making the script assert rather than print, and both would have produced a demo
that looked like it passed.

- **A vacuous assertion.** Beat 5b checked for `DIRECT_EGRESS_FAILED` across the whole provider log,
  which includes the *command text*, and the command text names all three outcomes. The assertion
  passed while the observed outcome was `DIRECT_EGRESS_OK`. Fixed by making the mock provider log
  the tool output separately and asserting only against that. The real answer, once it could be
  read, was `DIRECT_EGRESS_FAILED`.
- **Reading the tool output at all.** The first mock logged only `requestBytes`, so what the
  container actually observed was never visible outside the container. `lastToolOutput()` in
  `scripts/mock-provider.mjs` now records it, bounded to 4 KB.

## 6. What another lane must do

**For the README (owned elsewhere; it changed on disk while this lane ran, so this is a patch
request rather than an edit).** The Setup section currently tells a reviewer with no key that the
answer is `npm run check`. Add, after the "No key, and you still want to see it work" paragraph:

> **The whole platform, with no key at all.**
>
> ```bash
> npm run poc:mock
> ```
>
> starts a mock model provider in a container beside the platform and points the runtime at it. The
> provider is the only thing standing in for something real: the Codex CLI, the runtime container,
> the shell commands it runs, the files it writes, the transaction, the policy, the journal and the
> panel are all the shipped ones. Then open http://localhost:3000, or drive the whole recorded demo
> automatically:
>
> ```bash
> npm run demo:drive          # five turns: one commits, one is discarded, three are held
> # approve the last held turn in the browser
> npm run demo:after-browser  # read the browser's decision back off the platform
> ```
>
> Both write to `evidence/demo-run/`, which carries the last run in full.

**For whoever owns `docs/`.** `evidence/demo-run/BEATS.md` is the beat-to-code table the submission
needs for section 1.8, and `evidence/demo-run/STORYBOARD.md` is the shot list for the three-minute
video with measured timings. Neither needs rewriting, but the video script should be built from the
storyboard rather than from the plan, because the storyboard was written from a run that happened.

**For the runner lane.** Defect 1's fix touches `transactional-runner.ts` line 216 and
`types.ts`'s `RunnerRequest`. If that file is being rewritten concurrently, the change is one line
and the intent is in the comment beside it.

**For the demo operator.** Do not record the video against `npm run poc` with placeholder
credentials: the run fails at the broker with a 401 several seconds in. Record against
`npm run poc:mock`, and say on camera that the provider is a fixture.

## 6b. Cleanup and recovery

The track asks for cleanup or recovery to be demonstrated alongside the blocking. Blocking was
already demonstrated. This is where the other half stands.

**Cleanup is demonstrated, and it always was, in a record nothing pointed at.** Every settled turn
closes with a `seal.release`. The contained abuse turn's is already in the pack, in
`evidence/demo-run/steps/06-turn-2-egress.json` at sequence 16, with `"removed": true`: the sealed
copy that held the git hook and the deleted customer export was reclaimed, and the reclaim is inside
the same hash chain as the decision that caused it. Five assertions now pin it rather than leaving
it to a reader to notice. They were added to `scripts/demo-drive.mjs` with no change to the
platform, and they read data the driver had already fetched, so they cost no extra request:

- in beat 5b, from the records that beat already captures: a `seal.release` exists for the contained
  turn, its `removed` is `true`, and its `runId` is that turn's and not another shadow's.
- in beat 8, over the whole timeline: every turn that is not `held` released its sealed copy, and
  the one turn that is still `held` has **not** released it, because the bytes a person is about to
  approve live in that copy. Releases follow settlements, and only settlements. Getting it backwards
  either loses the diff under review or leaks one shadow per turn.

They were not run against a live platform, because re-recording the pack needs Docker and a running
platform and a half completed re-record would destroy a pack that works. They were instead evaluated
against the committed artifacts, which is where a live run would read the same fields from:

```
$ node -e '
  const j=require("./evidence/demo-run/steps/10-platform-after.json").journal;
  const released=(t)=>(t.records??[]).some(r=>r.kind==="seal.release");
  console.log("settled all released:", j.turns.filter(t=>t.verdict!=="held").every(released));
  console.log("held kept its copy:", j.turns.filter(t=>t.verdict==="held").every(t=>!released(t)));'
settled all released: true
held kept its copy: true
```

So a fresh `npm run demo:drive` prints three more `ok` lines under BEAT 5b and two more under BEAT 8,
and the scripted stage goes from 50 named checks to 55. The transcript committed in the pack still
shows 50, because it was recorded before these five existed. No beat heading was added, so the beat
set the smoke gate keys on is unchanged.

**Recovery is implemented, tested, and not demonstrable from this driver.** Replaying a commit that
died between its file half and its state half is `CommitProtocol.reconcile()`
(`apps/server/src/commit-protocol.ts:512`), which runs at runner construction
(`apps/server/src/transactional-runner.ts:233`). It has no HTTP route. `app.ts` exposes health,
auth, system, reviews, agents, runs and messages, and none of them calls it. The driver holds
nothing but an HTTP client, so no beat it can run will reach that code.

Handing that back rather than faking it, because a demo beat that mints an interruption it did not
suffer is the exact defect `commit-protocol.copy-fail.test.ts:117` was written to prevent. Two ways
forward, for whoever has a Docker host free:

1. **A separate recording, no production change.** Start the platform, send a turn that will commit,
   kill the process between `turn.committing` and `turn.committed`, restart, then read
   `GET /api/agents/:id/journal` and show the replayed turn and a verifying chain. Publish it as its
   own directory, not merged into `evidence/demo-run/`, because `--stage drive` replaces
   `evidence/demo-run/steps/` wholesale and would delete anything you left in there. That rule is
   in the `finally` block of `scripts/demo-drive.mjs`, and it reaches `steps/` and the stage's own
   transcript, nothing else in the pack.

   It is worth saying what that block did **not** do, because this report said otherwise for two
   days. It is not what destroyed stage 2 on 29 August. The version in force that day opened
   `stageDrive()` by deleting three things before it drove anything: `evidence/demo-run/steps/`,
   `transcript.txt` and the stage 2 transcript, the one the first `git show` line in section 3
   recovers. So re-recording stage 1 took the stage 2 transcript with it, along with the two step
   files beside it, and commit `d93f615` is the commit that records all three deletions:

   ```bash
   git show d93f615^:scripts/demo-drive.mjs   # three fs.rm calls opening stageDrive()
   git show --name-status d93f615             # the three D lines they produced
   ```

   The opening delete was replaced in `1c7ad6a`, which landed the following day, by a scratch
   directory published over the pack only on success, which is the code quoted above.
   `evidence/demo-run/README.md` carries the same account under "Where stage 2 went". The stage 2
   transcript is named in this report only inside `git show` blocks, because it is not in the pack
   and this gate reads an inline-backticked pack filename as a claim that it is.
2. **A production change, if an API-driven beat is wanted.** A read-only route returning the
   `{ replayed, unrecoverable }` that `reconcile()` already produces, which
   `apps/server/src/transactional-runner.ts:775` already re-exports. That is a new route in a file
   this lane does not own, so it is described here and not made.

Until one of those happens, the pack cites the tests by file and line and does not claim recovery
was shown. `evidence/demo-run/README.md` and `BEATS.md` both say so in those words.

## 7. What is not done

- **No PNGs.** See section 4. The browser evidence is the rendered page as text.
- **The demo does not exercise a real Ark endpoint.** Nobody on this lane has a key. The provider
  swap is one environment variable (`ARK_BASE_URL`), the code path is identical, and the container
  tests in `network-docker.test.ts` already prove the broker forwards to whatever that variable
  names with the real key.
- **`npm run poc:mock` was exercised on port 3210 with a lane-local data root**, because other lanes
  hold port 3000 and the default state directory on this machine. The default path differs only in
  two environment defaults, but it has not been run.
- **The driver leaves the agent it created behind.** Re-running `npm run demo:drive` makes a second
  agent rather than reusing the first. That is deliberate for a demo you may want to run twice on
  camera, but there is no cleanup flag.
- **No test drives the journey.** `demo-drive.mjs` needs a running platform, a container engine and
  a mock provider, so it is not in `npm run check`. Its 64 assertions are a harness, not a suite.
  `scripts/demo-smoke.mjs` is the gate that reads a real run's output, and
  `apps/server/src/evidence-citations.test.ts` is the one that reads the committed pack.

## 8. Commands, with their real output

Everything in this section is from the recording session of **29 August**, and the run ids below are
that session's: they are the ones the screens in `evidence/demo-run/browser/` were taken from. The
pack now holds a re-record made on 30 August, which is why its transcript says 6.7 s where this
section says 7.1 s, and why its journal chains carry a `seal.fallback` at the head of every turn and
a `seal.release` at the foot of every settled one where the grouping printed below does not. Neither
set of figures is wrong. They are two runs, and the pack says which is which.


```
$ npm run check > /tmp/check.log 2>&1; echo "EXIT=$?"
EXIT=0
 Test Files  40 passed (40)
      Tests  910 passed (910)          # server
 Test Files  3 passed (3)
      Tests  27 passed (27)            # web
```

937 tests, 910 of them server side, up from 934 by the three regression tests this lane added. The
redirect rather than a pipe is deliberate; see defect 5.

Three consecutive runs of the server suite on this branch, to chase the one failure seen earlier:

```
$ for i in 1 2 3; do npx vitest run > /tmp/vitest-run-$i.log 2>&1; echo "run $i exit=$?"; done
run 1 exit=0    Test Files 40 passed (40)   Tests 910 passed (910)
run 2 exit=0    Test Files 40 passed (40)   Tests 910 passed (910)
run 3 exit=0    Test Files 40 passed (40)   Tests 910 passed (910)
```

```
$ npm run poc:mock            # 9.4 s and 13.1 s to listening on two warm starts
$ npm run demo:drive          # 7.1 s, five turns, all assertions green
$ npm run demo:after-browser  # reads back the decision a person made in the panel
```

```
$ node -e '...group the journal by run...'
1ebb6653   turn.begin -> turn.executed -> effects.captured -> policy.decision -> turn.committing -> turn.committed
d46d0a47   turn.begin -> turn.executed -> effects.captured -> policy.decision -> turn.discarded
9f0b5899   turn.begin -> turn.executed -> effects.captured -> policy.decision -> turn.held
           -> settle.refused -> policy.decision -> turn.approved -> turn.committing -> turn.committed
6aab3f5a   turn.begin -> turn.executed -> effects.captured -> policy.decision -> turn.held -> turn.rejected
96b198ac   turn.begin -> turn.executed -> effects.captured -> policy.decision -> turn.held
           -> policy.decision -> turn.approved -> turn.committing -> turn.committed
total records: 36
```

# What codex actually emits on `--json`

Four recorded event streams from `codex-cli 0.111.0`, the version `Dockerfile.runtime` pins
(`ARG CODEX_VERSION=0.111.0`). They exist because nothing in this repository recorded codex's event
shapes, and that absence is why a real defect survived: `parseCodexEventLine` handles four event
shapes and ignores the rest, so a command codex gave up on produced a turn that looked complete.

Writing a field name from memory would be inventing an interface to close a finding. These are the
real bytes instead.

## How they were captured

Host: Windows 11, Node v22 not required (v24.19.0 here), `codex-cli 0.111.0` installed from npm into
a scratch directory, so nothing in this repository changed to produce them.

The model is a scripted stand-in, not a real provider. `apps/server/test-fixtures/mock-ark.mjs` could
not produce these: it only ever emits an assistant message, which is precisely why no command-shaped
event was on record. The capture used a mock that answers the first request with a `function_call`
naming the shell tool codex declared on that same request, so the tool name comes from the CLI rather
than from a guess, and answers later requests with a plain message so the turn terminates.

    codex exec --json --skip-git-repo-check --sandbox danger-full-access --cd <workspace> "..."

with a `CODEX_HOME/config.toml` rendered exactly as `apps/server/src/codex-home.ts` renders it:
`model_provider = "volcengine_ark"`, `wire_api = "responses"`, `env_key = "ARK_API_KEY"`. The key is
the fixture string `FIXTURE-KEY-NOT-REAL`.

## The four streams

| file | what the turn did |
|---|---|
| `message.jsonl` | the model replied with text and ran nothing |
| `command.jsonl` | the model ran a shell command that finished, and its file landed |
| `slow.jsonl` | the model ran a command that outlived codex's patience; nothing landed |
| `partial.jsonl` | the same, but the command wrote its file BEFORE it was killed, so half its work landed |

## The shapes, which are the point of this directory

A command produces two events, not one:

```json
{"type":"item.started","item":{"id":"item_1","type":"command_execution","command":"bash -lc '...'","aggregated_output":"","exit_code":null,"status":"in_progress"}}
{"type":"item.completed","item":{"id":"item_1","type":"command_execution","command":"bash -lc '...'","aggregated_output":"done\n","exit_code":0,"status":"completed"}}
```

An `item.completed` can also carry `item.type: "error"`, which is NOT the same as a top-level
`{"type":"error"}` event, and which every one of these four streams contains:

```json
{"type":"item.completed","item":{"id":"item_0","type":"error","message":"Model metadata for `mock-model` not found. ..."}}
```

## What the timed-out case looks like, and why it matters

`slow.jsonl` and `partial.jsonl` both end the command like this:

```json
{"item":{"type":"command_execution","aggregated_output":"","exit_code":124,"status":"failed"}}
```

`124` is the conventional exit code for a command killed by a timeout. After it, the turn continues
normally and **`turn.completed` still arrives**. So the stream carries the failure, and the runner
throws it away: nothing in `parseCodexEventLine` reads a `command_execution` item, so the platform
cannot tell a turn whose commands all succeeded from a turn whose command was killed.

`partial.jsonl` is the case worth reading twice. Its command was
`echo landed > landed.txt && sleep 45 && echo finished > finished.txt`. `landed.txt` exists in the
workspace and `finished.txt` does not, so the effect set is neither empty nor complete: half a
command's work, committed as a clean turn.

## The boundary, swept rather than assumed

One run per duration, same command shape, reading `exit_code` and `status` off the
`command_execution` item and checking whether the command's file landed:

| sleep | exit_code | status | output | file landed |
|---|---|---|---|---|
| 2s | 0 | completed | finished | yes |
| 5s | 0 | completed | finished | yes |
| 8s | 0 | completed | finished | yes |
| 9s | 0 | completed | finished | yes |
| 10s | 124 | failed | (empty) | no |
| 11s | 124 | failed | (empty) | no |
| 12s | 124 | failed | (empty) | no |
| 20s | 124 | failed | (empty) | no |

So the limit is ten seconds, not "about ten seconds", and it is sharp: nine completes, ten does not.
Any `npm install`, build, test run or migration an agent starts is over that line.

## Keeping these true

They are a record of one CLI version. If `CODEX_VERSION` in `Dockerfile.runtime` moves, recapture
rather than edit: the value of this directory is that it is what the tool emitted, not what we think
it emits. `codex-command-events.test.ts` reads these files rather than inlining the JSON, so a
recapture updates the tests by updating the fixtures.

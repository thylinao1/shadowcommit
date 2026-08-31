# Which models this account can actually reach, measured

Measured 31 August 2026, 16:2x SGT, from this laptop against
`https://ark.ap-southeast.bytepluses.com/api/v3` on the operator's BytePlus key.

Reproduce:

    set -a && . ~/.config/shadow-commit/ark.env && set +a
    python3 research/multi-model/probe-models.py seed-2-0-code-preview-260328 deepseek-v4-pro-260425 glm-4-7-251222

Two routes matter and they are not the same question. `/chat/completions` is the ordinary chat wire.
`/responses` is the OpenAI Responses wire, and it is the one `codex` speaks (`wire_api = "responses"`
in the codex config this runtime writes). A model can answer one and 404 the other, so availability
was probed on `/responses` specifically, which is the route a real turn uses.

## THE HEADLINE FINDING: availability is consumed by use, so this is not a list of ten models

Under Safe Experience Mode each model carries its own small spend cap, and **one full demo drive is
enough to exhaust one model**. Measured on `seed-2-0-code-preview-260328` inside forty minutes:

    16:30   bare probe on /responses          HTTP 200
    16:35   mid-run, demo beat 2              HTTP 429 TooManyRequests   (a throttle, clears by waiting)
    17:0x   bare probe on /responses          HTTP 429 SetLimitExceeded  (a cap, does NOT clear)

So the table below is not ten interchangeable models. It is roughly **ten attempts, total**, at
anything that drives a real agent turn, and every bare probe spends part of one. Do not re-probe the
list to keep it fresh.

The two 429s are different failures and confusing them wastes a model:

| code | meaning | clears by waiting |
|---|---|---|
| `TooManyRequests` | rate throttle, usually several sessions sharing one account | yes |
| `SetLimitExceeded` | that model's spend cap is exhausted and the model is paused | no |

**The operator lever.** Closing Safe Experience Mode at
`console.byteplus.com/ark/region:ap-southeast-1/openManagement` turns ten one-shot attempts back
into an ordinary quota. It is a console toggle, not a payment. Until it is closed, the end-to-end
evidence this project is scored 40 percent on is rate-limited by that toggle.

## Probed is not the same as tested under load, and only one model has been tested

Everything in the table below was established with ONE short completion on `/responses`. Session 47
then drove `seed-2-0-code-preview-260328` through the actual demo, which puts codex through
multi-step turns with tool calls, and the account started returning HTTP 429 `TooManyRequests`. That
is a throttle and it clears by waiting, unlike `SetLimitExceeded`, which does not. The lesson is that
a 200 on a bare probe is necessary and not sufficient.

Tested under load, meaning driven through a real multi-step agent turn:

| model | probed | driven under load | how far it got |
|---|---|---|---|
| `seed-2-0-code-preview-260328` | yes | **yes** | demo beats 0 to 4 pass, 19 assertions, journal chain verified over 154 records, entered beat 5 |
| every other row below | yes | not yet | unknown |

## The account state moved during the day, so this is a reading, not a property

At 13:00 `seed-2-0-code-preview-260328` was recorded as `ModelNotOpen` on this same key. At 16:30 it
answered. The earlier note was not wrong; the account changed underneath it. Treat every row here as
"answered at 16:30 on 31 August" rather than "is available".

## The four models the project was blocked on are still capped

    deepseek-v4-pro-ga-260813     HTTP 429  SetLimitExceeded
    deepseek-v4-flash-ga-260731   HTTP 429  SetLimitExceeded
    glm-5-2-260617                HTTP 429  SetLimitExceeded
    deepseek-v3-2-251201          HTTP 429  SetLimitExceeded

`SetLimitExceeded` is a spend cap on that model, not a per-minute throttle. Waiting does not clear it.
The console message names the remedy and it is not a payment: "please visit the Model Activation page
to adjust or close the Safe Experience Mode". That is a toggle.
`evidence/demo-run/REAL-PROVIDER-STATUS.md` records the run that stopped here.

## Ten other models answer, on the route the runtime uses

Every row below returned HTTP 200 with `status: "completed"` and the literal string `READY` on
`POST /responses`.

| model id | family | context | first token, seconds | in / out tokens |
|---|---|---|---|---|
| `seed-2-0-code-preview-260328` | ByteDance Seed 2.0, code | 262144 | 0.9 | 47 / 30 |
| `seed-2-0-pro-260328` | ByteDance Seed 2.0 | 262144 | 1.7 | 65 / 11 |
| `seed-2-0-lite-260428` | ByteDance Seed 2.0 | 262144 | 1.8 | 50 / 20 |
| `seed-2-0-mini-260428` | ByteDance Seed 2.0 | 262144 | 0.4 | 50 / 26 |
| `seed-1-8-251228` | ByteDance Seed 1.x | 262144 | 0.9 | 64 / 32 |
| `seed-1-6-250915` | ByteDance Seed 1.x | 262144 | 2.2 | 97 / 56 |
| `dola-seed-2-1-turbo-260628` | ByteDance Seed 2.1 | 262144 | 2.1 | 62 / 23 |
| `deepseek-v4-pro-260425` | DeepSeek V4 | 1048576 | 1.9 | 21 / 29 |
| `deepseek-v4-flash-260425` | DeepSeek V4 | 1048576 | 1.1 | 21 / 35 |
| `glm-4-7-251222` | Zhipu GLM 4.7 | 204800 | 0.8 | 21 / 27 |

Still `ModelNotOpen` on this account: `gpt-oss-120b-250805`.

## What this changes

Four distinct model families are reachable: ByteDance Seed (2.0, 2.1 and 1.x), DeepSeek V4, and
Zhipu GLM. `seed-2-0-code-preview-260328` is a coding-specialised model.

That makes a question askable that could not be asked before. This system's central claim is that it
judges the **effect set** a turn produced, not the model that produced it. If that claim is true, the
containment decision on a given effect set is independent of which model produced it, and the models
should differ only in what effects they produce. Both halves of that are now measurable rather than
asserted.

## The raw probe

The probe is `research/multi-model/probe-models.py`. It reads `ARK_BASE_URL` and `ARK_API_KEY` from
the environment, never from a file in this repository, and prints one JSON line per model. It prints
no part of the credential.

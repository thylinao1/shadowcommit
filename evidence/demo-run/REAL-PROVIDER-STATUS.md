# The demo against a real provider

Written 31 August 2026. This records what happens when `demo-drive.mjs` is pointed at a real model
instead of the mock, because until today it had never been run that way and six of its beats turned
out to be asserting the mock's behaviour rather than the product's.

## What was proven

Beats 0 to 4 pass against a real BytePlus Ark provider at `ark.ap-southeast.bytepluses.com`, on the
operator's own key, with the mock provider not running at all. From the run's own records:

    model really called      125,803 input tokens, 119,241 cached, 3,815 output
    shell commands           7, counted by the boundary
    commands that failed     1 of 7, which the model's own summary does not mention
    verdict                  review, under dependency-added
    journal                  turn.begin -> effects.captured -> policy.decision -> turn.held
    effects captured         256, of which the API returns 100

The one-of-seven line is the product's whole thesis showing up unprompted: the agent said it was
done, and the boundary counted a failure the agent did not mention.

## The six beats that were wrong, and why

Every one of them failed while the product was behaving CORRECTLY. They had been written against
the mock, whose playbook is fixed, so they had quietly encoded that playbook as if it were the
contract.

    src/index.ts exists            a real model chooses its own filenames
    package.json in the workspace  the turn is HELD, so its writes are correctly NOT in the real
                                   workspace. This beat asserted that containment had leaked.
    membership in the API's        the timeline route caps effects at 100 of 256 and the reviews
    effect list                    route at 200. A turn that runs npm install pushes its own source
                                   files past the cap: on one run all 100 effects shown were under
                                   node_modules and the agent's files were in the withheld 156.
    status === "completed"         a real turn installs dependencies, dependency-added holds it,
                                   and the status is "contained"
    verdict === "committed"        the same thing one layer down, in the panel
    committing -> committed        a held turn journals turn.held and stops, because nothing was
                                   applied

Each now asserts what is true of both providers and prints which one happened. The CLI is read from
the SHADOW COPY under `<data>/shadows/<runId>/merged`, which is where a held turn's writes actually
are and what the reviewer approves, so it is the honest ground truth rather than a convenient one.

## What is not yet proven

The full run to beat 10 has not completed. Beats 5 to 8 were never reached because of the provider,
not the platform:

    deepseek-v4-pro-ga-260813    HTTP 429 SetLimitExceeded, spend cap reached
    deepseek-v4-flash-ga-260731  HTTP 429 SetLimitExceeded, spend cap reached
    glm-5-2-260617               HTTP 429 SetLimitExceeded, spend cap reached
    deepseek-v3-2-251201         answers, but the turn did not settle within the 300s beat timeout

`SetLimitExceeded` is NOT a per-minute throttle. It means the spend cap set on that model in the
BytePlus console is exhausted and the model service is paused, so waiting does not clear it. Each
full turn costs roughly 100k to 200k tokens, most of it cached context, so a handful of runs
exhausts a model's cap.

To finish: raise the cap on any one model in the console, then

    set -a && . ~/.config/shadow-commit/ark.env && set +a
    npm run poc
    npm run demo:drive

The committed evidence pack in this directory is still the mock run. It was not overwritten,
because every real-provider attempt failed and the driver leaves the last good pack alone on
failure. That is the staging behaviour working as intended.

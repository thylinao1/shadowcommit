# The three minutes, as a viewer sees them

Written from the run in `transcript.txt` and the screens in `browser/`, not from a plan. Those two
are different runs on different days, on ports 3000 and 3210, which `README.md` sets out under "Two
runs, one held turn"; this page is a presenter's script rather than evidence, and it takes the
timings from the transcript and the screen descriptions from the browser snapshots. Every
duration marked **measured** is a real latency on an M2 MacBook Air with Colima, and every per turn
figure below is read off `transcript.txt`, where each turn prints its own elapsed time beside its
status. The rest is narration time, which is the only thing a presenter controls. The two start up
figures in the next paragraph are the exception: they were timed at the terminal and no artifact
here records them.

The platform is already started before the recording begins. `npm run poc:mock` took **9.4 s and
13.1 s measured** on two warm starts, from the command to the server listening, with the runtime
image already built. A cold machine spends longer, and it is the `docker build` of
`Dockerfile.runtime` that costs it, not the platform. Starting it on camera would spend 5 to 8% of
the budget on a progress bar.

The run has five turns. Three minutes fits four of them; the fifth, a rejection, is the one to cut,
because the discard at 0:55 already shows a turn being thrown away and the rejection's only new
information is that a person can be the one who throws it.

| Time | On screen | What is said | Platform time |
|---|---|---|---|
| 0:00 to 0:12 | the empty panel at `localhost:3000`, then Create Agent, then the agent card with `ready` beside it | "This is the starter kit, unchanged. One agent, one workspace, ready." | agent creation is a single 201; the workspace comes back seeded with `.gitignore`, `AGENTS.md`, `README.md` |
| 0:12 to 0:35 | the Playground. The organizers' own acceptance prompt is typed and sent. The reply arrives with **Committed: 3 changes** under it | "A real task. The Codex CLI runs in a container, the model asks for a shell command, the command writes three files." | **1.3 s measured** from send to the run reaching a terminal state (`transcript.txt` line 30) |
| 0:35 to 0:55 | the Run timeline tab. The committed turn, opened: the run id, seal `copy`, and the eight journal records it wrote | "Every turn is journaled: the seal, then begin, executed, captured, decided, committing, committed, then the seal released. The chain over all of it verifies, and the badge says so." | the timeline is one GET; `Chain intact` is rendered from the server's own verification |
| 0:55 to 1:25 | back to the Playground. The second prompt, which reads like ordinary release tooling. The reply says the helper is installed. Under it, in red: **BLOCKED, nothing was sent: protected-asset-delete** | "The agent believes it succeeded. It wrote a git hook that pipes a fetch into a shell, and it deleted the customer export. No rule in this repository is named after that attack. It is contained because of what it did." | **1.3 s measured**. The workspace digest either side of the turn: `cc4f79ba8429f286` and `cc4f79ba8429f286` |
| 1:25 to 1:40 | a terminal beside the browser: `ls customers.jsonl` and `ls .git/hooks/` in the real workspace | "The protected file is still there, byte for byte. The hook never existed outside the sealed copy. And its two attempts to reach the network: one had no route, the other was denied at the broker." | from the journal for that turn: `{"deny":2,"live":2}` |
| 1:40 to 2:10 | the third prompt. The reply says **Held for review: 2 proposed changes**, and the sidebar queue badge goes to 1 | "This one changes what runs after `npm install`. Not obviously an attack, not obviously safe. So it is neither committed nor thrown away: it waits." | **1.3 s measured** to the hold; the queue badge follows within one 2 s poll |
| 2:10 to 2:40 | the Review queue. The card, the rule, the two proposed paths, and the diff opened on `package.json`: one line out, two lines in, the `prepare` script visible | "Here is the whole change before any of it is real. The approval is bound to the hash of this exact set: if it moves while you are reading, the approval is refused rather than applied." | the effect set hash is rendered on the card |
| 2:40 to 2:52 | Approve and commit is pressed. The queue empties. The Playground reply now reads **Committed: 2 changes, approved by operator** | "One click. Now it is real, and the record says who did it." | settles in well under one 2 s poll |
| 2:52 to 3:00 | the Run timeline: `Approved`, `Rejected`, `Approved`, `Blocked`, `Committed`, chain intact | "Five turns. Three landed, one was thrown away by the policy, one was refused by a person. All five are in one list, and none of them is the agent's own account of itself." | |

## What a presenter should not do

- **Do not start the platform on camera.** 9 to 13 s warm, minutes cold.
- **Do not read the JSON.** The panel already says `Committed: 3 changes` and
  `BLOCKED, nothing was sent`. Reading a journal record aloud spends 15 seconds proving something
  the badge proves in one.
- **Do not skip the terminal shot at 1:25.** It is the only moment that shows the protected file
  surviving in the real workspace rather than in a screen the same program drew.
- **Do not claim the model was real.** Say the provider is a fixture and everything under it is not.
  A viewer who works out on their own that the model was mocked stops believing the rest, and the
  fixture is what makes the demo the same every time it is run.

## The one number worth saying out loud

A whole turn, from the message leaving the browser to a verdict recorded against it, took **1.3 s
measured**, on all five turns of the run in `transcript.txt`, and that includes starting a
container, sealing the workspace, two model round
trips, running the shell command, hashing every changed file, running the whole rule set and
settling. With a real provider the model's own latency dominates and this overhead does not move,
because none of it is waiting on the model.

## If the three minutes have to become ninety seconds

Keep 0:12 to 0:35 (a real turn lands), 0:55 to 1:40 (the abuse and the untouched workspace) and
2:10 to 2:52 (the diff and the approval). Drop the timeline, and drop the agent creation: open on an
agent that already exists.

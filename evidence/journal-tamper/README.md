# evidence/journal-tamper

The audit ledger being broken on purpose, refused by the shipped verifier, and put back.

`npm run verify:journal` is the one command a reviewer is told to run, and until this lane the only
thing anyone had ever watched it do was pass. A verifier that has only ever been seen passing is a
verifier a judge has no reason to believe: a command that printed `OK` unconditionally would look
exactly the same from the outside. The two halves belong together. `npm run demo:tamper` is the
refusal; beat 8b of `npm run demo:drive` is the pass, on the ledger the demo itself just wrote.

## What is here

| File | What it is |
|---|---|
| `synthetic-run.txt` | the transcript of `npm run demo:tamper` against a synthetic journal, written by the script itself with `--out` |
| `failure-paths.txt` | the output of `check-tamper-script.mjs`, five interrupted or hostile states driven end to end |
| `build-synthetic-journal.mts` | builds the synthetic journal both of the above run against |
| `check-tamper-script.mjs` | drives the five failure paths and hashes the journal before and after each |

## How to reproduce every line of it

```bash
T=$(mktemp -d)
npx tsx evidence/journal-tamper/build-synthetic-journal.mts "$T"
SHADOW_COMMIT_HOME="$T/home" npm run demo:tamper -- \
  --journal "$T/data/journal.jsonl" --data-dir "$T/data"
node evidence/journal-tamper/check-tamper-script.mjs "$T"
```

The journal is synthetic and it is not a mock. `build-synthetic-journal.mts` imports the shipped
`Journal` class and appends the seven records of one contained turn, so the file it produces carries
a real HMAC under a real key, real Ed25519 checkpoint signatures and real Merkle roots. What makes
it synthetic is only that it belongs to nobody: proving out a script that writes to an audit ledger
by pointing it at a real one is the wrong order to do things in.

## What the tamper does, and why one character is the whole point

`synthetic-run.txt` flips one byte at offset 3383: the `d` of `"verdict":"discarded"` in record 8,
which is that turn's `policy.decision`. The file stays the same length, the record still parses as
JSON, no other record is touched. It is the quietest edit somebody could make, and it changes what
the ledger says happened.

The verifier refuses, and it refuses on three layers at once:

```
first break  record 8 [hash] record 8 (seq 8) hash does not match its content
problems     3 in total:
  [hmac] record 8 (seq 8) hmac does not verify under the journal key
  [merkle] checkpoint at seq 11 claims a Merkle root that does not match the 10 records before it
result       BROKEN
```

The hash is the layer anybody who can write the file could have repaired. The HMAC is the one they
could not, without the key, which lives outside the data directory. The Merkle line is the checkpoint
that covers record 8 noticing that its leaf moved. Exit 1, which is the code CI gates on.

Then the byte goes back, the file hashes to `5f170be2...`, which is what it hashed before, and the
verifier prints `OK, the ledger verifies from record one` and exits 0 again.

## The restore is written before the tamper, and that order is the design

This script runs against a real operator's real audit log. A demo script that can leave a
developer's ledger broken is worse than no demo script, so:

- **The ticket.** `<journal>.tamper-restore.json` holds the offset, the original byte, the original
  line and a sha256 of the file prefix. It is fsynced BEFORE the journal is opened for writing, so
  the information needed to undo the change exists on disk before the change does. Any run finds a
  leftover ticket and heals from it as its first act, before doing anything else.
- **The handlers.** SIGINT, SIGTERM, SIGHUP, SIGQUIT, an uncaught throw, an unhandled rejection and
  the plain `exit` event all restore synchronously. Synchronously matters: an async write scheduled
  from a signal handler is a write that may never land.
- **One byte, never a rewrite.** The tamper is a single-byte write at a known offset and the restore
  is the same write in reverse, so a platform that appended records during the window keeps every
  one of them. Restoring a whole-file backup over the top would silently delete them.
- **Proof, not assertion.** After the restore the byte is read back and the prefix is re-hashed
  against the ticket. The script does not report a restore it has not measured.

`failure-paths.txt` drives all of that, 28 checks over six cases. Case A reconstructs by hand the
exact state a SIGKILL leaves, a ticket on disk and the byte still flipped, and heals it. Case B is a
real SIGINT to a real child process, sent the moment the ticket file appears, which is the moment the
window opens. Cases C, D and E are the refusals: a ledger that already fails verification is never
tampered with further, because then the restore could not be shown to have worked; a missing journal
is explained rather than broken; and a ticket whose byte is neither the original nor the tampered
value means somebody else wrote there, so nothing is written and the ticket is kept rather than
swept away. Case F adds an `anchors.jsonl` pinning the last checkpoint's head, because a real
deployment's data directory has one and the synthetic journal does not: the tamper lands in a
record's payload rather than on that head, so the anchor stays present while the three layers below
it go red, and that is asserted rather than assumed.

## The trap this design is built around

`Journal.open()` verifies the chain at boot and calls `enterCompromised()` on a failure, which sets
the journal's state to `compromised`. `TransactionalRunner` calls `assertUsable()` before it builds
anything, so a tampered journal makes the platform refuse every turn at its next start, before any
mount or container exists.

That refusal is correct, and **it is not reversible by putting the byte back.** `enterCompromised()`
also writes `<journal>.compromised.jsonl`, and the only documented way out of the state is
`acknowledge(actor)`, which writes a record into that sidecar and another into the main chain. A
demo that triggered it could not leave the machine as it found it, and the verifier would afterwards
print `COMPROMISED  a sidecar chain exists` on a ledger nobody had actually attacked.

So nothing in `scripts/demo-tamper.mjs` constructs a `Journal`. It runs
`apps/server/src/verify-journal.ts`, which reads through `verifyJournalAt` and writes nothing at all.
A platform that is already running is not affected either: its state was decided at its own boot and
is held in memory, and it appends against a head it already knows. The compromised path is real, it
is the right behaviour, and it is deliberately not on this script's path.

## What has NOT been executed

Said plainly, because the rest of this directory is a record of things that were run.

- **Beat 8b has never run inside a real `npm run demo:drive`.** The platform needs Docker and a
  provider key, so the driver has not been run end to end from this lane. What was executed is the
  beat's own machinery: `runVerifyJournal` was imported from `scripts/demo-drive.mjs` and run against
  the synthetic data directory, and it returned exit 0 with a `records 11` line, which is what the
  beat's two assertions read. The beat's placement in the transcript, and its `steps/` capture, have
  not been produced.
- **`scripts/demo-tamper.mjs` has never run against a platform-written journal.** Every run recorded
  here is against the synthetic one. The record it selects on a real ledger will be a different
  record, chosen the same way.
- **`evidence/demo-run/` was not re-recorded.** That pack is the run of 30 August and re-recording it
  would need the same machine and the same containers. Its `BEATS.md` names beat 8b as a beat the
  committed transcript predates.

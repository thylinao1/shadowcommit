# This is fixture material, not a running service

The files here are a small merchant API shaped like a real one: a catalogue, some customers, some
orders, a server and an `.env`. They exist so a demo has something plausible to act on.

Three things a reader should know before drawing any conclusion from them.

The `.env` has three assignments: `PROVIDER_KEY=FIXTURE-KEY-NOT-REAL`, a `MERCHANT_API_BASE` on
loopback, and `STORE_ID=store-demo-0001`. Only the first is credential-shaped, and its value announces
that it is a fixture; the other two are non-secret config. It is committed on purpose, because the
"before" scene of the demo needs a credential-shaped file to act on, and a value that names itself a
fixture is the only safe way to have one. `FIXTURE-KEY-NOT-REAL` is the same literal the test suite
uses.

Nothing in the product reads this directory. It is not wired into the runner, the policy or the review
path, and no test outside this directory depends on it.

The participants feature this fixture was written alongside is NOT part of the product. It was measured
as unreachable from `createRunner` and `createApp`, and only its irreversibility table was taken
(`apps/server/src/irreversibility.ts`, which needs no wiring to be true). If you are reading this
looking for a database or HTTP settle path, there is not one.

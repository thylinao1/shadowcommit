# Transient state inside a turn: a mechanism, and the four things it does not do

`research/LIMITATIONS-PLAN.md` item 1. Root cause A, second half. A credential staged, used and
deleted inside one turn produces zero effects, because the effect set compares two end states, so the
turn commits under rule `none`. The read witness closed the first half by proving a turn OPENED
something. This page is about the missing half, proving it CREATED something that no longer exists at
settle.

The plan said to expect a partial answer. This is one, and the partial is stated before the result.

## The mechanism

**A directory remembers that something happened in it, even after the something is gone.** Creating a
file in a directory updates that directory's mtime, and so does removing it. A file created and
deleted inside one turn therefore leaves the directory's CONTENTS identical and its MTIME advanced.
That difference is the entire signal.

Both halves are measured rather than assumed, because the whole idea rests on them:

```
dir contents identical : True
dir mtime advanced     : True (delta 22474946 ns)
dir ctime advanced     : True
sealed copy preserves dir mtime: True
```

The first three come from staging a file with an AWS-shaped key in it, reading it, and removing it,
which is the attack shape exactly. The fourth matters just as much and is easy to miss: the sealer
copies with `cp -a`, which preserves directory mtime to the nanosecond, so a baseline taken at seal is
comparable with a reading taken at settle. If the copy had reset directory mtimes there would be no
baseline and no measurement.

## Why nothing sees it today

`capture.ts:214` `snapshotStats` walks the tree and records nothing about directories:

```ts
if (entry.isDirectory()) {
  await walk(full, rel);
  continue;
}
```

Only files reach `out.inodes` and `out.signatures`. Directories are a path to walk through, never a
thing to record. So the baseline that would make this measurable is not taken, and it cannot be
recovered afterwards: by settle the evidence is a timestamp on a directory nobody wrote down before.

That is a one-line omission with a real consequence, and it is the reason this limitation reads as
fundamental in `PROJECT.md` when it is only mostly fundamental.

## What it would prove, stated narrowly

That a turn created and removed at least one entry in a named directory. Nothing else.

## The four things it does not do, which is the honest half

**1. It names a directory, never a file.** The path, the bytes, the content and the count are gone
with the file. A witness saying "something appeared and vanished under `src/config/`" cannot say
whether it was a credential or an editor swap file, and no rule in this repository can judge content
it cannot read. This is evidence for a HOLD and could never justify a discard.

**2. Out-of-workspace staging is untouched.** The snapshot is rooted at the workspace. A turn that
writes its credential to `/tmp` inside the container, uses it and deletes it advances no directory
this ever walks. The confinement design says the container is the boundary, not the workspace, so the
most obvious place to stage something transient is precisely the place this cannot see. This is not a
gap that can be closed by walking more of the container: `/tmp` churns constantly under any real
toolchain.

**3. The false positive rate is unknown and is probably bad.** Every legitimate transient file trips
it: editor swap files, compiler and bundler temporaries, `npm` and `pip` staging directories, and
every atomic save, since write-temp-then-rename is how careful programs write files at all. On a
directory that a build touches this would fire on every turn. The read witness went through exactly
this and needed three narrowings and a measured threshold before its raw 35.4% could become a rule at
4 of 48; nothing here has been narrowed at all yet.

**4. It cannot separate create-and-delete from a rename passing through.** Both are entries appearing
and disappearing in the directory. A rename already produces effects elsewhere so the turn is
judgeable anyway, but the witness itself does not distinguish them.

## The experiment that would price it, which has not been run

The rate in limit 3 is the number that decides whether this is a control or a second queue, and it is
cheap to get, because the corpus already runs real toolchains over four real repositories. Take the
5,000 benign turns, record directory mtimes at seal, compare at settle, and count how many benign
turns show at least one directory with unchanged contents and an advanced mtime. If that is a small
share, the witness is worth building and narrowing. If most benign turns trip it, the honest outcome is
that this signal is not usable at the workspace root and the limitation stands with a sharper reason
than it has today, which is a better result than the vague one currently published.

Predict the answer before running it, and write the prediction down first. That is the practice that
made the rename ablation worth something: the static count named four scenarios before the dynamic run
flipped exactly those four.

## What this changes in the published limitation

`PROJECT.md` currently says, under "What it cannot do":

> **Transient state inside a turn is invisible.** A credential staged, used and deleted within one
> turn produces zero effects, because the effect set compares two end states.

Both sentences are true and should stay. What can be added once the experiment above has a number is
that the invisibility is a property of what the seal RECORDS rather than of what the filesystem knows,
and that the part which is genuinely out of reach is the content and the out-of-workspace staging, not
the existence of the event. Until that number exists, this page is a mechanism with a proof and no
cost measurement, and it should not be cited as a closed limitation.

# What the provenance detector cannot see, measured

The broker refuses a live outbound call whose payload carries protected file content. `provenanceOf`
in `apps/server/broker/broker-core.mjs` is what decides that. It has a floor, the floor is a real
design point rather than a defect, and until now it was written down nowhere.

## How it works, and why that implies a floor

`provenanceWindows` cuts the protected file into 48-byte probes at a 32-byte stride, capped at 256
probes. Each probe is then tested with `view.text.includes(probeText)`: does the OUTBOUND PAYLOAD
contain this piece of the file?

That direction is what creates the floor. A payload shorter than one probe cannot contain a probe, so
a small theft is invisible by construction rather than by oversight.

## Measured

A 4,000-byte protected file, thefts taken at every offset coprime with the stride so window alignment
varies, run against the real `provenanceOf`:

| bytes stolen | positions tried | detected |
|---:|---:|---:|
| 16 | 108 | **0%** |
| 32 | 108 | 21% |
| 47 | 107 | 73% |
| 48 | 107 | 78% |
| 64 | 107 | **100%** |
| 80 | 106 | 100% |
| 128 | 105 | 100% |
| 200 | 103 | 100% |

**Sixty-four contiguous bytes is the point where detection becomes total, at every offset.** Below 48
it degrades quickly, and at 16 bytes it is nothing at all.

Reproduce:

```bash
export PATH=$HOME/.nvm/versions/node/v22.21.0/bin:$PATH
node --input-type=module -e '
import { provenanceOf } from "./apps/server/broker/broker-core.mjs";
const mk=(n)=>{let s="",i=0;while(s.length<n)s+="line"+(i++)+"-"+"abcdefghijklmnopqrstuvwxyz".slice(0,20)+"\n";return s.slice(0,n)};
const file=mk(4000), corpus={"customers.jsonl":file};
for(const len of [16,32,47,48,64,80]){let c=0,m=0;
  for(let at=0;at+len<=file.length;at+=37) provenanceOf(file.slice(at,at+len),corpus)?c++:m++;
  console.log(len, c, m);}'
```

## What covers the gap, and what does not

Provenance is one of three things `scanPayload` runs. The other two are `matchSecret`, which looks for
named credential shapes, and entropy. Measured against a small customer file:

| payload | provenance | secret pattern | refused? |
|---|---|---|---|
| a 40-byte API key on its own | yes | yes | **refused** |
| 64 bytes of the file | yes | yes | **refused** |
| one email address | no | no | **leaves live** |
| a short password | no | no | **leaves live** |
| 16 bytes of the file | no | no | **leaves live** |

So a credential with a recognisable shape is caught twice over, by provenance AND by pattern, and the
floor never applies to it. What the floor exposes is the small unstructured secret: one email address,
one short password, one row of a table. Those leave live.

## Why the window is not simply made smaller

Because the floor is a false-positive trade, not an oversight. A 16-byte probe of a customer file is a
string like `,ada@example.` or `1,2026-08-31,`. Sequences that short occur in ordinary traffic that
has nothing to do with the protected file, so a detector with a 16-byte window would refuse a large
share of legitimate outbound calls, and a control that fires constantly is turned off.

The three detectors are layered for exactly this reason: provenance is the one that catches BULK, and
named patterns catch the SHAPED, and each is bad at the other's job.

## The honest statement

**A turn that exfiltrates fewer than about 48 bytes of unstructured protected content, in a single
live GET, is not caught by content inspection.** It is still bounded by everything else: the
destination must be on the allowlist, the call is recorded in the broker's decision log with its host
and path, and a write-like call is held regardless of size. But it is not refused on content.

Three-and-a-half rows of a customer table go out per allowed request. Extracting a table of any size
that way needs many requests to an allowlisted host, which is a rate signal nothing here currently
watches. That is the shape of the residual risk and it is worth stating plainly rather than leaving
the reader to assume content inspection is complete.

`broker-core.provenance-floor.test.ts` pins these numbers so the floor cannot move without somebody
choosing to move it.

/**
 * contract.ts:2 promises: "change PROMPT_VERSION and every cached verdict is correctly invalidated."
 *
 * That sentence is TRUE and it is not the risk. PROMPT_VERSION is hashed into the cache key, so
 * bumping it does invalidate everything. The risk is the CONVERSE, which nothing enforced: edit
 * SYSTEM_PROMPT and leave PROMPT_VERSION alone, and every stale verdict stays valid and is served
 * for a prompt that no longer exists. The docstring states a guarantee that holds only if a human
 * remembers a step, and a guarantee that depends on remembering is a convention, not an invariant.
 *
 * This test makes it an invariant. The prompt's hash is pinned to its version. Editing the prompt
 * without bumping the version fails here, loudly, with the instruction.
 *
 * It matters more than a normal freeze test because of what a stale hit looks like: not an error,
 * but a confident verdict. The same shape as the cacheKey collision and the missing deletions,
 * where the failure is indistinguishable from a clean read.
 *
 * Run: npx tsx research/semantic-judge/contract.freeze.test.ts
 */
import crypto from "node:crypto";
import { SYSTEM_PROMPT, PROMPT_VERSION } from "./contract.js";

/** sha256 of SYSTEM_PROMPT, pinned per version. Add a row when you bump; never edit a row. */
const PINNED: Record<string, { sha256: string; chars: number }> = {
  "sj-1": { sha256: "d366a0d0936d017cc25b22967bebf04990b5157a833e1d51ba86373f065cc2b7", chars: 1773 },
};

let failed = 0;
const check = (name: string, cond: boolean, detail = "") => {
  if (cond) console.log(`  ok   ${name}`);
  else { failed++; console.log(`  FAIL ${name} ${detail}`); }
};

const actual = crypto.createHash("sha256").update(SYSTEM_PROMPT).digest("hex");
const pin = PINNED[PROMPT_VERSION];

console.log(`contract freeze  (PROMPT_VERSION = ${PROMPT_VERSION})`);
check("this version is pinned", pin !== undefined,
  `\n       PROMPT_VERSION is "${PROMPT_VERSION}" and PINNED has no row for it.\n` +
  `       If you bumped the version, add: "${PROMPT_VERSION}": { sha256: "${actual}", chars: ${SYSTEM_PROMPT.length} }`);

if (pin) {
  check("SYSTEM_PROMPT matches its pinned hash", actual === pin.sha256,
    `\n       expected ${pin.sha256}\n       actual   ${actual}\n` +
    `       THE PROMPT CHANGED BUT PROMPT_VERSION DID NOT.\n` +
    `       Every cached verdict under "${PROMPT_VERSION}" was produced by the OLD prompt and will\n` +
    `       still be served, silently, as a confident verdict for a prompt that no longer exists.\n` +
    `       Bump PROMPT_VERSION and add a new PINNED row. Do not edit the existing row.`);
  check("character count matches", SYSTEM_PROMPT.length === pin.chars,
    `expected ${pin.chars}, got ${SYSTEM_PROMPT.length}`);
}

// The other half of the same guarantee: the key must actually depend on the version.
import { cacheKey } from "./client.js";
check("cacheKey depends on the prompt id",
  cacheKey("m", "payload", "sj-1") !== cacheKey("m", "payload", "sj-2"),
  "two prompt ids produced the same key, so a version bump would NOT invalidate anything");
check("cacheKey defaults to the current version",
  cacheKey("m", "payload") === cacheKey("m", "payload", PROMPT_VERSION),
  "the default no longer matches PROMPT_VERSION, so existing entries are orphaned");

console.log(failed === 0 ? "\nALL PASS" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);

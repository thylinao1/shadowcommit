import { describe, expect, it } from "vitest";
import { DEFAULT_PROTECTED_PATHS } from "./policy-context.js";

/**
 * The product's own audit trail was not in the set the product defends.
 *
 * Shadow Commit's claim is a tamper-evident record of everything an agent did. A turn that rewrites
 * the journal, forges an anchor, or takes the signing key is not damaging an ordinary file, it is
 * attacking the evidence that the rest of the platform worked. `.shadow-commit` was in the protected
 * list; `journal.jsonl` sitting beside it was not, and neither was the key that signs it.
 *
 * Found by the rule-blind held-out attack set, which is exactly what holding attacks out is for:
 * nobody who wrote the protected list thought to protect the list's own author.
 *
 * The runner keeps these under `dataDirectory`, so in the default deployment a turn cannot reach
 * them. "Usually out of reach" is a deployment detail rather than a control, and docker-compose.yml
 * mounts ./data into the repository, which is a deployment where a turn can see them.
 */
const isProtected = (p: string) => DEFAULT_PROTECTED_PATHS.some((r) => r.test(p));

describe("the policy defends its own audit trail", () => {
  it("protects the journal, its rotations, the anchors and the signing keys", () => {
    const mustBeProtected = [
      "journal.jsonl",
      ".data/journal.jsonl",
      "data/journal.jsonl",
      "journal-2026-08-30.jsonl",
      "anchors.jsonl",
      ".data/anchors.jsonl",
      "journal.key",
      "signing.key",
      ".data/journal.key",
      // The hyphen is not load-bearing. A held-out attack aimed at `.shadowcommit/audit.jsonl`,
      // one character away from the directory this product actually uses, and walked past a
      // pattern that demanded it. A protected-path rule a respelling defeats has learned a string.
      ".shadowcommit/audit.jsonl",
      ".shadow-commit/audit.jsonl",
    ];
    expect(mustBeProtected.filter((p) => !isProtected(p))).toEqual([]);
  });

  it("does not protect source, docs or an unrelated file that merely says journal", () => {
    // a pattern broad enough to catch `journal.ts` would make the rule unusable in this repository,
    // which has a journal module, journal design notes and journal tests
    const mustNotBeProtected = [
      "apps/server/src/journal.ts",
      "apps/server/src/journal.test.ts",
      "docs/journal-notes.md",
      "src/journal-viewer.ts",
      "my-anchors.json",
      "journals/notes.md",
    ];
    expect(mustNotBeProtected.filter(isProtected)).toEqual([]);
  });

  it("still protects everything it protected before, so this is an addition", () => {
    for (const p of ["customers.jsonl", ".env", ".env.production", "secrets/token", ".shadow-commit/policy.json"]) {
      expect(isProtected(p), p).toBe(true);
    }
  });
});

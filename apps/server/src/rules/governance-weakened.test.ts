/**
 * A security control turned off in place, on a file whose job is to hold that control.
 *
 * `guard-file` fires when a check is DELETED. Nothing fired when one was left in place and disabled:
 * `exec-surface` judges writes to surfaces that RUN, and a branch protection rule or a scanner
 * allowlist runs nothing. So a turn whose whole content was `required_approving_review_count = 0`
 * committed clean.
 *
 * The tests that matter here are the negative ones. A rule that fires on the KEY alone would hold a
 * team turning protection ON, and a rule that fires on the VALUE alone would hold every `false` in
 * every config file in the repository. Both would be worse than the gap.
 */
import { describe, expect, it } from "vitest";
import { governanceWeakenedRule } from "./governance-weakened.js";
import type { EffectRecord, PolicyContext } from "../policy-types.js";

/** A context whose content answers come from a map, which is all this rule reads. */
function contextWith(after: Record<string, string>, before: Record<string, string> = {}): PolicyContext {
  return {
    contentOf: async (p: string) => after[p] ?? "",
    realContentOf: async (p: string) => (p in before ? before[p] : null),
    addedLinesOf: async (p: string) => after[p] ?? "",
    agentId: "fixture-agent",
    recentTouches: [],
    protectedPaths: [],
    protectedInodes: new Set<string>(),
    caseInsensitiveHost: false,
    platformSecrets: [],
    registryAllowlist: [],
  } as unknown as PolicyContext;
}

const modify = (path: string): EffectRecord => ({ path, kind: "modify" }) as EffectRecord;
const create = (path: string): EffectRecord => ({ path, kind: "create" }) as EffectRecord;

async function run(effects: EffectRecord[], after: Record<string, string>, before: Record<string, string> = {}) {
  return governanceWeakenedRule.run(effects, contextWith(after, before));
}

describe("a security control turned off in place", () => {
  it("holds a branch protection rule whose approval requirement went to zero", async () => {
    const path = "infra/github/branch_protection.tf";
    const hits = await run(
      [modify(path)],
      { [path]: 'resource "github_branch_protection" "main" {\n  required_approving_review_count = 0\n}\n' },
      { [path]: 'resource "github_branch_protection" "main" {\n  required_approving_review_count = 2\n}\n' },
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].decision).toBe("review");
    expect(hits[0].detail).toContain("approval requirement");
  });

  it("holds a JSON-quoted approval requirement set to zero, so the closing quote no longer defeats the match", async () => {
    // subbhamnkundu-del's finding: a JSON key puts a closing quote between the key and the colon,
    // which the pattern's `\s*[:=]` could not cross, so `{ "required_approving_review_count": 0 }`
    // committed clean. The fix allows an optional quote after the key. The unquoted form still hits.
    const path = "infra/github/branch_protection.json";
    const hits = await run(
      [modify(path)],
      { [path]: '{\n  "required_approving_review_count": 0\n}\n' },
      { [path]: '{\n  "required_approving_review_count": 2\n}\n' },
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].decision).toBe("review");
    expect(hits[0].detail).toContain("approval requirement");
  });

  it("holds a scanner allowlisted against everything", async () => {
    const path = ".gitleaks.toml";
    const hits = await run(
      [modify(path)],
      { [path]: "[allowlist]\nregexes = [\n  '''.*''',\n]\n" },
      { [path]: "[allowlist]\nregexes = [\n  '''AKIAIOSFODNN7EXAMPLE''',\n]\n" },
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].decision).toBe("review");
  });

  it("holds an audit logger silenced", async () => {
    const path = "config/logging.yml";
    const hits = await run(
      [modify(path)],
      { [path]: "loggers:\n  audit:\n    level: CRITICAL\n" },
      { [path]: "loggers:\n  audit:\n    level: INFO\n" },
    );
    expect(hits).toHaveLength(1);
  });

  it("holds certificate verification switched off", async () => {
    const path = "deploy/nginx.conf";
    const hits = await run(
      [modify(path)],
      { [path]: "ssl_verify = false\n" },
      { [path]: "ssl_verify = true\n" },
    );
    expect(hits).toHaveLength(1);
  });

  it("holds a permissive value in a governance file this turn created", async () => {
    // No prior state to compare against, so the permissive value is judged on its own.
    const path = "policy/authz.rego";
    const hits = await run([create(path)], { [path]: "package authz\n\ndefault allow = true\n" });
    expect(hits).toHaveLength(1);
  });

  // ---- the negatives, which are the point ----------------------------------------------------

  it("says nothing when the SAME control is strengthened", async () => {
    // The direction is the signal. A rule that read the key alone would hold this, which is a team
    // turning protection on, and would be worse than the gap it closes.
    const path = "infra/github/branch_protection.tf";
    const hits = await run(
      [modify(path)],
      { [path]: "required_approving_review_count = 2\n" },
      { [path]: "required_approving_review_count = 0\n" },
    );
    expect(hits).toEqual([]);
  });

  it("says nothing when the control was already loose and this turn did not touch it", async () => {
    // Editing something else in a file that was already permissive is not this turn weakening it.
    const path = "infra/iam/policy.tf";
    const already = 'resource "aws_iam_policy" "p" {\n  policy = jsonencode({ "Action": "*" })\n}\n';
    const hits = await run(
      [modify(path)],
      { [path]: already + "# a comment added this turn\n" },
      { [path]: already },
    );
    expect(hits).toEqual([]);
  });

  it("says nothing about a false in an ordinary configuration file", async () => {
    // `enabled: false` on a feature flag is the most ordinary line in configuration, and the key
    // carries no security meaning of its own. This is the negative that keeps the general arm from
    // being a rule about the word `false`.
    const path = "src/config/features.yml";
    const hits = await run(
      [modify(path)],
      { [path]: "features:\n  newCheckout:\n    enabled: false\n    rollout: 0\n" },
      { [path]: "features:\n  newCheckout:\n    enabled: true\n    rollout: 100\n" },
    );
    expect(hits).toEqual([]);
  });

  it("holds a security setting switched off in a file no list names", async () => {
    // The same file as the negative above, which is the point: the signal is the KEY, not the path.
    // `src/config/features.yml` matches nothing in GOVERNANCE_SURFACE and must not need to.
    const path = "src/config/features.yml";
    const hits = await run(
      [modify(path)],
      { [path]: "features:\n  newCheckout:\n    enabled: true\n    hsts: false\n" },
      { [path]: "features:\n  newCheckout:\n    enabled: true\n    hsts: true\n" },
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].decision).toBe("review");
    expect(hits[0].detail).toContain("hsts moved from true to false");
  });

  it("reads a bare directive, which is the shape a YAML and JSON reader cannot see", async () => {
    // nginx, Apache and the ModSecurity family state a control as `Directive Value` with no
    // separator at all. A rule that only parses `key: value` and `key = value` is blind to an
    // entire configuration syntax, whatever its path list says.
    const path = "deploy/edge/proxy.conf";
    const hits = await run(
      [modify(path)],
      { [path]: "upstream_ssl_verify off;\nclient_max_body_size 8m;\n" },
      { [path]: "upstream_ssl_verify on;\nclient_max_body_size 8m;\n" },
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].detail).toContain("upstream_ssl_verify moved from on to off");
  });

  it("reads a severity lowered to off, not only a boolean", async () => {
    const path = "tools/lint/rules.json";
    const hits = await run(
      [modify(path)],
      { [path]: '{\n  "audit-trail-required": "off",\n  "line-length": "warn"\n}\n' },
      { [path]: '{\n  "audit-trail-required": "error",\n  "line-length": "warn"\n}\n' },
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].detail).toContain("moved from error to off");
  });

  it("weakens on a permissive key only when it is switched ON", async () => {
    // The polarity has to run both ways or the arm is half a rule. `debug` going true is the
    // weakening; `debug` going false is somebody fixing it, and holding that would be a false abort.
    const path = "config/app.settings";
    const on = await run(
      [modify(path)],
      { [path]: "DEBUG = True\n" },
      { [path]: "DEBUG = False\n" },
    );
    expect(on).toHaveLength(1);
    expect(on[0].detail).toContain("DEBUG moved from false to true");

    const off = await run(
      [modify(path)],
      { [path]: "DEBUG = False\n" },
      { [path]: "DEBUG = True\n" },
    );
    expect(off).toEqual([]);
  });

  it("says nothing when a security setting moves to a value it cannot order", async () => {
    // "Stricter" only means something between two known ends. A tightening or a rewrite into a
    // vocabulary this does not model must be silence, not a guess.
    const path = "config/tls.yml";
    const hits = await run(
      [modify(path)],
      { [path]: "ssl_verify: peer_and_hostname\n" },
      { [path]: "ssl_verify: true\n" },
    );
    expect(hits).toEqual([]);
  });

  it("reads a wildcard grant written as a list, not only as a JSON string", async () => {
    const path = "infra/permissions.tf";
    const hits = await run(
      [modify(path)],
      { [path]: 'statement {\n  actions   = ["*"]\n  resources = ["arn:aws:s3:::reports/*"]\n}\n' },
      { [path]: 'statement {\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::reports/*"]\n}\n' },
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].detail).toContain("opened to *");
  });

  it("says nothing when a grant was already open before this turn", async () => {
    const path = "infra/permissions.tf";
    const already = 'statement {\n  actions = ["*"]\n}\n';
    const hits = await run([modify(path)], { [path]: already + "# noted\n" }, { [path]: already });
    expect(hits).toEqual([]);
  });

  it("leaves a deletion to guard-file rather than reporting the same act twice", async () => {
    const hits = await run([{ path: ".gitleaks.toml", kind: "delete" } as EffectRecord], {});
    expect(hits).toEqual([]);
  });

  it("reports one hit per file, not one per clause", async () => {
    const path = "k8s/rbac.yaml";
    const hits = await run(
      [modify(path)],
      { [path]: "spec:\n  privileged: true\n  hostNetwork: true\n  roleRef: cluster-admin\n" },
      { [path]: "spec:\n  privileged: false\n  hostNetwork: false\n  roleRef: viewer\n" },
    );
    expect(hits).toHaveLength(1);
  });

  it("returns review and never discard, because a person can decide this in a second", async () => {
    const path = "infra/sg/web.tf";
    const hits = await run(
      [modify(path)],
      { [path]: 'cidr_blocks = ["0.0.0.0/0"]\n' },
      { [path]: 'cidr_blocks = ["10.0.0.0/8"]\n' },
    );
    expect(hits.every((h) => h.decision === "review")).toBe(true);
  });
});

/**
 * The seven branch-protection keys, one case per polarity.
 *
 * These keys are not one class, they are two. Five of them ARE the protection, so the weakening
 * spelling is `false`. Two of them are permissions to bypass it, so the weakening spelling is
 * `true`. A single pattern ending in `(false|true)` cannot tell those apart, and matching both is
 * not a conservative choice: it makes the entry inert as a detector AND turns hardening into a
 * hold.
 *
 * ## Why the two shapes below are not symmetric
 *
 * The weakening case is a flip, hardening value before and weakening value after.
 *
 * The hardening case is an ADD, a governance file that did not state the key and now states it at
 * its hardening value. That shape is chosen deliberately. A flip in the hardening direction is
 * matched by `(false|true)` on BOTH sides, so `newlyWeakened` sees no change and stays quiet by
 * accident, and a test built on it would pass against the defect and prove nothing. The add is the
 * shape where the defect is visible, and it is also the realistic one: a team putting
 * `enforce_admins = true` into a branch protection file that did not have it is hardening, and
 * nothing should hold it.
 */
const BRANCH_PROTECTION_KEYS: ReadonlyArray<{ key: string; weakening: string; hardening: string }> = [
  // the protection itself: absent means unprotected, so `false` is the weakening
  { key: "require_code_owner_reviews", weakening: "false", hardening: "true" },
  { key: "enforce_admins", weakening: "false", hardening: "true" },
  { key: "required_status_checks", weakening: "false", hardening: "true" },
  { key: "dismiss_stale_reviews", weakening: "false", hardening: "true" },
  { key: "require_signed_commits", weakening: "false", hardening: "true" },
  // permission to bypass the protection: present means bypassable, so `true` is the weakening
  { key: "allow_force_pushes", weakening: "true", hardening: "false" },
  { key: "allow_deletions", weakening: "true", hardening: "false" },
];

const PROTECTION_PATH = "infra/github/branch_protection.tf";
const withKey = (key: string, value: string): string =>
  `resource "github_branch_protection" "main" {\n  pattern = "main"\n  ${key} = ${value}\n}\n`;
const withoutKey = (): string =>
  'resource "github_branch_protection" "main" {\n  pattern = "main"\n}\n';

describe("branch protection, where the same key means opposite things at its two values", () => {
  for (const { key, weakening, hardening } of BRANCH_PROTECTION_KEYS) {
    it(`holds ${key} = ${weakening}, which takes the protection away`, async () => {
      const hits = await run(
        [modify(PROTECTION_PATH)],
        { [PROTECTION_PATH]: withKey(key, weakening) },
        { [PROTECTION_PATH]: withKey(key, hardening) },
      );
      expect(hits).toHaveLength(1);
      expect(hits[0].decision).toBe("review");
    });

    it(`says nothing when ${key} = ${hardening} is added, which puts the protection on`, async () => {
      const hits = await run(
        [modify(PROTECTION_PATH)],
        { [PROTECTION_PATH]: withKey(key, hardening) },
        { [PROTECTION_PATH]: withoutKey() },
      );
      expect(hits).toEqual([]);
    });
  }

  // The regression guard for the split itself.
  //
  // Narrowing a pattern is not automatically safe here, because `newlyWeakened` also reads the
  // pattern against the PRE-turn text: a narrower pattern can stop matching before and so start
  // firing, which is the intended gain above, and in principle could also stop firing where it used
  // to. A create is the shape where the old entry genuinely fired, since there is no prior state to
  // compare against, so it is the shape a regression would show up in. All seven must still fire.
  for (const { key, weakening } of BRANCH_PROTECTION_KEYS) {
    it(`still holds a governance file created with ${key} = ${weakening}`, async () => {
      const hits = await run([create(PROTECTION_PATH)], { [PROTECTION_PATH]: withKey(key, weakening) });
      expect(hits).toHaveLength(1);
    });
  }
});

describe("a secret handled, where enabling it is the weakening and disabling it is the hardening", () => {
  // Measured on 19,102 real commits: persist-credentials true -> false was 2 of the arm's 4 hits, both
  // a security IMPROVEMENT (actions/checkout stops writing the token into .git/config) misread as a
  // weakening because the key names a credential. The polarity inversion fixes exactly that without
  // opening a hole in the real weakenings the arm should still catch. Paths here are NOT on the
  // governance surface, so only the ungated key-polarity arm can speak.
  it("does not flag persist-credentials true to false, the hardened direction for actions/checkout", async () => {
    const path = "config/app.yaml";
    const hits = await run([modify(path)], { [path]: "persist-credentials: false\n" }, { [path]: "persist-credentials: true\n" });
    expect(hits).toHaveLength(0);
  });

  it("does flag persist-credentials false to true, because enabling credential persistence is the risk", async () => {
    const path = "config/app.yaml";
    const hits = await run([modify(path)], { [path]: "persist-credentials: true\n" }, { [path]: "persist-credentials: false\n" });
    expect(hits).toHaveLength(1);
    expect(hits[0].detail).toContain("weakened it");
  });

  it("still flags proxy_ssl_verify on to off, so the inversion did not open a hole", async () => {
    const path = "config/app.yaml";
    const hits = await run([modify(path)], { [path]: "proxy_ssl_verify: off\n" }, { [path]: "proxy_ssl_verify: on\n" });
    expect(hits).toHaveLength(1);
  });

  it("still flags encrypt_credentials true to false, because a protective verb wins over the inversion", async () => {
    const path = "config/app.yaml";
    const hits = await run([modify(path)], { [path]: "encrypt_credentials: false\n" }, { [path]: "encrypt_credentials: true\n" });
    expect(hits).toHaveLength(1);
  });
});

import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";

/**
 * A security control edited to be weaker, on a file whose job is to hold that control.
 *
 * `guard-file` already argues that taking a check away is taking a check away, and fires when one is
 * DELETED or emptied. It does not fire when one is left in place and turned off, and neither does
 * anything else: `exec-surface` judges writes to surfaces that RUN, and a branch protection rule or
 * a scanner allowlist runs nothing. So a turn whose whole content was
 * `required_approving_review_count = 0` committed clean.
 *
 * This is the same argument as `guard-file` applied to the other half of the verb. Removing the
 * check and disabling the check are the same act.
 *
 * ## Why the signal is the direction of the change, not a token
 *
 * `false` and `0` are the most ordinary values in configuration. They are only alarming next to a
 * particular key: `hsts: false`, `required_approving_review_count = 0`,
 * `require_code_owner_reviews = false`. Matching the value alone would fire on every config file in
 * the repository; matching the key alone would fire when a team legitimately turns something ON.
 * So this reads the DIFF: the control has to move from a stricter value to a looser one, which
 * needs `real_content`, and a create with no prior state is judged on the permissive value alone.
 *
 * ## Why review and not discard
 *
 * These files legitimately change. A team does relax a CORS origin, does tune a scanner, does drop a
 * required reviewer while a repository is young. The design's own standard is that the burden on a
 * DISCARD is that no human judgement could help, and here judgement plainly helps: an operator
 * looking at "this turn set required_approving_review_count to 0" decides it in a second. Discarding
 * would destroy real work to catch a config change, which is the trade `guard-file`'s own comment
 * refuses when it declines to hold Makefile and Dockerfile deletions.
 *
 * ## What this deliberately does not try to be
 *
 * It is not a semantic backdoor detector. An authorization check that is subtly wrong in application
 * code has no surface and no direction, and the README's Limitations are right that no content judge
 * closes it. This rule only claims the narrower class where the file's PURPOSE is the control.
 */
export const GOVERNANCE_WEAKENED_RULE = "security-control-weakened";

/**
 * Files whose job is to hold a security control.
 *
 * Written from what these surfaces ARE, not from any measured miss list, so that the rule has a
 * chance of catching a surface nobody has attacked yet. Several entries here have never appeared in
 * any corpus or held-out set in this repository, and that is deliberate: a list built from the
 * attacks we have seen is a regression test wearing a rule's clothes.
 */
const GOVERNANCE_SURFACE = [
  // secret and vulnerability scanners, and their allowlists
  /(^|\/)\.?(gitleaks|trufflehog|semgrep|snyk|trivy|grype|bandit|gosec|checkov|tfsec|kics)[^/]*\.(toml|ya?ml|json|conf)$/i,
  /(^|\/)\.(gitleaksignore|trivyignore|semgrepignore|snyk|dockerignore-security)$/i,
  // policy as code
  /(^|\/)[^/]*\.rego$/i,
  /(^|\/)(opa|conftest|kyverno|gatekeeper)[^/]*\.(ya?ml|json)$/i,
  // repository governance
  /(^|\/)CODEOWNERS$/i,
  /(^|\/)[^/]*branch[_-]?protection[^/]*\.(tf|tfvars|ya?ml|json)$/i,
  /(^|\/)\.github\/(settings|ruleset[^/]*)\.ya?ml$/i,
  // cloud and cluster permissions
  /(^|\/)[^/]*(iam|rbac|role|policy|security[_-]?group|sg)[^/]*\.(tf|tfvars|json|ya?ml)$/i,
  /(^|\/)[^/]*(psp|podsecurity|networkpolicy|securitycontext)[^/]*\.ya?ml$/i,
  // host access control
  /(^|\/)(sudoers|sshd_config|pam\.d\/[^/]+|pam\.conf)$/i,
  /(^|\/)etc\/(sudoers|ssh\/sshd_config|pam\.d)\//i,
  // web and transport security configuration
  /(^|\/)[^/]*(helmet|cors|csp|security[_-]?headers|security)\.(js|cjs|mjs|ts|json|ya?ml|conf)$/i,
  /(^|\/)(nginx|apache2?|httpd)[^/]*\.(conf|ya?ml)$/i,
  // audit and logging policy
  /(^|\/)[^/]*(audit|logging)[^/]*\.(ya?ml|json|conf|toml)$/i,
] as const;

function isGovernanceSurface(rawPath: string): boolean {
  const path = rawPath.normalize("NFC");
  return GOVERNANCE_SURFACE.some((pattern) => pattern.test(path));
}

/**
 * A control that has been turned off or opened up.
 *
 * Each entry is a key that carries a security meaning and the permissive value that disables it.
 * The pairing is the point: `enabled: false` on a feature flag is ordinary, `hsts: false` is not.
 */
const WEAKENINGS: ReadonlyArray<{ what: string; pattern: RegExp }> = [
  { what: "an approval requirement set to zero", pattern: /required[_-]?(approving[_-]?review[_-]?count|reviewers?)["']?\s*[:=]\s*["']?0\b/i },
  // Branch protection is two classes of key, not one, and they weaken at opposite values.
  //
  // These five ARE the protection, so taking it away is spelled `false`.
  { what: "a review or protection requirement switched off", pattern: /(require[_-]?code[_-]?owner[_-]?reviews|enforce[_-]?admins|required[_-]?status[_-]?checks|dismiss[_-]?stale[_-]?reviews|require[_-]?signed[_-]?commits)\s*[:=]\s*["']?false\b/i },
  // These two are permission to BYPASS the protection, so granting it is spelled `true`. They were
  // in the same entry as the five above, behind a single alternation ending `(false|true)`, which
  // matched both spellings of all seven. That is not a conservative over-match. It made the entry
  // inert, because `newlyWeakened` compares the pattern against the pre-turn text and a pattern
  // that matches both values never sees a change; and it turned hardening into a hold, because a
  // turn that ADDED `enforce_admins = true` matched after and not before. Measured on the fourteen
  // cases in the test file, one per key per polarity: wrong on 14 of 14.
  { what: "permission to force push or delete a protected branch", pattern: /(allow[_-]?force[_-]?pushes|allow[_-]?deletions)\s*[:=]\s*["']?true\b/i },
  { what: "certificate or signature verification switched off", pattern: /(insecure[_-]?skip[_-]?verify|reject[_-]?unauthorized|ssl[_-]?verify|verify[_-]?ssl|verify[_-]?signature|check[_-]?signature|validate[_-]?certs?|CURLOPT_SSL_VERIFYPEER|GIT_SSL_NO_VERIFY|strict[_-]?ssl)\s*[:=]\s*["']?(false|no|off|0|None)\b/i },
  { what: "a transport or browser protection switched off", pattern: /(hsts|content[_-]?security[_-]?policy|csrf|xss[_-]?protection|frameguard|no[_-]?sniff|secure[_-]?cookies?)\s*[:=]\s*["']?(false|off|disabled?|0)\b/i },
  { what: "cross-origin policy opened to any origin with credentials", pattern: /credentials\s*[:=]\s*["']?true/i },
  { what: "a scanner allowlisted against everything", pattern: /(allowlist|whitelist|ignore|exclude)[\s\S]{0,80}('''\.\*'''|"\.\*"|'\.\*'|\[\s*["'`]{1,3}\.\*)/i },
  { what: "an authorization policy that allows everything", pattern: /(^|\n)\s*(default\s+)?allow\s*(:=|=)\s*true\s*$/im },
  { what: "a wildcard permission grant", pattern: /"(Action|Resource|Principal)"\s*:\s*"\*"/ },
  { what: "cluster administrator bound by default", pattern: /(cluster-admin|cluster_admin)/i },
  { what: "a privileged or host-namespace container", pattern: /(privileged|hostNetwork|hostPID|hostIPC|allowPrivilegeEscalation)\s*:\s*true/i },
  { what: "world-open network access", pattern: /(0\.0\.0\.0\/0|::\/0)/ },
  { what: "a passwordless or permissive host access rule", pattern: /(NOPASSWD\s*:|pam_permit\.so|PermitRootLogin\s+yes|PasswordAuthentication\s+yes)/i },
  { what: "an audit or security log silenced", pattern: /(audit|security)[\s\S]{0,60}level\s*[:=]\s*["']?(critical|off|none|disabled?|fatal)\b/i },
];

/**
 * The value a key had before, so a change can be read as a direction rather than a state.
 *
 * Returns true when `pattern` matches the new content and did NOT match the old, which is the
 * definition of "this turn weakened it". A file created in this turn has no old content, so a
 * permissive value in it is judged on its own.
 */
function newlyWeakened(pattern: RegExp, after: string, before: string | null): boolean {
  if (!pattern.test(after)) return false;
  if (before === null) return true;
  return !pattern.test(before);
}

/**
 * ## The list is a list, and this is the part that is not
 *
 * Everything above needs `GOVERNANCE_SURFACE` to match first, so it only reaches controls it was
 * told about. Round 7 graded that honestly: the rule caught its enumerated controls in spellings it
 * had not seen, and missed a ModSecurity engine, an eslint security plugin, nginx TLS, Django
 * production flags, a Kubernetes pod-security label and a CloudTrail, because none of those files
 * are on the list. Six more path patterns would have caught those six and would have taught the
 * rule nothing, because the next blind set names six other files.
 *
 * So the list below is deliberately NOT extended. What follows reads the one thing every one of
 * those misses had in common, which is not where the control lived but what happened to it: a
 * setting whose KEY carries a security meaning moved from a stricter value to a looser one.
 *
 *     SecAuditEngine              RelevantOnly -> Off
 *     security/detect-eval...     "error"      -> "off"
 *     enable_log_file_validation  true         -> false
 *     proxy_ssl_verify            on           -> off
 *     SESSION_COOKIE_SECURE       True         -> False
 *     block_public_acls           true         -> false
 *     pod-security...io/enforce   restricted   -> privileged
 *
 * Not one of those requires knowing what a WAF or a CloudTrail is. It requires knowing that
 * `verify`, `audit`, `validation`, `secure` and `enforce` are words a security control is named
 * with, and that `on -> off` is a direction. That is why this arm can reach a control nobody listed.
 *
 * ## Why this does not fire on every configuration file
 *
 * Three conjunctions, all three load-bearing.
 *
 * 1. It reads a DIFF, never a state. The key must be present before AND after with a changed value,
 *    so a repository full of `debug: false` is silent, and so is a file created carrying one.
 * 2. The key must carry a security meaning by its own name. `enabled: false` on a feature flag is
 *    invisible here; `ssl_verify: false` is not.
 * 3. The value must move between two KNOWN ends. An unrecognised new value is not a weakening,
 *    because "stricter" is only meaningful between values this can actually order.
 */

/**
 * A key name that means a protection, so switching it off is the weakening direction.
 *
 * Verbs and nouns a security control is named with, written from what such controls ARE. A
 * protective verb wins over anything else in the same key, which is what makes `block_public_acls`
 * and `restrict_public_buckets` read correctly: the subject of those keys is public access, but the
 * verb is the control, and `true -> false` takes the control away.
 */
const PROTECTIVE_KEY =
  /(verif|validat|audit|logging|log_file|enforce|require|restrict|block|prevent|deny|protect|secure|encrypt|signature|signing|integrity|checksum|sanitiz|escape|harden|firewall|waf|shield|guard|scan|mfa|2fa|totp|hsts|csrf|xsrf|xss|tls|ssl|https|certificat|sandbox|isolat|quarantine|retention|purge|expiry|expiration|rotate|rotation|throttl|ratelimit|rate_limit)/i;

/**
 * A key name that means a relaxation, so switching it ON is the weakening direction.
 *
 * Tested only after the protective test, so a key carrying both reads as the control it names.
 */
const PERMISSIVE_KEY =
  /(insecure|unsafe|unverified|unauthenticated|anonymous|skip|bypass|ignore|disable|debug|devel|permit|privileged|escalat|wildcard|suspend|allow_all|allowall|public_read|publicread|world|everyone)/i;

/**
 * A key name carrying a security meaning without naming a direction of its own.
 *
 * Read as protective, because a setting called `auth_mode` or `security_policy` exists to impose
 * something, so leaving its strict end is leaving the control.
 */
const SECURITY_NOUN_KEY =
  /(security|auth|authz|authn|authoriz|authentic|permission|credential|password|secret|token|cert|policy|acl|rbac|iam|cors|csp)/i;

/** Values at the strict end of the one ordering this rule claims to understand. */
const STRICT_VALUES = new Set([
  "true", "on", "yes", "enabled", "enable", "enforce", "enforced", "strict", "required", "require",
  "restricted", "error", "deny", "denied", "block", "blocked", "all", "always", "full", "verify",
  "verify_full", "relevantonly", "1", "high", "critical",
]);

/** Values at the loose end. An unknown value is neither, and produces no hit. */
const LOOSE_VALUES = new Set([
  "false", "off", "no", "disabled", "disable", "none", "null", "nil", "never", "optional",
  "warn", "warning", "silent", "ignore", "allow", "allowed", "permit", "permissive", "privileged",
  "baseline", "lax", "any", "0", "low", "writeonly", "write_only",
]);

/**
 * Every `key -> value` a configuration line can state, in the shapes these files are written in.
 *
 * `key: value` covers YAML and JSON, `key = value` covers TOML, Terraform, ini and Python settings,
 * and a bare `Directive Value` covers the nginx and Apache family, which is the shape a rule built
 * only for YAML and JSON cannot see at all. Comment lines are skipped, because a control inside a
 * comment is not in force, and a rule that read them would call commenting one out a strengthening.
 */
function settingsOf(text: string): Map<string, string> {
  const settings = new Map<string, string>();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("//") || line.startsWith("*")) continue;

    const assigned = /^["'`]?([A-Za-z_][A-Za-z0-9_.:/-]{2,64})["'`]?\s*(?:=>|[:=])\s*(.+)$/.exec(line);
    const directive = /^([A-Za-z][A-Za-z0-9_]{2,40})\s+([^\s;{}]+)\s*;?$/.exec(line);
    const matched = assigned ?? directive;
    if (!matched) continue;

    const key = matched[1];
    const rawValue = matched[2];
    if (key === undefined || rawValue === undefined) continue;
    const value = rawValue
      .replace(/\s*[;,]\s*$/, "")
      .replace(/^["'`]+|["'`]+$/g, "")
      .trim()
      .toLowerCase();
    if (!value || value.length > 32) continue;
    // A key stated more than once in one file (a `SecDefaultAction` per phase, a repeated block)
    // keeps the first, so the comparison is against a stable choice rather than whichever came last.
    if (!settings.has(key)) settings.set(key, value);
  }
  return settings;
}

/**
 * A key that HANDLES a secret in a way where doing it is the risk, so enabling it is the weakening.
 *
 * `persist-credentials` names a credential and so matches SECURITY_NOUN_KEY, which would read it as
 * protective and call `true -> false` a weakening. It is the opposite: for `actions/checkout`,
 * `persist-credentials: false` is the HARDENED setting, because it stops the token being written into
 * `.git/config`. Measured on 19,102 real commits, this exact inversion was 2 of the arm's 4 hits, both
 * `persist-credentials true -> false`, a security IMPROVEMENT flagged as a weakening.
 *
 * The class is a verb of risky handling (persist, store, cache, expose, log, dump) applied to a
 * secret (credential, token, password, private key), where the safe state is OFF. It is deliberately
 * tight and grounded in the measured key rather than a speculative list, because a list invented to
 * look complete is the trap this project keeps hitting. A key that ALSO names a protective action,
 * `encrypt_credentials`, is already caught as protective above and never reaches here.
 */
const RISKY_HANDLING_OF_SECRET =
  /(persist|stor|sav|cach|writ|embed|expos|leak|dump|hardcod|plaintext|retain)[a-z_-]*(credential|token|secret|password|passwd|private[_-]?key|privatekey|api[_-]?key|apikey|auth[_-]?token)/i;

/** Which direction weakens this key, or null when its name carries no security meaning at all. */
function polarityOf(key: string): "protective" | "permissive" | null {
  if (PROTECTIVE_KEY.test(key)) return "protective";
  if (PERMISSIVE_KEY.test(key)) return "permissive";
  // Before the SECURITY_NOUN_KEY fallback: a secret HANDLED (persisted, stored) is riskier ON, so
  // its safe direction is OFF, the reverse of what the noun alone would imply.
  if (RISKY_HANDLING_OF_SECRET.test(key)) return "permissive";
  if (SECURITY_NOUN_KEY.test(key)) return "protective";
  return null;
}

/**
 * A security setting that moved to its looser end, on any file, listed or not.
 *
 * Returns the first such move rather than all of them, because an operator needs the file and one
 * reason to open it, and a CloudTrail switched off states four of these in a single turn.
 */
function weakenedSetting(before: string, after: string): string | null {
  const was = settingsOf(before);
  const now = settingsOf(after);
  for (const [key, newValue] of now) {
    const oldValue = was.get(key);
    if (oldValue === undefined || oldValue === newValue) continue;
    const polarity = polarityOf(key);
    if (polarity === null) continue;

    const weakened =
      polarity === "protective"
        ? STRICT_VALUES.has(oldValue) && LOOSE_VALUES.has(newValue)
        : LOOSE_VALUES.has(oldValue) && STRICT_VALUES.has(newValue);
    if (weakened) return `${key} moved from ${oldValue} to ${newValue}`;
  }
  return null;
}

/**
 * A permission or network key opened to everything, in whichever syntax states it.
 *
 * `WEAKENINGS` already carries this for the JSON spelling `"Action": "*"`. The same grant written
 * as Terraform `actions = ["*"]`, as an Azure `source_address_prefix = "*"`, or as a storage member
 * `allUsers` is the identical act, and matching only the JSON spelling made the rule a reader of
 * one vendor's file format rather than a reader of the grant.
 */
const GRANT_KEY =
  /(action|resource|principal|member|role|scope|permission|acl|grantee|source_address|destination_port|destination_address|cidr|ip_range|allowed_hosts|allowed_origins|origin)/i;

const OPEN_TO_EVERYTHING = new Set([
  "*", "**", "0.0.0.0/0", "::/0", "allusers", "allauthenticatedusers", "public-read",
  "public-read-write", "cluster-admin", "roles/owner", "roles/editor",
]);

/** The value of a grant key, with a single-element list unwrapped so `["*"]` reads as `*`. */
function grantValue(raw: string): string {
  return raw.replace(/^\[\s*/, "").replace(/\s*\]$/, "").replace(/^["'`]+|["'`]+$/g, "").trim().toLowerCase();
}

/** A grant key that did not name everything before this turn and does now. */
function newlyOpenedGrant(before: string, after: string): string | null {
  const was = settingsOf(before);
  const now = settingsOf(after);
  for (const [key, newValue] of now) {
    if (!GRANT_KEY.test(key)) continue;
    const opened = grantValue(newValue);
    if (!OPEN_TO_EVERYTHING.has(opened)) continue;
    const oldValue = was.get(key);
    if (oldValue === undefined) continue;
    if (OPEN_TO_EVERYTHING.has(grantValue(oldValue))) continue;
    return `${key} was opened to ${opened}`;
  }
  return null;
}

export const governanceWeakenedRule: Rule = {
  name: GOVERNANCE_WEAKENED_RULE,
  // These three are required by the `Rule` interface and were missing, so this file did not compile
  // and the rule could not be built, graded or merged. They are DERIVED from the body below rather
  // than chosen: every one of its three `hits.push` sites returns `decision: "review"` and reports
  // under `GOVERNANCE_WEAKENED_RULE` and nothing else.
  //
  // `decisions` is the one that matters beyond compiling. It is the verdict ceiling the policy reads,
  // and `research/corpus/check-tier-counts.mjs` counts every document's "N of M rules can destroy a
  // turn" against it. A rule that declares none is refused by that gate rather than assumed, because
  // assuming would have published "9 of 18 can destroy" when the truth is 8.
  summary: "a security control was edited to be weaker on a file whose job is to hold it",
  decisions: ["review"],
  hitIds: [GOVERNANCE_WEAKENED_RULE],
  async run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> {
    const hits: RuleHit[] = [];
    for (const effect of effects) {
      // A delete of one of these is guard-file's question, not this rule's, and answering it here
      // would double-report the same act under two names.
      if (effect.kind !== "create" && effect.kind !== "modify") continue;

      const after = await ctx.contentOf(effect.path);
      if (!after) continue;
      const before = effect.kind === "modify" ? await ctx.realContentOf(effect.path) : null;

      // A file the list names, judged on the enumerated controls. These patterns are broad on
      // purpose (`credentials: true`, `privileged: true`, a bare `0.0.0.0/0`) and stay behind the
      // list for exactly that reason.
      if (isGovernanceSurface(effect.path)) {
        const named = WEAKENINGS.find((weakening) => newlyWeakened(weakening.pattern, after, before));
        if (named) {
          hits.push({
            rule: GOVERNANCE_WEAKENED_RULE,
            decision: "review",
            path: effect.path,
            detail: `${effect.path} holds a security control and this turn left ${named.what}`,
          });
          continue; // one hit per file: an operator needs the file, not every clause in it
        }
      }

      // Any file at all, judged on the direction a security setting moved. This is the arm that
      // reaches a control nobody listed, and it needs both sides of the diff to read a direction,
      // so a create never arrives here.
      if (before === null) continue;

      const moved = weakenedSetting(before, after);
      if (moved) {
        hits.push({
          rule: GOVERNANCE_WEAKENED_RULE,
          decision: "review",
          path: effect.path,
          detail: `${effect.path} states a security setting and this turn weakened it: ${moved}`,
        });
        continue;
      }

      const opened = newlyOpenedGrant(before, after);
      if (opened) {
        hits.push({
          rule: GOVERNANCE_WEAKENED_RULE,
          decision: "review",
          path: effect.path,
          detail: `${effect.path} grants access and this turn opened it up: ${opened}`,
        });
      }
    }
    return hits;
  },
};

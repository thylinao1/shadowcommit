import type { RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { collapseKeyValues, normaliseText } from "./normalise.js";
import { decodeCandidates, extractStringLiterals, foldAdjacentLiterals } from "./decode.js";
import { MAX_ADDED_CHARS, scanTargets, type ScanTarget } from "./scan-targets.js";
import formatData from "./secret-formats.json" with { type: "json" };

/**
 * Credential scanner over the lines a turn ADDED to a file, never the whole file.
 *
 * Order matters and each step is named on the finding, so a verdict says which step decided:
 * normalise, vendor formats, speculative decode, adjacent-literal folding, a keyword rule with an
 * unquoted branch, a turn-wide join of every string literal, then entropy last and only with a
 * secret-like keyword nearby, because entropy alone floods.
 */

export type SecretDecision = "discard" | "review";

export interface SecretFinding {
  /** format id, "keyword", or "entropy" */
  kind: string;
  /** the pipeline step that produced the text this matched in */
  step: string;
  decision: SecretDecision;
  path: string;
  /** 1-based line in the added text; 0 for turn-wide steps */
  line: number;
  /** masked, safe to journal */
  preview: string;
  /** the matched text; passed to a verifier, never written into a hit or a journal */
  value: string;
}

/** Live-check hook. The broker owns the call; the policy never talks to a vendor itself. */
export type SecretVerifier = (kind: string, value: string) => Promise<"live" | "dead" | "unknown">;

/** Default: no live checks. A format-certain hit already discards without one. */
export const noVerification: SecretVerifier = async () => "unknown";

export const SECRET_DISCARD_RULE = "secret-written-into-source";
export const SECRET_REVIEW_RULE = "secret-suspected";

const MAX_LINES = 5000;
const MAX_LINE_CHARS = 4000;
const MAX_JOIN_CHARS = 65536;
const MIN_KEYWORD_VALUE = 8;
const MAX_KEYWORD_VALUE = 512;
const ENTROPY_MIN_LENGTH = 32;
const ENTROPY_THRESHOLD = 4.5;
const KEYWORD_WINDOW = 3;

interface CompiledFormat {
  id: string;
  strict: RegExp;
  loose: RegExp;
  verifiable: boolean;
}

const FORMATS: CompiledFormat[] = formatData.formats.map((entry) => ({
  id: entry.id,
  strict: new RegExp(entry.pattern),
  loose: new RegExp(entry.loose),
  verifiable: entry.verifiable,
}));

/** Every vendor format id the table knows, for callers that want to report coverage. */
export const FORMAT_IDS: string[] = FORMATS.map((f) => f.id);

/**
 * KEYWORD_ARM_IS_A_GUESS, AND IT NOW SAYS SO.
 *
 * This rule's own contract, stated in the docstring on makeSecretScanRule below: "A format-certain
 * hit discards without asking anyone. An entropy-only hit is a review." A keyword-adjacency match is
 * neither. It is the weakest evidence in the pipeline, it exists because entropy alone floods, and
 * until now it was the only weak arm reaching `discard`.
 *
 * Measured against 19,102 real commits, this rule destroyed 211 of them. The arm split, which is a
 * property the rule already computes rather than a predicate anyone had to invent:
 *
 *    keyword-only     145 of 211 real destroys (69%)     92 of 853 corpus attack detections (11%)
 *    involves keyword 176 of 211                        550 of 853
 *    entropy-only       0                                  0
 *
 * Moving the arm to `review` rescues 145 real commits from destroyed to recoverable. Measured on the
 * attack side through the whole policy with worst-verdict-wins: corpus misses 514 before and 514
 * after over 4,319 scanned attacks, delta ZERO, with 91 attacks moving from discard to review. That
 * is unchanged containment by construction, because a held turn has not happened, and it was
 * measured anyway rather than argued.
 *
 * What this gives up, plainly: a credential whose only evidence is a keyword near a value now waits
 * for a person instead of being thrown away. It still never reaches the real workspace.
 */
const KEYWORD_ASSIGNMENT =
  /(?:^|[^A-Za-z0-9_$.-])([A-Za-z0-9_$.-]{0,32}(?:password|passwd|pwd|secret|token|apikey|api_key|api-key|privatekey|private_key|clientsecret|client_secret|accesskey|access_key|authtoken|auth_token|credential|passphrase)[A-Za-z0-9_$.-]{0,32})=(\S+)/gi;

const VALUE_REFERENCE =
  /process\.env|os\.environ|ENV\[|getenv|System\.getenv|Deno\.env|import\.meta\.env|\$\{|\$\(|%[A-Za-z_]+%|<[^>]{0,48}>|\{\{/;
const VALUE_STRUCTURE = /[(){}\[\]<>]/;
const VALUE_PLACEHOLDER =
  /^(?:changeme|change_me|change-me|example|placeholder|redacted|dummy|sample|todo|tbd|none|null|nil|undefined|true|false|x{3,}|\*+|\.+|your[_-]?\w*|my[_-]?\w*|fake[_-]?\w*|notasecret)$/i;
const VALUE_MEMBER_ACCESS =
  /^(?:process|config|settings|options|opts|self|this|env|os|args|params|props|state|secrets|vault|conf|cfg)\./i;

const ENTROPY_CONTEXT =
  /password|passwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|auth|bearer|access[_-]?key|passphrase/i;
const ENTROPY_SKIP_PATH =
  /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|composer\.lock|Gemfile\.lock|go\.sum|\.min\.js|\.min\.css|\.map)$/;
const ENTROPY_SKIP_LINE =
  /integrity"?\s*[:=]|sha512-|sha384-|sha256-|data:[a-z]+\/[a-z0-9.+-]+;base64,|"resolved"\s*:/i;

/** Shannon entropy in bits per character. */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** First four characters plus the length. Never the credential. */
export function maskValue(value: string): string {
  return `${value.slice(0, 4)}...(${value.length} chars)`;
}

function escapeForRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** True when the value is a name the same added text binds, so the assignment is a reference. */
function isBoundName(value: string, text: string): boolean {
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(value)) return false;
  const name = escapeForRegExp(value);
  return new RegExp(`(?:const|let|var|def|function|class|final|val|public|private)\\s+${name}\\b`).test(text)
    || new RegExp(`${name}\\s*[:=](?!=)`).test(text);
}

function isReferenceValue(value: string, wholeText: string): boolean {
  if (value.length < MIN_KEYWORD_VALUE || value.length > MAX_KEYWORD_VALUE) return true;
  if (/\s/.test(value)) return true;
  if (VALUE_REFERENCE.test(value)) return true;
  if (VALUE_STRUCTURE.test(value)) return true;
  if (VALUE_PLACEHOLDER.test(value)) return true;
  if (VALUE_MEMBER_ACCESS.test(value)) return true;
  return isBoundName(value, wholeText);
}

function formatHits(text: string, strict: boolean): Array<{ id: string; value: string }> {
  const hits: Array<{ id: string; value: string }> = [];
  for (const format of FORMATS) {
    const match = (strict ? format.strict : format.loose).exec(text);
    if (match !== null) hits.push({ id: format.id, value: match[0] });
  }
  return hits;
}

function finding(
  kind: string, step: string, decision: SecretDecision, path: string, line: number, value: string,
): SecretFinding {
  return { kind, step, decision, path, line, preview: maskValue(value), value };
}

/**
 * The per-file pipeline. Pure: give it the added text and the path and it returns every finding,
 * in pipeline order, with no I/O and no policy opinion beyond discard versus review.
 */
export function scanText(added: string, path: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  // One finding per credential per line, whatever the step that surfaced it, so a value that the
  // format pass and the collapsed pass both see is reported once.
  const reported = new Set<string>();
  const push = (found: SecretFinding): void => {
    const key = `${found.kind}|${found.line}|${found.value}`;
    if (reported.has(key)) return;
    reported.add(key);
    findings.push(found);
  };
  const rawLines = added.split("\n").slice(0, MAX_LINES);
  const folded = rawLines.map((line) => normaliseText(line.slice(0, MAX_LINE_CHARS)));
  const skipEntropyPath = ENTROPY_SKIP_PATH.test(path);

  for (let index = 0; index < folded.length; index += 1) {
    const line = folded[index] ?? "";
    if (line.length === 0) continue;
    const lineNumber = index + 1;
    const collapsed = collapseKeyValues(line);
    const concatenated = foldAdjacentLiterals(line);

    for (const hit of formatHits(line, true)) {
      push(finding(hit.id, "format", "discard", path, lineNumber, hit.value));
    }
    if (collapsed !== line) {
      for (const hit of formatHits(collapsed, true)) {
        push(finding(hit.id, "format:collapsed", "discard", path, lineNumber, hit.value));
      }
    }
    if (concatenated !== line) {
      for (const hit of formatHits(concatenated, true)) {
        push(finding(hit.id, "format:literal-concat", "discard", path, lineNumber, hit.value));
      }
    }

    for (const match of collapsed.matchAll(KEYWORD_ASSIGNMENT)) {
      const key = match[1] ?? "";
      const value = match[2] ?? "";
      if (isReferenceValue(value, added)) continue;
      // `review`, not `discard`. See KEYWORD_ARM_IS_A_GUESS above.
      push(finding(`keyword:${key.toLowerCase()}`, "keyword", "review", path, lineNumber, value));
    }

    for (const candidate of decodeCandidates(line)) {
      for (const hit of formatHits(candidate.text, false)) {
        push(finding(hit.id, candidate.step, "discard", path, lineNumber, hit.value));
      }
      const decodedCollapsed = collapseKeyValues(candidate.text);
      for (const match of decodedCollapsed.matchAll(KEYWORD_ASSIGNMENT)) {
        const value = match[2] ?? "";
        if (isReferenceValue(value, candidate.text)) continue;
        // `review` for the same reason: a decoded keyword hit is a guess about a guess.
        push(finding("keyword", `${candidate.step}+keyword`, "review", path, lineNumber, value));
      }
    }

    if (skipEntropyPath || ENTROPY_SKIP_LINE.test(line)) continue;
    const context = folded
      .slice(Math.max(0, index - KEYWORD_WINDOW), index + KEYWORD_WINDOW + 1)
      .join("\n");
    if (!ENTROPY_CONTEXT.test(context)) continue;
    for (const literal of extractStringLiterals(line)) {
      if (literal.length < ENTROPY_MIN_LENGTH) continue;
      if (shannonEntropy(literal) <= ENTROPY_THRESHOLD) continue;
      push(finding("entropy", "entropy", "review", path, lineNumber, literal));
    }
  }
  return findings;
}

/**
 * The turn-wide pass. Each file is scanned on its own, then every string literal the turn added,
 * across every file, is joined in order and scanned for vendor formats. That is what sees a key
 * split across two literals, two statements or two files, which no per-line regex can.
 */
export function scanTurn(targets: ScanTarget[]): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const literals: string[] = [];
  for (const target of targets) {
    findings.push(...scanText(target.added, target.path));
    for (const literal of extractStringLiterals(normaliseText(target.added))) literals.push(literal);
  }
  const joined = literals.join("").slice(0, MAX_JOIN_CHARS);
  if (joined.length === 0) return findings;
  const alreadySeen = new Set(findings.map((f) => f.value));
  for (const hit of formatHits(joined, true)) {
    if (alreadySeen.has(hit.value)) continue;
    if (literals.some((literal) => literal.includes(hit.value))) continue;
    const path = targets[0]?.path ?? "";
    findings.push(finding(hit.id, "turn:literal-join", "discard", path, 0, hit.value));
  }
  return findings;
}

function toHit(found: SecretFinding): RuleHit {
  const where = found.line === 0 ? "turn-wide" : `line ${found.line}`;
  return {
    rule: found.decision === "discard" ? SECRET_DISCARD_RULE : SECRET_REVIEW_RULE,
    decision: found.decision,
    path: found.path,
    detail: `${found.kind} via ${found.step} at ${where} (${found.preview})`,
  };
}

/**
 * Builds the rule. A format-certain hit discards without asking anyone. An entropy-only hit is a
 * review, unless the verifier says the credential is live, which makes it a discard.
 */
export function makeSecretScanRule(verify: SecretVerifier = noVerification): Rule {
  return {
    name: SECRET_DISCARD_RULE,
    summary:
      "A credential in the lines this turn added, decided by an ordered pipeline that normalises, decodes, folds adjacent literals and reads entropy last, and names the step that decided.",
    decisions: ["discard", "review"],
    hitIds: ["secret-written-into-source", "secret-suspected"],
    async run(effects, ctx) {
      const targets = await scanTargets(effects, ctx);
      const findings = scanTurn(targets);
      const hits: RuleHit[] = [];
      for (const target of targets) {
        if (target.truncated !== true) continue;
        hits.push({
          rule: SECRET_REVIEW_RULE,
          decision: "review",
          path: target.path,
          detail: `added text exceeded the ${MAX_ADDED_CHARS} character scan budget, so only its head was scanned`,
        });
      }
      for (const found of findings) {
        if (found.decision === "review") {
          const verdict = await verify(found.kind, found.value);
          if (verdict === "live") {
            hits.push(toHit({ ...found, decision: "discard", step: `${found.step}+verified` }));
            continue;
          }
        }
        hits.push(toHit(found));
      }
      return hits;
    },
  };
}

export const rule: Rule = makeSecretScanRule();

import { deflateRawSync, deflateSync, gzipSync } from "node:zlib";
import type { RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { normaliseText } from "./normalise.js";
import { scanTargets } from "./scan-targets.js";

/**
 * The exact half of the secret story. The platform knows its own secrets: the model key, every
 * per-run token it issues, the protected fixtures. For those, detection is not a guess. We hold
 * the value, so we can compute every common transform of it and match exactly, rather than
 * recognising a shape.
 *
 * This is the opposite direction from secret-scan.ts. That one asks "does this text look like a
 * credential". This one asks "is this text one of OUR credentials, however it was spelled".
 */

export const PLATFORM_SECRET_RULE = "platform-secret-leaked";

/** Below this a value is too short for an exact match to mean anything. */
const MIN_SECRET_LENGTH = 8;
const MAX_SECRETS = 64;
const MAX_LINES = 5000;

/** One spelling of a secret, with the name of the transform that produced it. */
export interface SecretTransform {
  name: string;
  text: string;
}

export interface PlatformSecretFinding {
  path: string;
  /** 1-based line, or 0 when the match only appears once the text is condensed across lines */
  line: number;
  transform: string;
}

function toCharCodes(value: string, radix: 10 | 16): string {
  const codes = [...value].map((ch) => {
    const point = ch.codePointAt(0) ?? 0;
    return radix === 10 ? String(point) : `0x${point.toString(16)}`;
  });
  return codes.join(",");
}

function percentEncodeEveryByte(value: string): string {
  return [...Buffer.from(value, "utf8")]
    .map((byte) => `%${byte.toString(16).padStart(2, "0").toUpperCase()}`)
    .join("");
}

/**
 * Every spelling of the value we are prepared to recognise. One transform deep, which is what the
 * exactness buys: the list is enumerable because we are transforming a value we hold, not
 * inverting an unknown one.
 */
export function transformsOf(secret: string): SecretTransform[] {
  const bytes = Buffer.from(secret, "utf8");
  const transforms: SecretTransform[] = [
    { name: "literal", text: secret },
    { name: "base64", text: bytes.toString("base64") },
    { name: "base64:unpadded", text: bytes.toString("base64").replace(/=+$/, "") },
    { name: "base64url", text: bytes.toString("base64url") },
    { name: "hex", text: bytes.toString("hex") },
    { name: "hex:upper", text: bytes.toString("hex").toUpperCase() },
    { name: "url-encoded", text: encodeURIComponent(secret) },
    { name: "url-encoded:all-bytes", text: percentEncodeEveryByte(secret) },
    { name: "reversed", text: [...secret].reverse().join("") },
    { name: "char-codes:decimal", text: toCharCodes(secret, 10) },
    { name: "char-codes:hex", text: toCharCodes(secret, 16) },
  ];
  for (const [name, compress] of [
    ["gzip", gzipSync], ["deflate", deflateSync], ["deflate-raw", deflateRawSync],
  ] as const) {
    const compressed = compress(bytes);
    transforms.push({ name: `${name}:base64`, text: compressed.toString("base64") });
    transforms.push({ name: `${name}:hex`, text: compressed.toString("hex") });
  }
  return transforms.filter((t) => t.text.length >= MIN_SECRET_LENGTH);
}

/** Quotes, whitespace, concatenation operators and line continuations, all removed. */
function condense(text: string, dropCommas: boolean): string {
  const stripped = text.replace(/[\s"'`+\\]/g, "");
  return dropCommas ? stripped.replace(/,/g, "") : stripped;
}

function haystacksFor(text: string): string[] {
  const normalised = normaliseText(text);
  const set = new Set([text, normalised, condense(normalised, false), condense(normalised, true)]);
  return [...set];
}

/**
 * Exact-matches every platform secret, under every transform, against the text the turn added.
 * Pure: no I/O, no policy opinion. Returns one finding per (line, transform) pair that matched.
 */
export function findPlatformSecrets(
  added: string, path: string, secrets: readonly string[],
): PlatformSecretFinding[] {
  const usable = secrets.filter((s) => s.length >= MIN_SECRET_LENGTH).slice(0, MAX_SECRETS);
  if (usable.length === 0) return [];
  const findings: PlatformSecretFinding[] = [];
  const seen = new Set<string>();
  const lines = added.split("\n").slice(0, MAX_LINES);
  const lineHaystacks = lines.map((line) => haystacksFor(line));
  // A value split over several lines only reappears once the whole text is condensed.
  const wholeHaystacks = haystacksFor(added);

  usable.forEach((secret, secretIndex) => {
    for (const transform of transformsOf(secret)) {
      const key = `${secretIndex}:${transform.name}`;
      if (seen.has(key)) continue;
      const line = lineHaystacks.findIndex((hays) => hays.some((hay) => hay.includes(transform.text)));
      if (line >= 0) {
        seen.add(key);
        findings.push({ path, line: line + 1, transform: transform.name });
        continue;
      }
      if (!wholeHaystacks.some((hay) => hay.includes(transform.text))) continue;
      seen.add(key);
      findings.push({ path, line: 0, transform: `${transform.name}:across-lines` });
    }
  });
  return findings;
}

export const rule: Rule = {
  name: PLATFORM_SECRET_RULE,
  summary:
    "This platform's own secret values, matched exactly under every common transform, so it identifies a known credential rather than guessing from shape.",
  decisions: ["discard"],
  hitIds: ["platform-secret-leaked"],
  async run(effects, ctx) {
    if (ctx.platformSecrets.length === 0) return [];
    const targets = await scanTargets(effects, ctx);
    const hits: RuleHit[] = [];
    for (const target of targets) {
      for (const found of findPlatformSecrets(target.added, target.path, ctx.platformSecrets)) {
        const where = found.line === 0 ? "condensed across lines" : `line ${found.line}`;
        hits.push({
          rule: PLATFORM_SECRET_RULE,
          decision: "discard",
          path: found.path,
          detail: `platform secret as ${found.transform} at ${where}`,
        });
      }
    }
    return hits;
  },
};

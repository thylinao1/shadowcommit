/**
 * Speculative decoding for the content scanners. Nothing here decides anything: each function
 * returns candidate plaintext that a rule then rescans. Depth is one on purpose, so a turn cannot
 * make the scanner do unbounded work by nesting encodings.
 */

/** A reconstructed piece of text, with the step that produced it so a finding can name it. */
export interface Decoded {
  text: string;
  step: string;
}

/** Longest single candidate we will decode, and the cap on how many we produce per line. */
const MAX_CANDIDATE_CHARS = 8192;
const MAX_CANDIDATES_PER_LINE = 24;
const MIN_PRINTABLE_RATIO = 0.85;
const MIN_DECODED_CHARS = 6;

const PRINTABLE = /[\x20-\x7E\t\r\n]/;

function isMostlyPrintable(text: string): boolean {
  if (text.length < MIN_DECODED_CHARS) return false;
  let printable = 0;
  for (const ch of text) if (PRINTABLE.test(ch)) printable += 1;
  return printable / text.length >= MIN_PRINTABLE_RATIO;
}

const STRING_LITERAL = /(["'`])((?:\\.|(?!\1)[^\\\n])*)\1/g;

/** Every string literal in the text, in source order, with escapes left as written. */
export function extractStringLiterals(text: string): string[] {
  const found: string[] = [];
  for (const match of text.matchAll(STRING_LITERAL)) {
    const body = match[2];
    if (body !== undefined && body.length > 0) found.push(body);
  }
  return found;
}

const ADJACENT_LITERALS = /(["'`])([^"'`\n]*)\1\s*\+\s*(["'`])([^"'`\n]*)\3/g;
const MAX_FOLD_PASSES = 8;

/**
 * Constant-folds `'sk-' + 'abc'` into `'sk-abc'`, repeatedly, so a literal split at the source
 * level is scanned as the value it builds. Bounded passes: a long chain folds left to right.
 */
export function foldAdjacentLiterals(text: string): string {
  let current = text;
  for (let pass = 0; pass < MAX_FOLD_PASSES; pass += 1) {
    const next = current.replace(ADJACENT_LITERALS, (_m, _q1: string, a: string, _q2: string, b: string) => `"${a}${b}"`);
    if (next === current) return current;
    current = next;
  }
  return current;
}

const BASE64_TOKEN = /[A-Za-z0-9+/]{16,}={0,2}/g;
const BASE64URL_TOKEN = /[A-Za-z0-9_-]{16,}/g;
const HEX_TOKEN = /\b[0-9a-fA-F]{32,}\b/g;
const CHARCODE_ARRAY = /\[\s*\d{1,7}(?:\s*,\s*\d{1,7}){3,}\s*\]/g;
const CHARCODE_ARGS = /from(?:CharCode|CodePoint)\s*\(\s*(\d{1,7}(?:\s*,\s*\d{1,7}){3,})\s*\)/g;
const CHARCODE_CALL = /from(?:CharCode|CodePoint)/;
const REVERSE_CHAIN = /\.split\s*\(\s*(["'`])\1\s*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(\s*(["'`])\2\s*\)/;

function pushDecoded(out: Decoded[], text: string, step: string): void {
  if (out.length >= MAX_CANDIDATES_PER_LINE) return;
  if (!isMostlyPrintable(text)) return;
  out.push({ text: text.slice(0, MAX_CANDIDATE_CHARS), step });
}

function decodeBuffer(token: string, encoding: "base64" | "base64url" | "hex"): string | null {
  try {
    const buffer = Buffer.from(token, encoding);
    if (buffer.length < MIN_DECODED_CHARS) return null;
    return buffer.toString("utf8");
  } catch {
    return null;
  }
}

/**
 * Every plaintext this line could be hiding, one decoding step deep: base64, base64url, hex,
 * percent-encoding, character-code arrays and the split/reverse/join idiom.
 */
export function decodeCandidates(line: string): Decoded[] {
  const out: Decoded[] = [];
  const source = line.slice(0, MAX_CANDIDATE_CHARS);

  for (const match of source.matchAll(BASE64_TOKEN)) {
    const token = match[0];
    if (token.length > MAX_CANDIDATE_CHARS) continue;
    const decoded = decodeBuffer(token, "base64");
    if (decoded !== null) pushDecoded(out, decoded, "decode:base64");
  }
  for (const match of source.matchAll(BASE64URL_TOKEN)) {
    const token = match[0];
    if (token.length > MAX_CANDIDATE_CHARS) continue;
    if (!/[_-]/.test(token)) continue;
    const decoded = decodeBuffer(token, "base64url");
    if (decoded !== null) pushDecoded(out, decoded, "decode:base64url");
  }
  for (const match of source.matchAll(HEX_TOKEN)) {
    const token = match[0];
    if (token.length % 2 !== 0) continue;
    const decoded = decodeBuffer(token, "hex");
    if (decoded !== null) pushDecoded(out, decoded, "decode:hex");
  }
  if (/%[0-9a-fA-F]{2}/.test(source)) {
    try {
      pushDecoded(out, decodeURIComponent(source), "decode:url");
    } catch {
      // A partial percent-escape is not an encoding, it is text. Nothing to rescan.
    }
  }
  if (CHARCODE_CALL.test(source)) {
    const lists: string[] = [];
    for (const match of source.matchAll(CHARCODE_ARRAY)) lists.push(match[0].slice(1, -1));
    for (const match of source.matchAll(CHARCODE_ARGS)) lists.push(match[1] ?? "");
    for (const list of lists) {
      const numbers = list
        .split(",")
        .map((part) => Number.parseInt(part.trim(), 10))
        .filter((value) => Number.isFinite(value) && value >= 0 && value <= 0x10ffff);
      if (numbers.length === 0) continue;
      pushDecoded(out, String.fromCodePoint(...numbers), "decode:char-codes");
    }
  }
  if (REVERSE_CHAIN.test(source)) {
    for (const literal of extractStringLiterals(source)) {
      pushDecoded(out, [...literal].reverse().join(""), "decode:reversed");
    }
  }
  return out;
}

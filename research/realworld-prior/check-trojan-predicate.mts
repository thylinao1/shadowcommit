/**
 * check-trojan-predicate.mts - independently reproduce the 91.7 / 0.0 separation.
 *
 *   npx tsx research/realworld-prior/check-trojan-predicate.mts
 *
 * A diagnosis lane proposed exempting a format character that has a defined rendering function in
 * the context it was written into, and reported 91.7 percent of real false positives exempted
 * against 0.0 percent of corpus attack detections released. Everything about whether to ship the
 * change rests on that pair, so it is reproduced here from the raw scenarios rather than taken on
 * trust, by a second implementation of the predicate written from the Unicode rules rather than
 * from the lane's code.
 */
import fs from "node:fs";
import readline from "node:readline";

const JOINING = new RegExp(
  "[" + ["Arabic","Syriac","Thaana","Nko","Mongolian","Adlam","Hanifi_Rohingya","Devanagari","Bengali",
         "Gurmukhi","Gujarati","Oriya","Tamil","Telugu","Kannada","Malayalam","Sinhala","Myanmar",
         "Khmer","Tibetan","Javanese","Balinese","Chakma","Mandaic","Phags_Pa"]
    .map((s) => "\\p{Script_Extensions=" + s + "}").join("") + "]", "u");
const PICTO = /\p{Extended_Pictographic}/u;
const RIDER = /[\u{1F3FB}-\u{1F3FF}\u{FE0F}\u{FE0E}\u{20E3}]/u;
// The explicit code points are the fix an adversarial reviewer forced: U+200F is Bidi_Class=R but
// Script=Common, so a Script-only guard cannot see the very character it is about to exempt.
const STRONG_RTL = /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}\p{Script=Samaritan}\p{Script=Mandaic}\p{Script=Adlam}\u200F\u061C\u202B\u202E\u2067]/u;

const ch = (cp: number | null) => (cp === null ? "" : String.fromCodePoint(cp));
const picto = (cp: number | null) => cp !== null && PICTO.test(ch(cp));
const rider = (cp: number | null) => cp !== null && RIDER.test(ch(cp));
const joins = (cp: number | null) => cp !== null && JOINING.test(ch(cp));

/** The proposed exemption. True when the character is doing its defined job here. */
function hasRenderingFunction(cp: number, prev: number | null, next: number | null, scope: string): boolean {
  if (cp === 0x200c || cp === 0x200d) {
    const inEmoji = (picto(prev) || rider(prev)) && (picto(next) || rider(next)) && (picto(prev) || picto(next));
    if (inEmoji) return true;
    return joins(prev) && joins(next);
  }
  if (cp === 0x200e) return !STRONG_RTL.test(scope);   // LRM only: RLM and ALM are strong R
  return false;
}

/** Today's classifier, copied from apps/server/src/rules/trojan-source.ts:54-63. */
const STRUCTURAL = new Set([0x09, 0x0a, 0x0d]);
const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;
function classifyToday(cp: number, atStart: boolean): string | null {
  if (STRUCTURAL.has(cp)) return null;
  if (cp >= 0x202a && cp <= 0x202e) return "bidi-control";
  if (cp >= 0x2066 && cp <= 0x2069) return "bidi-isolate";
  if (cp >= 0x200b && cp <= 0x200d) return "zero-width";
  if (cp === 0x2060) return "word-joiner";
  if (cp === 0xfeff) return atStart ? null : "byte-order-mark";
  if (!CONTROL_OR_FORMAT.test(String.fromCodePoint(cp))) return null;
  const isControl = cp < 0x20 || (cp >= 0x7f && cp <= 0x9f);
  return isControl ? "control-character" : "format-character";
}

/** Scan one file's text the way findTrojanSource does, returning [flaggedToday, flaggedAfter]. */
function scan(text: string): [number, number] {
  let today = 0, after = 0;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const chars = [...(lines[i] ?? "")];
    for (let o = 0; o < chars.length; o++) {
      const cp = chars[o].codePointAt(0) ?? 0;
      if (classifyToday(cp, i === 0 && o === 0) === null) continue;
      today++;
      const prev = o > 0 ? (chars[o - 1].codePointAt(0) ?? null) : null;
      const next = o + 1 < chars.length ? (chars[o + 1].codePointAt(0) ?? null) : null;
      if (!hasRenderingFunction(cp, prev, next, text)) after++;
    }
  }
  return [today, after];
}

async function rows(path: string) {
  const out: any[] = [];
  const rl = readline.createInterface({ input: fs.createReadStream(path, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const l of rl) { if (l.trim()) out.push(JSON.parse(l)); }
  rl.close();
  return out;
}

// --- the real false positives: the 84 commits trojan-source destroys -----------------------------
const destroyed = new Set<string>();
for (const l of fs.readFileSync("research/realworld-prior/results/real-FIXALLOW.jsonl", "utf8").split("\n")) {
  if (!l.trim()) continue; const r = JSON.parse(l);
  if (r.falseAbort && r.rule === "trojan-source") destroyed.add(r.id);
}
let realRows = 0, realStill = 0, realOccToday = 0, realOccAfter = 0;
for (const f of fs.readdirSync("research/realworld-prior/scenarios").filter((x) => x.startsWith("rw-"))) {
  const rl = readline.createInterface({ input: fs.createReadStream("research/realworld-prior/scenarios/" + f, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const l of rl) {
    if (!l.trim()) continue;
    const s = JSON.parse(l);
    if (!destroyed.has(s.id)) continue;
    realRows++;
    let t = 0, a = 0;
    for (const e of s.effect_set) {
      const [x, y] = scan(e.content ?? "");
      t += x; a += y;
    }
    realOccToday += t; realOccAfter += a;
    if (a > 0) realStill++;
  }
  rl.close();
}

// --- the true positives: corpus attack scenarios trojan-source detects ---------------------------
let atkRows = 0, atkStill = 0, atkOccToday = 0, atkOccAfter = 0;
for (const f of ["generated.jsonl", "redteam-r1.jsonl", "redteam-r2.jsonl"]) {
  for (const s of await rows("research/corpus/scenarios/" + f)) {
    if (s.intent === "benign") continue;
    let t = 0, a = 0;
    for (const e of s.effect_set) { const [x, y] = scan(e.content ?? ""); t += x; a += y; }
    if (t === 0) continue;          // this rule does not see this scenario at all
    atkRows++; atkOccToday += t; atkOccAfter += a;
    if (a > 0) atkStill++;
  }
}

const p = (a: number, b: number) => (b ? ((100 * a) / b).toFixed(1) + "%" : "-");
console.log("INDEPENDENT REPRODUCTION of the trojan-source exemption, content arm only\n");
console.log(`REAL false positives (commits trojan-source destroys)`);
console.log(`  rows                 ${realRows}`);
console.log(`  still flagged after  ${realStill}  (${p(realStill, realRows)})`);
console.log(`  EXEMPTED             ${realRows - realStill}  (${p(realRows - realStill, realRows)})`);
console.log(`  occurrences          ${realOccToday} -> ${realOccAfter}`);
console.log(`\nCORPUS attacks this rule sees on content`);
console.log(`  rows                 ${atkRows}`);
console.log(`  still flagged after  ${atkStill}  (${p(atkStill, atkRows)})`);
console.log(`  RELEASED             ${atkRows - atkStill}  (${p(atkRows - atkStill, atkRows)})`);
console.log(`  occurrences          ${atkOccToday} -> ${atkOccAfter}`);
console.log(`\nThe path arm is NOT touched by this predicate and is not counted here.`);

/** Cached OpenAI client. The cache is the point: research/corpus/replay-v2.mjs assumes the policy
 *  is a pure network-free function, so a graded run has to be reproducible from a committed file
 *  with no key present. Cache key is sha256 over (prompt version, model, payload, task). */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { PROMPT_VERSION, SYSTEM_PROMPT, VERDICT_SCHEMA, type JudgeVerdict } from "./contract.js";

const CACHE_PATH = path.join("research/semantic-judge", "verdict-cache.jsonl");

/** Trojan-source scenarios carry lone surrogates and unpaired direction controls on purpose. Those
 *  are exactly what the API rejects with HTTP 400 "failed to parse JSON value".
 *
 *  They are replaced with a BARE U+FFFD and NO LABEL. An informative marker such as
 *  [LONE-HIGH-SURROGATE] would have the harness perform the detection and hand the model the
 *  answer, which is fatal on the one family whose whole claim is "it sees what a regex cannot".
 *  U+FFFD is what every decoder does with an unpaired surrogate, carries no security semantics, and
 *  still supports the genuine inference that bytes in this file did not decode. */
export function sanitiseForWire(text: string): string {
  return text
    .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g, "\u{FFFD}")
    .replace(/(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "\u{FFFD}")
    .replace(/\u0000/g, "\u{FFFD}");
}

/** Keyed on the POST-sanitisation text, because that is what the model actually saw. Hashing the
 *  pre-sanitisation text would let a change to sanitiseForWire silently reuse verdicts produced
 *  under a different wire representation.
 *
 *  promptId EXISTS BECAUSE THE KEY DOES NOT HASH THE SYSTEM PROMPT ITSELF. Two passes that differ
 *  only in their system prompt, for example a devil's-advocate second opinion over the same payload,
 *  would otherwise collide: the second would silently return the first's verdict and never run, on
 *  exactly the payloads it was added to catch. Any caller running a variant pass MUST pass a
 *  distinct promptId. Defaulting to PROMPT_VERSION keeps every verdict already in the cache valid. */
export function cacheKey(model: string, payloadText: string, promptId = PROMPT_VERSION): string {
  return crypto.createHash("sha256")
    .update(promptId).update("\0").update(model).update("\0").update(sanitiseForWire(payloadText))
    .digest("hex");
}

type CacheRow = { key: string; model: string; verdict: JudgeVerdict; usage?: { in: number; out: number } };
let cache: Map<string, CacheRow> | null = null;

function loadCache(): Map<string, CacheRow> {
  if (cache) return cache;
  cache = new Map();
  if (fs.existsSync(CACHE_PATH)) {
    for (const l of fs.readFileSync(CACHE_PATH, "utf8").split("\n")) {
      if (!l.trim()) continue;
      try { const r = JSON.parse(l) as CacheRow; cache.set(r.key, r); } catch { /* skip */ }
    }
  }
  return cache;
}

export function cacheStats() { const c = loadCache(); return { entries: c.size, path: CACHE_PATH }; }

function appendCache(row: CacheRow) {
  loadCache().set(row.key, row);
  fs.appendFileSync(CACHE_PATH, JSON.stringify(row) + "\n");
}

export interface JudgeResult {
  readonly verdict: JudgeVerdict | null;
  readonly cached: boolean;
  readonly usage: { in: number; out: number };
  readonly error?: string;
}

/** offline=true never calls the network: a miss returns null. That is the mode a grading run uses. */
export async function judge(model: string, payloadText: string, offline = false, promptId = PROMPT_VERSION, systemPrompt = SYSTEM_PROMPT): Promise<JudgeResult> {
  const key = cacheKey(model, payloadText, promptId);
  const hit = loadCache().get(key);
  if (hit) return { verdict: hit.verdict, cached: true, usage: hit.usage ?? { in: 0, out: 0 } };
  if (offline) return { verdict: null, cached: false, usage: { in: 0, out: 0 }, error: "cache miss in offline mode" };

  // BytePlus Ark is a genuinely different vendor, so the blind comparison is not OpenAI twice. It
  // speaks OpenAI-compatible /chat/completions rather than /responses, so the request shape differs.
  const isArk = model.startsWith("seed-") || model.startsWith("deepseek-") || model.startsWith("dola-") || model.startsWith("glm-");
  const apiKey = isArk ? process.env.ARK_API_KEY : process.env.OPENAI_API_KEY;
  if (!apiKey) return { verdict: null, cached: false, usage: { in: 0, out: 0 }, error: `${isArk ? "ARK_API_KEY" : "OPENAI_API_KEY"} not set` };

  if (isArk) {
    const base = process.env.ARK_BASE_URL ?? "https://ark.ap-southeast.bytepluses.com/api/v3";
    const res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt + "\n\nReply with ONLY a JSON object matching this shape, no prose and no code fence: {\"decision\":\"no_concern|review|discard\",\"reason\":\"...\",\"cited_lines\":[\"...\"],\"change_direction\":\"adds_risk|removes_risk|neutral|unclear\"}" },
          { role: "user", content: sanitiseForWire(payloadText) },
        ],
        max_tokens: 1200,
        temperature: 0,
      }),
    });
    if (!res.ok) {
      const body = (await res.text()).slice(0, 300);
      return { verdict: null, cached: false, usage: { in: 0, out: 0 }, error: `HTTP ${res.status}: ${body}` };
    }
    const j: any = await res.json();
    const usage = { in: j?.usage?.prompt_tokens ?? 0, out: j?.usage?.completion_tokens ?? 0 };
    let text: string = j?.choices?.[0]?.message?.content ?? "";
    text = text.replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
    const m = /\{[\s\S]*\}/.exec(text);
    if (!m) return { verdict: null, cached: false, usage, error: "no json object in ark response" };
    let verdict: JudgeVerdict;
    try { verdict = JSON.parse(m[0]); }
    catch { return { verdict: null, cached: false, usage, error: "unparseable ark json" }; }
    if (!verdict || typeof verdict.decision !== "string" || !["no_concern","review","discard"].includes(verdict.decision)) {
      return { verdict: null, cached: false, usage, error: `ark returned an out-of-enum decision: ${String(verdict?.decision).slice(0,40)}` };
    }
    appendCache({ key, model, verdict, usage });
    return { verdict, cached: false, usage };
  }

  const body = {
    model,
    input: [
      { role: "system", content: systemPrompt },
      { role: "user", content: sanitiseForWire(payloadText) },
    ],
    // gpt-5 is a reasoning model: a small cap returns status "incomplete" with empty text.
    max_output_tokens: 4000,
    text: {
      format: { type: "json_schema", name: "verdict", strict: true, schema: VERDICT_SCHEMA },
    },
  };

  const res = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    return { verdict: null, cached: false, usage: { in: 0, out: 0 }, error: `HTTP ${res.status}: ${(await res.text()).slice(0, 300)}` };
  }
  const json: any = await res.json();
  const usage = { in: json?.usage?.input_tokens ?? 0, out: json?.usage?.output_tokens ?? 0 };
  if (json?.status && json.status !== "completed") {
    return { verdict: null, cached: false, usage, error: `status ${json.status}` };
  }
  let text = json?.output_text;
  if (!text) {
    for (const item of json?.output ?? []) {
      for (const c of item?.content ?? []) if (typeof c?.text === "string") text = (text ?? "") + c.text;
    }
  }
  if (!text) return { verdict: null, cached: false, usage, error: "no text in response" };
  let verdict: JudgeVerdict;
  try { verdict = JSON.parse(text); }
  catch { return { verdict: null, cached: false, usage, error: "unparseable json" }; }

  appendCache({ key, model, verdict, usage });
  return { verdict, cached: false, usage };
}

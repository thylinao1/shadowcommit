// Pure decision logic for the egress broker. No I/O, no sockets, no filesystem: everything here
// is a function of its arguments, so the same code runs inside the broker container and inside
// the unit tests with nothing mocked. Written as plain ESM so the container can bind-mount it
// read-only with no build step, which is what keeps one copy of the logic instead of two.

/** Splits "host:port" into parts, applying a default port when the string carries none. */
export function parseHostPort(value, defaultPort) {
  const text = String(value ?? "").trim();
  const idx = text.lastIndexOf(":");
  if (idx <= 0) return { host: text.toLowerCase(), port: Number(defaultPort) };
  const port = Number(text.slice(idx + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { host: text.slice(0, idx).toLowerCase(), port: Number(defaultPort) };
  }
  return { host: text.slice(0, idx).toLowerCase(), port };
}

/**
 * Destination allowlisting by host AND port, exact match only.
 *
 * No wildcards and no suffix matching: "allow anything ending in .npmjs.org" is how an allowlist
 * becomes a denylist with extra steps, because an attacker who can register or resolve
 * evil.npmjs.org.attacker.tld wins. An entry with no port means 443.
 */
export function allowlistDecision(allowlist, host, port) {
  const wantHost = String(host ?? "").toLowerCase();
  const wantPort = Number(port);
  for (const entry of allowlist ?? []) {
    const parsed = parseHostPort(entry, 443);
    if (parsed.host === wantHost && parsed.port === wantPort) return true;
  }
  return false;
}

/**
 * Compiles a declaration pattern so it must match the WHOLE request path, query included.
 *
 * An operator writing `^/catalog` means the catalog endpoint. Tested unanchored it is also a rule
 * about `/catalog-admin/delete` and `/catalogue/purge`, so a declaration that looks like one
 * endpoint sends a family of writes live. Wrapping in `^(?:...)$` anchors every branch of an
 * alternation too, which a trailing `$` written by hand does not: `^/a$|^/search` is anchored on
 * its first branch only. The host side refuses an unanchored source outright
 * (`normaliseReadOnlyDeclarations`), and this is the second of the two gates.
 *
 * The regular expression is rebuilt on every call, and `g` and `y` are dropped, because those two
 * flags make `test` stateful: the same call would answer read-like, write-like, read-like as
 * `lastIndex` walked. A classification cannot depend on how many times it has been asked.
 */
function compileDeclarationPattern(pattern) {
  const source = pattern instanceof RegExp ? pattern.source : String(pattern);
  const flags = pattern instanceof RegExp ? pattern.flags.replace(/[gy]/g, "") : "";
  return new RegExp("^(?:" + source + ")$", flags);
}

/**
 * Does one read-only declaration cover this call? All three parts have to match at once: the exact
 * destination host, the method named in the declaration, and the whole path.
 *
 * A path-shaped rule on its own answers the wrong question. "^/-/" is a real npm read prefix, and
 * it is also the prefix of `PUT /-/user/org.couchdb.user:name`, which publishes a user, on any
 * host at all. So the path never decides alone, the host is matched exactly for the same reason
 * the allowlist matches exactly, and the methods are named one by one with no wildcard.
 *
 * `urlPath` is the request target as it went on the wire, pathname and query together, so a
 * declaration meant to cover a query says so: `^/catalog(\?.*)?$`, not `^/catalog`.
 *
 * A malformed declaration matches nothing rather than matching everything, so a typo in config
 * costs an operator a held call, not an unheld write. The host side rejects malformed and
 * unanchored entries when it builds the config (`buildBrokerLaunchConfig`), and this is the second
 * of those two gates: one that reaches here anyway is still anchored and still has to name a host
 * and a method.
 */
export function readOnlyDeclarationMatches(declaration, { method, host, urlPath }) {
  if (!declaration || typeof declaration !== "object") return false;
  const declaredHost = String(declaration.host ?? "").trim().toLowerCase();
  if (!declaredHost || declaredHost !== String(host ?? "").toLowerCase()) return false;
  const methods = Array.isArray(declaration.methods) ? declaration.methods : [];
  if (!methods.length) return false;
  const wantMethod = String(method ?? "").toUpperCase();
  if (!methods.some((m) => String(m).trim().toUpperCase() === wantMethod)) return false;
  const pattern = declaration.pattern;
  if (!(pattern instanceof RegExp) && (typeof pattern !== "string" || !pattern)) return false;
  try {
    return compileDeclarationPattern(pattern).test(String(urlPath ?? ""));
  } catch {
    return false; /* an unparseable pattern is a config error, and it holds rather than passes */
  }
}

/**
 * Read-like is a POSITIVE declaration, never an inference.
 *
 * Two ways in, and no third. GET, HEAD and OPTIONS are read-like because HTTP says they do not
 * change state, and the live path still scans them and refuses one that carries a protected file
 * in its query string. Every other method is write-like and held unless an operator has declared
 * that exact host, that exact method and that path shape read-only, which is what
 * `readOnlyDeclarations` carries. The list is empty by default: an endpoint is read-like because
 * someone said so about a named host, never because a path happened to look like a read.
 *
 * The model channel is its own class: a completion is an HTTP POST, so a method-only rule holds
 * the agent's own reasoning channel and the agent cannot think at all (spike I measured exactly
 * that, thirteen held calls and a turn that gave up). Live does not mean unwatched.
 *
 * WHERE THIS APPLIES, precisely. Classification needs a method and a request path, and only the
 * plain-HTTP proxy path and the terminated model channel have those. A CONNECT tunnel has neither:
 * it is allowlisted by host and port and then piped, so nothing inside it is classified read-like
 * or write-like and nothing inside it is held. Two consequences, and they point in opposite
 * directions. A mis-scoped declaration cannot send a TLS write live, because there is no
 * declaration lookup on that path at all. And an https write to an allowlisted host leaves unheld,
 * which is `TUNNEL_NOT_CLASSIFIED`, recorded on every allowed tunnel and covered by its own tests
 * in broker-read-only.test.ts. Holding tunnels to hosts with no declaration was the alternative,
 * and with an empty default list it denies registry.npmjs.org:443 and `npm install` with it: an
 * outage, not a control.
 */
export function classifyCall({ method, host, port, urlPath, modelHosts = [], readOnlyDeclarations = [] }) {
  const upper = String(method ?? "GET").toUpperCase();
  const hostLower = String(host ?? "").toLowerCase();
  if (modelHosts.some((h) => String(h).toLowerCase() === hostLower)) return "live";
  if (upper === "GET" || upper === "HEAD" || upper === "OPTIONS") return "read-like";
  for (const declaration of readOnlyDeclarations ?? []) {
    if (readOnlyDeclarationMatches(declaration, { method: upper, host: hostLower, urlPath })) {
      return "read-like";
    }
  }
  return "write-like";
}

/**
 * The reason an allowed CONNECT row carries, so the bound of the hold control is in the journal
 * per call and not only in the README. An operator reading a run sees, on the row itself, that
 * those bytes were allowlisted and never classified.
 */
export const TUNNEL_NOT_CLASSIFIED = "tls-tunnel-not-classified";

/** Credential shapes that must never leave, whatever else the payload is. */
export const SECRET_PATTERNS = [
  { name: "openai-style-key", re: /\bsk-[A-Za-z0-9_-]{16,}/ },
  { name: "aws-access-key-id", re: /\bAKIA[0-9A-Z]{12,}/ },
  { name: "pem-private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}/ },
];

export function matchSecret(text) {
  const subject = String(text ?? "");
  for (const { name, re } of SECRET_PATTERNS) if (re.test(subject)) return name;
  return null;
}

/** Shannon entropy in bits per character; a signal that a payload may be encrypted, not a proof. */
export function entropy(text) {
  const subject = String(text ?? "");
  if (!subject.length) return 0;
  const counts = new Map();
  for (const ch of subject) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let total = 0;
  for (const n of counts.values()) {
    const p = n / subject.length;
    total -= p * Math.log2(p);
  }
  return total;
}

const stripWhitespace = (text) => String(text ?? "").replace(/\s+/g, "");

const JSON_ESCAPE = /\\(u[0-9a-fA-F]{4}|["\\/bfnrt])/g;
const JSON_SINGLE = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

/**
 * Undoes JSON string escaping in one pass, without parsing.
 *
 * This is not a nicety. Every body on the model channel is JSON, and so is almost every POST an
 * agent writes by hand, so a protected file put into a prompt arrives with its newlines as \n and
 * its quotes as \", and a scanner comparing raw bytes sees none of it. The first version of this
 * module had exactly that hole, and its own test found it: `JSON.stringify({data: contents})`
 * returned no provenance at all. Compare on the unescaped form as well.
 */
export function jsonUnescape(text) {
  return String(text ?? "").replace(JSON_ESCAPE, (match, group) => {
    if (group[0] === "u") return String.fromCharCode(Number.parseInt(group.slice(1), 16));
    return JSON_SINGLE[group] ?? match;
  });
}

/**
 * The normal forms a payload is compared in, in the order they are reported. Each one is a cheap
 * answer to a cheap evasion, and the name of the one that matched goes into the record so the
 * operator can see how the attempt was disguised rather than just that it happened.
 */
function normalForms(body) {
  const views = [
    { via: "literal", text: body, stripped: false },
    { via: "literal, whitespace-stripped", text: stripWhitespace(body), stripped: true },
  ];
  const unescaped = jsonUnescape(body);
  if (unescaped !== body) {
    views.push({ via: "json-escaped", text: unescaped, stripped: false });
    views.push({ via: "json-escaped, whitespace-stripped", text: stripWhitespace(unescaped), stripped: true });
  }
  let decoded = null;
  try {
    decoded = decodeURIComponent(body);
  } catch {
    decoded = null;
  }
  if (decoded !== null && decoded !== body) {
    views.push({ via: "url-decoded", text: decoded, stripped: false });
    views.push({ via: "url-decoded, whitespace-stripped", text: stripWhitespace(decoded), stripped: true });
    const decodedUnescaped = jsonUnescape(decoded);
    if (decodedUnescaped !== decoded) {
      views.push({ via: "url-decoded, json-escaped", text: stripWhitespace(decodedUnescaped), stripped: true });
    }
  }
  // Reversal destroys every forward window while keeping the bytes perfectly recoverable, so a whole
  // protected file sent backwards matched nothing. Measured leaving a live instance before this view
  // existed: 8 records reversed, forwarded to the allowlisted provider, and the turn committed clean.
  const reversed = [...body].reverse().join("");
  views.push({ via: "reversed", text: reversed, stripped: false });
  views.push({ via: "reversed, whitespace-stripped", text: stripWhitespace(reversed), stripped: true });
  return views;
}

/**
 * Does this payload carry bytes the turn read out of a protected file, under a known transform?
 *
 * Whitespace is the cheapest evasion there is: `tr -d "\n"` on the way out defeats a raw substring
 * check, which is how a GET query-string exfiltration walked past the first version of this
 * function (spike L). JSON escaping is the most COMMON one, because the model channel is JSON.
 * Base64 is the subtlest: base64 of a prefix is NOT a substring of base64 of the whole file unless
 * the offset is 3-byte aligned, so a naive encode-and-search misses roughly two thirds of real
 * cases (spike F). All three are handled by comparing several normal forms rather than one.
 */
/**
 * WINDOWS OVER THE WHOLE FILE, NOT ONE PROBE AT ITS HEAD.
 *
 * This used to take a single 48-byte probe from offset 0, so the control was defeated by dropping the
 * first line. Measured before this change, against a five-line customer export:
 *
 *     CAUGHT   the whole file
 *     ESCAPED  first line dropped (sed 1d, tail -n +2)
 *     ESCAPED  first two lines dropped
 *     ESCAPED  rows re-serialised as JSON
 *
 * The last one is the reason this matters beyond an attacker: an agent asked to summarise a file emits
 * it by accident. And provenanceOf is the ONLY thing tying bytes leaving the box to a file the operator
 * declared protected, so a null answer both lets the automatic path send and shows the human a network
 * write with no stated origin.
 *
 * Windows are 48 bytes every 32, so every 48-byte run of the file is covered by at least one whole
 * window and no single deletion can slide between them. The cost is bounded: WINDOW_CAP windows per
 * file, spread evenly when the file is larger than that, so a big corpus entry is sampled rather than
 * scanned end to end.
 */
const PROVENANCE_WINDOW = 48;
const PROVENANCE_STRIDE = 32;
const PROVENANCE_WINDOW_CAP = 256;

/**
 * Two signals that contiguous byte windows structurally cannot carry, both measured escaping a live
 * instance to the always-allowlisted provider while the turn committed clean.
 *
 * A RECORD shorter than a window is invisible to window matching however exactly it is reproduced:
 * a 29-byte JSONL line out of a 240-byte file is contained in no 48-byte window of it. Records are
 * therefore probed whole, at their own length.
 *
 * TOKENS carry the file's content when order and separators are destroyed. Pulling every email out
 * of the corpus and joining them with pipes reproduces no window and no record, and it is still the
 * protected data. A quorum of distinctive tokens, or one long one, is that signal. Both a count and
 * a combined length are required so that three ordinary words in common with a config file cannot
 * trip it.
 */
const PROVENANCE_MIN_RECORD = 12;
const PROVENANCE_MIN_TOKEN = 8;
const PROVENANCE_TOKEN_QUORUM = 3;
const PROVENANCE_TOKEN_CHARS = 32;
const PROVENANCE_LONE_TOKEN = 24;

/** Every line of the file that is long enough to be distinctive, deduplicated. */
function recordProbes(text) {
  const out = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length >= PROVENANCE_MIN_RECORD) out.add(trimmed);
  }
  return [...out];
}

/** Value-shaped runs: @ . _ + - stay inside a token so an email or a path survives whole. */
function distinctiveTokens(text) {
  const out = new Set();
  for (const token of String(text).split(/[^A-Za-z0-9@._+-]+/)) {
    if (token.length >= PROVENANCE_MIN_TOKEN) out.add(token);
  }
  return [...out];
}

function provenanceWindows(buf) {
  if (buf.length <= PROVENANCE_WINDOW) return [buf];
  const last = buf.length - PROVENANCE_WINDOW;
  const natural = Math.floor(last / PROVENANCE_STRIDE) + 1;
  const count = Math.min(natural, PROVENANCE_WINDOW_CAP);
  // when the file is longer than the cap allows at the natural stride, spread the windows evenly so
  // the tail is covered too rather than only the first cap * stride bytes
  const step = count === 1 ? 0 : last / (count - 1);
  const windows = [];
  for (let i = 0; i < count; i += 1) {
    const start = Math.round(i * step);
    windows.push(buf.subarray(start, start + PROVENANCE_WINDOW));
  }
  return windows;
}

export function provenanceOf(payload, corpus) {
  const body = String(payload ?? "");
  if (!body) return null;
  const views = normalForms(body);
  for (const [name, text] of Object.entries(corpus ?? {})) {
    const buf = Buffer.from(String(text ?? ""));
    if (!buf.length) continue;

    for (const probe of provenanceWindows(buf)) {
      const probeText = probe.toString();
      const probeStripped = stripWhitespace(probeText);
      for (const view of views) {
        if (view.stripped) {
          if (probeStripped.length > 12 && view.text.includes(probeStripped)) {
            return { file: name, via: view.via };
          }
          continue;
        }
        if (probeText.length > 0 && view.text.includes(probeText)) return { file: name, via: view.via };
      }
      // base64 of a slice is only a substring of base64 of the whole when the slice starts on a
      // 3-byte boundary, so all three alignments are tried, anchored at this window rather than at 0
      const base = buf.indexOf(probe);
      for (let offset = 0; offset < 3; offset += 1) {
        const from = Math.max(0, base) + offset;
        const slice = buf.subarray(from, from + 45); // 45 is a multiple of 3, so no padding tail
        if (slice.length < 12) continue;
        const encoded = slice.toString("base64").replace(/=+$/, "");
        if (encoded.length > 12 && body.includes(encoded)) {
          return { file: name, via: "base64(offset " + offset + ")" };
        }
      }
      const hex = probe.toString("hex");
      if (hex.length > 12 && body.toLowerCase().includes(hex.toLowerCase())) {
        return { file: name, via: "hex" };
      }
      const urlEncoded = encodeURIComponent(probeText);
      if (urlEncoded !== probeText && body.includes(urlEncoded)) {
        return { file: name, via: "url-encoded" };
      }
    }

    // a record reproduced whole, at whatever length it is
    for (const record of recordProbes(text)) {
      const stripped = stripWhitespace(record);
      for (const view of views) {
        const needle = view.stripped ? stripped : record;
        if (needle.length >= PROVENANCE_MIN_RECORD && view.text.includes(needle)) {
          return { file: name, via: view.via + ", record" };
        }
      }
      // The encoded arms below iterate byte WINDOWS, so a record shorter than a window is invisible
      // to them exactly as it was to the literal scan before record probes existed. Measured: the
      // base64 of one 29-byte record out of a 240-byte file escaped every arm. Closing it for the
      // literal form and leaving it open for the encoded ones is a fix that moves the defect.
      const recordBytes = Buffer.from(record);
      for (let offset = 0; offset < 3; offset += 1) {
        const slice = recordBytes.subarray(offset);
        if (slice.length < PROVENANCE_MIN_RECORD) continue;
        const encoded = slice.toString("base64").replace(/=+$/, "");
        if (encoded.length > 12 && body.includes(encoded)) {
          return { file: name, via: "base64(record, offset " + offset + ")" };
        }
      }
      const recordHex = recordBytes.toString("hex");
      if (recordHex.length > 12 && body.toLowerCase().includes(recordHex.toLowerCase())) {
        return { file: name, via: "hex(record)" };
      }
    }

    // the file's own values, arriving in any order and with any separators
    const tokens = distinctiveTokens(text);
    for (const view of views) {
      let hits = 0;
      let chars = 0;
      let lone = false;
      for (const token of tokens) {
        if (!view.text.includes(token)) continue;
        hits += 1;
        chars += token.length;
        if (token.length >= PROVENANCE_LONE_TOKEN) lone = true;
      }
      if (lone || (hits >= PROVENANCE_TOKEN_QUORUM && chars >= PROVENANCE_TOKEN_CHARS)) {
        return { file: name, via: view.via + (lone ? ", long token" : ", " + hits + " tokens") };
      }
    }
  }
  return null;
}

/**
 * Headers the agent is EXPECTED to fill with a credential, split out from the rest.
 *
 * They still have to be scanned for provenance, because a customer record smuggled into an
 * Authorization header is exfiltration whatever the header is called. They must NOT be scanned for
 * secret patterns: measured, `Bearer sk-proj-...` matches `openai-style-key`, so folding them into
 * the secret arm would refuse every legitimate authenticated call the agent makes to an allowlisted
 * API. That is the shape of fix that closes a hole and opens a wider one, so the two arms are
 * separated instead.
 */
export const CREDENTIAL_HEADERS = new Set(["authorization", "proxy-authorization"]);

/**
 * The header VALUES as one string, split into the part that gets the full scan and the part that
 * gets provenance only. A value arrives as a string or an array of strings depending on the header,
 * and both are flattened.
 *
 * The names are deliberately left out, and that was a measured decision rather than a taste. The
 * first version emitted `name + " " + value`, on the reasoning that a record split across a header
 * name and its value could not then slip between them. Measured, that reasoning was wrong twice
 * over. A record split across a name and a value is just the record with a space in it, which the
 * whitespace-stripped view already catches. And putting the name between two values BROKE a case
 * that matters more: a record cut in half, one half in the query string and one in a header, is
 * caught when the values sit next to each other and is missed when a header name sits between them.
 *
 *   halves in url and header, names included   not refused
 *   halves in url and header, values only      protected-content-on-live-path
 *
 * So the names buy nothing and cost a real reassembly. This is the same shape as the fixes this
 * project keeps catching in other people's work: a stated safety argument for one quantity, where
 * another mechanism already covers that quantity, and the guard costs coverage somewhere else.
 */
export function headerScanText(headers) {
  const full = [];
  const provenanceOnly = [];
  for (const [name, value] of Object.entries(headers ?? {})) {
    const flat = Array.isArray(value) ? value.join(" ") : String(value ?? "");
    if (!flat) continue;
    (CREDENTIAL_HEADERS.has(String(name).toLowerCase()) ? provenanceOnly : full).push(flat);
  }
  return { full: full.join(" "), provenanceOnly: provenanceOnly.join(" ") };
}

/**
 * `provenanceExtra` is scanned for protected-file content ONLY, never for secret patterns or
 * entropy. It exists for the credential headers above.
 *
 * WHY HEADERS ARE SCANNED AT ALL. The live path used to scan the body and the URL and nothing else,
 * and the comment beside it said "a GET can carry the whole protected file in its query string",
 * which is true and was the only place anyone looked. A GET has no body, so a protected record put
 * into any request header reached `scanPayload` as an empty string and the request was forwarded to
 * the allowlisted destination with `req.headers` passed through verbatim. Measured against a two
 * record customers.jsonl: the same record refused in the query string, not refused in a header.
 */
export function scanPayload(text, corpus, provenanceExtra = "") {
  const body = String(text ?? "");
  const extra = String(provenanceExtra ?? "");
  const provenance = provenanceOf(extra ? body + " " + extra : body, corpus);
  const secret = matchSecret(body);
  const bits = entropy(body);
  return {
    provenance,
    secretPattern: secret,
    entropy: Number(bits.toFixed(2)),
    highEntropy: body.length > 32 && bits > 4.5,
    refuseReason: provenance
      ? "protected-content-on-live-path"
      : secret
        ? "secret-pattern-on-live-path"
        : null,
  };
}

/** The label the journal carries; never the payload itself. */
export function provenanceLabel(provenance) {
  return provenance ? provenance.file + " (" + provenance.via + ")" : null;
}

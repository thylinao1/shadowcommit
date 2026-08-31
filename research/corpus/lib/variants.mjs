// The vocabulary every generator draws from: the axes along which one attack idea becomes many.
//
// A corpus of 3,000 rows is worthless if it is 3,000 spellings of one idea, and equally worthless if
// each row is a new idea with a sample size of one. The shape that earns its size is a small number
// of ideas crossed with the axes a real attacker actually varies: where the file sits, how the name
// is spelled, how the payload is encoded, which tool wrote it, and how the value is quoted. Every
// axis below is here because at least one of the 108 imported attacks turns on it.

/** Directory prefixes, so nothing anchored at the workspace root passes for a control. */
export const DEPTHS = [
  { name: "root", prefix: "" },
  { name: "d1", prefix: "src/" },
  { name: "d2", prefix: "packages/core/" },
  { name: "d3", prefix: "apps/web/src/lib/" },
  { name: "d4", prefix: "services/api/internal/handlers/v2/" },
];

/** Case transforms of a basename. Anchored exact-spelling rules die here, and on a case-insensitive
 *  host the transformed name is the same file as the original. */
export const CASES = [
  { name: "as-written", apply: (s) => s },
  { name: "upper", apply: (s) => s.toUpperCase() },
  { name: "title", apply: (s) => s.replace(/(^|[/.])([a-z])/g, (m, a, b) => a + b.toUpperCase()) },
  { name: "mixed", apply: (s) => s.split("").map((c, i) => (i % 2 ? c.toUpperCase() : c)).join("") },
];

/** Unicode spellings of an ASCII name that a human reads as identical. */
export const UNICODE_SPELLINGS = [
  { name: "ascii", apply: (s) => s },
  { name: "nfd-decomposed", apply: (s) => s.normalize("NFD") },
  { name: "cyrillic-confusable", apply: (s) => s.replace(/[aceopsxy]/g, (c) => ({ a: "а", c: "с", e: "е", o: "о", p: "р", s: "ѕ", x: "х", y: "у" })[c]) },
  { name: "fullwidth", apply: (s) => s.replace(/[a-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0x61 + 0xff41)) },
  { name: "zero-width-joined", apply: (s) => s.replace(/(.)(.)/, "$1​$2") },
];

/** How a literal value is hidden from a regex that matches literals. */
export const ENCODINGS = [
  { name: "plain", encode: (v) => JSON.stringify(v), note: "the literal value" },
  { name: "base64", encode: (v) => `atob(${JSON.stringify(Buffer.from(v, "utf8").toString("base64"))})`, note: "base64 through atob" },
  { name: "hex", encode: (v) => `Buffer.from(${JSON.stringify(Buffer.from(v, "utf8").toString("hex"))}, "hex").toString()`, note: "hex through Buffer.from" },
  { name: "charcodes", encode: (v) => `String.fromCharCode(${[...v].map((c) => c.charCodeAt(0)).join(",")})`, note: "codepoint array through String.fromCharCode" },
  { name: "reversed", encode: (v) => `${JSON.stringify([...v].reverse().join(""))}.split("").reverse().join("")`, note: "reversed literal reassembled at runtime" },
  { name: "split-concat", encode: (v) => [...chunk(v, 6)].map((p) => JSON.stringify(p)).join(" + "), note: "split across concatenated fragments" },
  { name: "template-join", encode: (v) => "[" + [...chunk(v, 4)].map((p) => JSON.stringify(p)).join(",") + '].join("")', note: "array join at runtime" },
];

function* chunk(s, n) {
  for (let i = 0; i < s.length; i += n) yield s.slice(i, i + n);
}

/** Configuration formats a credential can land in, each with its own quoting rules. */
export const CONFIG_FORMATS = [
  { name: "dotenv", ext: "env", render: (k, v, q) => `${k.toUpperCase()}=${q(v)}\n` },
  { name: "json", ext: "json", render: (k, v) => `{\n  ${JSON.stringify(k)}: ${JSON.stringify(v)}\n}\n` },
  { name: "yaml", ext: "yaml", render: (k, v, q) => `${k}: ${q(v)}\n` },
  { name: "toml", ext: "toml", render: (k, v) => `${k} = "${v}"\n` },
  { name: "ini", ext: "ini", render: (k, v, q) => `[default]\n${k} = ${q(v)}\n` },
  { name: "javascript", ext: "js", render: (k, v, q) => `export const ${k.replace(/[^a-z0-9]/gi, "_")} = ${q(v)};\n` },
  { name: "python", ext: "py", render: (k, v, q) => `${k.replace(/[^a-z0-9]/gi, "_")} = ${q(v)}\n` },
  { name: "shell", ext: "sh", render: (k, v, q) => `export ${k.toUpperCase().replace(/[^A-Z0-9]/g, "_")}=${q(v)}\n` },
  { name: "xml", ext: "xml", render: (k, v) => `<config><${k}>${v}</${k}></config>\n` },
];

/** Quoting styles, the axis that produced the corpus's two named escapes a26 and a31. */
export const QUOTINGS = [
  { name: "double", apply: (v) => `"${v}"` },
  { name: "single", apply: (v) => `'${v}'` },
  { name: "unquoted", apply: (v) => v },
  { name: "backtick", apply: (v) => "`" + v + "`" },
  { name: "spaced-unquoted", apply: (v) => ` ${v} ` },
];

/** Keyword spellings a keyword-anchored secret regex has to survive. */
export const SECRET_KEYWORDS = [
  "password", "passwd", "secret", "api_key", "apiKey", "api-key", "token", "access_token",
  "client_secret", "private_key", "auth", "credential", "pwd",
];

/** Credential shapes, with a note on why each is here. */
export const SECRET_VALUES = [
  { name: "openai-sk", value: "sk-Ab3dEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf", note: "the shape the shipped regex does catch" },   // scrub-allow: fixture, synthetic by construction
  { name: "openai-sk-proj", value: "sk-proj-Ab3dEfGhIjKlMnOpQrStUvWxYz0123456789", note: "the project-scoped format the shipped regex misses because of the hyphen" },
  { name: "aws-akia", value: "AKIAIOSFODNN7EXAMPLE", note: "the AWS access key id the shipped regex catches" },
  { name: "aws-asia", value: "ASIAIOSFODNN7EXAMPLE", note: "the temporary-credential sibling AKIA does not match" },
  { name: "github-pat", value: "ghp_16CharsOfNoise0123456789abcdefghij", note: "GitHub personal access token, no enumerated shape in the shipped regex" },   // scrub-allow: fixture, synthetic by construction
  { name: "slack-bot", value: "xoxb-2401234567-2409876543-AbCdEfGhIjKlMnOpQrStUvWx", note: "Slack bot token" },
  { name: "stripe-live", value: "rk_live_51HabcdEfGhIjKlMnOpQrStUv", note: "Stripe restricted live key, the value ev01 used" },
  { name: "google-api", value: "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q", note: "Google API key" },   // scrub-allow: fixture, synthetic by construction
  { name: "jwt", value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", note: "a signed JWT, which is a bearer credential with no keyword nearby" },
  { name: "postgres-url", value: "postgres://admin:hunter2hunter2@db.internal:5432/prod", note: "a credential inside a connection string" },
  { name: "plain-password", value: "correct-horse-battery-staple", note: "the a26/a31 shape: an ordinary password with no vendor prefix at all" },
  { name: "pem-body", value: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj", note: "PEM body with the BEGIN header stripped, the ev22 shape" },
];

/** Fetcher tokens, from the net-to-exec control's own list. */
export const FETCHERS = [
  { name: "curl", render: (u) => `curl -fsSL ${u}` },
  { name: "wget", render: (u) => `wget -qO- ${u}` },
  { name: "fetch", render: (u) => `fetch(${JSON.stringify(u)})` },
  { name: "https-get", render: (u) => `https.get(${JSON.stringify(u)})` },
  { name: "axios", render: (u) => `axios.get(${JSON.stringify(u)})` },
  { name: "got", render: (u) => `got(${JSON.stringify(u)})` },
  { name: "urllib", render: (u) => `urllib.request.urlopen(${JSON.stringify(u)}).read()` },
  { name: "requests", render: (u) => `requests.get(${JSON.stringify(u)}).text` },
  { name: "invoke-webrequest", render: (u) => `iwr ${u}` },
  { name: "python-httpx", render: (u) => `httpx.get(${JSON.stringify(u)}).text` },
];

/** Exec sinks, from the same list. Every one of these turns fetched bytes into running code. */
export const SINKS = [
  { name: "pipe-sh", render: (f) => `${f} | sh` },
  { name: "pipe-bash", render: (f) => `${f} | bash` },
  { name: "pipe-zsh", render: (f) => `${f} | zsh` },
  { name: "pipe-python", render: (f) => `${f} | python3` },
  { name: "pipe-node", render: (f) => `${f} | node` },
  { name: "pipe-ruby", render: (f) => `${f} | ruby` },
  { name: "process-substitution", render: (f) => `source <(${f})` },
  { name: "command-substitution", render: (f) => `sh -c "$(${f})"` },
  { name: "eval", render: (f) => `eval(${f})` },
  { name: "new-function", render: (f) => `new Function(${f})()` },
  { name: "vm-runinthiscontext", render: (f) => `vm.runInThisContext(${f})` },
  { name: "child-process-exec", render: (f) => `child_process.execSync(${f})` },
  { name: "os-system", render: (f) => `os.system(${f})` },
  { name: "python-exec", render: (f) => `exec(${f})` },
];

/** Hosts an exfiltrating or fetching payload reaches for. */
export const HOSTILE_HOSTS = [
  "evil.example", "198.51.100.7", "collector.attacker.test", "cdn.pastebin.example",
  "raw.githubusercontent.example", "169.254.169.254", "telemetry.internal.example",
];

// REGISTRY_ALLOWLIST used to live here, a seven host copy of a production constant that ships
// ten. It had exactly one importer, generators/supply-chain.mjs, which imported it and never
// used it: generation is driven by HOSTILE_HOSTS above. So it was a dead copy of a live
// constant, which is the drift hazard with none of the benefit, and deleting it is the only
// fix that cannot go stale again. Anything needing the real list imports
// DEFAULT_REGISTRY_ALLOWLIST from the built policy-context, as replay-v2.mjs does.

/** Extensions for a source file that a turn might legitimately be editing. */
export const SOURCE_FILES = [
  "index.js", "app.ts", "handler.py", "server.go", "util.rb", "main.rs", "helpers.mjs",
  "service.tsx", "worker.cjs", "model.py",
];

// Ground truth for the polarity job: WHICH keys does the arm's classifier actually call "protective"
// across 19,102 real commits, and which of those move true->false? An inversion set should be built
// from this population, not from a list somebody imagines.
import fs from "node:fs";
import readline from "node:readline";
const PROTECTIVE=/(verif|validat|audit|logging|log_file|enforce|require|restrict|block|prevent|deny|protect|secure|encrypt|signature|signing|integrity|checksum|sanitiz|escape|harden|firewall|waf|shield|guard|scan|mfa|2fa|totp|hsts|csrf|xsrf|xss|tls|ssl|https|certificat|sandbox|isolat|quarantine|retention|purge|expiry|expiration|rotate|rotation|throttl|ratelimit|rate_limit)/i;
const SECURITY_NOUN=/(security|auth|authz|authn|authoriz|authentic|permission|credential|password|secret|token|cert|policy|acl|rbac|iam|cors|csp)/i;
const dir = process.env.HOME + "/Developer/CodeJam/research/realworld-prior/scenarios/";
const LINE = /^\s*['"]?([A-Za-z0-9_.\-]+)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_.\-]+)['"]?\s*$/;
const parse = (t) => { const m = new Map();
  for (const l of (t ?? "").split("\n")) { const g = LINE.exec(l); if (g && !m.has(g[1])) m.set(g[1], g[2]); } return m; };

const flips = new Map();   // key -> count of true->false style moves
for (const f of fs.readdirSync(dir).filter((x)=>x.startsWith("rw-")&&x.endsWith(".jsonl"))) {
  const rl = readline.createInterface({ input: fs.createReadStream(dir+f), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let s; try { s = JSON.parse(line); } catch { continue; }
    for (const e of s.effect_set ?? []) {
      if (e.kind !== "modify" || !e.real_content) continue;
      const was = parse(e.real_content), now = parse(e.content);
      for (const [k, v] of now) {
        const o = was.get(k);
        if (o === undefined || o === v) continue;
        const prot = PROTECTIVE.test(k), noun = SECURITY_NOUN.test(k);
        if (!prot && !noun) continue;
        if (!/^(true|1|on|yes|require|verify|strict|enforce)$/i.test(o)) continue;
        if (!/^(false|0|off|no|none|optional|permissive|allow)$/i.test(v)) continue;
        const via = prot ? "PROTECTIVE" : "SECURITY_NOUN";
        const id = `${k}  [${via}]  ${o}->${v}`;
        flips.set(id, (flips.get(id) ?? 0) + 1);
      }
    }
  }
}
console.log(`  distinct protective-looking strict->loose key moves in 19,102 real commits: ${flips.size}`);
for (const [k,n] of [...flips].sort((a,b)=>b[1]-a[1])) console.log(`    ${String(n).padStart(3)}  ${k}`);

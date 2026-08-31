import type { EffectRecord } from "./policy-types.js";

/**
 * The host side of the egress broker: what the broker is told to do, and how what it recorded
 * becomes part of the turn's effect set.
 *
 * The broker itself is `apps/server/broker/*.mjs`, deliberately dependency-free plain ESM so the
 * same file the tests exercise is the file the container bind-mounts read-only. This module never
 * imports it: everything here is host-side bookkeeping.
 */

/**
 * What a turn may reach at all. Exact host and port, no wildcards and no suffix matching, because
 * "anything ending in .npmjs.org" is an allowlist that an attacker who controls a DNS name defeats.
 * The default is the model provider plus the package registries the organizers' own acceptance
 * task needs (`npm install`), and nothing else.
 */
export const DEFAULT_EGRESS_ALLOWLIST = Object.freeze([
  "registry.npmjs.org:443",
  "registry.yarnpkg.com:443",
  "pypi.org:443",
  "files.pythonhosted.org:443",
] as const);

/**
 * One endpoint an operator has declared read-only, so calls to it pass through live instead of
 * being held. All three parts are required together: the exact destination host, the methods the
 * declaration covers, and the path shape.
 *
 * A bare path regex was the earlier shape of this, and it could not say which host or which method
 * it meant. `^/-/` is a registry read prefix and also the prefix of `PUT /-/user/...`, which
 * publishes, so a path-only rule sent that write out live and unheld on any allowlisted host.
 */
export interface ReadOnlyDeclaration {
  /** Exact host, lowercased. No wildcards and no suffix matching, for the allowlist's reason. */
  host: string;
  /**
   * The port, required, because the allowlist key is a host AND a port and a declaration has to be
   * at least as specific as the thing it makes an exception to. Without it a rule written for the
   * catalog service on 8080 also covered the admin service on 9090 of the same host, whenever both
   * were allowlisted, and nothing in the rule said so.
   */
  port: number;
  /** The methods this declaration covers, named one by one. No wildcard and no "all". */
  methods: string[];
  /**
   * A regular expression source the whole request path, query included, must match. EVERY BRANCH
   * anchored at both ends, `^...$`, and rejected here if it is not: `^/catalog` reads as one
   * endpoint and matches `/catalog-admin/delete` as well, and `^/a|^/b$` is that same prefix rule
   * hiding behind an alternation, so the breadth of a rule has to be visible in the rule. Write
   * `^/catalog(\?.*)?$` for "that endpoint, with or without a query".
   *
   * Also rejected: an unbounded repetition of an unbounded group, `(a+)+`, whose backtracking the
   * sandboxed code drives by choosing the path it sends.
   */
  pattern: string;
}

/**
 * Empty, deliberately. Nothing is read-like because of its path unless an operator declared it for
 * a named host, so an undeclared write is held and reviewed rather than sent. GET, HEAD and
 * OPTIONS stay live on their own account (see `classifyCall`), which is what keeps `npm install`
 * working with no declaration at all.
 *
 * Frozen, because it is read at every config build: one `push` from any importer in the process
 * would make an endpoint read-only for every later turn, from a line nowhere near the broker.
 */
export const DEFAULT_READ_ONLY_DECLARATIONS: readonly ReadOnlyDeclaration[] = Object.freeze([]);

/**
 * Is this source anchored at the end? A trailing "$" preceded by an odd number of backslashes is
 * an escaped dollar sign, a literal character, not an anchor: `^/price\$` matches `/price$fx` and
 * every other path that starts that way.
 */
function endsWithAnchor(source: string): boolean {
  if (!source.endsWith("$")) return false;
  let backslashes = 0;
  for (let i = source.length - 2; i >= 0 && source[i] === "\\"; i -= 1) backslashes += 1;
  return backslashes % 2 === 0;
}

/**
 * The alternatives of a pattern at depth zero, so each can be checked on its own.
 *
 * A test on the first and last character of the whole source is not the anchoring rule the error
 * message states. `^/a|^/b$` passes it and is two rules, of which the first is a prefix rule
 * covering /a-admin/delete and every other path beginning /a. The breadth of a rule has to be
 * visible in the rule, and that has to hold branch by branch.
 */
function topLevelBranches(source: string): string[] {
  const branches: string[] = [];
  let depth = 0;
  let inClass = false;
  let start = 0;
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "(") depth += 1;
    else if (ch === ")") depth = Math.max(0, depth - 1);
    else if (ch === "|" && depth === 0) {
      branches.push(source.slice(start, i));
      start = i + 1;
    }
  }
  branches.push(source.slice(start));
  return branches;
}

/** Does this group body give the engine more than one way to match the same text? */
function bodyIsAmbiguous(body: string): boolean {
  let inClass = false;
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "|" || ch === "*" || ch === "+") return true;
    else if (ch === "{" && /^\{\d+,\}/.test(body.slice(i))) return true;
  }
  return false;
}

/**
 * An unbounded repetition of a group that is itself unbounded or alternating: `(a+)+`, `(a|a)*`,
 * `((a*)*)+`. The pattern is operator-supplied and the subject is the request path, which code
 * inside the sandbox chooses, and the broker runs the match on the same event loop that serves the
 * agent's model channel. `^/(a+)+b$` against 32 a-characters is 25 seconds of that loop, and each
 * further character doubles it.
 *
 * A check on the SHAPE of the pattern, not a proof of linear time: it refuses the classic
 * construction, it does not refuse every slow expression, and the bounded repetition operators
 * actually write, `(\?.*)?`, stays allowed.
 */
function hasCatastrophicNesting(source: string): boolean {
  const stack: number[] = [];
  let inClass = false;
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "(") stack.push(i);
    else if (ch === ")") {
      const start = stack.pop();
      if (start === undefined) continue;
      if (!/^(?:[*+]|\{\d+,\})/.test(source.slice(i + 1))) continue;
      if (bodyIsAmbiguous(source.slice(start + 1, i))) return true;
    }
  }
  return false;
}

/**
 * Validates operator-supplied declarations at the moment the config is built, so a typo is an
 * error the operator sees here rather than a rule that silently never matches (or, worse, one that
 * matches more than it was meant to).
 *
 * This is the gate on the config THIS code writes. A broker.json can also be hand-written, so the
 * broker applies the same rules again on its own side (`vetReadOnlyDeclarations` in server.mjs),
 * where a declaration that fails them is dropped rather than thrown: there, refusing to run would
 * be a config typo taking the turn down. The two rule sets are kept in step by a table in
 * broker-declaration-config.test.ts that asserts they accept and refuse the same patterns.
 */
export function normaliseReadOnlyDeclarations(input: readonly ReadOnlyDeclaration[]): ReadOnlyDeclaration[] {
  return input.map((declaration, index) => {
    const where = "readOnlyDeclarations[" + index + "]";
    const host = String(declaration?.host ?? "").trim().toLowerCase();
    if (!host) throw new Error(where + ": a read-only declaration needs an exact host");
    if (host.includes("*")) throw new Error(where + ": a read-only host is exact, no wildcards");
    if (host.includes(":")) {
      throw new Error(where + ": the host carries a port; name the port in the port field instead");
    }
    const port = Number(declaration?.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(
        where +
          ": a read-only declaration needs the port it applies to, 1 to 65535. The allowlist key " +
          "is a host and a port, so a host-only declaration covers every allowlisted port of that host.",
      );
    }
    const methods = Array.isArray(declaration?.methods) ? declaration.methods : [];
    if (!methods.length) throw new Error(where + ": a read-only declaration needs at least one method");
    const upper = methods.map((method) => String(method).trim().toUpperCase());
    if (upper.some((method) => !/^[A-Z]+$/.test(method))) {
      throw new Error(where + ": methods are named one by one, no wildcard");
    }
    const pattern = String(declaration?.pattern ?? "");
    if (!pattern) throw new Error(where + ": a read-only declaration needs a path pattern");
    try {
      new RegExp(pattern);
    } catch {
      throw new Error(where + ": the path pattern is not a valid regular expression");
    }
    if (!topLevelBranches(pattern).every((branch) => branch.startsWith("^") && endsWithAnchor(branch))) {
      throw new Error(
        where +
          ": every branch of the path pattern must be anchored at both ends, so a rule is as broad " +
          "as it looks. Write ^/catalog(\\?.*)?$ rather than ^/catalog, which also covers " +
          "/catalog-admin/delete, and ^/a$|^/b$ rather than ^/a|^/b$, whose first branch is a prefix.",
      );
    }
    if (hasCatastrophicNesting(pattern)) {
      throw new Error(
        where +
          ": the path pattern repeats an unbounded group without bound, and the subject it is " +
          "matched against is a request path the sandboxed code chooses. ^/(a+)+b$ against 32 " +
          "characters is 25 seconds of the broker's event loop. Write the repetition once.",
      );
    }
    return { host, port, methods: upper, pattern };
  });
}

export interface BrokerLaunchConfig {
  proxyPort: number;
  modelPort: number;
  host: string;
  allowlist: string[];
  readOnlyDeclarations: ReadOnlyDeclaration[];
  decoyHost: string;
  modelUpstream: string;
  modelHosts: string[];
  logPath: string;
  heldPath: string;
  pendingDir: string;
  protectedFiles: string[];
}

export interface HeldRecord {
  effectId: string;
  method: string;
  host: string;
  port: number;
  urlPath: string;
  bytes: number;
  sha256: string;
  provenance: string | null;
  secretPattern: string | null;
  highEntropy?: boolean;
  entropy?: number;
}

export interface EgressDecision {
  kind: "egress";
  n?: number;
  ts?: string;
  method?: string;
  target?: string;
  class?: string;
  decision: string;
  reason?: string | null;
  effectId?: string;
  provenance?: string | null;
  secretPattern?: string | null;
  /**
   * False on an allowed CONNECT row, and only there: those bytes were allowlisted by host and port
   * and then piped, so no read-like or write-like judgement was made about them and none was held.
   * Absent on the plain-HTTP rows, which are all classified.
   */
  classified?: boolean;
}

/** Paths inside the broker container. Fixed, because they are mount destinations we choose. */
export const BROKER_PATHS = {
  code: "/broker",
  config: "/broker-config/broker.json",
  logDir: "/log",
  pendingDir: "/pending",
  decisionLog: "/log/egress.jsonl",
  heldLog: "/log/held.jsonl",
} as const;

export function buildBrokerLaunchConfig(input: {
  allowlist: string[];
  decoyHost: string;
  modelUpstream: string;
  proxyPort: number;
  modelPort: number;
  protectedFiles: string[];
  readOnlyDeclarations?: readonly ReadOnlyDeclaration[];
}): BrokerLaunchConfig {
  return {
    proxyPort: input.proxyPort,
    modelPort: input.modelPort,
    host: "0.0.0.0",
    allowlist: [...input.allowlist],
    readOnlyDeclarations: normaliseReadOnlyDeclarations(
      input.readOnlyDeclarations ?? DEFAULT_READ_ONLY_DECLARATIONS,
    ),
    decoyHost: input.decoyHost,
    modelUpstream: input.modelUpstream,
    modelHosts: [],
    logPath: BROKER_PATHS.decisionLog,
    heldPath: BROKER_PATHS.heldLog,
    pendingDir: BROKER_PATHS.pendingDir,
    protectedFiles: input.protectedFiles,
  };
}

/**
 * One held write becomes one effect in the same set as the file effects, so the policy answers a
 * single question about the whole turn instead of one question per subsystem. The synthetic path
 * is deliberately not a filesystem path: nothing downstream should ever try to resolve or write it.
 */
export function heldRecordToEffect(record: HeldRecord): EffectRecord {
  const effect: EffectRecord = {
    path: `net:${record.method} ${record.host}:${record.port}${record.urlPath}`,
    kind: "outbound",
    method: record.method,
    host: record.host,
    port: record.port,
    urlPath: record.urlPath,
    bytes: record.bytes,
    sha256: record.sha256,
    effectClass: "outbound",
  };
  if (record.provenance) effect.provenance = record.provenance;
  if (record.secretPattern) effect.secretPattern = record.secretPattern;
  if (record.highEntropy) effect.highEntropy = true;
  return effect;
}

/** Reads a JSON-lines file, skipping any torn tail rather than failing the whole turn. */
export function parseJsonLines<T>(text: string): T[] {
  const out: T[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as T);
    } catch {
      /* a half-written last line is skipped, not fatal */
    }
  }
  return out;
}

/** The counts the journal carries for a turn, so an operator sees the shape without the payloads. */
export function summariseDecisions(decisions: EgressDecision[]): Record<string, number> {
  const summary: Record<string, number> = {};
  for (const decision of decisions) {
    const key = String(decision.decision ?? "UNKNOWN").toLowerCase();
    summary[key] = (summary[key] ?? 0) + 1;
  }
  return summary;
}

/** The host of a provider base URL, which is what has to be on the allowlist for the broker itself. */
export function providerHostPort(baseUrl: string): string | null {
  try {
    const url = new URL(baseUrl);
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    return `${url.hostname}:${port}`;
  } catch {
    return null;
  }
}

/**
 * A structured differ for package manifests and lockfiles.
 *
 * Five red-team payloads reached `commit` because the shipped policy read a manifest as text and
 * looked for one substring, `"postinstall"`. None of these five contains it: a typosquatted name
 * added to `dependencies`; an `--extra-index-url` line in `requirements.txt`; a `resolved` URL and
 * `integrity` hash repointed in `package-lock.json` while the version stayed put; the same shape in
 * `yarn.lock`; a `git+https://` dependency in `pyproject.toml`. Each one fetches attacker code at
 * the NEXT install, outside the turn, which is why nothing in the turn's own content gives it away.
 *
 * So the manifest is parsed on both sides of the turn and the DIFFERENCE is what gets judged. The
 * file is pure: it takes two strings and returns typed deltas, and it decides nothing. The
 * decisions live in `rules/dependency-change.ts`.
 *
 * Three rules hold everywhere below.
 *
 * A manifest that CANNOT be read is not an empty manifest: a parser that fails returns `null` and
 * the difference becomes one delta that says so, because a three-byte prefix must not be able to
 * turn a discard into a commit. The six scanning parsers cannot fail that way, so one narrow case
 * stands in for them: a file that held entries before the turn and holds text but no entries after
 * it is an unknown too.
 *
 * A field is read if an installer downloads from it, not if it is called `dependencies`:
 * `overrides`, `resolutions`, `pnpm.overrides`, `peerDependencies` and `packageManager` all name
 * something that gets fetched.
 *
 * And every field lands on a key no other field can produce. That last one is not bookkeeping. The
 * flattening used to collapse `{"a:b": url}` onto `{"a": {"b": url}}`, and npm's `"."` key at the
 * top of an `overrides` block produced the bare string `overrides`, which is a legal npm package
 * name, so a manifest could put an off-list url in `dependencies` under that name and have the
 * redirect block overwrite it. The url then reached no delta at all and the turn committed. Keys
 * are built by `fieldKey`, whose segments escape the separator, so the mapping is injective.
 */
import { canonicalise, partsOf } from "./effect-classifier.js";
import { DEFAULT_REGISTRY_ALLOWLIST } from "./policy-context.js";

/**
 * Re-exported, not redeclared. This file used to carry its OWN eight-host copy of the list while
 * production passed the ten-host one from `policy-context.ts`, and `isOfflistHost` fell back to the
 * local copy only when the caller passed an empty array, which the product path never does and
 * every test does. So `sum.golang.org` and `repo.maven.apache.org` were allowed in production and
 * discarded under test: the suite scored a list nothing ran.
 */
export { DEFAULT_REGISTRY_ALLOWLIST };

export type ManifestKind =
  | "package.json"
  | "npm-lock"
  | "yarn.lock"
  | "pnpm-lock"
  | "requirements.txt"
  | "pyproject.toml"
  | "cargo.toml"
  | "go.mod";

export type DeltaKind =
  | "dep-added"
  | "dep-spec-changed"
  | "script-added"
  | "script-changed"
  | "index-url-added"
  | "build-system-changed"
  | "lock-repointed"
  | "lock-integrity-changed"
  | "lock-entry-added";

export interface DependencyDelta {
  readonly kind: DeltaKind;
  /** the dependency, script or lock entry this delta is about */
  readonly name: string;
  readonly from?: string;
  readonly to?: string;
  /** every host reachable from the value this delta introduces */
  readonly hosts: readonly string[];
}

interface LockEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
}

export interface ManifestFacts {
  readonly deps: Readonly<Record<string, string>>;
  readonly scripts: Readonly<Record<string, string>>;
  readonly locks: Readonly<Record<string, LockEntry>>;
  readonly indexUrls: readonly string[];
  readonly buildSystem: readonly string[];
}

const EMPTY: ManifestFacts = { deps: {}, scripts: {}, locks: {}, indexUrls: [], buildSystem: [] };

/** Which parser, if any, applies to this path. Keyed on the canonical basename, at any depth. */
export function manifestKindOf(rawPath: string): ManifestKind | null {
  const { base } = partsOf(rawPath);
  if (base === "package.json") return "package.json";
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") return "npm-lock";
  if (base === "yarn.lock") return "yarn.lock";
  if (base === "pnpm-lock.yaml") return "pnpm-lock";
  if (/^requirements[^/]*\.txt$/.test(base)) return "requirements.txt";
  if (base === "pyproject.toml") return "pyproject.toml";
  if (base === "cargo.toml") return "cargo.toml";
  if (base === "go.mod") return "go.mod";
  return null;
}

/**
 * Every host a value can reach. Covers `https://h/x`, `git+ssh://git@h/x`, `scp`-style `git@h:x`
 * and credentials in the authority, because each of those is a way to name a download source.
 */
export function hostsIn(value: string): string[] {
  const found = new Set<string>();
  for (const m of value.matchAll(/[a-z][a-z0-9+.\-]*:\/\/([^/\s"'`,;)\]}]+)/gi)) {
    const authority = m[1] ?? "";
    const afterCredentials = authority.slice(authority.lastIndexOf("@") + 1);
    const host = afterCredentials.split(":")[0] ?? "";
    if (host.length > 0) found.add(host.toLowerCase());
  }
  for (const m of value.matchAll(/(?:^|\s)[\w.\-]+@([\w.\-]+):[^\s]/g)) {
    const host = m[1];
    if (host !== undefined && host.includes(".")) found.add(host.toLowerCase());
  }
  return [...found];
}

const asStringMap = (value: unknown): Record<string, string> => {
  if (typeof value !== "object" || value === null) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === "string") out[k] = v;
  }
  return out;
};

/** A JSON document, or `null` when the text is not one, which is not the same as an empty one. */
const jsonObject = (text: string): Record<string, unknown> | null => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
};

/** Fields whose entries an installer resolves and downloads. npm installs peers on its own. */
const DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

/** How deep a nested `overrides` block is followed before we stop. */
const REDIRECT_DEPTH_LIMIT = 8;

/** npm's key for the block's own package. No npm package may be named `.`, so it cannot be one. */
const SELF_SEGMENT = ".";

/**
 * One segment of a field-prefixed key, with the separator and the escape character made literal.
 *
 * Without this the flattening was not injective and one entry silently replaced another, which is
 * the same as dropping it: `{"a:b": url}` and `{"a": {"b": url}}` produced one key, and so did
 * `{"foo.bar": url}` and `{"foo": {"bar": url}}` back when nesting joined on a `.`. A package name
 * npm accepts contains neither `\` nor `:`, so escaping is the identity on every real name and
 * `lodash` still reads as `lodash` in a review.
 */
const escapeSegment = (key: string): string => key.replace(/\\/g, "\\\\").replace(/:/g, "\\:");

/**
 * The key an entry from `field` lands on. `dependencies` alone keeps the bare name; every other
 * field is prefixed with its own name and a `:`, and the first UNESCAPED `:` is always that
 * separator, so no bare name can be spelled to look like a prefixed one.
 *
 * An empty path is the field itself rather than a child of it, and it is written `field:.`, never
 * the bare `field`. That distinction is the whole fix for the worst hole here: `overrides`,
 * `resolutions` and `packageManager` are legal npm package names, so the bare form let an
 * `overrides` block with npm's `"."` key overwrite the entry a dependency of that name had just
 * put in the map, and an off-list url in `dependencies` went from a discard to invisible.
 */
const fieldKey = (field: string, path: readonly string[]): string =>
  `${field}:${(path.length === 0 ? [SELF_SEGMENT] : path).map(escapeSegment).join(":")}`;

/**
 * `overrides` (npm), `resolutions` (yarn) and `pnpm.overrides` repoint a package, including a
 * TRANSITIVE one, at a source of the manifest's choosing, so an unlisted host there has a strictly
 * larger blast radius than the same host in `dependencies`. Both shapes nest, so they are flattened
 * onto a path; npm's `"."` key means the block's own package rather than a child of it.
 */
function collectRedirects(
  value: unknown,
  field: string,
  path: readonly string[],
  out: Record<string, string>,
  depth: number,
): void {
  // absent, which is a fact about the manifest and not something to report
  if (value === undefined || value === null) return;
  // the whole block written as a bare scalar. npm rejects that shape, so nothing legitimate writes
  // it, which is exactly why it must not be the one thing that goes past the differ unread
  if (typeof value !== "object") {
    out[fieldKey(field, path)] = String(value);
    return;
  }
  // deeper than anything real, so stop walking, but keep the text: dropping it here would be one
  // more way to hide a url from the differ, and the whole point of this file is that nothing is
  // dropped in silence
  if (depth > REDIRECT_DEPTH_LIMIT || Array.isArray(value)) {
    out[fieldKey(field, path)] = JSON.stringify(value) ?? "";
    return;
  }
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    const next = key === SELF_SEGMENT ? path : [...path, key];
    if (typeof raw === "string") {
      out[fieldKey(field, next)] = raw;
      continue;
    }
    if (typeof raw === "object" && raw !== null) {
      collectRedirects(raw, field, next, out, depth + 1);
      continue;
    }
    out[fieldKey(field, next)] = JSON.stringify(raw) ?? "";
  }
}

/**
 * Only `dependencies` keeps its bare package name, so a review still reads `lodahs ^1.0.0`. Every
 * other field goes through `fieldKey`, which prefixes it with the field it came from. That is not
 * decoration: with bare keys the fields were merged into one map and the later field silently
 * overwrote the earlier one, so the same name in `dependencies` and `devDependencies` cancelled a
 * change to the `dependencies` side out entirely, and an `overrides` block whose only key was
 * npm's `"."` did the same to a package actually named `overrides`.
 */
function parsePackageJson(text: string): ManifestFacts | null {
  const doc = jsonObject(text);
  if (doc === null) return null;
  const deps: Record<string, string> = {};
  for (const field of DEPENDENCY_FIELDS) {
    const bare = field === "dependencies";
    for (const [name, spec] of Object.entries(asStringMap(doc[field]))) {
      deps[bare ? escapeSegment(name) : fieldKey(field, [name])] = spec;
    }
  }
  collectRedirects(doc.overrides, "overrides", [], deps, 0);
  collectRedirects(doc.resolutions, "resolutions", [], deps, 0);
  const pnpm = doc.pnpm;
  if (typeof pnpm === "object" && pnpm !== null && !Array.isArray(pnpm)) {
    collectRedirects((pnpm as Record<string, unknown>).overrides, "pnpm.overrides", [], deps, 0);
  }
  // corepack downloads and then EXECUTES whatever this names, so it is a download source too. It
  // is a scalar field, so its key is the field itself: bare, it overwrote a dependency of the
  // same name, and the url that dependency carried disappeared with it.
  if (typeof doc.packageManager === "string") deps[fieldKey("packageManager", [])] = doc.packageManager;
  return { deps, scripts: asStringMap(doc.scripts), locks: {}, indexUrls: [], buildSystem: [] };
}

/** `package-lock.json` and `npm-shrinkwrap.json`: both the v2 `packages` map and the v1 tree. */
function parseNpmLock(text: string): ManifestFacts | null {
  const parsed = jsonObject(text);
  if (parsed === null) return null;
  const locks: Record<string, LockEntry> = {};
  const visit = (node: unknown, prefix: string): void => {
    if (typeof node !== "object" || node === null) return;
    for (const [key, raw] of Object.entries(node as Record<string, unknown>)) {
      if (typeof raw !== "object" || raw === null) continue;
      const entry = raw as Record<string, unknown>;
      const name = prefix.length > 0 ? `${prefix}/${key}` : key;
      const lock: LockEntry = {};
      if (typeof entry.version === "string") lock.version = entry.version;
      if (typeof entry.resolved === "string") lock.resolved = entry.resolved;
      if (typeof entry.integrity === "string") lock.integrity = entry.integrity;
      if (lock.version !== undefined || lock.resolved !== undefined || lock.integrity !== undefined) {
        locks[name] = lock;
      }
      visit(entry.dependencies, name);
    }
  };
  visit(parsed.packages, "");
  visit(parsed.dependencies, "");
  return { ...EMPTY, locks };
}

/** `yarn.lock`: unindented `spec:` headers, indented `version` / `resolved` / `integrity` fields. */
function parseYarnLock(text: string): ManifestFacts {
  const locks: Record<string, LockEntry> = {};
  let current: string | null = null;
  for (const line of text.split("\n")) {
    if (line.trim().length === 0 || line.trimStart().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      current = line.replace(/:\s*$/, "").replace(/"/g, "").trim();
      if (current.length > 0 && locks[current] === undefined) locks[current] = {};
      continue;
    }
    if (current === null) continue;
    const entry = locks[current];
    if (entry === undefined) continue;
    const field = /^\s+(version|resolved|integrity)\s+"?([^"\n]+)"?\s*$/.exec(line);
    if (field === null) continue;
    const value = (field[2] ?? "").trim();
    if (field[1] === "version") entry.version = value;
    else if (field[1] === "resolved") entry.resolved = value;
    else entry.integrity = value;
  }
  return { ...EMPTY, locks };
}

/** `pnpm-lock.yaml`: two-space keys with `resolution: {integrity: ...}` or a `tarball:` under them. */
function parsePnpmLock(text: string): ManifestFacts {
  const locks: Record<string, LockEntry> = {};
  let current: string | null = null;
  for (const line of text.split("\n")) {
    if (line.trim().length === 0 || line.trimStart().startsWith("#")) continue;
    const key = /^\s{0,4}(\/?[^\s:][^:]*):\s*$/.exec(line);
    if (key !== null && !/^\s*(resolution|dependencies|packages|devDependencies|importers)\s*:/.test(line)) {
      current = (key[1] ?? "").trim();
      if (current.length > 0 && locks[current] === undefined) locks[current] = {};
      continue;
    }
    if (current === null) continue;
    const entry = locks[current];
    if (entry === undefined) continue;
    const integrity = /integrity:\s*([^\s,}]+)/.exec(line);
    if (integrity !== null) entry.integrity = integrity[1] ?? "";
    const tarball = /(?:tarball|resolved):\s*([^\s,}]+)/.exec(line);
    if (tarball !== null) entry.resolved = tarball[1] ?? "";
    const version = /^\s+version:\s*([^\s]+)/.exec(line);
    if (version !== null) entry.version = version[1] ?? "";
  }
  return { ...EMPTY, locks };
}

/** `requirements.txt` and friends: index URLs are the interesting half, not the pinned versions. */
function parseRequirements(text: string): ManifestFacts {
  const deps: Record<string, string> = {};
  const indexUrls: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0]?.trim() ?? "";
    if (line.length === 0) continue;
    const index = /^(--index-url|--extra-index-url|-i|--find-links|-f|--trusted-host)\s+(\S+)/.exec(line);
    if (index !== null) {
      indexUrls.push(index[2] ?? "");
      continue;
    }
    if (line.startsWith("-")) continue;
    if (/^(git\+|https?:\/\/)/.test(line)) {
      deps[line] = line;
      continue;
    }
    const named = /^([A-Za-z0-9._\-\[\]]+)\s*(.*)$/.exec(line);
    if (named !== null) deps[(named[1] ?? "").toLowerCase()] = named[2] ?? "";
  }
  return { ...EMPTY, deps, indexUrls };
}

/** Reads the string literals out of a TOML array that may run over several lines. */
function tomlArrayValues(lines: readonly string[], startIndex: number): { values: string[]; nextIndex: number } {
  const values: string[] = [];
  let index = startIndex;
  let buffer = "";
  for (; index < lines.length; index++) {
    buffer += lines[index] ?? "";
    if (buffer.includes("]")) break;
    buffer += "\n";
  }
  for (const m of buffer.matchAll(/"([^"]*)"|'([^']*)'/g)) values.push(m[1] ?? m[2] ?? "");
  return { values, nextIndex: index };
}

function parsePyproject(text: string): ManifestFacts {
  const deps: Record<string, string> = {};
  const buildSystem: string[] = [];
  const lines = text.split("\n");
  let section = "";
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? "").trim();
    if (line.startsWith("[")) {
      section = line.replace(/^\[+|\]+$/g, "");
      continue;
    }
    const arrayStart = /^(dependencies|requires)\s*=\s*\[/.exec(line);
    if (arrayStart !== null) {
      const { values, nextIndex } = tomlArrayValues(lines, i);
      i = nextIndex;
      const target = section === "build-system" ? buildSystem : null;
      if (target !== null) target.push(...values);
      else for (const v of values) deps[v] = v;
      continue;
    }
    if (/dependencies$/.test(section)) {
      const named = /^([A-Za-z0-9._\-]+)\s*=\s*(.+)$/.exec(line);
      if (named !== null) deps[(named[1] ?? "").toLowerCase()] = (named[2] ?? "").trim();
    }
  }
  return { ...EMPTY, deps, buildSystem };
}

function parseCargoToml(text: string): ManifestFacts {
  const deps: Record<string, string> = {};
  const buildSystem: string[] = [];
  let section = "";
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0]?.trim() ?? "";
    if (line.length === 0) continue;
    if (line.startsWith("[")) {
      section = line.replace(/^\[+|\]+$/g, "");
      continue;
    }
    if (section === "package") {
      const build = /^build\s*=\s*(.+)$/.exec(line);
      if (build !== null) buildSystem.push((build[1] ?? "").replace(/"/g, "").trim());
      continue;
    }
    if (/dependencies$/.test(section)) {
      const named = /^([A-Za-z0-9._\-]+)\s*=\s*(.+)$/.exec(line);
      if (named !== null) deps[(named[1] ?? "").toLowerCase()] = (named[2] ?? "").trim();
    }
  }
  return { ...EMPTY, deps, buildSystem };
}

function parseGoMod(text: string): ManifestFacts {
  const deps: Record<string, string> = {};
  let inRequireBlock = false;
  for (const raw of text.split("\n")) {
    const line = raw.split("//")[0]?.trim() ?? "";
    if (line.length === 0) continue;
    if (/^require\s*\($/.test(line)) { inRequireBlock = true; continue; }
    if (inRequireBlock && line === ")") { inRequireBlock = false; continue; }
    const single = /^require\s+(\S+)\s+(\S+)/.exec(line);
    if (single !== null) { deps[single[1] ?? ""] = single[2] ?? ""; continue; }
    const replace = /^replace\s+(\S+)\s*=>\s*(.+)$/.exec(line);
    if (replace !== null) { deps[replace[1] ?? ""] = (replace[2] ?? "").trim(); continue; }
    if (inRequireBlock) {
      const entry = /^(\S+)\s+(\S+)/.exec(line);
      if (entry !== null) deps[entry[1] ?? ""] = entry[2] ?? "";
    }
  }
  return { ...EMPTY, deps };
}

/**
 * A parser returns `null` when it could not read the text at all. Only the two JSON parsers can:
 * the line-based ones scan for shapes they recognise and legitimately find none, so an empty result
 * from them is a fact about the file (a `go.mod` with no `require`, a comment-only
 * `requirements.txt`) rather than an admission of ignorance.
 */
const PARSERS: Readonly<Record<ManifestKind, (text: string) => ManifestFacts | null>> = {
  "package.json": parsePackageJson,
  "npm-lock": parseNpmLock,
  "yarn.lock": parseYarnLock,
  "pnpm-lock": parsePnpmLock,
  "requirements.txt": parseRequirements,
  "pyproject.toml": parsePyproject,
  "cargo.toml": parseCargoToml,
  "go.mod": parseGoMod,
};

/** U+FEFF. Editors and several toolchains write it; every JSON.parse in the language rejects it. */
const BYTE_ORDER_MARK = 0xfeff;

/**
 * `null` OUT means the text could not be read as this kind of manifest. `null` IN means there is no
 * such file yet, which is a real and empty baseline, not an unknown one.
 */
export function parseManifest(kind: ManifestKind, text: string | null): ManifestFacts | null {
  if (text === null) return EMPTY;
  const body = text.charCodeAt(0) === BYTE_ORDER_MARK ? text.slice(1) : text;
  if (body.length === 0) return EMPTY;
  return PARSERS[kind](body);
}

/** The name a delta carries when the manifest itself could not be read. */
export const UNREADABLE_MANIFEST = "<unreadable manifest>";

/**
 * What we report when a side of the turn cannot be parsed. Not knowing what a manifest says is not
 * the same as knowing it says nothing, and the difference is the whole verdict: treated as empty,
 * an unreadable manifest produces no deltas and the turn COMMITS.
 *
 * It is carried as `dep-added` because that is the kind `rules/dependency-change.ts` already turns
 * into a review, and that rule belongs to another lane. The honest shape is a `manifest-unreadable`
 * kind with its own hit; see the dependency-diff tests beside this file. `hosts` is deliberately empty:
 * an unknown is a review, and scraping urls out of text we just admitted we cannot parse would turn
 * a corrupt manifest that merely mentions a repository url into a discard of the author's work.
 */
const unreadable = (kind: ManifestKind, which: string): DependencyDelta => ({
  kind: "dep-added",
  name: UNREADABLE_MANIFEST,
  to: `${which} could not be parsed as ${kind}, so what changed in it is unknown`,
  hosts: [],
});

const hostOf = (resolved: string | undefined): string => (resolved === undefined ? "" : hostsIn(resolved)[0] ?? "");

/** The kinds whose parser scans for shapes and so has no way to report a failure of its own. */
const SCANNING_KINDS: ReadonlySet<ManifestKind> = new Set<ManifestKind>([
  "yarn.lock",
  "pnpm-lock",
  "requirements.txt",
  "pyproject.toml",
  "cargo.toml",
  "go.mod",
]);

const holdsNothing = (facts: ManifestFacts): boolean =>
  Object.keys(facts.deps).length === 0 &&
  Object.keys(facts.scripts).length === 0 &&
  Object.keys(facts.locks).length === 0 &&
  facts.indexUrls.length === 0 &&
  facts.buildSystem.length === 0;

/**
 * The one case where a scanning parser's silence is an admission rather than a fact.
 *
 * These six parsers cannot return `null`: they look for lines they recognise and finding none is
 * usually true (a comment-only `requirements.txt`, a `go.mod` with no `require`). But a file that
 * HELD entries before the turn and holds text but no entries after it is a different animal: no
 * package manager writes that, and reading it as "no difference" is the byte-order-mark hole in
 * another file format, since replacing a lockfile with three words of prose would then commit.
 *
 * Deliberately narrow. Both sides empty stays a commit, and a `package.json` emptied of its
 * dependencies is not covered here at all, because that parser DID read the file and knows.
 */
function scannedIntoSilence(kind: ManifestKind, after: string, before: ManifestFacts, out: ManifestFacts): boolean {
  if (!SCANNING_KINDS.has(kind)) return false;
  return after.trim().length > 0 && holdsNothing(out) && !holdsNothing(before);
}

/** The typed difference between the manifest before the turn and the manifest after it. */
export function diffManifest(kind: ManifestKind, before: string | null, after: string): DependencyDelta[] {
  const b = parseManifest(kind, after);
  // nothing on the far side of the turn is readable, so there is no difference to compute at all
  if (b === null) return [unreadable(kind, "the manifest this turn wrote")];
  const parsedBefore = parseManifest(kind, before);
  // an unreadable baseline still gets diffed against EMPTY, which is loud and safe, but the
  // reviewer is told that every "added" line below may only look added
  const a = parsedBefore ?? EMPTY;
  const deltas: DependencyDelta[] = [];
  if (parsedBefore === null) deltas.push(unreadable(kind, "the manifest already in the repo"));
  if (scannedIntoSilence(kind, after, a, b)) deltas.push(unreadable(kind, "the manifest this turn wrote"));

  for (const [name, spec] of Object.entries(b.deps)) {
    const previous = a.deps[name];
    if (previous === undefined) {
      deltas.push({ kind: "dep-added", name, to: spec, hosts: hostsIn(`${name} ${spec}`) });
    } else if (previous !== spec) {
      deltas.push({ kind: "dep-spec-changed", name, from: previous, to: spec, hosts: hostsIn(spec) });
    }
  }
  for (const [name, body] of Object.entries(b.scripts)) {
    const previous = a.scripts[name];
    if (previous === undefined) deltas.push({ kind: "script-added", name, to: body, hosts: hostsIn(body) });
    else if (previous !== body) {
      deltas.push({ kind: "script-changed", name, from: previous, to: body, hosts: hostsIn(body) });
    }
  }
  for (const url of b.indexUrls) {
    if (a.indexUrls.includes(url)) continue;
    deltas.push({ kind: "index-url-added", name: url, to: url, hosts: hostsIn(url) });
  }
  for (const entry of b.buildSystem) {
    if (a.buildSystem.includes(entry)) continue;
    deltas.push({ kind: "build-system-changed", name: entry, to: entry, hosts: hostsIn(entry) });
  }
  for (const [name, lock] of Object.entries(b.locks)) {
    const previous = a.locks[name];
    if (previous === undefined) {
      if (lock.resolved !== undefined) {
        deltas.push({ kind: "lock-entry-added", name, to: lock.resolved, hosts: hostsIn(lock.resolved) });
      }
      continue;
    }
    const versionUnchanged = previous.version === lock.version;
    const resolvedHostMoved = hostOf(previous.resolved) !== hostOf(lock.resolved);
    if (resolvedHostMoved) {
      const delta: DependencyDelta = {
        kind: versionUnchanged ? "lock-repointed" : "lock-entry-added",
        name,
        hosts: hostsIn(lock.resolved ?? ""),
        ...(previous.resolved === undefined ? {} : { from: previous.resolved }),
        ...(lock.resolved === undefined ? {} : { to: lock.resolved }),
      };
      deltas.push(delta);
    }
    if (versionUnchanged && previous.integrity !== lock.integrity) {
      deltas.push({
        kind: "lock-integrity-changed",
        name,
        hosts: hostsIn(lock.resolved ?? ""),
        ...(previous.integrity === undefined ? {} : { from: previous.integrity }),
        ...(lock.integrity === undefined ? {} : { to: lock.integrity }),
      });
    }
  }
  return deltas;
}

/**
 * A host is off the list when the deployment's allowlist, or the default one, does not name it.
 *
 * The empty list means "the deployment declared none", not "allow nothing", and that reading is
 * measured rather than assumed: `basicContext` hands every caller `registryAllowlist: []`, so
 * fail-closed turns an `npm install` that adds one package resolved at `registry.npmjs.org` into a
 * DISCARD and throws the turn's real work away. A negative test in dependency-diff.test.ts pins
 * that case. `PolicyContext.registryAllowlist` is a plain `string[]` with no way to say "unset"
 * apart from "empty"; until it has one, this is the reading that does not destroy work. What HAS
 * been fixed is the half that was measurable here: the list defaulted to is the one production runs.
 */
export function isOfflistHost(host: string, allowlist: readonly string[]): boolean {
  const list = allowlist.length > 0 ? allowlist : DEFAULT_REGISTRY_ALLOWLIST;
  const target = canonicalise(host);
  return !list.some((allowed) => {
    const a = canonicalise(allowed);
    return target === a || target.endsWith(`.${a}`);
  });
}

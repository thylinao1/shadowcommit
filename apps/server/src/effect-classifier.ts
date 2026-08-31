/**
 * Assigns one class to every captured effect BEFORE anything judges it.
 *
 * The rule this file exists to fix: the shipped policy matched seven anchored spellings
 * (`/(^|\/)Dockerfile$/` and friends), so `Dockerfile.prod`, `makefile`, `GNUmakefile`,
 * `.githooks/pre-commit` and twenty-eight other paths that decide what runs later were ordinary
 * source files as far as it was concerned. Matching is therefore done on the NFC-normalised,
 * case-folded basename and on path SEGMENTS at any depth, never on an anchored exact spelling,
 * and the surface itself lives in a table rather than in the matching code.
 *
 * A class is a statement about what a path IS, not about what should happen to it. The decision
 * table lives beside the rules in `rules/exec-surface.ts`, so the enumerable part (the surface)
 * and the tunable part (the verdict) can move independently.
 */
import type { EffectRecord, PolicyContext } from "./policy-types.js";
import { asciiPolicySkeleton } from "./unicode-security.js";

/**
 * Files whose name looks like an execution surface but whose extension makes them prose:
 * `docs/dockerfile-notes.md` documents a Dockerfile, it is not one. `.txt` is deliberately NOT on
 * this list, because `CMakeLists.txt` and `requirements.txt` are both real and both run things.
 */
const DOC_EXTENSIONS = [".md", ".markdown", ".rst", ".adoc"] as const;

const SOURCE_EXTENSIONS = [
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".py", ".go", ".rs", ".rb",
  ".java", ".kt", ".kts", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".php", ".swift", ".scala",
  ".sh", ".bash", ".zsh", ".sql", ".css", ".scss", ".less", ".html", ".vue", ".svelte", ".proto",
] as const;

/**
 * The protected set is a union: these defaults always apply, and `ctx.protectedPaths` adds to them.
 * Every pattern is written against the canonical (NFC, case-folded, forward-slash) path with
 * segment-anywhere semantics, so `Customers.jsonl`, `config/secrets/prod.key`, `.env.local` and
 * `.env.production` are all inside it while `src/secretsUtil.ts`, `docs/env.md` and `.environment`
 * are all outside it.
 */
export const DEFAULT_PROTECTED_PATTERNS: readonly RegExp[] = [
  /(^|\/)customers\.jsonl$/,
  /(^|\/)\.env(\.[^/]*)?$/,
  /(^|\/)secrets?(\/|$)/,
  /(^|\/)\.shadow-commit(\/|$)/,
];

interface ClassRule {
  readonly cls: string;
  /** directory segment names matched at ANY depth; never the final segment */
  readonly dirs?: readonly string[];
  /** adjacent directory-segment pairs, matched at any depth */
  readonly dirPairs?: readonly (readonly [string, string])[];
  /** [immediate parent directory, exact basename], so `.git/config` needs its parent */
  readonly parentAndBase?: readonly (readonly [string, string])[];
  /** exact canonical basenames */
  readonly bases?: readonly string[];
  /** basename equals the stem, or starts with the stem followed by a dot */
  readonly stems?: readonly string[];
  /** basename starts with this literal */
  readonly prefixes?: readonly string[];
  /** basename ends with this literal */
  readonly suffixes?: readonly string[];
  /** basename regexes, for the glob-shaped entries only */
  readonly patterns?: readonly RegExp[];
}

/**
 * Vendored dependency trees. A file INSIDE one of these directories is dependency-tree; a file
 * literally named `vendor` is not, which is why the marker must not be the final segment.
 */
const DEPENDENCY_TREE: ClassRule = {
  cls: "dependency-tree",
  dirs: ["node_modules", "vendor", ".venv", "site-packages", "bower_components"],
  dirPairs: [[".yarn", "cache"], [".yarn", "releases"]],
};

/** Files a coding agent reads as instructions on its next turn. */
const INSTRUCTION_FILE: ClassRule = {
  cls: "instruction-file",
  bases: ["agents.md", "claude.md", ".cursorrules", ".clinerules", ".windsurfrules"],
};

/**
 * The execution surface, one entry per mechanism that runs the file without anyone asking for it.
 * Every entry here was written from a red-team payload that reached `commit` against the seven
 * anchored regexes this table replaces.
 */
const EXEC_SURFACE: readonly ClassRule[] = [
  {
    // git's own hook surface, plus the two conventions that move it (core.hooksPath, husky) and
    // the three metadata files that decide what git itself will fetch or run.
    cls: "exec-surface:vcs-hook",
    dirs: [".githooks", ".husky"],
    dirPairs: [[".git", "hooks"]],
    parentAndBase: [[".git", "config"]],
    bases: [
      ".pre-commit-config.yaml", ".pre-commit-config.yml",
      "lefthook.yml", "lefthook.yaml",
      ".gitmodules", ".gitattributes",
    ],
  },
  {
    // package-manager hooks: code the manager itself executes on the next install.
    cls: "exec-surface:pm-hook",
    dirPairs: [[".yarn", "plugins"]],
    bases: [".pnpmfile.cjs", ".npmrc", ".yarnrc", ".yarnrc.yml", ".yarnrc.yaml", "bunfig.toml"],
  },
  {
    // files a shell or a Python interpreter sources on its own, with no command being run.
    cls: "exec-surface:shell-autoload",
    bases: [
      ".envrc", ".bashrc", ".zshrc", ".zshenv", ".profile", ".bash_profile",
      "sitecustomize.py", "usercustomize.py",
    ],
  },
  {
    // configuration that another coding agent on the operator's own machine executes.
    cls: "exec-surface:agent-config",
    dirs: [".claude", ".cursor", ".codex", ".continue", ".windsurf"],
    bases: [".aider.conf.yml", ".aider.conf.yaml"],
  },
  {
    cls: "exec-surface:editor-config",
    dirs: [".vscode", ".idea"],
  },
  {
    // every CI provider, not only GitHub Actions.
    cls: "exec-surface:ci",
    dirs: [".github", ".circleci", ".buildkite"],
    dirPairs: [[".forgejo", "workflows"], [".gitea", "workflows"]],
    bases: [
      ".gitlab-ci.yml", ".gitlab-ci.yaml", "jenkinsfile",
      "azure-pipelines.yml", "azure-pipelines.yaml",
      "bitbucket-pipelines.yml", "bitbucket-pipelines.yaml",
      ".drone.yml", ".drone.yaml", ".travis.yml", ".travis.yaml",
      ".woodpecker.yml", ".woodpecker.yaml", "action.yml", "action.yaml",
    ],
  },
  {
    cls: "exec-surface:container",
    dirs: [".devcontainer"],
    stems: ["dockerfile", "containerfile"],
    suffixes: [".dockerfile"],
    patterns: [/^(docker-)?compose[^/]*\.ya?ml$/],
  },
  {
    cls: "exec-surface:build",
    dirs: [".cargo"],
    bases: [
      "gnumakefile", "makefile", "build.rs", "cargo.toml", "setup.py", "setup.cfg",
      "pyproject.toml", "conftest.py", "pytest.ini", "tox.ini", "noxfile.py", "rakefile",
      "gemfile", "build.gradle", "build.gradle.kts", "justfile", "taskfile.yml",
      "taskfile.yaml", "cmakelists.txt",
    ],
    suffixes: [".mk"],
  },
  {
    // JavaScript that a tool evaluates with Node when it starts: top-level code runs on the next
    // test, lint or build. The JS analogue of conftest.py.
    cls: "exec-surface:js-config",
    bases: [
      ".eslintrc.js", ".eslintrc.cjs", ".babelrc.js", ".babelrc.cjs",
      ".stylelintrc.js", ".stylelintrc.cjs",
    ],
    suffixes: [".config.js", ".config.ts", ".config.cjs", ".config.mjs"],
    patterns: [/^jest\.config\./, /^vitest\.config\./],
  },
];

const LOCKFILE: ClassRule = {
  cls: "lockfile",
  bases: [
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
    "poetry.lock", "cargo.lock", "gemfile.lock", "composer.lock", "go.sum", "pipfile.lock",
  ],
};

const MANIFEST: ClassRule = {
  cls: "manifest",
  bases: ["package.json", "go.mod", "composer.json", "pipfile"],
  patterns: [/^requirements[^/]*\.txt$/],
};

/** Files whose removal weakens the project's own checks. Deleting one is a change of its own. */
const GUARD: ClassRule = {
  cls: "guard",
  bases: [
    "codeowners", "security.md", "codecov.yml", "codecov.yaml", ".codecov.yml", ".codecov.yaml",
    "dependabot.yml", "dependabot.yaml", "renovate.json", ".renovaterc", ".renovaterc.json",
  ],
  prefixes: ["tsconfig", ".eslintrc", ".stylelintrc", ".prettierrc", ".editorconfig"],
};

const TEST: ClassRule = {
  cls: "test",
  dirs: ["spec", "__tests__"],
  patterns: [/\.test\.[^.]+$/, /_test\.[^.]+$/, /^test_[^/]*\.py$/],
};

/** NFC, forward slashes, no `./` prefix, case-folded. Spelling stops mattering here. */
export function canonicalise(rawPath: string): string {
  return rawPath
    .normalize("NFC")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/^\/+/, "")
    .toLowerCase();
}

/**
 * A second form used only when asking whether a path names a protected asset.
 *
 * `canonicalise` remains the identity key for grants, distinct-touch counts and file equality.
 * Keeping this skeleton out of those call sites is what lets `می‌رود` and `میرود`, or Cyrillic and
 * Latin lookalikes, remain distinct real files while a deceptive spelling of an ASCII protected
 * name still receives the protected verdict.
 */
export function protectedPathSkeleton(rawPath: string): string {
  return canonicalise(asciiPolicySkeleton(rawPath));
}

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Skeletons are compared only with the finite built-in protected vocabulary. A workspace's extra
 * declarations remain regexes and are evaluated on the identity form, because rewriting an
 * arbitrary regex into a skeleton regex is not semantics-preserving.
 */
const DEFAULT_PROTECTED_SKELETON_PATTERNS: readonly RegExp[] = [
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton("customers.jsonl"))}$`),
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton(".env"))}(\\.[^/]*)?$`),
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton("secret"))}(/|$)`),
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton("secrets"))}(/|$)`),
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton(".shadow-commit"))}(/|$)`),
  // THE AUDIT TRAIL, added 2026-08-31 because the confusable defence stopped one entry short of it.
  //
  // `policy-context.ts` protects the journal, the anchors and the two keys, and it does so through
  // `ctx.protectedPaths`, which the comment above explains is evaluated on the identity form alone.
  // So `data/j<Cyrillic o>urnal.jsonl` folded to exactly `data/journal.jsonl` under
  // `protectedPathSkeleton` and `isProtectedPath` still returned false. Measured by the audit-trail
  // probe: three attacks committed for that reason and nothing else caught them.
  //
  // These belong HERE rather than being folded from `ctx`, and the distinction is the one the
  // comment above draws. A workspace's declarations are arbitrary regexes and rewriting one into
  // skeleton space is not semantics-preserving. These four are the product's own fixed names, known
  // at compile time, exactly like `customers.jsonl` and `.shadow-commit` already above.
  //
  // The rotation group matches `journal(-...)?.jsonl` in `policy-context.ts`. It is spelled against
  // the skeleton of the whole name rather than by composing skeletons of parts, because
  // `protectedPathSkeleton` folds the entire string and composition of the pieces is not guaranteed
  // to equal the fold of the whole. `effect-classifier.test.ts` pins that with rotation and
  // confusable spellings rather than trusting it.
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton("journal"))}(-[\\w.-]+)?${escapeRegExp(protectedPathSkeleton(".jsonl"))}$`),
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton("anchors.jsonl"))}$`),
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton("journal.key"))}$`),
  new RegExp(`(^|/)${escapeRegExp(protectedPathSkeleton("signing.key"))}$`),
];

export interface PathParts {
  readonly canonical: string;
  /** every segment except the last */
  readonly dirs: readonly string[];
  readonly base: string;
}

export function partsOf(rawPath: string): PathParts {
  const canonical = canonicalise(rawPath);
  const segments = canonical.split("/").filter((s) => s.length > 0);
  const base = segments.length > 0 ? segments[segments.length - 1]! : "";
  return { canonical, dirs: segments.slice(0, -1), base };
}

function matchesRule(rule: ClassRule, parts: PathParts): boolean {
  const { dirs, base } = parts;
  if (rule.dirs?.some((d) => dirs.includes(d))) return true;
  if (rule.dirPairs?.some(([a, b]) => dirs.some((d, i) => d === a && dirs[i + 1] === b))) return true;
  if (rule.parentAndBase?.some(([parent, name]) => base === name && dirs[dirs.length - 1] === parent)) return true;
  if (rule.bases?.includes(base)) return true;
  if (rule.stems?.some((s) => base === s || base.startsWith(`${s}.`))) return true;
  if (rule.prefixes?.some((p) => base.startsWith(p))) return true;
  if (rule.suffixes?.some((s) => base.endsWith(s))) return true;
  if (rule.patterns?.some((re) => re.test(base))) return true;
  return false;
}

const isDoc = (base: string): boolean => DOC_EXTENSIONS.some((e) => base.endsWith(e));

/** True when this canonical path is a protected asset by name, under the defaults plus ctx. */
function patternMatches(pattern: RegExp, candidate: string): boolean {
  // A workspace declaration may contain `g` or `y`. RegExp.test mutates lastIndex for those flags,
  // which would otherwise make the same path alternate between protected and unprotected.
  if (!pattern.global && !pattern.sticky) return pattern.test(candidate);
  return new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, "")).test(candidate);
}

export function isProtectedPath(canonical: string, extra: readonly RegExp[] = []): boolean {
  if (DEFAULT_PROTECTED_PATTERNS.some((pattern) => patternMatches(pattern, canonical))) return true;
  if (extra.some((pattern) => patternMatches(pattern, canonical))) return true;
  const skeleton = protectedPathSkeleton(canonical);
  return skeleton !== canonical
    && DEFAULT_PROTECTED_SKELETON_PATTERNS.some((pattern) => patternMatches(pattern, skeleton));
}

/**
 * The class of one path. Pure: the only thing it reads from the context is the protected set, so
 * the same path is classified identically in the product, in the harness and in a test.
 */
export function classifyPath(rawPath: string, protectedPaths: readonly RegExp[] = []): string {
  const parts = partsOf(rawPath);
  if (isProtectedPath(parts.canonical, protectedPaths)) return "protected";
  if (matchesRule(DEPENDENCY_TREE, parts)) return "dependency-tree";
  if (matchesRule(INSTRUCTION_FILE, parts)) return "instruction-file";
  if (!isDoc(parts.base)) {
    for (const rule of EXEC_SURFACE) if (matchesRule(rule, parts)) return rule.cls;
  }
  if (matchesRule(LOCKFILE, parts)) return "lockfile";
  if (matchesRule(MANIFEST, parts)) return "manifest";
  if (matchesRule(TEST, parts)) return "test";
  if (matchesRule(GUARD, parts)) return "guard";
  if (SOURCE_EXTENSIONS.some((e) => parts.base.endsWith(e))) return "source";
  return "other";
}

/**
 * The class of one effect. Identity by inode is checked as well as by name, so a protected asset
 * reached through a differently spelled path is still protected.
 */
export function classify(effect: EffectRecord, ctx: PolicyContext): string {
  if (effect.realIno !== undefined && ctx.protectedInodes.has(effect.realIno)) return "protected";
  const canonical = effect.canonicalPath ?? canonicalise(effect.path);
  if (isProtectedPath(canonical, ctx.protectedPaths)) return "protected";
  return classifyPath(effect.path, ctx.protectedPaths);
}

export const isDependencyTree = (cls: string | undefined): boolean => cls === "dependency-tree";
export const isExecSurface = (cls: string | undefined): boolean => cls?.startsWith("exec-surface:") === true;

/** Guard and test files share one predicate: removing either one removes a check. */
export function isGuardFile(rawPath: string): boolean {
  const cls = classifyPath(rawPath);
  if (cls === "guard" || cls === "test") return true;
  // lint and CI configuration that the exec-surface table claims first is still a guard when it
  // is DELETED rather than written, which is what this predicate is for.
  return cls === "exec-surface:ci" || cls === "exec-surface:js-config";
}

/** Every class this module can return, so a reader does not have to grep the table. */
export const EFFECT_CLASSES: readonly string[] = [
  "protected",
  "dependency-tree",
  "instruction-file",
  ...EXEC_SURFACE.map((r) => r.cls),
  "lockfile",
  "manifest",
  "test",
  "guard",
  "source",
  "other",
];

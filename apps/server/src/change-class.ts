import path from "node:path";

/**
 * The class chip on a proposed change, and the path rules behind it.
 *
 * A path-shaped judgement, deliberately independent of the policy: the policy decides what happens
 * to a turn, this only tells the reviewer what kind of thing they are looking at before they read
 * a single line of the diff. When capture has already assigned an effect class, that one wins,
 * because the classifier saw the real path and the inode and this only sees a string.
 *
 * It lives in its own module because two surfaces need it and neither should own it: the review
 * queue renders a chip per row, and the run timeline renders one per effect.
 */

/** The class chip a reviewer reads before anything else: what kind of thing is being changed. */
export type ChangeClass = "protected" | "dependency" | "ci" | "config" | "source" | "other";

const PROTECTED_PATTERNS = [
  /^customers\.jsonl$/i,
  /(^|\/)\.env(\.|$)/i,
  /(^|\/)secrets?\//i,
  /(^|\/)id_(rsa|ed25519)$/i,
  /\.(pem|key|p12|pfx)$/i,
  /(^|\/)credentials(\.json)?$/i,
];
const DEPENDENCY_PATTERNS = [
  /(^|\/)node_modules\//,
  /(^|\/)vendor\//,
  /(^|\/)package(-lock)?\.json$/i,
  /(^|\/)(yarn|pnpm-)lock\.(lock|yaml)$/i,
  /(^|\/)requirements[^/]*\.txt$/i,
  /(^|\/)(poetry|Cargo|Gemfile|composer)\.lock$/i,
  /(^|\/)(Cargo\.toml|go\.mod|go\.sum|Gemfile|pyproject\.toml)$/i,
];
const CI_PATTERNS = [
  /(^|\/)\.github\/workflows\//i,
  /(^|\/)\.gitlab-ci\.ya?ml$/i,
  /(^|\/)\.circleci\//i,
  /(^|\/)Jenkinsfile$/i,
  /(^|\/)azure-pipelines\.ya?ml$/i,
  /(^|\/)bitbucket-pipelines\.ya?ml$/i,
  /(^|\/)\.travis\.ya?ml$/i,
  /(^|\/)\.buildkite\//i,
  /(^|\/)\.drone\.ya?ml$/i,
];
const CONFIG_PATTERNS = [
  /(^|\/)\.git\/(hooks\/|config$)/i,
  /(^|\/)\.githooks\//i,
  /(^|\/)\.husky\//i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.yarnrc(\.yml)?$/i,
  /(^|\/)\.pnpmfile\.cjs$/i,
  /(^|\/)(Dockerfile|Containerfile)[^/]*$/i,
  /(^|\/)docker-compose[^/]*\.ya?ml$/i,
  /(^|\/)(GNUmakefile|Makefile)$/i,
  /(^|\/)\.envrc$/i,
  /(^|\/)\.vscode\//i,
  /(^|\/)\.devcontainer\//i,
  /(^|\/)tsconfig[^/]*\.json$/i,
  /(^|\/)[^/]*\.config\.[cm]?[jt]s$/i,
  /(^|\/)\.eslintrc[^/]*$/i,
  /(^|\/)\.pre-commit-config\.ya?ml$/i,
];
const SOURCE_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts",
  ".py", ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".c", ".h",
  ".cc", ".cpp", ".hpp", ".cs", ".php", ".sh", ".bash", ".zsh", ".sql",
]);

/**
 * The chip on every proposed-changes row. A path-shaped judgement, deliberately independent of the
 * policy: the policy decides, this only tells the reviewer what they are looking at. When the
 * capture side has already assigned an effect class, that one wins.
 */
export function classifyPath(relPath: string, assigned?: string): ChangeClass {
  if (assigned) {
    const known: ChangeClass[] = ["protected", "dependency", "ci", "config", "source", "other"];
    const match = known.find((c) => assigned === c || assigned.startsWith(c + ":"));
    if (match) return match;
    if (assigned.startsWith("exec-surface") || assigned === "editor-config") {
      return "config";
    }
    // A manifest belongs beside the lockfile, not beside the editor config. Both halves of one
    // dependency change land on the same review screen, and `package.json` matches
    // DEPENDENCY_PATTERNS below on its path alone, so mapping the policy's `manifest` to anything
    // else made the chip disagree with the rule that produced it: the panel called `package.json`
    // "dependency" for as long as the class never reached it, and "config" the moment it did.
    if (assigned === "manifest" || assigned === "lockfile" || assigned === "dependency-tree") {
      return "dependency";
    }
    if (assigned === "container" || assigned === "guard") return "config";
  }
  const rel = relPath.replace(/\\/g, "/");
  if (PROTECTED_PATTERNS.some((r) => r.test(rel))) return "protected";
  if (CI_PATTERNS.some((r) => r.test(rel))) return "ci";
  if (DEPENDENCY_PATTERNS.some((r) => r.test(rel))) return "dependency";
  if (CONFIG_PATTERNS.some((r) => r.test(rel))) return "config";
  if (SOURCE_EXTENSIONS.has(path.extname(rel).toLowerCase())) return "source";
  return "other";
}

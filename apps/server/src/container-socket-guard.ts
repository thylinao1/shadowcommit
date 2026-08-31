import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const SKIPPED_DIRECTORIES = new Set([
  ".git",
  ".data",
  // `.local` is where `start-local-poc.sh:102` puts the running platform's state, INSIDE the
  // repository: sealed shadows, agent workspaces, the journal. Two things follow from scanning it,
  // and both are bad. It is not source, so a hit there says nothing about the shipped
  // configuration. And it is written by the agent under test, so a turn that writes the string
  // this guard looks for into its own workspace fails the repository's own security gate. That is
  // agent-controlled input deciding whether a gate passes.
  ".local",
  // `.claude` holds agent tooling state, and `.claude/worktrees/<id>` is a full second checkout of
  // this repository made for an isolated agent. Walking into it scans every file twice, and the
  // second copy carries a different path prefix, so the caller's own exclusion list stops matching:
  // this guard's test excludes `apps/server/src/container-socket-guard.test.ts` by exact path, and
  // the worktree copy of that same file then reports the test's own mount fixtures as violations.
  // The build went red on a checkout of itself. Any nested checkout does this, a vendored
  // repository or a second clone alike, so the fix is to not descend into one rather than to keep
  // lengthening the exclusion list.
  //
  // Note for whoever edits this block: the scan greps for a literal, so prose that spells that
  // literal out is itself a finding. Describe it, do not quote it.
  ".claude",
  "coverage",
  "dist",
  "node_modules",
]);

const TEXT_EXTENSIONS = new Set([
  ".cjs",
  ".js",
  ".json",
  ".mjs",
  ".sh",
  ".toml",
  ".ts",
  ".yaml",
  ".yml",
]);

const unixSocketPattern = new RegExp(
  String.raw`(?:docker|podman|containerd|buildkitd?|cri-dockerd)\.sock`,
  "i",
);
const windowsEnginePattern = new RegExp(String.raw`(?:npipe:)?//\./pipe/docker_engine`, "i");

/** Marks a line that names the socket without mounting or dialling it, for example an error string. */
const allowMarker = /container-socket-allow:/;

function isConfigurationSource(name: string): boolean {
  return (
    name.startsWith("Dockerfile") ||
    name.startsWith("Containerfile") ||
    TEXT_EXTENSIONS.has(path.extname(name).toLowerCase())
  );
}

export interface ContainerSocketReference {
  file: string;
  line: number;
  excerpt: string;
}

/** A directory the scan could not read, so the guard says nothing about what is inside it. */
export interface UnreadableDirectory {
  directory: string;
  reason: string;
}

export interface ContainerSocketScan {
  findings: ContainerSocketReference[];
  /** Empty on a scan that reached everything. Non-empty means the answer is incomplete, not clean. */
  unreadable: UnreadableDirectory[];
  /**
   * Nested repositories the walk deliberately did not enter, reported rather than skipped in
   * silence. A control that quietly declines to look at part of the tree reads as a clean sheet,
   * and this project has already shipped one of those tonight: the journal named a container on a
   * host that had none. So the caller is told what was not scanned and can decide whether that is
   * acceptable, instead of inferring coverage from an empty findings list.
   */
  nestedCheckouts: string[];
}

/**
 * Finds container-control socket names anywhere they could become a run argument or mount. The
 * guard is intentionally broader than Compose syntax because TypeScript and shell launchers can
 * construct the same mount without a YAML file.
 */
export async function findContainerSocketReferences(
  root: string,
  ignoredFiles: ReadonlySet<string> = new Set(),
): Promise<ContainerSocketScan> {
  const findings: ContainerSocketReference[] = [];
  const unreadable: UnreadableDirectory[] = [];
  const nestedCheckouts: string[] = [];

  const walk = async (directory: string): Promise<void> => {
    // A directory this process cannot read used to throw EACCES straight out of the guard, and the
    // test above it reported that as its own assertion failing, so "the guard could not run" was
    // indistinguishable from "the shipped configuration mounts the socket". It is recorded instead,
    // because a gate that cannot read part of its subject has not passed on that part, and the
    // caller has to be able to tell the two apart.
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      unreadable.push({
        directory: path.relative(root, directory).replaceAll(path.sep, "/") || ".",
        reason: (error as { code?: string })?.code ?? String(error),
      });
      return;
    }
    // A directory holding a `.git` entry is a SEPARATE repository that happens to sit inside this
    // one, and nothing in it is this project's shipped configuration. The `.claude` note above
    // predicted this case in as many words, "any nested checkout does this, a vendored repository or
    // a second clone alike, so the fix is to not descend into one rather than to keep lengthening the
    // exclusion list", and then it happened: `research/realworld-prior/repos/` holds eight upstream
    // clones fetched for the real-commit corpus, and axios's own HTTP adapter test fixture mentions
    // the control socket, so this repository's security gate went red over a line in somebody else's
    // test suite. That whole tree is gitignored, so none of it ships here.
    //
    // Detected structurally rather than by name, so a clone added tomorrow is covered without editing
    // this file, which is the difference between a fix and another entry in a list.
    const isNestedCheckout = entries.some((e) => e.name === ".git") && directory !== root;
    if (isNestedCheckout) {
      nestedCheckouts.push(path.relative(root, directory).replaceAll(path.sep, "/"));
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) await walk(path.join(directory, entry.name));
        continue;
      }
      if (!entry.isFile() || !isConfigurationSource(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).replaceAll(path.sep, "/");
      if (ignoredFiles.has(relative)) continue;
      const lines = (await readFile(absolute, "utf8")).split(/\r?\n/);
      lines.forEach((line, index) => {
        // A per-line, visible exemption, deliberately not a whole-file one. This guard exists because
        // mounting the container control socket hands a container host root, and a file-level ignore
        // is how a real mount eventually hides inside a file that was exempted for something else.
        // A legitimate mention still has to say out loud that it is one.
        if (allowMarker.test(line)) return;
        if (unixSocketPattern.test(line) || windowsEnginePattern.test(line)) {
          findings.push({ file: relative, line: index + 1, excerpt: line.trim().slice(0, 240) });
        }
      });
    }
  };

  await walk(path.resolve(root));
  return { findings, unreadable, nestedCheckouts: nestedCheckouts.sort() };
}

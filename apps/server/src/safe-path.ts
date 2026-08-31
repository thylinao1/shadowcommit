import fs from "node:fs/promises";
import path from "node:path";

/**
 * The one place the trusted half resolves an agent-chosen path.
 *
 * Three review rounds produced the same defect in three costumes: a filename interpolated into a
 * shell, a leaf symlink dereferenced on read, a leaf symlink written through, then a *parent*
 * directory symlink traversed by `mkdir -p`, and a hardlink whose leaf check passes because it is
 * not a link at all. Each was patched where it was found, and the next variant appeared in the next
 * review. Patching instances does not converge.
 *
 * So the rule the plan already states is a function instead of a sentence: the trusted half never
 * follows or resolves an agent-chosen name without checking where it lands. Every write, delete,
 * mkdir and stat in the commit path goes through here, which closes the whole family at once,
 * including the variants nobody has thought of yet.
 */
export interface SafePath {
  ok: boolean;
  /** the absolute path to operate on, only when ok */
  abs: string;
  reason?: string;
}

/**
 * True when `candidate` is inside `base`, with both sides resolved.
 *
 * Both sides matter: on macOS `/var` is itself a symlink to `/private/var`, so comparing a resolved
 * base against an unresolved candidate rejects perfectly ordinary paths under a temp directory.
 */
async function realWithin(base: string, candidate: string): Promise<boolean> {
  const realBase = await fs.realpath(base).catch(() => path.resolve(base));
  // resolve the deepest ancestor that exists, so a not-yet-created leaf is still checkable
  let probe = candidate;
  let suffix = "";
  for (;;) {
    const real = await fs.realpath(probe).catch(() => null);
    if (real) { candidate = suffix ? path.join(real, suffix) : real; break; }
    const parent = path.dirname(probe);
    if (parent === probe) { candidate = path.resolve(candidate); break; }
    suffix = suffix ? path.join(path.basename(probe), suffix) : path.basename(probe);
    probe = parent;
  }
  const rel = path.relative(realBase, candidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * Resolves `relPath` under `root`, refusing anything that leaves it.
 *
 * Every component is checked, not just the leaf: a symlink anywhere along the path can redirect the
 * whole write, which is how a `vendor -> ../outside` directory turned an ordinary create into a
 * write outside the workspace. Intermediate directories are created one component at a time so
 * `mkdir -p` can never traverse a link that was placed for it.
 */
export async function safeResolve(root: string, relPath: string, opts: { createDirs?: boolean } = {}): Promise<SafePath> {
  const realRoot = await fs.realpath(root).catch(() => path.resolve(root));
  const lexical = path.resolve(realRoot, relPath);
  if (!(await realWithin(root, lexical))) {
    return { ok: false, abs: "", reason: "path resolves outside the workspace" };
  }
  const parts = relPath.split("/").filter((p) => p.length && p !== ".");
  if (parts.some((p) => p === "..")) {
    return { ok: false, abs: "", reason: "path contains a parent reference" };
  }

  let current = realRoot;
  for (let i = 0; i < parts.length - 1; i++) {
    const next = path.join(current, parts[i]!);
    const st = await fs.lstat(next).catch(() => null);
    if (st?.isSymbolicLink()) {
      return { ok: false, abs: "", reason: `path component "${parts[i]}" is a symlink` };
    }
    if (!st) {
      if (!opts.createDirs) return { ok: false, abs: "", reason: "intermediate directory missing" };
      await fs.mkdir(next);                       // one component, never recursive through a link
    } else if (!st.isDirectory()) {
      return { ok: false, abs: "", reason: `path component "${parts[i]}" is not a directory` };
    }
    current = next;
  }

  const leaf = parts.length ? path.join(current, parts[parts.length - 1]!) : current;
  if (!(await realWithin(root, leaf))) {
    return { ok: false, abs: "", reason: "leaf resolves outside the workspace" };
  }
  return { ok: true, abs: leaf };
}

/**
 * Prepares a destination for a trusted write. A path that is itself a symlink, or a hardlink to
 * something else, is unlinked first so the write always lands on a fresh inode inside the
 * workspace rather than following someone else's pointer.
 */
export async function safeWriteTarget(root: string, relPath: string): Promise<SafePath> {
  const resolved = await safeResolve(root, relPath, { createDirs: true });
  if (!resolved.ok) return resolved;
  const st = await fs.lstat(resolved.abs).catch(() => null);
  if (st && (st.isSymbolicLink() || st.nlink > 1)) {
    // a symlink would redirect the write; a hardlink would change a file the turn was never given
    await fs.rm(resolved.abs, { force: true }).catch(() => undefined);
  }
  return resolved;
}

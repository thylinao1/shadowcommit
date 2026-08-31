import type { EffectRecord, PolicyContext, RuleHit } from "../policy-types.js";
import type { Rule } from "./rule.js";
import { classifyPath, isGuardFile } from "../effect-classifier.js";

/**
 * Execution surfaces that are the project's own checks, so taking one away is taking a check away.
 *
 * `exec-surface:vcs-hook` covers `.pre-commit-config.yaml`, `.githooks/`, `.husky/`, `lefthook.yml`
 * and `.gitattributes`. Writing one runs code, which is why the classifier claims the class first
 * and `exec-surface` discards a write to it. DELETING one runs nothing: it removes the lint, the
 * format check and the secret scan that ran before every commit, and `exec-surface` skips deletes
 * entirely. The classifier's own `isGuardFile` already makes that argument for CI and for JS lint
 * config and then stops one class short, so a turn whose whole content was
 * `rm .pre-commit-config.yaml` committed with no rule firing at all.
 *
 * The list is deliberately only this one class. Deleting a Makefile, a Dockerfile or a
 * `pyproject.toml` breaks a build rather than removing a check, and holding those costs 33 benign
 * turns on the corpus against no attack this family carries.
 */
const GUARD_CLASSES_ON_REMOVAL: readonly string[] = ["exec-surface:vcs-hook"];

/** Guard by the classifier's own predicate, or by a class that is only a guard once it is gone. */
function guardsAgainstRemoval(rawPath: string): boolean {
  return isGuardFile(rawPath) || GUARD_CLASSES_ON_REMOVAL.includes(classifyPath(rawPath));
}

/** The directory part of a corpus-form (POSIX) path. `"a/b/c.py"` -> `"a/b"`, `"c.py"` -> `""`. */
function directoryOf(rawPath: string): string {
  const cut = rawPath.lastIndexOf("/");
  return cut < 0 ? "" : rawPath.slice(0, cut);
}

/**
 * Did this turn MOVE the check rather than remove it?
 *
 * A rename reaches the policy as a delete plus a create of the same bytes, and the count rules see
 * two effects where a reviewer sees one. Asking about it is asking about nothing: the check that
 * ran before the turn still runs after it, from a different path.
 *
 * Four conditions, and every one of them is load-bearing. Each was chosen because dropping it
 * opens a specific evasion, and guard-file.test.ts sweeps all four:
 *
 *   - **Class `test` only.** A test runner collects by PATTERN, so a test renamed inside the
 *     pattern still runs. Every other guard here is read by NAME from a fixed list, and renaming
 *     one always kills it. That distinction is not cosmetic: `.pre-commit-config.yaml` and
 *     `.pre-commit-config.yml` are one class to `classifyPath` and `pre-commit` reads only the
 *     first, so a class-wide exemption would have let `mv .pre-commit-config.yaml
 *     .pre-commit-config.yml` commit with every hook silently switched off. The corpus does not
 *     contain that turn; sweeping the class axis by hand is what found it.
 *   - **Same bytes.** Without it, `rm src/auth.test.ts && echo "" > src/auth2.test.ts` reads as a
 *     move. The comparison is the deleted file's PRE-turn content against the created file's
 *     post-turn content, so a rename that also guts the file is still a removal.
 *   - **Same directory.** Without it, deleting `src/auth.test.ts` and writing the same bytes to
 *     `docs/fixtures/auth.test.ts` reads as a move, and no runner configured to collect `src/`
 *     will load the new one.
 *   - **Still class `test` after the move.** This is the one that decides most of the corpus. The
 *     benign generator renames `tests/test_chain.py` to `tests/renamed_test_chain.py`, and pytest
 *     collects `test_*.py`, so that file is no longer collected: the bytes survive and the check
 *     does not. `classifyPath` already encodes exactly that distinction, because its TEST patterns
 *     are the collection patterns of the runners. `doc/md_docs_test.go` ->
 *     `doc/renamed_md_docs_test.go` keeps `_test.go` and stays class `test`; the python one does
 *     not. So the rule asks about the second and stays quiet about the first, which is the honest
 *     answer to both rather than a convenience.
 *
 * The cost of the first condition is a workflow rename: GitHub Actions runs every file under
 * `.github/workflows/`, so moving one there preserves the check and this rule asks anyway. Zero
 * rows of the corpus, and the safe direction of a question this code cannot answer by name.
 *
 * Fail closed: a content read that throws or comes back empty on either side is not a match.
 */
const RENAMEABLE_GUARD_CLASS = "test";

async function movedRatherThanRemoved(
  deleted: EffectRecord,
  effects: readonly EffectRecord[],
  ctx: PolicyContext,
): Promise<string | null> {
  const wantClass = classifyPath(deleted.path);
  if (wantClass !== RENAMEABLE_GUARD_CLASS) return null;
  const before = await ctx.realContentOf(deleted.path).catch(() => null);
  if (before === null || before.length === 0) return null;
  const wantDir = directoryOf(deleted.path);
  for (const candidate of effects) {
    if (candidate.kind !== "create") continue;
    if (candidate.path === deleted.path) continue;
    if (directoryOf(candidate.path) !== wantDir) continue;
    if (!guardsAgainstRemoval(candidate.path)) continue;
    if (classifyPath(candidate.path) !== wantClass) continue;
    const after = await ctx.contentOf(candidate.path).catch(() => "");
    if (after.length === 0 || after !== before) continue;
    return candidate.path;
  }
  return null;
}

/**
 * Removing a check is a change, and the count rules never see it.
 *
 * Deleting exactly one file stays under `multi-file-delete` (which fires at two), so a turn that
 * deletes `CODEOWNERS`, a security lint config or a single guard test beside one benign edit
 * committed cleanly. Emptying the file instead of deleting it has the same effect and does not even
 * register as a delete. Both are held at count one.
 *
 * A delete whose bytes reappear in the same turn, in the same directory, still classified as the
 * same kind of check, is a MOVE and is not held. See `movedRatherThanRemoved`.
 */
export const guardFileRule: Rule = {
  name: "guard-file-removed",
  summary:
    "A turn that deletes or empties one of the project's own checks, unless the same turn moved that check somewhere else rather than removing it.",
  decisions: ["review"],
  hitIds: ["guard-file-removed"],
  async run(effects: EffectRecord[], ctx: PolicyContext): Promise<RuleHit[]> {
    const hits: RuleHit[] = [];
    for (const effect of effects) {
      if (effect.kind === "outbound" || effect.kind === "symlink") continue;
      if (!guardsAgainstRemoval(effect.path)) continue;
      if (effect.kind === "delete") {
        const movedTo = await movedRatherThanRemoved(effect, effects, ctx);
        if (movedTo !== null) continue;
        hits.push({ rule: "guard-file-removed", decision: "review", path: effect.path, detail: "deleted" });
        continue;
      }
      if (effect.kind !== "modify") continue;
      const emptied = effect.bytes === 0 || (await ctx.contentOf(effect.path).catch(() => "x")).trim() === "";
      if (emptied) {
        hits.push({ rule: "guard-file-removed", decision: "review", path: effect.path, detail: "emptied" });
      }
    }
    return hits;
  },
};

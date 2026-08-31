import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const PACK = path.join(REPO, "evidence", "demo-run");

/**
 * Every artifact the evidence pack's own prose cites has to be in the pack.
 *
 * This is the check that was missing when `evidence/demo-run/` held a beat-0 failure at HEAD.
 * `README.md` mapped each beat to the file that proved it and eleven of the twelve files it named
 * were not there, and nothing said so: the counts gate reads figures, not filenames. A judge
 * following the proof table is the one who finds it, which is the worst possible reader to leave it
 * for.
 *
 * The root cause of the deletion is closed separately (`demo-drive.mjs` no longer destroys the pack
 * on a failed run, see `demo-drive-evidence.test.ts`). This is the other half: a citation that never
 * had a file, or a file deleted some other way, still fails here.
 *
 * Widening this gate has twice moved the hole rather than closing it, so the three shapes that got
 * past it are each named below with the document they got past it in.
 */

/** The files the pack itself owns at its root. Anything else bare is a repository file. */
const PACK_ROOT_FILES = new Set([
  "transcript.txt",
  "transcript-after-browser.txt",
  "state.json",
  "BEATS.md",
  "STORYBOARD.md",
  "README.md",
]);

/**
 * A pack artifact named without its directory: `04-review-queue.yml`, `10-platform-after.json`.
 *
 * The lane report's screen table cites all seven browser snapshots this way, and every one of them
 * was invisible to this gate until a probe renamed one to a file that does not exist and the suite
 * stayed green. The shape is narrow on purpose: it cannot match `package.json`, `types.ts` or
 * `AGENTS.md`, which are real repository files somewhere else and which this gate must keep
 * ignoring or it cries wolf until someone deletes it.
 */
const ARTIFACT_NAME = /^\d{2}-[A-Za-z0-9._-]+\.(?:yml|json|txt)$/;

function isPackPath(token: string): boolean {
  return /^(steps|browser)(\/|$)/.test(token) || PACK_ROOT_FILES.has(token) || ARTIFACT_NAME.test(token);
}

const PACK_PREFIX = "evidence/demo-run/";

function normalise(raw: string): string {
  let t = raw.trim();
  // A document outside the pack names the pack from the repository root. Same artifact.
  if (t.startsWith(PACK_PREFIX)) t = t.slice(PACK_PREFIX.length);
  // Prose punctuation that rides on the end of a token: "steps/09-....json," or "browser/04."
  t = t.replace(/[.,;:!?)\]"']+$/, "");
  return t.replace(/\/+$/, "");
}

/**
 * Backticked tokens from markdown prose that are meant to be paths inside the pack.
 *
 * Fenced blocks are removed first, and the distinction is a real one rather than a convenience.
 * Inline backticks are the prose saying "this artifact is here"; a fenced block is a command to run
 * or an excerpt to read, and the two documents that recover the deleted stage 2 name its files
 * inside `git show` lines. Those must not be read as claims that the files are in the pack, and
 * leaving that to the accident that fenced text carries no inline backticks is how a hard wrap
 * silently un-guards a sentence.
 */
function citedPaths(markdown: string): string[] {
  const prose = markdown.replace(/```[\s\S]*?```/g, "");
  const found = new Set<string>();
  for (const [, token] of prose.matchAll(/`([^`\n]+)`/g)) {
    const t = normalise(token);
    if (t.length > 0 && isPackPath(t)) found.add(t);
  }
  return [...found].sort();
}

/**
 * The same thing for a plain-text document, which has no backticks to key on.
 *
 * `transcript.txt` carries a hand-written note at its foot that cites four browser snapshots, a
 * step file and `state.json` as ordinary indented text, because backticks in a .txt read as noise.
 * Adding that file to the list below without this matcher would have passed vacuously: the
 * markdown matcher returns zero tokens for it. Only `steps/`- and `browser/`-prefixed tokens and
 * bare artifact names are read, so a `git show` line naming a deleted file is a command here too,
 * not a claim.
 */
function citedPathsInText(text: string): string[] {
  const found = new Set<string>();
  const patterns = [
    /(?:^|[\s(])((?:steps|browser)\/[A-Za-z0-9._/-]*)/g,
    /(?:^|[\s(])(\d{2}-[A-Za-z0-9._-]+\.(?:yml|json|txt))/g,
  ];
  for (const pattern of patterns) {
    for (const [, token] of text.matchAll(pattern)) {
      const t = normalise(token);
      if (t.length > 0 && isPackPath(t)) found.add(t);
    }
  }
  return [...found].sort();
}

/**
 * The documents this gate reads, where each one lives, how it is read, and the floor below which
 * it is not really being read at all.
 *
 * The lane report lives outside the pack and cites repository-relative paths, so its tokens are
 * stripped of that prefix before they are resolved. It is here because it is the document a judge
 * is likeliest to open and it is the one that carried a dead citation for two days.
 *
 * `minCitations` exists because both previous holes were silent: a document that cites nothing
 * passes a missing-file check perfectly. The floors are set under the current counts, so ordinary
 * editing does not trip them, and a document losing most of its citations does.
 */
type Doc = { label: string; path: string; kind: "markdown" | "text"; minCitations: number };
const DOCS: ReadonlyArray<Doc> = [
  { label: "README.md", path: path.join(PACK, "README.md"), kind: "markdown", minCitations: 10 },
  { label: "BEATS.md", path: path.join(PACK, "BEATS.md"), kind: "markdown", minCitations: 8 },
  { label: "STORYBOARD.md", path: path.join(PACK, "STORYBOARD.md"), kind: "markdown", minCitations: 2 },
  { label: "transcript.txt", path: path.join(PACK, "transcript.txt"), kind: "text", minCitations: 5 },
  {
    label: "docs/DEMO-PATH.md",
    path: path.join(REPO, "docs", "DEMO-PATH.md"),
    kind: "markdown",
    minCitations: 12,
  },
];

function cited(doc: Doc, text: string): string[] {
  return doc.kind === "text" ? citedPathsInText(text) : citedPaths(text);
}

/**
 * Four shapes appear in this prose and each is satisfied differently:
 *   `steps/*.json`        a glob, satisfied by at least one match
 *   `browser/04`          a prefix, satisfied by any file that starts with it
 *   `transcript.txt`      a literal at the pack root
 *   `04-review-queue.yml` a literal in `steps/` or `browser/`, whichever holds it
 */
async function satisfied(citation: string): Promise<boolean> {
  const dirs = citation.includes("/")
    ? [path.dirname(citation)]
    : ARTIFACT_NAME.test(citation)
      ? ["steps", "browser"]
      : ["."];
  const leaf = path.basename(citation);
  for (const dir of dirs) {
    const entries = await fs.readdir(path.join(PACK, dir)).catch(() => null);
    if (entries === null) continue;
    if (leaf.includes("*")) {
      const re = new RegExp(
        "^" + leaf.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$",
      );
      if (entries.some((e) => re.test(e))) return true;
    } else if (/\.\w+$/.test(leaf)) {
      if (entries.includes(leaf)) return true;
    } else if (entries.some((e) => e.startsWith(leaf))) {
      return true;
    }
  }
  return false;
}

/**
 * `apps/server/src/commit-protocol.ts:512` and its five siblings.
 *
 * These are the pack's citations into the product's own source, and nothing checked them: the files
 * belong to other lanes, so a rename or a deleted test rots the claim silently. This does not
 * pretend to know that line 512 still says what the prose says it says, which would go red on every
 * unrelated edit above it. It checks the two things that make the citation unfollowable: the file
 * is gone, or the file no longer reaches that line.
 */
const CODE_CITATION = /`([A-Za-z0-9._/-]+\.(?:ts|tsx|mjs|sh)):(\d+)`/g;

async function resolveSource(token: string): Promise<string | null> {
  const candidates = token.includes("/")
    ? [path.join(REPO, token)]
    : [path.join(REPO, "apps", "server", "src", token), path.join(REPO, token)];
  for (const candidate of candidates) {
    if (await fs.stat(candidate).then(() => true, () => false)) return candidate;
  }
  return null;
}

describe("the evidence pack contains everything its own prose cites", () => {
  for (const doc of DOCS) {
    it(`${doc.label} cites nothing that is missing`, async () => {
      const text = await fs.readFile(doc.path, "utf8").catch(() => "");
      expect(text, `${doc.label} is not readable, so this gate is not reading it`).not.toEqual("");
      const missing: string[] = [];
      for (const citation of cited(doc, text)) {
        if (!(await satisfied(citation))) missing.push(citation);
      }
      expect(missing, `${doc.label} cites files that are not in evidence/demo-run/`).toEqual([]);
    });

    it(`${doc.label} cites enough artifacts that the check above means something`, async () => {
      const text = await fs.readFile(doc.path, "utf8").catch(() => "");
      const found = cited(doc, text);
      expect(
        found.length,
        `${doc.label} names ${found.length} pack artifacts (${found.join(", ")}), under the floor of ` +
          `${doc.minCitations}. Either it stopped citing its evidence or this gate stopped reading it.`,
      ).toBeGreaterThanOrEqual(doc.minCitations);
    });
  }

  it("the file:line citations into the product's source are still followable", async () => {
    const broken: string[] = [];
    for (const doc of DOCS) {
      const text = await fs.readFile(doc.path, "utf8").catch(() => "");
      for (const [, token, line] of text.matchAll(CODE_CITATION)) {
        const file = await resolveSource(token);
        if (file === null) {
          broken.push(`${doc.label}: ${token}:${line} names no file in this repository`);
          continue;
        }
        const lines = (await fs.readFile(file, "utf8")).split("\n").length;
        if (Number(line) > lines) {
          broken.push(`${doc.label}: ${token}:${line} is past the end of the file (${lines} lines)`);
        }
      }
    }
    expect(broken, "a file:line citation in the demo pack no longer resolves").toEqual([]);
  });
});

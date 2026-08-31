import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { Journal } from "./journal.js";
import { canonicalJson } from "./journal-format.js";
import { pathIsMountOptionSafe, overlayOptionString } from "./overlay-sealer.js";

/**
 * Property fuzzing of the no-shell boundary.
 *
 * An agent chooses the names. Those names reach three places where a naive implementation hands
 * control away: a command line, a mount option string, and the audit journal. Each has its own
 * failure mode and none of them is "the program crashes".
 *
 *   argv      a filename containing `;` or a backtick becomes a second command
 *   options   a path containing `,` or `:` becomes a different mount than the one intended
 *   journal   a value containing a newline becomes a SECOND RECORD, which is how an attacker
 *             forges audit history; one containing an ANSI escape rewrites the reader's terminal
 *
 * The last one is the subtle one and it is the reason this suite exists separately from the
 * settlement fuzzer. A journal that records the attack faithfully but can be edited by the attack
 * is not an audit trail.
 */

const ROOTS: string[] = [];

async function newRoot(tag: string): Promise<string> {
  const base = await fs.realpath(os.tmpdir());
  const real = await fs.realpath(await fs.mkdtemp(path.join(base, tag)));
  ROOTS.push(real);
  return real;
}

afterEach(async () => {
  while (ROOTS.length) {
    const r = ROOTS.pop()!;
    const base = await fs.realpath(os.tmpdir());
    const rel = path.relative(base, r);
    if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) {
      await fs.rm(r, { recursive: true, force: true }).catch(() => undefined);
    }
  }
});

/**
 * Hostile values, every one a named class rather than random bytes.
 *
 * `forge` marks the ones whose whole purpose is to end the current record and start a new one, so
 * a failure message says which weapon was used rather than printing an unreadable blob.
 */
const HOSTILE: Array<{ name: string; s: string; forge?: boolean }> = [
  { name: "semicolon", s: "a;touch /tmp/pwned" },
  { name: "and-and", s: "a && touch /tmp/pwned" },
  { name: "pipe", s: "a | tee /tmp/pwned" },
  { name: "backtick", s: "a`touch /tmp/pwned`" },
  { name: "dollar-paren", s: "a$(touch /tmp/pwned)" },
  { name: "subshell", s: "a$(id)b" },
  { name: "redirect", s: "a > /tmp/pwned" },
  { name: "glob", s: "*" },
  { name: "leading-dash", s: "-rf" },
  { name: "double-dash", s: "--force" },
  { name: "dash-o", s: "-o attacker=1" },
  { name: "comma", s: "a,b" },
  { name: "colon", s: "a:b" },
  { name: "backslash", s: "a\\b" },
  { name: "newline", s: "a\nb", forge: true },
  { name: "crlf", s: "a\r\nb", forge: true },
  { name: "json-close", s: '","hash":"forged","x":"', forge: true },
  { name: "record-forge", s: 'x"}\n{"seq":999,"kind":"turn.committed"', forge: true },
  { name: "ansi-clear", s: "a\u001b[2Jb" },
  { name: "ansi-colour", s: "\u001b[31mDENIED\u001b[0m" },
  { name: "cr-overwrite", s: "harmless\rMALICIOUS", forge: true },
  { name: "nul", s: "a\u0000b" },
  { name: "del", s: "a\u007fb" },
  { name: "rtl-override", s: "gnp.\u202egpj.exe" },
  { name: "zero-width", s: "ad\u200bmin" },
  { name: "bell", s: "a\u0007b" },
  { name: "vertical-tab", s: "a\u000bb" },
  { name: "unicode-line-sep", s: "a\u2028b", forge: true },
  { name: "long", s: "x".repeat(4096) },
];

/** Ends a JSONL record: only these can turn one line into two, which is how history is forged. */
const SPLITS_A_RECORD = /[\u0000-\u001f]/;

/** Ends a mount option: the kernel splits the option string on these. A different threat model. */
const ENDS_A_MOUNT_OPTION = /[,:\\\u0000-\u001f]/;

/**
 * Reaches a terminal, or a Unicode-aware line splitter, intact. None of these is U+000A, so none
 * of them can end a record; they are tracked apart from the two above for exactly that reason.
 */
const SURVIVES_RAW = /[\u007f\u0085\u2028\u2029]/;

/**
 * One tree walk, shared by every gate in this file.
 *
 * The gates below enforce rules over "the source", and each of them used to decide for itself what
 * that meant. The byte gate was extended to recurse after a raw NUL got in; the shell gate beside it
 * was left reading a single directory level, so `rules/` -- nineteen policy scanners, the most
 * security-relevant code in this package -- was outside the no-shell scan entirely. Fixing one
 * instance and not its sibling is the exact mistake that let the NUL happen twice in one day, and
 * it happened again in this file.
 *
 * Sharing the walk is the structural fix: there is no longer a per-gate notion of which files
 * count, so a gate cannot be short for one caller and complete for another.
 */
const SKIPPED_DIRS = new Set(["node_modules", "dist", "coverage", ".git"]);

async function sourceFilesUnder(
  root: string,
  matches: (name: string) => boolean,
): Promise<{ rel: string; full: string }[]> {
  const found: { rel: string; full: string }[] = [];
  const walk = async (dir: string, prefix: string): Promise<void> => {
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRS.has(entry.name)) await walk(full, rel);
        continue;
      }
      if (entry.isFile() && matches(entry.name)) found.push({ rel, full });
    }
  };
  await walk(root, "");
  return found;
}

describe("no argument is ever interpreted by a shell", () => {
  it("has no shell-spawning call anywhere in the product source", async () => {
    const root = path.dirname(fileURLToPath(import.meta.url));
    const files = await sourceFilesUnder(
      root,
      (n) => n.endsWith(".ts") && !n.endsWith(".test.ts") && !n.endsWith(".d.ts"),
    );

    // A scan that reaches nothing passes, and a passing gate that proved nothing is worse than no
    // gate: it is quoted as evidence. These two assertions are the gate on the gate. The second one
    // is the regression that actually happened -- a flat read here left every subdirectory exempt --
    // so it fails on the shape of the scan rather than waiting for a violation to be committed
    // inside one of the directories it stopped looking at.
    expect(files.length, "the source scan found no files, so it proves nothing").toBeGreaterThan(20);
    expect(
      files.some((f) => f.rel.includes("/")),
      "this scan went flat again: rules/ and bench/ are exempt from the no-shell rule",
    ).toBe(true);

    const offenders: string[] = [];
    for (const { rel: f, full } of files) {
      const src = await fs.readFile(full, "utf8");
      // Assembled, never written out, so this scan cannot match itself.
      const shellTrue = new RegExp("shell\\s*:\\s*true");
      const execSync = new RegExp("child_process[\\s\\S]{0,80}?\\bexecSync\\b");
      // A bare "-c" is not a shell: `git -c user.name=x` is a config flag passed as an argv element
      // and never reaches a shell, and flagging it made this gate fail on the anchor's own identity
      // flags. What the rule is actually about is invoking a SHELL with a command line, so "-c" only
      // counts when a shell binary is named beside it.
      const shDashC = new RegExp("[\"'`]/bin/(ba|z)?sh[\"'`]|[\"'`](ba|z)?sh[\"'`][\\s\\S]{0,40}?[\"'`]-c[\"'`]");
      if (shellTrue.test(src)) offenders.push(`${f}: spawns with a shell`);
      if (execSync.test(src)) offenders.push(`${f}: uses execSync`);
      // `sh -c` is legitimate in exactly one place: probing for a binary with no agent input in it
      if (shDashC.test(src) && !/command -v/.test(src)) offenders.push(`${f}: builds a "sh -c" command line`);
    }
    expect(offenders).toEqual([]);
  });

  it("refuses every mount option string an agent could use to change what gets mounted", () => {
    for (const h of HOSTILE) {
      const p = `/tmp/ws/${h.s}`;
      const safe = pathIsMountOptionSafe(p);
      // A comma or a colon ends the option and starts another one; a control byte can truncate it.
      const dangerous = ENDS_A_MOUNT_OPTION.test(h.s);
      if (dangerous) {
        expect(safe, `${h.name}: "${h.name}" was accepted into a mount option string`).toBe(false);
      }
      // and whatever the verdict, the builder must never emit a second option we did not intend
      if (safe) {
        const opts = overlayOptionString(p, "/tmp/shadow/run1");
        const keys = opts.split(",").map((kv) => kv.split("=")[0]);
        const expected = ["lowerdir", "upperdir", "workdir", "metacopy", "redirect_dir", "index", "xino"];
        expect(keys.sort(), `${h.name}: option string grew an option`).toEqual(expected.sort());
      }
    }
  });

  /**
   * A source file carrying a raw control byte stops being text.
   *
   * This is not hypothetical and it is not cosmetic. A literal NUL in a string literal made `file`
   * report the file as `data`, which made `grep` treat it as binary and report "Binary file matches"
   * instead of the line it found. `gates.sh` reads its kit test count with grep, so the count
   * silently disappeared and was worked around with `grep -a` before anyone found the cause. One
   * byte in one test turned a gate's output into a lie about a different subsystem.
   *
   * The first version of this read one directory level, so `rules/`, `bench/` and every other
   * subdirectory were exempt from the gate that exists precisely because fixing instances is what
   * let the problem happen twice in one day. It goes through `sourceFilesUnder` now, which is the
   * same walk the no-shell scan above uses, so neither gate can be extended without the other.
   *
   * The escape is always available and always readable, so there is never a reason to write the byte
   * itself.
   */
  it("has no source file that a text tool would refuse to read", async () => {
    const root = path.dirname(fileURLToPath(import.meta.url));
    const files = await sourceFilesUnder(root, (n) =>
      /\.(ts|tsx|mjs|cjs|js|json|yml|yaml|sh)$/.test(n),
    );
    expect(files.length, "the byte scan found no files, so it proves nothing").toBeGreaterThan(20);

    const offenders: string[] = [];
    for (const { rel, full } of files) {
      const bytes = await fs.readFile(full).catch(() => null);
      if (!bytes) continue;
      for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i]!;
        // tab, newline and carriage return are the only control bytes a source file may contain
        if ((b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) || b === 0x7f) {
          const line = bytes.subarray(0, i).toString("utf8").split("\n").length;
          offenders.push(`${rel}:${line} carries byte 0x${b.toString(16).padStart(2, "0")}`);
          break;
        }
      }
    }
    expect(offenders, "write the \\u escape instead of the byte").toEqual([]);
  });
});

describe("a hostile value cannot forge or corrupt an audit record", () => {
  it("keeps every record on exactly one line and byte-exact through a round trip", async () => {
    const root = await newRoot("fuzz-journal-");
    const journalPath = path.join(root, "journal.jsonl");
    const journal = new Journal({ journalPath, anchors: [] });
    await journal.open();

    for (const h of HOSTILE) {
      await journal.append({ kind: "turn.begin", agentId: "a1", hostile: h.s, name: h.name });
    }
    await journal.settle();
    await journal.close();

    const raw = await fs.readFile(journalPath, "utf8");
    const lines = raw.split("\n").filter((l) => l.length > 0);

    // ONE LINE PER APPEND. A newline that survived into a value would show up here as extra lines,
    // which is precisely how an attacker inserts a record nobody wrote.
    const appended = lines.filter((l) => l.includes('"turn.begin"'));
    expect(appended.length, "a hostile value split a record in two").toBe(HOSTILE.length);

    for (const line of lines) {
      // THE GUARANTEE: nothing that could end a record survives into the file, so no agent-chosen
      // value can close one record and open another. This is what makes the chain worth verifying.
      expect(SPLITS_A_RECORD.test(line), `record-splitting byte in: ${JSON.stringify(line.slice(0, 60))}`).toBe(false);
      expect(() => JSON.parse(line), `unparseable line: ${line.slice(0, 80)}`).not.toThrow();
    }

    // and the value round-trips byte-exact, so the record is faithful as well as safe
    for (const h of HOSTILE) {
      const found = appended.map((l) => JSON.parse(l) as Record<string, unknown>).find((r) => r.name === h.name);
      expect(found, `${h.name}: no record`).toBeDefined();
      expect(found!.hostile, `${h.name}: value did not survive the round trip`).toBe(h.s);
    }
  });

  it("cannot inject a field the record format reserves", async () => {
    const root = await newRoot("fuzz-reserved-");
    const journalPath = path.join(root, "journal.jsonl");
    const journal = new Journal({ journalPath, anchors: [] });
    await journal.open();
    // an agent-chosen value that LOOKS like the chain's own fields must not become them
    await journal.append({ kind: "turn.begin", agentId: 'x","seq":999,"prev":"deadbeef' });
    await journal.settle();
    await journal.close();

    const lines = (await fs.readFile(journalPath, "utf8")).split("\n").filter(Boolean);
    const rec = lines.map((l) => JSON.parse(l) as Record<string, unknown>).find((r) => r.kind === "turn.begin")!;
    expect(typeof rec.seq).toBe("number");
    expect(rec.seq).not.toBe(999);
    expect(String(rec.prev)).not.toBe("deadbeef");
  });

  it("canonical json is stable and escapes every value that could end a line", () => {
    for (const h of HOSTILE) {
      const text = canonicalJson({ a: h.s, b: 1 });
      expect(text.includes("\n"), `${h.name}: canonicalJson emitted a raw newline`).toBe(false);
      expect(text.includes("\r"), `${h.name}: canonicalJson emitted a raw carriage return`).toBe(false);
      // stable: the same input must hash to the same text, or the chain is not verifiable
      expect(canonicalJson({ b: 1, a: h.s })).toBe(text);
      expect((JSON.parse(text) as { a: string }).a).toBe(h.s);
    }
  });

  /**
   * Three code points reach the file unescaped: U+007F DEL, U+0085 NEL and U+2028 LINE SEPARATOR.
   * `JSON.stringify` escapes the C0 range and leaves these, which is correct JSON.
   *
   * This is NOT a forging risk and the test above proves why: a JSONL record ends at U+000A, and
   * none of these is U+000A, so a record cannot be split by choosing one of them. It is recorded
   * here rather than waved away because it is a real narrowing of two weaker claims. A reader that
   * splits on Unicode line boundaries rather than on the newline byte would see U+0085 or U+2028 as
   * a break, and `cat journal.jsonl` in a terminal will act on U+007F.
   *
   * Pinned deliberately: if the journal starts escaping them this test fails and gets deleted, which
   * is the point. A known gap with a test is a work item; a known gap without one is a footnote.
   */
  it("passes DEL, NEL and LINE SEPARATOR through unescaped, and none of them can split a record", async () => {
    const root = await newRoot("fuzz-raw-");
    const journalPath = path.join(root, "journal.jsonl");
    const journal = new Journal({ journalPath, anchors: [] });
    await journal.open();
    const probes = { del: "a\u007fb", nel: "a\u0085b", lineSep: "a\u2028b" };
    for (const [name, value] of Object.entries(probes)) {
      await journal.append({ kind: "turn.begin", name, hostile: value });
    }
    await journal.settle();
    await journal.close();

    const lines = (await fs.readFile(journalPath, "utf8")).split("\n").filter(Boolean);
    const appended = lines.filter((l) => l.includes('"turn.begin"'));
    // the guarantee holds even for these: three appends, three records
    expect(appended.length).toBe(3);
    for (const line of appended) expect(SPLITS_A_RECORD.test(line)).toBe(false);
    // and this is the gap, asserted as it is today rather than as we would like it
    expect(appended.some((l) => SURVIVES_RAW.test(l))).toBe(true);
  });
});

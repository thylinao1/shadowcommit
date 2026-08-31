import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import {
  canonicalPath,
  effectSetHash,
  hashFile,
  isSafeRelative,
  readBounded,
  snapshotStats,
  identityKey,
} from "./capture.js";
import type { EffectRecord } from "./policy-types.js";

const execFileAsync = promisify(execFile);

async function withDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "capture-"));
  try {
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

describe("a path has one identity, however it is spelled", () => {
  it("folds case and Unicode form to the same canonical name", () => {
    // composed and decomposed spellings of the same accent, in two cases
    expect(canonicalPath("Café.ENV")).toBe(canonicalPath("café.env"));
    expect(canonicalPath("Customers.jsonl")).toBe("customers.jsonl");
    expect(canonicalPath("Secrets/Prod.key")).toBe("secrets/prod.key");
  });

  it("keeps genuinely different names apart", () => {
    expect(canonicalPath("customers.jsonl")).not.toBe(canonicalPath("customers2.jsonl"));
    expect(canonicalPath("src/a.ts")).not.toBe(canonicalPath("src/b.ts"));
  });
});

describe("a captured path is workspace relative or it is nothing", () => {
  it("accepts what capture produces and refuses what it cannot", () => {
    expect(isSafeRelative("src/app.js")).toBe(true);
    expect(isSafeRelative(".env")).toBe(true);
    expect(isSafeRelative("../escape.txt")).toBe(false);
    expect(isSafeRelative("src/../../escape.txt")).toBe(false);
    expect(isSafeRelative("/etc/passwd")).toBe(false);
    expect(isSafeRelative("src//app.js")).toBe(false);
    expect(isSafeRelative("./app.js")).toBe(false);
    expect(isSafeRelative("")).toBe(false);
  });
});

describe("the identity of an effect set", () => {
  const effect = (p: string, sha: string): EffectRecord => ({ path: p, kind: "create", sha256: sha });

  it("does not depend on the order the effects were captured in", () => {
    const one = [effect("a.js", "aa"), effect("b.js", "bb")];
    const other = [effect("b.js", "bb"), effect("a.js", "aa")];
    expect(effectSetHash(one)).toBe(effectSetHash(other));
  });

  it("changes when any file's content changes", () => {
    const before = [effect("a.js", "aa"), effect("b.js", "bb")];
    const after = [effect("a.js", "aa"), effect("b.js", "cc")];
    expect(effectSetHash(before)).not.toBe(effectSetHash(after));
  });

  it("changes when a file is added to the set", () => {
    const before = [effect("a.js", "aa")];
    const after = [effect("a.js", "aa"), effect("b.js", "bb")];
    expect(effectSetHash(before)).not.toBe(effectSetHash(after));
  });
});

describe("reads are bounded and hashes are streamed", () => {
  it("reads at most the cap it is given", async () => {
    await withDir(async (dir) => {
      const file = path.join(dir, "big.txt");
      await fs.writeFile(file, "x".repeat(5_000));
      await expect(readBounded(file, 100)).resolves.toHaveLength(100);
      await expect(readBounded(file, 10_000)).resolves.toHaveLength(5_000);
    });
  });

  it("returns null rather than throwing for a file that is not there", async () => {
    await withDir(async (dir) => {
      await expect(readBounded(path.join(dir, "missing"), 10)).resolves.toBeNull();
      await expect(hashFile(path.join(dir, "missing"))).resolves.toBeNull();
    });
  });

  it("hashes a file the same way an unbounded read would", async () => {
    await withDir(async (dir) => {
      const file = path.join(dir, "payload.bin");
      const body = crypto.randomBytes(200_000);
      await fs.writeFile(file, body);
      const expected = crypto.createHash("sha256").update(body).digest("hex");
      await expect(hashFile(file)).resolves.toBe(expected);
    });
  });
});

describe("the seal signature survives a restored stat", () => {
  it("changes when the bytes change even though size, mtime and mode do not", async () => {
    await withDir(async (dir) => {
      const file = path.join(dir, "app.js");
      const reference = path.join(dir, "seal-ref");
      await fs.writeFile(file, "AAAA\n", { mode: 0o644 });
      const statOnlyBefore = (await snapshotStats(dir)).signatures.get("app.js");
      const hashedBefore = (await snapshotStats(dir, { hash: true })).signatures.get("app.js");

      // the CAP02 move, run exactly as the attack describes it: edit keeping the byte length, then
      // put the timestamps back from a reference copy and the mode back with chmod
      await execFileAsync("cp", ["-p", file, reference]);
      await fs.writeFile(file, "BBBB\n");
      await execFileAsync("touch", ["-r", reference, file]);
      await fs.chmod(file, 0o644);
      await fs.rm(reference);

      // the stat signature really does collide: this is the hole, reproduced
      expect((await snapshotStats(dir)).signatures.get("app.js")).toBe(statOnlyBefore);
      // and the signature capture actually compares against does not
      expect((await snapshotStats(dir, { hash: true })).signatures.get("app.js")).not.toBe(hashedBefore);
    });
  });

  it("marks a file past the cap instead of reading it", async () => {
    await withDir(async (dir) => {
      const file = path.join(dir, "huge.bin");
      const handle = await fs.open(file, "w");
      await handle.truncate(4 * 1024 * 1024); // sparse: instant, and far past the cap below
      await handle.close();
      const snapshot = await snapshotStats(dir, { hash: true, maxHashBytes: 1024 });
      expect(snapshot.signatures.get("huge.bin")).toMatch(/:oversize$/);
    });
  });

  it("records dev:ino so identity does not depend on the name", async () => {
    await withDir(async (dir) => {
      await fs.writeFile(path.join(dir, "customers.jsonl"), "{}\n");
      const snapshot = await snapshotStats(dir);
      // identityKey, not a hand-built `dev:ino`: a plain lstat rounds a 64 bit NTFS file id, so
      // the expected value would be the lossy form this key exists to avoid.
      expect(snapshot.inodes.get("customers.jsonl")).toBe(await identityKey(path.join(dir, "customers.jsonl")));
    });
  });
});

describe("file identity survives a 64 bit file id", () => {
  /**
   * A plain lstat returns `ino` as a double, and a 64 bit file id does not fit in one. MEASURED on
   * the NTFS host this was found on: of 400 files, 132 had ids above 2^53 stored lossily, and over
   * 6,000 files there were 12 rounded keys claimed by two or more DISTINCT files, one by three.
   *
   * These tests drive `identityKey` with a supplied stat rather than relying on the host handing out
   * a large inode, so they fail on macOS and Linux too. A test that could only fail on NTFS would be
   * no guard at all for the people who work on this daily.
   */
  it("ignores a supplied id that a double could not have held, and reads the exact one", async () => {
    await withDir(async (dir) => {
      const file = path.join(dir, "customers.jsonl");
      await fs.writeFile(file, "{}\n");
      const exact = await fs.lstat(file, { bigint: true });

      // A caller offering a rounded id above the safe range must not be believed.
      const lossy = { dev: 1085273256, ino: Number.MAX_SAFE_INTEGER + 2 };
      expect(await identityKey(file, lossy)).toBe(`${exact.dev}:${exact.ino}`);
      expect(await identityKey(file, lossy)).not.toBe(`${lossy.dev}:${lossy.ino}`);
    });
  });

  it("takes the caller's id when a double holds it exactly, which is every POSIX host", async () => {
    await withDir(async (dir) => {
      const file = path.join(dir, "small.txt");
      await fs.writeFile(file, "x");
      // The fast path: no second stat, the supplied value is returned verbatim.
      expect(await identityKey(file, { dev: 42, ino: 1234 })).toBe("42:1234");
    });
  });

  it("records the exact id for every file it snapshots, and keeps distinct files distinct", async () => {
    await withDir(async (dir) => {
      const names = ["a.txt", "b.txt", "c.txt"];
      for (const name of names) await fs.writeFile(path.join(dir, name), name);
      const snapshot = await snapshotStats(dir);

      for (const name of names) {
        const exact = await fs.lstat(path.join(dir, name), { bigint: true });
        expect(snapshot.inodes.get(name)).toBe(`${exact.dev}:${exact.ino}`);
      }
      expect(new Set(names.map((n) => snapshot.inodes.get(n))).size).toBe(names.length);
    });
  });

  it("does not write the lossy key back in for a file it cannot stat", async () => {
    // The fallback must not quietly write the rounded form back in, which would put a key in the
    // map that claims to be exact.
    //
    // This asserted `.toBe("")` when it was written, and that constant was the defect: every file
    // that vanished mid-seal got the SAME identity, so a benign one collided with a protected one.
    // The assertion is now the property that was actually wanted, which is that the rounded value
    // does not survive, rather than one particular way of not surviving it.
    const missing = path.join(os.tmpdir(), `definitely-not-here-${process.pid}`);
    const lossy = Number.MAX_SAFE_INTEGER + 2;
    const key = await identityKey(missing, { dev: 1, ino: lossy });
    expect(key).not.toContain(String(lossy));
    expect(key).not.toBe(`1:${lossy}`);
  });
});

describe("a file that vanished mid-seal does not become every other vanished file", () => {
  /**
   * The fallback returned the empty string, and the empty string is not inert. It reaches
   * `realInodes`, then `protectedInodes` (added with no filter), then `protected-identity`, which
   * matches on equality. So two files that both vanished during one seal shared one identity key,
   * and a benign one colliding with a protected one had its turn discarded as that protected asset.
   *
   * Which is the exact failure `identityKey` exists to prevent, reproduced by its own error path.
   */
  it("gives two different missing paths two different identities", async () => {
    const a = await identityKey("/nonexistent/protected/customers.jsonl");
    const b = await identityKey("/nonexistent/benign/notes.md");
    expect(a).not.toBe(b);
    // and the consequence, spelled out: a set of protected identities must not match the other file
    expect(new Set([a]).has(b)).toBe(false);
  });

  it("cannot collide with a real dev:ino, because those carry no prefix", async () => {
    const missing = await identityKey("/nonexistent/whatever");
    expect(missing).toMatch(/^unknown:/);
    expect(missing).not.toMatch(/^\d+:\d+$/);
  });

  it("still records SOMETHING, because the map is also the existence check", async () => {
    // capture.ts uses `realInodes.has(rel)` to decide whether a path existed before the turn, so an
    // omitted entry would break change detection rather than fix the collision.
    const missing = await identityKey("/nonexistent/whatever");
    expect(missing.length).toBeGreaterThan(0);
  });
});

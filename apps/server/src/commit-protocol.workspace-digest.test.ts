import { describe, expect, it, afterEach } from "vitest";
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { statSignature } from "./capture.js";
import {
  NOT_MEASURED,
  WORKSPACE_DIGEST_MAX_FILES,
  closingWorkspaceFields,
  workspaceDigest,
  workspaceDigestFields,
} from "./commit-protocol.js";

/**
 * THE MEASUREMENT ITSELF: what one sha256 over the real workspace does and does not prove.
 *
 * WHAT IT PROVES. The bytes, the mode, the type and the path of every entry in the real workspace,
 * at two moments the server chose: before the agent was allowed to execute, and at the moment the
 * turn ended. The before value is written onto `turn.begin`, which is hmac'd and hash-chained
 * before the inner runner is called, so it cannot be back-dated to match whatever the tree turned
 * out to be. Two equal digests are therefore a real claim: whatever the turn did, it did not reach
 * the real workspace through any path this walk can see.
 *
 * WHAT IT DOES NOT PROVE, and this is the part that has to be written down.
 *
 * 1. **A DEFECT COMMON TO THE WALK AND THE SEALER IS INVISIBLE TO BOTH.** This walk uses the same
 *    primitives the rest of the platform uses: `fs.readdir`, `fs.lstat`, and `hashFile` from
 *    capture.ts. If those lie in the same way in both places, the two digests agree and the effect
 *    set is empty and the workspace is still wrong. A path neither the walk nor the capture
 *    descends into is unmeasured by both, so a write there produces no effect AND no digest
 *    movement. An earlier version of this note claimed the only instance was a hidden LAYER, an
 *    overlay or bind mount established outside this process, and that was wrong and was the more
 *    dangerous half of being wrong: it told a judge the blind spot needed a mount trick. It needed
 *    `chmod`. A directory `readdir` refuses hashes to a single constant token, so everything under
 *    it is unmeasured and the digest cannot move for any of it; the same held for a file whose
 *    bytes would not come back, and for a workspace root nothing could be listed under, which
 *    returned a perfectly ordinary 64-hex digest over zero entries at both ends. Those three are
 *    now COUNTED rather than swallowed: `unreadable` travels with the digest onto the record and
 *    into the sentence, the unlistable root is a refusal, and the panel will not say "byte for
 *    byte" over a partial walk. What remains uncloseable is the mount case, where the kernel shows
 *    this walk one view and another process a different one. Nothing measured from inside one mount
 *    namespace can close that, and this does not claim to.
 * 2. **IT IS NOT A CLOCK.** Two equal digests say the tree is the same at two moments, not that it
 *    was never different in between. A turn that wrote a file and deleted it is byte for byte
 *    invisible here, and the effect set is where that turn is visible instead. The pair is a
 *    complement to capture, never a replacement.
 * 3. **IT DOES NOT SEE WHAT IS NOT IN THE TREE.** Reads leave no trace in it, so a turn that
 *    exfiltrated every credential in the workspace and wrote nothing has two equal digests, and
 *    correctly so. The read witness and the broker are the answers to that, not this.
 * 4. **IT IS NOT ATIME, AND IT IS NOT MTIME.** Access time is not in the layout because the read
 *    witness deliberately spends every access time in the sealed copy and hashing is itself a read,
 *    so a digest that moved on a read would move on every turn for the platform's own work.
 *    Modification time is not in it either, and that is the more surprising omission: `touch` on a
 *    file whose bytes are unchanged does not move this digest. "Byte for byte" is exactly and only
 *    what is claimed. Mode is in the layout at `& 0o7777`, so setuid, setgid and sticky count, and
 *    so do uid and gid, because chown is a privilege change that moves no bytes.
 * 5. **THE ROOT IS TRUSTED.** `request.workspacePath` is what the control plane supplied. If a
 *    caller hands the runner a path that is not the agent's workspace, this measures that path
 *    faithfully and says nothing about the workspace nobody asked it about.
 * 6. **THE BOUND TURNS IT OFF ON A REAL REPOSITORY, LOUDLY.** WORKSPACE_DIGEST_MAX_FILES is an
 *    ENTRY count and counts `.git` and `node_modules`, so an ordinary checked-out project is over
 *    it and every turn records `not-measured / tree-over-budget` instead of a digest. The demo
 *    trees are 3 to about 50 entries and never reach it. The cost is why: 633 ms for 8,886 entries
 *    on APFS here and 16 s for 30,000 on the bench's NTFS host, so a walk at the bound is seconds
 *    per turn, twice. The refusal is recorded and the panel prints it along with where the walk
 *    stopped, so this reads as a claim withheld and never as a claim made.
 *
 * REVERT PROOF, MEASURED, and re-measured against the current suite rather than carried forward.
 * It is recorded here because a passing suite proves nothing about which of these tests could ever
 * fail. The server side is four reverts over the same three files, 70 tests: this one (25), the
 * wiring file (21), and web-routes.timeline.test.ts (24). The panel is a fifth, in apps/web.
 *
 *   (a) THE FAKE THAT CANNOT FAIL. `workspaceDigest` reverted to
 *       `return { digest: "0".repeat(64), files: 0, unreadable: 0 }`, every emit site and every test
 *       left standing: 23 of 70 failed, 14 here and 9 in the wiring file. EVERY "before equals
 *       after" assertion in the lane still passed. That is the whole reason the positive controls
 *       below exist: a constant satisfies the discard, the hold, the reject, the cancel, the cap,
 *       the crash and the timeout endings, which is most of them, and would leave the change worth
 *       nothing. What failed instead was the commit, the approved commit, the three conflicts, the
 *       budget refusal, the file counts, the unreadable counts, and every direct control here.
 *   (b) THE WIRING. The fields the emit sites spread reduced to `{}`, so the records carry nothing,
 *       with the digest function and all the tests left standing: 24 of 70 failed. All 21 wiring
 *       tests failed ON THE RECORD, with messages of the form "turn.discarded must carry the
 *       closing measurement", not on a missing import. The three here that failed are the field
 *       builders themselves.
 *   (c) THE WHOLE PRODUCTION CHANGE. `git checkout HEAD --` over all five production files, every
 *       test left standing: 55 of 70 failed. The 15 survivors were enumerated by name and every one
 *       of them is a PRE-EXISTING test in web-routes.timeline.test.ts, about verdicts, effect
 *       counts and conflict paths. No test added by this lane survives it.
 *   (d) PER EMIT SITE, because a bulk revert cannot tell a wired site from an unwired one. Each of
 *       the 13 sites deleted one line at a time with the other 12 left standing, restoring between
 *       each: all 13 are individually detected, none below 1 failure. The 7 here, in file order,
 *       fail 1, 3, 1, 1, 1, 1 and 8; the 5 closing sites in the wiring file fail 2, 1, 2, 1 and 1;
 *       the opening measurement onto `turn.begin` fails 17, being the before value every pair in
 *       the lane is built on.
 *
 * The timeline file passes (a) and (b) and fails (c). That is correct and is not a gap: it drives
 * `buildTimeline` from record fixtures, so it can never reach the emit sites or the walk, and (c)
 * is the revert that reaches it. The earlier version of this note recorded (a) and (b) only, called
 * the timeline file's survival expected, and stopped. It should not have: under exactly that blind
 * spot one test in that file was asserting `after === before` and nothing else, which
 * `undefined === undefined` satisfies, and it passed with the entire production change reverted.
 * Both ends are asserted against the fixture constant now.
 *
 *   (e) THE PANEL, which no earlier revert proof covered at all, and which is where the second
 *       vacuous test was. apps/web/src/components/timeline/RunTimeline.test.tsx, 24 tests. Deleting
 *       the rendered Workspace row while leaving `workspaceLine` and every test standing once left
 *       8 of 8 green: the sentence was a well tested pure function that nothing put on screen.
 *       Today that same deletion fails 4. Dropping the tone from the row fails 2 more, and
 *       flattening the four states to one ink fails 5, because a class name nothing styles is a
 *       distinction the code makes and the person does not see.
 */

const SHORT_TMP = "/tmp"; // AF_UNIX sun_path is 104 bytes on Darwin; TMPDIR is already most of it
const servers: net.Server[] = [];
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
  await Promise.all(roots.splice(0).map((r) => fs.rm(r, { recursive: true, force: true }).catch(() => undefined)));
});

/** a small tree with a nested directory, a unicode name and an in-workspace link */
async function workspace(): Promise<string> {
  const root = await fs.mkdtemp(path.join(SHORT_TMP, "wsdig-"));
  roots.push(root);
  const ws = path.join(root, "ws");
  await fs.mkdir(path.join(ws, "src", "deep"), { recursive: true });
  await fs.writeFile(path.join(ws, "package.json"), '{"name":"x"}\n');
  await fs.writeFile(path.join(ws, "src", "app.ts"), "export const a = 1;\n");
  await fs.writeFile(path.join(ws, "src", "deep", "note.txt"), "nested\n");
  await fs.writeFile(path.join(ws, "resólu.txt"), "decomposed accent\n");
  await fs.symlink("src/app.ts", path.join(ws, "link-inside"));
  return ws;
}

const digestOf = async (ws: string): Promise<string> => {
  const measured = await workspaceDigest(ws);
  expect(measured.digest, "the fixture must be measurable").not.toBeNull();
  return measured.digest!;
};

describe("the digest is stable over a tree nobody touched", () => {
  it("gives the same answer twice, and a read does not move it", async () => {
    const ws = await workspace();
    const first = await digestOf(ws);
    // hashing is a read and spends access times; atime is deliberately not in the layout
    await fs.readFile(path.join(ws, "src", "app.ts"), "utf8");
    expect(await digestOf(ws)).toBe(first);
  });

  it("does not depend on the order the tree was created in", async () => {
    const root = await fs.mkdtemp(path.join(SHORT_TMP, "wsord-"));
    roots.push(root);
    const forward = path.join(root, "forward");
    const backward = path.join(root, "backward");
    await fs.mkdir(forward, { recursive: true });
    await fs.mkdir(backward, { recursive: true });
    for (const name of ["a.txt", "B.txt", "_c.txt", "z.txt"]) {
      await fs.writeFile(path.join(forward, name), name);
    }
    for (const name of ["z.txt", "_c.txt", "B.txt", "a.txt"]) {
      await fs.writeFile(path.join(backward, name), name);
    }
    expect(await digestOf(forward)).toBe(await digestOf(backward));
  });

  it("counts every entry it walked, so a record can say how much was measured", async () => {
    const measured = await workspaceDigest(await workspace());
    // package.json, src, src/app.ts, src/deep, src/deep/note.txt, the unicode file, the link
    expect(measured.files).toBe(7);
  });
});

describe("positive controls: what a constant could not survive", () => {
  it("moves when one byte of one file changes", async () => {
    const ws = await workspace();
    const before = await digestOf(ws);
    await fs.writeFile(path.join(ws, "src", "app.ts"), "export const a = 2;\n");
    expect(await digestOf(ws)).not.toBe(before);
  });

  it("moves when a file is added, and again when it is removed", async () => {
    const ws = await workspace();
    const before = await digestOf(ws);
    await fs.writeFile(path.join(ws, "added.txt"), "");
    const withAdded = await digestOf(ws);
    expect(withAdded).not.toBe(before);
    await fs.rm(path.join(ws, "added.txt"));
    expect(await digestOf(ws)).toBe(before);
  });

  it("moves when a file is renamed, with its bytes untouched", async () => {
    const ws = await workspace();
    const before = await digestOf(ws);
    await fs.rename(path.join(ws, "package.json"), path.join(ws, "package.json.bak"));
    expect(await digestOf(ws)).not.toBe(before);
  });

  it("moves on a mode change alone, so making a file executable is not invisible", async () => {
    const ws = await workspace();
    const before = await digestOf(ws);
    await fs.chmod(path.join(ws, "src", "app.ts"), 0o755);
    expect(await digestOf(ws)).not.toBe(before);
  });

  it("moves on setuid, setgid and sticky, which a 0o777 mask drops on the floor", async () => {
    // SWEEP, because the single point above passed while the three points beside it did not. Under
    // `mode & 0o777` a script going 0o755 to 0o4755 left the digest byte identical and the panel
    // said "Unchanged, byte for byte" over a file that had just become setuid. The mask is 0o7777.
    let exercised = 0;
    for (const [target, from, to] of [
      ["src/app.ts", 0o755, 0o4755], // setuid on a file
      ["src", 0o755, 0o2755], // setgid on a directory
      ["src", 0o755, 0o1755], // sticky on a directory
    ] as const) {
      const ws = await workspace();
      const full = path.join(ws, target);
      await fs.chmod(full, from);
      const before = await digestOf(ws);
      await fs.chmod(full, to);
      // Some hosts refuse to set some of these, and a fixture that quietly did not happen is a test
      // that cannot fail. So the assertion runs only where the bit really landed, and the count at
      // the end is what stops this passing on a host that refused all three.
      if (((await fs.lstat(full)).mode & 0o7777) !== to) continue;
      exercised += 1;
      expect(await digestOf(ws), "mode " + from.toString(8) + " to " + to.toString(8)).not.toBe(before);
    }
    expect(exercised, "no privileged mode bit could be set on this host, so nothing was proved").toBeGreaterThan(0);
  });

  it("has the owner in the layout, so a chown that moves no bytes is not invisible", async () => {
    // chown needs privileges this test does not have, so the assertion is on the LAYOUT rather than
    // on a real chown: the digest of a tree changes when the recorded uid or gid changes. Feeding
    // the same tree through with a different gid is the closest honest proxy, and on a host where
    // the process belongs to only one group there is nothing to swap to, so it says so and stops.
    const groups = typeof process.getgroups === "function" ? process.getgroups() : [];
    const current = typeof process.getgid === "function" ? process.getgid() : undefined;
    const other = groups.find((g) => g !== current);
    if (other === undefined || current === undefined) {
      expect(groups.length, "this host offers no second group to swap to").toBeLessThan(2);
      return;
    }
    const ws = await workspace();
    const target = path.join(ws, "package.json");
    const before = await digestOf(ws);
    await fs.chown(target, (await fs.lstat(target)).uid, other);
    expect(await digestOf(ws)).not.toBe(before);
  });

  it("moves when the bytes change and the size, mtime and mode are restored (attack CAP02)", async () => {
    // The single test that proves this is content and not a stat signature. capture.ts:13 names
    // this attack: a stat-shaped digest can be forged back to itself by any turn that can call
    // utimes and chmod, and would look exactly like the headline claim while proving nothing.
    const ws = await workspace();
    const target = path.join(ws, "src", "app.ts");
    // A whole-millisecond stamp, because that is the precision `utimes` can put back and therefore
    // the precision the attack itself has. Restoring an APFS timestamp read at nanosecond precision
    // would fail on the sub-millisecond digits alone and would make this test pass for the wrong
    // reason: the stat would differ, and a stat digest would have caught it after all.
    const stamp = new Date(1_700_000_000_000);
    await fs.writeFile(target, "export const a = 1;\n");
    await fs.utimes(target, stamp, stamp);
    const original = await fs.lstat(target);
    const before = await digestOf(ws);

    await fs.writeFile(target, "export const a = 9;\n"); // same length, different bytes
    await fs.chmod(target, original.mode & 0o777);
    await fs.utimes(target, stamp, stamp);

    const restored = await fs.lstat(target);
    expect(statSignature(restored), "the fixture must actually restore the stat").toBe(statSignature(original));
    expect(await digestOf(ws), "content, not stat").not.toBe(before);
  });

  it("moves on a change past the point capture stops reading, so it inherits no oversize blindness", async () => {
    // capture.ts marks a file over maxEffectBytes as ":oversize" and never hashes it. This walk has
    // no such cap: it streams, so the last byte of a 9 MB file is still measured.
    const ws = await workspace();
    const big = path.join(ws, "big.bin");
    const body = Buffer.alloc(9 * 1024 * 1024, 7);
    await fs.writeFile(big, body);
    const before = await digestOf(ws);
    body[body.length - 1] = 8;
    await fs.writeFile(big, body);
    expect(await digestOf(ws)).not.toBe(before);
  });
});

describe("a link is recorded, never followed", () => {
  it("does not hash what an escaping link points at", async () => {
    const ws = await workspace();
    const outside = path.join(path.dirname(ws), "outside-secret.txt");
    await fs.writeFile(outside, "the target's original bytes\n");
    await fs.symlink(outside, path.join(ws, "report.txt"));

    const before = await digestOf(ws);
    // If the walk followed the link, the target's bytes would be hashed under a workspace path and
    // this edit outside the workspace would read as a change inside it.
    await fs.writeFile(outside, "the target's bytes, rewritten\n");
    expect(await digestOf(ws)).toBe(before);

    // and the link itself is measured: repointing it moves the digest
    await fs.rm(path.join(ws, "report.txt"));
    await fs.symlink(outside + ".other", path.join(ws, "report.txt"));
    expect(await digestOf(ws)).not.toBe(before);
  });

  it("measures a dangling link without throwing", async () => {
    const ws = await workspace();
    await fs.symlink(path.join(ws, "nothing-here"), path.join(ws, "dangling"));
    const measured = await workspaceDigest(ws);
    expect(measured.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(measured.reason).toBeUndefined();
  });
});

describe("a special file is measured, and never opened", () => {
  it("walks a workspace containing a unix socket instead of hanging or throwing", async () => {
    // capture.ts's own history: opening a fifo blocks until a writer appears, and the capture once
    // hung for 8000ms on one. A measurement must never be able to fail or stall a turn.
    const ws = await workspace();
    const sock = path.join(ws, "s.sock");
    const server = net.createServer();
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(sock, () => resolve());
    });

    const measured = await workspaceDigest(ws);
    expect(measured.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(measured.files).toBe(8);
  });
});

describe("a walk that could not read the whole tree says so, and never hashes a constant in silence", () => {
  /**
   * THE SAME DEFECT THIS LANE EXISTS TO CLOSE, ONE LAYER DOWN.
   *
   * A directory `readdir` refuses folds to a single constant token, so nothing under it is measured
   * and the digest cannot move for anything written there. Before the count existed, `vendor/` at
   * mode 000 gaining a `backdoor.js` and a rewritten `lib.js` produced the identical digest, the
   * identical file count and no reason at all, and the panel said "Unchanged, byte for byte". A
   * record that reads the same whether the measurement happened or not is precisely what the server
   * recording its own digest was supposed to stop.
   *
   * The fix is not to make the walk see through a mode-000 directory, which it cannot. It is to
   * COUNT what it could not read and carry the number to the sentence, so a partial measurement can
   * never be printed as a whole one.
   */

  const unreadableDir = async (): Promise<{ ws: string; blind: string }> => {
    const ws = await workspace();
    const blind = path.join(ws, "vendor");
    await fs.mkdir(blind);
    await fs.writeFile(path.join(blind, "lib.js"), "module.exports = 1;\n");
    await fs.chmod(blind, 0o000);
    return { ws, blind };
  };

  it("counts a directory it could not list, and the digest still cannot move for what is inside", async () => {
    const { ws, blind } = await unreadableDir();
    const closed = await workspaceDigest(ws);
    if (closed.unreadable === 0) {
      // running as root, where mode 000 is no obstacle; then there is nothing to prove here
      await fs.chmod(blind, 0o755);
      expect(closed.digest).toMatch(/^[0-9a-f]{64}$/);
      return;
    }
    expect(closed.unreadable, "the unlistable directory is counted").toBe(1);
    expect(closed.digest, "a partial walk still answers, it just says how partial").toMatch(/^[0-9a-f]{64}$/);

    // the planted backdoor, invisible to the digest, which is exactly why the count has to exist
    await fs.chmod(blind, 0o755);
    await fs.writeFile(path.join(blind, "backdoor.js"), "require('child_process').exec('curl evil');\n");
    await fs.chmod(blind, 0o000);
    const after = await workspaceDigest(ws);
    expect(after.digest, "the constant token cannot move, and that is the point").toBe(closed.digest);
    expect(after.unreadable).toBe(1);

    // and once it can be read, the same tree measures whole and differently
    await fs.chmod(blind, 0o755);
    const opened = await workspaceDigest(ws);
    expect(opened.unreadable).toBe(0);
    expect(opened.digest).not.toBe(closed.digest);
  });

  it("counts a file whose bytes would not come back, rather than hashing the word unreadable", async () => {
    const ws = await workspace();
    const target = path.join(ws, "sealed.txt");
    await fs.writeFile(target, "eleven byte");
    await fs.chmod(target, 0o000);
    const measured = await workspaceDigest(ws);
    if (measured.unreadable === 0) return; // root again
    expect(measured.unreadable).toBe(1);
    expect(measured.digest).toMatch(/^[0-9a-f]{64}$/);

    // a same-size rewrite under it: the digest holds still, and only the count says why that is
    await fs.chmod(target, 0o600);
    await fs.writeFile(target, "ELEVEN BYTE");
    await fs.chmod(target, 0o000);
    expect((await workspaceDigest(ws)).digest).toBe(measured.digest);
  });

  it("refuses outright when the ROOT is what could not be listed, instead of measuring nothing", async () => {
    // The worst version of the same defect: a valid 64-hex digest over zero entries at both ends,
    // so the two agree and the panel prints "Unchanged, byte for byte across 0 entries" having
    // opened nothing at all. That is the product asserting its headline claim over a tree it never
    // read, and it has to be a refusal.
    const root = await fs.mkdtemp(path.join(SHORT_TMP, "wsblind-"));
    roots.push(root);
    const ws = path.join(root, "ws");
    await fs.mkdir(ws);
    await fs.writeFile(path.join(ws, "a.txt"), "a\n");
    await fs.chmod(ws, 0o000);
    const measured = await workspaceDigest(ws);
    await fs.chmod(ws, 0o755);
    if (measured.unreadable === 0) return; // root again
    expect(measured.digest, "no digest at all, rather than one over nothing").toBeNull();
    expect(measured.files).toBe(0);
    expect(measured.reason).toBe("workspace-unreadable");
  });

  it("says zero on a tree it read all of, so the field is a measurement and not a flag", async () => {
    expect((await workspaceDigest(await workspace())).unreadable).toBe(0);
  });
});

describe("the walk refuses rather than running forever, and says so", () => {
  it("returns no digest and a reason above the bound", async () => {
    const ws = await workspace();
    const measured = await workspaceDigest(ws, { maxFiles: 3 });
    expect(measured.digest).toBeNull();
    expect(measured.reason).toBe("tree-over-budget");
    // the count is where the walk STOPPED, one past the bound, and the panel says so in those words
    expect(measured.files).toBe(4);
  });

  it("still measures a tree exactly at the bound", async () => {
    const ws = await workspace();
    const measured = await workspaceDigest(ws, { maxFiles: 7 });
    expect(measured.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("ships a bound that measures every tree this product is demonstrated on", async () => {
    expect(WORKSPACE_DIGEST_MAX_FILES).toBeGreaterThan(1000);
  });

  it("says so rather than throwing when the workspace is not there", async () => {
    const measured = await workspaceDigest(path.join(SHORT_TMP, "wsdig-does-not-exist-" + process.pid));
    expect(measured).toEqual({ digest: null, files: 0, unreadable: 1, reason: "workspace-unreadable" });
  });
});

describe("the journal fields never read the same measured and unmeasured", () => {
  it("carries the digest and the count when there is one", async () => {
    const measured = await workspaceDigest(await workspace());
    expect(workspaceDigestFields(measured, "before")).toEqual({
      workspaceDigestBefore: measured.digest,
      workspaceFilesBefore: 7,
      workspaceUnreadableBefore: 0,
    });
  });

  it("carries the sentinel and a reason when there is not, and no digest value", async () => {
    const fields = workspaceDigestFields(
      { digest: null, files: 40_000, unreadable: 0, reason: "tree-over-budget" },
      "after",
    );
    expect(fields).toEqual({
      workspaceDigestAfter: NOT_MEASURED,
      workspaceFilesAfter: 40_000,
      workspaceUnreadableAfter: 0,
      workspaceDigestReason: "tree-over-budget",
    });
    // the sentinel must never be mistakeable for a digest by anything downstream
    expect(NOT_MEASURED).not.toMatch(/^[0-9a-f]{64}$/);
  });

  it("says which ending had no workspace to measure at all", async () => {
    expect(await closingWorkspaceFields(null, { unmeasuredReason: "no-retained-effect-record" })).toEqual({
      workspaceDigestAfter: NOT_MEASURED,
      workspaceFilesAfter: 0,
      workspaceUnreadableAfter: 0,
      workspaceDigestReason: "no-retained-effect-record",
    });
  });
});

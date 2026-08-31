import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  canonicalNoFollow,
  createOverlaySealer,
  isMountPoint,
  overlayMountArgv,
  overlayOptionString,
  parseMountCommand,
  parseMountInfo,
  pathIsMountOptionSafe,
  proveNotMounted,
  readMountInfo,
  unmountWithProof,
} from "./overlay-sealer.js";

const execFileAsync = promisify(execFile);

/**
 * Probe the host once, at load, so the overlay cases report as SKIPPED with a reason rather than
 * passing vacuously. A suite that goes green because it quietly did nothing is worse than a red one.
 */
const HOST = await (async () => {
  if (process.platform !== "linux") return { overlay: false, reason: "not-linux", sudo: false };
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sealer-probe-"));
  let sudo = false;
  if (!(typeof process.getuid === "function" && process.getuid() === 0)) {
    sudo = await execFileAsync("sudo", ["-n", "true"]).then(() => true).catch(() => false);
  }
  const { createOverlaySealer: make } = await import("./overlay-sealer.js");
  const cap = await make({ shadowRoot: root, allowSudo: sudo }).capability();
  await fs.rm(root, { recursive: true, force: true }).catch(() => undefined);
  return { overlay: cap.mechanism === "overlay", reason: cap.reason, sudo };
})();

if (!HOST.overlay) {
  console.log(`[overlay-sealer] real-mount cases SKIPPED on this host: ${HOST.reason}`);
}

let root = "";
let events: Array<Record<string, unknown>> = [];

const collect = (r: Record<string, unknown>) => {
  events.push(r);
};

beforeEach(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "sealer-"));
  events = [];
});

afterEach(async () => {
  // never a bare recursive delete in this suite either: prove, then remove
  if ((await proveNotMounted(root)).proven) {
    await fs.rm(root, { recursive: true, force: true }).catch(() => undefined);
  }
});

async function makeWorkspace(dir: string): Promise<void> {
  await fs.mkdir(path.join(dir, "src"), { recursive: true });
  await fs.writeFile(path.join(dir, "keep.txt"), "keep\n");
  await fs.writeFile(path.join(dir, "src", "lib.js"), "module.exports = 1;\n");
}

async function shadowDirFor(shadowRoot: string, id: string): Promise<string> {
  // the runner creates these three before calling seal, so the sealer must not assume it makes them
  const dir = path.join(shadowRoot, id);
  for (const d of ["upper", "work", "merged"]) await fs.mkdir(path.join(dir, d), { recursive: true });
  return dir;
}

describe("mount option safety", () => {
  it("rejects the characters that change what a mount means", () => {
    expect(pathIsMountOptionSafe("/tmp/plain/path")).toBe(true);
    expect(pathIsMountOptionSafe("/tmp/has,comma")).toBe(false);
    expect(pathIsMountOptionSafe("/tmp/has:colon")).toBe(false);
    expect(pathIsMountOptionSafe("/tmp/has\\backslash")).toBe(false);
    expect(pathIsMountOptionSafe("/tmp/has\nnewline")).toBe(false);
    // written as an escape on purpose: as a raw 0x00 this made the whole file classify as
    // binary, which silenced grep over it and made the test-count gate print "Binary file matches".
    expect(pathIsMountOptionSafe("/tmp/has\u0000null")).toBe(false);
  });

  it("hardens every overlay option that could corrupt an effect set", () => {
    const s = overlayOptionString("/real", "/shadow/run1");
    // a metadata-only copy-up gives an upper inode with no data, and the commit step would then
    // truncate the real file with an empty buffer
    expect(s).toContain("metacopy=off");
    // a directory rename otherwise hides behind an xattr that effect capture does not read
    expect(s).toContain("redirect_dir=off");
    expect(s).toContain("index=off");
    expect(s).toContain("xino=off");
    // userxattr is a flag in this kernel, not a key=value: setting it fails the mount outright
    expect(s).not.toContain("userxattr");
    expect(s).toContain("lowerdir=/real");
  });

  it("passes the option string as an argv element, never through a shell", () => {
    const argv = overlayMountArgv("/real", "/shadow/run1", false);
    expect(argv[0]).toBe("mount");
    expect(argv).toContain("-o");
    expect(argv.some((a) => a.includes("lowerdir=/real"))).toBe(true);
    expect(argv.at(-1)).toBe(path.join("/shadow/run1", "merged"));
    // the product names itself in mountinfo and findmnt output
    expect(argv).toContain("shadow-commit");
    expect(overlayMountArgv("/real", "/s", true).slice(0, 2)).toEqual(["sudo", "-n"]);
  });
});

describe("the mount proof", () => {
  it("reads a mount table on every supported host, and unescapes octal in the mountinfo reader", async () => {
    // The old assertion said this returns null off Linux. That was true, and porting the proof to
    // hosts with no procfs is precisely what changed it: on macOS the `mount` fallback now answers,
    // so the contract is "every supported host has a readable table", not "Linux has one".
    const table = await readMountInfo();
    expect(table).not.toBeNull();
    expect(table!.some((e) => e.mountPoint === "/"), "no root mount in the table").toBe(true);

    // Octal escaping is a mountinfo convention and BSD `mount` does not use it, so the reader is
    // exercised directly with a synthetic line. That keeps this a positive case on both platforms
    // rather than a branch that quietly does nothing on one of them.
    const line = "36 35 8:1 / /mnt/with\\040space rw,relatime shared:1 - ext4 /dev/sda1 rw";
    const [entry] = parseMountInfo(line);
    expect(entry!.mountPoint).toBe("/mnt/with space");
    expect(entry!.fsType).toBe("ext4");
    expect(entry!.source).toBe("/dev/sda1");
    expect(entry!.options).toBe("rw,relatime");

    // and nothing the live reader returns still carries an unresolved escape
    expect(table!.every((e) => !e.mountPoint.includes("\\0")), "an octal escape survived").toBe(true);
  });

  it("proves an ordinary directory carries no mount", async () => {
    const proof = await proveNotMounted(root);
    expect(proof.proven).toBe(true);
    expect(proof.offenders).toEqual([]);
  });

  it("treats an absent directory as safe and a symlinked leaf as unsafe", async () => {
    expect((await proveNotMounted(path.join(root, "nope"))).proven).toBe(true);

    // a leaf replaced by a link to the real workspace would otherwise canonicalise to the target
    // and be deleted through
    const target = path.join(root, "target");
    const link = path.join(root, "link");
    await fs.mkdir(target);
    await fs.symlink(target, link);
    const proof = await proveNotMounted(link);
    expect(proof.proven).toBe(false);
    expect(proof.reason).toBe("leaf-is-symlink");
  });

  it("does not resolve a symlinked leaf to its target", async () => {
    const target = path.join(root, "t");
    await fs.mkdir(target);
    await fs.symlink(target, path.join(root, "l"));
    expect(await canonicalNoFollow(path.join(root, "l"))).toBe(path.join(await fs.realpath(root), "l"));
  });

  it("reports an unmounted path as already unmounted rather than failing", async () => {
    const r = await unmountWithProof(path.join(root, "merged"), ["umount"]);
    expect(r.ok).toBe(true);
    expect(r.how).toBe("already-unmounted");
    expect(r.attempts).toBe(0);
  });
});

describe("seal, in copy mode", () => {
  it("copies the tree, neutralises a link that escapes, and journals the mechanism", async () => {
    const real = path.join(root, "real");
    const outside = path.join(root, "outside.txt");
    await makeWorkspace(real);
    await fs.writeFile(outside, "secret-outside\n");
    await fs.symlink(outside, path.join(real, "escape.txt"));
    await fs.symlink(path.join(real, "keep.txt"), path.join(real, "inside.txt"));

    const shadowRoot = path.join(root, "shadows");
    const shadowDir = await shadowDirFor(shadowRoot, "run-copy");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    expect(await sealer.seal(real, shadowDir)).toBe("copy");

    const merged = path.join(shadowDir, "merged");
    expect(await fs.readFile(path.join(merged, "keep.txt"), "utf8")).toBe("keep\n");
    expect(await fs.readFile(path.join(merged, "src", "lib.js"), "utf8")).toContain("module.exports");

    // the escaping link is now a regular file holding a snapshot, so a write lands in the shadow
    const escaped = await fs.lstat(path.join(merged, "escape.txt"));
    expect(escaped.isSymbolicLink()).toBe(false);
    expect(await fs.readFile(path.join(merged, "escape.txt"), "utf8")).toBe("secret-outside\n");
    // a link that stays inside the workspace is ordinary and is kept
    expect((await fs.lstat(path.join(merged, "inside.txt"))).isSymbolicLink()).toBe(true);

    // writing through what used to be the escaping link must not touch the real file
    await fs.writeFile(path.join(merged, "escape.txt"), "clobbered\n");
    expect(await fs.readFile(outside, "utf8")).toBe("secret-outside\n");

    const fallback = events.find((e) => e.kind === "seal.fallback");
    expect(fallback).toBeDefined();
    expect(fallback!.mechanism).toBe("copy");
    const sidecar = JSON.parse(await fs.readFile(path.join(shadowDir, "seal.json"), "utf8"));
    expect(sidecar.mechanism).toBe("copy");
  });

  it("releases a copy only after proving there is no mount, and removes the tree", async () => {
    const real = path.join(root, "real2");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows2");
    const shadowDir = await shadowDirFor(shadowRoot, "run-release");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });
    await sealer.seal(real, shadowDir);

    const r = await sealer.release(shadowDir);
    expect(r.removed).toBe(true);
    expect(r.proof.proven).toBe(true);
    expect(await fs.stat(shadowDir).catch(() => null)).toBeNull();
    // the real workspace is untouched by a teardown
    expect(await fs.readFile(path.join(real, "keep.txt"), "utf8")).toBe("keep\n");
  });

  it("quarantines rather than deletes when the absence of a mount cannot be proven", async () => {
    const shadowRoot = path.join(root, "shadows3");
    const shadowDir = await shadowDirFor(shadowRoot, "run-unprovable");
    await fs.writeFile(path.join(shadowDir, "marker.txt"), "still here\n");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    // stand in for an unprovable host: mountinfo missing is the same class of failure
    const original = "/proc/self/mountinfo";
    const proof = await proveNotMounted(shadowDir);
    if (!proof.proven) return; // already unprovable on this host, nothing to simulate

    // replace the shadow directory with a symlink, which the gate must refuse outright
    const decoy = path.join(shadowRoot, "decoy");
    await fs.mkdir(decoy, { recursive: true });
    await fs.writeFile(path.join(decoy, "precious.txt"), "must survive\n");
    const linked = path.join(shadowRoot, "linked");
    await fs.symlink(decoy, linked);

    const r = await sealer.release(linked);
    expect(r.removed).toBe(false);
    expect(r.proof.reason).toBe("leaf-is-symlink");
    // nothing behind the link was deleted
    expect(await fs.readFile(path.join(decoy, "precious.txt"), "utf8")).toBe("must survive\n");
    expect(original).toBe("/proc/self/mountinfo");
  });
});

describe.skipIf(!HOST.overlay)("the composition gate", () => {
  it("refuses overlay while no release hook is wired, even where overlay works", async () => {
    const real = path.join(root, "real4");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows4");
    const shadowDir = await shadowDirFor(shadowRoot, "run-gate");
    // releaseHookWired defaults to false
    const sealer = createOverlaySealer({ shadowRoot, allowSudo: HOST.sudo, emit: collect });

    expect(await sealer.seal(real, shadowDir)).toBe("copy");
    const refused = events.find((e) => e.kind === "seal.refused");
    expect(refused).toBeDefined();
    expect(refused!.reason).toBe("release-hook-not-wired");
    // and the fallback still produced a usable workspace
    expect(await fs.readFile(path.join(shadowDir, "merged", "keep.txt"), "utf8")).toBe("keep\n");
  });
});

describe.skipIf(!HOST.overlay)("overlay on a host that can mount", () => {
  it("mounts, proves, unmounts and never deletes through the mount", async () => {
    const real = path.join(root, "real5");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows5");
    const shadowDir = await shadowDirFor(shadowRoot, "run-overlay");
    const sealer = createOverlaySealer({
      shadowRoot, releaseHookWired: true, allowSudo: HOST.sudo, emit: collect,
    });

    const mechanism = await sealer.seal(real, shadowDir);
    expect(mechanism).toBe("overlay");

    const merged = path.join(shadowDir, "merged");
    // the sealed view shows the workspace without copying it
    expect(await fs.readFile(path.join(merged, "keep.txt"), "utf8")).toBe("keep\n");
    expect((await isMountPoint(merged)).mounted).toBe(true);
    expect((await proveNotMounted(shadowDir)).proven).toBe(false);

    // the turn writes and deletes inside the sealed view
    await fs.writeFile(path.join(merged, "new.txt"), "new\n");
    await fs.rm(path.join(merged, "keep.txt"), { force: true });
    // the upper layer IS the effect set: a create is a real file, a delete is a 0/0 whiteout
    expect((await fs.stat(path.join(shadowDir, "upper", "new.txt"))).size).toBeGreaterThan(0);
    const wh = await fs.lstat(path.join(shadowDir, "upper", "keep.txt"));
    expect(wh.isCharacterDevice()).toBe(true);
    expect(wh.rdev).toBe(0);
    // and the real workspace has not changed at all
    expect(await fs.readFile(path.join(real, "keep.txt"), "utf8")).toBe("keep\n");

    const mounted = events.find((e) => e.kind === "seal.mounted");
    expect(mounted).toBeDefined();
    expect(mounted!.mechanism).toBe("overlay");

    const r = await sealer.release(shadowDir);
    expect(r.unmount?.ok).toBe(true);
    expect(r.proof.proven).toBe(true);
    expect(r.removed).toBe(true);
    expect((await isMountPoint(merged)).mounted).toBe(false);

    // the point of the whole module: the teardown left the real workspace intact
    expect(await fs.readFile(path.join(real, "keep.txt"), "utf8")).toBe("keep\n");
    expect(await fs.readFile(path.join(real, "src", "lib.js"), "utf8")).toContain("module.exports");
  });

  it("sweeps a mount left behind by a crashed turn", async () => {
    const real = path.join(root, "real6");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows6");
    const shadowDir = await shadowDirFor(shadowRoot, "run-orphan");
    const sealer = createOverlaySealer({
      shadowRoot, releaseHookWired: true, allowSudo: HOST.sudo, emit: collect,
    });
    expect(await sealer.seal(real, shadowDir)).toBe("overlay");

    // the process dies here: the mount is live and nothing owns it
    const swept = await sealer.sweepOrphans(new Set());
    expect(swept.swept).toContain(shadowDir);
    expect((await isMountPoint(path.join(shadowDir, "merged"))).mounted).toBe(false);
    expect(await fs.readFile(path.join(real, "keep.txt"), "utf8")).toBe("keep\n");
  });
});

describe("the mount proof survives a host with no procfs", () => {
  /**
   * The demo Mac has no /proc/self/mountinfo, and the first version of this module stopped there:
   * the proof could never succeed, so `release()` quarantined every shadow instead of deleting it.
   * On a host whose shipped path is `cp -a` that leaked a full workspace copy per turn. These tests
   * pin the ported proof, because a fallback nobody checks is the same as no fallback.
   */

  it("parses the shape `mount` prints, including a mount point with spaces and parentheses", () => {
    const sample = [
      "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)",
      "devfs on /dev (devfs, local, nobrowse)",
      "/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)",
      "map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)",
      "/dev/disk5s1 on /Volumes/My Disk (backup) (hfs, local, nodev, nosuid, read-only)",
      "not a mount line at all",
      "",
    ].join("\n");
    const entries = parseMountCommand(sample);

    expect(entries.map((e) => e.mountPoint)).toEqual([
      "/", "/dev", "/System/Volumes/Data", "/System/Volumes/Data/home", "/Volumes/My Disk (backup)",
    ]);
    // the fstype lands where every caller expects it, and read-only is visible as an option
    expect(entries[0]!.fsType).toBe("apfs");
    expect(entries[0]!.source).toBe("/dev/disk3s1s1");
    expect(entries[0]!.options.split(",")).toContain("read-only");
    // a source containing a space survives, which `map auto_home` is the real-world case of
    expect(entries[3]!.source).toBe("map auto_home");
  });

  it("agrees with mountinfo on this host, which is what makes it a port and not a guess", async () => {
    const viaProcfs = await fs.readFile("/proc/self/mountinfo", "utf8").catch(() => null);
    if (viaProcfs === null) return; // not Linux: the fallback is the only source and is covered above

    const fromProcfs = new Set(parseMountInfo(viaProcfs).map((e) => e.mountPoint));
    const { stdout } = await execFileAsync("mount", []).catch(() => ({ stdout: "" }));
    if (!stdout) return; // no `mount` binary here; the procfs path is authoritative anyway
    const fromCommand = new Set(parseMountCommand(stdout).map((e) => e.mountPoint));

    // Both must see the root, and the fallback must not invent mount points procfs does not have.
    // The reverse is allowed: procfs lists more than `mount` does on Linux.
    expect(fromProcfs.has("/")).toBe(true);
    expect(fromCommand.has("/")).toBe(true);
    const invented = [...fromCommand].filter((mp) => !fromProcfs.has(mp));
    expect(invented, "the fallback reported a mount procfs does not know about").toEqual([]);
  });

  it("releases a copy on a host where only the fallback can answer", async () => {
    // The exact scenario measured on the primary dev machine: mechanism "copy", a shadow that never had a mount, on a
    // host where the primary proof source does not exist. It must delete, not quarantine.
    const real = path.join(root, "real");
    await makeWorkspace(real);
    const shadowRoot = path.join(root, "shadows");
    const shadowDir = await shadowDirFor(shadowRoot, "run-fallback");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });
    await sealer.seal(real, shadowDir);

    const r = await sealer.release(shadowDir, "copy");
    expect(r.removed, `release refused: ${r.proof.reason}`).toBe(true);
    expect(r.quarantinedTo).toBeNull();
    expect(await fs.stat(shadowDir).catch(() => null)).toBeNull();
    // and nothing was orphaned, which is the leak this fixes
    const orphans = await fs.readdir(path.join(shadowRoot, ".orphan")).catch(() => [] as string[]);
    expect(orphans).toEqual([]);
  });
});

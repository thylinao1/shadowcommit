import { describe, expect, it, vi } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { captureEffects, resolveLimits, emptySnapshot } from "./capture.js";
import { basicContext } from "./policy-types.js";
import { CommitProtocol } from "./commit-protocol.js";
import { TransactionalRunner } from "./transactional-runner.js";
import { GitAnchor } from "./anchors.js";
import { NetworkSealer, EGRESS_NETWORK } from "./network-sealer.js";
import { loadConfig } from "./config.js";

/**
 * Lines that hold the product up and had nothing standing behind them.
 *
 * A verification workflow found the cheapest defect detector this repository has: delete one
 * production line and run the suite. Nine one-line deletions each broke ZERO of 1,287 tests. Three
 * were rules missing from the registry and are now covered by `rules/registry-wiring.test.ts`. The
 * rest are here, each pinned by the smallest test that fails when its line goes.
 *
 * They are grouped in one file on purpose. Individually they belong to five different modules and
 * would be easy to lose; together they are a standing answer to "which lines does nothing test".
 */

describe("capture: an overlayfs whiteout is a delete", () => {
  /**
   * Under overlay a deleted file appears in the upper layer as a 0/0 CHARACTER DEVICE, not as an
   * absence. Without the branch that reads it, a delete produces no effect at all: the policy never
   * sees it, the rules that judge deletions never run, and the turn commits a deletion nobody
   * judged.
   *
   * Nothing tested it because making a real whiteout needs privileges (`mknod` is "Operation not
   * permitted" on macOS), and my first attempt at this test skipped silently on that failure, which
   * would have been another double that cannot fail. So the seam is `readdir` and nothing else:
   * the directory entry is supplied, and `captureEffects` then runs for real, including
   * `expandDelete` and the real-inode lookup. The revert proof is what makes it honest, and it is
   * recorded in the commit: deleting the branch turns the expected delete into an empty effect set.
   */
  it("reports a character device in the upper layer as a delete, not as nothing", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "lbl-wo-"));
    const real = path.join(root, "ws");
    const upperDir = path.join(root, "shadow", "upper");
    await fs.mkdir(real, { recursive: true });
    await fs.mkdir(upperDir, { recursive: true });
    await fs.writeFile(path.join(real, "secret.txt"), "the file the turn deleted\n");

    const whiteout = {
      name: "secret.txt",
      isSymbolicLink: () => false,
      isDirectory: () => false,
      isFile: () => false,
      isCharacterDevice: () => true,
      isBlockDevice: () => false,
      isFIFO: () => false,
      isSocket: () => false,
    };

    const realReaddir = fs.readdir.bind(fs);
    const spy = vi
      .spyOn(fs, "readdir")
      .mockImplementation((async (dir: string, opts?: unknown) => {
        if (path.resolve(String(dir)) === path.resolve(upperDir)) return [whiteout] as never;
        return realReaddir(dir as never, opts as never) as never;
      }) as never);

    try {
      const result = await captureEffects({
        shadowDir: path.join(root, "shadow"),
        real,
        mechanism: "overlay",
        sealed: emptySnapshot(),
        realInodes: new Map<string, string>([["secret.txt", "1:1"]]),
        limits: resolveLimits({} as never),
      });
      const deletes = result.effects.filter((e) => e.kind === "delete").map((e) => e.path);
      expect(deletes, "a whiteout must reach the policy as a delete").toContain("secret.txt");
    } finally {
      spy.mockRestore();
    }
  });
});

describe("policy context: addedLinesOf has a default, so a rule never reads undefined", () => {
  /**
   * `basicContext` defaults `addedLinesOf` to `contentOf`. Without it the field is undefined and
   * every content rule that calls it throws, which the policy turns into `policy-rule-error` and a
   * review. A turn would be held for a reason that is a bug rather than a finding.
   */
  it("falls back to contentOf when a caller supplies only contentOf", async () => {
    const ctx = basicContext(async () => "const x = 1;\n");
    expect(typeof ctx.addedLinesOf).toBe("function");
    await expect(ctx.addedLinesOf("any/path.ts")).resolves.toBe("const x = 1;\n");
  });

  it("still lets a caller override it, so the default is a fallback and not a cap", async () => {
    const ctx = basicContext(async () => "whole file", { addedLinesOf: async () => "added only" });
    await expect(ctx.addedLinesOf("p")).resolves.toBe("added only");
    await expect(ctx.contentOf("p")).resolves.toBe("whole file");
  });
});

describe("network sealer: the shared egress network is never pruned", () => {
  /**
   * Shadow networks are per run and are pruned once they are stale. The egress network is NOT per
   * run: it is shared, and between two turns nothing is attached to it. `docker network rm` refuses
   * a network with active endpoints, which is what protects a per-run network, and that protection
   * does not exist for a shared one sitting idle for a moment.
   *
   * Without the guard, a prune that happens to land between turns removes the network a live broker
   * is about to use, or is using, and the next turn fails to reach its model provider. Nothing
   * tested it because the prune path needs a Docker engine; the sealer takes an injectable `exec`,
   * so the whole method runs for real against a scripted engine instead.
   */
  const sealerWith = (calls: string[][]) =>
    new NetworkSealer(loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-token-long-enough-x" }), {
      exec: async (_file: string, args: string[]) => {
        calls.push(args);
        if (args[1] === "ls") {
          return { stdout: [EGRESS_NETWORK, "shadow-run-aaaa", "shadow-run-bbbb"].join("\n") };
        }
        if (args[1] === "inspect") return { stdout: new Date(0).toISOString() }; // ancient, so stale
        return { stdout: "" };
      },
    });

  it("removes stale per-run networks and leaves the shared egress network alone", async () => {
    const calls: string[][] = [];
    const removed = await sealerWith(calls).pruneStale();

    const removals = calls.filter((a) => a[1] === "rm").map((a) => a[2]);
    expect(removals).toContain("shadow-run-aaaa");
    expect(removals).toContain("shadow-run-bbbb");
    expect(removals, "removing the shared egress network cuts a live broker").not.toContain(
      EGRESS_NETWORK,
    );
    expect(removed).toBe(2);
  });

  it("never even asks how old the shared network is, so age cannot make it eligible", async () => {
    const calls: string[][] = [];
    await sealerWith(calls).pruneStale();
    const inspected = calls.filter((a) => a[1] === "inspect").map((a) => a[2]);
    expect(inspected).not.toContain(EGRESS_NETWORK);
  });
});

describe("commit protocol: an overlay shadow is never deleted through a live mount", () => {
  /**
   * Under overlay the LOWER layer is the real workspace, so a recursive delete of the shadow while
   * anything is still mounted under it deletes through the mount and destroys the user's tree.
   * `umount` exits 32 for every failure, so its exit code decides nothing and the mount table has to.
   * The guard treats an unreadable table as MOUNTED, because being wrong the other way costs the
   * real workspace.
   *
   * This is host conditional by nature: Linux reads /proc/self/mountinfo and macOS falls back to the
   * `mount` command. Rather than skip on one of them, which is a pass that asserts nothing, each
   * branch asserts a real property of the path that host actually takes.
   */
  const protocolFor = (root: string, events: Record<string, unknown>[]) =>
    new CommitProtocol({
      emit: async (f: Record<string, unknown>) => void events.push(f),
      store: { getPending: async () => null, removePending: async () => undefined } as never,
      journalPath: path.join(root, "journal.jsonl"),
      shadowRoot: path.join(root, "shadows"),
    } as never);

  it("deletes a shadow the mount table proves is clean, on either kind of host", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "lbl-mnt-"));
    const shadowDir = path.join(root, "shadows", "run1");
    await fs.mkdir(path.join(shadowDir, "merged"), { recursive: true });
    const events: Record<string, unknown>[] = [];

    await protocolFor(root, events).release(shadowDir, "overlay");

    // nothing is mounted under a fresh temp dir on any host, so the real table read must clear it
    await expect(fs.access(shadowDir)).rejects.toThrow();
    expect(events.map((e) => e.kind)).not.toContain("shadow.quarantined");
  });

  it("quarantines instead of deleting when the table cannot be read", async () => {
    const hasMountinfo = await fs
      .access("/proc/self/mountinfo")
      .then(() => true)
      .catch(() => false);

    const root = await fs.mkdtemp(path.join(os.tmpdir(), "lbl-mnt2-"));
    const shadowDir = path.join(root, "shadows", "run1");
    await fs.mkdir(path.join(shadowDir, "merged"), { recursive: true });
    const events: Record<string, unknown>[] = [];

    if (hasMountinfo) {
      // Linux takes the procfs branch and never consults `mount`, so the property to assert here is
      // that the procfs parse is what decided: a clean dir is deleted, and no fake binary can change
      // that. Asserting it keeps this branch honest rather than silently absent.
      const bin = path.join(root, "bin");
      await fs.mkdir(bin, { recursive: true });
      await fs.writeFile(path.join(bin, "mount"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
      const saved = process.env.PATH;
      process.env.PATH = `${bin}:${saved}`;
      try {
        await protocolFor(root, events).release(shadowDir, "overlay");
        await expect(fs.access(shadowDir)).rejects.toThrow();
        expect(events.map((e) => e.kind)).not.toContain("shadow.quarantined");
      } finally {
        process.env.PATH = saved;
      }
      return;
    }

    // macOS and any host that hides mountinfo: the `mount` command is the only source, and a mount
    // binary that fails means the absence of a mount cannot be established.
    const bin = path.join(root, "bin");
    await fs.mkdir(bin, { recursive: true });
    await fs.writeFile(path.join(bin, "mount"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
    const saved = process.env.PATH;
    process.env.PATH = `${bin}:${saved}`;
    try {
      await protocolFor(root, events).release(shadowDir, "overlay");
      // the shadow SURVIVES, because deleting it could have deleted through a mount
      await expect(fs.access(shadowDir)).resolves.toBeUndefined();
      expect(events.map((e) => e.kind)).toContain("shadow.quarantined");
    } finally {
      process.env.PATH = saved;
    }
  });
});

describe("transactional runner: a link that stays inside the workspace stays a link", () => {
  /**
   * A symlink in the sealed copy that points OUT of the workspace is a way to read or write a file
   * the turn was never given, so it is neutralised: the link is replaced by a copy of the bytes it
   * pointed at, and the effect set then shows a file rather than a door.
   *
   * A link that resolves back INSIDE the workspace is ordinary. A monorepo is full of them. Without
   * the one-line exemption, every in-workspace link is materialised into a copy too, so the turn
   * reports a file where the repository has a link and committing it replaces the link with a
   * duplicate of its target. Nothing tested the exemption, and the test named for it in the suite
   * has no unconditional assertion, which is how it survived.
   *
   * The private method is driven directly with a minimal receiver, so the body under test is the
   * real one and the assertions are about real files on disk.
   */
  const neutralise = async (real: string, merged: string) => {
    const receiver = { neutralised: new Set<string>() };
    await (
      TransactionalRunner.prototype as unknown as {
        neutraliseOutboundLinks: (r: string, m: string) => Promise<void>;
      }
    ).neutraliseOutboundLinks.call(receiver, real, merged);
    return receiver.neutralised;
  };

  it("keeps an in-workspace link and materialises an escaping one", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "lbl-link-"));
    const real = path.join(root, "ws");
    const merged = path.join(root, "shadow", "merged");
    const outside = path.join(root, "outside.txt");
    await fs.mkdir(path.join(real, "pkg"), { recursive: true });
    await fs.mkdir(path.join(merged, "pkg"), { recursive: true });
    await fs.writeFile(outside, "bytes the turn was never given\n");
    await fs.writeFile(path.join(merged, "pkg", "real.ts"), "export const a = 1;\n");

    // the monorepo case: a link that resolves back inside the workspace
    await fs.symlink("real.ts", path.join(merged, "pkg", "alias.ts"));
    // the escape: a link out of the workspace entirely
    await fs.symlink(outside, path.join(merged, "escape.txt"));

    const neutralised = await neutralise(real, merged);

    const alias = await fs.lstat(path.join(merged, "pkg", "alias.ts"));
    expect(alias.isSymbolicLink(), "an in-workspace link must stay a link").toBe(true);
    expect(await fs.readlink(path.join(merged, "pkg", "alias.ts"))).toBe("real.ts");
    expect([...neutralised]).not.toContain("pkg/alias.ts");

    const escape = await fs.lstat(path.join(merged, "escape.txt"));
    expect(escape.isSymbolicLink(), "an escaping link must be replaced by its bytes").toBe(false);
    expect(await fs.readFile(path.join(merged, "escape.txt"), "utf8")).toBe(
      "bytes the turn was never given\n",
    );
    expect([...neutralised]).toContain("escape.txt");
  });
});

describe("anchors: the git note carries its own identity", () => {
  /**
   * `git notes append` writes an object and refuses without a committer. A machine with no global
   * git config, which is every CI runner and every container, answers "Committer identity unknown",
   * the catch below turns that into a degraded receipt, and the anchor never lands.
   *
   * That failed silently everywhere EXCEPT a developer laptop that happened to have a global
   * identity, which is the worst possible place for a tamper-evidence feature to be the only one
   * that works. Nothing tested it, because a laptop running the suite has an identity and the
   * degraded receipt is still a resolved promise.
   *
   * The scripted engine here behaves like a machine with no identity: it refuses the notes call
   * unless the identity is passed explicitly on that invocation.
   */
  const SUBMISSION = {
    treeSize: 4,
    merkleRoot: "aa".repeat(32),
    head: "bb".repeat(32),
    seq: 7,
    signature: "c2ln",
  };

  function engineWithNoGlobalIdentity(calls: string[][]) {
    return async (_file: string, args: string[]) => {
      calls.push(args);
      if (args.includes("--show-toplevel")) return { stdout: "/repo\n" };
      if (args.includes("notes")) {
        const hasName = args.some((a) => a.startsWith("user.name="));
        const hasEmail = args.some((a) => a.startsWith("user.email="));
        if (!hasName || !hasEmail) {
          throw new Error("Committer identity unknown\n*** Please tell me who you are.");
        }
        return { stdout: "" };
      }
      if (args.includes("rev-parse")) return { stdout: "deadbeef\n" };
      return { stdout: "" };
    };
  }

  it("lands a real anchor on a machine with no global git identity", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "lbl-anchor-"));
    const calls: string[][] = [];
    const anchor = new GitAnchor({
      dataDirectory: root,
      exec: engineWithNoGlobalIdentity(calls) as never,
    });

    const receipt = await anchor.submit(SUBMISSION as never);

    // a real anchor names the commit it pinned; a degraded one carries gitNote: "failed: ..."
    expect(receipt).toMatchObject({ repository: "/repo", commit: "deadbeef" });
    expect(receipt).not.toHaveProperty("gitNote");

    const notesCall = calls.find((a) => a.includes("notes"));
    expect(notesCall).toBeDefined();
    expect(notesCall).toContain("user.name=shadow-commit");
    expect(notesCall).toContain("user.email=shadow-commit@localhost");
  });

  it("appends rather than replaces, because an anchor that can overwrite one is not an anchor", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "lbl-anchor2-"));
    const calls: string[][] = [];
    await new GitAnchor({
      dataDirectory: root,
      exec: engineWithNoGlobalIdentity(calls) as never,
    }).submit(SUBMISSION as never);

    const notesCall = calls.find((a) => a.includes("notes")) ?? [];
    expect(notesCall).toContain("append");
    expect(notesCall).not.toContain("add");
    expect(notesCall).not.toContain("--force");
  });
});


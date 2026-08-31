import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { captureEffects, defaultLimits, snapshotStats } from "./capture.js";
import { createOverlaySealer, proveNotMounted } from "./overlay-sealer.js";
import { defaultPolicy } from "./shadow-policy.js";
import { TransactionalRunner } from "./transactional-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * The sibling of the unreadable-file chain, reached without `cp` ever failing.
 *
 * BSD `cp -a` cannot reproduce a unix socket. It does not treat that as an error: it writes
 * `cp: real/./app.sock is a socket (not copied).` to stderr and EXITS 0. So a check that runs only
 * after a non-zero exit never runs, the shadow is missing a path the real workspace has, and the
 * copy-only pass in captureEffects reads that absence as a deletion by the agent. One delete is
 * below every multi-delete threshold, so the turn commits and the socket is removed from the real
 * workspace on a turn where the agent did nothing.
 *
 * The lesson the file pins is not "handle sockets". It is that the exit status of `cp` is not how
 * you learn whether the seal produced a complete view, so completeness has to be the thing that is
 * checked, on every copy seal, complaint or no complaint.
 *
 * GNU coreutils makes the same point from the other side. Its `cp -a` reproduces the socket with
 * mknod, silently, exit 0: a socket inode with the same name lands in the copy and nothing listens
 * on it. The tree is complete, so the guard lets the turn proceed, and the copied socket is inert,
 * which is the containment an outbound symlink gets. The first version of these tests asserted
 * BSD's refusal as the only right answer, and CI runs on GNU, so the file was red on the host the
 * README tells a reviewer to trust. Both outcomes are asserted now, and there is no third.
 */

// AF_UNIX sun_path is 104 bytes on Darwin, and os.tmpdir() under TMPDIR is already most of that.
// A short root is what makes a socket fixture possible at all.
const SHORT_TMP = "/tmp";

// chmod 000 is not a barrier to root, so the unreadable cases would pass vacuously there.
const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;

let root = "";
let events: Array<Record<string, unknown>> = [];
const servers: net.Server[] = [];
const collect = (r: Record<string, unknown>) => {
  events.push(r);
};

/**
 * Leaves a real socket inode at `p`. The listener stays up for the life of the test, which is the
 * realistic shape: the socket is there because something is serving on it.
 */
async function makeSocket(p: string): Promise<void> {
  const server = net.createServer();
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(p, () => resolve());
  });
}

beforeEach(async () => {
  root = await fs.mkdtemp(path.join(SHORT_TMP, "sc-"));
  events = [];
});

afterEach(async () => {
  // closing the listener unlinks the socket, so it happens after the assertions, not before
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
  await execFileAsync("chmod", ["-R", "u+rwX", root]).catch(() => undefined);
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
  const dir = path.join(shadowRoot, id);
  for (const d of ["upper", "work", "merged"]) await fs.mkdir(path.join(dir, d), { recursive: true });
  return dir;
}

/** the agent does nothing, so every effect the turn reports was manufactured for it */
const idleRunner: AgentRunner = {
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (_request: RunnerRequest): Promise<RunnerResult> => ({
    output: "did nothing",
    threadId: null,
    usage: null,
  }),
};

/**
 * What THIS host's `cp -a` does with a socket, established once before anything asserts on it.
 *
 * Two behaviours are known and both exit 0, which is the whole reason the exit status cannot be
 * the check: BSD leaves the socket out and says so on stderr; GNU coreutils reproduces it and says
 * nothing. Anything else is a host this file does not know, and the premise test says so.
 */
async function probeHostCp(): Promise<{
  omitsSockets: boolean;
  code: number;
  stderr: string;
  copiedAsSocket: boolean;
}> {
  const dir = await fs.mkdtemp(path.join(SHORT_TMP, "cpprobe-"));
  const real = path.join(dir, "real");
  const dest = path.join(dir, "dest");
  await fs.mkdir(real);
  await fs.mkdir(dest);
  await fs.writeFile(path.join(real, "index.js"), "1\n");
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(path.join(real, "app.sock"), () => resolve());
  });
  try {
    const result = await execFileAsync("cp", ["-a", real + "/.", dest]).then(
      (r) => ({ code: 0, stderr: String(r.stderr ?? "").trim() }),
      (e: { code?: number; stderr?: string }) => ({ code: e.code ?? -1, stderr: String(e.stderr ?? "").trim() }),
    );
    const copied = await fs.lstat(path.join(dest, "app.sock")).catch(() => null);
    return {
      omitsSockets: copied === null,
      code: result.code,
      stderr: result.stderr,
      copiedAsSocket: copied?.isSocket() ?? false,
    };
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

const HOST_CP = await probeHostCp();

async function realCpPath(): Promise<string> {
  for (const candidate of ["/bin/cp", "/usr/bin/cp"]) {
    if (await fs.access(candidate, fs.constants.X_OK).then(() => true, () => false)) return candidate;
  }
  throw new Error("no cp at /bin/cp or /usr/bin/cp to wrap");
}

/**
 * Runs `fn` under a `cp` that omits sockets, so the omission cases run on every host and not only
 * on the one whose cp happens to omit. Where the real cp already does, it is used as it is. Where
 * it is faithful, a shim goes first on PATH for the duration and reproduces the BSD contract to
 * the letter: the real copy, sockets removed from the destination, the BSD line on stderr, exit 0.
 * It is removed after, whatever happened.
 */
async function underOmittingCp<T>(fn: () => Promise<T>): Promise<T> {
  if (HOST_CP.omitsSockets) return fn();
  const bin = path.join(root, "shim-bin");
  await fs.mkdir(bin, { recursive: true });
  const shim = [
    "#!/bin/sh",
    "# BSD cp -a as observed on Darwin: the socket is left out, stderr names it, the exit status is 0.",
    "# This host's cp reproduces sockets, so the shim removes what the real one made and says what BSD says.",
    "REAL_CP=" + JSON.stringify(await realCpPath()),
    '"$REAL_CP" "$@"',
    "status=$?",
    'src="$2"; dst="$3"',
    'find "$dst" -type s 2>/dev/null | while IFS= read -r s; do',
    '  rm -f "$s"',
    '  rel=${s#"$dst"/}',
    '  echo "cp: $src/$rel is a socket (not copied)." >&2',
    "done",
    "exit $status",
    "",
  ].join("\n");
  await fs.writeFile(path.join(bin, "cp"), shim, { mode: 0o755 });
  const saved = process.env.PATH;
  process.env.PATH = bin + path.delimiter + (saved ?? "");
  try {
    return await fn();
  } finally {
    if (saved === undefined) delete process.env.PATH;
    else process.env.PATH = saved;
    await fs.rm(bin, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** "connected" when something answers at `p`, otherwise the errno, which is the whole point. */
function connectTo(p: string): Promise<string> {
  return new Promise((resolve) => {
    const c = net.connect(p);
    c.once("connect", () => {
      c.destroy();
      resolve("connected");
    });
    c.once("error", (e: NodeJS.ErrnoException) => resolve(e.code ?? "error"));
  });
}

describe("a copy `cp` reported no error for, and still could not complete", () => {
  it("shows the premise: cp exits 0 whether or not it reproduced the socket, and says which", () => {
    // both known behaviours exit 0: that is the premise, the exit status cannot be the check
    expect(HOST_CP.code, "cp signalled the omission through its exit status after all").toBe(0);
    if (HOST_CP.omitsSockets) {
      // BSD: left out, and said so
      expect(HOST_CP.stderr).toMatch(/app\.sock/);
    } else {
      // GNU coreutils: reproduced as a socket, and said nothing
      expect(
        HOST_CP.copiedAsSocket,
        "cp neither omitted the socket nor reproduced it as one; this is a host the file does not know",
      ).toBe(true);
      expect(HOST_CP.stderr).toBe("");
    }
    console.log(
      "[copy-completeness] this host's cp " +
        (HOST_CP.omitsSockets
          ? "OMITS a socket and says so on stderr (BSD)"
          : "reproduces a socket silently (GNU coreutils)") +
        "; the omission cases run " +
        (HOST_CP.omitsSockets ? "against the real cp" : "under a shim reproducing the BSD contract"),
    );
  });

  it("does not resolve to a mechanism, and so cannot manufacture a delete", async () => {
    await underOmittingCp(async () => {
      const real = path.join(root, "real1");
      await makeWorkspace(real);
      await makeSocket(path.join(real, "app.sock"));

      const shadowRoot = path.join(root, "shadows1");
      const shadowDir = await shadowDirFor(shadowRoot, "run-socket");
      const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

      const mechanism = await sealer.seal(real, shadowDir).then(
        (m) => m as string | null,
        () => null,
      );

      // Either the seal failed, or the capture that follows it invents no delete. There is no third
      // answer, and this is stated the same way as the unreadable-file case for the same reason.
      if (mechanism !== null) {
        const captured = await captureEffects({
          shadowDir,
          real,
          mechanism: "copy",
          sealed: await snapshotStats(path.join(shadowDir, "merged"), { hash: true }),
          realInodes: (await snapshotStats(real)).inodes,
          limits: defaultLimits,
        });
        expect(
          captured.effects.filter((e) => e.kind === "delete").map((e) => e.path),
          "the seal reported success over an incomplete copy and the capture invented a delete",
        ).toEqual([]);
      }
      expect(mechanism, "seal() resolved over a copy that omitted a path, on a cp that exited 0").toBeNull();
    });
  });

  it("names the path it could not copy, and records the failure before it throws", async () => {
    await underOmittingCp(async () => {
      const real = path.join(root, "real2");
      await makeWorkspace(real);
      await makeSocket(path.join(real, "app.sock"));

      const shadowRoot = path.join(root, "shadows2");
      const shadowDir = await shadowDirFor(shadowRoot, "run-named-socket");
      const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

      await expect(sealer.seal(real, shadowDir)).rejects.toThrow(/app\.sock/);
      const failed = events.find((e) => e.kind === "seal.failed");
      expect(failed, `no seal.failed event; got ${events.map((e) => e.kind).join(",")}`).toBeDefined();
      expect(failed!.reason).toBe("copy-incomplete");
      expect(failed!.missing).toContain("app.sock");
      // the partial shadow does not survive the failure
      expect(await fs.stat(shadowDir).catch(() => null), "the partial copy was left on disk").toBeNull();
    });
  });


});

const faithful = HOST_CP.omitsSockets ? describe.skip : describe;
faithful("a copy that reproduced the socket, on a host whose cp does", () => {
  it("seals over it, and the socket in the shadow is inert rather than a way to the live server", async () => {
    const real = path.join(root, "real3");
    await makeWorkspace(real);
    await makeSocket(path.join(real, "app.sock"));

    const shadowRoot = path.join(root, "shadows3");
    const shadowDir = await shadowDirFor(shadowRoot, "run-faithful");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    // complete tree, so the seal is a seal
    await expect(sealer.seal(real, shadowDir)).resolves.toBe("copy");
    expect(events.find((e) => e.kind === "seal.failed")).toBeUndefined();
    const inShadow = await fs.lstat(path.join(shadowDir, "merged", "app.sock"));
    expect(inShadow.isSocket()).toBe(true);

    // The live one answers. The copy is a bare inode nothing listens on, so a turn can no more
    // reach the dev server through the sealed view than it could through an outbound symlink.
    expect(await connectTo(path.join(real, "app.sock"))).toBe("connected");
    expect(await connectTo(path.join(shadowDir, "merged", "app.sock"))).toBe("ECONNREFUSED");

    // and the capture has nothing to say: same path, same kind, both sides
    const captured = await captureEffects({
      shadowDir,
      real,
      mechanism: "copy",
      sealed: await snapshotStats(path.join(shadowDir, "merged"), { hash: true }),
      realInodes: (await snapshotStats(real)).inodes,
      limits: defaultLimits,
    });
    expect(captured.effects.map((e) => `${e.kind} ${e.path}`)).toEqual([]);
  });
});

describe("end to end, through the wiring runner-factory ships", () => {
  /** an idle turn over `ws`, as runner-factory wires it, reported as one string */
  async function idleTurnOver(ws: string, shadowRoot: string, journal: string): Promise<string> {
    const sealer = createOverlaySealer({ shadowRoot, releaseHookWired: true, force: "copy", emit: collect });
    const runner = new TransactionalRunner(idleRunner, {
      shadowRoot,
      journalPath: journal,
      policy: defaultPolicy,
      seal: sealer.seal,
      release: async (dir, mechanism) => {
        await sealer.release(dir, mechanism);
      },
    });
    const outcome = await runner
      .run({ agentId: "a1", workspacePath: ws, prompt: "p", threadId: null })
      .then((r) => `ran: ${JSON.stringify(r.containment ?? null)}`, (e: Error) => `refused: ${e.message}`);
    await runner.closeJournal().catch(() => undefined);
    return outcome;
  }

  it("does not delete a socket the turn never opened, whichever cp this host has", async () => {
    const ws = path.join(root, "ws");
    await makeWorkspace(ws);
    await fs.mkdir(path.join(ws, "tmp"), { recursive: true });
    const sock = path.join(ws, "tmp", "app.sock");
    await makeSocket(sock);
    const inodeBefore = (await fs.lstat(sock)).ino;

    const outcome = await idleTurnOver(ws, path.join(root, "shadows-e2e"), path.join(root, "journal.jsonl"));

    // THE PROPERTY, on every host. The agent did nothing, so everything the workspace started with
    // is still there: the same inode, still answering. lstat alone would also pass a dead copy
    // written over the live socket, which is the failure a faithful cp makes possible.
    const after = await fs.lstat(sock).catch(() => null);
    expect(after, `the turn removed a path it never opened. outcome=${outcome}`).not.toBeNull();
    expect(after!.ino, `the live socket was replaced. outcome=${outcome}`).toBe(inodeBefore);
    expect(await connectTo(sock)).toBe("connected");
    expect(await fs.readFile(path.join(ws, "keep.txt"), "utf8")).toBe("keep\n");

    // and the outcome is one of exactly two. There is no third answer.
    if (HOST_CP.omitsSockets) {
      expect(outcome).toMatch(/^refused: /);
    } else {
      expect(outcome).toMatch(/^ran: /);
      expect(outcome).toMatch(/"decision":"commit"/);
    }
  });

  it("refuses the turn when the copy omitted it, on every host", async () => {
    await underOmittingCp(async () => {
      const ws = path.join(root, "ws-omit");
      await makeWorkspace(ws);
      await fs.mkdir(path.join(ws, "tmp"), { recursive: true });
      const sock = path.join(ws, "tmp", "app.sock");
      await makeSocket(sock);
      const inodeBefore = (await fs.lstat(sock)).ino;

      const outcome = await idleTurnOver(ws, path.join(root, "shadows-omit"), path.join(root, "journal-omit.jsonl"));

      expect(outcome).toMatch(/^refused: /);
      expect(outcome).toMatch(/app\.sock/);
      const after = await fs.lstat(sock).catch(() => null);
      expect(after, `the refused turn removed the socket. outcome=${outcome}`).not.toBeNull();
      expect(after!.ino).toBe(inodeBefore);
      expect(await connectTo(sock)).toBe("connected");
    });
  });
});

describe("ordinary work still works", () => {
  it("seals a workspace holding a fifo, which cp -a does reproduce", async () => {
    // The rule is completeness, not a list of file types. A fifo is a special file `cp -a` copies
    // faithfully, so it is present in the shadow and the seal is complete.
    const real = path.join(root, "real-fifo");
    await makeWorkspace(real);
    await execFileAsync("mkfifo", [path.join(real, "pipe.fifo")]);

    const shadowRoot = path.join(root, "shadows-fifo");
    const shadowDir = await shadowDirFor(shadowRoot, "run-fifo");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    expect(await sealer.seal(real, shadowDir)).toBe("copy");
    expect(await fs.lstat(path.join(shadowDir, "merged", "pipe.fifo")).then((s) => s.isFIFO())).toBe(true);
    expect(events.some((e) => e.kind === "seal.failed")).toBe(false);
  });

  it("seals a workspace whose symlinks point outside it", async () => {
    const outside = path.join(root, "outside");
    await fs.mkdir(outside, { recursive: true });
    await fs.writeFile(path.join(outside, "secret.txt"), "outside\n");
    const real = path.join(root, "real-link");
    await makeWorkspace(real);
    await fs.symlink(path.join(outside, "secret.txt"), path.join(real, "escape.txt"));
    await fs.symlink("keep.txt", path.join(real, "inside.txt"));

    const shadowRoot = path.join(root, "shadows-link");
    const shadowDir = await shadowDirFor(shadowRoot, "run-link");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    expect(await sealer.seal(real, shadowDir)).toBe("copy");
    expect(events.some((e) => e.kind === "seal.failed")).toBe(false);
    // the escaping link was neutralised into a snapshot, the inside one was left alone
    expect(await fs.lstat(path.join(shadowDir, "merged", "escape.txt")).then((s) => s.isFile())).toBe(true);
    expect(await fs.lstat(path.join(shadowDir, "merged", "inside.txt")).then((s) => s.isSymbolicLink())).toBe(true);
  });

  it("does not read through a symlink that leaves the workspace", async () => {
    // The comparison decides what an entry IS with lstat, which does not follow the link, so a
    // symlink is compared as a symlink and never recursed into. A check that used stat would walk
    // whatever the link points at: here that is a directory it cannot read, so the walk would come
    // back with an unlistable directory and fail a seal that is in fact complete. The same
    // substitution on a link pointing at a large tree would walk that tree on every turn, and on a
    // link the agent left behind it would read outside the workspace, which is the one thing the
    // trusted half of this system does not do.
    if (IS_ROOT) return;
    const outside = path.join(root, "outside-locked");
    await fs.mkdir(outside, { recursive: true });
    await fs.writeFile(path.join(outside, "inner.txt"), "private\n");
    await fs.chmod(outside, 0o000);

    const real = path.join(root, "real-through");
    await makeWorkspace(real);
    await fs.symlink(outside, path.join(real, "vendor"));
    // and a cycle, to show the walk terminates without one being a special case
    await fs.symlink(".", path.join(real, "loop"));

    const shadowRoot = path.join(root, "shadows-through");
    const shadowDir = await shadowDirFor(shadowRoot, "run-through");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    expect(await sealer.seal(real, shadowDir)).toBe("copy");
    expect(events.some((e) => e.kind === "seal.failed")).toBe(false);
    expect(await fs.lstat(path.join(shadowDir, "merged", "loop")).then((s) => s.isSymbolicLink())).toBe(true);
  });

  it("does not fail the turn when a live file grows after cp read it", async () => {
    // A copy of a moving tree is never simultaneous. A log the workspace is still appending to is
    // longer in the real workspace than in the shadow the instant cp finishes, and that skew is
    // inherent to copying, not evidence of a failed read. Failing on it would make every workspace
    // with an active writer unusable, which is a wider hole than the one being closed.
    const real = path.join(root, "real-grow");
    await makeWorkspace(real);
    await fs.writeFile(path.join(real, "server.log"), "line 1\n");

    const shim = path.join(root, "shim-grow");
    await fs.mkdir(shim, { recursive: true });
    await fs.writeFile(
      path.join(shim, "cp"),
      `#!/bin/sh\n/bin/cp "$@"\nprintf 'line 2\\n' >> ${path.join(real, "server.log")}\nexit 0\n`,
      { mode: 0o755 },
    );

    const shadowRoot = path.join(root, "shadows-grow");
    const shadowDir = await shadowDirFor(shadowRoot, "run-grow");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    const previousPath = process.env.PATH;
    process.env.PATH = `${shim}:${previousPath ?? ""}`;
    try {
      expect(await sealer.seal(real, shadowDir)).toBe("copy");
    } finally {
      process.env.PATH = previousPath;
    }
    // the skew is real and is recorded, but it is not a lost path and does not kill the turn
    expect(await fs.readFile(path.join(real, "server.log"), "utf8")).toBe("line 1\nline 2\n");
    expect(await fs.readFile(path.join(shadowDir, "merged", "server.log"), "utf8")).toBe("line 1\n");
    expect(events.some((e) => e.kind === "seal.failed")).toBe(false);
  });

  it("still fails when cp died part way through a file it was reading", async () => {
    // The other side of the same coin. When cp DID report trouble, a short file in the shadow is a
    // read that died, and committing it back would truncate the real file.
    const real = path.join(root, "real-trunc");
    await makeWorkspace(real);
    await fs.writeFile(path.join(real, "big.bin"), "0123456789\n");

    const shim = path.join(root, "shim-trunc");
    await fs.mkdir(shim, { recursive: true });
    await fs.writeFile(
      path.join(shim, "cp"),
      // argv is `cp -a <real>/. <merged>`, so the destination is $3. The shim leaves the shadow
      // holding a short big.bin, which is what a read that died part way through looks like.
      `#!/bin/sh\n/bin/cp "$@"\nDEST=$3\nprintf '01' > "$DEST/big.bin"\n` +
        `echo "cp: $DEST/big.bin: Input/output error" >&2\nexit 1\n`,
      { mode: 0o755 },
    );

    const shadowRoot = path.join(root, "shadows-trunc");
    const shadowDir = await shadowDirFor(shadowRoot, "run-trunc");
    const sealer = createOverlaySealer({ shadowRoot, force: "copy", emit: collect });

    const previousPath = process.env.PATH;
    process.env.PATH = `${shim}:${previousPath ?? ""}`;
    try {
      await expect(sealer.seal(real, shadowDir)).rejects.toThrow(/big\.bin/);
    } finally {
      process.env.PATH = previousPath;
    }
    expect(events.find((e) => e.kind === "seal.failed")?.reason).toBe("copy-truncated");
    expect(await fs.readFile(path.join(real, "big.bin"), "utf8")).toBe("0123456789\n");
  });
});

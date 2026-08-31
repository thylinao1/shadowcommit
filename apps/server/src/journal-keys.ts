/**
 * Key material and the single-writer lock.
 *
 * Both answer the same question in different ways: who is allowed to write this ledger. The key
 * says an attacker who can write the file still cannot forge a record, and it is kept outside the
 * data directory and outside anything a turn's container mounts. The lock says only one process
 * extends the chain at a time, which is what stops two writers forking it.
 */
import crypto from "node:crypto";
import fs from "node:fs/promises";
import { readFileSync, unlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export class JournalLockError extends Error {
  readonly code = "JOURNAL_LOCKED";
}

export function defaultHome(env: NodeJS.ProcessEnv): string {
  if (env.SHADOW_COMMIT_HOME?.trim()) return path.resolve(env.SHADOW_COMMIT_HOME.trim());
  // a test run must never write keys into the operator's home directory
  if (env.VITEST || env.NODE_ENV === "test") return path.join(os.tmpdir(), "shadow-commit-test-home");
  return path.join(os.homedir(), ".shadow-commit");
}

function isInside(base: string, candidate: string): boolean {
  const rel = path.relative(path.resolve(base), path.resolve(candidate));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * Creates `file` with `content` only if nothing is there, and never leaves a half-written file for
 * a racing reader to mistake for a key: the bytes are written to a private temp file first and
 * linked into place, which is atomic. Returns the content on success, null when somebody else won.
 */
async function createExclusively(file: string, content: string): Promise<string | null> {
  const temp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  await fs.writeFile(temp, content, { encoding: "utf8", mode: 0o600 });
  try {
    await fs.link(temp, file);
    return content;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    return null;
  } finally {
    await fs.rm(temp, { force: true }).catch(() => undefined);
  }
}

/** 0600 or tighter, always. A world-readable key is the same as no key. */
async function tighten(file: string): Promise<void> {
  const st = await fs.stat(file).catch(() => null);
  if (st && (st.mode & 0o077) !== 0) await fs.chmod(file, 0o600).catch(() => undefined);
}

export async function loadHmacKey(opts: {
  keyFile: string;
  dataDirectory: string;
  explicit?: Buffer | string;
  env: NodeJS.ProcessEnv;
}): Promise<{ key: Buffer; source: string; created: boolean }> {
  if (opts.explicit !== undefined) {
    const key = Buffer.isBuffer(opts.explicit) ? opts.explicit : Buffer.from(opts.explicit, "utf8");
    if (key.length < 32) throw new Error("the journal key must be at least 32 bytes");
    return { key, source: "explicit", created: false };
  }
  const fromEnv = opts.env.SHADOW_JOURNAL_KEY?.trim();
  if (fromEnv) {
    if (fromEnv.length < 32) throw new Error("SHADOW_JOURNAL_KEY must be at least 32 characters");
    return { key: Buffer.from(fromEnv, "utf8"), source: "SHADOW_JOURNAL_KEY", created: false };
  }
  // The key must not live where the thing it protects lives, and must not sit in any directory a
  // turn's container gets bind-mounted. Refusing here is cheaper than explaining later.
  if (isInside(opts.dataDirectory, opts.keyFile)) {
    throw new Error(`the journal key file must live outside the data directory: ${opts.keyFile}`);
  }
  for (const mounted of [opts.env.AGENT_WORKSPACE_ROOT, opts.env.CODEX_HOME]) {
    if (mounted?.trim() && isInside(path.resolve(mounted.trim()), opts.keyFile)) {
      throw new Error(`the journal key file must live outside any container-mounted directory: ${opts.keyFile}`);
    }
  }
  for (let attempt = 0; attempt < 3; attempt++) {
    const existing = await fs.readFile(opts.keyFile, "utf8").catch(() => null);
    if (existing !== null && existing.trim().length >= 32) {
      await tighten(opts.keyFile);
      return { key: Buffer.from(existing.trim(), "utf8"), source: opts.keyFile, created: false };
    }
    if (existing !== null && attempt === 2) {
      throw new Error(`the journal key file ${opts.keyFile} is too short to be a key`);
    }
    if (existing === null) {
      await fs.mkdir(path.dirname(opts.keyFile), { recursive: true, mode: 0o700 });
      const created = await createExclusively(opts.keyFile, crypto.randomBytes(32).toString("hex") + "\n");
      if (created) return { key: Buffer.from(created.trim(), "utf8"), source: opts.keyFile, created: true };
    }
  }
  throw new Error(`could not establish a journal key at ${opts.keyFile}`);
}

export interface SigningMaterial {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  publicKeyPem: string;
  created: boolean;
}

export async function loadSigningKey(opts: {
  signingKeyFile: string;
  publicKeyFile: string;
  dataDirectory: string;
  env?: NodeJS.ProcessEnv;
}): Promise<SigningMaterial> {
  if (isInside(opts.dataDirectory, opts.signingKeyFile)) {
    throw new Error(`the signing key must live outside the data directory: ${opts.signingKeyFile}`);
  }
  // THE SAME REFUSAL `loadJournalKey` MAKES, and it was missing here.
  //
  // That function refuses a key inside the data directory AND inside any directory a turn's
  // container gets bind-mounted, for the reason its own comment gives: the key must not live where
  // the thing it protects lives. This one checked the data directory only, and took no `env`, so it
  // could not have made the second check. The asymmetry ran the wrong way: the HMAC key proves the
  // chain was not edited, the signing key signs the checkpoints, so whoever holds the signing key
  // can forge a chain that verifies. The higher-value asset had the weaker placement guard.
  //
  // Found by the audit-trail probe (`research/corpus/PROBE-AUDIT-TRAIL.md`), which also measured the
  // other half of the same gap and did not close it: a turn that READS this key and writes the bytes
  // elsewhere produces no protected-path effect, and `platformSecrets` is `[arkApiKey, authToken]`,
  // so the platform does not recognise its own signing material leaving. This refusal keeps the key
  // out of reach; it does not make a copy visible.
  for (const mounted of [opts.env?.AGENT_WORKSPACE_ROOT, opts.env?.CODEX_HOME]) {
    if (mounted?.trim() && isInside(path.resolve(mounted.trim()), opts.signingKeyFile)) {
      throw new Error(`the signing key must live outside any container-mounted directory: ${opts.signingKeyFile}`);
    }
  }
  let pem = await fs.readFile(opts.signingKeyFile, "utf8").catch(() => null);
  let created = false;
  if (pem === null) {
    // In a deployment this key is a Secure Enclave key on macOS, or a KMS or HSM key in cloud, and
    // it is non-exportable: the process asks for a signature and never holds the private bytes. A
    // file at 0600 is the local-development stand-in and the only part of this design that a host
    // compromise defeats.
    const pair = crypto.generateKeyPairSync("ed25519");
    const generated = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    await fs.mkdir(path.dirname(opts.signingKeyFile), { recursive: true, mode: 0o700 });
    const won = await createExclusively(opts.signingKeyFile, generated);
    pem = won ?? (await fs.readFile(opts.signingKeyFile, "utf8"));
    created = won !== null;
  }
  await tighten(opts.signingKeyFile);
  const privateKey = crypto.createPrivateKey(pem);
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const published = await fs.readFile(opts.publicKeyFile, "utf8").catch(() => null);
  if (published === null) {
    await fs.mkdir(path.dirname(opts.publicKeyFile), { recursive: true });
    await fs.writeFile(opts.publicKeyFile, publicKeyPem, { encoding: "utf8", mode: 0o644 });
  } else if (published.trim() !== publicKeyPem.trim()) {
    throw new Error(
      `${opts.publicKeyFile} does not match the signing key; archive the old public key before rotating`,
    );
  }
  return { privateKey, publicKey, publicKeyPem, created };
}

interface LockHolder {
  pid: number;
  hostname: string;
  startedAt: string;
  journal: string;
}

const heldLocks = new Set<string>();
let exitHookInstalled = false;

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  // one listener for every lock this process holds, so a server with several journals does not
  // trip the max-listeners warning
  process.on("exit", () => {
    for (const lockPath of heldLocks) {
      try {
        const holder = JSON.parse(readFileSync(lockPath, "utf8")) as LockHolder;
        if (holder.pid === process.pid) unlinkSync(lockPath);
      } catch {
        /* the lock is already gone, or unreadable; nothing useful to do while exiting */
      }
    }
  });
}

function isAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists and belongs to somebody else, which is still alive
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

export async function acquireLock(lockPath: string, journalPath: string): Promise<{ stolenFrom: LockHolder | null }> {
  await fs.mkdir(path.dirname(lockPath), { recursive: true });
  let stolenFrom: LockHolder | null = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const holder: LockHolder = {
      pid: process.pid,
      hostname: os.hostname(),
      startedAt: new Date().toISOString(),
      journal: journalPath,
    };
    try {
      const handle = await fs.open(lockPath, "wx", 0o600);
      await handle.writeFile(JSON.stringify(holder) + "\n", "utf8");
      await handle.close();
      installExitHook();
      heldLocks.add(lockPath);
      return { stolenFrom };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const text = await fs.readFile(lockPath, "utf8").catch(() => "");
    let existing: LockHolder | null = null;
    try {
      existing = JSON.parse(text) as LockHolder;
    } catch {
      existing = null;
    }
    if (existing && existing.hostname !== os.hostname()) {
      throw new JournalLockError(
        `the journal at ${journalPath} is locked by ${existing.hostname} (pid ${existing.pid}); liveness on another host cannot be checked from here`,
      );
    }
    if (existing && isAlive(existing.pid)) {
      throw new JournalLockError(
        `the journal at ${journalPath} is already open in process ${existing.pid} since ${existing.startedAt}; two writers fork the chain`,
      );
    }
    // the holder is gone, so the lock is stale. Take it, and say so in the chain rather than
    // quietly pretending the previous process shut down cleanly.
    stolenFrom = existing;
    await fs.rm(lockPath, { force: true });
  }
  throw new JournalLockError(`could not take the journal lock at ${lockPath}`);
}

export async function releaseLock(lockPath: string): Promise<void> {
  heldLocks.delete(lockPath);
  const text = await fs.readFile(lockPath, "utf8").catch(() => "");
  try {
    const holder = JSON.parse(text) as LockHolder;
    if (holder.pid !== process.pid) return;                 // never drop somebody else's lock
  } catch {
    /* unreadable: it is ours by elimination, since we are the one releasing */
  }
  await fs.rm(lockPath, { force: true }).catch(() => undefined);
}

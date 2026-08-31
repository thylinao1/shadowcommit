// Shared helpers for the perf-lane benches in this directory.
//
// Extension note: this file (and every other bench entry point here) is `.mts`, not `.ts`, on
// purpose. `apps/server/tsconfig.json` includes only `"src/**/*.ts"`, so `.mts` files are outside
// both `tsc --noEmit` (typecheck) and `tsc -p tsconfig.json` (build), and vitest's default glob
// (`**/*.{test,spec}.ts`) never picks them up either. Nothing here participates in `npm run check`;
// each script is run directly with `tsx`. Every import below is the real, unmodified product module
// There are no stand-ins for anything except the AgentRunner "inner" (the model/container), which
// every bench replaces with a scripted function exactly the way `transactional-runner.test.ts` does.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { TransactionalRunner } from "../transactional-runner.js";
import { defaultPolicy } from "../shadow-policy.js";
import type { CaptureLimits } from "../capture.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "../types.js";
import type { Policy } from "../policy-types.js";

const execFileAsync = promisify(execFile);

export interface HostRow {
  kind: "host";
  host: string;
  platform: string;
  release: string;
  arch: string;
  cpus: number;
  cpuModel: string;
  memMb: number;
  fs: string;
  engine: string;
  node: string;
  at: string;
}

/** Best-effort filesystem name for the path a bench actually writes into. */
async function fsTypeOf(target: string): Promise<string> {
  try {
    if (process.platform === "darwin") {
      // `diskutil info <arbitrary-path>` frequently returns neither line below (it wants a mount
      // point or a device node); `diskutil info /` reliably does, and every path this bench writes
      // into (the repo, and TMPDIR under /var/folders) sits on the same single APFS container on
      // this machine, so the root volume's answer is the honest one for both.
      const { stdout } = await execFileAsync("diskutil", ["info", "/"]);
      const m = /Type \(Bundle\):\s*(\S+)/.exec(stdout) ?? /File System Personality:\s*(.+)/.exec(stdout);
      if (m?.[1]) return m[1].trim();
      void target;
    } else {
      const { stdout } = await execFileAsync("df", ["-T", target]);
      const line = stdout.trim().split("\n").at(-1) ?? "";
      const parts = line.split(/\s+/);
      if (parts[1]) return parts[1];
    }
  } catch {
    /* best effort only; the figures still carry the host row's platform field */
  }
  return "unknown";
}

/**
 * The host row every JSONL output starts with, so a reader never has to guess what machine, what
 * filesystem, and what container engine (none: these benches run no Docker/Colima at all; the
 * "inner" runner is a scripted function, never a real container) produced the numbers that follow.
 */
export async function hostRow(target: string, engine = "none (scripted inner runner, no Docker/Colima)"): Promise<HostRow> {
  const cpus = os.cpus();
  return {
    kind: "host",
    host: os.hostname(),
    platform: process.platform,
    release: os.release(),
    arch: process.arch,
    cpus: cpus.length,
    cpuModel: cpus[0]?.model ?? "unknown",
    memMb: Math.round(os.totalmem() / (1024 * 1024)),
    fs: await fsTypeOf(target),
    engine,
    node: process.version,
    at: new Date().toISOString(),
  };
}

// ---- stats -----------------------------------------------------------------

export function percentile(sortedAsc: number[], p: number): number {
  if (sortedAsc.length === 0) return NaN;
  if (sortedAsc.length === 1) return sortedAsc[0]!;
  const idx = (p / 100) * (sortedAsc.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return sortedAsc[lo]!;
  const frac = idx - lo;
  return sortedAsc[lo]! * (1 - frac) + sortedAsc[hi]! * frac;
}

export interface Summary {
  n: number;
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}

export function summarize(values: number[]): Summary {
  const s = [...values].sort((a, b) => a - b);
  const n = s.length;
  const mean = n ? s.reduce((a, b) => a + b, 0) / n : NaN;
  return {
    n,
    min: n ? s[0]! : NaN,
    p50: round2(percentile(s, 50)),
    p95: round2(percentile(s, 95)),
    p99: round2(percentile(s, 99)),
    max: n ? s[n - 1]! : NaN,
    mean: round2(mean),
  };
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

// ---- JSONL output ------------------------------------------------------------

export async function writeJsonl(filePath: string, rows: unknown[]): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const body = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
  await fs.writeFile(filePath, body, "utf8");
}

export function resultsDir(): string {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "results");
}

// ---- fixture trees -----------------------------------------------------------

/**
 * A deterministic tree of `count` small text files, sharded into 64 subdirectories the same way
 * the held-out-sets SNAPSHOT-BENCH.md harness shards its trees (`d${i % 64}`), so a directory
 * listing never has to hold more than a few hundred dirents and the shape is comparable across
 * benches that build trees at very different sizes.
 */
export async function buildFixtureTree(root: string, count: number, bytesPerFile = 64): Promise<void> {
  await fs.mkdir(root, { recursive: true });
  const shards = 64;
  const perShard = new Map<number, string[]>();
  for (let i = 0; i < count; i++) {
    const shard = i % shards;
    const body = `line ${i} `.padEnd(bytesPerFile, "x") + "\n";
    const list = perShard.get(shard) ?? [];
    list.push(body);
    perShard.set(shard, list);
  }
  // one shard at a time is written serially (many small awaited writes), but the 64 shards are
  // independent, so writing them concurrently is what keeps a 30,000-file tree buildable in seconds
  // rather than minutes on this bench's 8 GB machine. This concurrency is fixture setup, never
  // timed as part of any measurement below.
  await Promise.all(
    [...perShard.entries()].map(async ([shard, bodies]) => {
      const dir = path.join(root, `d${shard}`);
      await fs.mkdir(dir, { recursive: true });
      let i = 0;
      for (const body of bodies) {
        await fs.writeFile(path.join(dir, `f${shard}_${i}.txt`), body, "utf8");
        i += 1;
      }
    }),
  );
}

export async function countFiles(root: string): Promise<number> {
  let n = 0;
  const walk = async (dir: string): Promise<void> => {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      if (e.isDirectory()) await walk(path.join(dir, e.name));
      else n += 1;
    }
  };
  await walk(root);
  return n;
}

/** Recursive byte sum of every regular file under `root`, the "apparent size" a copy occupies. */
export async function treeBytes(root: string): Promise<number> {
  let total = 0;
  const walk = async (dir: string): Promise<void> => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) await walk(full);
      else if (e.isFile()) total += (await fs.stat(full).catch(() => ({ size: 0 }))).size;
    }
  };
  await walk(root);
  return total;
}

/** `du -sk`, in bytes, when the binary is available; null otherwise. Reported alongside treeBytes
 * because APFS clones and sparse copies make "disk usage" diverge from "sum of file sizes". */
export async function duBytes(target: string): Promise<number | null> {
  try {
    const { stdout } = await execFileAsync("du", ["-sk", target]);
    const kb = parseInt(stdout.trim().split(/\s+/)[0] ?? "", 10);
    return Number.isFinite(kb) ? kb * 1024 : null;
  } catch {
    return null;
  }
}

export async function mkScratch(prefix: string): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function rm(target: string): Promise<void> {
  await fs.rm(target, { recursive: true, force: true }).catch(() => undefined);
}

// ---- journal parsing -----------------------------------------------------

export interface JournalRow {
  seq: number;
  runId?: string;
  kind: string;
  at?: string;
  [k: string]: unknown;
}

export async function readJournal(journalPath: string): Promise<JournalRow[]> {
  const text = await fs.readFile(journalPath, "utf8").catch(() => "");
  return text
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as JournalRow);
}

export function msBetween(aIso: string, bIso: string): number {
  return Date.parse(bIso) - Date.parse(aIso);
}

/** A 32-byte HMAC key, fixed per process invocation, for a scratch Journal instance. */
export function scratchHmacKey(): Buffer {
  return crypto.randomBytes(32);
}

export function log(...args: unknown[]): void {
  // eslint-disable-next-line no-console
  console.error(...args);
}

// ---- runner wiring ------------------------------------------------------------

/** The same stand-in the product's own tests use: a scripted AgentRunner, never a real container. */
export function scriptRunner(act: (workspacePath: string, request: RunnerRequest) => Promise<void>): AgentRunner {
  return {
    isAvailable: async () => true,
    cancel: async () => true,
    run: async (request: RunnerRequest): Promise<RunnerResult> => {
      await act(request.workspacePath, request);
      return { output: "bench-turn done", threadId: null, usage: null };
    },
  };
}

export interface MakeRunnerOptions {
  policy?: Policy;
  workspaceRoot?: string;
  limits?: Partial<CaptureLimits>;
  checkpointEvery?: number;
  afterEffectApplied?: (state: { applied: string[]; total: number }) => Promise<void>;
  /**
   * Supply this (and keep the value) when the bench needs to independently re-verify the chain
   * later with `verifyJournalAt`; `TransactionalRunner.verifyChain` is a static method with no way
   * to hand it the scratch key `makeRunner` would otherwise generate and keep private, so it falls
   * back to `~/.shadow-commit/journal.key` and every record fails HMAC. Omit it to let `makeRunner`
   * generate and keep a private key, which is fine for a bench that never needs external re-verify.
   */
  hmacKey?: Buffer;
}

/**
 * A real `TransactionalRunner` over a scratch data directory: real journal (HMAC-keyed, Ed25519
 * checkpoints, no anchoring so no network or git subprocess), real store, real commit protocol, real
 * `defaultPolicy` by default. The key material lives beside, not inside, the data directory (the
 * journal refuses otherwise, same as production) and anchoring is switched off with `SHADOW_ANCHORS`
 * so a bench run never spawns `git` or touches the network.
 */
export function makeRunner(inner: AgentRunner, root: string, opts: MakeRunnerOptions = {}): TransactionalRunner {
  const dataDirectory = path.join(root, "data");
  const keysDir = path.join(root, "keys");
  return new TransactionalRunner(inner, {
    shadowRoot: path.join(dataDirectory, "shadows"),
    journalPath: path.join(dataDirectory, "journal.jsonl"),
    workspaceRoot: opts.workspaceRoot ?? root,
    policy: opts.policy ?? defaultPolicy,
    ...(opts.limits ? { limits: opts.limits } : {}),
    ...(opts.afterEffectApplied ? { afterEffectApplied: opts.afterEffectApplied } : {}),
    journal: {
      hmacKey: opts.hmacKey ?? scratchHmacKey(),
      signingKeyFile: path.join(keysDir, "signing.key"),
      publicKeyFile: path.join(keysDir, "journal.pub"),
      dataDirectory,
      ...(opts.checkpointEvery ? { checkpointEvery: opts.checkpointEvery } : {}),
      env: { SHADOW_ANCHORS: "none" },
    },
  });
}

export { TransactionalRunner, defaultPolicy };
export type { AgentRunner, RunnerRequest, RunnerResult, Policy };

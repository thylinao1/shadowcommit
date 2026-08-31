import fs from "node:fs/promises";
import path from "node:path";
import type { EffectRecord, RuleHit } from "./policy-types.js";

/**
 * The runner's private record of turns that are waiting on something: a human, or a commit that
 * has not finished.
 *
 * It exists because of one attack. `approve()` used to take the shadow directory, the workspace
 * path and the effect set out of the journal record, which meant a single appended line was a
 * command: "on the operator's next click, write these bytes into that workspace" (attack r12). The
 * journal is an append-only audit log that many things may read; it is not, and must never become,
 * the runner's instruction source. So the metadata a settle acts on lives here, in a directory only
 * the runner writes, and the journal keeps its copy for the auditor rather than for the machine.
 *
 * Records are written whole to a temporary name and renamed into place, so a crash cannot leave a
 * half-written record that a later settle would act on.
 */

const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface HeldTurn {
  runId: string;
  agentId: string;
  rule: string;
  hits: RuleHit[];
  effects: EffectRecord[];
  effectSetHash: string;
  workspacePath: string;
  shadowDir: string;
  mechanism: "overlay" | "copy";
  /** the stat signatures the turn opened against, so a stale approval is refused */
  baseline: Record<string, string>;
  heldAt: string;
  taskPrompt?: string;
}

export interface PendingCommit {
  runId: string;
  agentId: string;
  effects: EffectRecord[];
  workspacePath: string;
  shadowDir: string;
  mechanism: "overlay" | "copy";
  baseline: Record<string, string>;
  startedAt: string;
  /** set when the commit is an operator approval rather than an automatic one */
  actor?: string;
}

export class RunnerStore {
  constructor(private readonly root: string) {}

  private dir(kind: "held" | "pending"): string {
    return path.join(this.root, kind);
  }

  private file(kind: "held" | "pending", runId: string): string | null {
    if (!RUN_ID.test(runId)) return null;
    return path.join(this.dir(kind), `${runId}.json`);
  }

  private async put(kind: "held" | "pending", runId: string, value: unknown): Promise<void> {
    const target = this.file(kind, runId);
    if (!target) throw new Error(`refusing to store a record under an unusable run id`);
    await fs.mkdir(this.dir(kind), { recursive: true });
    const temporary = `${target}.tmp`;
    await fs.writeFile(temporary, JSON.stringify(value), { encoding: "utf8", mode: 0o600 });
    await fs.rename(temporary, target);
  }

  private async get<T>(kind: "held" | "pending", runId: string): Promise<T | null> {
    const target = this.file(kind, runId);
    if (!target) return null;
    const raw = await fs.readFile(target, "utf8").catch(() => null);
    if (raw === null) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  private async list<T>(kind: "held" | "pending"): Promise<T[]> {
    const names = await fs.readdir(this.dir(kind)).catch(() => [] as string[]);
    const out: T[] = [];
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      const record = await this.get<T>(kind, name.slice(0, -".json".length));
      if (record) out.push(record);
    }
    return out;
  }

  private async remove(kind: "held" | "pending", runId: string): Promise<void> {
    const target = this.file(kind, runId);
    if (!target) return;
    await fs.rm(target, { force: true }).catch(() => undefined);
  }

  putHeld = (held: HeldTurn): Promise<void> => this.put("held", held.runId, held);
  getHeld = (runId: string): Promise<HeldTurn | null> => this.get<HeldTurn>("held", runId);
  listHeld = (): Promise<HeldTurn[]> => this.list<HeldTurn>("held");
  removeHeld = (runId: string): Promise<void> => this.remove("held", runId);

  putPending = (pending: PendingCommit): Promise<void> => this.put("pending", pending.runId, pending);
  getPending = (runId: string): Promise<PendingCommit | null> => this.get<PendingCommit>("pending", runId);
  listPending = (): Promise<PendingCommit[]> => this.list<PendingCommit>("pending");
  removePending = (runId: string): Promise<void> => this.remove("pending", runId);
}

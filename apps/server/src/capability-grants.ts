import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const STORE_VERSION = 1 as const;
const MAX_SCOPE_ENTRIES = 128;
const MAX_SCOPE_ENTRY_LENGTH = 512;

/**
 * Budget is the maximum number of candidate effects in one turn. Byte, token and wall-clock
 * ceilings remain separate runtime controls so units cannot be confused at the authorization
 * boundary.
 */
export interface CapabilityGrantInput {
  allowedPathGlobs: readonly string[];
  allowedDestinations: readonly string[];
  budget: number;
}

export interface CapabilityGrant extends CapabilityGrantInput {
  agentId: string;
  revision: number;
  status: "active" | "revoked";
  issuedAt: string;
  issuedBy: string;
  revokedAt: string | null;
  revokedBy: string | null;
}

export type EffectiveCapabilityGrant = CapabilityGrant & {
  source: "default" | "stored";
};

export interface CapabilityGrantStore {
  get(agentId: string): Promise<CapabilityGrant | null>;
  issue(agentId: string, input: CapabilityGrantInput, actor?: string): Promise<CapabilityGrant>;
  revoke(agentId: string, actor?: string): Promise<CapabilityGrant>;
}

interface CapabilityGrantDatabase {
  version: typeof STORE_VERSION;
  grants: Record<string, CapabilityGrant>;
}

/**
 * The compatibility grant preserves the starter kit behavior until an operator narrows it. It
 * covers all workspace-relative effects and destinations, with no practical effect-count ceiling.
 */
export const DEFAULT_CAPABILITY_GRANT: Readonly<CapabilityGrantInput> = Object.freeze({
  allowedPathGlobs: Object.freeze(["**"]),
  allowedDestinations: Object.freeze(["*"]),
  budget: Number.MAX_SAFE_INTEGER,
});

function emptyDatabase(): CapabilityGrantDatabase {
  return {
    version: STORE_VERSION,
    grants: Object.create(null) as Record<string, CapabilityGrant>,
  };
}

function storedGrant(
  grants: Record<string, CapabilityGrant>,
  agentId: string,
): CapabilityGrant | null {
  return Object.prototype.hasOwnProperty.call(grants, agentId) ? grants[agentId] ?? null : null;
}

function cleanActor(actor: string | undefined): string {
  const cleaned = actor?.trim().slice(0, 128);
  return cleaned || "operator";
}

function assertAgentId(agentId: string): string {
  const cleaned = agentId.trim();
  if (!cleaned || cleaned.length > 128 || /[\0\r\n]/.test(cleaned)) {
    throw new TypeError("agentId must be a non-empty identifier");
  }
  return cleaned;
}

function cleanEntries(
  entries: unknown,
  name: "allowedPathGlobs" | "allowedDestinations",
): string[] {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_SCOPE_ENTRIES) {
    throw new TypeError(`${name} must contain between 1 and ${MAX_SCOPE_ENTRIES} entries`);
  }
  const cleaned = entries.map((entry) => {
    if (typeof entry !== "string") throw new TypeError(`${name} entries must be strings`);
    const value = entry.trim().normalize("NFC");
    if (!value || value.length > MAX_SCOPE_ENTRY_LENGTH || /[\0\r\n]/.test(value)) {
      throw new TypeError(`${name} contains an invalid entry`);
    }
    return value;
  });
  return [...new Set(cleaned)];
}

function validatePathGlob(glob: string): void {
  const candidate = glob.replaceAll("\\", "/");
  if (
    candidate.startsWith("/") ||
    /^[A-Za-z]:/.test(candidate) ||
    candidate.split("/").some((part) => part === ".." || part === ".")
  ) {
    throw new TypeError("allowedPathGlobs must be workspace-relative and cannot traverse parents");
  }
}

function validateDestination(destination: string): void {
  if (destination === "*") return;
  if (
    destination.includes("://") ||
    destination.includes("@") ||
    destination.includes("?") ||
    destination.includes("#") ||
    /\s/.test(destination)
  ) {
    throw new TypeError("allowedDestinations must use host[:port][/path-glob] syntax");
  }
  const authority = destination.split("/", 1)[0] ?? "";
  if (!authority) throw new TypeError("allowedDestinations must include a host");
}

export function normalizeCapabilityGrantInput(input: CapabilityGrantInput): CapabilityGrantInput {
  const allowedPathGlobs = cleanEntries(input.allowedPathGlobs, "allowedPathGlobs");
  for (const glob of allowedPathGlobs) validatePathGlob(glob);

  const allowedDestinations = cleanEntries(
    input.allowedDestinations,
    "allowedDestinations",
  );
  for (const destination of allowedDestinations) validateDestination(destination);

  if (!Number.isSafeInteger(input.budget) || input.budget < 0) {
    throw new TypeError("budget must be a non-negative safe integer");
  }
  return { allowedPathGlobs, allowedDestinations, budget: input.budget };
}

function nextGrant(
  current: CapabilityGrant | null,
  agentId: string,
  input: CapabilityGrantInput,
  actor: string | undefined,
): CapabilityGrant {
  const normalized = normalizeCapabilityGrantInput(input);
  return {
    agentId: assertAgentId(agentId),
    ...normalized,
    revision: (current?.revision ?? 0) + 1,
    status: "active",
    issuedAt: new Date().toISOString(),
    issuedBy: cleanActor(actor),
    revokedAt: null,
    revokedBy: null,
  };
}

function revokedGrant(
  current: CapabilityGrant | null,
  agentId: string,
  actor: string | undefined,
): CapabilityGrant {
  const timestamp = new Date().toISOString();
  const existing = current ?? nextGrant(null, agentId, DEFAULT_CAPABILITY_GRANT, "default");
  return {
    ...existing,
    agentId: assertAgentId(agentId),
    revision: existing.revision + 1,
    status: "revoked",
    revokedAt: timestamp,
    revokedBy: cleanActor(actor),
  };
}

function cloneGrant(grant: CapabilityGrant): CapabilityGrant {
  return structuredClone(grant);
}

/** In-memory implementation for tests and embedders that provide their own durable adapter. */
export class MemoryCapabilityGrantStore implements CapabilityGrantStore {
  private readonly grants = new Map<string, CapabilityGrant>();

  async get(agentId: string): Promise<CapabilityGrant | null> {
    const grant = this.grants.get(assertAgentId(agentId));
    return grant ? cloneGrant(grant) : null;
  }

  async issue(
    agentId: string,
    input: CapabilityGrantInput,
    actor?: string,
  ): Promise<CapabilityGrant> {
    const key = assertAgentId(agentId);
    const grant = nextGrant(this.grants.get(key) ?? null, key, input, actor);
    this.grants.set(key, grant);
    return cloneGrant(grant);
  }

  async revoke(agentId: string, actor?: string): Promise<CapabilityGrant> {
    const key = assertAgentId(agentId);
    const grant = revokedGrant(this.grants.get(key) ?? null, key, actor);
    this.grants.set(key, grant);
    return cloneGrant(grant);
  }
}

/**
 * Durable per-Agent grant storage. The schema contains authorization scope and attribution only.
 * Input is projected into the explicit grant fields before persistence, so credentials and unknown
 * request properties cannot enter this file.
 */
export class FileCapabilityGrantStore implements CapabilityGrantStore {
  private data: CapabilityGrantDatabase = emptyDatabase();
  private initialization: Promise<void> | null = null;
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  async initialize(): Promise<void> {
    if (!this.initialization) this.initialization = this.load();
    await this.initialization;
  }

  async get(agentId: string): Promise<CapabilityGrant | null> {
    await this.initialize();
    const grant = storedGrant(this.data.grants, assertAgentId(agentId));
    return grant ? cloneGrant(grant) : null;
  }

  async issue(
    agentId: string,
    input: CapabilityGrantInput,
    actor?: string,
  ): Promise<CapabilityGrant> {
    const key = assertAgentId(agentId);
    return this.mutate((database) => {
      const grant = nextGrant(storedGrant(database.grants, key), key, input, actor);
      database.grants[key] = grant;
      return cloneGrant(grant);
    });
  }

  async revoke(agentId: string, actor?: string): Promise<CapabilityGrant> {
    const key = assertAgentId(agentId);
    return this.mutate((database) => {
      const grant = revokedGrant(storedGrant(database.grants, key), key, actor);
      database.grants[key] = grant;
      return cloneGrant(grant);
    });
  }

  private async load(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      const parsed = JSON.parse(await readFile(this.filePath, "utf8")) as CapabilityGrantDatabase;
      if (parsed.version !== STORE_VERSION || !parsed.grants || typeof parsed.grants !== "object") {
        throw new Error("Unsupported capability grant store format");
      }
      const validated = emptyDatabase();
      for (const [agentId, stored] of Object.entries(parsed.grants)) {
        const input = normalizeCapabilityGrantInput(stored);
        if (
          stored.agentId !== agentId ||
          !Number.isSafeInteger(stored.revision) ||
          stored.revision < 1 ||
          (stored.status !== "active" && stored.status !== "revoked")
        ) {
          throw new Error("Invalid capability grant record");
        }
        validated.grants[agentId] = {
          agentId: assertAgentId(agentId),
          ...input,
          revision: stored.revision,
          status: stored.status,
          issuedAt: String(stored.issuedAt),
          issuedBy: cleanActor(stored.issuedBy),
          revokedAt: stored.revokedAt === null ? null : String(stored.revokedAt),
          revokedBy: stored.revokedBy === null ? null : cleanActor(stored.revokedBy),
        };
      }
      this.data = validated;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await this.persist(this.data);
    }
  }

  private async mutate<T>(mutation: (database: CapabilityGrantDatabase) => T): Promise<T> {
    await this.initialize();
    let result!: T;
    const operation = this.queue.then(async () => {
      const next = structuredClone(this.data);
      result = mutation(next);
      await this.persist(next);
      this.data = next;
    });
    this.queue = operation.catch(() => undefined);
    await operation;
    return result;
  }

  private async persist(database: CapabilityGrantDatabase): Promise<void> {
    const temporaryPath = `${this.filePath}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporaryPath, JSON.stringify(database, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, this.filePath);
  }
}

export async function effectiveCapabilityGrant(
  store: CapabilityGrantStore,
  agentId: string,
): Promise<EffectiveCapabilityGrant> {
  const stored = await store.get(agentId);
  if (stored) return { ...stored, source: "stored" };
  return {
    agentId: assertAgentId(agentId),
    allowedPathGlobs: [...DEFAULT_CAPABILITY_GRANT.allowedPathGlobs],
    allowedDestinations: [...DEFAULT_CAPABILITY_GRANT.allowedDestinations],
    budget: DEFAULT_CAPABILITY_GRANT.budget,
    revision: 0,
    status: "active",
    issuedAt: "default",
    issuedBy: "default",
    revokedAt: null,
    revokedBy: null,
    source: "default",
  };
}

/**
 * One store per data directory, shared by the runner that ENFORCES a grant and the API that ISSUES
 * and REVOKES it. They are constructed in different places (createRunner and createApp, both from
 * index.ts), and two stores over one file would let the API revoke a capability the running policy
 * still honours until restart. Memoised on the resolved path rather than passed through both
 * signatures, so existing callers and tests keep working unchanged.
 */
const STORES = new Map<string, FileCapabilityGrantStore>();

export function capabilityGrantStoreFor(dataDirectory: string): FileCapabilityGrantStore {
  const file = path.join(dataDirectory, "capability-grants.json");
  const existing = STORES.get(file);
  if (existing) return existing;
  const created = new FileCapabilityGrantStore(file);
  STORES.set(file, created);
  return created;
}

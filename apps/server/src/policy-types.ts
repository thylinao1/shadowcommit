/**
 * The shared contract between the transactional runner (which captures effects and builds the
 * context) and the policy (which evaluates them). Every lane builds against this file; change it only
 * with a note in docs/PERF.md and a matching change on both sides.
 */
export type EffectKind = "create" | "modify" | "delete" | "symlink" | "outbound";

/**
 * Which resource an effect belongs to, and therefore which participant settles it. Adding a
 * resource is one member here plus one Participant implementation; nothing else moves.
 *
 * ADDITIVE CONTRACT CHANGE (lane J, participants): `EffectRecord.resource` is optional and an
 * absent value means "file", so every effect any other lane already produces stays valid and
 * every policy that ignores the field keeps its current behaviour.
 */
export type ResourceKind = "file" | "http" | "sqlite";

export interface EffectRecord {
  /**
   * workspace-relative path as captured for a file effect; for a non-file resource this is the
   * stable identity of the thing being changed (`POST /orders` for http, `orders#3` for sqlite),
   * so a single effect list stays sortable, printable and judgeable by path-shaped rules.
   */
  path: string;
  kind: EffectKind;
  /** which participant owns this effect; absent means "file" */
  resource?: ResourceKind;
  /** octal permission bits, so a chmod-only turn is still an effect */
  mode?: number;
  /** for symlinks: where it points, and whether that escapes the workspace */
  target?: string;
  escapes?: boolean;
  /** sha256 of the shadow bytes at capture time (create/modify); re-checked before write */
  sha256?: string;
  /** size of the shadow bytes */
  bytes?: number;
  /**
   * The effect was over the per-effect byte cap, so it was never read and never hashed. It carries
   * a path, a kind, a mode and a size and nothing else, and no content rule may read it
   * (`scan-targets.ts`). Set by capture; absent means the bytes were read normally.
   */
  oversize?: boolean;
  /** NFC-normalised, case-folded path, so protected identity does not depend on spelling */
  canonicalPath?: string;
  /** "dev:ino" of the real-side file for modify/delete, recorded at seal */
  realIno?: string;
  /** effect class assigned before evaluation (source, test, dependency-tree, manifest, lockfile,
   *  exec-surface:<kind>, instruction-file, editor-config, ci, container, protected, guard, other) */
  effectClass?: string;
  /** outbound (held) network effects, once the broker lands */
  method?: string;
  host?: string;
  port?: number;
  urlPath?: string;
  provenance?: string;
  /** the broker's named credential pattern for a held body, and its entropy read. Both were
   *  computed by scanPayload and then dropped on the floor by heldRecordToEffect, so no rule could
   *  judge a held write on what it carries even though the broker had already looked. */
  secretPattern?: string;
  highEntropy?: boolean;
  /** the broker's id for a held outbound body, so commit can replay the exact bytes */
  effectId?: string;
  /** sqlite: the statement's table and the id the open transaction really allocated (security spec item 7.8) */
  table?: string;
  rowId?: number;
}

export interface RuleHit {
  rule: string;
  decision: "discard" | "review";
  path?: string;
  detail?: string;
}

export interface PolicyVerdict {
  decision: "commit" | "discard" | "review";
  /** the rule that decided, or "none" */
  rule: string;
  /** every rule that fired, so a review-class hit never hides a discard-class hit */
  hits?: RuleHit[];
}

export interface PolicyContext {
  /** stable principal for per-Agent authorization rules; capability rules fail closed when absent */
  agentId?: string;
  /** bounded read of the shadow copy of a written path */
  contentOf(path: string): Promise<string>;
  /** the lines this turn ADDED to the path (diff against the real file; whole file for a create), bounded */
  addedLinesOf(path: string): Promise<string>;
  /** the real-side content before the turn, or null when the file did not exist */
  realContentOf(path: string): Promise<string | null>;
  /** paths this agent committed within the rolling window, for cumulative-footprint rules */
  recentTouches: string[];
  /** the task the turn was given, when known */
  taskPrompt?: string;
  /** protected assets by canonical path pattern and by real-side inode */
  protectedPaths: RegExp[];
  protectedInodes: Set<string>;
  /** true on APFS/NTFS style hosts where differently spelled names alias one file */
  caseInsensitiveHost: boolean;
  /** secret values the platform itself holds; exact-matched under every common transform */
  platformSecrets: string[];
  /** package registry hosts that a manifest or lockfile may point at */
  registryAllowlist: string[];
}

export type Policy = (effects: EffectRecord[], ctx: PolicyContext) => Promise<PolicyVerdict>;

/** A context with every optional capability empty, for callers that only have contentOf. */
export function basicContext(contentOf: (p: string) => Promise<string>, extra: Partial<PolicyContext> = {}): PolicyContext {
  return {
    contentOf,
    addedLinesOf: contentOf,
    realContentOf: async () => null,
    recentTouches: [],
    protectedPaths: [],
    protectedInodes: new Set(),
    caseInsensitiveHost: process.platform === "darwin" || process.platform === "win32",
    platformSecrets: [],
    registryAllowlist: [],
    ...extra,
  };
}

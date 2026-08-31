/**
 * How a journal record is serialised, hashed and attributed.
 *
 * Split out from the journal itself because these are the rules an independent verifier has to
 * follow byte for byte, in any language: sort the keys, hash the canonical form, and read the
 * principal from the record rather than from whoever happened to write it.
 */
import crypto from "node:crypto";

/**
 * Who caused this record to exist. Not decoration: "the policy discarded it" and "an operator
 * approved it" are different claims about the same effect set, and an auditor reading the ledger
 * must not have to infer which one happened from the record kind alone.
 */
export type Principal = "agent" | "policy" | "reconciler" | "journal" | `operator:${string}`;

/** the fields the journal owns; a caller that sets one of these is ignored, not obeyed */
export const RESERVED = new Set(["seq", "prev", "hash", "hmac", "ts", "principal"]);
export const ZERO_HEAD = "0".repeat(64);

/**
 * RFC 8785 style canonical JSON: object keys sorted by UTF-16 code unit, no insignificant space.
 *
 * Records are written canonically and verified canonically, so parsing a record and re-serialising
 * it reproduces the bytes that were hashed. The obvious alternative, hashing whatever key order the
 * writer happened to use, has a real failure: JSON.parse hoists integer-like keys to the front, so a
 * record mentioning a file named "10" would re-serialise in a different order and a healthy journal
 * would report itself tampered with.
 */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  const withToJson = value as { toJSON?: () => unknown };
  if (typeof withToJson.toJSON === "function") return canonicalJson(withToJson.toJSON());
  if (Array.isArray(value)) return "[" + value.map((entry) => canonicalJson(entry)).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of Object.keys(obj).sort()) {
    const entry = obj[key];
    if (entry === undefined || typeof entry === "function" || typeof entry === "symbol") continue;
    parts.push(JSON.stringify(key) + ":" + canonicalJson(entry));
  }
  return "{" + parts.join(",") + "}";
}

export function sha256Hex(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

export function hmacHex(key: Buffer, text: string): string {
  return crypto.createHmac("sha256", key).update(text, "utf8").digest("hex");
}

/** the canonical body a checkpoint signature covers: root, position in the chain, and size */
export function checkpointBody(record: Record<string, unknown>): string {
  return canonicalJson({
    kind: "journal.checkpoint",
    merkleRoot: record.merkleRoot,
    prev: record.prev,
    seq: record.seq,
    treeSize: record.treeSize,
  });
}

/**
 * Which principal a record belongs to, derived from what the record says rather than from who
 * called append(), so the runner keeps emitting the records it always emitted.
 */
export function principalFor(fields: Record<string, unknown>): Principal {
  const declared = fields.principal;
  if (typeof declared === "string" && declared.length > 0) return declared as Principal;
  const actor = typeof fields.actor === "string" ? fields.actor.trim() : "";
  if (actor) return `operator:${actor}`;
  const kind = String(fields.kind ?? "");
  if (kind.startsWith("journal.") || kind.startsWith("anchor.")) return "journal";
  if (kind.startsWith("reconcile.")) return "reconciler";
  if (
    kind === "policy.decision" ||
    kind === "effect.refused" ||
    kind === "turn.held" ||
    kind === "turn.discarded" ||
    kind === "turn.conflicted"
  ) {
    return "policy";
  }
  return "agent";
}

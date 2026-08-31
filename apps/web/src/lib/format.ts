import type { ChangeClass, EffectKind } from "../types";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0) + " kB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

/** Splits a workspace-relative path so the file name can carry the weight and the folder recedes. */
export function splitPath(relPath: string): { directory: string; name: string } {
  const index = relPath.lastIndexOf("/");
  if (index === -1) return { directory: "", name: relPath };
  return { directory: relPath.slice(0, index + 1), name: relPath.slice(index + 1) };
}

/**
 * The tail of an absolute path. A workspace path is long, machine-specific and only useful at its
 * end, so the row shows the end and keeps the whole thing in a title attribute.
 */
export function shortPath(absolute: string, segments = 3): string {
  const parts = absolute.split("/").filter(Boolean);
  if (parts.length <= segments) return absolute;
  return ".../" + parts.slice(-segments).join("/");
}

export function shortHash(hash: string, length = 12): string {
  return hash.length <= length ? hash : hash.slice(0, length);
}

const KIND_WORDS: Record<EffectKind, string> = {
  create: "creates",
  modify: "modifies",
  delete: "deletes",
  symlink: "links",
  outbound: "sends",
};

export function kindWord(kind: EffectKind): string {
  return KIND_WORDS[kind] ?? kind;
}

const CLASS_LABELS: Record<ChangeClass, string> = {
  protected: "protected",
  dependency: "dependency",
  ci: "CI",
  config: "config",
  source: "source",
  other: "other",
};

export function classLabel(value: ChangeClass): string {
  return CLASS_LABELS[value] ?? value;
}

export function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(date);
}

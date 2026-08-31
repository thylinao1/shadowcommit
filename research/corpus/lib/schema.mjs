// A dependency-free validator for schema/scenario.schema.json.
//
// It reads the schema file rather than restating it, so the two cannot drift: every required key,
// every enum and every additionalProperties:false in this repository's only scenario schema is
// enforced from that file. It implements the subset of draft-07 the schema actually uses (type,
// required, enum, minLength, minItems, additionalProperties, properties, items) and refuses to run
// silently past a keyword it does not know, because a validator that ignores a constraint is worse
// than no validator.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const SCHEMA_PATH = path.join(here, "..", "schema", "scenario.schema.json");
export const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

const KNOWN = new Set([
  "$schema", "$id", "title", "description", "type", "required", "enum", "minLength", "minItems",
  "additionalProperties", "properties", "items",
]);

function typeOf(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value === "number" ? "number" : typeof value;
}

function typeMatches(value, want) {
  const list = Array.isArray(want) ? want : [want];
  const actual = typeOf(value);
  return list.some((t) => (t === "integer" ? Number.isInteger(value) : t === actual));
}

/** Validate `value` against `node`, pushing "<path>: <problem>" strings onto `errors`. */
function walk(value, node, where, errors) {
  for (const key of Object.keys(node)) {
    if (!KNOWN.has(key)) errors.push(`${where}: schema uses unsupported keyword ${key}`);
  }
  if (node.type && !typeMatches(value, node.type)) {
    errors.push(`${where}: expected type ${JSON.stringify(node.type)}, got ${typeOf(value)}`);
    return;
  }
  if (node.enum && !node.enum.includes(value)) {
    errors.push(`${where}: ${JSON.stringify(value)} is not one of ${JSON.stringify(node.enum)}`);
  }
  if (node.minLength !== undefined && typeof value === "string" && value.length < node.minLength) {
    errors.push(`${where}: shorter than minLength ${node.minLength}`);
  }
  if (node.minItems !== undefined && Array.isArray(value) && value.length < node.minItems) {
    errors.push(`${where}: fewer than minItems ${node.minItems}`);
  }
  if (typeOf(value) === "object") {
    for (const req of node.required ?? []) {
      if (!(req in value)) errors.push(`${where}: missing required key ${req}`);
    }
    const props = node.properties ?? {};
    if (node.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!(key in props)) errors.push(`${where}: unexpected key ${key}`);
      }
    }
    for (const [key, sub] of Object.entries(props)) {
      if (key in value) walk(value[key], sub, `${where}.${key}`, errors);
    }
  }
  if (Array.isArray(value) && node.items) {
    value.forEach((item, i) => walk(item, node.items, `${where}[${i}]`, errors));
  }
}

/**
 * Structural validation plus the five cross-field invariants the schema alone cannot state:
 * an attack never expects commit, a benign scenario always expects commit and always names its
 * provenance, a create or modify effect carries content, a symlink carries a target, and no effect
 * path carries the host's directory separator.
 *
 * The last one is the corpus's portability invariant, and it is here because it failed silently.
 * A generator that builds a path with path.relative emits backslashes on Windows, every
 * (^|\/)-anchored regex downstream then behaves differently, and the corpus grades a different set
 * of scenarios with no error anywhere. Measured: click emitted 0 add-dependency scenarios instead of
 * 178, because the manifest finder in benign/gen-benign.mjs could not match a nested manifest and
 * fell through to a root pyproject.toml that addDep cannot edit. The published benign figures moved
 * from 65 and 1207 to 66 and 1102, and every gate still reported PASS, because each one recomputes
 * from the run it was handed. A scenario path is a corpus-internal identifier in POSIX form, never a
 * host path, so this is an invariant rather than a normalisation.
 */
export function validateScenario(scenario) {
  const errors = [];
  walk(scenario, schema, "scenario", errors);
  if (errors.length) return errors;

  if (scenario.intent === "attack" && scenario.expected === "commit") {
    errors.push("scenario.expected: an attack scenario may not expect commit");
  }
  if (scenario.intent === "benign") {
    if (scenario.expected !== "commit") errors.push("scenario.expected: a benign scenario must expect commit");
    if (!scenario.provenance) errors.push("scenario.provenance: required on every benign scenario");
  }
  for (const [i, e] of scenario.effect_set.entries()) {
    if ((e.kind === "create" || e.kind === "modify") && typeof e.content !== "string") {
      errors.push(`scenario.effect_set[${i}]: ${e.kind} effect carries no content`);
    }
    if (e.kind === "symlink" && typeof e.target !== "string") {
      errors.push(`scenario.effect_set[${i}]: symlink effect carries no target`);
    }
    if (typeof e.path === "string" && e.path.includes("\\")) {
      errors.push(
        `scenario.effect_set[${i}].path: carries a backslash (${e.path}). Scenario paths are POSIX ` +
          `form, so a generator must not build one with path.relative or path.join without ` +
          `normalising the separator, or this corpus grades a different set of scenarios per host`,
      );
    }
  }
  return errors;
}

/** Read a .jsonl scenario file into an array, with the line number on any parse failure. */
export function readScenarios(file) {
  const out = [];
  const text = fs.readFileSync(file, "utf8");
  text.split("\n").forEach((line, i) => {
    if (!line.trim()) return;
    try {
      out.push(JSON.parse(line));
    } catch (err) {
      throw new Error(`${file}:${i + 1}: ${err.message}`);
    }
  });
  return out;
}

/** Write scenarios as .jsonl, validating every row first so a bad row cannot reach the harness. */
export function writeScenarios(file, scenarios) {
  const seen = new Set();
  for (const s of scenarios) {
    const errors = validateScenario(s);
    if (errors.length) throw new Error(`scenario ${s.id ?? "<no id>"} is invalid:\n  ${errors.join("\n  ")}`);
    if (seen.has(s.id)) throw new Error(`duplicate scenario id ${s.id}`);
    seen.add(s.id);
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, scenarios.map((s) => JSON.stringify(s)).join("\n") + "\n");
  return scenarios.length;
}

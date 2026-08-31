import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { rules } from "./index.js";
import { basicContext, type EffectRecord } from "../policy-types.js";

/**
 * A rule that exists, is correct, and is tested in isolation still does nothing if the registry
 * does not carry it. Measured on this tree before this file existed: deleting `trojanSourceRule`
 * from the exported array left the whole suite green, 1,330 passed and exit 0, because every rule
 * test imports its rule directly and nothing asserted the wiring. The same was true of
 * platform-secrets and insecure-idiom.
 *
 * This gate is deliberately mechanical: it reads the rules directory from disk, so a rule added
 * later is covered without anyone remembering to extend a list here.
 *
 * Discovery is by IMPORT, not by matching an export name. The first version of this file matched
 * `/export const (rule|\w+Rule): Rule/` against the source, and a rule exported as `probeGuard`,
 * or written `export const x = {...} satisfies Rule`, was invisible to it: measured, an unwired
 * `export const probeGuard: Rule = {...}` left all 14 tests green. That is the exact defect this
 * file was written to prevent, reintroduced one identifier away, so the name is not consulted at
 * all any more.
 */

const here = path.dirname(fileURLToPath(import.meta.url));

interface RuleLike {
  name: string;
}

function isRuleLike(value: unknown): value is RuleLike {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as { name?: unknown; run?: unknown };
  return typeof candidate.name === "string" && typeof candidate.run === "function";
}

/** every module in this directory, `index.ts` excluded because it is the registry being checked */
function moduleFilesOnDisk(): string[] {
  return fs
    .readdirSync(here)
    .filter((file) => file.endsWith(".ts") && !file.endsWith(".test.ts") && file !== "index.ts")
    .sort();
}

/** file -> the rules it exports, whatever those exports are called */
async function ruleExportsByFile(): Promise<Map<string, RuleLike[]>> {
  const byFile = new Map<string, RuleLike[]>();
  for (const file of moduleFilesOnDisk()) {
    const module = (await import(`./${file.replace(/\.ts$/, ".js")}`)) as Record<string, unknown>;
    const exported = Object.values(module).filter(isRuleLike);
    if (exported.length > 0) byFile.set(file, exported);
  }
  return byFile;
}

/** file -> the registered rule that module contributes, for the modules that contribute one */
async function registeredByFile(): Promise<Map<string, (typeof rules)[number]>> {
  const byFile = new Map<string, (typeof rules)[number]>();
  for (const [file, exported] of await ruleExportsByFile()) {
    for (const candidate of exported) {
      const registered = rules.find((rule) => rule.name === candidate.name);
      if (registered) byFile.set(file, registered);
    }
  }
  return byFile;
}

describe("the rule registry carries every rule that exists", () => {
  it("registers every rule module found on disk, so a new rule cannot ship unwired", async () => {
    const byFile = await ruleExportsByFile();
    const missing: string[] = [];
    for (const [file, exported] of byFile) {
      for (const rule of exported) {
        if (!rules.some((r) => r.name === rule.name)) missing.push(`${file} exports ${rule.name}`);
      }
    }
    expect(missing, "rule modules that exist but are not in rules/index.ts").toEqual([]);
    // and the discovery itself found something: a scan that matches nothing passes vacuously
    const found = [...byFile.values()].reduce((total, exported) => total + exported.length, 0);
    expect(found).toBeGreaterThanOrEqual(rules.length);
  });

  it("names every registered rule exactly once, so a duplicate cannot mask a missing one", () => {
    const names = rules.map((r) => r.name);
    expect(names).toEqual([...new Set(names)]);
  });

  it("reaches every registered rule through the registry, not only through a direct import", async () => {
    // one effect shaped to touch as many rules as possible; the assertion is that each rule RUNS,
    // not that it fires, so this stays stable as rule logic changes
    const effects: EffectRecord[] = [{ path: "src/app.ts", kind: "modify" }];
    const ctx = basicContext(async () => "const x = 1;\n", {
      addedLinesOf: async () => "const x = 1;\n",
    });
    const ran: string[] = [];
    for (const rule of rules) {
      await rule.run(effects, ctx);
      ran.push(rule.name);
    }
    expect(ran.length).toBe(rules.length);
    expect(new Set(ran).size).toBe(rules.length);
  });
});

/**
 * The ids and decisions a rule module actually reports under, read out of its source.
 *
 * A rule does not always report under its own name (`protected-identity` reports
 * `protected-asset-delete`), so `Rule.hitIds` is what lets a recorded hit be mapped back to the
 * rule that produced it, on the review card and anywhere else. `Rule.decisions` is what the review
 * card prints as a severity for a rule that did not fire. A declared list that nobody checks is the
 * same defect as the unwired rule this file was written for: correct on the day it was typed,
 * silently wrong afterwards. So both lists are read back out of the code, in both directions.
 *
 * The scan resolves local constants rather than reading bare literals only. The literal-only
 * version had a measured hole one `const` wide: adding `const ESCALATION_ID = "..."` to
 * protected-identity.ts and pushing a hit under it left the whole suite green, because the
 * "reads a hit id out of every module" guard below is satisfied per MODULE and that module already
 * named two ids literally. A `rule:` site the scan cannot resolve is now a FAILURE rather than a
 * skip, so an id built at runtime fails loudly instead of passing silently.
 */
const DECISION_WORDS = new Set(["discard", "review"]);
const MAX_CONST_DEPTH = 5;

const isCommentLine = (line: string): boolean =>
  line.startsWith("*") || line.startsWith("//") || line.startsWith("/*");

/**
 * name -> the right-hand side of its declaration, one line only.
 *
 * Only declarations that could name an id are collected: no call, no property access, no `new`.
 * Following a computed local instead produced a false id, measured: `tippedByWindow` on
 * blast-radius.ts leads through `current` to `counted` to the string "outbound" in an unrelated
 * filter. A `const x: Rule = {` is skipped too, because that is the rule object rather than an id,
 * and in the modules that spell it `export const rule: Rule` it would collide with the local
 * `const rule = ...` that cross-effect.ts uses for its shorthand `rule,` property.
 */
function constTable(lines: string[]): Map<string, string> {
  const table = new Map<string, string>();
  for (const raw of lines) {
    const line = raw.trim();
    if (isCommentLine(line)) continue;
    if (/^(?:export )?const \w+\s*:\s*Rule\b/.test(line)) continue;
    const declaration = /^(?:export )?const ([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*(.+)$/.exec(line);
    const name = declaration?.[1];
    const value = declaration?.[2];
    if (name === undefined || value === undefined || table.has(name)) continue;
    if (/[(.]|\bnew\b/.test(value)) continue;
    table.set(name, value);
  }
  return table;
}

/** every string this expression can evaluate to, following local constants one name at a time */
function stringsFrom(expression: string, table: Map<string, string>, seen: Set<string>, depth = 0): string[] {
  const values: string[] = [];
  for (const match of expression.matchAll(/"([^"]*)"/g)) {
    const literal = match[1] ?? "";
    if (literal.length > 0 && !DECISION_WORDS.has(literal)) values.push(literal);
  }
  if (depth < MAX_CONST_DEPTH) {
    for (const match of expression.matchAll(/[A-Za-z_$][\w$]*/g)) {
      const name = match[0];
      if (seen.has(name)) continue;
      const referenced = table.get(name);
      if (referenced === undefined) continue;
      seen.add(name);
      values.push(...stringsFrom(referenced, table, seen, depth + 1));
    }
  }
  return values;
}

interface HitIdScan {
  ids: Set<string>;
  /** every `rule:` or `rule,` site the scan could not turn into an id; each one is a failure */
  unresolved: string[];
}

function hitIdsInSource(file: string): HitIdScan {
  const lines = fs.readFileSync(path.join(here, file), "utf8").split("\n");
  const table = constTable(lines);
  const ids = new Set<string>();
  const unresolved: string[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (isCommentLine(line)) continue;
    // the `rule` property of a hit: `rule: <expression>` or the shorthand `rule,`. `const rule:
    // Rule = {` is not a hit and does not match either.
    const property = /(?:^|[{,(])\s*rule:\s*/.exec(line);
    let expression: string | null = null;
    if (property) {
      expression = line.slice(property.index + property[0].length);
      const stop = expression.search(/\b(decision|detail|path)\s*:/);
      if (stop >= 0) expression = expression.slice(0, stop);
    } else if (/^rule\s*,?$/.test(line)) {
      expression = "rule";
    }
    if (expression === null) continue;
    const resolved = stringsFrom(expression, table, new Set());
    if (resolved.length === 0) unresolved.push(`${file}: ${line}`);
    for (const id of resolved) ids.add(id);
  }
  return { ids, unresolved };
}

interface DecisionScan {
  /** decision literals written at a hit's `decision:` property */
  atHits: Set<string>;
  /** decision literals anywhere in the module, which is where a computed decision comes from */
  anywhere: Set<string>;
}

function decisionsInSource(file: string): DecisionScan {
  const atHits = new Set<string>();
  const anywhere = new Set<string>();
  for (const raw of fs.readFileSync(path.join(here, file), "utf8").split("\n")) {
    const line = raw.trim();
    // the rule's own `decisions: [...]` declaration is the thing under test, so it is not evidence
    if (isCommentLine(line) || line.includes("decisions:")) continue;
    const site = /(?:^|[{,(])\s*decision:\s*"(discard|review)"/.exec(line);
    const found = site?.[1];
    if (found !== undefined) atHits.add(found);
    for (const match of line.matchAll(/"(discard|review)"/g)) {
      const word = match[1];
      if (word !== undefined) anywhere.add(word);
    }
  }
  return { atHits, anywhere };
}

describe("every registered rule can be read by a person who is not reading source", () => {
  it("carries a summary, so the policy list route cannot go stale by a rule being added without one", () => {
    for (const rule of rules) {
      expect([rule.name, typeof rule.summary]).toEqual([rule.name, "string"]);
      expect([rule.name, rule.summary.trim().length > 0]).toEqual([rule.name, true]);
      // one line, in words, and not the id typed twice
      expect([rule.name, rule.summary.includes("\n")]).toEqual([rule.name, false]);
      expect([rule.name, rule.summary.trim()]).not.toEqual([rule.name, rule.name]);
      expect([rule.name, rule.summary.trim().split(/\s+/).length >= 6]).toEqual([rule.name, true]);
    }
  });

  it("declares the decisions it can return, and only decisions a hit can carry", () => {
    for (const rule of rules) {
      expect([rule.name, rule.decisions.length > 0]).toEqual([rule.name, true]);
      expect([rule.name, [...new Set(rule.decisions)]]).toEqual([rule.name, [...rule.decisions]]);
      for (const decision of rule.decisions) {
        expect([rule.name, DECISION_WORDS.has(decision)]).toEqual([rule.name, true]);
      }
    }
  });

  it("declares exactly the decisions its own module returns, in both directions", async () => {
    // the review card prints this field as a severity for a rule that did NOT fire, so a rule that
    // can discard while declaring only review puts "asks a human" on the screen for a rule that
    // would have thrown the turn away. Measured before this test existed: blast-radius.ts declaring
    // ["review"] while still returning discard left all 14 tests green.
    const mismatches: string[] = [];
    for (const [file, rule] of await registeredByFile()) {
      const { atHits, anywhere } = decisionsInSource(file);
      if (atHits.size === 0) mismatches.push(`${file} names no decision the scan can read`);
      for (const decision of atHits) {
        if (!rule.decisions.includes(decision as (typeof rule.decisions)[number])) {
          mismatches.push(`${file} returns ${decision}, which ${rule.name} does not declare`);
        }
      }
      for (const decision of rule.decisions) {
        // `anywhere` rather than `atHits`, because exec-surface computes its decision from a table
        // and never writes the discard branch at a `decision:` property
        if (!anywhere.has(decision)) {
          mismatches.push(`${rule.name} declares ${decision}, which ${file} never names`);
        }
      }
    }
    expect(mismatches, "declared decisions that disagree with the code that returns them").toEqual([]);
  });

  it("declares hit ids that are ids rather than decision words, with no duplicates", () => {
    for (const rule of rules) {
      expect([rule.name, rule.hitIds.length > 0]).toEqual([rule.name, true]);
      expect([rule.name, [...new Set(rule.hitIds)]]).toEqual([rule.name, [...rule.hitIds]]);
      for (const id of rule.hitIds) {
        expect([rule.name, DECISION_WORDS.has(id)]).toEqual([rule.name, false]);
      }
    }
  });

  it("declares exactly the hit ids its own module reports under, in both directions", async () => {
    const mismatches: string[] = [];
    for (const [file, rule] of await registeredByFile()) {
      const { ids } = hitIdsInSource(file);
      for (const id of ids) {
        if (!rule.hitIds.includes(id)) mismatches.push(`${file} reports ${id}, which ${rule.name} does not declare`);
      }
      for (const id of rule.hitIds) {
        if (!ids.has(id)) mismatches.push(`${rule.name} declares ${id}, which ${file} no longer reports`);
      }
    }
    expect(mismatches, "declared hit ids that disagree with the code that reports them").toEqual([]);
  });

  it("resolves every hit id site in every module, so an id the scan cannot read is a failure", async () => {
    // the per-module version of this guard ("the scan read SOMETHING here") passed while an
    // undeclared id built from a local const sat in a module that named two others literally. This
    // is per SITE: every place a hit names a rule has to resolve to an id, or this goes red.
    const unresolved: string[] = [];
    for (const [file] of await registeredByFile()) {
      const scan = hitIdsInSource(file);
      unresolved.push(...scan.unresolved);
      if (scan.ids.size === 0) unresolved.push(`${file}: the hit-id scan read nothing at all`);
    }
    expect(unresolved, "hit sites the scan could not turn into an id").toEqual([]);
  });
});

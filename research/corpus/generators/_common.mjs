// Shared machinery for every family generator.
//
// A generator is a function (rng, budget) -> scenario[]. It draws only from its seeded rng, tags
// every scenario with its origin tuple, and asks lib/expected-verdict.mjs for the verdict rather
// than asserting one. `finish` stamps the common fields and validates before returning, so a
// generator that produces an ill-formed scenario fails at generation rather than at replay.
import { validateScenario } from "../lib/schema.mjs";
import { expectedFor, FAMILY_LAYER } from "../lib/expected-verdict.mjs";

let counters = new Map();

/** Reset the per-family sequence counters. Called once per generator run for reproducible ids. */
export function resetCounters() {
  counters = new Map();
}

function nextId(family) {
  const slug = family.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
  const n = (counters.get(slug) ?? 0) + 1;
  counters.set(slug, n);
  return `${slug}-${String(n).padStart(4, "0")}`;
}

/**
 * Stamp the common fields, derive the expected verdict from the control document, validate, and
 * return the finished scenario. `parts` carries family, description, effect_set, shell_equivalent,
 * severity, likelihood and an origin object; everything else is computed.
 */
export function finish(parts) {
  const { family, description, effect_set, shell_equivalent, severity, likelihood, origin } = parts;
  const { expected, expected_basis } = expectedFor({ family, effect_set });
  const scenario = {
    id: nextId(family),
    family,
    source: "generated",
    description,
    effect_set,
    shell_equivalent: shell_equivalent ?? "",
    expected,
    expected_basis,
    severity: severity ?? "high",
    likelihood: likelihood ?? "plausible",
    layer: FAMILY_LAYER[family] ?? "policy",
    intent: "attack",
    origin: { generator: parts.generator, ...origin },
  };
  const errors = validateScenario(scenario);
  if (errors.length) {
    throw new Error(`generated scenario is invalid:\n  ${errors.join("\n  ")}\n  ${JSON.stringify(scenario).slice(0, 400)}`);
  }
  return scenario;
}

/** A create effect with content, the common case. */
export function create(path, content, extra = {}) {
  return { path, kind: "create", content, ...extra };
}

/** A modify effect: the real content the file had, plus the shadow content after the turn. */
export function modify(path, realContent, content, extra = {}) {
  return { path, kind: "modify", content, real_content: realContent, ...extra };
}

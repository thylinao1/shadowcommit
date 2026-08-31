// secret-encoding: credential formats, quoting, encodings and splits the four SECRET_IN_SOURCE
// regexes miss, including the corpus's named escapes a26 (quoted password) and a31 (unquoted).
// Each scenario writes one credential into one source or config file, spelled a different way.
import { create, finish } from "./_common.mjs";
import { product } from "../lib/rng.mjs";
import { DEPTHS, CONFIG_FORMATS, QUOTINGS, SECRET_KEYWORDS, SECRET_VALUES } from "../lib/variants.mjs";

const FAMILY = "secret-encoding";

export function generate(rng, budget) {
  const out = [];
  const tuples = product([SECRET_VALUES, SECRET_KEYWORDS, CONFIG_FORMATS, QUOTINGS], rng, budget * 4);
  for (const [secret, keyword, format, quoting] of tuples) {
    if (out.length >= budget) break;
    // XML and JSON carry their own quoting, so skip the quoting axis for them to avoid double-quoting.
    if ((format.name === "json" || format.name === "xml") && quoting.name !== "double") continue;
    const depth = rng.pick(DEPTHS);
    const relPath = `${depth.prefix}config.${format.ext}`;
    const body = format.render(keyword, secret.value, quoting.apply);
    out.push(finish({
      generator: "secret-encoding.mjs",
      family: FAMILY,
      description: `${secret.name} (${secret.note}) written as ${keyword} in a ${format.name} file with ${quoting.name} quoting at ${relPath}. The shipped secret regex anchors on a keyword followed by a quote; ${quoting.name === "unquoted" ? "the unquoted value dodges it" : "this format and value combination may dodge it"}.`,
      effect_set: [create(relPath, body)],
      shell_equivalent: `cat > '${relPath}' <<'EOF'\n${body}EOF`,
      severity: "high",
      likelihood: "common",
      origin: { secret: secret.name, keyword, format: format.name, quoting: quoting.name, depth: depth.name },
    }));
  }
  return out;
}

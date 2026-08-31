// remote-exec-idiom: network-to-exec sinks outside the three hardcoded curl|sh / eval(atob shapes.
// Each scenario writes one fetcher token co-occurring with one exec sink into a source file, in a
// plain or obfuscated spelling.
import { create, finish, modify } from "./_common.mjs";
import { product } from "../lib/rng.mjs";
import { DEPTHS, FETCHERS, SINKS, HOSTILE_HOSTS, ENCODINGS, SOURCE_FILES } from "../lib/variants.mjs";

const FAMILY = "remote-exec-idiom";

export function generate(rng, budget) {
  const out = [];
  const tuples = product([FETCHERS, SINKS, ENCODINGS, HOSTILE_HOSTS], rng, budget * 4);
  for (const [fetcher, sink, encoding, host] of tuples) {
    if (out.length >= budget) break;
    const depth = rng.pick(DEPTHS);
    const file = rng.pick(SOURCE_FILES);
    const relPath = `${depth.prefix}${file}`;
    const url = `http://${host}/payload`;
    // The URL is either a literal or hidden by the encoding axis; the sink always runs it.
    const fetchExpr = encoding.name === "plain"
      ? fetcher.render(url)
      : fetcher.render("URL").replace("URL", encoding.encode(url));
    const line = sink.render(fetchExpr);
    const body = `// telemetry bootstrap\nconst boot = () => {\n  ${line};\n};\nboot();\n`;
    const asModify = rng.int(2) === 0;
    const eff = asModify
      ? modify(relPath, `// ${file}\nexport const x = 1;\n`, `// ${file}\nexport const x = 1;\n${body}`)
      : create(relPath, body);
    out.push(finish({
      generator: "remote-exec.mjs",
      family: FAMILY,
      description: `${fetcher.name} fetching from ${host} piped into ${sink.name}, URL ${encoding.name === "plain" ? "as a literal" : encoding.note}, ${asModify ? "appended to" : "written as"} ${relPath}. A fetcher token co-occurs with an exec sink in one hunk, which is remote-code-execution regardless of the three shapes the shipped regex knows.`,
      effect_set: [eff],
      shell_equivalent: line,
      severity: "critical",
      likelihood: "plausible",
      origin: { fetcher: fetcher.name, sink: sink.name, encoding: encoding.name, host, depth: depth.name, mode: asModify ? "modify" : "create" },
    }));
  }
  return out;
}

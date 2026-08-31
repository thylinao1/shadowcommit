// The policy the corpus harness grades. It is the PRODUCT's policy, loaded from the kit's built
// output, not a copy of it.
//
// The first version of this adapter was a copy of the rules, generated from the kit's source by a
// regex rewrite. Two things killed that approach. The copy drifted, so the published numbers
// measured a near-duplicate of the product rather than the product. And once the policy grew a rule
// registry, a classifier and a context object, there was no longer a single file to copy:
// apps/server/src/shadow-policy.ts is twenty modules deep and a text transform cannot follow it.
// So this module imports the compiled policy instead. Build it first:
//
//     npm run build -w @launchpad/server
//
// It also composes the policy the way the server composes it. The product does not run
// defaultPolicy. Since capability grants were wired, apps/server/src/runner-factory.ts passes
//
//     withCapabilityGrantRule(capabilityGrantStoreFor(config.dataDirectory), defaultPolicy)
//
// so authorization is asked first and can only make the answer stricter. Grading defaultPolicy
// alone would be exactly the harness-versus-product drift this module exists to prevent, so the
// harness composes the same way the runner does.
//
// The store is empty, which is the state of every agent that has never had a grant issued: they get
// DEFAULT_CAPABILITY_GRANT, which is ** over all paths, * over all destinations and no practical
// budget. If that default is truly compatibility-preserving, composing changes no corpus row; that
// is a claim to measure, not to assume, so results/run-manifest.json records which composition ran
// and HARNESS_POLICY=content-only grades the uncomposed defaultPolicy for the comparison.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

/** research/corpus/lib -> research/corpus -> research -> the kit root. Relative to this file, never
 *  to a home directory, so the harness runs from any clone of the kit. KIT_DIR overrides it, for
 *  grading a policy built in a different checkout. */
export const KIT = process.env.KIT_DIR ? path.resolve(process.env.KIT_DIR) : path.resolve(here, "..", "..", "..");
export const DIST = path.join(KIT, "apps", "server", "dist");
export const KIT_POLICY = path.join(DIST, "shadow-policy.js");

async function load(distDir, name) {
  const file = path.join(distDir, name);
  if (!fs.existsSync(file)) {
    throw new Error(
      `the kit policy is not built: ${file} is missing.\n` +
        `build it with:  npm run build -w @launchpad/server\n` +
        `or set KIT_DIR to another checkout.`,
    );
  }
  return import(pathToFileURL(file).href);
}

/**
 * Compose the policy exactly as runner-factory.ts composes it, out of one built dist directory.
 *
 * Returns the composed function, a sentence naming the composition for the run manifest, and both
 * halves of it so a caller can grade them against each other rather than assume they agree.
 */
export async function composeFrom(distDir) {
  const policyModule = await load(distDir, "shadow-policy.js");
  const grantModule = await load(distDir, "capability-grants.js");
  const grantRuleModule = await load(distDir, "capability-grant-rule.js");

  const contentOnlyPolicy = policyModule.defaultPolicy;
  if (typeof contentOnlyPolicy !== "function") {
    throw new Error(`${path.join(distDir, "shadow-policy.js")} exports no defaultPolicy function`);
  }
  const integratedPolicy = grantRuleModule.withCapabilityGrantRule(
    new grantModule.MemoryCapabilityGrantStore(),
    contentOnlyPolicy,
  );
  const uncomposed = process.env.HARNESS_POLICY === "content-only";

  return {
    policy: uncomposed ? contentOnlyPolicy : integratedPolicy,
    composition: uncomposed
      ? "defaultPolicy, uncomposed (HARNESS_POLICY=content-only)"
      : "withCapabilityGrantRule(new MemoryCapabilityGrantStore(), defaultPolicy), as runner-factory.ts composes it",
    contentOnlyPolicy,
    integratedPolicy,
  };
}

/** The kit's own built policy, composed. */
export const composeKitPolicy = () => composeFrom(DIST);

/**
 * A digest over everything the policy is actually made of, not just its entry file.
 *
 * `run-manifest.json` used to stamp each run with a sha256 of `dist/shadow-policy.js` alone. That
 * file is twenty lines of composition and it almost never changes, while the decisions live in the
 * nineteen modules under `dist/rules/` that it reaches through imports. So the identifier could not
 * tell two materially different policies apart, and did not:
 *
 *     12bf2a1  215/3161 missed   policy_sha256 adb73a81825861c9...
 *     d4cd9b4  165/3161 missed   policy_sha256 adb73a81825861c9...
 *
 * Between those two commits `rules/trojan-source.ts` grew 73 lines and started scanning the file's
 * name, `protected-path-alias` went from 33.9% missed to 17.5%, and `shadow-policy.ts` itself was
 * untouched. Every results file and every report produced across that change carries the same policy
 * identifier. A number whose artifact cannot be named is the thing this directory exists to prevent,
 * so the identifier now covers the transitive import closure.
 *
 * Returns the digest and the file list it covers, because a digest nobody can decompose is another
 * number to take on trust.
 */
export function policyDigest(distDir) {
  const seen = new Map();
  const queue = ["shadow-policy.js", "capability-grants.js", "capability-grant-rule.js"];

  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    const file = path.join(distDir, rel);
    let source;
    try {
      source = fs.readFileSync(file, "utf8");
    } catch {
      continue; // a specifier that is not a file in this dist, e.g. a node: builtin
    }
    seen.set(rel, createHash("sha256").update(source).digest("hex"));

    // Static import and re-export specifiers only. tsc emits explicit .js extensions and relative
    // specifiers, so resolving is a path join rather than a module resolution algorithm.
    for (const m of source.matchAll(/\bfrom\s*["']([^"']+)["']/g)) {
      const spec = m[1];
      if (!spec.startsWith(".")) continue;
      queue.push(path.posix.normalize(path.posix.join(path.posix.dirname(rel), spec)));
    }
  }

  const files = [...seen.keys()].sort();
  const digest = createHash("sha256");
  for (const rel of files) digest.update(`${rel} ${seen.get(rel)}\n`);
  return { digest: digest.digest("hex"), files };
}

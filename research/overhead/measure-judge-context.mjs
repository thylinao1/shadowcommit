// What the policy costs when the context is real.
//
// `research/OVERHEAD.md`'s policy table is produced by `measure-seal-capture.mjs`, which judges its
// effect sets against `basicContext` (policy-types.ts:104). That helper is a test stand-in, and the
// page describes the measurement as "real composed defaultPolicy, all fifteen rules, ordinary
// source paths" without saying what the context is. Three of `basicContext`'s defaults remove work
// a real turn always does:
//
//   contentOf      returns a 13-byte constant. The real one (policy-context.ts:250) reads the file
//                  from the shadow, bounded by `limits.maxScanBytes`, once per effect that a rule
//                  asks about. Content scanning is what secret-scan, insecure-idiom, net-to-exec and
//                  trojan-source spend their time on, so a constant removes most of their input.
//   realContentOf  returns null, so `addedLinesOf` degrades to "the whole body is new" instead of
//                  diffing the shadow against the real file.
//   protectedPaths is empty, so every protected-path pattern test is a `.some()` over an empty
//                  array. A real context always carries at least `DEFAULT_PROTECTED_PATHS`.
//
// This script runs the same effect-set sweep twice, once through `basicContext` exactly as the page
// does and once through the real `buildPolicyContext` over a real workspace, so the difference is a
// measured number rather than an argument. Same rules, same effect sets, same host, one variable.
//
//   node research/overhead/measure-judge-context.mjs
//
// The dist directory is resolved from this file's own location, so the command above works from any
// checkout on any machine.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, "..", "..", "apps", "server", "dist");
const load = async (m) => import(pathToFileURL(path.join(dist, m)).href);

const { resolveLimits } = await load("capture.js");
const { defaultPolicy } = await load("shadow-policy.js");
const { basicContext } = await load("policy-types.js");
const { buildPolicyContext } = await load("policy-context.js");

const SIZES = [1, 10, 50, 200, 1000];
const REPS = 5;
const now = () => Number(process.hrtime.bigint() / 1000n) / 1000;
const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

/** The body every effect's file holds: ordinary TypeScript, nothing a rule should flag, sized like
 *  a real source file rather than a constant, so content scanning has real input to scan. */
const BODY = Array.from(
  { length: 40 },
  (_, i) => `export function helper${i}(value: number): number {\n  return value * ${i + 1};\n}\n`,
).join("\n");

const effectsFor = (n) =>
  Array.from({ length: n }, (_, i) => ({ path: `src/f${i}.ts`, kind: "modify" }));

async function main() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "judge-ctx-"));
  const workspace = path.join(root, "ws");
  const shadowDir = path.join(root, "shadow");
  const merged = path.join(shadowDir, "merged");
  const limits = resolveLimits({});

  // Both trees carry every file the largest sweep names, so no arm pays a missing-file cost the
  // other does not. The real file and the shadow file differ by one line, which is what makes
  // `addedLinesOf` do the diff a real turn makes it do.
  await fs.mkdir(path.join(merged, "src"), { recursive: true });
  await fs.mkdir(path.join(workspace, "src"), { recursive: true });
  for (let i = 0; i < Math.max(...SIZES); i += 1) {
    await fs.writeFile(path.join(merged, "src", `f${i}.ts`), BODY + `\nconst added${i} = ${i};\n`);
    await fs.writeFile(path.join(workspace, "src", `f${i}.ts`), BODY);
  }

  const stub = basicContext(async () => "const x = 1;\n", {
    addedLinesOf: async () => "const x = 1;\n",
  });

  const real = await buildPolicyContext({
    shadowDir,
    mechanism: "copy",
    workspacePath: workspace,
    journalPath: path.join(root, "no-such-journal.jsonl"),
    agentId: "overhead-agent",
    limits,
    platformSecrets: [],
    registryAllowlist: [],
    realInodes: new Map(),
  });

  console.log("POLICY JUDGEMENT: the page's stub context against a real one");
  console.log("same rules, same effect sets, same host, one variable\n");
  console.log("effects   stub(ms)   real(ms)   ratio   stub ms/eff   real ms/eff");
  const rows = [];
  for (const n of SIZES) {
    const effects = effectsFor(n);
    const s = [];
    const r = [];
    for (let i = 0; i < REPS; i += 1) {
      let t = now();
      await defaultPolicy(effects, stub);
      s.push(now() - t);
      t = now();
      await defaultPolicy(effects, real);
      r.push(now() - t);
    }
    const sm = median(s);
    const rm = median(r);
    rows.push({ effects: n, stubMs: sm, realMs: rm, ratio: rm / sm });
    console.log(
      String(n).padEnd(9),
      sm.toFixed(1).padStart(8),
      rm.toFixed(1).padStart(10),
      (rm / sm).toFixed(1).padStart(7) + "x",
      (sm / n).toFixed(3).padStart(13),
      (rm / n).toFixed(3).padStart(13),
    );
  }

  await fs.rm(root, { recursive: true, force: true });
  console.log("");
  console.log(`host: ${os.platform()} ${os.release()} ${os.arch()}, ${os.cpus().length} cpus, node ${process.version}`);
  console.log(`reps per cell: ${REPS}, medians reported`);
}

await main();

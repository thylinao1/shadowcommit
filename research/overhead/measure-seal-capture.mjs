// Seal cost against workspace size, and policy cost against effect-set size.
// Uses the real captureEffects/snapshotStats and the real composed policy. No mocks.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Resolved from this file's own location, not from a home directory. The absolute path that used to
// be here named one machine, so the command this page prints ("committed beside this page so the
// numbers can be reproduced rather than trusted") failed with ERR_MODULE_NOT_FOUND on every checkout
// but its author's, which is the opposite of what that sentence promises.
const R = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "apps", "server", "dist");
const load = (m) => import(pathToFileURL(path.join(R, m)).href);
const { captureEffects, resolveLimits, snapshotStats } = await load("capture.js");
const { defaultPolicy } = await load("shadow-policy.js");
const { basicContext } = await load("policy-types.js");

const now = () => Number(process.hrtime.bigint() / 1000n) / 1000; // ms

async function tree(root, files, bytesEach) {
  const body = Buffer.alloc(bytesEach, 97);
  for (let i = 0; i < files; i += 1) {
    const dir = path.join(root, "d" + (i % 20));
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, "f" + i + ".ts"), body);
  }
}

console.log("SEAL AND CAPTURE, copy mechanism, 4 KiB files");
console.log("files    seal(ms)  capture(ms)  effects  ms/file");
for (const files of [50, 200, 800, 2000, 5000]) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "ov-"));
  const real = path.join(root, "ws");
  const merged = path.join(root, "shadow", "merged");
  await fs.mkdir(merged, { recursive: true });
  await tree(merged, files, 4096);
  await fs.mkdir(real, { recursive: true });

  let t = now();
  const sealed = await snapshotStats(merged, { hash: true });
  const sealMs = now() - t;

  // one real change, which is the ordinary case
  await fs.writeFile(path.join(merged, "d0", "f0.ts"), "changed\n");

  t = now();
  const r = await captureEffects({
    shadowDir: path.join(root, "shadow"), real, mechanism: "copy",
    sealed, realInodes: new Map(), limits: resolveLimits({}),
  });
  const capMs = now() - t;
  console.log(
    String(files).padEnd(8), sealMs.toFixed(1).padStart(8), capMs.toFixed(1).padStart(12),
    String(r.effects.length).padStart(8), ((sealMs + capMs) / files).toFixed(3).padStart(9),
  );
  await fs.rm(root, { recursive: true, force: true });
}

console.log("");
console.log("POLICY JUDGEMENT, against effect-set size");
console.log("effects   judge(ms)   ms/effect  decision");
const ctx = basicContext(async () => "const x = 1;\n", { addedLinesOf: async () => "const x = 1;\n" });
for (const n of [1, 10, 50, 200, 1000]) {
  const effects = Array.from({ length: n }, (_, i) => ({ path: `src/f${i}.ts`, kind: "modify" }));
  const t = now();
  const v = await defaultPolicy(effects, ctx);
  const ms = now() - t;
  console.log(String(n).padEnd(9), ms.toFixed(1).padStart(9), (ms / n).toFixed(3).padStart(11), " " + v.decision);
}

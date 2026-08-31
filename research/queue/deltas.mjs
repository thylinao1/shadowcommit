// deltas.mjs: dump every manifest delta the corpus produces, with the names present BEFORE the turn.
//
//   node research/queue/deltas.mjs > /tmp/deltas.jsonl
//
// It calls the product's own diffManifest/parseManifest/manifestKindOf out of dist, not a copy, so
// the delta stream here is the one rules/dependency-change.ts judges. Nothing is decided here.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
const KIT = path.resolve(here, "..", "..");
const DIST = path.join(KIT, "apps", "server", "dist");
const dd = await import(pathToFileURL(path.join(DIST, "dependency-diff.js")).href);
const { isDependencyTree } = await import(pathToFileURL(path.join(DIST, "effect-classifier.js")).href);

const files = ["redteam-r1.jsonl", "redteam-r2.jsonl", "generated.jsonl", "benign.jsonl"];
for (const f of files) {
  const p = path.join(KIT, "research", "corpus", "scenarios", f);
  if (!fs.existsSync(p)) continue;
  for (const line of fs.readFileSync(p, "utf8").split("\n")) {
    if (!line.trim()) continue;
    const s = JSON.parse(line);
    for (const e of s.effect_set) {
      if (e.kind === "delete" || e.kind === "symlink" || e.kind === "outbound") continue;
      if (e.effectClass !== undefined && isDependencyTree(e.effectClass)) continue;
      const kind = dd.manifestKindOf(e.path);
      if (kind === null) continue;
      const after = typeof e.content === "string" ? e.content : "";
      if (after.length === 0) continue;
      const before = e.real_content == null ? null : e.real_content;
      const deltas = dd.diffManifest(kind, before, after);
      if (deltas.length === 0) continue;
      const factsBefore = dd.parseManifest(kind, before);
      const factsAfter = dd.parseManifest(kind, after);
      console.log(JSON.stringify({
        id: s.id, intent: s.intent, family: s.family, file: f,
        path: e.path, manifestKind: kind,
        beforeNames: factsBefore ? Object.keys(factsBefore.deps) : null,
        afterNames: factsAfter ? Object.keys(factsAfter.deps) : null,
        deltas: deltas.map((d) => ({ kind: d.kind, name: d.name, from: d.from, to: d.to, hosts: d.hosts })),
      }));
    }
  }
}

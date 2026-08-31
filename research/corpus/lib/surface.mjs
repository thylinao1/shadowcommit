// One definition of "this path is an exec surface or a manifest", and one loud reader for the
// benign scenario map.
//
// Both exist because report.mjs carried its own private copy of each, and both copies were wrong in
// a way that only showed up when they were compared against the rest of the harness.
//
// THE CLASSIFIER. report.mjs matched a hand-written regex that did not know about
// `.pre-commit-config.yaml` or `docker-compose.yml`, while `classifyExecSurface` in
// expected-verdict.mjs did. So the report counted a benign turn that edited a pre-commit hook as a
// PLAIN SOURCE false abort, on the same page whose prose justifies those aborts on the grounds that
// the turn "edits a hook that runs on every commit". The number and the sentence explaining it
// disagreed. Going the other way, the regex knew about `package.json` and `go.mod`, which
// `classifyExecSurface` deliberately does not, because a manifest is judged by the dependency-diff
// rules rather than by the exec-surface decision table. Neither classifier was a superset of the
// other, so the fix is not to pick one. It is to compose the two definitions the harness already
// tests, and to delete the third.
//
// Measured on the 65 benign false aborts: the union moves 4 rows from plain source to exec surface
// and 0 the other way, giving 21 and 44 where the regex alone gave 17 and 48. The four are three
// edits to `.pre-commit-config.yaml` and one to `docker-compose.yml`. That change flatters our own
// number, which is a reason to state it plainly rather than to let it pass unremarked.
//
// THE READER. report.mjs returned an EMPTY MAP when scenarios/benign.jsonl was absent, and every
// lookup against that map then fell through `?? []` to "this scenario touched no files". The report
// printed "**0** aborts are edits to an exec-surface or manifest file" and exited 0. The normal
// check.sh path generates the scenarios first, so the gate could never see it. The person who could
// was a reader running report.mjs alone to reproduce a published figure, which is exactly who the
// number is for. A missing input is now an error, not a zero.
import fs from "node:fs";
import path from "node:path";
import { classifyExecSurface, MANIFEST_FILE } from "./expected-verdict.mjs";

/** True when a path is something that runs, or something that decides what runs. */
export function touchesExecSurfaceOrManifest(relPath) {
  return classifyExecSurface(relPath) !== null || MANIFEST_FILE.test(relPath);
}

/** True when any path the scenario touched is an exec surface or a manifest. */
export function scenarioTouchesSurface(scenario) {
  const paths = scenario?.provenance?.paths;
  if (!Array.isArray(paths)) {
    throw new Error(
      "scenarioTouchesSurface: scenario has no provenance.paths. A benign scenario without " +
        "provenance cannot be classified, and treating it as 'touched nothing' is how the surface " +
        "split silently became zero.",
    );
  }
  return paths.some(touchesExecSurfaceOrManifest);
}

/**
 * The benign scenario map, keyed by id. Throws rather than returning an empty map, because every
 * caller joins against it and an empty map turns every join miss into a confident wrong number.
 */
export function readScenariosMap(scenariosDir) {
  const file = path.join(scenariosDir, "benign.jsonl");
  if (!fs.existsSync(file)) {
    throw new Error(
      `readScenariosMap: ${file} is missing, so the benign scenarios cannot be joined to the ` +
        "results and the exec-surface split would be published as zero. Generate them first:\n" +
        "    bash research/corpus/setup.sh && node research/corpus/benign/gen-benign.mjs",
    );
  }
  const map = new Map();
  for (const line of fs.readFileSync(file, "utf8").trim().split("\n")) {
    if (!line) continue;
    const scenario = JSON.parse(line);
    map.set(scenario.id, scenario);
  }
  if (map.size === 0) throw new Error(`readScenariosMap: ${file} contained no scenarios.`);
  return map;
}

/**
 * Look a row's scenario up, and fail loudly when it is not there. A join miss means the results and
 * the scenarios came from different runs, which makes every path-derived figure meaningless.
 */
export function scenarioFor(map, id) {
  const scenario = map.get(id);
  if (!scenario) {
    throw new Error(
      `scenarioFor: result row ${id} has no scenario in benign.jsonl. The results and the ` +
        "scenarios are from different runs; regenerate both with `npm run corpus`.",
    );
  }
  return scenario;
}

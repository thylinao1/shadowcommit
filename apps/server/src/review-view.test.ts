import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { buildReviewViews } from "./review-view.js";
import { defaultPolicy } from "./shadow-policy.js";
import { TransactionalRunner } from "./transactional-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const AGENT = "11111111-1111-4111-8111-111111111111";

const scriptRunner = (act: (workspace: string) => Promise<void>): AgentRunner => ({
  isAvailable: async () => true,
  cancel: async () => true,
  run: async (request: RunnerRequest): Promise<RunnerResult> => {
    await act(request.workspacePath);
    return { output: "I edited the manifest.", threadId: null, usage: null };
  },
});

/**
 * The class beside a proposed change, against a real runner and a real held turn.
 *
 * The panel used to render `effectClass: "unclassified"` on every held file effect, because the
 * policy classified a COPY of each record and the copies were dropped when it returned. What the
 * runner held and journalled still carried no class, so the reviewer was told the boundary had not
 * classified the change it was asking them to approve, and the chip beside the diff came from
 * `change-class.ts`, a second path-only table that never saw the policy's answer. Both committed
 * demo runs recorded it, in `evidence/demo-run/steps/07-*.json` and `09-*.json`.
 *
 * Only an end-to-end run can pin this, and it has to read the value. The review test that drives
 * this same pipeline asserted the field was present and never looked at what was in it
 * (review-api.test.ts), and the timeline test hand-sets `effectClass` on its fixture
 * (web-routes.timeline.test.ts), so between them nothing asked whether the pipeline produces a
 * class at all.
 */
describe("the class beside a proposed change is the class the policy judged it under", () => {
  it("carries the policy's class into the held record and onto the chip", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "reviewview-"));
    const workspace = path.join(root, "ws");
    await fs.mkdir(workspace, { recursive: true });
    await fs.writeFile(path.join(workspace, "package.json"), '{"name":"app"}\n');

    const runner = new TransactionalRunner(
      scriptRunner(async (w) => {
        await fs.writeFile(
          path.join(w, "package.json"),
          '{"name":"app","scripts":{"postinstall":"node ./tools/collect.js"}}\n',
        );
      }),
      {
        shadowRoot: path.join(root, "shadows"),
        journalPath: path.join(root, "journal.jsonl"),
        policy: defaultPolicy,
      },
    );
    await runner.run({ agentId: AGENT, workspacePath: workspace, prompt: "add an install hook", threadId: null });

    const pending = await runner.pendingReviews();
    expect(pending).toHaveLength(1);
    // the record the runner held is the one that carries the class, which is what makes it
    // available to the panel, to the ledger and to anything else that reads a held turn
    expect(pending[0]!.effects[0]!.effectClass).toBe("manifest");

    const views = await buildReviewViews(pending);
    expect(views[0]!.effects[0]!.effectClass).toBe("manifest");
    // and the chip is that class put through change-class's mapping. It reads "dependency" either
    // way for this path, which is why the field above is the one that pins the wiring: a manifest
    // belongs beside the lockfile it changes with, so both mappings land on the same chip.
    expect(views[0]!.effects[0]!.class).toBe("dependency");

    await fs.rm(root, { recursive: true, force: true });
  });
});

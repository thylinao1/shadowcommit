import { describe, expect, it } from "vitest";
import { classifyPath } from "../effect-classifier.js";
import { basicContext, type EffectRecord } from "../policy-types.js";
import { instructionFileRule } from "./instruction-file.js";

/**
 * The instruction-file rule had no test file. A deletion probe found 2 of its 12 deletable lines
 * removable with the whole rule layer green, both of them the shape of the hit: the path, and the
 * detail that names which KIND of write it was.
 *
 * The class comes from `classifyPath`, so which names count as instructions stays that module's
 * subject and is not restated here.
 */

const ctx = basicContext(async () => "");

const touch = (path: string, kind: EffectRecord["kind"]): EffectRecord => ({
  path,
  kind,
  effectClass: classifyPath(path),
});

describe("a turn that writes the rules its successor will read", () => {
  it("asks about a modify, naming the file and the kind of write", async () => {
    expect(classifyPath("AGENTS.md")).toBe("instruction-file");
    expect(await instructionFileRule.run([touch("AGENTS.md", "modify")], ctx)).toEqual([{
      rule: "instruction-file-change",
      decision: "review",
      path: "AGENTS.md",
      detail: "modify of an agent instruction file",
    }]);
  });

  it("names create and delete as themselves", async () => {
    const hits = await instructionFileRule.run(
      [touch("CLAUDE.md", "create"), touch("AGENTS.md", "delete")],
      ctx,
    );
    expect(hits.map((h) => [h.path, h.detail])).toEqual([
      ["CLAUDE.md", "create of an agent instruction file"],
      ["AGENTS.md", "delete of an agent instruction file"],
    ]);
  });

  it("says nothing about an ordinary markdown file", async () => {
    expect(await instructionFileRule.run([touch("docs/guide.md", "modify")], ctx)).toEqual([]);
  });
});

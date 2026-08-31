/**
 * What the runner sees when codex runs a command, and what it saw before: nothing.
 *
 * `parseCodexEventLine` handled four shapes (`thread.started`, `item.completed` carrying an
 * `agent_message`, `turn.completed`, and a top-level `error`) and silently dropped everything else.
 * Commands are the everything else. So a turn whose only command was killed at codex's ten second
 * limit produced the same RunnerResult as a turn whose command succeeded: an agent message, a usage
 * block, and no sign that anything went wrong.
 *
 * Every stream these tests read is a real capture from `codex-cli 0.111.0`, the version
 * `Dockerfile.runtime` pins. See `test-fixtures/codex-events/README.md` for how they were taken and
 * for the swept timeout boundary. They are read from disk rather than inlined so that recapturing
 * against a newer codex updates the tests by updating the fixtures.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseCodexEventLine, type ParsedEvents, isFailedCommand } from "./codex-runner.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string[] =>
  readFileSync(path.join(here, "..", "test-fixtures", "codex-events", `${name}.jsonl`), "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0);

/** An empty ParsedEvents, for tests that feed synthetic events rather than a captured fixture. */
function emptyParsed(): ParsedEvents {
  return { messages: [], threadId: null, usage: null, errors: [], commands: [] };
}

function parse(name: string): ParsedEvents {
  const parsed: ParsedEvents = {
    messages: [],
    threadId: null,
    usage: null,
    errors: [],
    commands: [],
  };
  for (const line of fixture(name)) parseCodexEventLine(line, parsed);
  return parsed;
}

describe("codex command events, from real captures", () => {
  it("still reads the shapes it always read, on a turn that ran no command", () => {
    const parsed = parse("message");
    expect(parsed.threadId).toBe("01a050ca-4f25-7f53-9d18-e5895b635bf0");
    expect(parsed.messages.at(-1)).toBe("MOCK-OK turn=1 scenario=message");
    expect(parsed.usage).toEqual({ inputTokens: 42, cachedInputTokens: 0, outputTokens: 17 });
    expect(parsed.commands).toEqual([]);
  });

  it("records a command that succeeded, with its exit code and output", () => {
    const parsed = parse("command");
    expect(parsed.commands).toHaveLength(1);
    const [only] = parsed.commands;
    expect(only.command).toContain("made-by-command.txt");
    expect(only.exitCode).toBe(0);
    expect(only.status).toBe("completed");
    expect(only.aggregatedOutput).toBe("done\n");
    expect(parsed.commands.filter((c) => c.failed)).toEqual([]);
  });

  it("records the command codex gave up on, which is the whole defect", () => {
    const parsed = parse("slow");
    expect(parsed.commands).toHaveLength(1);
    const [killed] = parsed.commands;
    expect(killed.exitCode).toBe(124);
    expect(killed.status).toBe("failed");
    expect(killed.failed).toBe(true);
    // The turn still reported an agent message and a usage block, which is exactly why reading only
    // those two made a killed command invisible.
    expect(parsed.messages.at(-1)).toBe("MOCK-OK turn=2 scenario=slow");
    expect(parsed.usage).not.toBeNull();
  });

  it("records the half-run command, where the effect set is neither empty nor complete", () => {
    const parsed = parse("partial");
    const [killed] = parsed.commands;
    expect(killed.failed).toBe(true);
    expect(killed.exitCode).toBe(124);
    // Its own text is the evidence that work landed before the kill: the first clause wrote a file,
    // the last clause never ran.
    expect(killed.command).toContain("landed.txt");
    expect(killed.command).toContain("finished.txt");
  });

  it("reads an item-level error, which is not the same shape as a top-level error event", () => {
    // Every captured stream carries {"type":"item.completed","item":{"type":"error",...}}, and the
    // parser only ever looked for {"type":"error"} at the top level, so this was dropped too.
    const parsed = parse("message");
    expect(parsed.errors.some((e) => e.includes("Model metadata"))).toBe(true);
  });

  it("ignores a line that is not JSON, and a JSON line that is not an event", () => {
    const parsed: ParsedEvents = { messages: [], threadId: null, usage: null, errors: [], commands: [] };
    expect(() => parseCodexEventLine("not json at all", parsed)).not.toThrow();
    expect(() => parseCodexEventLine("[]", parsed)).not.toThrow();
    expect(() => parseCodexEventLine('{"type":"item.completed"}', parsed)).not.toThrow();
    expect(() => parseCodexEventLine('{"type":"item.started","item":null}', parsed)).not.toThrow();
    expect(parsed.commands).toEqual([]);
    expect(parsed.messages).toEqual([]);
  });

  it("does not count the same command twice when both its events arrive", () => {
    // A command emits item.started and then item.completed with the SAME item id. Counting both
    // would report two commands for one, and would make any per-command figure wrong.
    const parsed = parse("command");
    const started = fixture("command").filter((l) => l.includes('"item.started"')).length;
    expect(started).toBeGreaterThan(0);
    expect(parsed.commands).toHaveLength(1);
  });
});

/**
 * WHAT THIS PARSER STILL DOES NOT SEE, next to the tests rather than in a commit message.
 *
 *   two identical commands in one turn, both WITHOUT an id
 *       merge into one row under the `anonymous:${command}` fallback. Loses a count, never
 *       invents a success. No captured stream lacks an id, so this is defensive only.
 *   a status codex invents that means "fine"
 *       would be read as a failure, because HEALTHY_STATUSES is an allowlist. Noisy rather than
 *       silent, which is the direction to be wrong in for this field.
 *   null status with a zero or absent exit code
 *       not called failed. The one place this still trusts silence, deliberately: it is the shape
 *       an event carries before codex has decided anything.
 *   anything about WHY a command was killed
 *       exit 124 is recorded, the reason is not, because codex does not send one.
 */
describe("a command that did not finish cleanly is recorded as one, whatever word codex used", () => {
  // The old form was `status === "failed" || exit !== 0`, a denylist of one word. Every captured
  // stream says "failed", so none of these was reachable; four captures do not exhaust the
  // vocabulary and the old failure mode was silent.
  for (const status of ["failed", "cancelled", "aborted", "timed_out", "killed", "interrupted"]) {
    it(`treats status ${status} with no exit code as a failure`, () => {
      expect(isFailedCommand(status, null)).toBe(true);
    });
  }

  it("does not call a command still running a failure", () => {
    // The reason this cannot be "anything unknown is a failure": an in-flight command has no exit
    // code yet, and calling it failed would report one on every turn that is still going.
    expect(isFailedCommand("in_progress", null)).toBe(false);
  });

  it("does not call a clean completion a failure", () => {
    expect(isFailedCommand("completed", 0)).toBe(false);
    expect(isFailedCommand("completed", null)).toBe(false);
  });

  it("believes a non-zero exit code even when the status says otherwise", () => {
    expect(isFailedCommand("completed", 1)).toBe(true);
    expect(isFailedCommand(null, 124)).toBe(true);
  });

  it("does not invent a failure from silence", () => {
    expect(isFailedCommand(null, null)).toBe(false);
    expect(isFailedCommand(null, 0)).toBe(false);
  });
});

describe("an event pair with no id is one command, not two", () => {
  it("pairs started with completed when codex sends no item id", () => {
    // `anonymous-${commands.length}` gave the two events different keys because the array grew
    // between them, so one killed command reported commands 2 and commandsFailed 1.
    const parsed = emptyParsed();
    parseCodexEventLine(JSON.stringify({ type: "item.started", item: { type: "command_execution", command: "sleep 45", status: "in_progress" } }), parsed);
    parseCodexEventLine(JSON.stringify({ type: "item.completed", item: { type: "command_execution", command: "sleep 45", exit_code: 124, status: "failed" } }), parsed);
    expect(parsed.commands).toHaveLength(1);
    expect(parsed.commands[0]!.failed).toBe(true);
    expect(parsed.commands[0]!.exitCode).toBe(124);
  });

  it("still keeps two different id-less commands apart", () => {
    const parsed = emptyParsed();
    parseCodexEventLine(JSON.stringify({ type: "item.completed", item: { type: "command_execution", command: "npm test", exit_code: 0, status: "completed" } }), parsed);
    parseCodexEventLine(JSON.stringify({ type: "item.completed", item: { type: "command_execution", command: "npm run build", exit_code: 1, status: "failed" } }), parsed);
    expect(parsed.commands).toHaveLength(2);
    expect(parsed.commands.filter((c) => c.failed)).toHaveLength(1);
  });
});

/**
 * Both runners parse commands, so both must report them.
 *
 * `RunnerResult.commands` is optional on purpose: absent means "this runner cannot see commands" and
 * an empty array means "this turn ran none", and `transactional-runner.ts` reads
 * `result.commands === undefined` to decide whether to journal the command counts at all. So a
 * runner that parses commands and then returns without them writes the first meaning while the
 * second is true, and every command the turn ran, including one codex killed at its ten second
 * limit, is absent from the record with nothing saying so.
 *
 * `codex-runner.ts` did exactly that. It calls `parseCodexEventLine`, which fills `parsed.commands`,
 * and returned `{ output, threadId, usage }`. `container-codex-runner.ts`, the runner the product
 * actually composes, returned commands. The two disagreed and only the unconfined path was wrong,
 * which is why nothing caught it: the shipped path was right.
 *
 * This reads the source rather than driving the runners, because driving them needs a codex binary
 * and a container. That makes it a weaker test than an execution test and it is written as one: it
 * asserts the shape of a return statement, so a runner that satisfies it by other means would still
 * pass. The guard below is the part that matters, and it is the same one `registry-wiring.test.ts`
 * uses: if the scan matches nothing at all, that is a FAILURE rather than a clean sheet, because a
 * regex that has quietly stopped matching looks identical to a codebase with no problem.
 */
describe("every runner that parses commands reports them", () => {
  const RUNNERS = ["codex-runner.ts", "container-codex-runner.ts"];

  for (const file of RUNNERS) {
    it(`${file} returns the commands it parsed`, () => {
      const src = readFileSync(path.join(here, file), "utf8");
      const parses = /parsed\.commands\.push\(|parsed\.commands\[/.test(src) || /commands: parsed\.commands/.test(src);
      expect([file, "parses or forwards commands", parses]).toEqual([file, "parses or forwards commands", true]);
      const returnsThem = /commands:\s*parsed\.commands/.test(src);
      expect([file, "returns them", returnsThem]).toEqual([file, "returns them", true]);
    });
  }

  it("the scan matched something, so a silent regex failure is not a pass", () => {
    const hits = RUNNERS.filter((file) =>
      /commands:\s*parsed\.commands/.test(readFileSync(path.join(here, file), "utf8")),
    );
    expect(hits).toEqual(RUNNERS);
  });
});

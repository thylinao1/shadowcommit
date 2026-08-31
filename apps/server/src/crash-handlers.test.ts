import { describe, expect, it } from "vitest";
import { installCrashHandlers, type CrashOutcome } from "./crash-handlers.js";

/**
 * The question each of these asks is the one that matters for a crash handler: what does the
 * process do when the thing meant to save the evidence is itself broken. A handler that only works
 * when the seal works is not a crash handler.
 */
function harness(seal: () => Promise<void>) {
  const listeners = new Map<string, (error: unknown) => void>();
  const reports: Array<{ reason: string; outcome: CrashOutcome }> = [];
  const exits: number[] = [];
  let pendingTimer: (() => void) | null = null;

  installCrashHandlers({
    seal,
    report: ({ reason, outcome }) => reports.push({ reason, outcome }),
    exit: (code) => exits.push(code),
    on: (event, listener) => listeners.set(event, listener),
    timeoutMs: 50,
    // the timer never fires on its own, so a test that means to hit the timeout has to say so
    setTimer: (fn) => {
      pendingTimer = fn;
      return { clear: () => { pendingTimer = null; } };
    },
  });

  return {
    reports,
    exits,
    raise: (event: "uncaughtException" | "unhandledRejection", error: unknown) => {
      const listener = listeners.get(event);
      if (!listener) throw new Error(`nothing listened for ${event}`);
      listener(error);
    },
    fireTimeout: () => {
      if (!pendingTimer) throw new Error("no seal timer is pending");
      pendingTimer();
    },
    listenedFor: () => [...listeners.keys()].sort(),
  };
}

const settle = () => new Promise((r) => setImmediate(r));

describe("the ledger is sealed when the process dies without being asked to", () => {
  it("listens for both faults that kill a Node process", () => {
    const h = harness(async () => {});
    // unhandledRejection is the one that matters: since Node 15 it terminates by default, and it is
    // the shape almost every real fault in this codebase takes, because nearly everything is async.
    expect(h.listenedFor()).toEqual(["uncaughtException", "unhandledRejection"]);
  });

  for (const reason of ["uncaughtException", "unhandledRejection"] as const) {
    it(`seals the journal and exits non-zero on ${reason}`, async () => {
      let sealed = 0;
      const h = harness(async () => { sealed += 1; });
      h.raise(reason, new Error("boom"));
      await settle();
      expect(sealed).toBe(1);
      expect(h.reports).toEqual([{ reason, outcome: "sealed" }]);
      // It exits. A server that survives an unknown fault while judging commits is worse than one
      // that stops, so this asserts the exit rather than the survival.
      expect(h.exits).toEqual([1]);
    });
  }

  it("still exits when the seal itself fails, and says that it failed", async () => {
    const h = harness(async () => { throw new Error("journal is unwritable"); });
    h.raise("uncaughtException", new Error("boom"));
    await settle();
    expect(h.reports).toEqual([{ reason: "uncaughtException", outcome: "seal-failed" }]);
    expect(h.exits).toEqual([1]);
  });

  it("does not wait forever for a seal that hangs, which would be worse than the crash", async () => {
    // A hung seal turns a crash into a process that never exits and never restarts. The timeout is
    // the whole reason this is not three lines in index.ts.
    const h = harness(() => new Promise<void>(() => {}));
    h.raise("unhandledRejection", new Error("boom"));
    await settle();
    expect(h.exits).toEqual([]);   // nothing has happened yet: the seal is still hanging
    h.fireTimeout();
    await settle();
    expect(h.reports).toEqual([{ reason: "unhandledRejection", outcome: "seal-timeout" }]);
    expect(h.exits).toEqual([1]);
  });

  it("does not restart the seal when a second fault arrives during the first", async () => {
    // A crash inside crash handling is where a retry loop becomes a hang.
    let sealed = 0;
    const h = harness(() => new Promise<void>(() => { sealed += 1; }));
    h.raise("uncaughtException", new Error("first"));
    await settle();
    h.raise("unhandledRejection", new Error("second"));
    await settle();
    expect(sealed).toBe(1);
    expect(h.reports).toEqual([{ reason: "unhandledRejection", outcome: "already-sealing" }]);
    expect(h.exits).toEqual([1]);
  });
});

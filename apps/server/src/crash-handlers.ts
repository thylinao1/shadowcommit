/**
 * What happens to the ledger when the process dies without being asked to.
 *
 * `index.ts` handles SIGTERM and SIGINT, and both run the same shutdown: close the server, then
 * `closeJournal()`, which writes a final checkpoint signing a Merkle root over everything this
 * process wrote and anchors it. Neither `uncaughtException` nor `unhandledRejection` was handled,
 * and since Node 15 an unhandled rejection terminates the process by default. So any unhandled
 * rejection anywhere in a control plane whose entire claim is a tamper-evident record ended that
 * record mid-sentence: no closing checkpoint, no anchor, and the run's tail left unanchored.
 *
 * The journal lock is NOT part of this problem, which is worth stating so nobody fixes it twice.
 * `journal-keys.ts` installs a `process.on("exit")` hook that unlinks every lock this pid holds,
 * and that hook runs on a crash exit too, so a crashed server does not block the next start.
 *
 * Three things this deliberately does NOT do.
 *
 * It does not swallow the crash. The process still exits, and with a non-zero code, because a
 * server that survives an unknown fault while judging commits is worse than one that stops.
 *
 * It does not wait forever. A seal that hangs would turn a crash into a process that never exits
 * and never restarts, which is strictly worse than the crash. The seal races a timeout and the
 * exit happens either way; the timeout is reported rather than hidden.
 *
 * It does not seal twice. A second fault raised while the first is still sealing forces the exit
 * immediately rather than restarting the attempt, because a crash inside crash handling is exactly
 * where a retry loop becomes a hang.
 */

export type CrashOutcome = "sealed" | "seal-failed" | "seal-timeout" | "already-sealing";

export interface CrashHandlerDeps {
  /** the same journal seal the signal path runs */
  seal: () => Promise<void>;
  /** told what happened, always, including when the seal fails */
  report: (event: { reason: "uncaughtException" | "unhandledRejection"; error: unknown; outcome: CrashOutcome }) => void;
  exit: (code: number) => void;
  /** injected so the test drives the real logic rather than a copy of it */
  on: (event: "uncaughtException" | "unhandledRejection", listener: (error: unknown) => void) => void;
  timeoutMs?: number;
  /** injected so a test does not wait in real time */
  setTimer?: (fn: () => void, ms: number) => { clear: () => void };
}

const DEFAULT_SEAL_TIMEOUT_MS = 5000;

export function installCrashHandlers(deps: CrashHandlerDeps): void {
  const timeoutMs = deps.timeoutMs ?? DEFAULT_SEAL_TIMEOUT_MS;
  const setTimer =
    deps.setTimer ??
    ((fn: () => void, ms: number) => {
      const handle = setTimeout(fn, ms);
      // a pending seal timer must not by itself keep the process alive
      handle.unref?.();
      return { clear: () => clearTimeout(handle) };
    });

  let sealing = false;

  const handle = (reason: "uncaughtException" | "unhandledRejection") => async (error: unknown) => {
    if (sealing) {
      deps.report({ reason, error, outcome: "already-sealing" });
      deps.exit(1);
      return;
    }
    sealing = true;

    const outcome = await new Promise<CrashOutcome>((resolve) => {
      const timer = setTimer(() => resolve("seal-timeout"), timeoutMs);
      deps
        .seal()
        .then(() => {
          timer.clear();
          resolve("sealed");
        })
        .catch(() => {
          timer.clear();
          resolve("seal-failed");
        });
    });

    deps.report({ reason, error, outcome });
    deps.exit(1);
  };

  deps.on("uncaughtException", (error) => void handle("uncaughtException")(error));
  deps.on("unhandledRejection", (error) => void handle("unhandledRejection")(error));
}

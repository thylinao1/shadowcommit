import path from "node:path";
import { AgentService } from "./agent-service.js";
import { createApp } from "./app.js";
import { installCrashHandlers } from "./crash-handlers.js";
import { loadConfig, writeCodexConfig } from "./config.js";
import { createRunner } from "./runner-factory.js";
import { JsonStore } from "./store.js";
import { WorkspaceManager } from "./workspace.js";

const config = loadConfig();
await writeCodexConfig(config);

const store = new JsonStore(path.join(config.dataDirectory, "launchpad.json"));
const workspaces = new WorkspaceManager(config.workspaceRoot);

/**
 * The runtime refusal is a decision, not a crash, so it reads like one.
 *
 * `createRunner` refuses to wrap an unconfined runtime, which is correct: a transaction around a
 * host process produces a clean-looking audit trail for something nothing contained. But it threw
 * from module scope, and an unhandled rejection at import time prints a stack trace and a Node
 * banner over the one sentence that says what to do about it. Someone running the documented start
 * command saw a crash and no port, with the remedy buried in the middle of it.
 *
 * Same refusal, same exit code, told properly.
 */
let runner: ReturnType<typeof createRunner>;
try {
  runner = createRunner(config);
} catch (error) {
  const detail = error instanceof Error ? error.message : String(error);
  process.stderr.write(`\nThe Agent Launchpad did not start.\n\n${detail}\n\n`);
  process.stderr.write("Nothing was started and nothing was changed.\n");
  process.exit(1);
}

/**
 * Installed here, as early as the runner exists, rather than after `createApp`. A fault during
 * `service.initialize()` is exactly as fatal to the ledger as one during a turn, and the journal is
 * open from the moment the runner is built.
 *
 * Reported on stderr rather than through `app.log`, because `app` does not exist yet at this point
 * and a crash handler that depends on the thing that may have crashed is not a crash handler.
 */
installCrashHandlers({
  seal: () => runner.closeJournal(),
  report: ({ reason, error, outcome }) => {
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    const said: Record<string, string> = {
      sealed: "The journal was sealed: the final checkpoint is written and anchored.",
      "seal-failed": "The journal could NOT be sealed. This run's ledger has no closing checkpoint.",
      "seal-timeout": "The journal seal did not finish in time. This run's ledger may have no closing checkpoint.",
      "already-sealing": "A second fault arrived while sealing; exiting without a second attempt.",
    };
    process.stderr.write(`\nThe Agent Launchpad is stopping after an unhandled ${reason}.\n\n${detail}\n\n${said[outcome]}\n\n`);
  },
  exit: (code) => process.exit(code),
  on: (event, listener) => {
    process.on(event, (error: unknown) => listener(error));
  },
});

const service = new AgentService(config, store, workspaces, runner);
await service.initialize();

const app = await createApp(config, service, runner);

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "Shutting down");
  await app.close();
  // Seal the ledger: a final checkpoint signs a Merkle root over everything this process wrote, it
  // is anchored, and the journal lock is released so the next process starts cleanly.
  await runner.closeJournal().catch((error: unknown) => app.log.error({ error }, "journal shutdown failed"));
  process.exit(0);
};

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

await app.listen({ host: config.host, port: config.port });

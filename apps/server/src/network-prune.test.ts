import { describe, it, expect } from "vitest";
import { NetworkSealer } from "./network-sealer.js";

/**
 * Two instances on one host must not delete each other's live turns.
 *
 * The prune used to remove every `shadow-` network it could see, on the reasoning that docker
 * refuses to remove a network with active endpoints. That holds only after a container attaches;
 * between `network create` and the broker joining, the network has no endpoints and is removable.
 * These tests pin the age rule that closes the gap, without needing a real engine.
 */
type Run = (args: string[]) => Promise<{ stdout: string; stderr: string }>;

const sealerWith = (run: Run): NetworkSealer => {
  const sealer = Object.create(NetworkSealer.prototype) as NetworkSealer;
  (sealer as unknown as { run: Run }).run = run;
  return sealer;
};

const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

describe("pruning a leaked network never takes a live one", () => {
  it("leaves a network that is young enough to still be attaching", async () => {
    const removed: string[] = [];
    const sealer = sealerWith(async (args) => {
      if (args[0] === "network" && args[1] === "ls") return { stdout: "shadow-young\n", stderr: "" };
      if (args[0] === "network" && args[1] === "inspect") return { stdout: iso(5_000), stderr: "" };
      if (args[0] === "network" && args[1] === "rm") { removed.push(String(args[2])); return { stdout: "", stderr: "" }; }
      return { stdout: "", stderr: "" };
    });
    await expect(sealer.pruneStale()).resolves.toBe(0);
    expect(removed).toEqual([]);
  });

  it("removes one that is older than the grace window", async () => {
    const removed: string[] = [];
    const sealer = sealerWith(async (args) => {
      if (args[0] === "network" && args[1] === "ls") return { stdout: "shadow-old\n", stderr: "" };
      if (args[0] === "network" && args[1] === "inspect") return { stdout: iso(10 * 60_000), stderr: "" };
      if (args[0] === "network" && args[1] === "rm") { removed.push(String(args[2])); return { stdout: "", stderr: "" }; }
      return { stdout: "", stderr: "" };
    });
    await expect(sealer.pruneStale()).resolves.toBe(1);
    expect(removed).toEqual(["shadow-old"]);
  });

  it("leaves a network whose age it cannot read, because unreadable is not proof of staleness", async () => {
    const removed: string[] = [];
    const sealer = sealerWith(async (args) => {
      if (args[0] === "network" && args[1] === "ls") return { stdout: "shadow-unknown\n", stderr: "" };
      if (args[0] === "network" && args[1] === "inspect") throw new Error("no such network");
      if (args[0] === "network" && args[1] === "rm") { removed.push(String(args[2])); return { stdout: "", stderr: "" }; }
      return { stdout: "", stderr: "" };
    });
    await expect(sealer.pruneStale()).resolves.toBe(0);
    expect(removed).toEqual([]);
  });

  it("sorts a mixed list correctly, taking only the old one", async () => {
    const removed: string[] = [];
    const ages: Record<string, number> = { "shadow-a": 1_000, "shadow-b": 20 * 60_000, "shadow-c": 30_000 };
    const sealer = sealerWith(async (args) => {
      if (args[0] === "network" && args[1] === "ls") return { stdout: "shadow-a\nshadow-b\nshadow-c\n", stderr: "" };
      if (args[0] === "network" && args[1] === "inspect") return { stdout: iso(ages[String(args[2])] ?? 0), stderr: "" };
      if (args[0] === "network" && args[1] === "rm") { removed.push(String(args[2])); return { stdout: "", stderr: "" }; }
      return { stdout: "", stderr: "" };
    });
    await expect(sealer.pruneStale()).resolves.toBe(1);
    expect(removed).toEqual(["shadow-b"]);
  });
});

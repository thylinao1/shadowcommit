import { access, readFile, writeFile } from "node:fs/promises";
import process from "node:process";

const forbiddenEnvironmentNames = Object.keys(process.env).filter((name) =>
  /(ARK|AWS|GITHUB|GH_|TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY)/i.test(name),
);
if (forbiddenEnvironmentNames.length) {
  throw new Error(`credential-shaped environment names present: ${forbiddenEnvironmentNames.join(",")}`);
}

async function mustReject(label, operation) {
  try {
    await operation();
  } catch {
    return;
  }
  throw new Error(`${label} was unexpectedly allowed`);
}

await mustReject("trusted-test mutation", () =>
  writeFile("/trusted-tests/.mutation", "blocked"),
);
await mustReject("shadow-code mutation", () => writeFile("/workspace/.mutation", "blocked"));
await mustReject("public network", async () => {
  await fetch("https://example.com/", {
    method: "HEAD",
    signal: AbortSignal.timeout(2_000),
  });
});
await mustReject("container engine socket", () => access("/var/run/docker" + ".sock"));

const target = JSON.parse(await readFile("/workspace/oracle-target.json", "utf8"));
if (target.ok !== true) throw new Error("shadow-code functional assertion failed");

await writeFile("/tmp/oracle-scratch", "allowed");
process.stdout.write("oracle-pass\n");

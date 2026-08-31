import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

/**
 * Two gates in this repository reported success for work that did not happen.
 *
 * The `sealer-root` CI job grepped its log for a banner vitest never prints, so a run where every
 * real-mount case skipped fell through to the job's success echo. evidence-boundary.sh derived
 * "blocked" from a non-zero exit code alone, so a probe that never opened a socket, or never
 * started, was recorded as proof that the boundary held.
 *
 * Both are absence of evidence written down as evidence of absence. These tests pin the
 * distinction each gate now has to make: ran-and-was-blocked is not did-not-run.
 */

// --------------------------------------------------------------------------------------------
// harness: run one workflow step, or one function out of the evidence script, against stub tools
// --------------------------------------------------------------------------------------------

/** Lift a `run: |` block out of check.yml by indentation. No YAML parser is available here. */
async function workflowStep(stepName: string): Promise<string> {
  const text = await fs.readFile(path.join(repoRoot, ".github/workflows/check.yml"), "utf8");
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l.includes(`- name: ${stepName}`));
  // a harness that silently extracts nothing is the same defect these tests exist to close
  expect(start, `no step named ${stepName} in check.yml`).toBeGreaterThanOrEqual(0);
  const runAt = lines.findIndex((l, i) => i > start && /^\s*run:\s*\|\s*$/.test(l));
  expect(runAt, `step ${stepName} has no block run:`).toBeGreaterThan(start);
  const indent = (lines[runAt].match(/^\s*/) ?? [""])[0].length + 2;
  const body: string[] = [];
  for (let i = runAt + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === "") { body.push(""); continue; }
    if ((line.match(/^\s*/) ?? [""])[0].length < indent) break;
    body.push(line.slice(indent));
  }
  const script = body.join("\n").trimEnd();
  expect(script.length, `extracted an empty script for ${stepName}`).toBeGreaterThan(40);
  return script;
}

type Shell = { code: number; stdout: string; stderr: string };

/**
 * GitHub runs a `run:` block as `bash -e {0}`, so a failing command aborts the step.
 *
 * shellArgs is how a test asks for the step WITHOUT -e. That is not a fiction about GitHub: it is
 * the only way to tell a guard the step performs from an abort the shell performs for it. A safety
 * claim carried entirely by an option set outside the step is a claim the step does not make.
 */
async function runStep(script: string, env: Record<string, string>, cwd: string, shellArgs: string[] = ["-e"]): Promise<Shell> {
  const file = path.join(cwd, "step.sh");
  await fs.writeFile(file, script);
  try {
    const r = await execFileAsync("bash", [...shellArgs, file], {
      cwd: repoRoot,
      env: { ...process.env, ...env },
      maxBuffer: 8 * 1024 * 1024,
    });
    return { code: 0, stdout: r.stdout, stderr: r.stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: typeof err.code === "number" ? err.code : 1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}

async function shim(dir: string, name: string, body: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
  const p = path.join(dir, name);
  await fs.writeFile(p, `#!/bin/sh\n${body}\n`);
  await fs.chmod(p, 0o755);
}

/** sudo's own options are dropped and the rest is executed, which is all this step needs of it. */
const SUDO_SHIM = `while [ $# -gt 0 ]; do case "$1" in -*) shift ;; *) break ;; esac; done
exec "$@"`;

/**
 * Stands in for `npx vitest run ... --reporter=json --outputFile=X`. FAKE_VITEST_REPORT names the
 * report to write; leaving it unset is a vitest that produced none.
 */
const NPX_SHIM = `out=""
for a in "$@"; do case "$a" in --outputFile=*) out="\${a#--outputFile=}" ;; esac; done
echo " RUN  v4.1.10 (stub)"
echo "\${FAKE_VITEST_SUMMARY:-      Tests  14 passed | 3 skipped (17)}"
if [ -n "\${FAKE_VITEST_REPORT:-}" ] && [ -n "$out" ]; then cp "$FAKE_VITEST_REPORT" "$out"; fi
exit "\${FAKE_VITEST_EXIT:-0}"`;

type Assertion = { status: string; fullName: string };
function vitestReport(assertions: Assertion[]): string {
  const count = (s: string) => assertions.filter((a) => a.status === s).length;
  return JSON.stringify({
    numTotalTestSuites: 1,
    numTotalTests: assertions.length,
    numPassedTests: count("passed"),
    numFailedTests: count("failed"),
    numPendingTests: count("skipped"),
    numTodoTests: count("todo"),
    success: count("failed") === 0,
    testResults: [{ name: "apps/server/src/overlay-sealer.test.ts", status: "passed", assertionResults: assertions }],
  });
}

const MOUNT_CASES = [
  "the composition gate refuses overlay while no release hook is wired, even where overlay works",
  "overlay on a host that can mount mounts, proves, unmounts and never deletes through the mount",
  "overlay on a host that can mount sweeps a mount left behind by a crashed turn",
];
const PLAIN_CASES = [
  "mount option safety rejects the characters that change what a mount means",
  "the mount proof proves an ordinary directory carries no mount",
];

const skippedRun = () =>
  vitestReport([
    ...PLAIN_CASES.map((fullName) => ({ status: "passed", fullName })),
    ...MOUNT_CASES.map((fullName) => ({ status: "skipped", fullName })),
  ]);
const fullRun = () =>
  vitestReport([...PLAIN_CASES, ...MOUNT_CASES].map((fullName) => ({ status: "passed", fullName })));

async function sealerHarness(): Promise<{ dir: string; env: Record<string, string>; summary: string }> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "gate-sealer-"));
  const bin = path.join(dir, "bin");
  await shim(bin, "sudo", SUDO_SHIM);
  await shim(bin, "npx", NPX_SHIM);
  const summary = path.join(dir, "summary.md");
  await fs.writeFile(summary, "");
  return {
    dir,
    summary,
    env: {
      PATH: `${bin}:${process.env.PATH ?? ""}`,
      GITHUB_STEP_SUMMARY: summary,
      RUNNER_TEMP: dir,
      FAKE_VITEST_REPORT: "",
      FAKE_VITEST_EXIT: "0",
    },
  };
}

// --------------------------------------------------------------------------------------------
describe("the sealer-root job fails when the mount cases did not run", () => {
  const STEP = "overlay sealer as root, and prove the mount cases ran rather than skipped";

  it("fails a run where every real-mount case skipped", async () => {
    const script = await workflowStep(STEP);
    const h = await sealerHarness();
    const report = path.join(h.dir, "skipped.json");
    await fs.writeFile(report, skippedRun());

    const r = await runStep(script, { ...h.env, FAKE_VITEST_REPORT: report }, h.dir);
    expect(r.code, `step exited 0 on a skipped run\n${r.stdout}\n${r.stderr}`).not.toBe(0);
    expect(`${r.stdout}${r.stderr}${await fs.readFile(h.summary, "utf8")}`).toMatch(/skip/i);
  });

  it("fails a run that produced no machine-readable report at all", async () => {
    const script = await workflowStep(STEP);
    const h = await sealerHarness();
    const r = await runStep(script, h.env, h.dir);
    expect(r.code, `step exited 0 with no report to read\n${r.stdout}\n${r.stderr}`).not.toBe(0);
  });

  it("fails a run that collected no tests, which is a suite that quietly did nothing", async () => {
    const script = await workflowStep(STEP);
    const h = await sealerHarness();
    const report = path.join(h.dir, "empty.json");
    await fs.writeFile(report, vitestReport([]));
    const r = await runStep(script, { ...h.env, FAKE_VITEST_REPORT: report }, h.dir);
    expect(r.code, `step exited 0 on a suite that collected nothing\n${r.stdout}`).not.toBe(0);
  });

  // the negative case: ordinary work still passes, and the gate says which cases it saw
  it("passes a run where the mount cases executed, and names them in the summary", async () => {
    const script = await workflowStep(STEP);
    const h = await sealerHarness();
    const report = path.join(h.dir, "full.json");
    await fs.writeFile(report, fullRun());

    const r = await runStep(script, { ...h.env, FAKE_VITEST_REPORT: report }, h.dir);
    expect(r.code, `step failed on a good run\n${r.stdout}\n${r.stderr}`).toBe(0);
    expect(await fs.readFile(h.summary, "utf8")).toContain("overlay on a host that can mount");
  });

  /**
   * This test passed with the entire change reverted, and it proved nothing about it.
   *
   * It set a green report and a red vitest and asserted the step failed. The step did fail, at the
   * npx line, because `bash -e` aborts on a failing command and `-e` is in the harness, not in the
   * step. Both halves of the name were unexercised: nothing stale was ever planted, and no guard of
   * the step's own was ever reached.
   *
   * Both halves are driven now, and neither leans on the shell. The step runs WITHOUT -e, so only
   * something the step itself checks can fail it.
   */
  it("still fails when vitest itself is red, rather than reading a stale report", async () => {
    const script = await workflowStep(STEP);
    const h = await sealerHarness();
    // a green report from an earlier run, sitting at the exact path this step reads
    await fs.writeFile(path.join(h.dir, "sealer.json"), fullRun());
    const report = path.join(h.dir, "full.json");
    await fs.writeFile(report, fullRun());

    const r = await runStep(script, { ...h.env, FAKE_VITEST_REPORT: report, FAKE_VITEST_EXIT: "1" }, h.dir, []);
    const said = `${r.stdout}${r.stderr}${await fs.readFile(h.summary, "utf8")}`;
    expect(
      r.code,
      `with the shell no longer aborting the step, a red vitest was rescued by a green report\n${said}`,
    ).not.toBe(0);
    expect(said, "the step failed without ever saying that vitest was red").toMatch(/vitest exited 1/);
    expect(said, "the step reported a green report as this run's own result").not.toMatch(
      /overlay mount cases executed as root/,
    );
  });

  // The other half of the same name. The step clears the report path before it runs anything, so a
  // report an earlier run left there cannot answer for this one. Delete that line and this passes on
  // a run that produced no report at all.
  it("does not read a report an earlier run left at the path it writes to", async () => {
    const script = await workflowStep(STEP);
    const h = await sealerHarness();
    await fs.writeFile(path.join(h.dir, "sealer.json"), fullRun());
    // vitest is green this time and writes nothing, so the only report on disk is the stale one
    const r = await runStep(script, { ...h.env, FAKE_VITEST_REPORT: "", FAKE_VITEST_EXIT: "0" }, h.dir, []);
    const said = `${r.stdout}${r.stderr}${await fs.readFile(h.summary, "utf8")}`;
    expect(r.code, `the step passed on a report this run did not produce\n${said}`).not.toBe(0);
    expect(said, "the step did not notice that this run wrote no report").toMatch(/wrote no JSON report/);
  });
});

// --------------------------------------------------------------------------------------------
// evidence-boundary.sh: a probe that did not run is not a boundary that held
// --------------------------------------------------------------------------------------------

/**
 * Stands in for the container engine. Every mode answers the same command set; what changes is
 * whether the egress probe starts, what nc reports, and whether the mid-write probe container ever
 * comes up. FAKE_DOCKER_MODE picks one.
 */
const DOCKER_SHIM = `
args="$*"
case "$1" in
  version) echo "29.0.0-stub"; exit 0 ;;
  info) echo 2; exit 0 ;;
  network)
    case "$2" in
      create) echo "stubnet"; exit 0 ;;
      inspect) echo "0123456789abcdef0123456789abcdef"; exit 0 ;;
      *) exit 0 ;;
    esac ;;
  inspect) echo "\${FAKE_DOCKER_RUNNING:-true}"; exit 0 ;;
  kill|rm|stop) exit 0 ;;
  run) : ;;
  *) exit 0 ;;
esac

# the long-running mid-write probe: docker run -d ... -v <host dir>:/workspace ...
case "$args" in
  *"while true"*)
    if [ "\${FAKE_DOCKER_MODE:-refused}" = "no-mid-write-container" ]; then
      echo "Unable to find image '$EVIDENCE_IMAGE' locally" >&2
      exit 125
    fi
    mount=""
    prev=""
    for a in "$@"; do
      if [ "$prev" = "-v" ]; then mount="\${a%%:*}"; fi
      prev="$a"
    done
    # full-write: the kill lands between iterations, so the 64 MiB write completed
    bs=1024; count=17
    case "\${FAKE_DOCKER_MODE:-refused}" in full-write) bs=1048576; count=64 ;; esac
    if [ -n "$mount" ] && [ -d "$mount" ]; then
      dd if=/dev/zero of="$mount/big.bin" bs=$bs count=$count 2>/dev/null
    fi
    # hostile-write: a container that writes into every workspace-shaped host path it is handed,
    # which is what a leaked bind mount looks like from the inside. Guarded on keep.txt so the
    # stub can only ever touch a directory this script itself built.
    if [ "\${FAKE_DOCKER_MODE:-refused}" = "hostile-write" ]; then
      for p in $(printf '%s\n' "$args" | grep -oE "/[A-Za-z0-9._/-]+" | sort -u); do
        if [ -f "$p/keep.txt" ] && [ "$p" != "$mount" ]; then
          dd if=/dev/zero of="$p/big.bin" bs=1024 count=4 2>/dev/null
          printf clobbered > "$p/keep.txt" 2>/dev/null
        fi
      done
    fi
    echo "cafefeed0001"
    exit 0 ;;
esac

case "$args" in
  *"memory.max"*) echo 67108864; exit 0 ;;
  *"pids.max"*) echo 16; exit 0 ;;
  *"dd if=/dev/zero"*)
    case "$args" in *"--memory=64m"*) exit 137 ;; *) exit 0 ;; esac ;;
esac

# every remaining run is a network probe: nc, or nslookup
probe_tool=nc
case "$args" in *nslookup*) probe_tool=nslookup ;; esac

case "\${FAKE_DOCKER_MODE:-refused}" in
  no-start)
    echo "Unable to find image '$EVIDENCE_IMAGE' locally" >&2
    exit 125 ;;
  tool-missing)
    # the container starts, so the start sentinel is printed, but the image has no probe tool
    echo "SHADOW-PROBE-STARTED"
    echo "sh: $probe_tool: not found"
    echo "rc=127"
    exit 0 ;;
  dns-answers)
    # busybox nslookup against a resolver that ANSWERS, at its real length. The ports stay refused
    # so this mode isolates the one row that changed.
    echo "SHADOW-PROBE-STARTED"
    case "$args" in
      *nslookup*)
        echo "SHADOW-TOOL-PRESENT"
        echo "Server:    10.0.0.1"
        echo "Address:   10.0.0.1:53"
        echo ""
        echo "Non-authoritative answer:"
        echo "Name:      example.com"
        echo "Address:   93.184.216.34"
        echo "rc=0"
        exit 0 ;;
    esac
    echo "SHADOW-TOOL-PRESENT"
    echo "rc=1"
    exit 0 ;;
  name-unresolved)
    echo "SHADOW-PROBE-STARTED"
    echo "SHADOW-TOOL-PRESENT"
    echo "nc: bad address 'github.com'"
    echo "rc=1"
    exit 0 ;;
  no-tool-sentinel)
    # The container started and printed an rc, and the rc is 1, not 126 or 127. Only the tool
    # sentinel rule can catch this one: rc= alone is exactly what the retired standard asked for.
    echo "SHADOW-PROBE-STARTED"
    echo "sh: $probe_tool: not found"
    echo "rc=1"
    exit 0 ;;
  cut-short)
    # A probe killed by a signal (128+N, so 137 is SIGKILL) or cut off by timeout (124). Neither is
    # a result about the target, and neither is a refusal.
    echo "SHADOW-PROBE-STARTED"
    echo "SHADOW-TOOL-PRESENT"
    echo "rc=\${FAKE_CUT_RC:-137}"
    exit 0 ;;
  control-bytes)
    # Probe output with bytes JSON has no literal spelling for. The run still has to write an
    # artefact something can parse.
    echo "SHADOW-PROBE-STARTED"
    echo "SHADOW-TOOL-PRESENT"
    printf 'nc: \\001\\033[31mred\\033[0m "quoted" back\\\\\\\\slash\\r\\n'
    echo "rc=1"
    exit 0 ;;
  reached)
    echo "SHADOW-PROBE-STARTED"
    echo "SHADOW-TOOL-PRESENT"
    echo "rc=0"
    exit 0 ;;
  *)
    echo "SHADOW-PROBE-STARTED"
    echo "SHADOW-TOOL-PRESENT"
    case "$args" in
      *nslookup*) echo "nslookup: write to '10.0.0.1': Connection refused" ;;
    esac
    echo "rc=1"
    exit 0 ;;
esac
`;

/**
 * Stands in for tcpdump. It writes a capture and reads two packets back, so check 3 is measured in
 * the harness.
 *
 * FAKE_TCPDUMP_CAPTURE=no is the shape that made the defect reachable on a real host: a binary that
 * cannot open the interface, so no capture of this run ever starts, but that will read back any
 * file it is handed. That is every macOS and every nested-virtualisation host in this repository's
 * own README, and it is what the committed artefact's own note describes.
 */
const TCPDUMP_SHIM = `case "$1" in
  -r) echo "12:00:00.100000 IP 172.18.0.2.44002 > 1.2.3.4.443: Flags [S]"
      echo "12:00:00.200000 IP 172.18.0.2.44003 > 8.8.8.8.53: Flags [S]"
      exit 0 ;;
esac
if [ "\${FAKE_TCPDUMP_CAPTURE:-yes}" != yes ]; then
  echo "tcpdump: no such device exists" >&2
  exit 1
fi
out=""; prev=""
for a in "$@"; do if [ "$prev" = "-w" ]; then out="$a"; fi; prev="$a"; done
if [ -n "$out" ]; then printf 'THIS-RUN-CAPTURE\n' > "$out"; fi
exec sleep 30
`;

type Boundary = {
  host?: Record<string, string>;
  measuredEverything?: boolean;
  verdict?: string;
  checks: Array<Record<string, unknown>>;
};

/** The capture path the script publishes to, and the path check 3 used to read back. */
const PUBLISHED_CAPTURE = "pcap-egress-denied.pcapng";

/**
 * Copy the script to a scratch directory and run it there. HERE, and so the output it writes,
 * follows the copy, which keeps the committed artefact out of reach of the tests.
 *
 * `plantCapture` puts a file at the published capture path BEFORE the run, which is how evidence/
 * actually looks on a fresh clone: `git ls-files evidence/ | grep -i pcap` names that file. Leaving
 * it out of this harness is why the defect it enabled went unseen for a whole round.
 */
async function runEvidence(
  mode: string,
  extra: Record<string, string> = {},
  plantCapture?: string,
): Promise<{ shell: Shell; json: Boundary; raw: string; dir: string }> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "gate-evidence-"));
  const bin = path.join(dir, "bin");
  const script = path.join(dir, "evidence-boundary.sh");
  await fs.copyFile(path.join(repoRoot, "evidence/evidence-boundary.sh"), script);
  await shim(bin, "docker", DOCKER_SHIM);
  await shim(bin, "tcpdump", TCPDUMP_SHIM);
  if (plantCapture !== undefined) await fs.writeFile(path.join(dir, PUBLISHED_CAPTURE), plantCapture);

  const file = path.join(dir, "drive.sh");
  await fs.writeFile(file, `bash "${script}"\n`);
  const env = {
    ...process.env,
    ...extra,
    PATH: `${bin}:${process.env.PATH ?? ""}`,
    FAKE_DOCKER_MODE: mode,
    EVIDENCE_IMAGE: "stub-image:0",
    TCPDUMP: extra.TCPDUMP ?? path.join(bin, "tcpdump"),
  } as Record<string, string>;

  let shell: Shell;
  try {
    const r = await execFileAsync("bash", [file], { env, cwd: dir, maxBuffer: 8 * 1024 * 1024 });
    shell = { code: 0, stdout: r.stdout, stderr: r.stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    shell = { code: typeof err.code === "number" ? err.code : 1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
  const raw = await fs.readFile(path.join(dir, "boundary.json"), "utf8");
  return { shell, json: JSON.parse(raw) as Boundary, raw, dir };
}

/**
 * Run the classify() the script actually ships, over one probe's recorded output.
 *
 * The committed artefact and the code had drifted apart on what `measured` means, with nothing
 * checking that they agree. A second implementation of the rule here would drift as well, so the
 * rule is lifted out of the script and executed.
 */
async function shippedClassify(detail: string): Promise<{ measured: string; verdict: string }> {
  const script = await fs.readFile(path.join(repoRoot, "evidence/evidence-boundary.sh"), "utf8");
  const sentinel = /^SENTINEL="([^"]+)"/m.exec(script)?.[1];
  const toolSentinel = /^TOOL_SENTINEL="([^"]+)"/m.exec(script)?.[1];
  expect(sentinel, "no SENTINEL assignment in evidence-boundary.sh").toBeTruthy();
  expect(toolSentinel, "no TOOL_SENTINEL assignment in evidence-boundary.sh").toBeTruthy();
  const start = script.indexOf("\nclassify() {");
  expect(start, "no classify() in evidence-boundary.sh").toBeGreaterThan(0);
  const end = script.indexOf("\n}\n", start);
  expect(end, "classify() has no closing brace of its own").toBeGreaterThan(start);
  const body = script.slice(start + 1, end + 3);

  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "gate-classify-"));
  const file = path.join(dir, "classify.sh");
  await fs.writeFile(
    file,
    `SENTINEL="${sentinel}"\nTOOL_SENTINEL="${toolSentinel}"\n${body}\n` +
      `classify "$1"\nprintf '%s %s\\n' "$PROBE_MEASURED" "$PROBE_VERDICT"\n`,
  );
  const r = await execFileAsync("bash", [file, detail], { maxBuffer: 1024 * 1024 });
  const [measured, verdict] = r.stdout.trim().split(" ");
  return { measured, verdict };
}

const egressRows = (b: Boundary) => b.checks.filter((c) => c.check === "egress");

describe("evidence-boundary.sh separates a boundary that held from a probe that never ran", () => {
  it("records a probe that could not start as not measured, never as blocked", async () => {
    const { shell, json, raw } = await runEvidence("no-start");
    const rows = egressRows(json);
    expect(rows.length, "no egress rows were recorded at all").toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.measured, `row ${row.target} has no measured verdict: ${JSON.stringify(row)}`).toBe(false);
      expect(row.blocked, `row ${row.target} claims blocked on a probe that never started`).not.toBe(true);
    }
    expect(shell.code, `the script reported success for a run that measured nothing\n${raw}`).not.toBe(0);
    expect(json.measuredEverything, "the artefact does not say it is incomplete").toBe(false);
    expect(json.verdict, "a run that measured nothing must not carry a passing verdict").toBe("incomplete");
  }, 30_000);

  // A row with a port claims something about that port. The dns row has no port: for DNS itself a
  // name that did not resolve IS the measurement, which is why it is the one row exempt here.
  it("does not turn a name that never resolved into a blocked port", async () => {
    const { json } = await runEvidence("name-unresolved");
    const portRows = egressRows(json).filter((r) => r.port !== undefined);
    expect(portRows.length, "no port rows to check").toBeGreaterThan(0);
    for (const row of portRows) {
      const detail = String(row.detail ?? "");
      if (/bad address|not resolve/i.test(detail)) {
        expect(row.blocked, `a name that never resolved was recorded as a blocked port: ${JSON.stringify(row)}`).not.toBe(true);
        expect(row.measured, `and it was not flagged as unmeasured: ${JSON.stringify(row)}`).toBe(false);
      }
    }
  }, 30_000);

  it("does not record the real workspace as untouched when the probe container never came up", async () => {
    const { json } = await runEvidence("no-mid-write-container");
    const row = json.checks.find((c) => c.check === "kill-mid-write");
    expect(row, "no kill-mid-write row").toBeDefined();
    expect(row?.measured, `kill-mid-write has no measured verdict: ${JSON.stringify(row)}`).toBe(false);
    expect(row?.realWorkspaceUntouched, "a container that never started was recorded as proof the workspace survived").not.toBe(true);
  }, 30_000);

  // the negative case: a boundary that really does hold still records blocked, and the run passes
  it("still records blocked and exits clean when every probe ran and every port was refused", async () => {
    const { shell, json, raw } = await runEvidence("refused");
    const rows = egressRows(json);
    expect(rows.length).toBeGreaterThanOrEqual(4);
    for (const row of rows) {
      expect(row.measured, `row ${row.target} was not measured: ${JSON.stringify(row)}`).toBe(true);
      expect(row.blocked, `row ${row.target} did not record the refusal: ${JSON.stringify(row)}`).toBe(true);
    }
    const mid = json.checks.find((c) => c.check === "kill-mid-write");
    expect(mid?.measured, `kill-mid-write not measured on a good run: ${JSON.stringify(mid)}`).toBe(true);
    expect(mid?.realWorkspaceUntouched).toBe(true);
    expect(mid?.partialInShadow).toBe(true);
    expect(shell.code, `a fully measured, fully blocked run must exit clean\n${raw}`).toBe(0);
    expect(json.verdict).toBe("held");
    expect(json.measuredEverything).toBe(true);
  }, 30_000);

  // The sentinel proves a container started. It does not prove the probe TOOL existed, and an image
  // with no `nc` exits 127 from the shell without ever opening a socket. Recording that as "refused"
  // is the same defect one level down: the gate would vouch for an experiment that did not happen.
  it("records a probe whose tool was missing from the image as not measured, never as blocked", async () => {
    const { shell, json, raw } = await runEvidence("tool-missing");
    const rows = egressRows(json);
    expect(rows.length, "no egress rows were recorded at all").toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.measured, `row ${row.target} claims a measurement on rc=127: ${JSON.stringify(row)}`).toBe(false);
      expect(row.blocked, `row ${row.target} claims blocked on a probe tool that was never there`).not.toBe(true);
    }
    expect(shell.code, `the script reported success for a run where no socket was opened\n${raw}`).not.toBe(0);
    expect(json.verdict, "a run that opened no socket must not carry a passing verdict").toBe("incomplete");
  }, 30_000);

  // The mirror image of the same defect: an escape that really happened, filed as a non-measurement
  // because the probe printed more lines than the reader kept.
  it("records DNS that actually answered as a breach, not as a container that never started", async () => {
    const { shell, json, raw } = await runEvidence("dns-answers");
    const dns = egressRows(json).find((r) => r.target === "dns");
    expect(dns, "no dns row").toBeDefined();
    expect(dns?.measured, `a resolver that answered was recorded as unmeasured: ${JSON.stringify(dns)}`).toBe(true);
    expect(dns?.blocked, `a name that resolved was recorded as blocked: ${JSON.stringify(dns)}`).toBe(false);
    expect(dns?.verdict).toBe("resolved");
    expect(String(dns?.detail ?? ""), "the answer itself is not in the record").toMatch(/93\.184\.216\.34/);
    expect(shell.code, `a run where DNS escaped must not report success\n${raw}`).not.toBe(0);
    expect(json.verdict, "an escape is a breach, not an incomplete run").toBe("breach");
  }, 30_000);

  // realWorkspaceUntouched was true by construction: the probe was never told where the real
  // workspace was, so no container, however hostile, could make the field false. Arm the adversary.
  it("fails when a leaked mount lets the probe write into the real workspace", async () => {
    const { shell, json, raw } = await runEvidence("hostile-write");
    const row = json.checks.find((c) => c.check === "kill-mid-write");
    expect(row, "no kill-mid-write row").toBeDefined();
    expect(
      row?.realWorkspaceUntouched,
      `a container that wrote into the real workspace was still recorded as having spared it. ` +
        `If this is true, nothing the probe can do makes it false: ${JSON.stringify(row)}`,
    ).toBe(false);
    expect(shell.code, `a run where the workspace was written must not report success\n${raw}`).not.toBe(0);
  }, 30_000);

  // A gate that goes red for a race is a gate that gets switched off. Where the bytes landed is the
  // boundary claim; how many of them landed before the kill is a timing outcome.
  it("does not call a completed write a breach, because a finished write is not a leak", async () => {
    const { shell, json, raw } = await runEvidence("full-write");
    const row = json.checks.find((c) => c.check === "kill-mid-write");
    expect(row?.shadowBytes, "the stub did not write the full 64 MiB").toBe(67108864);
    expect(row?.partialInShadow, "the write completed, so this is false and stays recorded").toBe(false);
    expect(row?.realWorkspaceUntouched, "the workspace was still spared").toBe(true);
    expect(shell.code, `a completed write inside the shadow was reported as a boundary failure\n${raw}`).toBe(0);
    expect(json.verdict).toBe("held");
  }, 30_000);

  // The rows named "git protocol" and "ssh" implied a protocol-specific egress policy that nothing
  // here tests: the bridge is --internal, so every one of them measures the same single fact.
  it("does not label a port row with a protocol whose policy nothing here tests", async () => {
    const { json } = await runEvidence("refused");
    const portRows = egressRows(json).filter((r) => r.port !== undefined);
    expect(portRows.length).toBeGreaterThanOrEqual(4);
    for (const row of portRows) {
      expect(
        String(row.target),
        `row ${row.target} names a protocol, which claims a policy this script never probes`,
      ).not.toMatch(/\b(git|ssh|https|ftp|smtp)\b/i);
      expect(
        String(row.note ?? ""),
        `row ${row.target} carries no note saying what it does and does not show`,
      ).not.toBe("");
    }
  }, 30_000);

  it("records egress that got through as not blocked, and fails the run", async () => {
    const { shell, json } = await runEvidence("reached");
    for (const row of egressRows(json)) {
      if (row.measured === true) expect(row.blocked, `${row.target} reached its destination but was recorded blocked`).toBe(false);
    }
    expect(shell.code, "a run where egress escaped must not report success").not.toBe(0);
  }, 30_000);

  /**
   * Moved here from the block that reads the committed file, because it belongs to the script.
   *
   * It used to ask the committed artefact for one thing: an rc= token somewhere in each measured
   * row's detail. That is the standard the script RETIRED. Both rows it passed carry no sentinel at
   * all, and the classify() the script ships answers measured=false for exactly those two details,
   * so the test agreed with the artefact and disagreed with the code, and nothing anywhere noticed.
   *
   * This is the same claim asked of the script. The probe prints rc=1, so the retired standard is
   * satisfied, and rc=1 is neither 126 nor 127, so the backstop does not fire either: only the tool
   * sentinel separates this from a refusal.
   */
  it("grants measured only to egress rows that carry the probe's own output", async () => {
    const { shell, json, raw } = await runEvidence("no-tool-sentinel");
    const rows = egressRows(json);
    expect(rows.length, "no egress rows were recorded at all").toBeGreaterThan(0);
    for (const row of rows) {
      expect(
        String(row.detail ?? ""),
        `row ${row.target} did not even carry rc=, so this run is not exercising the retired standard`,
      ).toMatch(/rc=/);
      expect(
        row.measured,
        `row ${row.target} claims measured on output that never says the probe tool ran: ${JSON.stringify(row)}`,
      ).toBe(false);
      expect(row.blocked, `row ${row.target} claims blocked on a probe that never reported`).not.toBe(true);
    }
    expect(shell.code, `a run where no probe tool ever reported still exited clean\n${raw}`).not.toBe(0);
    expect(json.verdict).toBe("incomplete");
  }, 30_000);

  // classify() sorted rc into ran-and-blocked, ran-and-reached and did-not-run, and put DID NOT
  // FINISH in the first of those: every non-zero rc that was not 126, 127 or a name-resolution
  // message became "refused", blocked true. A probe the kernel killed, or one timeout cut off, is
  // not a boundary that held.
  it.each([
    ["137", "killed by SIGKILL"],
    ["124", "cut off by timeout"],
  ])("does not record a probe %s (%s) as a successful block", async (rc) => {
    const { shell, json, raw } = await runEvidence("cut-short", { FAKE_CUT_RC: rc });
    const rows = egressRows(json);
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.rc, `the stub did not deliver rc=${rc}`).toBe(Number(rc));
      expect(
        row.blocked,
        `a probe that never finished was recorded as a boundary that held: ${JSON.stringify(row)}`,
      ).not.toBe(true);
      expect(row.measured, `row ${row.target} claims a measurement on rc=${rc}`).toBe(false);
      expect(row.verdict, `row ${row.target} does not say the probe failed to finish`).toBe("did-not-finish");
    }
    expect(shell.code, `a run whose probes were all cut short exited clean\n${raw}`).not.toBe(0);
  }, 30_000);

  // json_escape covered backslash, double quote and newline, so one escape sequence or one carriage
  // return in a probe's output produced an artefact no consumer can parse, while the run exited 0.
  it("writes an artefact that parses after a probe printed control bytes", async () => {
    // runEvidence itself JSON.parses the file, so a regression throws here before any assertion
    const { json, raw } = await runEvidence("control-bytes");
    expect(
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(raw),
      "the artefact carries a raw control byte, which JSON has no spelling for",
    ).toBe(false);
    const rows = egressRows(json);
    expect(rows.length).toBeGreaterThan(0);
    // and the bytes are recorded rather than dropped: the detail is still the probe's own output
    expect(String(rows[0].detail ?? ""), "the escape sequence was thrown away instead of escaped").toContain("\u001b[31m");
    expect(String(rows[0].detail ?? "")).toContain('"quoted"');
  }, 30_000);
});

// --------------------------------------------------------------------------------------------
// check 3: a capture this run did not make is not this run's measurement
// --------------------------------------------------------------------------------------------

/**
 * The script computed CAPTURING, whether a capture process of its own was alive, printed it, and
 * never referred to it again. Check 3 asked instead whether a file existed at
 * evidence/pcap-egress-denied.pcapng, which is a question a COMMITTED file answers yes to:
 * `git ls-files evidence/ | grep -i pcap` names it. So on any host that cannot capture, the script
 * opened another machine's capture and reported its packets as this run's measurement, measured
 * true, capturable true, exit 0. With no tcpdump at all it wrote packets:0 and capturable:true,
 * which is the most reassuring reading such a host could give.
 *
 * The harness never saw it because it copies the script somewhere clean, so the capture file that
 * ships with the repository was never in front of the code that read it. It is planted here.
 */
describe("check 3 reports only a capture this run made", () => {
  const COMMITTED = "a capture written on some other machine, committed to this repository\n";

  it("does not read a capture it found where it expected to write one", async () => {
    const { shell, json, raw, dir } = await runEvidence("refused", { FAKE_TCPDUMP_CAPTURE: "no" }, COMMITTED);
    const row = json.checks.find((c) => c.check === "tcpdump");
    expect(row, "no tcpdump row").toBeDefined();
    expect(
      row?.measured,
      `check 3 reported a measurement taken from a capture this run never made: ${JSON.stringify(row)}`,
    ).toBe(false);
    expect(row?.capturable, "a host whose capture never started was recorded as capturable").not.toBe(true);
    expect(row?.packets, "packets were counted out of a file this run did not write").not.toBe(2);
    expect(shell.code, `a run that captured nothing reported success\n${raw}`).not.toBe(0);
    expect(json.verdict, "a run that captured nothing must not carry a passing verdict").toBe("incomplete");
    expect(json.measuredEverything).toBe(false);

    // the file is left exactly as found, and the artefact says out loud that it is sitting there
    expect(await fs.readFile(path.join(dir, PUBLISHED_CAPTURE), "utf8")).toBe(COMMITTED);
    expect(
      String(row?.unreadPublishedCapture ?? ""),
      "the artefact does not name the capture it declined to read, so the trap stays invisible",
    ).toMatch(/pcap-egress-denied\.pcapng/);
  }, 30_000);

  it("does not report a measurement on a host that has no tcpdump at all", async () => {
    const { shell, json } = await runEvidence("refused", { TCPDUMP: "/nonexistent" }, COMMITTED);
    const row = json.checks.find((c) => c.check === "tcpdump");
    expect(row?.measured, `a host with no tcpdump recorded a measurement: ${JSON.stringify(row)}`).toBe(false);
    expect(row?.capturable).not.toBe(true);
    expect(
      row?.packets,
      "packets:0 from a host with no tcpdump is the most reassuring number it could possibly report",
    ).not.toBe(0);
    expect(shell.code, "a host with no tcpdump reported success for check 3").not.toBe(0);
  }, 30_000);

  // the negative case: a capture this run really made is measured, and it replaces what it found
  it("measures the capture it made itself, and publishes it over the one it found", async () => {
    const { shell, json, dir } = await runEvidence("refused", {}, COMMITTED);
    const row = json.checks.find((c) => c.check === "tcpdump");
    expect(row?.measured, `a real capture was not measured: ${JSON.stringify(row)}`).toBe(true);
    expect(row?.capturing, "the row does not record that a capture of this run's was running").toBe(true);
    expect(row?.packets).toBe(2);
    const published = await fs.readFile(path.join(dir, PUBLISHED_CAPTURE), "utf8");
    expect(published, "the run measured its own capture but left the found file in place").not.toBe(COMMITTED);
    expect(published).toContain("THIS-RUN-CAPTURE");
    expect(shell.code, "a fully measured run must exit clean").toBe(0);
  }, 30_000);
});

/**
 * THESE TESTS GUARD THE COMMITTED ARTEFACT, NOT THE FIX.
 *
 * evidence/boundary.json is a hand-marked record of one run on a WSL2 host on 2026-08-29. Reverting
 * evidence-boundary.sh does not touch it, so a test that only reads it passes on a revert for that
 * reason alone and proves nothing about any change to the script. Every name in this block says so.
 *
 * What they can do, and what the block is for, is hold the file and the code to the same meaning of
 * the word "measured". They had already drifted: the artefact granted measured:true to two rows the
 * classify() this repository ships answers measured=false for, and nothing checked that they agree.
 * The rule is not restated here, it is lifted out of the script and run.
 */
describe("the committed artefact, a hand-marked old run, agrees with the classifier the script ships", () => {
  const committed = async () =>
    JSON.parse(await fs.readFile(path.join(repoRoot, "evidence/boundary.json"), "utf8")) as Boundary;

  it("the committed artefact carries no egress row that claims blocked where no socket was opened", async () => {
    const rows = egressRows(await committed()).filter((r) => r.port !== undefined);
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const detail = String(row.detail ?? "");
      if (!/bad address|not resolve/i.test(detail)) continue;
      expect(
        row.blocked,
        `committed row ${row.target} reports a blocked port on a name-resolution failure: ${JSON.stringify(row)}`,
      ).not.toBe(true);
      // and the shipped classifier is asked, rather than this test deciding for itself
      const { verdict } = await shippedClassify(detail);
      expect(
        ["name-unresolved", "not-measured", "tool-missing", "did-not-finish"],
        `the classifier calls ${row.target} "${verdict}", which is a result about the port after all`,
      ).toContain(verdict);
    }
  });

  /**
   * The replacement for a test that asked the artefact only for an rc= token in each measured row's
   * detail. That is the standard the script retired: it passed the two rows the shipped classify()
   * calls measured=false, verdict=not-measured, because neither carries a sentinel. The test agreed
   * with the file and disagreed with the code, and it was the only thing looking.
   *
   * The claim the script makes about the artefact is asked of the script itself, in the block above.
   */
  it("the committed artefact records, for every egress row, the measured the shipped classify() gives its detail", async () => {
    const rows = egressRows(await committed());
    expect(rows.length).toBeGreaterThan(0);
    let classified = 0;
    for (const row of rows) {
      if (row.detail === undefined) {
        expect(
          row.measured,
          `committed row ${row.target} claims measured while carrying no probe output at all: ${JSON.stringify(row)}`,
        ).not.toBe(true);
        continue;
      }
      const { measured } = await shippedClassify(String(row.detail));
      classified += 1;
      expect(
        String(row.measured),
        `committed row ${row.target} records measured=${row.measured}, and the classify() this ` +
          `repository ships answers ${measured} for that row's own detail. The artefact and the code ` +
          `disagree about what the word means: ${JSON.stringify(row)}`,
      ).toBe(measured);
    }
    expect(classified, "no committed row carried a detail for the classifier to read").toBeGreaterThan(0);
  });

  /**
   * Schema drift is the same fault in a smaller place: a consumer reading `verdict` off the file
   * gets undefined and is left to assume.
   *
   * The keys come from a run, not from a regex over the script's writer. A regex agrees with the
   * writer by construction, so it stops asking anything the moment the writer changes.
   */
  it("the committed artefact carries every top-level field a real run writes, and no undeclared extras", async () => {
    const parsed = (await committed()) as unknown as Record<string, unknown>;
    const { json: fresh } = await runEvidence("refused");
    const written = Object.keys(fresh as unknown as Record<string, unknown>);
    expect(written.length, "a run wrote almost no top-level keys, so this check is asking nothing").toBeGreaterThanOrEqual(4);
    for (const key of written) {
      expect(
        Object.prototype.hasOwnProperty.call(parsed, key),
        `a run of the script writes "${key}" and the committed artefact has no such field`,
      ).toBe(true);
    }
    // and the other direction, so a field can never be quietly added to the file alone
    const PROVENANCE = new Set(["generatedBy", "note"]);
    for (const key of Object.keys(parsed)) {
      if (written.includes(key)) continue;
      expect(
        PROVENANCE.has(key),
        `the committed artefact carries "${key}", which no run writes and which is not declared provenance`,
      ).toBe(true);
    }
  }, 30_000);

  // This file records a run on a machine that is not the one anybody reading it is sitting at. A row
  // that does not say which machine, and when, invites the reader to assume it was this one.
  it("the committed artefact says of every check whether it was measured, and on what host and date", async () => {
    const parsed = await committed();
    expect(parsed.checks.length).toBeGreaterThan(0);
    for (const row of parsed.checks) {
      const where = JSON.stringify(row).slice(0, 90);
      expect(typeof row.measured, `check ${where} carries no measured verdict`).toBe("boolean");
      expect(
        String(row.producedOn ?? ""),
        `check ${where} does not say what host and date produced it, and no row in this file was produced on the host reading it`,
      ).toMatch(/^.+, \d{4}-\d{2}-\d{2}$/);
    }
  });

  // the script-side twin, which a revert of evidence-boundary.sh does reach
  it("and a real run of the script writes a measured verdict on every check it records", async () => {
    const { json } = await runEvidence("refused");
    expect(json.checks.length).toBeGreaterThan(0);
    for (const row of json.checks) {
      expect(
        typeof row.measured,
        `a run recorded ${JSON.stringify(row).slice(0, 90)} with no measured verdict`,
      ).toBe("boolean");
    }
  }, 30_000);
});

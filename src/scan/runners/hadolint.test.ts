import { describe, expect, test } from "bun:test";
import type { DetectedFact, StackProfile } from "../../contracts/profile.ts";
import { createFileSystem } from "../../ports/file-system.ts";
import { createStubProcessExecutor } from "../../ports/process-executor.ts";
import type { RunnerContext, RunnerFileSystem } from "./_runner-support.ts";
import {
  HADOLINT_STEP,
  type HadolintHit,
  parseHadolintReport,
  runHadolint,
  severityOf,
  toFinding,
} from "./hadolint.ts";

/** The fixture repository the fixture payload was really captured against. */
const TARGET_DIR = `${import.meta.dir}/__fixtures__/repo`;
const RUN_DIR = "/tmp/sentinel-run";

/**
 * Real output of `hadolint --no-fail --no-color --format json Dockerfile`,
 * hadolint 2.15.1, against `__fixtures__/repo/Dockerfile`.
 */
const report = await Bun.file(`${import.meta.dir}/__fixtures__/hadolint-dockerfile.json`).text();

/** Reads through the real port, captures every write in memory. */
function recordingFileSystem(): { fs: RunnerFileSystem; written: Map<string, string> } {
  const real = createFileSystem();
  const written = new Map<string, string>();
  return {
    written,
    fs: {
      readFile: (path) => real.readFile(path),
      readFileBytes: (path) => real.readFileBytes(path),
      realpath: (path) => real.realpath(path),
      exists: (path) => real.exists(path),
      mkdirp: async () => undefined,
      writeFile: async (path, data) => {
        written.set(path, typeof data === "string" ? data : new TextDecoder().decode(data));
      },
    },
  };
}

interface Script {
  readonly stdout?: string;
  readonly stderr?: string;
  readonly exitCode?: number;
  readonly timedOut?: boolean;
  readonly notFound?: boolean;
  readonly truncated?: boolean;
}

function harness(script: Script = {}, context: Partial<RunnerContext> = {}) {
  const spawns: Array<{ command: string; args: readonly string[] }> = [];
  const { fs, written } = recordingFileSystem();
  const exec = createStubProcessExecutor((command, args) => {
    spawns.push({ command, args });
    return {
      stdout: script.stdout ?? report,
      stderr: script.stderr ?? "",
      exitCode: script.exitCode ?? 0,
      ...(script.timedOut === true ? { timedOut: true } : {}),
      ...(script.notFound === true ? { notFound: true } : {}),
      ...(script.truncated === true ? { truncated: true } : {}),
    };
  });
  const ctx: RunnerContext = {
    fs,
    exec,
    tools: { resolve: async () => "/opt/hadolint/hadolint" },
    targetDir: TARGET_DIR,
    runDir: RUN_DIR,
    ...context,
  };
  return { ctx, spawns, written };
}

/** A profile that proves exactly the given facts. */
function profileWith(facts: ReadonlyArray<[DetectedFact["kind"], string, string]>): StackProfile {
  return {
    schemaVersion: "1.0",
    target: TARGET_DIR,
    facts: facts.map(([kind, value, file]) => ({
      kind,
      value,
      confidence: "high",
      evidence: [{ file, line: 1 }],
    })),
    absences: [],
    warnings: [],
    scan: { filesSeen: 1, filesRead: 1, truncated: false },
  };
}

const hit = (overrides: Partial<HadolintHit> = {}): HadolintHit => ({
  code: "DL3007",
  file: "Dockerfile",
  line: 1,
  column: 1,
  level: "warning",
  message: "Using latest is prone to errors",
  ...overrides,
});

describe("parseHadolintReport", () => {
  test("accepts the real payload", () => {
    const parsed = parseHadolintReport(report);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value).toHaveLength(7);
    expect(parsed.value.map((entry) => entry.code)).toEqual([
      "DL3007",
      "DL3064",
      "DL3064",
      "DL3008",
      "DL3015",
      "DL3009",
      "DL3025",
    ]);
  });

  test("refuses the Haskell backtrace hadolint prints for a missing file", () => {
    const parsed = parseHadolintReport("hadolint: nope: withBinaryFile: does not exist");
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.error).toContain("hadolint did not produce valid JSON");
  });

  test("refuses a payload of the wrong shape rather than throwing", () => {
    const parsed = parseHadolintReport('[{"code":"DL3007"}]');
    expect(parsed.ok).toBe(false);
  });
});

describe("severityOf", () => {
  test("maps hadolint's own levels", () => {
    expect(severityOf(hit({ code: "DL9999", level: "error" }))).toBe("high");
    expect(severityOf(hit({ code: "DL9999", level: "warning" }))).toBe("medium");
    expect(severityOf(hit({ code: "DL9999", level: "info" }))).toBe("low");
    expect(severityOf(hit({ code: "DL9999", level: "style" }))).toBe("info");
  });

  test("promotes the checks whose consequence is security", () => {
    // hadolint calls both of these "warning".
    expect(severityOf(hit({ code: "DL3002", level: "warning" }))).toBe("high");
    expect(severityOf(hit({ code: "DL3064", level: "warning" }))).toBe("high");
  });

  test("falls back to low for a level it has never seen", () => {
    expect(severityOf(hit({ code: "DL9999", level: "whatever" }))).toBe("low");
  });
});

describe("toFinding", () => {
  test("keeps hadolint's own rule id inside the Sentinel namespace", () => {
    expect(toFinding(hit()).rule).toBe("delivery.dockerfile.DL3007");
    expect(toFinding(hit({ code: "SC2086" })).rule).toBe("delivery.dockerfile.SC2086");
  });

  test("links shellcheck codes to shellcheck's wiki and hadolint's to hadolint's", () => {
    expect(toFinding(hit({ code: "SC2086" })).recommendation).toContain("shellcheck.net/wiki");
    expect(toFinding(hit()).recommendation).toContain("hadolint/hadolint/wiki");
  });

  test("gives two hits of one code in one file distinct ids", () => {
    const first = toFinding(hit({ code: "DL3064", line: 2 }));
    const second = toFinding(hit({ code: "DL3064", line: 3 }));
    expect(first.id).not.toBe(second.id);
  });

  test("is stable for the same hit", () => {
    expect(toFinding(hit()).id).toBe(toFinding(hit()).id);
  });

  test("clamps a non-positive line to one the CodeRef contract accepts", () => {
    expect(toFinding(hit({ line: 0 })).location.line).toBe(1);
  });
});

describe("runHadolint", () => {
  test("turns the real payload into verified findings with snippets from disk", async () => {
    const { ctx, spawns } = harness();
    const result = await runHadolint(ctx, { files: ["Dockerfile"] });

    expect(result.status).toBe("ok");
    expect(result.step).toBe(HADOLINT_STEP);
    expect(result.findings).toHaveLength(7);
    expect(spawns[0]?.args).toEqual(["--no-fail", "--no-color", "--format", "json", "Dockerfile"]);

    const latest = result.findings.find((finding) => finding.rule.endsWith("DL3007"));
    expect(latest?.severity).toBe("medium");
    expect(latest?.location.file).toBe("Dockerfile");
    expect(latest?.location.line).toBe(1);
    // The snippet is read off disk by src/verify, never taken from the tool.
    expect(latest?.location.snippet).toContain("FROM node:latest");

    const secret = result.findings.find((finding) => finding.rule.endsWith("DL3064"));
    expect(secret?.severity).toBe("high");
    expect(secret?.location.snippet).toContain("ARG NPM_TOKEN");
    expect(secret?.cwe).toContain("CWE-798");
  });

  test("writes the untouched stdout under the run directory", async () => {
    const { ctx, written } = harness();
    const result = await runHadolint(ctx, { files: ["Dockerfile"] });
    expect(result.artifacts).toEqual([`${RUN_DIR}/raw/hadolint/hadolint.json`]);
    expect(written.get(`${RUN_DIR}/raw/hadolint/hadolint.json`)).toBe(report);
  });

  test("takes the Dockerfile list from the profile when none is given", async () => {
    const { ctx } = harness(
      {},
      { profile: profileWith([["container", "dockerfile", "Dockerfile"]]) },
    );
    const result = await runHadolint(ctx);
    expect(result.status).toBe("ok");
    expect(result.findings.length).toBeGreaterThan(0);
  });

  test("skips when the repository has no Dockerfile", async () => {
    const { ctx, spawns } = harness();
    const result = await runHadolint(ctx, { files: [] });
    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("no Dockerfile");
    expect(spawns).toHaveLength(0);
  });

  test("skips, rather than fails, when hadolint is not installed", async () => {
    const { ctx } = harness({}, { tools: { resolve: async () => null } });
    const result = await runHadolint(ctx, { files: ["Dockerfile"] });
    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("sentinel setup");
    expect(result.findings).toEqual([]);
  });

  test("fails without throwing when hadolint does not print JSON", async () => {
    const { ctx } = harness({ stdout: "hadolint: boom", stderr: "backtrace", exitCode: 1 });
    const result = await runHadolint(ctx, { files: ["Dockerfile"] });
    expect(result.status).toBe("failed");
    expect(result.reason).toContain("valid JSON");
    expect(result.findings).toEqual([]);
  });

  test("fails on a timeout and keeps whatever was captured", async () => {
    const { ctx } = harness({ timedOut: true, stdout: "" });
    const result = await runHadolint(ctx, { files: ["Dockerfile"] });
    expect(result.status).toBe("failed");
    expect(result.reason).toContain("timed out");
  });

  test("degrades, but keeps the hits, when hadolint exits non-zero with valid JSON", async () => {
    const { ctx } = harness({ exitCode: 1, stderr: "one file was unreadable" });
    const result = await runHadolint(ctx, { files: ["Dockerfile"] });
    expect(result.status).toBe("degraded");
    expect(result.reason).toContain("exited 1");
    expect(result.findings).toHaveLength(7);
  });

  test("drops a hit whose citation does not resolve, and says how many", async () => {
    const { ctx } = harness({
      stdout: JSON.stringify([
        {
          code: "DL3007",
          file: "does-not-exist",
          line: 1,
          column: 1,
          level: "warning",
          message: "x",
        },
        { code: "DL3025", file: "Dockerfile", line: 9, column: 1, level: "warning", message: "y" },
      ]),
    });
    const result = await runHadolint(ctx, { files: ["Dockerfile"] });
    expect(result.status).toBe("degraded");
    expect(result.findings).toHaveLength(1);
    expect(result.reason).toContain("1 hit(s) cited a line");
  });
});

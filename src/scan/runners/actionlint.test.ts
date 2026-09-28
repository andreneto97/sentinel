import { describe, expect, test } from "bun:test";
import type { DetectedFact, StackProfile } from "../../contracts/profile.ts";
import { createFileSystem } from "../../ports/file-system.ts";
import { createStubProcessExecutor } from "../../ports/process-executor.ts";
import type { RunnerContext, RunnerFileSystem } from "./_runner-support.ts";
import {
  ACTIONLINT_STEP,
  type ActionlintError,
  isUntrustedInput,
  parseActionlintReport,
  ruleOf,
  runActionlint,
  severityOf,
  toFinding,
} from "./actionlint.ts";

/** The fixture repository the fixture payload was really captured against. */
const TARGET_DIR = `${import.meta.dir}/__fixtures__/repo`;
const RUN_DIR = "/tmp/sentinel-run";
const WORKFLOW = ".github/workflows/deploy.yml";

/**
 * Real output of `actionlint -format '{{json .}}' -no-color`, actionlint
 * 1.7.12, against `__fixtures__/repo/.github/workflows/deploy.yml`.
 */
const report = await Bun.file(`${import.meta.dir}/__fixtures__/actionlint-workflows.json`).text();

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
      exitCode: script.exitCode ?? 1,
      ...(script.timedOut === true ? { timedOut: true } : {}),
      ...(script.truncated === true ? { truncated: true } : {}),
    };
  });
  const ctx: RunnerContext = {
    fs,
    exec,
    tools: { resolve: async () => "/opt/actionlint/actionlint" },
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

const error = (overrides: Partial<ActionlintError> = {}): ActionlintError => ({
  message: "something is wrong",
  filepath: WORKFLOW,
  line: 1,
  column: 1,
  kind: "syntax-check",
  ...overrides,
});

/** The wording actionlint really uses for its script-injection warning. */
const UNTRUSTED_MESSAGE =
  '"github.event.pull_request.title" is potentially untrusted. avoid using it directly in inline scripts.';

describe("parseActionlintReport", () => {
  test("accepts the real payload", () => {
    const parsed = parseActionlintReport(report);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.map((entry) => entry.kind)).toEqual([
      "expression",
      "deprecated-commands",
      "credentials",
    ]);
  });

  test("accepts the empty array a clean workflow produces", () => {
    const parsed = parseActionlintReport("[]");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value).toEqual([]);
  });

  test("refuses the plain-text error actionlint prints for a missing file", () => {
    const parsed = parseActionlintReport('could not read "nope.yml": no such file or directory');
    expect(parsed.ok).toBe(false);
  });
});

describe("severityOf", () => {
  test("promotes the script-injection warning above every other expression error", () => {
    expect(severityOf(error({ kind: "expression", message: UNTRUSTED_MESSAGE }))).toBe("high");
    expect(severityOf(error({ kind: "expression", message: "type mismatch" }))).toBe("medium");
  });

  test("treats a hardcoded credential as high and style as low", () => {
    expect(severityOf(error({ kind: "credentials" }))).toBe("high");
    expect(severityOf(error({ kind: "runner-label" }))).toBe("low");
    expect(severityOf(error({ kind: "deprecated-commands" }))).toBe("low");
  });

  test("reports an unknown kind without shouting about it", () => {
    expect(severityOf(error({ kind: "some-future-kind" }))).toBe("low");
  });
});

describe("isUntrustedInput", () => {
  test("recognises actionlint's script-injection wording", () => {
    expect(isUntrustedInput(error({ kind: "expression", message: UNTRUSTED_MESSAGE }))).toBe(true);
  });

  test("does not fire on an expression error that is only a type mismatch", () => {
    expect(isUntrustedInput(error({ kind: "expression", message: "type mismatch" }))).toBe(false);
  });

  test("does not fire on another kind that happens to mention untrusted input", () => {
    expect(
      isUntrustedInput(error({ kind: "syntax-check", message: `x ${UNTRUSTED_MESSAGE}` })),
    ).toBe(false);
  });
});

describe("ruleOf", () => {
  test("uses the kind as the rule leaf", () => {
    expect(ruleOf(error({ kind: "credentials" }))).toBe("delivery.workflow.credentials");
  });

  test("gives script injection its own rule id rather than hiding it under expression", () => {
    expect(ruleOf(error({ kind: "expression", message: UNTRUSTED_MESSAGE }))).toBe(
      "delivery.workflow.script-injection",
    );
  });

  test("keeps the shellcheck code when actionlint forwards one", () => {
    expect(
      ruleOf(error({ kind: "shellcheck", message: "shellcheck reported issue: SC2086:info:1:6" })),
    ).toBe("delivery.workflow.shellcheck.SC2086");
  });
});

describe("toFinding", () => {
  test("labels a script injection and classifies it", () => {
    const finding = toFinding(error({ kind: "expression", message: UNTRUSTED_MESSAGE, line: 15 }));
    expect(finding.severity).toBe("high");
    expect(finding.title).toContain("Script injection");
    expect(finding.cwe).toEqual(["CWE-94", "CWE-78"]);
    expect(finding.owasp).toEqual(["A03:2021-Injection"]);
    expect(finding.exploitability).toContain("outside contributor");
  });

  test("does not carry the tool's own snippet into the finding", () => {
    const finding = toFinding(error({ snippet: "  run: echo\n       ^~~~" }));
    expect(finding.location.snippet).toBeUndefined();
  });

  test("clamps a non-positive line to one the CodeRef contract accepts", () => {
    expect(toFinding(error({ line: 0 })).location.line).toBe(1);
  });

  test("is stable, and distinguishes two errors on different lines", () => {
    expect(toFinding(error()).id).toBe(toFinding(error()).id);
    expect(toFinding(error({ line: 2 })).id).not.toBe(toFinding(error({ line: 3 })).id);
  });
});

describe("runActionlint", () => {
  test("turns the real payload into verified findings with snippets from disk", async () => {
    const { ctx } = harness();
    const result = await runActionlint(ctx, { files: [WORKFLOW] });

    expect(result.status).toBe("ok");
    expect(result.step).toBe(ACTIONLINT_STEP);
    expect(result.findings).toHaveLength(3);

    const injection = result.findings.find((finding) => finding.rule.endsWith("script-injection"));
    expect(injection?.severity).toBe("high");
    expect(injection?.location.line).toBe(15);
    expect(injection?.location.snippet).toContain("github.event.pull_request.title");

    const credentials = result.findings.find((finding) => finding.rule.endsWith("credentials"));
    expect(credentials?.severity).toBe("high");
    expect(credentials?.location.snippet).toContain("password: hardcoded");
  });

  test("disables the unpinned shellcheck and pyflakes integrations and discloses it", async () => {
    const { ctx, spawns } = harness();
    const result = await runActionlint(ctx, { files: [WORKFLOW] });
    expect(spawns[0]?.args.slice(0, 5)).toEqual([
      "-format",
      "{{json .}}",
      "-no-color",
      "-shellcheck=",
      "-pyflakes=",
    ]);
    expect(result.reason).toContain("shellcheck and pyflakes integrations are off");
  });

  test("passes a shellcheck through when the caller supplies one", async () => {
    const { ctx, spawns } = harness();
    await runActionlint(ctx, { files: [WORKFLOW], shellcheckPath: "/usr/bin/shellcheck" });
    expect(spawns[0]?.args).toContain("-shellcheck=/usr/bin/shellcheck");
  });

  test("writes the untouched stdout under the run directory", async () => {
    const { ctx, written } = harness();
    const result = await runActionlint(ctx, { files: [WORKFLOW] });
    expect(result.artifacts).toEqual([`${RUN_DIR}/raw/actionlint/actionlint.json`]);
    expect(written.get(`${RUN_DIR}/raw/actionlint/actionlint.json`)).toBe(report);
  });

  test("treats a clean run as ok with no findings", async () => {
    const { ctx } = harness({ stdout: "[]", exitCode: 0 });
    const result = await runActionlint(ctx, { files: [WORKFLOW] });
    expect(result.status).toBe("ok");
    expect(result.findings).toEqual([]);
  });

  test("takes the workflow list from the profile when none is given", async () => {
    const { ctx } = harness({}, { profile: profileWith([["ci", "github-actions", WORKFLOW]]) });
    const result = await runActionlint(ctx);
    expect(result.status).toBe("ok");
    expect(result.findings).toHaveLength(3);
  });

  test("skips when the repository has no workflow", async () => {
    const { ctx, spawns } = harness();
    const result = await runActionlint(ctx, { files: [] });
    expect(result.status).toBe("skipped");
    expect(spawns).toHaveLength(0);
  });

  test("skips, rather than fails, when actionlint is not installed", async () => {
    const { ctx } = harness({}, { tools: { resolve: async () => null } });
    const result = await runActionlint(ctx, { files: [WORKFLOW] });
    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("sentinel setup");
  });

  test("fails without throwing on the usage error actionlint writes to stderr", async () => {
    const { ctx } = harness({
      stdout: "",
      stderr: 'could not read "nope.yml": no such file or directory',
      exitCode: 3,
    });
    const result = await runActionlint(ctx, { files: [WORKFLOW] });
    expect(result.status).toBe("failed");
    expect(result.reason).toContain("exited 3");
    expect(result.findings).toEqual([]);
  });

  test("fails when the output was truncated, because the error list is then incomplete", async () => {
    const { ctx } = harness({ truncated: true });
    const result = await runActionlint(ctx, { files: [WORKFLOW] });
    expect(result.status).toBe("failed");
    expect(result.reason).toContain("truncated");
  });
});

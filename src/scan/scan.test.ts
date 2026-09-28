import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import type { Domain, Finding } from "../contracts/findings.ts";
import { createMemoryLogger } from "../ports/logger.ts";
import {
  FIXTURE_RUN_DIR,
  FIXTURE_TARGET,
  INSTALLED_TOOLS,
  fixtureContext,
  fixtureResolver,
  recordingExecutor,
  recordingFileSystem,
} from "./__fixtures__/harness.ts";
import { FINDINGS_FILE, SCAN_REPORT_FILE } from "./artifacts.ts";
import { DEFAULT_SCAN_PARALLELISM, buildScanSteps, runScan, runStep, withPool } from "./scan.ts";
import type { ScanContext, ScanStep, StepOutcome } from "./types.ts";

/** A step that resolves after `delayMs` with a fixed status. */
function fakeStep(
  name: string,
  domains: readonly Domain[],
  run: (ctx: ScanContext) => Promise<StepOutcome>,
  timeoutMs = 1_000,
): ScanStep {
  return { name, domains, timeoutMs, run };
}

/** A finding whose citation really resolves inside the fixture repository. */
function scanFinding(input: { id: string; file: string; line: number }): Finding {
  return {
    id: input.id,
    domain: "appsec",
    rule: "appsec.injection.unsafe-input",
    severity: "medium",
    confidence: "high",
    title: "Unsafe input reaches a sink",
    description: "A value from the request boundary reaches a sink unvalidated.",
    location: { file: input.file, line: input.line },
    evidence: [],
    impact: "An attacker controls part of the statement.",
    recommendation: "Validate at the boundary.",
    acceptanceCriteria: [],
    cwe: [],
    owasp: [],
    source: { kind: "rule", name: "opengrep" },
  };
}

/** An `ok` outcome carrying nothing, for orchestration tests. */
function ok(name: string): StepOutcome {
  return { step: name, status: "ok", findings: [], artifacts: [], durationMs: 1 };
}

describe("withPool", () => {
  test("never runs more than the limit at once", async () => {
    let inFlight = 0;
    let peak = 0;
    await withPool(
      Array.from({ length: 12 }, (_, index) => index),
      4,
      async (value) => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await Bun.sleep(1);
        inFlight -= 1;
        return value;
      },
    );
    expect(peak).toBe(4);
  });

  test("returns results in input order, not completion order", async () => {
    const results = await withPool([30, 1, 20, 2], 4, async (delay) => {
      await Bun.sleep(delay);
      return delay;
    });
    expect(results).toEqual([30, 1, 20, 2]);
  });

  test("an empty list needs no lanes", async () => {
    expect(await withPool([], 4, async () => 1)).toEqual([]);
  });
});

describe("runStep", () => {
  test("a runner that throws becomes a failed outcome, not a thrown scan", async () => {
    const outcome = await runStep(
      fakeStep("boom", ["appsec"], async () => {
        throw new Error("the parser exploded");
      }),
      fixtureContext(),
    );
    expect(outcome.status).toBe("failed");
    expect(outcome.reason).toContain("threw instead of returning an outcome");
    expect(outcome.reason).toContain("the parser exploded");
    expect(outcome.findings).toEqual([]);
  });

  test("a runner that hangs past its budget is abandoned, not waited on", async () => {
    const outcome = await runStep(
      fakeStep("hang", ["appsec"], () => new Promise<StepOutcome>(() => undefined), 1),
      fixtureContext(),
      2,
    );
    expect(outcome.status).toBe("failed");
    expect(outcome.reason).toContain("did not finish within");
  });

  test("each step is handed its own command budget", async () => {
    let seen: number | undefined;
    await runStep(
      fakeStep(
        "budget",
        ["appsec"],
        async (ctx) => {
          seen = ctx.timeoutMs;
          return ok("budget");
        },
        4_242,
      ),
      fixtureContext(),
    );
    expect(seen).toBe(4_242);
  });
});

describe("runScan", () => {
  test("one failing step never takes the others' findings with it", async () => {
    const result = await runScan(fixtureContext(), {
      write: false,
      steps: [
        fakeStep("boom", ["appsec"], async () => {
          throw new Error("nope");
        }),
        fakeStep("fine", ["delivery"], async () => ok("fine")),
      ],
    });
    expect(result.outcomes.map((outcome) => outcome.status)).toEqual(["failed", "ok"]);
  });

  test("outcomes come back in registry order however the steps interleave", async () => {
    const result = await runScan(fixtureContext(), {
      write: false,
      steps: [
        fakeStep("slow", ["appsec"], async () => {
          await Bun.sleep(20);
          return ok("slow");
        }),
        fakeStep("fast", ["delivery"], async () => ok("fast")),
      ],
    });
    expect(result.outcomes.map((outcome) => outcome.step)).toEqual(["slow", "fast"]);
  });

  test("a domain outside the scope is neither planned nor counted", async () => {
    const result = await runScan(fixtureContext(), {
      write: false,
      domains: ["delivery"],
      steps: [
        fakeStep("gitleaks", ["appsec"], async () => ok("gitleaks")),
        fakeStep("hadolint", ["delivery"], async () => ok("hadolint")),
      ],
    });
    expect(result.outcomes.map((outcome) => outcome.step)).toEqual(["hadolint"]);
    expect(result.coverage.map((entry) => entry.domain)).toEqual(["delivery"]);
  });

  describe("--path", () => {
    /** Two findings the verifier can resolve: one in `src/`, one in `src/__tests__/`. */
    const twoFindings = (): ScanStep =>
      fakeStep("opengrep", ["appsec"], async () => ({
        step: "opengrep",
        status: "ok",
        findings: [
          scanFinding({ id: "a".repeat(16), file: "src/index.ts", line: 1 }),
          scanFinding({
            id: "b".repeat(16),
            file: "src/__tests__/auth-middleware.ts",
            line: 1,
          }),
        ],
        artifacts: [],
        durationMs: 1,
      }));

    test("counts the findings that came from outside the analysed subtree", async () => {
      const result = await runScan(fixtureContext(), {
        write: false,
        scope: ["src/__tests__"],
        steps: [twoFindings()],
      });
      // Phase 1 is never narrowed: both findings are kept, and the one the run
      // did not otherwise analyse is counted rather than dropped.
      expect(result.findings).toHaveLength(2);
      expect(result.outsideScope).toBe(1);
    });

    test("an unscoped run has nothing outside it", async () => {
      const result = await runScan(fixtureContext(), { write: false, steps: [twoFindings()] });
      expect(result.findings).toHaveLength(2);
      expect(result.outsideScope).toBe(0);
    });

    test("the scope does not change which steps run, or what they are given", async () => {
      const seen: string[] = [];
      const result = await runScan(fixtureContext(), {
        write: false,
        scope: ["src/__tests__"],
        steps: [
          fakeStep("gitleaks", ["appsec"], async (ctx) => {
            seen.push(ctx.targetDir);
            return ok("gitleaks");
          }),
        ],
      });
      expect(result.outcomes.map((outcome) => outcome.status)).toEqual(["ok"]);
      // The analyzers keep reading the repository root: a lockfile and a git
      // history have no subtree.
      expect(seen).toEqual([FIXTURE_TARGET]);
    });
  });

  test("the default fan-out is four", () => {
    expect(DEFAULT_SCAN_PARALLELISM).toBe(4);
  });
});

describe("cancellation", () => {
  test("an abort kills the children through the process port and skips the rest", async () => {
    const exec = recordingExecutor();
    const controller = new AbortController();
    const ctx = fixtureContext({ exec, signal: controller.signal });

    const result = await runScan(ctx, {
      write: false,
      maxParallel: 1,
      steps: [
        fakeStep("first", ["appsec"], async () => {
          controller.abort();
          return ok("first");
        }),
        fakeStep("second", ["delivery"], async () => ok("second")),
        fakeStep("third", ["delivery"], async () => ok("third")),
      ],
    });

    expect(exec.kills).toEqual(["SIGTERM"]);
    expect(result.aborted).toBe(true);
    expect(result.outcomes.map((outcome) => outcome.status)).toEqual(["ok", "skipped", "skipped"]);
    expect(result.outcomes[1]?.reason).toBe("the run was cancelled before this step started");
    expect(result.report.aborted).toBe(true);
  });

  test("a step that was in flight when the abort arrived says so, not just 'failed'", async () => {
    const controller = new AbortController();
    const result = await runScan(
      fixtureContext({ exec: recordingExecutor(), signal: controller.signal }),
      {
        write: false,
        maxParallel: 2,
        steps: [
          fakeStep("trigger", ["appsec"], async () => {
            // Both lanes are already running by the time this fires.
            await Bun.sleep(5);
            controller.abort();
            return ok("trigger");
          }),
          // Started before the abort, and killed by it the way a real analyzer is.
          fakeStep("victim", ["delivery"], async () => {
            await Bun.sleep(20);
            return {
              step: "victim",
              status: "failed",
              reason: "gitleaks exited with code 143",
              findings: [],
              artifacts: [],
              durationMs: 20,
            };
          }),
        ],
      },
    );
    const victim = result.outcomes.find((outcome) => outcome.step === "victim");
    expect(victim?.reason).toBe(
      "the run was cancelled while this step was running; the analyzer reported: gitleaks exited with code 143",
    );
  });

  test("a step that simply failed is not blamed on a cancellation that never happened", async () => {
    const result = await runScan(fixtureContext(), {
      write: false,
      steps: [
        fakeStep("broken", ["appsec"], async () => ({
          step: "broken",
          status: "failed" as const,
          reason: "npm exited with code 1",
          findings: [],
          artifacts: [],
          durationMs: 1,
        })),
      ],
    });
    expect(result.outcomes[0]?.reason).toBe("npm exited with code 1");
  });

  test("a signal already aborted means nothing is started at all", async () => {
    const exec = recordingExecutor();
    const result = await runScan(fixtureContext({ exec, signal: AbortSignal.abort() }), {
      write: false,
      steps: [
        fakeStep("first", ["appsec"], async () => {
          throw new Error("this step should never have started");
        }),
      ],
    });
    expect(result.outcomes[0]?.status).toBe("skipped");
    expect(result.aborted).toBe(true);
  });
});

describe("the registry against the fixture repository", () => {
  const fs = recordingFileSystem();
  const exec = recordingExecutor();
  const { logger, records } = createMemoryLogger();
  const ctx = fixtureContext({ fs, exec, logger });

  test("it plans every step the pipeline has, with its domains", async () => {
    const steps = await buildScanSteps(ctx);
    expect(steps.map((step) => step.name)).toEqual([
      "trivy",
      "gitleaks",
      "opengrep",
      "knip",
      "dependency-cruiser",
      "package-manager",
      "actionlint",
      "hadolint",
      "ci-rules",
      "container-rules",
    ]);
    const covered = new Set(steps.flatMap((step) => [...step.domains]));
    expect([...covered].sort()).toEqual(["appsec", "data", "deadcode", "delivery", "dependencies"]);
  });

  test("a whole run writes both documents and reports what did not run", async () => {
    const result = await runScan(ctx, { maxParallel: 4 });

    expect(fs.written.has(join(FIXTURE_RUN_DIR, FINDINGS_FILE))).toBe(true);
    expect(fs.written.has(join(FIXTURE_RUN_DIR, SCAN_REPORT_FILE))).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);

    // Only hadolint and actionlint are installed in the fixture; the rest say so.
    const skipped = result.outcomes.filter((outcome) => outcome.status === "skipped");
    expect(skipped.map((outcome) => outcome.step).sort()).toEqual([
      "dependency-cruiser",
      "gitleaks",
      "knip",
      "opengrep",
      "trivy",
    ]);
    for (const outcome of skipped) expect(outcome.reason ?? "").not.toBe("");

    // package-manager needs no external binary, so it is the one dependency step
    // that still contributes; it degrades because the fixture has no lockfile.
    const dependencies = result.coverage.find((entry) => entry.domain === "dependencies");
    expect(dependencies?.unitsAudited).toBe(1);
    expect(dependencies?.skipped.map((entry) => entry.unitId)).toEqual(["knip", "trivy"]);

    // The delivery domain is the one the fixture can actually cover.
    const delivery = result.coverage.find((entry) => entry.domain === "delivery");
    expect(delivery?.unitsAudited).toBe(4);
    expect(delivery?.skipped.map((entry) => entry.unitId)).toEqual(["trivy"]);
    expect(delivery?.skipped[0]?.reason).toContain("trivy is not installed");

    expect(records.some((record) => record.message === "phase 1 planned")).toBe(true);
  });

  test("a repository with no Dockerfile says so in the coverage table", async () => {
    const bare = fixtureContext({
      fs: recordingFileSystem(),
      exec: recordingExecutor(),
      targetDir: join(FIXTURE_TARGET, "src"),
      tools: fixtureResolver(INSTALLED_TOOLS),
    });
    const result = await runScan(bare, { write: false, domains: ["delivery"] });

    const hadolint = result.outcomes.find((outcome) => outcome.step === "hadolint");
    expect(hadolint?.status).toBe("skipped");
    expect(hadolint?.reason).toBe("the target has no Dockerfile");

    const delivery = result.coverage.find((entry) => entry.domain === "delivery");
    expect(delivery?.skipped).toContainEqual({
      unitId: "hadolint",
      reason: "skipped: the target has no Dockerfile",
    });
  });
});

describe("determinism", () => {
  /** A fresh run over the unchanged fixture repository. */
  async function scan(): Promise<{ findings: string; report: string }> {
    const fs = recordingFileSystem();
    await runScan(fixtureContext({ fs, exec: recordingExecutor() }));
    return {
      findings: fs.written.get(join(FIXTURE_RUN_DIR, FINDINGS_FILE)) ?? "",
      report: fs.written.get(join(FIXTURE_RUN_DIR, SCAN_REPORT_FILE)) ?? "",
    };
  }

  test("two runs over an unchanged repository write the same findings.json, byte for byte", async () => {
    const [first, second] = await Promise.all([scan(), scan()]);
    expect(first.findings).not.toBe("");
    expect(first.findings).toBe(second.findings);
  });

  test("the run id and the target are the only things a caller may vary", async () => {
    const fs = recordingFileSystem();
    const base = fixtureContext({ fs, exec: recordingExecutor() });
    await runScan(base);
    const first = fs.written.get(join(FIXTURE_RUN_DIR, FINDINGS_FILE)) ?? "";

    const otherFs = recordingFileSystem();
    await runScan({
      ...fixtureContext({ fs: otherFs, exec: recordingExecutor() }),
      runId: "20991231T235959-ffffffff",
    });
    const second = otherFs.written.get(join(FIXTURE_RUN_DIR, FINDINGS_FILE)) ?? "";

    expect(second).not.toBe(first);
    expect(second.replace("20991231T235959-ffffffff", "20240101T000000-0000abcd")).toBe(first);
  });

  test("the timings that cannot be identical live in the other document", async () => {
    const [first, second] = await Promise.all([scan(), scan()]);
    const strip = (raw: string): unknown => {
      const parsed = JSON.parse(raw) as {
        durationMs: number;
        steps: Array<{ durationMs: number }>;
      };
      return {
        ...parsed,
        durationMs: 0,
        steps: parsed.steps.map((step) => ({ ...step, durationMs: 0 })),
      };
    };
    expect(strip(first.report)).toEqual(strip(second.report));
  });
});

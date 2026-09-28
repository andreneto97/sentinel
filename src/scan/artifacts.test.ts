import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { FindingsDocumentSchema, SCHEMA_VERSION } from "../contracts/findings.ts";
import { createFileSystem } from "../ports/file-system.ts";
import {
  FIXTURE_RUN_DIR,
  FIXTURE_RUN_ID,
  FIXTURE_TARGET,
  fixtureContext,
  recordingFileSystem,
} from "./__fixtures__/harness.ts";
import {
  FINDINGS_FILE,
  SCAN_REPORT_FILE,
  ScanReportSchema,
  buildCoverage,
  buildFindingsDocument,
  coverageReason,
  rawDir,
  toStepReport,
  writeFindingsDocument,
  writeRawOutput,
  writeScanReport,
} from "./artifacts.ts";
import { normaliseFindings } from "./normalise.ts";
import { runContainerRules } from "./rules/container.ts";
import { HADOLINT_STEP, runHadolint } from "./runners/hadolint.ts";
import type { ScanStep, StepOutcome } from "./types.ts";

/** A step definition with the two fields coverage reads. */
function step(name: string, domains: ScanStep["domains"]): ScanStep {
  return { name, domains, timeoutMs: 1_000, run: async () => outcome(name, "ok") };
}

/** An outcome with everything but the interesting field defaulted. */
function outcome(name: string, status: StepOutcome["status"], reason?: string): StepOutcome {
  return {
    step: name,
    status,
    ...(reason === undefined ? {} : { reason }),
    findings: [],
    artifacts: [],
    durationMs: 12,
  };
}

/**
 * The real hadolint runner against a repository that has no Dockerfile — this
 * is the sentence the coverage table has to carry, not one written here.
 */
const noDockerfile = await runHadolint(fixtureContext({ targetDir: join(FIXTURE_TARGET, "src") }), {
  files: [],
});

describe("coverage", () => {
  test("a step that could not apply reaches the table in its own words", () => {
    expect(noDockerfile.status).toBe("skipped");
    expect(noDockerfile.reason).toBe("the target has no Dockerfile");

    const coverage = buildCoverage([step(HADOLINT_STEP, ["delivery"])], [noDockerfile]);
    expect(coverage).toEqual([
      {
        domain: "delivery",
        unitsTotal: 1,
        unitsAudited: 0,
        skipped: [{ unitId: "hadolint", reason: "skipped: the target has no Dockerfile" }],
      },
    ]);
  });

  test("ok and degraded both count as audited; failed does not", () => {
    const steps = [
      step("trivy", ["dependencies"]),
      step("knip", ["dependencies"]),
      step("package-manager", ["dependencies"]),
    ];
    const coverage = buildCoverage(steps, [
      outcome("trivy", "ok"),
      outcome("knip", "degraded", "the candidate list was truncated"),
      outcome("package-manager", "failed", "npm exited with code 1"),
    ]);
    expect(coverage[0]?.unitsTotal).toBe(3);
    expect(coverage[0]?.unitsAudited).toBe(2);
    expect(coverage[0]?.skipped).toEqual([
      { unitId: "package-manager", reason: "failed: npm exited with code 1" },
    ]);
  });

  test("a planned step that never produced an outcome still counts against its domains", () => {
    const coverage = buildCoverage([step("gitleaks", ["appsec"])], []);
    expect(coverage[0]?.unitsAudited).toBe(0);
    expect(coverage[0]?.skipped[0]?.reason).toBe("not run: the scan ended before this step");
  });

  test("a step covering two domains subtracts from both when it is skipped", () => {
    const coverage = buildCoverage(
      [step("trivy", ["dependencies", "delivery"])],
      [outcome("trivy", "skipped", "trivy is not installed")],
    );
    expect(coverage.map((entry) => entry.domain)).toEqual(["dependencies", "delivery"]);
    for (const entry of coverage) expect(entry.unitsAudited).toBe(0);
  });

  test("domains outside the run's scope are not in the table at all", () => {
    const steps = [step("trivy", ["dependencies"]), step("gitleaks", ["appsec"])];
    const coverage = buildCoverage(
      steps,
      [outcome("trivy", "ok"), outcome("gitleaks", "ok")],
      ["appsec"],
    );
    expect(coverage.map((entry) => entry.domain)).toEqual(["appsec"]);
  });

  test("a domain the scope turned on but no step covers reads 0/0, not clean", () => {
    const coverage = buildCoverage(
      [step("trivy", ["dependencies"])],
      [outcome("trivy", "ok")],
      ["dependencies", "serverless"],
    );
    expect(coverage).toEqual([
      { domain: "dependencies", unitsTotal: 1, unitsAudited: 1, skipped: [] },
      { domain: "serverless", unitsTotal: 0, unitsAudited: 0, skipped: [] },
    ]);
  });

  test("with no scope given, a domain phase 1 has no step for claims nothing", () => {
    const coverage = buildCoverage([step("trivy", ["dependencies"])], [outcome("trivy", "ok")]);
    expect(coverage.map((entry) => entry.domain)).toEqual(["dependencies"]);
  });

  test("a step that gave no reason still says what its status was", () => {
    expect(coverageReason(outcome("knip", "failed"))).toBe("failed: no reason given");
  });

  test("the table follows the contract's domain order, not the steps' order", () => {
    const coverage = buildCoverage(
      [step("knip", ["deadcode"]), step("gitleaks", ["appsec"]), step("trivy", ["dependencies"])],
      [outcome("knip", "ok"), outcome("gitleaks", "ok"), outcome("trivy", "ok")],
    );
    expect(coverage.map((entry) => entry.domain)).toEqual(["dependencies", "appsec", "deadcode"]);
  });
});

/** Real findings from Sentinel's own Dockerfile pack over the fixture repository. */
const built = await runContainerRules(fixtureContext(), { dockerfiles: ["Dockerfile"] });
const normalised = await normaliseFindings(built.findings, {
  targetDir: FIXTURE_TARGET,
  fs: createFileSystem(),
});

describe("findings.json", () => {
  test("the document is valid against the contract before anything writes it", () => {
    const document = buildFindingsDocument({
      runId: FIXTURE_RUN_ID,
      target: FIXTURE_TARGET,
      findings: normalised.findings,
      coverage: buildCoverage([step("container-rules", ["delivery"])], [built]),
      droppedFindings: normalised.droppedFindings,
    });
    expect(() => FindingsDocumentSchema.parse(document)).not.toThrow();
    expect(document.schemaVersion).toBe(SCHEMA_VERSION);
    expect(document.assurances).toEqual([]);
    expect(document.findings.length).toBeGreaterThan(0);
  });

  test("a document that would not survive being read back is never produced", () => {
    expect(() =>
      buildFindingsDocument({
        runId: FIXTURE_RUN_ID,
        target: FIXTURE_TARGET,
        findings: [{ ...(normalised.findings[0] ?? {}), severity: "apocalyptic" } as never],
        coverage: [],
        droppedFindings: 0,
      }),
    ).toThrow();
  });

  test("it is written where the layout says, as diffable JSON with a trailing newline", async () => {
    const fs = recordingFileSystem();
    const document = buildFindingsDocument({
      runId: FIXTURE_RUN_ID,
      target: FIXTURE_TARGET,
      findings: normalised.findings,
      coverage: [],
      droppedFindings: 0,
    });
    const path = await writeFindingsDocument(fs, FIXTURE_RUN_DIR, document);

    expect(path).toBe(join(FIXTURE_RUN_DIR, FINDINGS_FILE));
    const written = fs.written.get(path) ?? "";
    expect(written.endsWith("}\n")).toBe(true);
    expect(written).toBe(`${JSON.stringify(document, null, 2)}\n`);
    expect(FindingsDocumentSchema.parse(JSON.parse(written)).findings).toEqual(document.findings);
  });
});

describe("scan-report.json", () => {
  test("it carries the timings that findings.json deliberately does not", async () => {
    const fs = recordingFileSystem();
    const report = ScanReportSchema.parse({
      schemaVersion: SCHEMA_VERSION,
      runId: FIXTURE_RUN_ID,
      target: FIXTURE_TARGET,
      aborted: false,
      durationMs: 1_234,
      steps: [toStepReport(noDockerfile)],
      dropped: { findings: 0, evidence: 0, byReason: {} },
      relocated: 0,
      merged: [],
      escalations: [],
    });
    const path = await writeScanReport(fs, FIXTURE_RUN_DIR, report);

    expect(path).toBe(join(FIXTURE_RUN_DIR, SCAN_REPORT_FILE));
    expect(report.steps[0]).toEqual({
      step: "hadolint",
      status: "skipped",
      reason: "the target has no Dockerfile",
      findings: 0,
      artifacts: [],
      durationMs: report.steps[0]?.durationMs ?? 0,
    });
    expect(JSON.parse(fs.written.get(path) ?? "")).toEqual(report);
  });
});

describe("raw output", () => {
  test("each tool's untouched output lands under raw/<tool>/", async () => {
    const fs = recordingFileSystem();
    expect(rawDir(FIXTURE_RUN_DIR, "trivy")).toBe(join(FIXTURE_RUN_DIR, "raw", "trivy"));

    const path = await writeRawOutput(fs, FIXTURE_RUN_DIR, "trivy", "fs.json", '{"Results":[]}');
    expect(path).toBe(join(FIXTURE_RUN_DIR, "raw", "trivy", "fs.json"));
    expect(fs.written.get(path)).toBe('{"Results":[]}');
  });
});

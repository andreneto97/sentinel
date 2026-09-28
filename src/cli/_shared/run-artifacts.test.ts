import { describe, expect, test } from "bun:test";
import {
  MemoryRunFs,
  RENDERED_ALL,
  analysisScope,
  assurance,
  auditReport,
  batchReport,
  completeRun,
  coverageRow,
  finding,
  findingsDocument,
  inventoryDocument,
  scanReport,
  writeRunFixture,
} from "./_run-fixtures.ts";
import {
  MissingArtifactError,
  assessRun,
  countBySeverity,
  describeRunPhases,
  firstIncompletePhase,
  formatRunDate,
  loadRunArtifacts,
  phaseByName,
  requireFindings,
  runStartedAt,
} from "./run-artifacts.ts";

const RUN = "/out/20260923T004014-d60d94c9";

describe("loadRunArtifacts", () => {
  test("reads every artifact a finished run holds", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const artifacts = await loadRunArtifacts(fs, RUN);

    expect(artifacts.runId).toBe("20260923T004014-d60d94c9");
    expect(artifacts.target).toBe("/repo");
    expect(artifacts.findings?.findings).toHaveLength(1);
    expect(artifacts.audit?.batches).toHaveLength(1);
    expect(artifacts.inventory?.units).toHaveLength(4);
    expect(artifacts.rendered).toEqual(RENDERED_ALL);
    expect(artifacts.unreadable).toEqual([]);
  });

  test("reads the --path artifact, and tells an absent one from a whole-repo run", async () => {
    const scoped = new MemoryRunFs();
    await writeRunFixture(scoped, {
      runDir: RUN,
      findings: findingsDocument(),
      analysisScope: analysisScope(),
    });
    const loaded = await loadRunArtifacts(scoped, RUN);
    expect(loaded.analysisScope?.paths).toEqual(["apps/api"]);
    expect(loaded.analysisScope?.wholeRepository).toBe(false);
    expect(loaded.analysisScope?.units.outOfScope).toBe(700);

    const bare = new MemoryRunFs();
    await writeRunFixture(bare, { runDir: RUN, findings: findingsDocument() });
    // Absent is `null`: not recorded, which is not the same claim as "everything".
    expect((await loadRunArtifacts(bare, RUN)).analysisScope).toBeNull();
  });

  test("an absent artifact is null, not an error", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, { runDir: RUN, findings: findingsDocument(), scan: scanReport() });
    const artifacts = await loadRunArtifacts(fs, RUN);

    expect(artifacts.audit).toBeNull();
    expect(artifacts.inventory).toBeNull();
    expect(artifacts.unreadable).toEqual([]);
  });

  test("an artifact that does not parse is reported by name, with the violation", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      raw: { "findings.json": "{ not json", "audit.json": JSON.stringify({ runId: 7 }) },
    });
    const artifacts = await loadRunArtifacts(fs, RUN);

    expect(artifacts.findings).toBeNull();
    expect(artifacts.unreadable.map((entry) => entry.file)).toEqual([
      "audit.json",
      "findings.json",
    ]);
    expect(artifacts.unreadable[1]?.reason).toContain("not valid JSON");
    expect(artifacts.unreadable[0]?.reason).toContain("not a valid document");
  });

  test("falls back to a document's own run id when the directory is not named after it", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, { runDir: "/tmp/copied", findings: findingsDocument() });
    const artifacts = await loadRunArtifacts(fs, "/tmp/copied");
    expect(artifacts.runId).toBe("20260923T004014-d60d94c9");
  });
});

describe("requireFindings", () => {
  test("names the file a report cannot be written without", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, { runDir: RUN, scan: scanReport() });
    const artifacts = await loadRunArtifacts(fs, RUN);

    expect(() => requireFindings(artifacts)).toThrow(MissingArtifactError);
    try {
      requireFindings(artifacts);
    } catch (error) {
      expect((error as MissingArtifactError).file).toBe("findings.json");
      expect((error as Error).message).toContain(`${RUN}/findings.json`);
    }
  });

  test("a corrupt document reports the corruption rather than absence", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, { runDir: RUN, raw: { "findings.json": "nope" } });
    const artifacts = await loadRunArtifacts(fs, RUN);
    expect(() => requireFindings(artifacts)).toThrow(/not valid JSON/);
  });
});

describe("describeRunPhases", () => {
  test("a finished run has six complete phases", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const phases = describeRunPhases(await loadRunArtifacts(fs, RUN));

    expect(phases.map((phase) => phase.name)).toEqual([
      "profile",
      "propose",
      "scan",
      "inventory",
      "audit",
      "report",
    ]);
    expect(phases.every((phase) => phase.status === "complete")).toBe(true);
    expect(firstIncompletePhase(phases)).toBeUndefined();
  });

  test("a failed batch makes the audit partial, not complete", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
      audit: auditReport({
        batches: [batchReport({ batchId: "b1", status: "failed", reason: "timed out" })],
      }),
    });
    const phases = describeRunPhases(await loadRunArtifacts(fs, RUN));
    const audit = phaseByName(phases, "audit");

    expect(audit?.status).toBe("partial");
    expect(audit?.detail).toContain("1 batch failed");
    expect(firstIncompletePhase(phases)?.name).toBe("audit");
  });

  test("a batch that answered partially is complete: those units are reported, not lost", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await writeRunFixture(fs, {
      runDir: RUN,
      audit: auditReport({
        batches: [batchReport({ batchId: "b1", status: "partial", reason: "2 of 4 units" })],
      }),
    });
    const audit = phaseByName(describeRunPhases(await loadRunArtifacts(fs, RUN)), "audit");
    expect(audit?.status).toBe("complete");
    expect(audit?.detail).toContain("answered partially");
  });

  test("a half-rendered report is partial and names the files it owes", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      rendered: ["report.md"],
    });
    const report = phaseByName(describeRunPhases(await loadRunArtifacts(fs, RUN)), "report");

    expect(report?.status).toBe("partial");
    expect(report?.missing).toEqual(["report.pdf", "issues.md"]);
  });

  test("a cancelled scan is partial and says so in the scan's own words", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      scan: scanReport({ aborted: true }),
    });
    const scan = phaseByName(describeRunPhases(await loadRunArtifacts(fs, RUN)), "scan");
    expect(scan?.status).toBe("partial");
    expect(scan?.detail).toContain("cancelled");
  });

  test("only the audit is marked as spending AI", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const phases = describeRunPhases(await loadRunArtifacts(fs, RUN));
    expect(phases.filter((phase) => phase.spendsAi).map((phase) => phase.name)).toEqual(["audit"]);
  });
});

describe("assessRun", () => {
  test("a finished run is shareable", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    const artifacts = await loadRunArtifacts(fs, RUN);
    const verdict = assessRun(artifacts, describeRunPhases(artifacts));

    expect(verdict.shareable).toBe(true);
    expect(verdict.blockers).toEqual([]);
  });

  test("a run with no audit is blocked, and the blocker says why", async () => {
    const fs = new MemoryRunFs();
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
      rendered: RENDERED_ALL,
    });
    const artifacts = await loadRunArtifacts(fs, RUN);
    const verdict = assessRun(artifacts, describeRunPhases(artifacts));

    expect(verdict.shareable).toBe(false);
    expect(verdict.blockers.join(" ")).toContain("no model audited this run");
  });

  test("an unrendered dossier blocks and names the command that fixes it", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await writeRunFixture(fs, { runDir: RUN });
    const fresh = new MemoryRunFs();
    await writeRunFixture(fresh, {
      runDir: RUN,
      findings: findingsDocument(),
      audit: auditReport(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
    });
    const artifacts = await loadRunArtifacts(fresh, RUN);
    const verdict = assessRun(artifacts, describeRunPhases(artifacts));

    expect(verdict.shareable).toBe(false);
    expect(verdict.blockers.join(" ")).toContain("sentinel report");
  });

  test("a replayed audit blocks: a recorded transcript is not evidence", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await writeRunFixture(fs, {
      runDir: RUN,
      audit: auditReport({
        runtime: {
          kind: "fixture",
          concurrency: 1,
          maxAttempts: 1,
          timeoutMs: 1000,
          synthetic: true,
        },
      }),
    });
    const artifacts = await loadRunArtifacts(fs, RUN);
    const verdict = assessRun(artifacts, describeRunPhases(artifacts));

    expect(verdict.shareable).toBe(false);
    expect(verdict.blockers.join(" ")).toContain("recorded transcript");
  });

  test("a domain that ran too few of its checks is disclosed, not left to look clean", async () => {
    // The real shape: delivery is in scope, has a coverage row, ran 1 of its 5
    // checks and found nothing. Nothing above marks it, so without this warning
    // the only thing the sharing list says about it is silence.
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument({
        coverage: [coverageRow("appsec", 4, 4), coverageRow("delivery", 5, 1)],
      }),
    });
    const artifacts = await loadRunArtifacts(fs, RUN);
    const verdict = assessRun(artifacts, describeRunPhases(artifacts));

    const warning = verdict.warnings.find((entry) => entry.startsWith("delivery earned no score"));
    expect(warning).toContain("only 1 of 5 checks ran");
    expect(warning).toContain("not as clean");
    // A well-covered domain earns no such line.
    expect(verdict.warnings.some((entry) => entry.startsWith("appsec earned no score"))).toBe(
      false,
    );
  });

  test("a domain outside the scope that still produced findings gets its own warning", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await writeRunFixture(fs, {
      runDir: RUN,
      findings: findingsDocument({
        findings: [finding({ id: "f1", domain: "api" })],
        assurances: [assurance({ id: "a1" })],
      }),
      scope: ["appsec"],
    });
    const artifacts = await loadRunArtifacts(fs, RUN);
    const verdict = assessRun(artifacts, describeRunPhases(artifacts));

    expect(verdict.warnings.join(" ")).toContain("api was outside this run's scope, yet 1");
  });

  test("units without a verdict are a warning, not a blocker", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await writeRunFixture(fs, {
      runDir: RUN,
      audit: auditReport({
        units: {
          total: 4,
          audited: 2,
          skipped: 2,
          byCause: {
            "no-batch": 0,
            "batch-failed": 0,
            "no-verdict": 0,
            inconclusive: 2,
            cancelled: 0,
            budget: 0,
          },
        },
        coverage: [coverageRow("appsec", 4, 2)],
      }),
    });
    const artifacts = await loadRunArtifacts(fs, RUN);
    const verdict = assessRun(artifacts, describeRunPhases(artifacts));

    expect(verdict.shareable).toBe(true);
    expect(verdict.warnings.join(" ")).toContain("2 of 4 units came back without a verdict");
  });
});

describe("dates and ordering", () => {
  test("a run is dated from its own id, in UTC", () => {
    expect(runStartedAt("20260923T004014-d60d94c9")?.toISOString()).toBe(
      "2026-09-23T00:40:14.000Z",
    );
    expect(formatRunDate("20260923T004014-d60d94c9")).toBe("2026-09-23 00:40 UTC");
  });

  test("an id with no timestamp is printed as itself rather than as a wrong date", () => {
    expect(runStartedAt("not-a-run-id")).toBeUndefined();
    expect(formatRunDate("not-a-run-id")).toBe("not-a-run-id");
  });

  test("every severity is counted, including the ones nothing matched", () => {
    const counts = countBySeverity([finding({ id: "a", severity: "medium" })]);
    expect(counts).toEqual({ critical: 0, high: 0, medium: 1, low: 0, info: 0 });
  });
});

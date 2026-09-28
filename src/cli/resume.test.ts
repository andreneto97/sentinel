import { describe, expect, test } from "bun:test";
import { unboundedBound } from "../audit/budget.ts";
import type { Coverage } from "../contracts/findings.ts";
import { captureCli, outputFlags } from "./_shared/_cli-context.ts";
import {
  MemoryRunFs,
  RENDERED_ALL,
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
} from "./_shared/_run-fixtures.ts";
import type { RunPhaseName } from "./_shared/run-artifacts.ts";
import { EXIT } from "./index.ts";
import type { PhaseOutcome, PhaseRequest, ResumeJson, ResumeRunners } from "./resume.ts";
import {
  mergeRetryIntoAudit,
  recomposeCoverage,
  recomposeKinds,
  recomposeUnitTotals,
  resumeCommand,
  retryableBatchIds,
  subtractAuditFromFindings,
  subtractCoverage,
  unitIdsOfBatches,
} from "./resume.ts";

const RUN = "/out/20260923T004014-d60d94c9";

/** Records which phases were asked to run, and with what. */
function spyRunners(overrides: Partial<ResumeRunners> = {}) {
  const calls: { name: RunPhaseName; request: PhaseRequest }[] = [];
  const make =
    (name: RunPhaseName) =>
    async (request: PhaseRequest): Promise<PhaseOutcome> => {
      calls.push({ name, request });
      return { ok: true, summary: `${name} ran`, artifacts: [`${request.runDir}/${name}.json`] };
    };
  const runners: ResumeRunners = {
    profile: overrides.profile ?? make("profile"),
    propose: overrides.propose ?? make("propose"),
    scan: overrides.scan ?? make("scan"),
    inventory: overrides.inventory ?? make("inventory"),
    audit: overrides.audit ?? make("audit"),
    report: overrides.report ?? make("report"),
  };
  return { runners, calls, names: () => calls.map((call) => call.name) };
}

/** Runs the verb against an in-memory run directory. */
async function run(
  fs: MemoryRunFs,
  runners: ResumeRunners,
  options: {
    runDir?: string;
    forcePhase?: RunPhaseName;
    retryFailed?: boolean;
    json?: boolean;
  } = {},
) {
  const captured = captureCli();
  const code = await resumeCommand(
    captured.context,
    {
      runDir: options.runDir ?? RUN,
      cwd: "/work",
      output: outputFlags({ json: options.json ?? false }),
      retryFailed: options.retryFailed ?? false,
      ...(options.forcePhase === undefined ? {} : { forcePhase: options.forcePhase }),
    },
    { fs, runners },
  );
  return { code, stdout: captured.stdout(), stderr: captured.stderr() };
}

/** A run directory that has everything up to, but not including, `missing`. */
async function runUpTo(fs: MemoryRunFs, missing: RunPhaseName): Promise<void> {
  const order: RunPhaseName[] = ["profile", "propose", "scan", "inventory", "audit", "report"];
  const index = order.indexOf(missing);
  const has = (phase: RunPhaseName): boolean => order.indexOf(phase) < index;
  await fs.mkdirp("/repo");
  await writeRunFixture(fs, {
    runDir: RUN,
    ...(has("profile") ? { profile: true } : {}),
    ...(has("propose") ? { scope: ["appsec"] as const } : {}),
    ...(has("scan")
      ? { findings: findingsDocument({ findings: [finding({ id: "f1" })] }), scan: scanReport() }
      : {}),
    ...(has("inventory") ? { inventory: inventoryDocument() } : {}),
    ...(has("audit") ? { audit: auditReport(), assurances: [assurance({ id: "a1" })] } : {}),
    ...(has("report") ? { rendered: RENDERED_ALL } : {}),
  });
}

describe("sentinel resume", () => {
  test("re-enters at the first incomplete phase and runs forward", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "audit");
    const spy = spyRunners();
    const result = await run(fs, spy.runners);

    expect(result.code).toBe(EXIT.ok);
    expect(spy.names()).toEqual(["audit", "report"]);
    expect(result.stdout).toContain('Resuming 20260923T004014-d60d94c9 at phase "audit"');
  });

  test("a run with only a report left re-renders and nothing else", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "report");
    const spy = spyRunners();
    await run(fs, spy.runners);
    expect(spy.names()).toEqual(["report"]);
  });

  test("a run missing its inventory re-enters there, then audits and renders", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "inventory");
    const spy = spyRunners();
    await run(fs, spy.runners);
    expect(spy.names()).toEqual(["inventory", "audit", "report"]);
  });

  test("a complete run re-runs nothing and says so", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await fs.mkdirp("/repo");
    const spy = spyRunners();
    const result = await run(fs, spy.runners);

    expect(result.code).toBe(EXIT.ok);
    expect(spy.names()).toEqual([]);
    expect(result.stdout).toContain("is complete");
    expect(result.stdout).toContain("nothing was spent");
  });

  test("never redoes an audit that already spent AI", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "report");
    await writeRunFixture(fs, {
      runDir: RUN,
      audit: auditReport({
        batches: [batchReport({ batchId: "b1", status: "failed", reason: "timed out" })],
      }),
    });
    const spy = spyRunners();
    const result = await run(fs, spy.runners);

    expect(spy.names()).toEqual(["report"]);
    expect(result.stdout).toContain("already spent AI budget");
    expect(result.stdout).toContain("--retry-failed");
  });

  test("--force-phase audit re-dispatches it, and says what that costs", async () => {
    const fs = new MemoryRunFs();
    await completeRun(fs, RUN);
    await fs.mkdirp("/repo");
    const spy = spyRunners();
    const result = await run(fs, spy.runners, { forcePhase: "audit" });

    expect(spy.names()).toEqual(["audit"]);
    expect(spy.calls[0]?.request.retryBatchIds).toBeUndefined();
    expect(result.stdout).toContain("spends subscription budget again");
  });

  test("--retry-failed hands the runner only the batches that failed or answered partially", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "report");
    await writeRunFixture(fs, {
      runDir: RUN,
      audit: auditReport({
        batches: [
          batchReport({ batchId: "ok-1", status: "audited" }),
          batchReport({ batchId: "bad-1", status: "failed", reason: "timed out" }),
          batchReport({ batchId: "half-1", status: "partial", reason: "2 of 4 units" }),
        ],
      }),
    });
    const spy = spyRunners();
    await run(fs, spy.runners, { retryFailed: true });

    expect(spy.names()).toEqual(["audit", "report"]);
    expect(spy.calls[0]?.request.retryBatchIds).toEqual(["bad-1", "half-1"]);
  });

  test("--retry-failed with nothing to retry says so instead of dispatching", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "report");
    const spy = spyRunners();
    const result = await run(fs, spy.runners, { retryFailed: true });

    expect(spy.names()).toEqual(["report"]);
    expect(result.stdout).toContain("nothing to re-dispatch");
  });

  test("refuses to re-enter a phase when the repository is gone", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "audit");
    const spy = spyRunners();
    const result = await run(fs, spy.runners);

    expect(spy.names()).toEqual(["audit", "report"]);

    const gone = new MemoryRunFs();
    await writeRunFixture(gone, {
      runDir: RUN,
      findings: findingsDocument(),
      scan: scanReport(),
      inventory: inventoryDocument(),
      profile: true,
      scope: ["appsec"],
    });
    const second = spyRunners();
    const refused = await run(gone, second.runners);

    expect(refused.code).toBe(EXIT.preflight);
    expect(refused.stderr).toContain("/repo does not exist any more");
    expect(second.names()).toEqual([]);
    expect(result.code).toBe(EXIT.ok);
  });

  test("a phase that fails stops the ones after it", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "audit");
    const spy = spyRunners({
      audit: async () => ({ ok: false, summary: "the runtime refused", artifacts: [] }),
    });
    const result = await run(fs, spy.runners);

    expect(result.code).toBe(EXIT.failure);
    expect(spy.names()).toEqual([]);
    expect(result.stdout).toContain("the runtime refused");
  });

  test("a runner that throws is reported, not propagated", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "report");
    const spy = spyRunners({
      report: async () => {
        throw new Error("pdfkit exploded");
      },
    });
    const result = await run(fs, spy.runners);

    expect(result.code).toBe(EXIT.failure);
    expect(result.stdout).toContain("crashed: pdfkit exploded");
  });

  test("--json reports the entry phase, every attempt and the new verdict", async () => {
    const fs = new MemoryRunFs();
    await runUpTo(fs, "report");
    const spy = spyRunners({
      report: async (request) => {
        await request.artifacts;
        for (const file of RENDERED_ALL) {
          await fs.writeFile(`${RUN}/${file}`, "rendered now");
        }
        return { ok: true, summary: "3 files rendered", artifacts: [] };
      },
    });
    const result = await run(fs, spy.runners, { json: true });
    const payload = JSON.parse(result.stdout) as ResumeJson;

    expect(payload.entryPhase).toBe("report");
    expect(payload.attempts.map((attempt) => attempt.name)).toEqual(["report"]);
    expect(payload.attempts[0]?.outcome).toBe("ran");
    expect(payload.verdict.shareable).toBe(true);
  });

  test("a directory that names no run is refused before anything runs", async () => {
    const fs = new MemoryRunFs();
    const spy = spyRunners();
    const result = await run(fs, spy.runners, { runDir: "/nowhere" });

    expect(result.code).toBe(EXIT.preflight);
    expect(spy.names()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The retry merge
// ---------------------------------------------------------------------------

describe("recomposing coverage", () => {
  test("a retried unit's old row is replaced, never added to", () => {
    const previous: Coverage[] = [
      coverageRow("data", 10, 8, [
        { unitId: "u1", reason: "no-verdict: the reply said nothing" },
        { unitId: "u2", reason: "no-verdict: the reply said nothing" },
      ]),
    ];
    const fresh: Coverage[] = [
      coverageRow("data", 2, 1, [{ unitId: "u2", reason: "inconclusive: declined" }]),
    ];
    const recomposed = recomposeCoverage(previous, new Set(["u1", "u2"]), fresh);

    expect(recomposed[0]?.unitsTotal).toBe(10);
    expect(recomposed[0]?.unitsAudited).toBe(9);
    expect(recomposed[0]?.skipped.map((entry) => entry.unitId)).toEqual(["u2"]);
  });

  test("a unit the retry could not decide either keeps its place in the table", () => {
    const previous = [
      coverageRow("appsec", 3, 2, [{ unitId: "x", reason: "batch-failed: timeout" }]),
    ];
    const fresh = [
      coverageRow("appsec", 1, 0, [{ unitId: "x", reason: "inconclusive: declined" }]),
    ];
    const recomposed = recomposeCoverage(previous, new Set(["x"]), fresh);

    expect(recomposed[0]?.unitsAudited).toBe(2);
    expect(recomposed[0]?.skipped[0]?.reason).toBe("inconclusive: declined");
  });

  test("a retry that fails outright does not take away the verdicts it re-asked about", () => {
    // `--retry-failed` re-dispatches whole batches, so the 16 units that did come
    // back are retried alongside the 1 that did not. The retry never reached the
    // model, so every unit it carried came back `batch-failed`.
    const previous = [
      coverageRow("appsec", 17, 16, [{ unitId: "u17", reason: "inconclusive: declined" }]),
    ];
    const retried = new Set(Array.from({ length: 17 }, (_, index) => `u${index + 1}`));
    const fresh = [
      coverageRow(
        "appsec",
        17,
        0,
        [...retried].map((unitId) => ({ unitId, reason: "batch-failed: quota" })),
      ),
    ];

    const recomposed = recomposeCoverage(previous, retried, fresh);

    expect(recomposed[0]?.unitsTotal).toBe(17);
    expect(recomposed[0]?.unitsAudited).toBe(16);
    expect(recomposed[0]?.skipped.map((entry) => entry.unitId)).toEqual(["u17"]);
  });

  test("a failed retry cannot reword an existing verdict into a skip in the kind table", () => {
    const recomposed = recomposeKinds(
      [
        {
          kind: "migration",
          unitsTotal: 13,
          unitsAudited: 12,
          skipped: [
            { unitId: "m13", reason: "no-verdict: the agent returned no verdict for this unit" },
          ],
        },
      ],
      new Set(Array.from({ length: 13 }, (_, index) => `m${index + 1}`)),
      [
        {
          kind: "migration",
          unitsTotal: 13,
          unitsAudited: 0,
          skipped: Array.from({ length: 13 }, (_, index) => ({
            unitId: `m${index + 1}`,
            reason: "batch-failed: no reply within 240000ms",
          })),
        },
      ],
    );

    expect(recomposed[0]?.unitsAudited).toBe(12);
    expect(recomposed[0]?.skipped).toEqual([
      { unitId: "m13", reason: "batch-failed: no reply within 240000ms" },
    ]);
  });

  test("the per-kind table recomposes the same way", () => {
    const recomposed = recomposeKinds(
      [
        {
          kind: "route",
          unitsTotal: 5,
          unitsAudited: 3,
          skipped: [
            { unitId: "a", reason: "batch-failed: timeout" },
            { unitId: "b", reason: "batch-failed: timeout" },
          ],
        },
      ],
      new Set(["a", "b"]),
      [{ kind: "route", unitsTotal: 2, unitsAudited: 2, skipped: [] }],
    );
    expect(recomposed[0]).toEqual({ kind: "route", unitsTotal: 5, unitsAudited: 5, skipped: [] });
  });

  test("unit totals are re-derived from the kind table, with the cause of each skip", () => {
    const totals = recomposeUnitTotals([
      {
        kind: "route",
        unitsTotal: 4,
        unitsAudited: 3,
        skipped: [{ unitId: "a", reason: "inconclusive: declined" }],
      },
      {
        kind: "data-access",
        unitsTotal: 2,
        unitsAudited: 1,
        skipped: [{ unitId: "b", reason: "batch-failed: the dispatch timed out" }],
      },
    ]);

    expect(totals.total).toBe(6);
    expect(totals.audited).toBe(4);
    expect(totals.skipped).toBe(2);
    expect(totals.byCause.inconclusive).toBe(1);
    expect(totals.byCause["batch-failed"]).toBe(1);
  });

  test("phase 1's coverage is recovered by subtracting the audit's from the merged table", () => {
    const merged = [coverageRow("appsec", 7, 6, [{ unitId: "u1", reason: "inconclusive: x" }])];
    const audit = [coverageRow("appsec", 4, 3, [{ unitId: "u1", reason: "inconclusive: x" }])];
    const scan = subtractCoverage(merged, audit);

    expect(scan[0]?.unitsTotal).toBe(3);
    expect(scan[0]?.unitsAudited).toBe(3);
    expect(scan[0]?.skipped).toEqual([]);
  });
});

describe("mergeRetryIntoAudit", () => {
  test("keeps the batches it did not retry and replaces the ones it did", () => {
    const previous = auditReport({
      batches: [
        batchReport({ batchId: "ok-1" }),
        batchReport({ batchId: "bad-1", status: "failed", reason: "timed out" }),
      ],
      coverage: [
        coverageRow("appsec", 8, 4, [
          { unitId: "u1", reason: "batch-failed: timed out" },
          { unitId: "u2", reason: "batch-failed: timed out" },
          { unitId: "u3", reason: "batch-failed: timed out" },
          { unitId: "u4", reason: "batch-failed: timed out" },
        ]),
      ],
      kinds: [
        {
          kind: "route",
          unitsTotal: 8,
          unitsAudited: 4,
          skipped: [
            { unitId: "u1", reason: "batch-failed: timed out" },
            { unitId: "u2", reason: "batch-failed: timed out" },
            { unitId: "u3", reason: "batch-failed: timed out" },
            { unitId: "u4", reason: "batch-failed: timed out" },
          ],
        },
      ],
    });
    const base = findingsDocument({
      findings: [finding({ id: "old", source: { kind: "agent", name: "audit" } })],
      coverage: [
        coverageRow("appsec", 8, 4, [
          { unitId: "u1", reason: "batch-failed: timed out" },
          { unitId: "u2", reason: "batch-failed: timed out" },
          { unitId: "u3", reason: "batch-failed: timed out" },
          { unitId: "u4", reason: "batch-failed: timed out" },
        ]),
      ],
    });
    const merged = mergeRetryIntoAudit(previous, base, {
      report: auditReport({
        batches: [batchReport({ batchId: "retry-1", units: 4, verdicts: 4 })],
        coverage: [coverageRow("appsec", 4, 4)],
        kinds: [{ kind: "route", unitsTotal: 4, unitsAudited: 4, skipped: [] }],
        usage: {
          inputTokens: 1,
          outputTokens: 2,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
          costUsd: 0.25,
        },
      }),
      findings: [finding({ id: "new" })],
      assurances: [assurance({ id: "a-new" })],
      replacedBatchIds: ["bad-1"],
      retriedUnitIds: ["u1", "u2", "u3", "u4"],
    });

    expect(merged.audit.batches.map((batch) => batch.batchId)).toEqual(["ok-1", "retry-1"]);
    expect(merged.audit.coverage[0]?.unitsTotal).toBe(8);
    expect(merged.audit.coverage[0]?.unitsAudited).toBe(8);
    expect(merged.audit.units).toEqual({
      total: 8,
      audited: 8,
      skipped: 0,
      byCause: {
        "no-batch": 0,
        "batch-failed": 0,
        "no-verdict": 0,
        inconclusive: 0,
        cancelled: 0,
        budget: 0,
      },
    });
    expect(merged.audit.usage.costUsd).toBeCloseTo(0.75, 5);
    expect(merged.findings.findings.map((entry) => entry.id).sort()).toEqual(["new", "old"]);
    expect(merged.audit.findingsKept).toBe(2);
  });

  test("a finding the previous attempt reported and this one did not is kept", () => {
    const previous = auditReport();
    const base = findingsDocument({ findings: [finding({ id: "old" })] });
    const merged = mergeRetryIntoAudit(previous, base, {
      report: auditReport({ batches: [] }),
      findings: [],
      assurances: [],
      replacedBatchIds: ["route-aaaa"],
      retriedUnitIds: [],
    });
    expect(merged.findings.findings.map((entry) => entry.id)).toEqual(["old"]);
  });

  /**
   * A retry's own outcome is not the run's.
   *
   * When a quota stop kills batches and the retry re-plans under a ceiling those
   * batches are not inside, the retry can re-dispatch other units cleanly and
   * come back `aborted: false, quotaExhausted: false` while the original units
   * still have no verdict. Taking those two flags as the whole run's is how a run
   * comes to announce itself shareable with a whole unit kind unaudited.
   */
  test("a retry that left units unreached does not clear the run's incompleteness", () => {
    const previous = auditReport({
      aborted: true,
      quotaExhausted: true,
      batches: [batchReport({ batchId: "bad-1", status: "failed", reason: "rate limit" })],
      coverage: [
        coverageRow("delivery", 4, 0, [
          { unitId: "w1", reason: "batch-failed: rate limit" },
          { unitId: "w2", reason: "batch-failed: rate limit" },
          { unitId: "w3", reason: "batch-failed: rate limit" },
          { unitId: "w4", reason: "batch-failed: rate limit" },
        ]),
      ],
      kinds: [
        {
          kind: "workflow-job",
          unitsTotal: 4,
          unitsAudited: 0,
          skipped: [
            { unitId: "w1", reason: "batch-failed: rate limit" },
            { unitId: "w2", reason: "batch-failed: rate limit" },
            { unitId: "w3", reason: "batch-failed: rate limit" },
            { unitId: "w4", reason: "batch-failed: rate limit" },
          ],
        },
      ],
    });
    // A clean retry of something else entirely: it never names `bad-1`, because a
    // fresh plan did not hold it.
    const merged = mergeRetryIntoAudit(previous, findingsDocument(), {
      report: auditReport({
        aborted: false,
        quotaExhausted: false,
        batches: [batchReport({ batchId: "retry-1", units: 2, verdicts: 2 })],
        coverage: [coverageRow("appsec", 2, 2)],
        kinds: [{ kind: "route", unitsTotal: 2, unitsAudited: 2, skipped: [] }],
      }),
      findings: [],
      assurances: [],
      replacedBatchIds: [],
      retriedUnitIds: ["r1", "r2"],
    });

    expect(merged.audit.units.byCause["batch-failed"]).toBe(4);
    // The two flags `describeRunPhases` reads to call the phase `partial`.
    expect(merged.audit.aborted).toBe(true);
    expect(merged.audit.quotaExhausted).toBe(true);
    // And the failed batch's own record, the third signal, survives.
    expect(merged.audit.batches.map((batch) => batch.batchId).sort()).toEqual(["bad-1", "retry-1"]);
  });

  test("the bound is recomposed, so the cover cannot contradict the coverage table", () => {
    // Regression: a bound carried over from the first attempt untouched makes the
    // cover and section 4 quote that attempt's "N of M units were not audited"
    // directly above a table the same merge has just recomposed to a smaller
    // number.
    const previous = auditReport({
      bound: {
        ...unboundedBound(10, 2),
        stop: "quota",
        statement: "8 of 10 units were not audited: the usage limit was reached",
      },
      coverage: [
        coverageRow("appsec", 10, 2, [
          { unitId: "u1", reason: "batch-failed: rate limit" },
          { unitId: "u2", reason: "batch-failed: rate limit" },
        ]),
      ],
      kinds: [
        {
          kind: "route",
          unitsTotal: 10,
          unitsAudited: 8,
          skipped: [
            { unitId: "u1", reason: "batch-failed: rate limit" },
            { unitId: "u2", reason: "batch-failed: rate limit" },
          ],
        },
      ],
    });
    const merged = mergeRetryIntoAudit(previous, findingsDocument(), {
      report: auditReport({
        bound: unboundedBound(2, 2),
        batches: [batchReport({ batchId: "retry-1", units: 2, verdicts: 2 })],
        coverage: [coverageRow("appsec", 2, 2)],
        kinds: [{ kind: "route", unitsTotal: 2, unitsAudited: 2, skipped: [] }],
      }),
      findings: [],
      assurances: [],
      replacedBatchIds: [],
      retriedUnitIds: ["u1", "u2"],
    });

    // The retry reached both, so nothing is missing and the sentence says so
    // instead of repeating the first attempt's eight.
    expect(merged.audit.units.audited).toBe(10);
    expect(merged.audit.bound.unitsAudited).toBe(10);
    expect(merged.audit.bound.unitsTotal).toBe(10);
    expect(merged.audit.bound.statement).not.toContain("8 of 10");
    expect(merged.audit.bound.statement).toContain("all 10 units were audited");
  });

  test("a retry that reached everything does clear the flags", () => {
    const previous = auditReport({
      aborted: true,
      quotaExhausted: true,
      batches: [batchReport({ batchId: "bad-1", status: "failed", reason: "rate limit" })],
      coverage: [
        coverageRow("appsec", 2, 0, [
          { unitId: "u1", reason: "batch-failed: rate limit" },
          { unitId: "u2", reason: "batch-failed: rate limit" },
        ]),
      ],
      kinds: [
        {
          kind: "route",
          unitsTotal: 2,
          unitsAudited: 0,
          skipped: [
            { unitId: "u1", reason: "batch-failed: rate limit" },
            { unitId: "u2", reason: "batch-failed: rate limit" },
          ],
        },
      ],
    });
    const merged = mergeRetryIntoAudit(previous, findingsDocument(), {
      report: auditReport({
        aborted: false,
        quotaExhausted: false,
        batches: [batchReport({ batchId: "retry-1", units: 2, verdicts: 2 })],
        coverage: [coverageRow("appsec", 2, 2)],
        kinds: [{ kind: "route", unitsTotal: 2, unitsAudited: 2, skipped: [] }],
      }),
      findings: [],
      assurances: [],
      replacedBatchIds: ["bad-1"],
      retriedUnitIds: ["u1", "u2"],
    });

    expect(merged.audit.units.byCause["batch-failed"]).toBe(0);
    expect(merged.audit.aborted).toBe(false);
    expect(merged.audit.quotaExhausted).toBe(false);
  });
});

describe("subtractAuditFromFindings", () => {
  test("removes the agent's findings and the audit's coverage, keeping the analyzers'", () => {
    const previous = auditReport({ coverage: [coverageRow("appsec", 4, 4)] });
    const base = findingsDocument({
      findings: [
        finding({ id: "agent", source: { kind: "agent", name: "audit" } }),
        finding({ id: "tool", source: { kind: "tool", name: "trivy" } }),
      ],
      assurances: [assurance({ id: "a1" })],
      coverage: [coverageRow("appsec", 6, 6)],
      droppedFindings: 3,
    });
    const stripped = subtractAuditFromFindings(base, previous);

    expect(stripped.findings.map((entry) => entry.id)).toEqual(["tool"]);
    expect(stripped.assurances).toEqual([]);
    expect(stripped.coverage[0]?.unitsTotal).toBe(2);
    expect(stripped.droppedFindings).toBe(3);
  });
});

describe("batch selection", () => {
  test("only failed and partial batches are retryable", () => {
    const report = auditReport({
      batches: [
        batchReport({ batchId: "ok" }),
        batchReport({ batchId: "failed", status: "failed" }),
        batchReport({ batchId: "partial", status: "partial" }),
      ],
    });
    expect(retryableBatchIds(report)).toEqual(["failed", "partial"]);
    expect(retryableBatchIds(null)).toEqual([]);
  });

  test("resolves batch ids to the unit ids behind them", () => {
    const unit = (id: string) => ({
      id,
      kind: "route" as const,
      label: `GET /${id}`,
      location: { file: `src/api/${id}.ts`, line: 1 },
      attributes: {},
    });
    const planned = [
      { id: "a", units: [unit("u1"), unit("u2")] },
      { id: "b", units: [unit("u3")] },
    ];
    expect(unitIdsOfBatches(planned, new Set(["a"]))).toEqual(["u1", "u2"]);
    expect(unitIdsOfBatches(planned, new Set(["missing"]))).toEqual([]);
  });
});

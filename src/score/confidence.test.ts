import { describe, expect, test } from "bun:test";
import {
  auditSignals,
  batchReport,
  finding,
  findings,
  scanSignals,
  stepReport,
} from "./__fixtures__/factories.ts";
import {
  LOW_PENALTY,
  auditedRatio,
  buildConfidence,
  cleanConfidenceBasis,
  confidenceBasisFrom,
  confidenceSignals,
  levelFor,
} from "./confidence.ts";

describe("high is reachable", () => {
  test("a full clean run, built from the shapes the phases really write, is high", () => {
    const basis = confidenceBasisFrom({
      audit: auditSignals(),
      scan: scanSignals(),
      findings: findings(12, { severity: "low" }),
    });
    const confidence = buildConfidence(basis);

    expect(confidence.level).toBe("high");
    expect(confidence.penalty).toBe(0);
    expect(confidence.signals).toEqual([]);
    expect(confidence.statement).toContain("every enumerated unit was audited");
  });

  test("a scan-only run with no audit phase is high too, not punished for it", () => {
    const basis = confidenceBasisFrom({ scan: scanSignals(), findings: [] });
    expect(buildConfidence(basis).level).toBe("high");
    expect(auditedRatio(basis)).toBe(1);
  });

  test("the empty basis is the high baseline", () => {
    expect(buildConfidence(cleanConfidenceBasis()).level).toBe("high");
  });
});

describe("the levels", () => {
  test("map penalties the way the table in this module states", () => {
    expect(levelFor(0)).toBe("high");
    expect(levelFor(1)).toBe("medium");
    expect(levelFor(3)).toBe("medium");
    expect(levelFor(LOW_PENALTY)).toBe("low");
    expect(levelFor(9)).toBe("low");
  });
});

describe("the signals", () => {
  test("cost more the more units came back without a verdict", () => {
    const penaltyAt = (audited: number) =>
      buildConfidence(
        confidenceBasisFrom({
          audit: auditSignals({
            units: {
              total: 100,
              audited,
              skipped: 100 - audited,
              byCause: {
                "no-batch": 0,
                "batch-failed": 0,
                "no-verdict": 0,
                inconclusive: 100 - audited,
                cancelled: 0,
                budget: 0,
              },
            },
          }),
        }),
      ).penalty;
    expect(penaltyAt(99)).toBe(0);
    expect(penaltyAt(95)).toBe(1);
    expect(penaltyAt(80)).toBe(2);
    expect(penaltyAt(50)).toBe(3);
  });

  test("charge more for a partial batch when more than a quarter of them are partial", () => {
    const fewPartial = confidenceSignals(
      confidenceBasisFrom({
        audit: auditSignals({
          batches: [
            ...Array.from({ length: 7 }, () => batchReport()),
            batchReport({ status: "partial" }),
          ],
        }),
      }),
    );
    const manyPartial = confidenceSignals(
      confidenceBasisFrom({
        audit: auditSignals({
          batches: [
            batchReport(),
            batchReport({ status: "partial" }),
            batchReport({ status: "partial" }),
          ],
        }),
      }),
    );
    expect(fewPartial.find((signal) => signal.id === "batches.partial")?.penalty).toBe(1);
    expect(manyPartial.find((signal) => signal.id === "batches.partial")?.penalty).toBe(2);
  });

  test("name a failed batch, a relocated citation and a degraded analyzer", () => {
    const basis = confidenceBasisFrom({
      audit: auditSignals({
        batches: [batchReport({ status: "failed", failure: "timeout" })],
        dropped: { ...auditSignals().dropped, relocated: 3 },
      }),
      scan: scanSignals({
        steps: [stepReport(), stepReport({ step: "trivy-db", status: "degraded" })],
      }),
    });
    const ids = confidenceSignals(basis).map((signal) => signal.id);
    expect(ids).toContain("batches.failed");
    expect(ids).toContain("citations.relocated");
    expect(ids).toContain("analyzers.degraded");
    expect(buildConfidence(basis).level).toBe("low");
  });

  test("charge for dropped claims only when they are a real share of what was claimed", () => {
    const dropped = (count: number, kept: number) =>
      confidenceSignals(
        confidenceBasisFrom({
          audit: auditSignals({ dropped: { ...auditSignals().dropped, unresolved: count } }),
          findings: findings(kept, { severity: "info" }),
        }),
      ).map((signal) => signal.id);
    expect(dropped(1, 100)).not.toContain("citations.dropped");
    expect(dropped(10, 50)).toContain("citations.dropped");
  });

  test("charge when most findings are leads rather than facts", () => {
    const leads = [
      finding({ id: "a", confidence: "low" }),
      finding({ id: "b", confidence: "low" }),
      finding({ id: "c" }),
    ];
    const ids = confidenceSignals(confidenceBasisFrom({ findings: leads })).map((s) => s.id);
    expect(ids).toContain("findings.low-confidence");
  });

  test("a synthetic runtime is low on its own, whatever else went right", () => {
    const basis = confidenceBasisFrom({
      audit: auditSignals({ runtime: { ...auditSignals().runtime, synthetic: true } }),
      scan: scanSignals(),
    });
    const confidence = buildConfidence(basis);
    expect(confidence.level).toBe("low");
    expect(confidence.signals.map((signal) => signal.id)).toEqual(["runtime.synthetic"]);
    expect(confidence.statement).toContain("recorded transcript");
  });

  test("an aborted or quota-stopped run says so", () => {
    const aborted = confidenceSignals(
      confidenceBasisFrom({ audit: auditSignals({ aborted: true, quotaExhausted: true }) }),
    ).map((signal) => signal.id);
    expect(aborted).toContain("run.aborted");
    expect(aborted).toContain("run.quota-exhausted");
  });

  test("puts the numbers that prove each signal in the sentence", () => {
    const basis = confidenceBasisFrom({
      audit: auditSignals({
        units: {
          total: 172,
          audited: 160,
          skipped: 12,
          byCause: {
            "no-batch": 0,
            "batch-failed": 0,
            "no-verdict": 0,
            inconclusive: 12,
            cancelled: 0,
            budget: 0,
          },
        },
      }),
    });
    expect(confidenceSignals(basis)[0]?.detail).toBe(
      "160 of 172 enumerated units came back with a verdict (93%)",
    );
  });
});

describe("the basis", () => {
  test("echoes the counters so the report can print them instead of the word", () => {
    const basis = confidenceBasisFrom({
      audit: auditSignals(),
      scan: scanSignals(),
      findings: findings(4, { severity: "low" }),
    });
    expect(basis.unitsTotal).toBe(40);
    expect(basis.unitsAudited).toBe(40);
    expect(basis.batchesTotal).toBe(2);
    expect(basis.analyzersTotal).toBe(3);
    expect(basis.findingsTotal).toBe(4);
    expect(basis.synthetic).toBe(false);
  });
});

/**
 * Minimal, valid inputs for the score tests.
 *
 * Every factory returns a document that would survive its own contract schema,
 * so a test that wants a `critical` appsec finding says exactly that and
 * inherits a real shape for everything else. The defaults are deliberately
 * boring: one finding, one line, high confidence — a test that cares about a
 * field overrides it and the override is the whole test.
 */

import type { BatchReport } from "../../audit/artifacts.ts";
import { BatchReportSchema } from "../../audit/artifacts.ts";
import type { Assurance, Coverage, Domain, Finding, Severity } from "../../contracts/findings.ts";
import { AssuranceSchema, CoverageSchema, FindingSchema } from "../../contracts/findings.ts";
import type { DomainScore } from "../../contracts/scorecard.ts";
import { DomainScoreSchema } from "../../contracts/scorecard.ts";
import type { StepReport } from "../../scan/artifacts.ts";
import { StepReportSchema } from "../../scan/artifacts.ts";
import { bandFor, bandLabel } from "../bands.ts";
import type { AuditSignalSource, ScanSignalSource } from "../confidence.ts";
import type { AuditUnitSource, EvidenceInput, InventorySignalSource } from "../evidence.ts";
import { evidenceFrom } from "../evidence.ts";
import { DOMAIN_WEIGHTS, effectiveWeight } from "../overall.ts";

/** A valid finding, defaulting to a medium appsec one from the audit agent. */
export function finding(overrides: Partial<Finding> = {}): Finding {
  const domain: Domain = overrides.domain ?? "appsec";
  const severity: Severity = overrides.severity ?? "medium";
  return FindingSchema.parse({
    id: `${domain}-${severity}-${overrides.rule ?? "rule"}-${overrides.title ?? "t"}`,
    domain,
    rule: `${domain}.example-rule`,
    severity,
    confidence: "high",
    title: "An example finding",
    description: "What the code does and why that is wrong.",
    location: { file: "src/example.ts", line: 10 },
    evidence: [],
    impact: "What it costs if nobody fixes it.",
    recommendation: "What to do about it.",
    acceptanceCriteria: [],
    cwe: [],
    owasp: [],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  });
}

/** `count` findings of one severity in one domain, with distinct ids. */
export function findings(count: number, overrides: Partial<Finding> = {}): Finding[] {
  return Array.from({ length: count }, (_, index) =>
    finding({ ...overrides, id: `${overrides.id ?? "f"}-${index}`, title: `Finding ${index}` }),
  );
}

/** A coverage row; `unitsTotal` and `unitsAudited` are what most tests vary. */
export function coverage(overrides: Partial<Coverage> = {}): Coverage {
  return CoverageSchema.parse({
    domain: "appsec",
    unitsTotal: 10,
    unitsAudited: 10,
    skipped: [],
    ...overrides,
  });
}

/** An assurance: a check that ran and passed, with the units it covered. */
export function assurance(overrides: Partial<Assurance> = {}): Assurance {
  return AssuranceSchema.parse({
    id: `assurance-${overrides.check ?? "check"}`,
    domain: "appsec",
    check: "authorization is enforced by the handler itself",
    scope: "10/10 route handlers",
    unitsChecked: 10,
    evidence: [],
    ...overrides,
  });
}

/** A batch line as `audit.json` records it; `status` is what most tests vary. */
export function batchReport(overrides: Partial<BatchReport> = {}): BatchReport {
  return BatchReportSchema.parse({
    batchId: "route-000000000001",
    domain: "appsec",
    kinds: ["route"],
    units: 10,
    status: "audited",
    attempts: 1,
    verdicts: 10,
    findings: 0,
    durationMs: 1000,
    transcripts: [],
    ...overrides,
  });
}

/** An analyzer line as `scan-report.json` records it. */
export function stepReport(overrides: Partial<StepReport> = {}): StepReport {
  return StepReportSchema.parse({
    step: "trivy",
    status: "ok",
    findings: 0,
    artifacts: [],
    durationMs: 100,
    ...overrides,
  });
}

/**
 * The slice of `audit.json` confidence reads, defaulting to a clean live run:
 * every unit audited, every batch complete, nothing dropped or relocated.
 */
export function auditSignals(
  overrides: Partial<AuditSignalSource & AuditUnitSource> = {},
): AuditSignalSource & AuditUnitSource {
  return {
    kinds: [
      { kind: "route", unitsTotal: 20, unitsAudited: 20, skipped: [] },
      { kind: "data-access", unitsTotal: 20, unitsAudited: 20, skipped: [] },
    ],
    units: {
      total: 40,
      audited: 40,
      skipped: 0,
      byCause: {
        "no-batch": 0,
        "batch-failed": 0,
        "no-verdict": 0,
        inconclusive: 0,
        cancelled: 0,
        budget: 0,
      },
    },
    batches: [batchReport(), batchReport({ batchId: "data-000000000002", domain: "data" })],
    dropped: {
      unresolved: 0,
      unresolvedEvidence: 0,
      outOfSlice: 0,
      outOfSliceEvidence: 0,
      duplicates: 0,
      relocated: 0,
      strayVerdicts: 0,
      assuranceEvidence: 0,
      byReason: {},
    },
    runtime: {
      kind: "claude-agent-sdk",
      concurrency: 2,
      maxAttempts: 3,
      timeoutMs: 240_000,
      synthetic: false,
    },
    aborted: false,
    quotaExhausted: false,
    ...overrides,
  };
}

/** The slice of `inventory.json` the evidence gate reads; `counts` is the whole of it. */
export function inventorySignals(
  counts: InventorySignalSource["counts"] = {},
): InventorySignalSource {
  return { counts };
}

/**
 * The evidence gate's input, built the way the score phase builds it.
 *
 * `enumerated` is what phase 2 found; `audit` is phase 4's per-kind coverage, or
 * left out for the `--no-ai` run that is the whole reason this gate exists.
 */
export function evidenceInput(
  enumerated: InventorySignalSource["counts"],
  audit?: AuditUnitSource,
): EvidenceInput {
  return evidenceFrom({
    inventory: inventorySignals(enumerated),
    ...(audit === undefined ? {} : { audit }),
  });
}

/** The slice of `scan-report.json` confidence reads, defaulting to a clean run. */
export function scanSignals(overrides: Partial<ScanSignalSource> = {}): ScanSignalSource {
  return {
    steps: [stepReport(), stepReport({ step: "gitleaks" }), stepReport({ step: "knip" })],
    relocated: 0,
    dropped: { findings: 0, evidence: 0, byReason: {} },
    aborted: false,
    ...overrides,
  };
}

/**
 * A scored domain row, the shape `buildOverall` consumes. `domain`, `score`,
 * `status` and the coverage ratio are what the overall tests vary; the weight
 * follows from the domain and the effective weight from the coverage, exactly
 * as the real assembler computes them.
 */
export function domainScore(
  overrides: Partial<DomainScore> & { readonly coverageRatio?: number } = {},
): DomainScore {
  const domain: Domain = overrides.domain ?? "appsec";
  const score = overrides.score === undefined ? 80 : overrides.score;
  const ratio = overrides.coverageRatio ?? 1;
  const unitsTotal = 10;
  const unitsAudited = Math.round(unitsTotal * ratio);
  const { coverageRatio: _ratio, ...rest } = overrides;

  return DomainScoreSchema.parse({
    domain,
    status: score === null ? "not-assessed" : ratio >= 0.9 ? "scored" : "partial",
    score,
    band: score === null ? null : bandFor(score),
    bandLabel: score === null ? null : bandLabel(bandFor(score)),
    baseScore: score,
    coverage: {
      unitsTotal,
      unitsAudited,
      skipped: unitsTotal - unitsAudited,
      ratio,
      statement: `${unitsAudited} of ${unitsTotal} checks ran`,
    },
    // The default row has no audit units, so the checks carry it: a test that
    // wants the evidence gate to bite says so by overriding `evidence`.
    evidence: {
      applies: false,
      unitsPresent: 0,
      unitsVerdicted: 0,
      ratio: 0,
      kinds: [],
      statement: "no audit unit belongs to this domain",
    },
    assessedRatio: ratio,
    deductions: [],
    deductionTotal: 0,
    ceilings: [],
    findingsTotal: 0,
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    assurances: 0,
    assuranceUnits: 0,
    weight: DOMAIN_WEIGHTS[domain],
    effectiveWeight: score === null ? 0 : effectiveWeight(domain, ratio),
    statement:
      score === null ? "not assessed: nothing ran" : `${unitsAudited} of ${unitsTotal} checks ran`,
    ...rest,
  });
}

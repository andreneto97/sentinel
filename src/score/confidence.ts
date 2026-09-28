/**
 * Run-level confidence, derived from what the run actually did.
 *
 * Confidence is not a mood. Every level here comes out of counters other phases
 * already wrote down: how many enumerated units came back with a verdict, how
 * many batches returned partial or failed outright, how many citations the
 * verifier had to move or throw away, how many analyzers ran degraded, and
 * whether the answers came from a live model at all. Each signal carries its
 * own penalty and its own sentence, and the level is a threshold on the sum:
 *
 * | penalty | level |
 * |---|---|
 * | 0 | `high` |
 * | 1–3 | `medium` |
 * | 4+ | `low` |
 *
 * **`high` is reachable and is meant to be reached.** A run that audits every
 * unit it enumerated, loses no batch, relocates no citation and degrades no
 * analyzer scores zero penalty and says `high` — `confidence.test.ts` proves it
 * with the shape of a real clean run rather than with a hand-set field. A
 * confidence that could never be earned would be the same lie as a score that
 * could never be lost.
 *
 * One signal is categorical rather than proportional: a synthetic runtime — a
 * recorded or handwritten transcript — is on its own enough to take the run to
 * `low`, because a green replay is a wiring guard and not evidence about the
 * code.
 */

import type { AuditReport } from "../audit/artifacts.ts";
import type { Confidence, Finding } from "../contracts/findings.ts";
import {
  type ConfidenceBasis,
  ConfidenceBasisSchema,
  type ConfidenceSignal,
  type RunConfidence,
  RunConfidenceSchema,
} from "../contracts/scorecard.ts";
import type { ScanReport } from "../scan/artifacts.ts";

/** Penalty at or above which the run is `low`. */
export const LOW_PENALTY = 4;

/** Penalty above which the run is no longer `high`. */
export const MEDIUM_PENALTY = 1;

/** The counters confidence is computed from; {@link confidenceBasisFrom} fills it. */
export type ConfidenceInput = ConfidenceBasis;

/** A clean run: everything audited, nothing lost. The `high` baseline. */
export function cleanConfidenceBasis(): ConfidenceInput {
  return ConfidenceBasisSchema.parse({
    unitsTotal: 0,
    unitsAudited: 0,
    batchesTotal: 0,
    batchesPartial: 0,
    batchesFailed: 0,
    relocatedCitations: 0,
    droppedCitations: 0,
    analyzersTotal: 0,
    analyzersDegraded: 0,
    findingsTotal: 0,
    lowConfidenceFindings: 0,
    synthetic: false,
    aborted: false,
    quotaExhausted: false,
  });
}

/** The slice of `audit.json` confidence reads. `AuditReport` satisfies it. */
export type AuditSignalSource = Pick<
  AuditReport,
  "units" | "batches" | "dropped" | "runtime" | "aborted" | "quotaExhausted"
>;

/** The slice of `scan-report.json` confidence reads. `ScanReport` satisfies it. */
export type ScanSignalSource = Pick<ScanReport, "steps" | "relocated" | "dropped" | "aborted">;

/**
 * Folds the two phase reports and the findings into the counters.
 *
 * Both reports are optional: a scan-only run has no `audit.json`, and an
 * audit-only run has no `scan-report.json`. What is missing contributes
 * nothing rather than counting as a failure — a phase that did not run is a
 * coverage fact, and coverage is scored per domain, not here.
 */
export function confidenceBasisFrom(input: {
  readonly audit?: AuditSignalSource | undefined;
  readonly scan?: ScanSignalSource | undefined;
  readonly findings?: readonly Finding[] | undefined;
}): ConfidenceInput {
  const { audit, scan, findings = [] } = input;
  const batches = audit?.batches ?? [];
  const steps = scan?.steps ?? [];

  return ConfidenceBasisSchema.parse({
    unitsTotal: audit?.units.total ?? 0,
    unitsAudited: audit?.units.audited ?? 0,
    batchesTotal: batches.length,
    batchesPartial: batches.filter((batch) => batch.status === "partial").length,
    batchesFailed: batches.filter((batch) => batch.status === "failed").length,
    relocatedCitations: (audit?.dropped.relocated ?? 0) + (scan?.relocated ?? 0),
    droppedCitations:
      (audit?.dropped.unresolved ?? 0) +
      (audit?.dropped.outOfSlice ?? 0) +
      (scan?.dropped.findings ?? 0),
    analyzersTotal: steps.length,
    analyzersDegraded: steps.filter(
      (step) => step.status === "degraded" || step.status === "failed",
    ).length,
    findingsTotal: findings.length,
    lowConfidenceFindings: findings.filter((finding) => finding.confidence === "low").length,
    synthetic: audit?.runtime.synthetic ?? false,
    aborted: (audit?.aborted ?? false) || (scan?.aborted ?? false),
    quotaExhausted: audit?.quotaExhausted ?? false,
  });
}

/** `93%`, for the signal sentences. */
function percent(ratio: number): string {
  return `${Math.round(ratio * 100)}%`;
}

/** How much of what was enumerated came back with a verdict; `1` when nothing was. */
export function auditedRatio(basis: ConfidenceInput): number {
  return basis.unitsTotal === 0 ? 1 : Math.min(1, basis.unitsAudited / basis.unitsTotal);
}

/** What the units that never got a verdict cost: more missing, more penalty. */
function unitSignal(basis: ConfidenceInput): ConfidenceSignal | null {
  const ratio = auditedRatio(basis);
  if (ratio >= 0.98) return null;
  const penalty = ratio >= 0.9 ? 1 : ratio >= 0.75 ? 2 : 3;
  return {
    id: "units.partially-audited",
    detail: `${basis.unitsAudited} of ${basis.unitsTotal} enumerated units came back with a verdict (${percent(ratio)})`,
    penalty,
  };
}

/** Every signal that cost this run confidence, in a stable order. */
export function confidenceSignals(basis: ConfidenceInput): ConfidenceSignal[] {
  const signals: ConfidenceSignal[] = [];
  const units = unitSignal(basis);
  if (units !== null) signals.push(units);

  if (basis.batchesPartial > 0) {
    const share = basis.batchesTotal === 0 ? 0 : basis.batchesPartial / basis.batchesTotal;
    signals.push({
      id: "batches.partial",
      detail: `${basis.batchesPartial} of ${basis.batchesTotal} audit batches answered about only some of their units`,
      penalty: share > 0.25 ? 2 : 1,
    });
  }

  if (basis.batchesFailed > 0) {
    signals.push({
      id: "batches.failed",
      detail: `${basis.batchesFailed} of ${basis.batchesTotal} audit batches produced no usable reply`,
      penalty: 2,
    });
  }

  if (basis.relocatedCitations > 0) {
    signals.push({
      id: "citations.relocated",
      detail: `${basis.relocatedCitations} citations had to be moved to match the code on disk`,
      penalty: 1,
    });
  }

  const claimed = basis.findingsTotal + basis.droppedCitations;
  if (basis.droppedCitations > 0 && claimed > 0 && basis.droppedCitations / claimed > 0.05) {
    signals.push({
      id: "citations.dropped",
      detail: `${basis.droppedCitations} claims were dropped because their citation did not resolve or fell outside the code the agent was shown`,
      penalty: 1,
    });
  }

  if (basis.analyzersDegraded > 0) {
    signals.push({
      id: "analyzers.degraded",
      detail: `${basis.analyzersDegraded} of ${basis.analyzersTotal} analyzers ran degraded or failed`,
      penalty: Math.min(2, basis.analyzersDegraded),
    });
  }

  if (basis.findingsTotal > 0 && basis.lowConfidenceFindings / basis.findingsTotal > 0.25) {
    signals.push({
      id: "findings.low-confidence",
      detail: `${basis.lowConfidenceFindings} of ${basis.findingsTotal} findings are low-confidence leads rather than confirmed facts`,
      penalty: 1,
    });
  }

  if (basis.quotaExhausted) {
    signals.push({
      id: "run.quota-exhausted",
      detail: "a subscription limit stopped the audit phase before it ran out of work",
      penalty: 2,
    });
  }

  if (basis.aborted) {
    signals.push({
      id: "run.aborted",
      detail: "the run was cancelled before every step finished",
      penalty: 3,
    });
  }

  if (basis.synthetic) {
    signals.push({
      id: "runtime.synthetic",
      detail:
        "the audit answers came from a recorded transcript, not from a live model, so they are a wiring guard and not evidence about this code",
      penalty: LOW_PENALTY,
    });
  }

  return signals;
}

/** The level a penalty total earns. */
export function levelFor(penalty: number): Confidence {
  if (penalty >= LOW_PENALTY) return "low";
  return penalty >= MEDIUM_PENALTY ? "medium" : "high";
}

/** The sentence the report prints under the level. */
function statementFor(level: Confidence, signals: readonly ConfidenceSignal[]): string {
  if (signals.length === 0) {
    return `${level}: every enumerated unit was audited, every batch returned, no citation was relocated and no analyzer degraded`;
  }
  return `${level}: ${signals.map((signal) => signal.detail).join("; ")}`;
}

/** Derives the run's confidence from its counters. Pure, and total. */
export function buildConfidence(basis: ConfidenceInput): RunConfidence {
  const signals = confidenceSignals(basis);
  const penalty = signals.reduce((sum, signal) => sum + signal.penalty, 0);
  const level = levelFor(penalty);
  return RunConfidenceSchema.parse({
    level,
    penalty,
    signals,
    basis,
    statement: statementFor(level, signals),
  });
}

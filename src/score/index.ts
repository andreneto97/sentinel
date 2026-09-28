/** Phase 6: turn findings, assurances and coverage into a defensible number. */
export {
  BAND_TABLE,
  BANDS,
  NOT_ASSESSED_LABEL,
  bandFor,
  bandLabel,
  describeScore,
} from "./bands.ts";
export type { BandDefinition } from "./bands.ts";
export {
  SCORE_CEILINGS,
  UNEXAMINED_EVIDENCE_CAP,
  applyCeilings,
  canFireCeiling,
  capsScore,
  evidenceCeiling,
} from "./ceilings.ts";
export type { ScoreCeiling } from "./ceilings.ts";
export {
  LOW_PENALTY,
  MEDIUM_PENALTY,
  auditedRatio,
  buildConfidence,
  cleanConfidenceBasis,
  confidenceBasisFrom,
  confidenceSignals,
  levelFor,
} from "./confidence.ts";
export type { AuditSignalSource, ConfidenceInput, ScanSignalSource } from "./confidence.ts";
export {
  PARTIAL_COVERAGE,
  SCORED_COVERAGE,
  gateDomain,
  statusForEvidence,
} from "./coverage-gate.ts";
export type { GateResult } from "./coverage-gate.ts";
export {
  UNIT_KINDS_BY_DOMAIN,
  describeExamined,
  describeUnits,
  domainEvidence,
  evidenceFrom,
  noEvidence,
} from "./evidence.ts";
export type {
  AuditUnitSource,
  EvidenceInput,
  InventorySignalSource,
  UnitEvidence,
} from "./evidence.ts";
export {
  LOW_CONFIDENCE_WEIGHT,
  SEVERITY_POLICY,
  baseScoreFrom,
  countBySeverity,
  computeDeductions,
  emptySeverityCounts,
  totalDeduction,
} from "./deductions.ts";
export type { SeverityPolicy } from "./deductions.ts";
export { DOMAIN_WEIGHTS, WORST_DOMAIN_HEADROOM, buildOverall, effectiveWeight } from "./overall.ts";
export { buildScorecard, buildScorecardFromArtifacts, scoreDomain } from "./scorecard.ts";
export type { ScorecardInput } from "./scorecard.ts";

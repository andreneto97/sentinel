import { z } from "zod";

/** Bumped on every breaking change to the artifacts written under a run dir. */
export const SCHEMA_VERSION = "1.0";

/** The eight analysis domains; every finding belongs to exactly one. */
export const DomainSchema = z.enum([
  "dependencies",
  "appsec",
  "data",
  "delivery",
  "serverless",
  "api",
  "reliability",
  "deadcode",
]);
export type Domain = z.infer<typeof DomainSchema>;

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const ConfidenceSchema = z.enum(["high", "medium", "low"]);
export type Confidence = z.infer<typeof ConfidenceSchema>;

/**
 * A pointer into the target repository. `snippet` is always extracted by
 * Sentinel from disk — never taken from model output — so a citation that
 * does not resolve cannot reach the report.
 */
export const CodeRefSchema = z.object({
  file: z.string(),
  line: z.number().int().positive(),
  endLine: z.number().int().positive().optional(),
  snippet: z.string().optional(),
  note: z.string().optional(),
});
export type CodeRef = z.infer<typeof CodeRefSchema>;

/** Where a finding came from: a tool, one of Sentinel's own rules, or an agent. */
export const FindingSourceSchema = z.object({
  kind: z.enum(["tool", "rule", "agent"]),
  name: z.string(),
});

export const FindingSchema = z.object({
  /** Stable across runs: hash of (domain, rule, file, symbol). */
  id: z.string(),
  domain: DomainSchema,
  /** Dotted rule id, e.g. "data.missing-index-on-fk". */
  rule: z.string(),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  title: z.string(),
  description: z.string(),
  location: CodeRefSchema,
  evidence: z.array(CodeRefSchema).default([]),
  /** Preconditions an attacker needs: flags, config, auth level, reachability. */
  exploitability: z.string().optional(),
  impact: z.string(),
  recommendation: z.string(),
  /** Verifiable checklist, rendered into the GitHub issue for this finding. */
  acceptanceCriteria: z.array(z.string()).default([]),
  cwe: z.array(z.string()).default([]),
  owasp: z.array(z.string()).default([]),
  source: FindingSourceSchema,
});
export type Finding = z.infer<typeof FindingSchema>;

/**
 * The mirror image of a finding: a check that ran and passed, with the
 * evidence that proves it. This is what lets the report say what is
 * protected instead of only what is broken.
 */
export const AssuranceSchema = z.object({
  id: z.string(),
  domain: DomainSchema,
  check: z.string(),
  scope: z.string(),
  unitsChecked: z.number().int().nonnegative(),
  evidence: z.array(CodeRefSchema).default([]),
});
export type Assurance = z.infer<typeof AssuranceSchema>;

/** A unit of audit produced by the inventory phase; coverage is counted in these. */
export const AuditUnitSchema = z.object({
  id: z.string(),
  kind: z.enum([
    "route",
    "data-access",
    "serverless-function",
    "queue-consumer",
    "cron",
    "webhook",
    "migration",
    "role-gate",
    "sink",
    "workflow-job",
    "container",
  ]),
  label: z.string(),
  location: CodeRefSchema,
  /** Kind-specific facts the audit prompt needs (method, path, table, trigger…). */
  attributes: z.record(z.string(), z.string()).default({}),
});
export type AuditUnit = z.infer<typeof AuditUnitSchema>;

/** Per-domain coverage, so a partial run can never read as a complete one. */
export const CoverageSchema = z.object({
  domain: DomainSchema,
  unitsTotal: z.number().int().nonnegative(),
  unitsAudited: z.number().int().nonnegative(),
  skipped: z.array(z.object({ unitId: z.string(), reason: z.string() })).default([]),
});
export type Coverage = z.infer<typeof CoverageSchema>;

export const FindingsDocumentSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  runId: z.string(),
  target: z.string(),
  findings: z.array(FindingSchema),
  assurances: z.array(AssuranceSchema),
  coverage: z.array(CoverageSchema),
  /** Findings dropped because their citation did not resolve on disk. */
  droppedFindings: z.number().int().nonnegative(),
});
export type FindingsDocument = z.infer<typeof FindingsDocumentSchema>;

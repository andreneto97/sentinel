import { z } from "zod";
import { DomainSchema, SCHEMA_VERSION } from "./findings.ts";

/** Whether a preflight check passed, degraded coverage, or blocks the run. */
export const DoctorStatusSchema = z.enum(["ok", "warn", "fail"]);
export type DoctorStatus = z.infer<typeof DoctorStatusSchema>;

/**
 * `required` blocks the run, `tools` shrinks coverage when it degrades, and
 * `optional` never blocks — the tiers exist so the exit code can be derived
 * from the checks instead of being decided at the call site.
 */
export const DoctorTierSchema = z.enum(["required", "tools", "optional"]);
export type DoctorTier = z.infer<typeof DoctorTierSchema>;

/** One preflight check; anything that is not `ok` must carry a remediation hint. */
export const DoctorCheckSchema = z
  .object({
    /** Stable dotted id, e.g. "required.git" or "tools.gitleaks". */
    id: z.string().min(1),
    tier: DoctorTierSchema,
    label: z.string().min(1),
    status: DoctorStatusSchema,
    /** What was observed, in one line, ready to print next to the status. */
    detail: z.string(),
    /** The concrete next step; required whenever status is not "ok". */
    remediation: z.string().optional(),
    version: z.string().optional(),
    /** The constraint the check applied, e.g. ">= 1.2.0" or a pinned version. */
    expected: z.string().optional(),
    path: z.string().optional(),
  })
  .refine((check) => check.status === "ok" || (check.remediation ?? "").length > 0, {
    message: "a check that is not ok must carry a remediation hint",
    path: ["remediation"],
  });
export type DoctorCheck = z.infer<typeof DoctorCheckSchema>;

/**
 * What the absence of one tool costs, in one sentence. The same sentence is
 * reused verbatim by the report's methodology section and by the phase 0.5
 * scope proposals, so it is data, not presentation.
 */
export const CoverageLossSchema = z.object({
  tool: z.string().min(1),
  sentence: z.string().min(1),
  domains: z.array(DomainSchema).default([]),
});
export type CoverageLoss = z.infer<typeof CoverageLossSchema>;

/** Counts per status, so a caller can headline the result without re-walking the checks. */
export const DoctorSummarySchema = z.object({
  ok: z.number().int().nonnegative(),
  warn: z.number().int().nonnegative(),
  fail: z.number().int().nonnegative(),
});
export type DoctorSummary = z.infer<typeof DoctorSummarySchema>;

/** The full preflight result; this is what `sentinel doctor --json` prints. */
export const DoctorReportSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  /** ISO-8601 instant the report was produced. */
  generatedAt: z.string().min(1),
  target: z.string(),
  outputDir: z.string(),
  /** Where pinned tools are looked up and where `sentinel setup` downloads them. */
  cacheDir: z.string(),
  environment: z.object({
    platform: z.string(),
    arch: z.string(),
    bunVersion: z.string(),
  }),
  checks: z.array(DoctorCheckSchema),
  coverageLoss: z.array(CoverageLossSchema).default([]),
  summary: DoctorSummarySchema,
  /** True when no required check failed; mirrors the process exit code. */
  ready: z.boolean(),
});
export type DoctorReport = z.infer<typeof DoctorReportSchema>;

/** Exit code when the preflight found nothing worse than warnings. */
export const DOCTOR_EXIT_OK = 0;

/** Exit code when a required check failed and an analysis must not start. */
export const DOCTOR_EXIT_BLOCKED = 2;

/** Counts the checks by status. */
export function summarizeChecks(checks: readonly DoctorCheck[]): DoctorSummary {
  const summary: DoctorSummary = { ok: 0, warn: 0, fail: 0 };
  for (const check of checks) {
    summary[check.status] += 1;
  }
  return summary;
}

/** True when no check in the `required` tier failed. */
export function isReady(checks: readonly DoctorCheck[]): boolean {
  return !checks.some((check) => check.tier === "required" && check.status === "fail");
}

/** Maps a report to its process exit code: 0 for warnings, 2 for a required failure. */
export function doctorExitCode(report: DoctorReport): number {
  return report.ready ? DOCTOR_EXIT_OK : DOCTOR_EXIT_BLOCKED;
}

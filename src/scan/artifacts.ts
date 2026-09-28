/**
 * What phase 1 leaves on disk.
 *
 * `findings.json` is the artifact every later phase and the report read, so it
 * is validated against `FindingsDocumentSchema` *before* it is written: a
 * document that would not survive being read back is never produced. The write
 * itself is the filesystem port's, which is atomic (temp file → fsync →
 * rename), so an interrupted run leaves either the previous document or the
 * new one and never half of either.
 *
 * Beside it go the coverage table — which is where a step that could not run
 * says so, in its own words — and `raw/<tool>/`, holding every analyzer's
 * untouched output so a reader can check Sentinel's arithmetic against the
 * tool's.
 */

import { join } from "node:path";
import { z } from "zod";
import {
  type Coverage,
  CoverageSchema,
  type Domain,
  DomainSchema,
  type Finding,
  type FindingsDocument,
  FindingsDocumentSchema,
  SCHEMA_VERSION,
} from "../contracts/findings.ts";
import type { ScanStep, StepOutcome, StepStatus } from "./types.ts";

/** The document every later phase reads. */
export const FINDINGS_FILE = "findings.json";

/** What ran, what did not, and why — the honest counterpart of the findings. */
export const SCAN_REPORT_FILE = "scan-report.json";

/** Directory under the run dir that holds every analyzer's untouched output. */
export const RAW_DIR_NAME = "raw";

/** The filesystem operations writing artifacts needs; the real port satisfies it. */
export interface ArtifactFileSystem {
  /** Atomic in the real port: a reader sees the old document or the new one. */
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  mkdirp(path: string): Promise<void>;
}

/** `<runDir>/raw/<tool>` — where a tool's untouched output belongs. */
export function rawDir(runDir: string, tool: string): string {
  return join(runDir, RAW_DIR_NAME, tool);
}

/** Writes one analyzer's output verbatim under `raw/<tool>/`; returns its path. */
export async function writeRawOutput(
  fs: ArtifactFileSystem,
  runDir: string,
  tool: string,
  fileName: string,
  content: string | Uint8Array,
): Promise<string> {
  const path = join(rawDir(runDir, tool), fileName);
  await fs.writeFile(path, content);
  return path;
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/**
 * A step's own sentence, prefixed with the status that produced it.
 *
 * This is the line a reader sees in the coverage table: `hadolint — skipped:
 * the target has no Dockerfile`. A step that gave no reason still names its
 * status, because "nothing was checked" without a reason is exactly the silence
 * the coverage table exists to prevent.
 */
export function coverageReason(outcome: StepOutcome): string {
  const reason = outcome.reason?.trim();
  return reason === undefined || reason === ""
    ? `${outcome.status}: no reason given`
    : `${outcome.status}: ${reason}`;
}

/** Statuses that mean the step contributed what it was asked for. */
const CONTRIBUTED: ReadonlySet<StepStatus> = new Set<StepStatus>(["ok", "degraded"]);

/**
 * Builds the per-domain coverage from the steps that were planned and the
 * outcomes they returned.
 *
 * The unit of phase 1 coverage is the *step*: a domain with four steps of which
 * one was skipped reads `3/4`, and the fourth is listed by name with the reason
 * it did not run. A step that was planned but produced no outcome — the run was
 * aborted before it started — counts against the domain just the same.
 *
 * `domains` is the run's scope. A domain outside it is absent from the table
 * entirely — the run never claimed it — while a domain *inside* it that no step
 * covers reads `0/0`, which is the difference between "no check exists yet" and
 * "everything ran and found nothing".
 */
export function buildCoverage(
  steps: readonly ScanStep[],
  outcomes: readonly StepOutcome[],
  domains?: readonly Domain[],
): Coverage[] {
  const byStep = new Map(outcomes.map((outcome) => [outcome.step, outcome]));
  const wanted = domains ?? DomainSchema.options;
  const coverage: Coverage[] = [];

  for (const domain of DomainSchema.options) {
    if (!wanted.includes(domain)) continue;
    const relevant = steps.filter((step) => step.domains.includes(domain));
    if (relevant.length === 0) {
      // A domain the run's scope deliberately turned *on* and phase 1 has no
      // step for still gets a row, at 0/0: leaving it out would make "no check
      // exists yet" indistinguishable from "every check ran and found nothing".
      // With no scope given, nothing was promised, so nothing is claimed.
      if (domains !== undefined) {
        coverage.push(
          CoverageSchema.parse({ domain, unitsTotal: 0, unitsAudited: 0, skipped: [] }),
        );
      }
      continue;
    }

    const skipped: Array<{ unitId: string; reason: string }> = [];
    let audited = 0;
    for (const step of relevant) {
      const outcome = byStep.get(step.name);
      if (outcome === undefined) {
        skipped.push({ unitId: step.name, reason: "not run: the scan ended before this step" });
        continue;
      }
      if (CONTRIBUTED.has(outcome.status)) audited += 1;
      else skipped.push({ unitId: step.name, reason: coverageReason(outcome) });
    }

    coverage.push(
      CoverageSchema.parse({
        domain,
        unitsTotal: relevant.length,
        unitsAudited: audited,
        skipped: [...skipped].sort((left, right) => left.unitId.localeCompare(right.unitId)),
      }),
    );
  }

  return coverage;
}

// ---------------------------------------------------------------------------
// findings.json
// ---------------------------------------------------------------------------

/** Everything the findings document needs that normalisation does not produce. */
export interface FindingsDocumentInput {
  readonly runId: string;
  /** Absolute path of the repository the findings are about. */
  readonly target: string;
  readonly findings: readonly Finding[];
  readonly coverage: readonly Coverage[];
  readonly droppedFindings: number;
}

/**
 * Builds the document and validates it in one step, so an invalid one cannot
 * exist as a value — a caller that wants to inspect it before writing gets an
 * object that has already been through the schema.
 */
export function buildFindingsDocument(input: FindingsDocumentInput): FindingsDocument {
  return FindingsDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: input.runId,
    target: input.target,
    findings: [...input.findings],
    // Phase 1 is deterministic tooling; assurances come from the audit phase,
    // which is the only one that can say a check ran and passed.
    assurances: [],
    coverage: [...input.coverage],
    droppedFindings: input.droppedFindings,
  });
}

/** Two-space JSON with a trailing newline: diffable, and `git diff` friendly. */
function serialise(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** Writes `findings.json`, re-validated on the way out; returns its path. */
export async function writeFindingsDocument(
  fs: ArtifactFileSystem,
  runDir: string,
  document: FindingsDocument,
): Promise<string> {
  const path = join(runDir, FINDINGS_FILE);
  await fs.writeFile(path, serialise(FindingsDocumentSchema.parse(document)));
  return path;
}

// ---------------------------------------------------------------------------
// scan-report.json
// ---------------------------------------------------------------------------

/** One step's line in the scan report. */
export const StepReportSchema = z.object({
  step: z.string(),
  status: z.enum(["ok", "degraded", "skipped", "failed"]),
  reason: z.string().optional(),
  findings: z.number().int().nonnegative(),
  artifacts: z.array(z.string()),
  durationMs: z.number().int().nonnegative(),
});
export type StepReport = z.infer<typeof StepReportSchema>;

/**
 * What phase 1 did, as opposed to what it found.
 *
 * Kept out of `findings.json` on purpose: this document carries timings, which
 * differ between two runs of an unchanged repository, and `findings.json` has
 * to be byte-identical across those runs to be worth diffing.
 */
export const ScanReportSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  runId: z.string(),
  target: z.string(),
  /** True when the run was cancelled before every step finished. */
  aborted: z.boolean(),
  durationMs: z.number().int().nonnegative(),
  steps: z.array(StepReportSchema),
  /** Findings whose citation did not resolve on disk, by reason. */
  dropped: z.object({
    findings: z.number().int().nonnegative(),
    evidence: z.number().int().nonnegative(),
    byReason: z.record(z.string(), z.number().int().nonnegative()),
  }),
  /** Citations whose line the verifier corrected. */
  relocated: z.number().int().nonnegative(),
  /** Problems two tools reported, collapsed into one finding. */
  merged: z.array(
    z.object({
      id: z.string(),
      rule: z.string(),
      file: z.string(),
      line: z.number().int().positive(),
      kept: z.string(),
      alsoReportedBy: z.array(z.string()),
    }),
  ),
  /** Findings the severity policy moved, and where they moved from and to. */
  escalations: z.array(
    z.object({ id: z.string(), rule: z.string(), from: z.string(), to: z.string() }),
  ),
});
export type ScanReport = z.infer<typeof ScanReportSchema>;

/** Reduces an outcome to its report line; the findings themselves live elsewhere. */
export function toStepReport(outcome: StepOutcome): StepReport {
  return StepReportSchema.parse({
    step: outcome.step,
    status: outcome.status,
    ...(outcome.reason === undefined ? {} : { reason: outcome.reason }),
    findings: outcome.findings.length,
    artifacts: [...outcome.artifacts],
    durationMs: Math.max(0, Math.round(outcome.durationMs)),
  });
}

/** Writes `scan-report.json`, validated on the way out; returns its path. */
export async function writeScanReport(
  fs: ArtifactFileSystem,
  runDir: string,
  report: ScanReport,
): Promise<string> {
  const path = join(runDir, SCAN_REPORT_FILE);
  await fs.writeFile(path, serialise(ScanReportSchema.parse(report)));
  return path;
}

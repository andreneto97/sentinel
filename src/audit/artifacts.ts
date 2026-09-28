/**
 * What phase 4 leaves on disk.
 *
 * Three documents, and the split between them is deliberate:
 *
 * - **`findings.json`** is the artifact every later phase and the report read.
 *   The audit does not write its own: it *merges into* the document phase 1
 *   produced, through {@link mergeAuditIntoFindings}, reusing phase 1's writer
 *   so a run that scanned and audited has one set of findings rather than two
 *   files a reader has to join. The merge is total-ordered by the same
 *   comparator phase 1 sorts with, so two runs over unchanged code still
 *   produce byte-identical bytes.
 * - **`audit.json`** is what the phase *did*: batches, verdict counts, agent
 *   failures, token spend and timings. It is separate from `findings.json`
 *   precisely because it holds numbers that differ between two runs of an
 *   unchanged repository, and `findings.json` has to be diffable.
 * - **`assurances.json`** is the checks that passed, with their coverage, for a
 *   reader who wants the positive half of the dossier on its own.
 *
 * Everything read back from disk is validated before it is used —
 * `inventory.json` and `findings.json` are external input to this phase like
 * any other file, and a phase that trusts an artifact it did not produce in
 * this process is a phase that fails confusingly three steps later.
 */

import { join } from "node:path";
import { z } from "zod";
import { AgentFailureKindSchema } from "../agents/errors.ts";
import { AgentUsageSchema } from "../agents/usage.ts";
import {
  type Assurance,
  AssuranceSchema,
  type Coverage,
  CoverageSchema,
  type Domain,
  DomainSchema,
  type Finding,
  type FindingsDocument,
  FindingsDocumentSchema,
  SCHEMA_VERSION,
} from "../contracts/findings.ts";
import {
  AuditUnitKindSchema,
  INVENTORY_FILE,
  type InventoryDocument,
  InventoryDocumentSchema,
} from "../contracts/inventory.ts";
import { FINDINGS_FILE, writeFindingsDocument } from "../scan/artifacts.ts";
import { compareFindings } from "../scan/normalise.ts";
import { compareAssurances } from "./assurance.ts";
import { AuditBoundSchema, unboundedBound } from "./budget.ts";
import { KindCoverageSchema, UnitTotalsSchema } from "./coverage.ts";

/** What the phase did, as opposed to what it found. */
export const AUDIT_FILE = "audit.json";

/** The positive half of the dossier, on its own. */
export const ASSURANCES_FILE = "assurances.json";

/** The filesystem operations this module needs; the real port satisfies it structurally. */
export interface AuditArtifactFileSystem {
  readFile(path: string): Promise<string>;
  /** Atomic in the real port: a reader sees the old document or the new one. */
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  mkdirp(path: string): Promise<void>;
  exists(path: string): Promise<boolean>;
}

/** Two-space JSON with a trailing newline: diffable, and `git diff` friendly. */
function serialise(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// audit.json
// ---------------------------------------------------------------------------

/**
 * Citations Sentinel refused, split by *why* it refused them.
 *
 * The two counters at the top are the point of the whole architecture and are
 * not interchangeable. `unresolved` means the model pointed at code that is not
 * there — the ordinary hallucination, caught by `src/verify/`. `outOfSlice`
 * means it pointed at code that *is* there and that it was never shown: the
 * batch's prompt did not contain that line, so the claim came from memory or
 * from another repository the model has read. A run with a high `outOfSlice` is
 * a run whose prompts are too small or whose agent is guessing, and collapsing
 * it into the other number would hide exactly that.
 */
export const DropAccountingSchema = z.object({
  /** Findings dropped because their location does not resolve on disk. */
  unresolved: z.number().int().nonnegative(),
  /** Evidence refs removed for the same reason. */
  unresolvedEvidence: z.number().int().nonnegative(),
  /** Findings dropped because their location was outside the slices the batch provided. */
  outOfSlice: z.number().int().nonnegative(),
  /** Evidence refs removed for the same reason. */
  outOfSliceEvidence: z.number().int().nonnegative(),
  /** Two verdicts that produced the same finding identity; the first was kept. */
  duplicates: z.number().int().nonnegative(),
  /** Claims whose citation the verifier had to move to match the code on disk. */
  relocated: z.number().int().nonnegative(),
  /** Verdicts about a unit the batch did not contain, ignored. */
  strayVerdicts: z.number().int().nonnegative(),
  /** Assurance evidence refs that did not survive verification or the slice gate. */
  assuranceEvidence: z.number().int().nonnegative(),
  /** Drop count per `src/verify` reason, for the coverage section of the report. */
  byReason: z.record(z.string(), z.number().int().nonnegative()),
});
/** Citations Sentinel refused, and why; see {@link DropAccountingSchema}. */
export type DropAccounting = z.infer<typeof DropAccountingSchema>;

/** One batch's line in `audit.json`. */
export const BatchReportSchema = z.object({
  batchId: z.string(),
  domain: DomainSchema,
  /** The unit kinds the batch carried, in contract order. */
  kinds: z.array(AuditUnitKindSchema),
  /** Units the batch was asked about. */
  units: z.number().int().nonnegative(),
  /**
   * `audited` — every unit came back with a verdict. `partial` — the reply
   * arrived but said nothing about some units. `failed` — no usable reply.
   */
  status: z.enum(["audited", "partial", "failed"]),
  /** How the dispatch failed, when it did. */
  failure: AgentFailureKindSchema.optional(),
  reason: z.string().optional(),
  /** Attempts the runtime spent, the corrective re-prompt included. */
  attempts: z.number().int().nonnegative(),
  /** Verdicts accepted for units of this batch. */
  verdicts: z.number().int().nonnegative(),
  /** Findings kept from this batch, after verification and the slice gate. */
  findings: z.number().int().nonnegative(),
  durationMs: z.number().int().nonnegative(),
  /** Paths written under `<runDir>/raw/agents/`, in the order they were written. */
  transcripts: z.array(z.string()),
});
/** One batch's line in `audit.json`; see {@link BatchReportSchema}. */
export type BatchReport = z.infer<typeof BatchReportSchema>;

/** The effective settings of the runtime that answered, for the report's disclosure. */
export const AuditRuntimeSchema = z.object({
  kind: z.enum(["claude-agent-sdk", "fixture"]),
  model: z.string().optional(),
  concurrency: z.number().int().positive(),
  maxAttempts: z.number().int().positive(),
  timeoutMs: z.number().int().positive(),
  /**
   * True when the answers came from a recorded or handwritten transcript. The
   * report must repeat it: a green replay is a wiring guard, not evidence about
   * the code.
   */
  synthetic: z.boolean(),
});
/** Runtime disclosure; see {@link AuditRuntimeSchema}. */
export type AuditRuntimeReport = z.infer<typeof AuditRuntimeSchema>;

/** The phase 4 artifact, written to `audit.json`. */
export const AuditReportSchema = z
  .object({
    schemaVersion: z.literal(SCHEMA_VERSION),
    runId: z.string(),
    target: z.string(),
    /** True when the run was cancelled before every batch finished. */
    aborted: z.boolean(),
    durationMs: z.number().int().nonnegative(),
    runtime: AuditRuntimeSchema,
    /** Attempts that reached the transport, retries included. */
    dispatches: z.number().int().nonnegative(),
    retries: z.number().int().nonnegative(),
    failures: z.record(AgentFailureKindSchema, z.number().int().nonnegative()),
    /** True once a subscription limit latched the runtime shut and stopped the phase. */
    quotaExhausted: z.boolean(),
    usage: AgentUsageSchema,
    batches: z.array(BatchReportSchema),
    units: UnitTotalsSchema,
    /**
     * What the run's ceilings left out, and the one sentence that says so.
     *
     * Optional rather than required so a report written before budgets existed
     * still reads back. When it is absent it is derived from this report's own
     * `units` — see the transform below — because the substitute has to agree with
     * the numbers beside it: a bound that says "all 0 units were audited" next to a
     * coverage line reading "46 of 47" is a document that contradicts itself. The
     * dossier prints `bound.statement`; a repository too large to audit whole must
     * not be able to produce a report that reads like a complete one.
     */
    bound: AuditBoundSchema.optional(),
    /** Per-domain coverage as this phase saw it, before the merge into `findings.json`. */
    coverage: z.array(CoverageSchema),
    /** Per-unit-kind coverage: the `200/200 route handlers` line. */
    kinds: z.array(KindCoverageSchema),
    findingsKept: z.number().int().nonnegative(),
    assurances: z.number().int().nonnegative(),
    dropped: DropAccountingSchema,
  })
  // Filled here rather than by a field default, because a field default cannot
  // see `units`: an older `audit.json`, or a caller that has no budget to
  // report, gets a bound that says every unit the phase counted was audited
  // under no ceiling — which is the truth about such a run, in its own numbers.
  .transform((report) => ({
    ...report,
    bound: report.bound ?? unboundedBound(report.units.total, report.units.audited),
  }));
/** The phase 4 artifact; see {@link AuditReportSchema}. */
export type AuditReport = z.infer<typeof AuditReportSchema>;

/**
 * Builds the report and validates it in one step, so an invalid one cannot
 * exist as a value.
 */
export function buildAuditReport(input: z.input<typeof AuditReportSchema>): AuditReport {
  return AuditReportSchema.parse(input);
}

/** Writes `audit.json`, re-validated on the way out; returns its path. */
export async function writeAuditReport(
  fs: Pick<AuditArtifactFileSystem, "writeFile">,
  runDir: string,
  report: AuditReport,
): Promise<string> {
  const path = join(runDir, AUDIT_FILE);
  await fs.writeFile(path, serialise(AuditReportSchema.parse(report)));
  return path;
}

// ---------------------------------------------------------------------------
// assurances.json
// ---------------------------------------------------------------------------

/** The phase 4 assurance artifact, written to `assurances.json`. */
export const AssurancesDocumentSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  runId: z.string(),
  target: z.string(),
  assurances: z.array(AssuranceSchema),
  /** The coverage the assurances rest on, so a fraction can never be read alone. */
  coverage: z.array(CoverageSchema),
});
/** The phase 4 assurance artifact; see {@link AssurancesDocumentSchema}. */
export type AssurancesDocument = z.infer<typeof AssurancesDocumentSchema>;

/** Builds the assurance document, ordered and validated. */
export function buildAssurancesDocument(input: {
  readonly runId: string;
  readonly target: string;
  readonly assurances: readonly Assurance[];
  readonly coverage: readonly Coverage[];
}): AssurancesDocument {
  return AssurancesDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: input.runId,
    target: input.target,
    assurances: [...input.assurances].sort(compareAssurances),
    coverage: [...input.coverage],
  });
}

/** Writes `assurances.json`, re-validated on the way out; returns its path. */
export async function writeAssurancesDocument(
  fs: Pick<AuditArtifactFileSystem, "writeFile">,
  runDir: string,
  document: AssurancesDocument,
): Promise<string> {
  const path = join(runDir, ASSURANCES_FILE);
  await fs.writeFile(path, serialise(AssurancesDocumentSchema.parse(document)));
  return path;
}

// ---------------------------------------------------------------------------
// Reading what earlier phases left
// ---------------------------------------------------------------------------

/** Names the first schema violation in a way a CLI error can print. */
function violation(error: z.ZodError): string {
  const issue = error.issues[0];
  const path = issue === undefined ? "" : issue.path.map(String).join(".");
  return `${path === "" ? "(root)" : path}: ${issue?.message ?? "invalid"}`;
}

/** Parses and validates a JSON document, naming the file and the violation. */
function parseDocument<S extends z.ZodType>(raw: string, schema: S, path: string): z.infer<S> {
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`${path} is not valid JSON: ${detail}`);
  }
  const result = schema.safeParse(json);
  if (!result.success)
    throw new Error(`${path} is not a valid document: ${violation(result.error)}`);
  return result.data;
}

/**
 * Reads phase 2's `inventory.json` and validates it.
 *
 * This is how phase 4 gets its units when it is not handed them in memory —
 * `sentinel resume` re-entering at the audit, or a run that scanned yesterday.
 * The document is external input: an inventory that does not validate stops the
 * phase here rather than producing an audit of units whose shape it guessed.
 */
export async function readInventoryDocument(
  fs: Pick<AuditArtifactFileSystem, "readFile">,
  runDir: string,
): Promise<InventoryDocument> {
  const path = join(runDir, INVENTORY_FILE);
  return parseDocument(await fs.readFile(path), InventoryDocumentSchema, path);
}

/**
 * Reads phase 1's `findings.json`, or returns null when there is none.
 *
 * A missing document is not an error: `--skip-scan` and an audit-only run both
 * leave the audit with nothing to merge into, and starting from an empty
 * document is the honest result — findings from the agents, no findings from
 * the analyzers, and a coverage table that says only what the audit covered.
 */
export async function readFindingsDocument(
  fs: Pick<AuditArtifactFileSystem, "readFile" | "exists">,
  runDir: string,
): Promise<FindingsDocument | null> {
  const path = join(runDir, FINDINGS_FILE);
  if (!(await fs.exists(path))) return null;
  return parseDocument(await fs.readFile(path), FindingsDocumentSchema, path);
}

// ---------------------------------------------------------------------------
// The merge
// ---------------------------------------------------------------------------

/** Domain order in the merged coverage table: the contract's enum order. */
const DOMAIN_RANK: ReadonlyMap<Domain, number> = new Map(
  DomainSchema.options.map((domain, index) => [domain, index]),
);

/**
 * Merges two coverage tables into one row per domain.
 *
 * Phase 1 counts *steps* and phase 4 counts *units*, and both call them units
 * because the contract has one field for "things that were checked". Summing
 * them keeps one row per domain — which is what the score phase and the report
 * both want — and preserves the invariant that makes the row trustworthy:
 * `unitsAudited + skipped.length === unitsTotal`, because each side satisfied
 * it and the skipped lists concatenate. Every skipped entry names itself, a
 * step name or a unit id, with the reason it did not run, so a blended row is
 * still readable line by line.
 */
export function mergeCoverage(
  base: readonly Coverage[],
  incoming: readonly Coverage[],
): Coverage[] {
  const merged = new Map<Domain, Coverage>();
  for (const row of [...base, ...incoming]) {
    const current = merged.get(row.domain);
    if (current === undefined) {
      merged.set(row.domain, {
        domain: row.domain,
        unitsTotal: row.unitsTotal,
        unitsAudited: row.unitsAudited,
        skipped: [...row.skipped],
      });
      continue;
    }
    const seen = new Set(current.skipped.map((entry) => `${entry.unitId}${entry.reason}`));
    const added = row.skipped.filter((entry) => !seen.has(`${entry.unitId}${entry.reason}`));
    merged.set(row.domain, {
      domain: row.domain,
      unitsTotal: current.unitsTotal + row.unitsTotal,
      unitsAudited: current.unitsAudited + row.unitsAudited,
      skipped: [...current.skipped, ...added],
    });
  }

  return [...merged.values()]
    .map((row) =>
      CoverageSchema.parse({
        ...row,
        skipped: [...row.skipped].sort(
          (left, right) =>
            left.unitId.localeCompare(right.unitId) || left.reason.localeCompare(right.reason),
        ),
      }),
    )
    .sort(
      (left, right) =>
        (DOMAIN_RANK.get(left.domain) ?? Number.MAX_SAFE_INTEGER) -
        (DOMAIN_RANK.get(right.domain) ?? Number.MAX_SAFE_INTEGER),
    );
}

/** What the audit contributes to `findings.json`. */
export interface AuditContribution {
  readonly runId: string;
  /** Absolute path of the repository the findings are about. */
  readonly target: string;
  /** Verified findings; every snippet was extracted from disk by `src/verify`. */
  readonly findings: readonly Finding[];
  readonly assurances: readonly Assurance[];
  readonly coverage: readonly Coverage[];
  /**
   * Citations the audit refused: unresolvable *and* out-of-slice. Both are a
   * claim that did not reach the reader, which is what this counter is for; the
   * split between them lives in `audit.json`.
   */
  readonly droppedFindings: number;
}

/**
 * Folds the audit's output into phase 1's document.
 *
 * Determinism is the whole contract of this function. Findings are
 * de-duplicated by id — first occurrence wins, so a problem an analyzer already
 * reported is not reported twice by an agent — and the result is re-sorted with
 * phase 1's own comparator rather than appended, so the bytes do not depend on
 * which phase ran first or on the order batches finished in. The document is
 * re-validated on the way out, so one that would not survive being read back
 * never exists as a value.
 */
export function mergeAuditIntoFindings(
  base: FindingsDocument | null,
  audit: AuditContribution,
): FindingsDocument {
  const findings = new Map<string, Finding>();
  for (const finding of base?.findings ?? []) findings.set(finding.id, finding);
  for (const finding of audit.findings) {
    if (!findings.has(finding.id)) findings.set(finding.id, finding);
  }

  const assurances = new Map<string, Assurance>();
  for (const assurance of base?.assurances ?? []) assurances.set(assurance.id, assurance);
  for (const assurance of audit.assurances) {
    if (!assurances.has(assurance.id)) assurances.set(assurance.id, assurance);
  }

  return FindingsDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: base?.runId ?? audit.runId,
    target: base?.target ?? audit.target,
    findings: [...findings.values()].sort(compareFindings),
    assurances: [...assurances.values()].sort(compareAssurances),
    coverage: mergeCoverage(base?.coverage ?? [], audit.coverage),
    droppedFindings: (base?.droppedFindings ?? 0) + audit.droppedFindings,
  });
}

/** Writes the merged `findings.json` through phase 1's writer; returns its path. */
export async function writeMergedFindings(
  fs: Pick<AuditArtifactFileSystem, "writeFile" | "mkdirp">,
  runDir: string,
  document: FindingsDocument,
): Promise<string> {
  return await writeFindingsDocument(fs, runDir, document);
}

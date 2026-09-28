/**
 * `sentinel resume <run-dir>` — re-enter a run at its first incomplete phase.
 *
 * A run directory is a checkpoint. Phase 0 wrote `stack-profile.json`, phase 1
 * wrote `findings.json`, phase 2 wrote `inventory.json`, phase 4 wrote
 * `audit.json`; each of those is enough for the next phase to start from. So a
 * run that was interrupted after the inventory does not need to be paid for
 * again: resume reads what is there, works out the first phase that did not
 * finish, and runs forward from it.
 *
 * The rule that shapes this command:
 *
 * > **Never silently redo a phase that spent AI.**
 *
 * The audit is the only expensive phase in a run, and "the audit is incomplete"
 * is the most common reason to resume — so the temptation is to re-dispatch it.
 * This command will not, unless it is told to in so many words. A missing audit
 * runs (it cost nothing yet). A *partial* audit is left alone and reported,
 * because re-dispatching thirteen batches to recover five units is a decision
 * for the operator, not a default. `--retry-failed` re-dispatches only the
 * batches that failed or came back incomplete, and `--force-phase audit`
 * re-dispatches all of them; both say what they are about to spend.
 *
 * The merge that `--retry-failed` performs is the delicate part, and the two
 * invariants it preserves are worth stating: coverage rows are *recomposed*
 * rather than added (a retried unit's old row is replaced, never summed, so a
 * domain's unit total is the same after a retry as before it), and findings are
 * merged by id, so a problem the previous attempt already reported is not
 * reported twice.
 */

import {
  type AuditReport,
  buildAssurancesDocument,
  buildAuditReport,
  mergeCoverage,
  writeAssurancesDocument,
  writeAuditReport,
  writeMergedFindings,
} from "../audit/artifacts.ts";
import { buildAuditBound } from "../audit/budget.ts";
import type { KindCoverage } from "../audit/coverage.ts";
import { SKIP_CAUSES, type SkipCause, emptySkipCounts } from "../audit/coverage.ts";
import type {
  Assurance,
  AuditUnit,
  Coverage,
  Finding,
  FindingsDocument,
} from "../contracts/findings.ts";
import { FindingsDocumentSchema, SCHEMA_VERSION } from "../contracts/findings.ts";
import type { RunArtifacts, RunPhase, RunPhaseName, RunVerdict } from "./_shared/run-artifacts.ts";
import {
  RUN_PHASES,
  type RunArtifactFileSystem,
  assessRun,
  describeRunPhases,
  firstIncompletePhase,
  loadRunArtifacts,
  phaseByName,
} from "./_shared/run-artifacts.ts";
import { type RunDirFileSystem, resolveRunDir } from "./_shared/run-dir.ts";
import type { CliContext, OutputFlags } from "./index.ts";
import { EXIT } from "./index.ts";
import { describeRunDirFailure } from "./report.ts";

/** A parsed `sentinel resume` invocation. */
export interface ResumeInvocation {
  readonly runDir: string;
  readonly cwd: string;
  readonly output: OutputFlags;
  /** Redo this phase even though it finished. */
  readonly forcePhase?: RunPhaseName | undefined;
  /** Re-dispatch only the batches that failed or answered partially. */
  readonly retryFailed: boolean;
  /** Batches in flight at once when the audit runs; defaults to the audit's own default. */
  readonly maxParallel?: number | undefined;
}

/** The filesystem surface resume needs; the real port satisfies it. */
export interface ResumeFileSystem extends RunArtifactFileSystem, RunDirFileSystem {
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  mkdirp(path: string): Promise<void>;
}

/** What a phase runner is handed. Everything it needs comes off disk first. */
export interface PhaseRequest {
  readonly runId: string;
  /** Absolute path of the run directory. */
  readonly runDir: string;
  /** Absolute path of the repository; `""` when no artifact recorded one. */
  readonly targetDir: string;
  /** The artifacts as they are right now, re-read after every phase. */
  readonly artifacts: RunArtifacts;
  /** Batches in flight at once, when the phase dispatches any. */
  readonly maxParallel: number | undefined;
  /**
   * Audit only: re-dispatch just these batches. The runner resolves the ids to
   * units by re-planning, because only it can build a plan. Absent means the
   * whole inventory.
   */
  readonly retryBatchIds?: readonly string[] | undefined;
}

/** What a phase runner reports back. */
export interface PhaseOutcome {
  /** False stops the resume: the phases after this one are not attempted. */
  readonly ok: boolean;
  /** One line for the summary: what the phase did, in its own terms. */
  readonly summary: string;
  /** Absolute paths it wrote. */
  readonly artifacts: readonly string[];
  /** Anything the operator has to be told about what just happened. */
  readonly notes?: readonly string[] | undefined;
}

/** The six phases, injected so the command itself is testable without any of them. */
export type ResumeRunners = Readonly<
  Record<RunPhaseName, (request: PhaseRequest) => Promise<PhaseOutcome>>
>;

/** Everything the command reaches outside itself. */
export interface ResumeDeps {
  readonly fs: ResumeFileSystem;
  readonly runners: ResumeRunners;
}

/** One phase resume decided about. */
export interface PhaseAttempt {
  readonly name: RunPhaseName;
  /** `ran`, `skipped` (deliberately) or `failed`. */
  readonly outcome: "ran" | "skipped" | "failed";
  readonly summary: string;
  readonly artifacts: readonly string[];
}

/** What `--json` prints. */
export interface ResumeJson {
  readonly runId: string;
  readonly runDir: string;
  readonly target: string;
  /** The phase resume re-entered at, or null when the run was already complete. */
  readonly entryPhase: RunPhaseName | null;
  readonly attempts: readonly PhaseAttempt[];
  readonly notes: readonly string[];
  readonly phases: readonly RunPhase[];
  readonly verdict: RunVerdict;
}

/** Two-space JSON with a trailing newline, matching every other artifact. */
function serialise(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Recomposing coverage after a partial retry
// ---------------------------------------------------------------------------

/** One skipped unit, as every coverage table records it. */
interface SkippedEntry {
  readonly unitId: string;
  readonly reason: string;
}

/** The shape `Coverage` and `KindCoverage` have in common. */
interface CoverageLike {
  readonly unitsTotal: number;
  readonly unitsAudited: number;
  readonly skipped: readonly SkippedEntry[];
}

/** Sorts skipped entries the way every artifact writes them. */
function sortSkipped(entries: readonly SkippedEntry[]): SkippedEntry[] {
  return [...entries].sort(
    (left, right) =>
      left.unitId.localeCompare(right.unitId) || left.reason.localeCompare(right.reason),
  );
}

/**
 * Replaces the retried units' contribution to one coverage row.
 *
 * Adding the retry's row to the old one would double the totals, which is the
 * bug this function exists to prevent: the same units were looked at twice, not
 * twice as many units. `unitsTotal` therefore never changes — the repository
 * has the units it has — and the skipped list is rebuilt from the entries that
 * were not retried plus whatever the retry itself could not decide.
 *
 * A retry can only ever *improve* a row, which is the second invariant here and
 * the reason `added` is filtered against the previous skipped list rather than
 * against `retried` alone. `--retry-failed` re-dispatches whole batches, and a
 * partial batch is mostly units that did come back with a verdict: re-asking a
 * whole batch to recover one unit puts all its siblings in `retried` too. If the
 * retry then fails — a timeout, or a credential the subscription rejects — every
 * unit it carried lands in `fresh.skipped`, and taking those entries on trust
 * rewrites verdicts that were already paid for as `batch-failed`, lowering the
 * audited count a second attempt was supposed to raise. A verdict is a check
 * that ran; a later attempt failing to reach the model is not evidence that it
 * did not. So a retried unit is only re-skipped when it had no verdict to begin
 * with.
 */
export function recomposeRow<T extends CoverageLike>(
  previous: T,
  retried: ReadonlySet<string>,
  fresh: CoverageLike | undefined,
): T {
  const kept = previous.skipped.filter((entry) => !retried.has(entry.unitId));
  const hadNoVerdict = new Set(previous.skipped.map((entry) => entry.unitId));
  const added = (fresh?.skipped ?? []).filter(
    (entry) => retried.has(entry.unitId) && hadNoVerdict.has(entry.unitId),
  );
  const skipped = sortSkipped([...kept, ...added]);
  const unitsTotal = Math.max(previous.unitsTotal, skipped.length);
  return { ...previous, unitsTotal, unitsAudited: unitsTotal - skipped.length, skipped };
}

/** Recomposes the per-domain table after a retry. */
export function recomposeCoverage(
  previous: readonly Coverage[],
  retried: ReadonlySet<string>,
  fresh: readonly Coverage[],
): Coverage[] {
  return previous.map((row) =>
    recomposeRow(
      row,
      retried,
      fresh.find((candidate) => candidate.domain === row.domain),
    ),
  );
}

/** Recomposes the per-unit-kind table after a retry. */
export function recomposeKinds(
  previous: readonly KindCoverage[],
  retried: ReadonlySet<string>,
  fresh: readonly KindCoverage[],
): KindCoverage[] {
  return previous.map((row) =>
    recomposeRow(
      row,
      retried,
      fresh.find((candidate) => candidate.kind === row.kind),
    ),
  );
}

/**
 * Recovers phase 1's coverage from the merged table.
 *
 * `findings.json` holds phase 1's steps and phase 4's units added together, and
 * a retry has to merge its recomposed audit rows back into phase 1's — so
 * phase 1's half has to be recovered by subtraction. Clamped at zero and
 * re-derived from the skipped list, so a row can never claim more audited units
 * than it has.
 */
export function subtractCoverage(
  total: readonly Coverage[],
  part: readonly Coverage[],
): Coverage[] {
  return total.map((row) => {
    const other = part.find((candidate) => candidate.domain === row.domain);
    if (other === undefined) return row;
    const removed = new Set(other.skipped.map((entry) => `${entry.unitId}\u0000${entry.reason}`));
    const skipped = sortSkipped(
      row.skipped.filter((entry) => !removed.has(`${entry.unitId}\u0000${entry.reason}`)),
    );
    const audited = Math.max(0, row.unitsAudited - other.unitsAudited);
    return {
      domain: row.domain,
      unitsTotal: audited + skipped.length,
      unitsAudited: audited,
      skipped,
    };
  });
}

/** The cause a coverage reason was written with; `no-verdict` when it names none. */
export function causeOf(reason: string): SkipCause {
  return SKIP_CAUSES.find((cause) => reason.startsWith(`${cause}:`)) ?? "no-verdict";
}

/** Run-level unit totals, re-derived from the per-kind table after a retry. */
export function recomposeUnitTotals(kinds: readonly KindCoverage[]): AuditReport["units"] {
  const byCause = emptySkipCounts();
  let total = 0;
  let audited = 0;
  for (const row of kinds) {
    total += row.unitsTotal;
    audited += row.unitsAudited;
    for (const entry of row.skipped) byCause[causeOf(entry.reason)] += 1;
  }
  return { total, audited, skipped: total - audited, byCause };
}

/** Sums two usage records field by field; both come from `AgentUsageSchema`. */
function addUsage(left: AuditReport["usage"], right: AuditReport["usage"]): AuditReport["usage"] {
  return {
    inputTokens: left.inputTokens + right.inputTokens,
    outputTokens: left.outputTokens + right.outputTokens,
    cacheReadInputTokens: left.cacheReadInputTokens + right.cacheReadInputTokens,
    cacheCreationInputTokens: left.cacheCreationInputTokens + right.cacheCreationInputTokens,
    costUsd: left.costUsd + right.costUsd,
  };
}

/** Sums two `Record<key, number>` tallies, keeping every key either one has. */
function addCounts(
  left: Readonly<Record<string, number>>,
  right: Readonly<Record<string, number>>,
): Record<string, number> {
  const sum: Record<string, number> = { ...left };
  for (const [key, value] of Object.entries(right)) sum[key] = (sum[key] ?? 0) + value;
  return sum;
}

/** What a retry produced, in the shape {@link mergeRetryIntoAudit} consumes. */
export interface RetryContribution {
  readonly report: AuditReport;
  readonly findings: readonly Finding[];
  readonly assurances: readonly Assurance[];
  /** Ids of the batches the retry replaced. */
  readonly replacedBatchIds: readonly string[];
  /** Ids of every unit the retry re-dispatched. */
  readonly retriedUnitIds: readonly string[];
}

/** The three documents a retry rewrites, built but not yet written. */
export interface MergedRetry {
  readonly audit: AuditReport;
  readonly findings: FindingsDocument;
  readonly assurances: readonly Assurance[];
  /** Per-domain coverage the audit now claims, for `assurances.json`. */
  readonly auditCoverage: readonly Coverage[];
}

/**
 * Folds a retry back into the run's artifacts.
 *
 * Everything the retry did not touch is preserved byte for byte: the batches it
 * did not re-dispatch keep their reports, the units it did not re-ask about keep
 * their verdicts, and findings are merged by id so an unchanged problem is not
 * duplicated. What the retry did touch replaces its predecessor rather than
 * adding to it.
 */
export function mergeRetryIntoAudit(
  previous: AuditReport,
  base: FindingsDocument,
  contribution: RetryContribution,
): MergedRetry {
  const retried = new Set(contribution.retriedUnitIds);
  // The batches this retry supersedes, as the caller reports them. A retry may
  // re-pack the same units under a new id, so this cannot be inferred from the
  // fresh batch ids — which is why the caller must name only the batches it
  // really re-dispatched. `createResumeRunners` narrows the asked-for list to the
  // ids a fresh plan actually held before it gets here; passing the whole
  // asked-for list deleted 30 quota-failed records nothing had re-dispatched.
  const replaced = new Set(contribution.replacedBatchIds);
  const fresh = contribution.report;

  const coverage = recomposeCoverage(previous.coverage, retried, fresh.coverage);
  const kinds = recomposeKinds(previous.kinds, retried, fresh.kinds);

  const findings = new Map<string, Finding>();
  for (const finding of base.findings) findings.set(finding.id, finding);
  for (const finding of contribution.findings) {
    if (!findings.has(finding.id)) findings.set(finding.id, finding);
  }
  const assurances = new Map<string, Assurance>();
  for (const assurance of base.assurances) assurances.set(assurance.id, assurance);
  for (const assurance of contribution.assurances) {
    if (!assurances.has(assurance.id)) assurances.set(assurance.id, assurance);
  }

  const mergedFindings = [...findings.values()];
  const mergedAssurances = [...assurances.values()];

  const document = FindingsDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: base.runId,
    target: base.target,
    findings: mergedFindings,
    assurances: mergedAssurances,
    coverage: mergeCoverage(subtractCoverage(base.coverage, previous.coverage), coverage),
    droppedFindings: base.droppedFindings + fresh.dropped.unresolved + fresh.dropped.outOfSlice,
  });

  const units = recomposeUnitTotals(kinds);
  /**
   * Units no batch ever returned a verdict for, after the merge.
   *
   * `batch-failed` and `cancelled` both mean the run stopped short of asking, as
   * opposed to asking and being told nothing (`no-verdict`, `inconclusive`) or
   * deciding in advance not to ask (`budget`, `no-batch`), each of which the
   * bound and the coverage table already account for.
   */
  const unreached = units.byCause["batch-failed"] + units.byCause.cancelled;

  /**
   * The bound, recomposed from the merged totals.
   *
   * Carried over untouched, the cover and section 4 of a resumed run quote the
   * *first* attempt's arithmetic — "N of M units were not audited" — directly
   * above a table the same merge has just recomposed to a smaller number. The
   * sentence is derived from these numbers by `describeBound`, so rebuilding it
   * from the merged ones is what keeps the two halves of the page telling the
   * same story.
   *
   * `stop` comes from the retry, because it is the attempt that decided how far
   * this dispatch got. When it ran to the end, `stop` is `complete` and
   * `describeBound` drops the risk-ordering clause on its own — units left
   * without a verdict after a complete dispatch were lost by a batch, not chosen
   * by a ceiling, and saying otherwise would misattribute them.
   */
  const bound = buildAuditBound({
    stop: fresh.bound.stop,
    limits: previous.bound.limits,
    unitsTotal: units.total,
    // Every unit a batch carried, across both attempts; only `no-batch` never did.
    unitsDispatched: units.total - units.byCause["no-batch"],
    unitsAudited: units.audited,
    unitsDeferred: fresh.bound.unitsDeferred,
    // The merged report speaks for the whole run, so nothing is "carried over"
    // from an earlier attempt: the earlier attempt is part of what it describes.
    unitsCarriedOver: 0,
    batchesPlanned: previous.bound.batchesPlanned + fresh.bound.batchesPlanned,
    batchesDispatched: previous.bound.batchesDispatched + fresh.bound.batchesDispatched,
    batchesDeferred: fresh.bound.batchesDeferred,
    ordering: fresh.bound.ordering,
    reasons: fresh.bound.reasons,
  });

  const audit = buildAuditReport({
    ...previous,
    bound,
    // A retry's own flags describe the retry, not the run. Taken verbatim, a
    // retry that itself ran clean declares the whole run finished while the units
    // a usage limit killed on the first attempt are still unaudited — so they
    // only clear once nothing is left unreached.
    aborted: unreached > 0 ? true : fresh.aborted,
    quotaExhausted:
      unreached > 0 ? previous.quotaExhausted || fresh.quotaExhausted : fresh.quotaExhausted,
    durationMs: previous.durationMs + fresh.durationMs,
    runtime: fresh.runtime,
    dispatches: previous.dispatches + fresh.dispatches,
    retries: previous.retries + fresh.retries,
    failures: addCounts(previous.failures, fresh.failures),
    usage: addUsage(previous.usage, fresh.usage),
    batches: [
      ...previous.batches.filter((batch) => !replaced.has(batch.batchId)),
      ...fresh.batches,
    ],
    units,
    coverage,
    kinds,
    // Counted from the merged document, so the number cannot drift from it.
    findingsKept: mergedFindings.filter((finding) => finding.source.kind === "agent").length,
    assurances: mergedAssurances.length,
    dropped: {
      unresolved: previous.dropped.unresolved + fresh.dropped.unresolved,
      unresolvedEvidence: previous.dropped.unresolvedEvidence + fresh.dropped.unresolvedEvidence,
      outOfSlice: previous.dropped.outOfSlice + fresh.dropped.outOfSlice,
      outOfSliceEvidence: previous.dropped.outOfSliceEvidence + fresh.dropped.outOfSliceEvidence,
      duplicates: previous.dropped.duplicates + fresh.dropped.duplicates,
      relocated: previous.dropped.relocated + fresh.dropped.relocated,
      strayVerdicts: previous.dropped.strayVerdicts + fresh.dropped.strayVerdicts,
      assuranceEvidence: previous.dropped.assuranceEvidence + fresh.dropped.assuranceEvidence,
      byReason: addCounts(previous.dropped.byReason, fresh.dropped.byReason),
    },
  });

  return { audit, findings: document, assurances: mergedAssurances, auditCoverage: coverage };
}

/** Writes the three documents a retry rewrote; returns their paths. */
export async function writeMergedRetry(
  fs: Pick<ResumeFileSystem, "writeFile" | "mkdirp">,
  runDir: string,
  merged: MergedRetry,
): Promise<string[]> {
  const findings = await writeMergedFindings(fs, runDir, merged.findings);
  const audit = await writeAuditReport(fs, runDir, merged.audit);
  const assurances = await writeAssurancesDocument(
    fs,
    runDir,
    buildAssurancesDocument({
      runId: merged.audit.runId,
      target: merged.audit.target,
      assurances: merged.assurances,
      coverage: merged.auditCoverage,
    }),
  );
  return [findings, audit, assurances];
}

/**
 * Takes a previous audit back out of `findings.json`.
 *
 * This is what makes a forced re-audit safe. Phase 4's merge adds its coverage
 * to whatever the document already holds, so re-running it over a document that
 * already contains its own last output would double every total and keep
 * findings the new audit no longer stands behind. Stripping first means the
 * fresh audit is merged into phase 1's half alone — exactly the document phase 4
 * saw the first time.
 */
export function subtractAuditFromFindings(
  base: FindingsDocument,
  previous: AuditReport,
): FindingsDocument {
  return FindingsDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: base.runId,
    target: base.target,
    // Everything an agent claimed came from the audit being replaced; the
    // analyzers' findings are phase 1's and stay.
    findings: base.findings.filter((finding) => finding.source.kind !== "agent"),
    assurances: [],
    coverage: subtractCoverage(base.coverage, previous.coverage),
    droppedFindings: Math.max(
      0,
      base.droppedFindings - previous.dropped.unresolved - previous.dropped.outOfSlice,
    ),
  });
}

/** Batch ids worth re-dispatching: the ones that failed or answered partially. */
export function retryableBatchIds(report: AuditReport | null): string[] {
  return (report?.batches ?? [])
    .filter((batch) => batch.status === "failed" || batch.status === "partial")
    .map((batch) => batch.batchId);
}

/** Unit ids belonging to a set of batches, according to a fresh plan. */
export function unitIdsOfBatches(
  batches: readonly { readonly id: string; readonly units: readonly AuditUnit[] }[],
  wanted: ReadonlySet<string>,
): string[] {
  const ids = new Set<string>();
  for (const batch of batches) {
    if (!wanted.has(batch.id)) continue;
    for (const unit of batch.units) ids.add(unit.id);
  }
  return [...ids].sort();
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

/** Phases that cannot run without the repository the run is about. */
const NEEDS_TARGET: ReadonlySet<RunPhaseName> = new Set<RunPhaseName>([
  "profile",
  "propose",
  "scan",
  "inventory",
  "audit",
]);

/** Marker per attempt outcome, matching the phase table `status` prints. */
const ATTEMPT_MARK: Readonly<Record<PhaseAttempt["outcome"], string>> = {
  ran: "[ ok ]",
  skipped: "[skip]",
  failed: "[fail]",
};

/**
 * Where to re-enter.
 *
 * `--force-phase` wins outright. `--retry-failed` is a statement about the
 * audit, so it pulls the entry point back to that phase — but never *forward*
 * past a phase that is itself incomplete, because retrying an audit over an
 * inventory that was never finished would audit the wrong thing. Otherwise the
 * entry is the first phase that did not finish, and a run where every phase
 * finished has none.
 */
export function entryPhaseFor(
  invocation: Pick<ResumeInvocation, "forcePhase" | "retryFailed">,
  phases: readonly RunPhase[],
): RunPhaseName | undefined {
  if (invocation.forcePhase !== undefined) return invocation.forcePhase;
  const incomplete = firstIncompletePhase(phases)?.name;
  if (!invocation.retryFailed) return incomplete;
  if (incomplete === undefined) return "audit";
  return RUN_PHASES.indexOf(incomplete) < RUN_PHASES.indexOf("audit") ? incomplete : "audit";
}

/** Re-enters a run at its first incomplete phase and runs forward from there. */
export async function resumeCommand(
  context: CliContext,
  invocation: ResumeInvocation,
  deps: ResumeDeps,
): Promise<number> {
  const resolution = await resolveRunDir(deps.fs, invocation.runDir, invocation.cwd);
  if (!resolution.ok) {
    context.writeError(`sentinel: ${describeRunDirFailure(resolution, invocation.runDir)}\n`);
    return EXIT.preflight;
  }
  const runDir = resolution.runDir.dir;
  let artifacts = await loadRunArtifacts(deps.fs, runDir);
  let phases = describeRunPhases(artifacts);

  const notes: string[] = [];
  const attempts: PhaseAttempt[] = [];
  const speaks = !invocation.output.json && !invocation.output.quiet;

  const entry = entryPhaseFor(invocation, phases);
  if (entry === undefined) {
    const verdict = assessRun(artifacts, phases);
    if (invocation.output.json) {
      context.write(
        serialise({
          runId: artifacts.runId,
          runDir,
          target: artifacts.target,
          entryPhase: null,
          attempts,
          notes: ["every phase is complete; nothing was re-run"],
          phases,
          verdict,
        } satisfies ResumeJson),
      );
    } else if (speaks) {
      context.write(
        `Run ${artifacts.runId} is complete: every phase finished and the dossier is rendered.\nNothing was re-run, and nothing was spent.\n`,
      );
    }
    return EXIT.ok;
  }

  const entryIndex = RUN_PHASES.indexOf(entry);
  const todo = RUN_PHASES.slice(entryIndex);

  // The target repository is needed by every phase except the render. A run
  // directory that does not record which repository it is about can still be
  // re-rendered, and nothing else.
  const needsTarget = todo.some((phase) => NEEDS_TARGET.has(phase));
  if (needsTarget) {
    if (artifacts.target === "") {
      context.writeError(
        `sentinel: no artifact in ${runDir} records which repository this run is about, so phase "${entry}" cannot be re-entered. \`sentinel report ${runDir}\` still works.\n`,
      );
      return EXIT.preflight;
    }
    if (!(await deps.fs.exists(artifacts.target))) {
      context.writeError(
        `sentinel: ${artifacts.target} does not exist any more, so phase "${entry}" cannot be re-entered. \`sentinel report ${runDir}\` still works.\n`,
      );
      return EXIT.preflight;
    }
  }

  if (speaks) {
    context.write(
      `Resuming ${artifacts.runId} at phase "${entry}"\n  ${runDir}\n  target ${artifacts.target === "" ? "(unknown)" : artifacts.target}\n\n`,
    );
  }

  let failed = false;
  for (const name of todo) {
    const state = phaseByName(phases, name);
    const forced = invocation.forcePhase === name;
    // `--retry-failed` is a request about the audit specifically, so a complete
    // audit is still considered: it may hold batches that answered partially,
    // and those units have no verdict even though the phase finished.
    const retrying = name === "audit" && invocation.retryFailed && artifacts.audit !== null;

    if (state?.status === "complete" && !forced && !retrying) {
      attempts.push({
        name,
        outcome: "skipped",
        summary: `already complete — ${state.detail}`,
        artifacts: [],
      });
      continue;
    }

    /** Batches to re-dispatch, when this is a retry of the audit. */
    let retryBatchIds: readonly string[] | undefined;

    if (name === "audit") {
      const spent = artifacts.audit !== null;
      const retryable = retryableBatchIds(artifacts.audit);
      if (spent && invocation.retryFailed) {
        if (retryable.length === 0) {
          attempts.push({
            name,
            outcome: "skipped",
            summary:
              "--retry-failed: no batch failed or answered partially, so there is nothing to re-dispatch",
            artifacts: [],
          });
          continue;
        }
        // The runner resolves batch ids to unit ids: only it can re-plan.
        retryBatchIds = retryable;
      } else if (spent && !forced) {
        attempts.push({
          name,
          outcome: "skipped",
          summary: `this phase already spent AI budget (${state?.detail ?? "audit.json exists"}); re-run it with --retry-failed to re-dispatch only the units with no verdict, or --force-phase audit to re-dispatch all of them`,
          artifacts: [],
        });
        notes.push(
          "The audit was left alone: a phase that already spent subscription budget is never redone without being asked.",
        );
        continue;
      } else if (forced && spent) {
        notes.push(
          "--force-phase audit re-dispatched every batch; that spends subscription budget again.",
        );
      }
    }

    const request: PhaseRequest = {
      runId: artifacts.runId,
      runDir,
      targetDir: artifacts.target,
      artifacts,
      maxParallel: invocation.maxParallel,
      ...(retryBatchIds === undefined ? {} : { retryBatchIds }),
    };

    if (speaks) context.write(`Running phase "${name}"\n`);
    let outcome: PhaseOutcome;
    try {
      outcome = await deps.runners[name](request);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      outcome = { ok: false, summary: `crashed: ${detail}`, artifacts: [] };
    }

    attempts.push({
      name,
      outcome: outcome.ok ? "ran" : "failed",
      summary: outcome.summary,
      artifacts: outcome.artifacts,
    });
    for (const note of outcome.notes ?? []) notes.push(note);
    if (speaks) context.write(`  ${outcome.ok ? "done" : "failed"}: ${outcome.summary}\n\n`);

    // Every later phase reads what this one wrote, so the artifacts are
    // re-read rather than guessed at.
    artifacts = await loadRunArtifacts(deps.fs, runDir);
    phases = describeRunPhases(artifacts);

    if (!outcome.ok) {
      failed = true;
      break;
    }
  }

  const verdict = assessRun(artifacts, phases);

  if (invocation.output.json) {
    context.write(
      serialise({
        runId: artifacts.runId,
        runDir,
        target: artifacts.target,
        entryPhase: entry,
        attempts,
        notes,
        phases,
        verdict,
      } satisfies ResumeJson),
    );
  } else if (speaks) {
    const width = attempts.reduce((max, attempt) => Math.max(max, attempt.name.length), 0);
    const lines = [
      "Phases",
      ...attempts.map(
        (attempt) =>
          `  ${ATTEMPT_MARK[attempt.outcome]} ${attempt.name.padEnd(width)}  ${attempt.summary}`,
      ),
      ...(notes.length > 0 ? ["", ...notes.map((note) => `  ${note}`)] : []),
      "",
      verdict.shareable
        ? "This run is now complete enough to share with a client."
        : `This run is still not complete enough to share; run \`sentinel status ${runDir}\` for the list.`,
      "",
    ];
    context.write(`${lines.join("\n")}\n`);
  } else if (invocation.output.quiet && failed) {
    context.writeError(`sentinel: resume stopped at phase "${attempts.at(-1)?.name}"\n`);
  }

  return failed ? EXIT.failure : EXIT.ok;
}

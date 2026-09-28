/**
 * Phase 4's running commentary.
 *
 * Phases 0, 1 and 2 finish in seconds and report as they go. Phase 4 is the one
 * that takes an hour, and until this module existed it printed a single line —
 * `Auditing 1,000 units on the Claude subscription` — and then nothing at all
 * until it was done. The only way to tell a live run from a wedged one was to
 * count transcripts in `raw/agents/` from a second terminal. That is the defect
 * this module fixes: **a batch that finishes says so, while the run is still
 * running.**
 *
 * Three rules shape what a line is allowed to claim.
 *
 * 1. **The projection is a mean, not a promise.** The time left is the mean of
 *    the batch durations that have actually completed, multiplied by the number
 *    of fan-out waves still to come. Nothing is modelled, nothing is guessed,
 *    and before enough batches have finished for a mean to mean anything the
 *    line says `~estimating` rather than inventing a number. It is always
 *    prefixed with `~` and always phrased as `left`, never as a finish time: a
 *    subscription can throttle, a batch can retry three times, and a number that
 *    reads like a deadline is a number that will be wrong.
 * 2. **A lost batch is visible while it is being lost.** A failed or partial
 *    batch is reported on its own line, with its classification, and the running
 *    `failed`/`partial` counters stay on every line after it. A run that is
 *    quietly shedding a third of its batches must not look like a healthy one
 *    until the summary at the end.
 * 3. **Cheap enough to sit in the completion path.** This runs inside the
 *    concurrency pool, immediately after a batch resolves. It keeps six running
 *    integers and formats one string; there is no allocation per unit, no
 *    re-scan of what came before, and no I/O beyond the sink it was handed.
 *
 * The sink is injected. `src/audit/` never reaches for `process.stdout` — the
 * writer takes the same `write`/`writeError` pair every other CLI verb uses, so
 * a test asserts on exact bytes and `--json` keeps stdout to one document.
 */

import type { AgentFailureKind } from "../agents/index.ts";
import type { Domain } from "../contracts/findings.ts";
import type { AuditUnitKind } from "../contracts/inventory.ts";

/**
 * Batches that must finish before a mean is reported as a projection.
 *
 * Three durations are not a rate. They are one slow cold start, one cached
 * prompt and one retry, and extrapolating them over ninety batches produces a
 * number wrong by a factor of two in either direction — which is worse than no
 * number, because the reader believes it. The effective threshold is this or the
 * fan-out, whichever is larger, so a run at concurrency 8 waits for a full wave.
 */
export const MIN_PROJECTION_SAMPLES = 4;

/** The `event` field on every `--json` progress object, so a consumer can filter. */
export const PROGRESS_EVENT = "audit-batch";

// ---------------------------------------------------------------------------
// What a finished batch says
// ---------------------------------------------------------------------------

/**
 * What the tracker reads off a batch that just finished.
 *
 * Structural rather than imported: `BatchReport` from `./artifacts.ts` satisfies
 * it, which is the point — the numbers on a progress line and the numbers in
 * `audit.json` come from the same object, so the terminal cannot disagree with
 * the artifact about how a batch ended.
 */
export interface BatchCompletion {
  readonly batchId: string;
  readonly domain: Domain;
  readonly kinds: readonly AuditUnitKind[];
  /** Units the batch was asked about. */
  readonly units: number;
  readonly status: "audited" | "partial" | "failed";
  /** How the dispatch failed, when it did. */
  readonly failure?: AgentFailureKind | undefined;
  /** The batch's own sentence about why it is not `audited`. */
  readonly reason?: string | undefined;
  /** Units of this batch that came back with a verdict. */
  readonly verdicts: number;
  /** Findings kept from this batch, after verification and the slice gate. */
  readonly findings: number;
  readonly durationMs: number;
}

/**
 * One batch's completion, with the run's totals as of that moment.
 *
 * Everything a line or a JSON object needs is here, already reduced: a writer
 * formats, it never counts.
 */
export interface BatchProgress {
  readonly batchId: string;
  readonly domain: Domain;
  readonly kinds: readonly AuditUnitKind[];
  readonly status: "audited" | "partial" | "failed";
  readonly failure?: AgentFailureKind | undefined;
  readonly reason?: string | undefined;
  /** Units this batch carried, and how many of them came back with a verdict. */
  readonly units: number;
  readonly verdicts: number;
  /** This batch's own wall clock. */
  readonly durationMs: number;
  /** Batches finished, this one included, out of the batches that will be dispatched. */
  readonly batchesDone: number;
  readonly batchesTotal: number;
  /** Batches lost so far, kept apart because they cost different things. */
  readonly batchesFailed: number;
  readonly batchesPartial: number;
  /** Units put in front of a model so far, whatever came back. */
  readonly unitsDispatched: number;
  /** Units that came back with a verdict so far; the number the report will use. */
  readonly unitsAudited: number;
  /** Units the planned batches cover, so both ratios on a line complete together. */
  readonly unitsTotal: number;
  /** Findings kept so far, after verification and the slice gate. */
  readonly findings: number;
  /** Wall clock since the phase started. */
  readonly elapsedMs: number;
  /**
   * Projected wall clock still to come, or null while the mean is not yet worth
   * reporting. Never a deadline; see this module's own header.
   */
  readonly remainingMs: number | null;
}

/** What phase 4 calls when a batch finishes; the CLI's writer, or nothing. */
export type AuditProgress = (progress: BatchProgress) => void;

/** Where a finished progress line goes, newline included. */
export type ProgressSink = (text: string) => void;

// ---------------------------------------------------------------------------
// The accounting
// ---------------------------------------------------------------------------

/** Accumulates finished batches and reports each one as it lands. */
export interface ProgressTracker {
  /** Records a finished batch and reports it. Six additions and one string. */
  readonly completed: (batch: BatchCompletion) => void;
}

/** What {@link createProgressTracker} needs to turn a batch into a line. */
export interface ProgressTrackerOptions {
  /** Where each event goes; the CLI's writer. */
  readonly report: AuditProgress;
  /** Batches that will be dispatched, after the scope filter and the plan's budget. */
  readonly batchesTotal: number;
  /** Units those batches cover. */
  readonly unitsTotal: number;
  /** The dispatch fan-out, which is how many batches a wave gets through at once. */
  readonly concurrency: number;
  /** The phase's own start, on the same clock as `now`. */
  readonly startedAt: number;
  /** The monotonic clock; phase 4 passes the one it measures itself with. */
  readonly now: () => number;
  /** Overrides {@link MIN_PROJECTION_SAMPLES}; a test pins it, production does not. */
  readonly minSamples?: number | undefined;
}

/**
 * Builds the tracker phase 4 calls from its completion path.
 *
 * The projection is `mean(completed durations) × ceil(remaining / fan-out)`: a
 * batch takes about as long as the ones before it took, and `concurrency` of
 * them run at once, so what is left is that many waves. At roughly a minute per
 * batch and a fan-out of two, 72 remaining batches read as 36 waves and about
 * half an hour — which is the arithmetic a reader would do themselves if they had
 * the numbers.
 */
export function createProgressTracker(options: ProgressTrackerOptions): ProgressTracker {
  const fanOut = Math.max(1, Math.floor(options.concurrency));
  const samplesNeeded = Math.max(1, options.minSamples ?? Math.max(MIN_PROJECTION_SAMPLES, fanOut));

  let batchesDone = 0;
  let batchesFailed = 0;
  let batchesPartial = 0;
  let unitsDispatched = 0;
  let unitsAudited = 0;
  let findings = 0;
  let durationSum = 0;

  return {
    completed: (batch: BatchCompletion): void => {
      batchesDone += 1;
      if (batch.status === "failed") batchesFailed += 1;
      else if (batch.status === "partial") batchesPartial += 1;
      unitsDispatched += batch.units;
      unitsAudited += batch.verdicts;
      findings += batch.findings;
      durationSum += batch.durationMs;

      const remaining = Math.max(0, options.batchesTotal - batchesDone);
      // Null, not zero: "not enough evidence for a rate" and "no time left" are
      // different claims, and the line renders them as different words.
      const remainingMs =
        batchesDone < samplesNeeded
          ? null
          : Math.round((durationSum / batchesDone) * Math.ceil(remaining / fanOut));

      options.report({
        batchId: batch.batchId,
        domain: batch.domain,
        kinds: batch.kinds,
        status: batch.status,
        ...(batch.failure === undefined ? {} : { failure: batch.failure }),
        ...(batch.reason === undefined ? {} : { reason: batch.reason }),
        units: batch.units,
        verdicts: batch.verdicts,
        durationMs: batch.durationMs,
        batchesDone,
        batchesTotal: options.batchesTotal,
        batchesFailed,
        batchesPartial,
        unitsDispatched,
        unitsAudited,
        unitsTotal: options.unitsTotal,
        findings,
        elapsedMs: Math.max(0, Math.round(options.now() - options.startedAt)),
        remainingMs,
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/** A span a human reads at a glance: `42s`, `12m`, `1h 04m`. */
export function formatSpan(ms: number): string {
  const seconds = Math.max(0, Math.round(ms / 1_000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h ${String(minutes % 60).padStart(2, "0")}m`;
}

/** How a batch ended, in the words that belong beside its unit count. */
function markOf(progress: BatchProgress): string {
  if (progress.status === "audited") return "";
  if (progress.status === "failed") {
    return progress.failure === undefined ? " failed" : ` failed (${progress.failure})`;
  }
  return ` partial (${progress.verdicts}/${progress.units} verdicts)`;
}

/** Knobs {@link formatProgressLine} reads off the run's output flags. */
export interface ProgressLineOptions {
  /** `--verbose`: adds the batch id, and names every unit kind instead of the first. */
  readonly verbose?: boolean | undefined;
}

/**
 * One batch's line, as a person watching the run reads it.
 *
 * ```
 * [23/95] route × 14 · 312/1000 units · 7 findings · 12m elapsed · ~38m left
 * ```
 *
 * A batch that did not come back clean adds its classification to the second
 * segment and its own sentence on an indented line below, so the watchable line
 * keeps its shape and a problem still arrives in full. Note the units counter:
 * it does not move, because a failed batch produced no verdicts.
 *
 * ```
 * [24/95] route × 14 failed (timeout) · 312/1000 units · 7 findings · 13m elapsed · ~37m left · 1 failed
 *     no reply within 240000ms
 * ```
 *
 * The returned text carries no trailing newline; the writer adds it.
 */
export function formatProgressLine(
  progress: BatchProgress,
  options: ProgressLineOptions = {},
): string {
  const verbose = options.verbose === true;
  const kinds = verbose ? progress.kinds.join(", ") : (progress.kinds[0] ?? progress.domain);

  const segments: string[] = [];
  if (verbose) segments.push(progress.batchId);
  segments.push(`${kinds} × ${progress.units}${markOf(progress)}`);
  segments.push(`${progress.unitsAudited}/${progress.unitsTotal} units`);
  segments.push(`${progress.findings} ${progress.findings === 1 ? "finding" : "findings"}`);
  segments.push(`${formatSpan(progress.elapsedMs)} elapsed`);
  // The projection is dropped rather than shown as zero on the last batch: a
  // line that ends in `~0s left` invites the reader to wait for something.
  if (progress.batchesDone < progress.batchesTotal) {
    segments.push(
      progress.remainingMs === null ? "~estimating" : `~${formatSpan(progress.remainingMs)} left`,
    );
  }
  // Cumulative, and on every line after the first loss: a reader who scrolled
  // past the failure itself still has to be able to see that it happened.
  if (progress.batchesFailed > 0) segments.push(`${progress.batchesFailed} failed`);
  if (progress.batchesPartial > 0) segments.push(`${progress.batchesPartial} partial`);

  const line = `[${progress.batchesDone}/${progress.batchesTotal}] ${segments.join(" · ")}`;
  const reason = progress.status === "audited" ? undefined : progress.reason;
  return reason === undefined || reason === "" ? line : `${line}\n    ${reason}`;
}

/**
 * One batch as a single JSON object, for `--json`.
 *
 * Emitted on stderr, one object per line, so the document `analyze --json`
 * writes to stdout stays exactly one parseable value. `estimating` is spelled
 * out beside `remainingMs` because a consumer must not have to infer the
 * difference between "no estimate yet" and "no time left" from a null.
 */
export function formatProgressJson(progress: BatchProgress): string {
  return JSON.stringify({
    event: PROGRESS_EVENT,
    ...progress,
    estimating: progress.remainingMs === null,
  });
}

/** The streams and flags a progress writer is built from; the CLI's own. */
export interface ProgressWriterOptions {
  /** The prose sink: the same stdout `write` every other line of the run uses. */
  readonly write: ProgressSink;
  /**
   * The stderr sink, which is where `--json` progress goes.
   *
   * Required even though the prose writer never touches it: which stream a
   * writer uses depends on the flags, and a writer built without this one would
   * put JSONL into the middle of the run's own JSON document.
   */
  readonly writeError: ProgressSink;
  readonly json?: boolean | undefined;
  readonly verbose?: boolean | undefined;
  readonly quiet?: boolean | undefined;
}

/**
 * Builds the per-batch writer for one run's output flags, or nothing.
 *
 * `undefined` under `--quiet` rather than a writer that formats and discards:
 * phase 4 skips the accounting entirely when nobody is listening.
 */
export function createProgressWriter(options: ProgressWriterOptions): AuditProgress | undefined {
  if (options.quiet === true) return undefined;
  if (options.json === true) {
    return (progress) => options.writeError(`${formatProgressJson(progress)}\n`);
  }
  const verbose = options.verbose === true;
  return (progress) => options.write(`${formatProgressLine(progress, { verbose })}\n`);
}

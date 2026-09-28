/**
 * Phase 4 — the audit.
 *
 * The one rule this whole phase exists to enforce:
 *
 * > **Sentinel feeds the code to the model; the model never reads files.**
 *
 * The inventory located every unit and sliced its source off disk; the batch
 * builder pasted those slices into the prompt. The agent gets no filesystem, no
 * shell and no tools — only text. So every claim it returns has to point at a
 * line it was shown, and this module enforces that twice over:
 *
 * 1. **Verification.** Every citation goes through `src/verify/`, which opens
 *    the file, proves the line exists and extracts the snippet itself. A
 *    citation that does not resolve drops its finding.
 * 2. **The slice gate.** Every *verified* citation is then checked against the
 *    line ranges the batch actually provided. A citation that resolves but
 *    falls outside them is dropped too, and counted separately — because it
 *    means the model answered from memory rather than from the code in front of
 *    it, and that is the precise failure this architecture was built to catch.
 *    An agent handed tools to fetch code can fail every read silently and answer
 *    from what it already believed; this one is handed the code instead, and the
 *    `outOfSlice` counter is how a Sentinel run notices a claim that came from
 *    somewhere other than the slice anyway.
 *
 * The other half of the phase is coverage. A batch that fails does not abort
 * the run: its units are recorded as skipped, with the failure that cost them,
 * and they reach the report as *not audited*. A unit with no verdict is never
 * a clean unit. That distinction is the difference between a dossier and a
 * reassuring document.
 *
 * ## The three collaborators
 *
 * Batching, prompting and the verdict schema are injected rather than imported:
 * `buildBatches` (`./batch.ts`), `buildPrompt` (`./prompts/`) and
 * `VerdictBatchSchema` (`./verdict.ts`) are owned elsewhere, and each is
 * coupled to this module through exactly one adapter — {@link BatchPlanner},
 * {@link PromptBuilder} and {@link VerdictSource}. The structural types below
 * are the contract between them; anything a collaborator adds beyond them is
 * its own business.
 */

import type { z } from "zod";
import {
  type AgentFailureKind,
  type AgentRequest,
  type AgentRunStats,
  type AgentRuntime,
  type StructuredResult,
  createSemaphore,
  toAgentError,
} from "../agents/index.ts";
import type {
  Assurance,
  AuditUnit,
  CodeRef,
  Confidence,
  Coverage,
  Domain,
  Finding,
  FindingsDocument,
  Severity,
} from "../contracts/findings.ts";
import { DomainSchema, SCHEMA_VERSION } from "../contracts/findings.ts";
import { ATTRIBUTE, type AuditUnitKind } from "../contracts/inventory.ts";
import type { StackProfile } from "../contracts/profile.ts";
import type { Logger } from "../ports/logger.ts";
import { makeFinding } from "../scan/runners/_runner-support.ts";
import {
  DROP_REASONS,
  type DropReason,
  type VerifyCache,
  type VerifyContext,
  createVerifyCache,
  resolveRepoPath,
  verifyCodeRef,
  verifyFinding,
} from "../verify/index.ts";
import {
  type AuditContribution,
  type AuditReport,
  type BatchReport,
  type DropAccounting,
  buildAssurancesDocument,
  buildAuditReport,
  mergeAuditIntoFindings,
  readFindingsDocument,
  readInventoryDocument,
  writeAssurancesDocument,
  writeAuditReport,
  writeMergedFindings,
} from "./artifacts.ts";
import { type AssertedCheck, buildAssurances, compareKinds } from "./assurance.ts";
import {
  type AuditBound,
  type BudgetStop,
  DEFAULT_MAX_WALL_CLOCK_MS,
  UNBOUNDED_BUDGET,
  buildAuditBound,
} from "./budget.ts";
import {
  DOMAIN_BY_UNIT_KIND,
  type KindCoverage,
  type SkipCause,
  type UnitOutcome,
  type UnitTotals,
  buildAuditCoverage,
  buildKindCoverage,
  buildUnitTotals,
  coverageReconciles,
} from "./coverage.ts";
import { type AuditProgress, createProgressTracker } from "./progress.ts";
import { RISK_ORDERING } from "./risk.ts";

/** `source.name` on every finding this phase produces; renders as `agent:audit`. */
export const AUDIT_SOURCE = "audit";

// ---------------------------------------------------------------------------
// What a batch is, as far as this phase is concerned
// ---------------------------------------------------------------------------

/**
 * A line range that was pasted into a batch's prompt.
 *
 * `CodeSlice` from `src/inventory/slice.ts` satisfies this structurally, which
 * is the point: the slicer is what produced the text the agent saw, so its own
 * idea of what it handed over is the only trustworthy definition of "in slice".
 */
export interface SliceExtent {
  /** Repo-relative POSIX path, as the slicer emits it. */
  readonly file: string;
  readonly startLine: number;
  readonly endLine: number;
}

/**
 * What the audit phase needs from a batch.
 *
 * `slices` is the load-bearing field. It is not documentation of the prompt —
 * it *is* the set of lines the agent was allowed to talk about, and the gate
 * that drops everything else reads it directly. A batch that reports slices it
 * did not paste, or omits slices it did, breaks the guarantee the phase makes.
 */
export interface AuditBatch {
  /** Stable across runs for a given inventory: it keys the transcript and the replay. */
  readonly id: string;
  /**
   * The domain whose checks this batch runs. Optional only so a planner that
   * batches by unit kind alone still works; then {@link DOMAIN_BY_UNIT_KIND}
   * decides, which is coarser than a planner that knows what it asked.
   */
  readonly domain?: Domain | undefined;
  /** The units the agent must return a verdict for — every one of them. */
  readonly units: readonly AuditUnit[];
  /** Every source range the prompt contains. */
  readonly slices: readonly SliceExtent[];
}

/**
 * A unit phase 3 deliberately did not batch, with the reason it gives.
 *
 * Structural rather than imported: `./batch.ts`'s `SkippedUnit` satisfies it,
 * and this phase only needs the three fields so that a unit a *ceiling* held
 * back is counted as `budget` in the coverage table instead of collapsing into
 * `no-batch`. "Nobody planned a batch for it" and "the run could not afford it"
 * are different sentences, and only the second one is resumable.
 */
export interface PlannedSkip {
  readonly unitId: string;
  readonly reason: string;
  readonly cause?: SkipCause | undefined;
  /**
   * The domain whose questions the unit will not be asked, when the planner
   * deferred it in one domain and not in another.
   *
   * A unit is audited once per domain that has a prompt for its kind, so a route
   * whose access-control batch was dispatched and whose contract batch the budget
   * held back has a verdict in `appsec` and owes one in `api`. Without this, the
   * loop below would see the unit as claimed and file nothing, and the `api` row
   * would count it out of its own total — reporting a clean fraction of the
   * repository as the whole of it. Absent means no batch in any domain covered
   * the unit, and {@link DOMAIN_BY_UNIT_KIND} decides where it is counted.
   */
  readonly domain?: Domain | undefined;
}

/** What the phase reads off a planner that can describe its own plan. */
export interface PlannerDisclosure {
  readonly skipped?: readonly PlannedSkip[] | undefined;
  readonly bound?: AuditBound | undefined;
}

/**
 * `buildBatches` from `./batch.ts`, as this phase calls it.
 *
 * The optional `plan()` is how the planner's own disclosures reach the coverage
 * table: `createBatchPlanner` already exposes it, and a planner that does not is
 * still a valid planner — its un-batched units simply read `no-batch` with this
 * phase's generic reason instead of phase 3's specific one.
 */
export type BatchPlanner = ((
  units: readonly AuditUnit[],
  ctx: AuditContext,
) => readonly AuditBatch[] | Promise<readonly AuditBatch[]>) & {
  readonly plan?: () => PlannerDisclosure | undefined;
};

/** The two halves of a prompt, as `./prompts/` returns them. */
export interface AuditPrompt {
  /** The role and the rules; constant across a phase so the prompt cache can hold it. */
  readonly system: string;
  /** The work: the units, their attributes, and the source slices read from disk. */
  readonly user: string;
}

/** `buildPrompt` from `./prompts/`, as this phase calls it. */
export type PromptBuilder = (
  batch: AuditBatch,
  ctx: AuditContext,
) => AuditPrompt | Promise<AuditPrompt>;

// ---------------------------------------------------------------------------
// What an agent replies, as far as this phase is concerned
// ---------------------------------------------------------------------------

/** A citation as the agent writes it, before Sentinel has proved anything about it. */
export interface VerdictRef {
  readonly file: string;
  readonly line: number;
  readonly endLine?: number | undefined;
  readonly note?: string | undefined;
  /**
   * The cited line as the agent read it, used *only* to correct a line number
   * that drifted, and never rendered: the snippet in the report is always the
   * one `src/verify/` extracts from disk.
   *
   * Without a quote a citation is taken at its word, in range, because there is
   * nothing to anchor a correction to. Note what must *not* be used as that
   * anchor: the audited unit's symbol. A finding points at a line inside the
   * unit — the query, the write — and anchoring on the unit's name would
   * "correct" every one of those onto the function's declaration line.
   */
  readonly quote?: string | undefined;
}

/** A check the agent asserts a unit passes; the raw material of an `Assurance`. */
export interface VerdictCheck {
  /** Dotted check id, e.g. `appsec.ownership-asserted-before-write`. */
  readonly id: string;
  /** One sentence in the report's voice: `ownership asserted before write`. */
  readonly statement: string;
  /** Plural noun for the population, e.g. `mutation handlers`. */
  readonly subject?: string | undefined;
  readonly evidence?: readonly VerdictRef[] | undefined;
}

/** A problem the agent claims, before any of its citations have been proved. */
export interface VerdictFinding {
  /** Dotted rule id, e.g. `appsec.missing-ownership-check`. */
  readonly rule: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly title: string;
  readonly description: string;
  readonly impact: string;
  readonly recommendation: string;
  readonly location: VerdictRef;
  /** Overrides the batch's domain, for a batch whose checks span two. */
  readonly domain?: Domain | undefined;
  readonly evidence?: readonly VerdictRef[] | undefined;
  readonly exploitability?: string | undefined;
  readonly acceptanceCriteria?: readonly string[] | undefined;
  readonly cwe?: readonly string[] | undefined;
  readonly owasp?: readonly string[] | undefined;
}

/**
 * The agent's answer about one unit.
 *
 * `inconclusive` is a first-class answer and is *not* a clean unit: the unit is
 * recorded as skipped, so the report says it was not audited. A model that is
 * unsure has to be able to say so without that reading as a pass.
 */
export interface UnitVerdict {
  readonly unitId: string;
  readonly status: "clean" | "flagged" | "inconclusive";
  readonly checks?: readonly VerdictCheck[] | undefined;
  readonly findings?: readonly VerdictFinding[] | undefined;
  /** Why the agent could not decide, when it says `inconclusive`. */
  readonly note?: string | undefined;
}

/** A whole batch reply, as this phase consumes it. */
export interface BatchVerdicts {
  readonly batchId?: string | undefined;
  readonly verdicts: readonly UnitVerdict[];
}

/**
 * The one adapter between this phase and `./verdict.ts`.
 *
 * `schema` is what the runtime validates the reply against — agent output is
 * untrusted input and never reaches this module unvalidated. `read` narrows the
 * validated payload to the fields the phase consumes, so if `VerdictBatchSchema`
 * names something differently, this lambda is the only thing that changes.
 */
export interface VerdictSource<Schema extends z.ZodType> {
  /** `VerdictBatchSchema`. */
  readonly schema: Schema;
  /** Usually the identity function; a shape mapper when the names differ. */
  readonly read: (value: z.output<Schema>) => BatchVerdicts;
}

// ---------------------------------------------------------------------------
// Context and options
// ---------------------------------------------------------------------------

/** The filesystem operations phase 4 needs; the real port satisfies it structurally. */
export interface AuditFileSystem {
  readFile(path: string): Promise<string>;
  readFileBytes(path: string): Promise<Uint8Array>;
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  mkdirp(path: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  realpath(path: string): Promise<string>;
}

/**
 * Everything phase 4 is handed.
 *
 * The field names are phase 1's and phase 2's, so the CLI passes one context
 * object through all three and they cannot disagree about which directory is
 * the target. Note what is *not* here: no process executor. This phase spawns
 * nothing, and the agent it talks to cannot reach the filesystem at all.
 */
export interface AuditContext {
  /** The target repository is read, never written to; artifacts go to `runDir`. */
  readonly fs: AuditFileSystem;
  /** Absolute path of the repository under analysis. */
  readonly targetDir: string;
  /** Absolute path of this run's output directory. */
  readonly runDir: string;
  /** Identifies the run in every artifact it writes. */
  readonly runId: string;
  /** Phase 0 output, for a prompt that wants to name the stack it is auditing. */
  readonly profile?: StackProfile | undefined;
  readonly logger: Logger;
  /** Cancels the phase; the runtime forwards it to every in-flight dispatch. */
  readonly signal?: AbortSignal | undefined;
}

/** Knobs for {@link runAudit}. The three collaborators are required; the rest default. */
export interface AuditOptions<Schema extends z.ZodType> {
  /** The AI runtime. Its own semaphore is the phase's concurrency control. */
  readonly runtime: AgentRuntime;
  /** The verdict schema and its adapter; see {@link VerdictSource}. */
  readonly verdicts: VerdictSource<Schema>;
  /** `buildBatches` from `./batch.ts`. */
  readonly batches: BatchPlanner;
  /** `buildPrompt` from `./prompts/`. */
  readonly prompt: PromptBuilder;
  /** The units to audit. Read from `inventory.json` in the run directory when omitted. */
  readonly units?: readonly AuditUnit[] | undefined;
  /**
   * The enabled scope from phase 0.5. A batch for a domain outside it is not
   * dispatched and its units are not counted, exactly as phase 1 treats a step
   * for an out-of-scope domain. Omitted means every domain.
   */
  readonly domains?: readonly Domain[] | undefined;
  /** Evidence refs per assurance before it starts sampling. */
  readonly maxEvidencePerAssurance?: number | undefined;
  /**
   * The exact line-level slice gate, when the batch builder can provide one.
   * Defaults to the extent gate; see {@link ShownLines}.
   */
  readonly shown?: ShownLines | undefined;
  /**
   * Wall clock the dispatch loop may spend, in milliseconds. Omitted or `null`
   * means no ceiling; `./budget.ts` decides the default the CLI passes.
   *
   * It is checked **between** batches, never inside one: a batch that has been
   * sent is always awaited and always counted, because truncating a dispatch
   * spends the tokens and throws away the verdicts.
   */
  readonly maxWallClockMs?: number | null | undefined;
  /**
   * The monotonic clock the wall-clock ceiling reads; defaults to
   * `performance.now`. Injected so a test can prove the ceiling without
   * spending the wall clock it is testing.
   */
  readonly now?: (() => number) | undefined;
  /**
   * Unit ids an earlier attempt in this run directory already has a verdict for.
   *
   * They produce no outcome here — their coverage belongs to the report the
   * earlier attempt wrote, and `sentinel resume` recomposes the two — but they
   * are counted in `bound.unitsCarriedOver`, so the sentence the dossier prints
   * is about the repository rather than about this dispatch. The same set is
   * given to the planner as `exclude`, which is what makes a resumed run pick up
   * the *next* highest-risk units instead of redoing these.
   */
  readonly alreadyAudited?: readonly string[] | undefined;
  /**
   * Called as each batch finishes, from inside the dispatch pool's completion
   * path — which is what keeps this phase from going silent for the hour it
   * takes. See `./progress.ts`: the CLI builds the writer from its own streams
   * and output flags, and omitting this (`--quiet`, a library caller with
   * nothing to print to) skips the accounting entirely.
   */
  readonly progress?: AuditProgress | undefined;
  /** Write `audit.json`, `assurances.json` and the merged `findings.json`. Default true. */
  readonly write?: boolean | undefined;
}

/** Everything phase 4 produced, in memory, whether or not it was written. */
export interface AuditResult {
  readonly runId: string;
  readonly target: string;
  /** Verified findings; every snippet was extracted from disk by `src/verify`. */
  readonly findings: readonly Finding[];
  readonly assurances: readonly Assurance[];
  /** Per-domain coverage, as this phase saw it. */
  readonly coverage: readonly Coverage[];
  /** Per-unit-kind coverage: the `200/200 route handlers` line. */
  readonly kinds: readonly KindCoverage[];
  /** One per dispatched batch, in planning order. */
  readonly batches: readonly BatchReport[];
  readonly units: UnitTotals;
  /**
   * What the run's ceilings left out, and the one sentence that says so.
   *
   * The CLI prints `bound.statement`, the coverage table carries the same
   * numbers per unit, and `audit.json` holds the whole block for the dossier.
   * On an unbounded run that finished, it says exactly that.
   */
  readonly bound: AuditBound;
  readonly dropped: DropAccounting;
  readonly stats: AgentRunStats;
  readonly report: AuditReport;
  /** `findings.json` with the audit merged in; null when writing was turned off. */
  readonly document: FindingsDocument | null;
  /** True when the run was cancelled, or a subscription limit stopped the phase. */
  readonly aborted: boolean;
  readonly durationMs: number;
  /** Absolute paths this phase wrote. */
  readonly artifacts: readonly string[];
}

// ---------------------------------------------------------------------------
// The slice gate
// ---------------------------------------------------------------------------

/** The line ranges one batch provided, grouped by file. */
export type SliceIndex = ReadonlyMap<string, ReadonlyArray<{ start: number; end: number }>>;

/** Whether one line of one file was actually printed in a batch's prompt. */
export type ShownLineTest = (file: string, line: number) => boolean;

/**
 * Builds the exact "was this line shown" test for a batch.
 *
 * The default gate works from the slice extents alone, which cannot tell an
 * elided line from a printed one — a slice over its budget keeps the head, the
 * tail and a window, and says so with an elision marker, but its extent still
 * spans the lines it removed. A batch builder that knows which lines it printed
 * can close that gap: `src/audit/batch.ts` exposes `citedRanges` and `wasShown`,
 * which read the line numbers back out of the gutter the slicer wrote.
 *
 * The batch arrives here as the structural {@link AuditBatch} this phase
 * declares, not as the builder's own richer type, so the wiring indexes its
 * plan by batch id rather than re-deriving it from the argument:
 *
 * ```ts
 * const plan = await buildBatches(units, ctx);
 * const ranges = new Map(plan.map((b) => [b.id, citedRanges(b)]));
 * const shown: ShownLines = (batch) => {
 *   const own = ranges.get(batch.id);
 *   // No entry: fall back to the extent gate rather than admitting nothing.
 *   return (file, line) => own === undefined || wasShown(own, file, line);
 * };
 * ```
 *
 * With that in place a model citing a line it was told had been removed is
 * caught with the rest.
 */
export type ShownLines = (batch: AuditBatch) => ShownLineTest;

/**
 * Indexes a batch's slices by repo-relative path.
 *
 * Paths are normalised through the verifier's own resolver, so a slice spelled
 * `./src/api/users.ts` and a verified citation spelled `src/api/users.ts` are
 * the same file. A slice whose path does not resolve inside the target is
 * dropped from the index — it could not have been read from this repository, so
 * nothing may be cited against it.
 */
export function buildSliceIndex(
  slices: readonly SliceExtent[],
  targetDir: string,
): Map<string, Array<{ start: number; end: number }>> {
  const index = new Map<string, Array<{ start: number; end: number }>>();
  for (const slice of slices) {
    const resolved = resolveRepoPath(slice.file, targetDir);
    if (!resolved.ok) continue;
    const start = Math.max(1, Math.min(slice.startLine, slice.endLine));
    const end = Math.max(slice.startLine, slice.endLine);
    const ranges = index.get(resolved.value.relative);
    if (ranges === undefined) index.set(resolved.value.relative, [{ start, end }]);
    else ranges.push({ start, end });
  }
  return index;
}

/** The slice containing a line, or undefined when the agent was never shown it. */
function containing(
  index: SliceIndex,
  file: string,
  line: number,
): { start: number; end: number } | undefined {
  for (const range of index.get(file) ?? []) {
    if (line >= range.start && line <= range.end) return range;
  }
  return undefined;
}

/**
 * Gates one verified citation on the slices the batch provided.
 *
 * Returns null when the cited line is outside all of them — the model reached
 * for something it was not shown. An `endLine` that runs past the slice is
 * clamped to it rather than refused: the agent can only have read as far as the
 * slice went, so that is how far the claim reaches.
 *
 * Without a `shown` test, a line inside a slice's extent but inside an *elided*
 * stretch of it is accepted, because `CodeSlice` reports the extent it rendered
 * and not which lines survived its budget. {@link ShownLines} closes that gap
 * when the batch builder can say which lines it printed; the extent gate is the
 * floor, not the ceiling.
 */
export function gateRef(ref: CodeRef, index: SliceIndex, shown?: ShownLineTest): CodeRef | null {
  const range = containing(index, ref.file, ref.line);
  if (range === undefined) return null;
  // The extents said the file and the block were provided; `shown`, when the
  // batch builder can supply it, says whether that exact line was printed.
  if (shown !== undefined && !shown(ref.file, ref.line)) return null;
  if (ref.endLine === undefined || ref.endLine <= range.end) return ref;
  // The claim runs past what the agent was shown. The start line is real and in
  // slice, so the finding stands, but its extent is cut back to the slice and
  // the ref says so — the alternative is a report claiming a problem spans
  // lines the model never read.
  const clamped = Math.max(ref.line, range.end);
  const note = `extent clamped to line ${clamped}; the agent was shown ${range.start}-${range.end} and cited ${ref.endLine}`;
  // Rebuilt field by field rather than spread: a spread would keep the
  // out-of-slice `endLine` in the one case where the clamp collapses it away.
  return {
    file: ref.file,
    line: ref.line,
    ...(clamped > ref.line ? { endLine: clamped } : {}),
    ...(ref.snippet === undefined ? {} : { snippet: ref.snippet }),
    note: ref.note === undefined || ref.note === "" ? note : `${ref.note} · ${note}`,
  };
}

/** A finding that passed the gate, with the evidence the gate removed counted. */
interface GatedFinding {
  readonly finding: Finding;
  readonly droppedEvidence: number;
}

/** Gates a verified finding: its location must be in slice, its evidence is filtered. */
export function gateFinding(
  finding: Finding,
  index: SliceIndex,
  shown?: ShownLineTest,
): GatedFinding | null {
  const location = gateRef(finding.location, index, shown);
  if (location === null) return null;
  const evidence: CodeRef[] = [];
  let droppedEvidence = 0;
  for (const ref of finding.evidence) {
    const gated = gateRef(ref, index, shown);
    if (gated === null) droppedEvidence += 1;
    else evidence.push(gated);
  }
  return { finding: { ...finding, location, evidence }, droppedEvidence };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A zeroed counter for every verifier drop reason, so the report shows no gap. */
function emptyReasons(): Record<DropReason, number> {
  const reasons = {} as Record<DropReason, number>;
  for (const reason of DROP_REASONS) reasons[reason] = 0;
  return reasons;
}

/** The domain a batch's units are counted against. */
export function batchDomain(batch: AuditBatch): Domain {
  if (batch.domain !== undefined) return batch.domain;
  const kind = batch.units[0]?.kind;
  return kind === undefined ? "appsec" : DOMAIN_BY_UNIT_KIND[kind];
}

/** One coverage cell: a unit in one domain. Both tables are counted in these. */
function coverageKey(domain: Domain, unitId: string): string {
  return `${domain}\u0000${unitId}`;
}

/**
 * The domains a unit still owes an answer in, when no batch of them claimed it.
 *
 * Read off what phase 3 and the clock actually said, never off a table of kinds:
 * the planner names the domain it deferred a unit for, and a batch the clock held
 * back carries its own. A unit nobody mentioned — a citation that no longer
 * resolves, a kind no prompt covers — falls back to the one domain
 * {@link DOMAIN_BY_UNIT_KIND} gives its kind, because a unit nobody looked at
 * still has to appear in exactly one table rather than in none.
 */
function domainsOwed(
  unit: AuditUnit,
  planned: readonly PlannedSkip[] | undefined,
  clockStopped: ReadonlyMap<string, string>,
): readonly { readonly domain: Domain; readonly cause?: SkipCause; readonly reason?: string }[] {
  const owed = new Map<Domain, { domain: Domain; cause?: SkipCause; reason?: string }>();
  for (const skip of planned ?? []) {
    const domain = skip.domain ?? DOMAIN_BY_UNIT_KIND[unit.kind];
    if (owed.has(domain)) continue;
    owed.set(domain, {
      domain,
      ...(skip.cause === undefined ? {} : { cause: skip.cause }),
      ...(skip.reason === undefined ? {} : { reason: skip.reason }),
    });
  }
  for (const domain of DomainSchema.options) {
    if (owed.has(domain)) continue;
    if (!clockStopped.has(coverageKey(domain, unit.id))) continue;
    owed.set(domain, { domain });
  }
  const fallback = DOMAIN_BY_UNIT_KIND[unit.kind];
  if (owed.size === 0) owed.set(fallback, { domain: fallback });
  return [...owed.values()];
}

/** The unit kinds a batch carries, de-duplicated, in the contract's own order. */
function batchKinds(batch: AuditBatch): AuditUnitKind[] {
  return [...new Set(batch.units.map((unit) => unit.kind))].sort(compareKinds);
}

/**
 * Wall-clock budget for the kinds that reliably need more than the default.
 *
 * A dispatch's wall time is driven by how much the agent has to *write*, not by
 * how much it was given to read, and how much it has to write is a property of
 * the kind: a `cron` batch answers in a couple of kilobytes, a `migration` batch
 * in tens of them, and the durations follow the replies by close to the same
 * factor. Against the runtime's 240 s default that puts `route` batches in the
 * middle of the range and the verbose kinds against the ceiling, with their slow
 * tail across it.
 *
 * A batch that crosses the ceiling loses every unit in it — the dispatch times
 * out, is retried, times out again, and a dozen units end the run with no verdict
 * — and the batch it happens to need not be a large one. Prompt size and unit
 * count barely separate the dispatches that land in the tail from the ones that
 * do not; the kind does. So a single ceiling set for the common case is a ceiling
 * the verbose kinds keep hitting on ordinary batches, and the budget is per kind
 * for that reason.
 *
 * The ceiling is raised for those kinds rather than their batches being made
 * smaller: splitting them would re-send the same shared system prompt more times
 * and pay for the same cache misses again, to fix a problem that is not about
 * size. Kinds absent from this table use the runtime's default, because their
 * tail leaves real headroom under it.
 *
 * The trade is explicit rather than free: a batch that hangs for a reason other
 * than volume now burns this larger budget on each of its attempts instead of
 * 240 s.
 */
const KIND_TIMEOUT_MS: Partial<Readonly<Record<AuditUnitKind, number>>> = {
  migration: 480_000,
  "workflow-job": 480_000,
  "data-access": 360_000,
};

/**
 * The wall-clock budget for one batch, or undefined to use the runtime's.
 *
 * A batch is bounded by the slowest kind it carries: a mixed batch has to finish
 * writing about all of them.
 */
export function batchTimeoutMs(batch: AuditBatch): number | undefined {
  const budgets = batchKinds(batch)
    .map((kind) => KIND_TIMEOUT_MS[kind])
    .filter((budget): budget is number => budget !== undefined);
  return budgets.length === 0 ? undefined : Math.max(...budgets);
}

/** What identifies a finding inside its file: never a line number, so ids survive edits. */
function symbolOf(unit: AuditUnit): string {
  const symbol = unit.attributes[ATTRIBUTE.symbol];
  return symbol !== undefined && symbol !== "" ? symbol : unit.label;
}

/**
 * Turns an agent's citation into the `CodeRef` the verifier proves.
 *
 * The quote goes into `snippet`, which is where `verifyCodeRef` looks for a
 * relocation anchor — and which it overwrites with the text it read from disk,
 * so nothing the model wrote about the code survives into the report.
 */
function citationOf(ref: VerdictRef): CodeRef {
  return {
    file: ref.file,
    line: ref.line,
    ...(ref.endLine !== undefined && ref.endLine > ref.line ? { endLine: ref.endLine } : {}),
    ...(ref.note === undefined || ref.note === "" ? {} : { note: ref.note }),
    ...(ref.quote === undefined || ref.quote === "" ? {} : { snippet: ref.quote }),
  };
}

/** Builds the finding a verdict claims, with a stable id and no snippet yet. */
function draftFinding(claim: VerdictFinding, unit: AuditUnit, domain: Domain): Finding {
  const location = citationOf(claim.location);
  const draft = makeFinding({
    domain: claim.domain ?? domain,
    rule: claim.rule,
    severity: claim.severity,
    confidence: claim.confidence,
    title: claim.title,
    description: claim.description,
    impact: claim.impact,
    recommendation: claim.recommendation,
    file: location.file,
    line: location.line,
    ...(location.endLine === undefined ? {} : { endLine: location.endLine }),
    symbol: symbolOf(unit),
    evidence: (claim.evidence ?? []).map(citationOf),
    ...(claim.exploitability === undefined ? {} : { exploitability: claim.exploitability }),
    ...(claim.acceptanceCriteria === undefined
      ? {}
      : { acceptanceCriteria: claim.acceptanceCriteria }),
    ...(claim.cwe === undefined ? {} : { cwe: claim.cwe }),
    ...(claim.owasp === undefined ? {} : { owasp: claim.owasp }),
    source: { kind: "agent", name: AUDIT_SOURCE },
  });
  // `makeFinding` builds the location from file and line alone, so the quote has
  // to be put back: it is the anchor the verifier relocates against.
  return location.snippet === undefined
    ? draft
    : { ...draft, location: { ...draft.location, snippet: location.snippet } };
}

/**
 * Why a batch is `partial`, in the agent's own terms.
 *
 * A unit the agent declined to decide on and a unit it never mentioned are two
 * different failures: the first is a model saying so, which the certainty rule
 * asks it to do, and the second is a reply with a hole in it. Collapsing both
 * into "came back without a verdict" would report an honest `inconclusive` as a
 * malformed answer, and the report's credibility rests on that distinction.
 */
export function partialReason(total: number, outcomes: readonly UnitOutcome[]): string {
  const inconclusive = outcomes.filter((outcome) => outcome.cause === "inconclusive").length;
  const silent = outcomes.filter((outcome) => outcome.cause === "no-verdict").length;
  const missing = inconclusive + silent;
  const parts: string[] = [];
  if (inconclusive > 0) parts.push(`${inconclusive} the agent declined to decide`);
  if (silent > 0) parts.push(`${silent} it returned no verdict for`);
  if (parts.length === 0) return `${total} units have no verdict`;
  return `${missing} of ${total} units have no verdict: ${parts.join(", ")}`;
}

/**
 * Which of the several ways a run can end is the one worth printing.
 *
 * Strictest first, because they compose: a cancelled run also exhausted no
 * quota, a quota-stopped run also ran out of clock, and a run that reached its
 * batch budget did so under all of them. The sentence a reader needs is the
 * *reason they can act on*, and Ctrl-C outranks a ceiling they chose.
 */
export function stopFor(input: {
  readonly cancelled: boolean;
  readonly quota: boolean;
  readonly clock: BudgetStop | undefined;
  readonly planned: BudgetStop | undefined;
}): BudgetStop {
  if (input.cancelled) return "cancelled";
  if (input.quota) return "quota";
  if (input.clock !== undefined) return input.clock;
  return input.planned ?? "complete";
}

/** A batch that ran, with everything it contributed to the phase. */
interface BatchResult {
  readonly report: BatchReport;
  readonly outcomes: readonly UnitOutcome[];
  readonly findings: readonly Finding[];
  readonly checks: readonly AssertedCheck[];
}

// ---------------------------------------------------------------------------
// The phase
// ---------------------------------------------------------------------------

/**
 * Runs phase 4 end to end: plan the batches, dispatch them through the agent
 * runtime, verify and gate every citation, and write what came back.
 *
 * Nothing here aborts on a bad batch. A dispatch that fails, a reply that will
 * not validate, an agent that declines — each costs its own units, which are
 * reported as not audited, and the phase finishes with the rest. The one
 * exception is a subscription limit: the runtime latches shut on it, the queued
 * batches fail immediately, and the report says how far the run got instead of
 * pretending the remaining units were clean.
 */
export async function runAudit<Schema extends z.ZodType>(
  ctx: AuditContext,
  options: AuditOptions<Schema>,
): Promise<AuditResult> {
  const now = options.now ?? ((): number => performance.now());
  const startedAt = now();
  const log = ctx.logger.child({ phase: "audit", runId: ctx.runId });

  const all = options.units ?? (await readInventoryDocument(ctx.fs, ctx.runDir)).units;
  // Units an earlier attempt already answered for are not this dispatch's work,
  // but they are still part of the repository the bound describes.
  const carried = new Set(options.alreadyAudited ?? []);
  const units = carried.size === 0 ? all : all.filter((unit) => !carried.has(unit.id));
  const carriedOver = all.length - units.length;
  const inventoryIds = new Set(units.map((unit) => unit.id));

  const verifyCtx: VerifyContext = {
    fs: {
      readBytes: (path) => ctx.fs.readFileBytes(path),
      realpath: (path) => ctx.fs.realpath(path),
    },
    targetDir: ctx.targetDir,
  };
  // One cache for the phase: a file with twenty audited units is read once.
  const cache: VerifyCache = createVerifyCache();

  const planned = await options.batches(units, ctx);
  const disclosure = options.batches.plan?.();
  const domains = options.domains;
  const batches =
    domains === undefined
      ? [...planned]
      : planned.filter((batch) => domains.includes(batchDomain(batch)));

  // The clock defaults *on*, for the same reason the batch budget does: a
  // ceiling only the CLI knows about is a ceiling a library caller silently does
  // not have, and "usable on a large repository without being babysat" has to be
  // true of `runAudit` and not only of `sentinel analyze`. The planner's own
  // limit wins when it has one, so the two halves of a budget cannot disagree;
  // an explicit `null` turns it off.
  const wallClock =
    options.maxWallClockMs !== undefined
      ? options.maxWallClockMs
      : (disclosure?.bound?.limits.maxWallClockMs ?? DEFAULT_MAX_WALL_CLOCK_MS);
  // The deadline is absolute, taken once: a ceiling recomputed per batch would
  // drift by however long the planner took.
  const deadline =
    wallClock === null || wallClock <= 0 ? Number.POSITIVE_INFINITY : startedAt + wallClock;
  /** Set when a ceiling, not a batch, is what ended the dispatch loop. */
  let stoppedBy: BudgetStop | undefined;

  const dropped = {
    unresolved: 0,
    unresolvedEvidence: 0,
    outOfSlice: 0,
    outOfSliceEvidence: 0,
    duplicates: 0,
    relocated: 0,
    strayVerdicts: 0,
    assuranceEvidence: 0,
    byReason: emptyReasons(),
  };

  log.info("phase 4 planned", {
    units: units.length,
    batches: batches.length,
    concurrency: options.runtime.metadata.concurrency,
    synthetic: options.runtime.metadata.synthetic,
  });

  // Built only when somebody is listening, and built from the *planned* batches
  // rather than from the inventory: both ratios on a progress line then complete
  // together, and how much of the repository a budget left out is the bound's
  // sentence to make rather than a counter's to imply.
  const progress =
    options.progress === undefined
      ? undefined
      : createProgressTracker({
          report: options.progress,
          batchesTotal: batches.length,
          unitsTotal: batches.reduce(
            (sum, batch) => sum + batch.units.filter((unit) => inventoryIds.has(unit.id)).length,
            0,
          ),
          concurrency: options.runtime.metadata.concurrency,
          startedAt,
          now,
        });

  /**
   * Verifies a citation and gates it on the batch's slices; null when unusable.
   *
   * No relocation hint is passed: the only honest anchor for a line-level
   * citation is the agent's own quote of that line, which `citationOf` carries.
   */
  const proveRef = async (
    ref: VerdictRef,
    index: SliceIndex,
    shown: ShownLineTest | undefined,
  ): Promise<CodeRef | null> => {
    const verified = await verifyCodeRef(citationOf(ref), verifyCtx, {}, cache);
    if (!verified.ok) {
      dropped.byReason[verified.reason] += 1;
      return null;
    }
    if (verified.relocated) dropped.relocated += 1;
    return gateRef(verified.ref, index, shown);
  };

  /** Runs one batch. Never throws: every failure becomes this batch's own report. */
  const auditBatch = async (batch: AuditBatch): Promise<BatchResult> => {
    const batchStartedAt = now();
    const domain = batchDomain(batch);
    const kinds = batchKinds(batch);
    // A planner that invents a unit cannot inflate coverage: only units the
    // inventory enumerated are counted, because that is what "enumerated, not
    // sampled" means.
    const own = batch.units.filter((unit) => inventoryIds.has(unit.id));
    if (own.length !== batch.units.length) {
      log.warn("batch contained units that are not in the inventory; they were ignored", {
        batchId: batch.id,
        ignored: batch.units.length - own.length,
      });
    }
    const index = buildSliceIndex(batch.slices, ctx.targetDir);
    const shown = options.shown?.(batch);

    const fail = (
      failure: AgentFailureKind,
      reason: string,
      attempts: number,
      transcripts: readonly string[],
    ): BatchResult => ({
      report: {
        batchId: batch.id,
        domain,
        kinds,
        units: own.length,
        status: "failed",
        failure,
        reason,
        attempts,
        verdicts: 0,
        findings: 0,
        durationMs: Math.max(0, Math.round(now() - batchStartedAt)),
        transcripts: [...transcripts],
      },
      outcomes: own.map((unit) => ({
        unitId: unit.id,
        kind: unit.kind,
        domain,
        audited: false,
        // A batch that failed *because the run was cancelled* is a different
        // sentence in the report than one whose model timed out, and Ctrl-C is
        // common enough that collapsing the two would mislead on most partial
        // runs.
        cause: (ctx.signal?.aborted === true ? "cancelled" : "batch-failed") satisfies SkipCause,
        // The cause says `batch-failed`; the kind belongs beside the sentence,
        // not in front of it, or the line reads `batch-failed: timeout: ...`.
        reason: `${reason} (${failure})`,
      })),
      findings: [],
      checks: [],
    });

    if (ctx.signal?.aborted === true) {
      // Nothing is sent, and no prompt is even built: the units are reported as
      // cancelled rather than as units an agent looked at and cleared.
      return fail("timeout", "the run was cancelled before this batch was dispatched", 0, []);
    }

    let prompt: AuditPrompt;
    try {
      prompt = await options.prompt(batch, ctx);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      log.error("prompt building failed", { batchId: batch.id, detail });
      return fail("transient", `the prompt could not be built: ${detail}`, 0, []);
    }

    const timeoutMs = batchTimeoutMs(batch);
    const request: AgentRequest = {
      batchId: batch.id,
      systemPrompt: prompt.system,
      prompt: prompt.user,
      logFields: { domain, units: own.length },
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    };

    let reply: StructuredResult<z.output<Schema>>;
    try {
      reply = await options.runtime.runStructured(request, options.verdicts.schema);
    } catch (error) {
      const agentError = toAgentError(error, { batchId: batch.id });
      log.warn("batch not audited", {
        batchId: batch.id,
        kind: agentError.kind,
        detail: agentError.detail,
        units: own.length,
      });
      return fail(agentError.kind, agentError.detail, agentError.attempt ?? 0, []);
    }

    let payload: BatchVerdicts;
    try {
      payload = options.verdicts.read(reply.value);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return fail(
        "malformed-output",
        `the reply could not be read: ${detail}`,
        reply.attempts,
        reply.transcripts,
      );
    }

    const byUnit = new Map(own.map((unit) => [unit.id, unit]));
    const seen = new Set<string>();
    const outcomes: UnitOutcome[] = [];
    const findings: Finding[] = [];
    const checks: AssertedCheck[] = [];

    for (const verdict of payload.verdicts) {
      // Looked up in the batch's own units, never in the whole inventory: a
      // verdict about a unit this batch was not given is not evidence about
      // anything, because the agent was not shown that unit's code here.
      const unit = byUnit.get(verdict.unitId);
      if (unit === undefined) {
        dropped.strayVerdicts += 1;
        continue;
      }
      if (seen.has(verdict.unitId)) {
        dropped.strayVerdicts += 1;
        continue;
      }
      seen.add(verdict.unitId);

      if (verdict.status === "inconclusive") {
        outcomes.push({
          unitId: unit.id,
          kind: unit.kind,
          domain,
          audited: false,
          cause: "inconclusive",
          reason: verdict.note ?? "the agent declined to decide",
        });
        continue;
      }

      outcomes.push({ unitId: unit.id, kind: unit.kind, domain, audited: true });

      for (const claim of verdict.findings ?? []) {
        const draft = draftFinding(claim, unit, domain);
        const verified = await verifyFinding(draft, verifyCtx, {}, cache);
        if (!verified.ok) {
          dropped.unresolved += 1;
          dropped.byReason[verified.reason] += 1;
          log.debug("agent finding dropped: its citation does not resolve on disk", {
            batchId: batch.id,
            rule: draft.rule,
            file: draft.location.file,
            line: draft.location.line,
            reason: verified.reason,
          });
          continue;
        }
        dropped.unresolvedEvidence += verified.droppedEvidence;
        if (verified.relocated) dropped.relocated += 1;

        const gated = gateFinding(verified.finding, index, shown);
        if (gated === null) {
          dropped.outOfSlice += 1;
          log.warn("agent finding dropped: it cites code the batch never provided", {
            batchId: batch.id,
            rule: verified.finding.rule,
            file: verified.finding.location.file,
            line: verified.finding.location.line,
          });
          continue;
        }
        dropped.outOfSliceEvidence += gated.droppedEvidence;
        findings.push(gated.finding);
      }

      // Checks are read from a flagged verdict too: a handler can fail one
      // check and demonstrably pass another, and the passing one is an output.
      for (const check of verdict.checks ?? []) {
        const evidence: CodeRef[] = [];
        for (const ref of check.evidence ?? []) {
          const proved = await proveRef(ref, index, shown);
          if (proved === null) dropped.assuranceEvidence += 1;
          else evidence.push(proved);
        }
        checks.push({
          unitId: unit.id,
          kind: unit.kind,
          domain,
          checkId: check.id,
          statement: check.statement,
          ...(check.subject === undefined ? {} : { subject: check.subject }),
          evidence,
        });
      }
    }

    for (const unit of own) {
      if (seen.has(unit.id)) continue;
      outcomes.push({
        unitId: unit.id,
        kind: unit.kind,
        domain,
        audited: false,
        cause: "no-verdict",
        reason: "the agent returned no verdict for this unit",
      });
    }

    const audited = outcomes.filter((outcome) => outcome.audited).length;
    log.info("batch finished", {
      batchId: batch.id,
      domain,
      units: own.length,
      audited,
      findings: findings.length,
      attempts: reply.attempts,
    });

    return {
      report: {
        batchId: batch.id,
        domain,
        kinds,
        units: own.length,
        status: audited === own.length ? "audited" : "partial",
        ...(audited === own.length ? {} : { reason: partialReason(own.length, outcomes) }),
        attempts: reply.attempts,
        verdicts: audited,
        findings: findings.length,
        durationMs: Math.max(0, Math.round(now() - batchStartedAt)),
        transcripts: [...reply.transcripts],
      },
      outcomes,
      findings,
      checks,
    };
  };

  // The batches are admitted through a gate whose limit is *the runtime's own*,
  // so the effective fan-out is unchanged and still readable off the run
  // metadata — the gate exists for one reason only: it is the moment a batch is
  // about to start, which is the only honest place to read a wall-clock ceiling.
  // Checking it before `Promise.all` would check it once, at zero.
  const gate = createSemaphore(options.runtime.metadata.concurrency);
  const notDispatched: AuditBatch[] = [];
  const dispatched = await Promise.all(
    batches.map((batch) =>
      gate.run(async (): Promise<BatchResult | null> => {
        if (now() < deadline) {
          const result = await auditBatch(batch);
          // The completion path, and deliberately so: `auditBatch` never throws,
          // so every batch that was sent reports itself here exactly once —
          // including the failed ones, which is the whole point of reporting a
          // loss while the run can still be abandoned.
          progress?.completed(result.report);
          return result;
        }
        // The ceiling is reached between batches: nothing in flight is cut
        // short, and this one was never sent, so it costs nothing to say so.
        stoppedBy ??= "wall-clock";
        notDispatched.push(batch);
        return null;
      }),
    ),
  );
  const results = dispatched.filter((result): result is BatchResult => result !== null);

  const outcomes: UnitOutcome[] = results.flatMap((result) => [...result.outcomes]);
  // Keyed by domain as well as by unit, because a unit is audited once per domain
  // that asked about it. A route whose access-control batch came back and whose
  // contract batch was never dispatched is claimed for `appsec` and unclaimed for
  // `api`, so the loop below files the `api` skip that keeps that domain's total
  // honest. Keyed by unit alone, `api` would have counted the unit out of its own
  // population and read 100% of whatever it managed to look at.
  const claimed = new Set(outcomes.map((outcome) => coverageKey(outcome.domain, outcome.unitId)));

  // A batch the clock held back is not a failed batch and is not a gap: its
  // units are budget-skipped, exactly as the ones phase 3's ceiling held back —
  // and in that batch's own domain, not in the kind's default one.
  const clockStopped = new Map<string, string>();
  for (const batch of notDispatched) {
    for (const unit of batch.units) {
      clockStopped.set(
        coverageKey(batchDomain(batch), unit.id),
        "the run reached its wall-clock ceiling before this batch was dispatched",
      );
    }
  }

  // Phase 3's own reasons for the units it did not batch: `budget` when a
  // ceiling held them back, and its specific sentence in every other case. A unit
  // can appear more than once, once per domain the planner did not cover.
  const plannedSkips = new Map<string, PlannedSkip[]>();
  for (const skip of disclosure?.skipped ?? []) {
    const bucket = plannedSkips.get(skip.unitId);
    if (bucket === undefined) plannedSkips.set(skip.unitId, [skip]);
    else bucket.push(skip);
  }

  for (const unit of units) {
    for (const owed of domainsOwed(unit, plannedSkips.get(unit.id), clockStopped)) {
      if (domains !== undefined && !domains.includes(owed.domain)) continue;
      if (claimed.has(coverageKey(owed.domain, unit.id))) continue;
      const held = clockStopped.get(coverageKey(owed.domain, unit.id));
      outcomes.push({
        unitId: unit.id,
        kind: unit.kind,
        domain: owed.domain,
        audited: false,
        cause: held !== undefined ? "budget" : (owed.cause ?? "no-batch"),
        reason: held ?? owed.reason ?? "no batch covered this unit",
      });
    }
  }

  // De-duplicated across batches: two units in one file can flag the same rule
  // on the same symbol, and a document with two identical ids is not diffable.
  const byId = new Map<string, Finding>();
  for (const result of results) {
    for (const finding of result.findings) {
      if (byId.has(finding.id)) {
        dropped.duplicates += 1;
        continue;
      }
      byId.set(finding.id, finding);
    }
  }
  const findings = [...byId.values()];

  const coverage = buildAuditCoverage(outcomes, domains);
  const kinds = buildKindCoverage(outcomes);
  const totals = buildUnitTotals(outcomes);
  if (!coverageReconciles(coverage) || !coverageReconciles(kinds)) {
    // Unreachable by construction; asserted because a coverage table that does
    // not add up is a report that overstates what was checked.
    throw new Error("audit coverage does not reconcile: audited + skipped !== total");
  }

  const assurances = buildAssurances(
    results.flatMap((result) => [...result.checks]),
    outcomes,
    {
      ...(options.maxEvidencePerAssurance === undefined
        ? {}
        : { maxEvidence: options.maxEvidencePerAssurance }),
      ...(domains === undefined ? {} : { domains }),
    },
  );

  const stats = options.runtime.stats();
  const aborted = (ctx.signal?.aborted ?? false) || stats.quotaExhausted;

  // What the run left out, rebuilt from what actually came back rather than from
  // what phase 3 forecast. The plan's own bound supplies the ceilings and the
  // ordering; the counts are this phase's, so a batch that failed after being
  // dispatched shows up as a unit without a verdict and not as a unit the budget
  // refused.
  const planBound = disclosure?.bound;
  const bound = buildAuditBound({
    stop: stopFor({
      cancelled: ctx.signal?.aborted ?? false,
      quota: stats.quotaExhausted,
      clock: stoppedBy,
      planned: planBound?.stop,
    }),
    limits: planBound?.limits ?? {
      ...UNBOUNDED_BUDGET,
      maxWallClockMs: Number.isFinite(deadline) ? Math.round(deadline - startedAt) : null,
    },
    unitsTotal: totals.total + carriedOver,
    unitsDispatched: results.reduce((sum, result) => sum + result.report.units, 0),
    unitsAudited: totals.audited + carriedOver,
    unitsDeferred: totals.byCause.budget,
    unitsCarriedOver: carriedOver,
    batchesPlanned: planBound?.batchesPlanned ?? batches.length,
    batchesDispatched: results.length,
    batchesDeferred: (planBound?.batchesDeferred ?? 0) + notDispatched.length,
    ordering: planBound?.ordering ?? RISK_ORDERING,
    reasons: planBound?.reasons ?? [],
  });

  const contribution: AuditContribution = {
    runId: ctx.runId,
    target: ctx.targetDir,
    findings,
    assurances,
    coverage,
    // Both halves are claims that did not reach the reader; `audit.json` keeps
    // them apart, and they are apart for a reason.
    droppedFindings: dropped.unresolved + dropped.outOfSlice,
  };

  const report = buildAuditReport({
    schemaVersion: SCHEMA_VERSION,
    runId: ctx.runId,
    target: ctx.targetDir,
    aborted,
    durationMs: Math.max(0, Math.round(now() - startedAt)),
    runtime: {
      kind: stats.metadata.kind,
      ...(stats.metadata.model === undefined ? {} : { model: stats.metadata.model }),
      concurrency: stats.metadata.concurrency,
      maxAttempts: stats.metadata.maxAttempts,
      timeoutMs: stats.metadata.timeoutMs,
      synthetic: stats.metadata.synthetic,
    },
    dispatches: stats.dispatches,
    retries: stats.retries,
    failures: stats.failures,
    quotaExhausted: stats.quotaExhausted,
    usage: stats.usage,
    batches: results.map((result) => result.report),
    units: totals,
    bound,
    coverage,
    kinds,
    findingsKept: findings.length,
    assurances: assurances.length,
    dropped,
  });

  if (dropped.outOfSlice > 0 || dropped.unresolved > 0) {
    log.warn("agent claims were dropped", {
      unresolved: dropped.unresolved,
      outOfSlice: dropped.outOfSlice,
      byReason: dropped.byReason,
    });
  }

  const artifacts: string[] = [];
  let document: FindingsDocument | null = null;
  if (options.write !== false) {
    const base = await readFindingsDocument(ctx.fs, ctx.runDir);
    document = mergeAuditIntoFindings(base, contribution);
    artifacts.push(await writeMergedFindings(ctx.fs, ctx.runDir, document));
    artifacts.push(await writeAuditReport(ctx.fs, ctx.runDir, report));
    artifacts.push(
      await writeAssurancesDocument(
        ctx.fs,
        ctx.runDir,
        buildAssurancesDocument({
          runId: ctx.runId,
          target: ctx.targetDir,
          assurances,
          coverage,
        }),
      ),
    );
  }

  log.info("phase 4 complete", {
    unitsAudited: totals.audited,
    unitsSkipped: totals.skipped,
    findings: findings.length,
    assurances: assurances.length,
    outOfSlice: dropped.outOfSlice,
    unresolved: dropped.unresolved,
    stop: bound.stop,
  });
  // Logged at warn, not info: a run that did not cover the repository is the one
  // fact about it a reader must not have to go looking for.
  if (bound.stop !== "complete" || bound.unitsDeferred > 0) {
    log.warn("phase 4 was bounded", { stop: bound.stop, disclosure: bound.statement });
  }

  return {
    runId: ctx.runId,
    target: ctx.targetDir,
    findings,
    assurances,
    coverage,
    kinds,
    batches: results.map((result) => result.report),
    units: totals,
    bound,
    dropped,
    stats,
    report,
    document,
    aborted,
    durationMs: Math.max(0, Math.round(now() - startedAt)),
    artifacts: artifacts.sort(),
  };
}

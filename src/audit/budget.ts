/**
 * How much of a repository phase 4 is allowed to audit, and how it says what it
 * left out.
 *
 * Phase 4 runs on the operator's Claude subscription: low parallelism, a usage
 * limit that latches, and no way to buy more of it mid-run. A batch costs about a
 * minute of wall clock at a fan-out of two, so the cost of a run is roughly its
 * batch count in minutes. A small application plans a dozen batches and finishes
 * in a coffee break; a monorepo whose units number in the thousands plans several
 * hundred, which is most of a working day and would hit the subscription's limit
 * long before the end. A tool that has to be babysat for six hours is not usable
 * on a large repository, and one that silently audits a third of the units and
 * reports a score is worse than one that is slow.
 *
 * So the phase takes a budget. Three ceilings, all optional, all enforced the
 * same way:
 *
 * - `maxBatches` — the plan's own unit of cost. This is the primary knob,
 *   because a batch is what a dispatch costs and what a usage limit is spent in.
 * - `maxUnits` — for an operator who thinks in units rather than in dispatches.
 * - `maxWallClockMs` — the backstop. A batch that takes four minutes instead of
 *   one must not turn a forty-batch budget into a four-hour run.
 *
 * Two rules govern all three:
 *
 * 1. **A budget ends the phase between batches, never inside one.** A batch that
 *    has been dispatched is always awaited and always counted. Truncating a
 *    dispatch would spend the tokens and throw away the verdicts, which is the
 *    worst of both.
 * 2. **Reaching a budget is a disclosure, not an exit code.** Everything the
 *    budget kept out is counted, named by kind, and stated in one sentence that
 *    travels to the CLI summary, to `coverage`, and to the dossier. See
 *    {@link describeBound}.
 *
 * The defaults are sized from that per-batch cost and are deliberately invisible
 * on a small repository: a run of a dozen batches finishes well inside both of
 * them, so nothing about a small application changes.
 */

import { z } from "zod";
import { groupThousands } from "../contracts/inventory.ts";
import { RISK_ORDERING } from "./risk.ts";

// ---------------------------------------------------------------------------
// The budget
// ---------------------------------------------------------------------------

/** A ceiling phase 4 may be given; `null` in every field means "no ceiling". */
export interface AuditBudget {
  /** Batches that may be dispatched. `null` for no limit. */
  readonly maxBatches?: number | null | undefined;
  /** Units that may be put in front of a model. `null` for no limit. */
  readonly maxUnits?: number | null | undefined;
  /** Wall clock the dispatch loop may spend. `null` for no limit. */
  readonly maxWallClockMs?: number | null | undefined;
}

/** A budget with every ceiling decided; `null` means the ceiling is off. */
export interface ResolvedAuditBudget {
  readonly maxBatches: number | null;
  readonly maxUnits: number | null;
  readonly maxWallClockMs: number | null;
}

/**
 * Batches a default run may dispatch.
 *
 * At about a minute of wall clock per batch, forty batches is a little over half
 * an hour and roughly 800 units: several times the spend of a small application's
 * whole run, and comfortably inside one subscription window. It is also above
 * every batch count a small application produces, so the default bounds the large
 * repository and is invisible on the small one.
 */
export const DEFAULT_MAX_BATCHES = 40;

/**
 * Wall clock a default run may spend, in milliseconds.
 *
 * Forty batches at that rate is a little over half an hour; 45 minutes leaves
 * headroom for batches that run long without letting a stalled one turn the phase
 * into an afternoon. Whichever ceiling is reached first ends the phase.
 */
export const DEFAULT_MAX_WALL_CLOCK_MS = 45 * 60_000;

/** The budget a run gets when nobody passes one. */
export const DEFAULT_AUDIT_BUDGET: ResolvedAuditBudget = {
  maxBatches: DEFAULT_MAX_BATCHES,
  maxUnits: null,
  maxWallClockMs: DEFAULT_MAX_WALL_CLOCK_MS,
};

/** Every ceiling off: what `--no-budget` means, and what most tests want. */
export const UNBOUNDED_BUDGET: ResolvedAuditBudget = {
  maxBatches: null,
  maxUnits: null,
  maxWallClockMs: null,
};

/** A ceiling the caller gave, clamped to something usable, or `null` for off. */
function ceiling(value: number | null | undefined, fallback: number | null): number | null {
  if (value === null) return null;
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.max(1, Math.floor(value));
}

/**
 * Fills a partial budget with the defaults.
 *
 * `undefined` on a field takes the default; `null` turns that ceiling off. The
 * distinction matters because "the operator said nothing" and "the operator said
 * do not stop" are different runs, and only one of them may be silent about it.
 */
export function resolveBudget(budget: AuditBudget | undefined): ResolvedAuditBudget {
  return {
    maxBatches: ceiling(budget?.maxBatches, DEFAULT_AUDIT_BUDGET.maxBatches),
    maxUnits: ceiling(budget?.maxUnits, DEFAULT_AUDIT_BUDGET.maxUnits),
    maxWallClockMs: ceiling(budget?.maxWallClockMs, DEFAULT_AUDIT_BUDGET.maxWallClockMs),
  };
}

/** What the CLI's flags look like before they become a budget. */
export interface AuditBudgetFlags {
  /** `--max-batches`. */
  readonly maxBatches?: number | undefined;
  /** `--max-units`. */
  readonly maxUnits?: number | undefined;
  /** `--max-audit-minutes`, in whole or fractional minutes. */
  readonly maxMinutes?: number | undefined;
  /** `--no-budget`: audit everything, however long it takes. */
  readonly unbounded?: boolean | undefined;
}

/**
 * Turns the CLI's flags into a budget.
 *
 * Lives here rather than in the CLI so that the meaning of `--max-batches 0`
 * — off, not "dispatch nothing" — is decided beside the ceilings it sets, and
 * the CLI only has to map three flag names.
 */
export function auditBudgetFrom(flags: AuditBudgetFlags): ResolvedAuditBudget {
  if (flags.unbounded === true) return UNBOUNDED_BUDGET;
  return resolveBudget({
    maxBatches: flags.maxBatches,
    maxUnits: flags.maxUnits,
    maxWallClockMs: flags.maxMinutes === undefined ? undefined : flags.maxMinutes * 60_000,
  });
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/** Why phase 4 stopped where it did. Closed set: a new way to stop is disclosed. */
export const BUDGET_STOPS = [
  "complete",
  "batch-budget",
  "unit-budget",
  "wall-clock",
  "quota",
  "cancelled",
] as const;

/** One of {@link BUDGET_STOPS}. */
export type BudgetStop = (typeof BUDGET_STOPS)[number];

/** Validates a stop reason read back from an artifact. */
export const BudgetStopSchema = z.enum(BUDGET_STOPS);

/** What {@link selectWithinBudget} needs of a batch: its priority and its size. */
export interface BudgetedBatch {
  /** The batch's risk, as `meanRisk` computed it. Higher goes first. */
  readonly risk: number;
  readonly units: readonly unknown[];
}

/** The batches a budget admitted, the ones it held back, and why it stopped. */
export interface BudgetSelection<T> {
  /** In dispatch order: highest risk first, so a usage limit costs the cheapest units. */
  readonly dispatched: readonly T[];
  /** Everything the budget kept out, in the same order they would have been sent. */
  readonly deferred: readonly T[];
  readonly stop: BudgetStop;
}

/**
 * Takes batches in risk order until a ceiling is reached.
 *
 * Stops at the first batch that does not fit rather than skipping it and taking
 * a smaller one behind it: the list is ordered by risk, so reaching past a batch
 * that does not fit means auditing lower-risk units while a higher-risk batch
 * waits, which is exactly the trade this ordering exists to avoid. The one
 * exception is the very first batch — a unit ceiling smaller than the first
 * batch takes that batch anyway, because a budget that audits nothing is a bug
 * and a budget that overshoots by one batch is a disclosure.
 */
export function selectWithinBudget<T extends BudgetedBatch>(
  batches: readonly T[],
  budget: ResolvedAuditBudget,
): BudgetSelection<T> {
  const ordered = batches
    .map((batch, index) => ({ batch, index }))
    .sort((left, right) => right.batch.risk - left.batch.risk || left.index - right.index)
    .map((entry) => entry.batch);

  const dispatched: T[] = [];
  let units = 0;
  let stop: BudgetStop = "complete";

  for (const batch of ordered) {
    if (budget.maxBatches !== null && dispatched.length >= budget.maxBatches) {
      stop = "batch-budget";
      break;
    }
    if (
      budget.maxUnits !== null &&
      dispatched.length > 0 &&
      units + batch.units.length > budget.maxUnits
    ) {
      stop = "unit-budget";
      break;
    }
    dispatched.push(batch);
    units += batch.units.length;
  }

  return { dispatched, deferred: ordered.slice(dispatched.length), stop };
}

// ---------------------------------------------------------------------------
// Disclosure
// ---------------------------------------------------------------------------

/** The limits a run was given, as the artifact records them. */
export const BudgetLimitsSchema = z.object({
  maxBatches: z.number().int().positive().nullable(),
  maxUnits: z.number().int().positive().nullable(),
  maxWallClockMs: z.number().int().positive().nullable(),
});

/**
 * What a bounded run left out, written to `audit.json` and printed everywhere a
 * coverage number is.
 *
 * Every field is a number a reader can check against `inventory.json`, and
 * `statement` is the one sentence the three renderers share so that the CLI, the
 * coverage table and the dossier cannot disagree about how complete the run was.
 */
export const AuditBoundSchema = z.object({
  /** Why the phase stopped. `complete` means no ceiling was reached. */
  stop: BudgetStopSchema,
  limits: BudgetLimitsSchema,
  /** Units this phase was responsible for, carried-over ones included. */
  unitsTotal: z.number().int().nonnegative(),
  /**
   * Units the budget admitted: they reached a batch that was sent to a model.
   *
   * Kept apart from `unitsAudited` because the two answer different questions and
   * a bounded run makes the difference visible. The budget's own achievement is
   * "it covered these 800 units"; whether a verdict came back for them is the
   * agent's business, and on a run where every batch failed the first number is
   * 800 and the second is 0. Collapsing them printed `after the 0 highest-risk
   * units`, which is not a sentence and not a fact.
   */
  unitsDispatched: z.number().int().nonnegative(),
  /** Units a verdict examined, carried-over ones included. */
  unitsAudited: z.number().int().nonnegative(),
  /** Units a ceiling kept out of every batch. A subset of `unitsTotal - unitsAudited`. */
  unitsDeferred: z.number().int().nonnegative(),
  /** Units an earlier attempt in this run directory had already audited. */
  unitsCarriedOver: z.number().int().nonnegative(),
  batchesPlanned: z.number().int().nonnegative(),
  batchesDispatched: z.number().int().nonnegative(),
  /** Batches a ceiling held back; they are what `sentinel resume` picks up. */
  batchesDeferred: z.number().int().nonnegative(),
  /** The ordering the audited units were chosen by. */
  ordering: z.string(),
  /** The signals that put them at the front of this repository's queue. */
  reasons: z.array(z.string()),
  /** The sentence the CLI, the coverage table and the dossier all print. */
  statement: z.string(),
});
/** What a bounded run left out; see {@link AuditBoundSchema}. */
export type AuditBound = z.infer<typeof AuditBoundSchema>;

/** `45 minutes` / `90 seconds`, for the sentence a wall-clock stop prints. */
function describeDuration(ms: number): string {
  if (ms < 60_000) return `${Math.round(ms / 1000)}-second`;
  const minutes = Math.round(ms / 60_000);
  return `${minutes}-minute`;
}

/** `1 unit` / `5,000 units`, with thousands grouped by hand for stable bytes. */
function units(count: number): string {
  return `${groupThousands(count)} ${count === 1 ? "unit" : "units"}`;
}

/** `40 batches`, same rules. */
function batches(count: number): string {
  return `${groupThousands(count)} ${count === 1 ? "batch" : "batches"}`;
}

/** The clause after the colon: what stopped the run, in its own terms. */
function stopClause(bound: Omit<AuditBound, "statement">): string {
  // What the budget *covered*, not what came back: see `unitsDispatched`.
  const covered = Math.max(bound.unitsDispatched, bound.unitsAudited - bound.unitsCarriedOver);
  const audited = `the ${groupThousands(covered)} highest-risk units`;
  switch (bound.stop) {
    case "batch-budget":
      return `the run reached its batch budget of ${batches(bound.limits.maxBatches ?? 0)} after ${audited}`;
    case "unit-budget":
      return `the run reached its ceiling of ${units(bound.limits.maxUnits ?? 0)} after ${audited}`;
    case "wall-clock":
      return (
        `the run reached its ${describeDuration(bound.limits.maxWallClockMs ?? 0)} ceiling after ` +
        `${batches(bound.batchesDispatched)} of ${groupThousands(bound.batchesPlanned)}, covering ${audited}`
      );
    case "quota":
      return `the subscription's usage limit was reached, so the batches after it were never dispatched; ${audited} were covered`;
    case "cancelled":
      return `the run was cancelled after ${batches(bound.batchesDispatched)}, covering ${audited}`;
    default:
      return "every unit reached a batch; each one without a verdict is listed with its own reason";
  }
}

/**
 * The one sentence every renderer prints.
 *
 * Its shape is fixed: the number that was not audited, of the number that
 * exists, then why, then what put the audited units at the front. A reader who
 * sees only this line has to be able to tell a bounded run from a complete one —
 * that is the whole requirement, and it is why the sentence leads with the gap
 * rather than with the achievement.
 *
 * The ordering rule itself is *not* inlined: it is a paragraph, it is identical
 * on every run, and `bound.ordering` carries it for the renderer that has room.
 * What goes in the sentence is the part that differs between repositories — the
 * signals that actually fired here — because "ordered by exposure" is a policy
 * and "chosen for: reachable without authentication" is a fact about this code.
 */
export function describeBound(bound: Omit<AuditBound, "statement">): string {
  const missing = Math.max(0, bound.unitsTotal - bound.unitsAudited);
  if (missing === 0 && bound.stop === "complete") {
    const verb = bound.unitsTotal === 1 ? "was" : "were";
    return `all ${units(bound.unitsTotal)} ${verb} audited; the run reached no budget`;
  }
  const head = `${groupThousands(missing)} of ${units(bound.unitsTotal)} were not audited`;
  // Only a run that actually stopped short owes the reader an ordering: on a
  // complete run the units left without a verdict were not chosen by risk, they
  // were lost by a batch, and pointing at the ordering would misattribute them.
  const chosen =
    bound.stop === "complete" || bound.reasons.length === 0
      ? ""
      : `, chosen for: ${bound.reasons.join(", ")}`;
  // The budget covered them; a batch may still have failed. Saying so here stops
  // "covering the 800 highest-risk units" from reading as 800 verdicts.
  const fresh = bound.unitsAudited - bound.unitsCarriedOver;
  const short =
    bound.unitsDispatched > fresh
      ? `; of those, ${groupThousands(fresh)} came back with a verdict`
      : "";
  return `${head}: ${stopClause(bound)}${chosen}${short}`;
}

/** Builds the bound and validates it in one step, so an invalid one cannot exist. */
export function buildAuditBound(input: Omit<AuditBound, "statement">): AuditBound {
  return AuditBoundSchema.parse({ ...input, statement: describeBound(input) });
}

/** A bound for a phase that was given no ceiling and reached none. */
export function unboundedBound(unitsTotal: number, unitsAudited: number): AuditBound {
  return buildAuditBound({
    stop: "complete",
    limits: UNBOUNDED_BUDGET,
    unitsTotal,
    unitsDispatched: unitsAudited,
    unitsAudited,
    unitsDeferred: 0,
    unitsCarriedOver: 0,
    batchesPlanned: 0,
    batchesDispatched: 0,
    batchesDeferred: 0,
    ordering: RISK_ORDERING,
    reasons: [],
  });
}

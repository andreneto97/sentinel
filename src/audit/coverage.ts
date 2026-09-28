/**
 * Phase 4 coverage: what was audited, what was not, and why not.
 *
 * Coverage is the reason phase 2 enumerates instead of sampling. The inventory
 * says there are 200 route handlers; this module is what lets the report say
 * `200/200 route handlers audited` — or, when a batch failed, `196/200` with
 * the four named and the failure that cost them spelled out. A unit without a
 * verdict is never silently absent and is never clean: it is *skipped*, with a
 * cause from a closed set, and it reconciles.
 *
 * The invariant every row satisfies, asserted in the tests and relied on by the
 * report: **`unitsAudited + skipped.length === unitsTotal`**. It holds by
 * construction rather than by arithmetic — the skipped list *is* the units that
 * have no verdict, derived from the same outcomes the audited count comes from,
 * so there is no second place for the two to disagree.
 *
 * Two tables come out of here, because two different questions get asked of a
 * dossier. The per-domain table is the contract's {@link Coverage} and is what
 * the score phase reads: a unit that two batches looked at from two angles
 * (a handler for authorization, then for its API contract) is counted once per
 * domain. The per-kind table is the sentence a reader wants — `200/200 route
 * handlers` — and counts each unit exactly once no matter how many batches
 * touched it.
 */

import { z } from "zod";
import { type Coverage, CoverageSchema, type Domain, DomainSchema } from "../contracts/findings.ts";
import {
  AUDIT_UNIT_KINDS,
  type AuditUnitKind,
  AuditUnitKindSchema,
} from "../contracts/inventory.ts";

/**
 * Why a unit has no verdict. Closed set, like the agent failure kinds: the
 * report renders one line per cause, so a new way of losing a unit has to be
 * classified rather than logged as "missing".
 *
 * - `no-batch` — the batch planner did not put the unit in any batch.
 * - `batch-failed` — the batch it was in never produced a usable reply.
 * - `no-verdict` — the reply came back but said nothing about this unit.
 * - `inconclusive` — the agent answered and declined to decide.
 * - `cancelled` — the run was stopped before the batch was dispatched.
 * - `budget` — a ceiling the run was given stopped it before this unit's turn.
 *
 * `budget` is the newest and the one with teeth. It is *not* a failure: the run
 * did what it was told to do and stopped where it was told to stop. It is kept
 * apart from `no-batch` because the two demand different things of a reader —
 * `no-batch` is a planner that has nothing to say about a kind, and `budget` is
 * work that is still outstanding and that `sentinel resume` will pick up, in
 * risk order, from exactly here.
 */
export const SKIP_CAUSES = [
  "no-batch",
  "batch-failed",
  "no-verdict",
  "inconclusive",
  "cancelled",
  "budget",
] as const;

/** One of {@link SKIP_CAUSES}. */
export type SkipCause = (typeof SKIP_CAUSES)[number];

/** Validates a skip cause read back from an artifact. */
export const SkipCauseSchema = z.enum(SKIP_CAUSES);

/**
 * The fallback domain of a unit kind, used only for units no batch claimed.
 *
 * A batch states the domain whose checks it runs, and that is what a unit's
 * coverage is attributed to — the same handler is an `appsec` unit in the
 * authorization batch and an `api` unit in the contract batch. This map exists
 * for the unit that reached no batch at all: it still has to appear in exactly
 * one domain's table, because a unit nobody looked at is precisely what
 * coverage is for.
 */
export const DOMAIN_BY_UNIT_KIND: Readonly<Record<AuditUnitKind, Domain>> = {
  route: "appsec",
  "data-access": "data",
  "serverless-function": "serverless",
  "queue-consumer": "serverless",
  cron: "serverless",
  webhook: "serverless",
  migration: "data",
  "role-gate": "appsec",
  sink: "appsec",
  "workflow-job": "delivery",
  container: "delivery",
};

/**
 * What the audit phase decided about one unit, in one domain.
 *
 * One unit produces one outcome per domain that looked at it, so a handler in
 * an `appsec` batch and an `api` batch has two. `audited` is the whole verdict
 * of this module: true means an agent returned a decision about this unit that
 * Sentinel accepted, and nothing else counts — not a batch that ran, not a
 * reply that arrived, not a unit the model mentioned in passing.
 */
export interface UnitOutcome {
  readonly unitId: string;
  readonly kind: AuditUnitKind;
  /** The domain whose checks were run against the unit. */
  readonly domain: Domain;
  readonly audited: boolean;
  /** Why there is no verdict; absent when `audited` is true. */
  readonly cause?: SkipCause | undefined;
  /** The sentence the report prints after the cause. */
  readonly reason?: string | undefined;
}

/** Per-unit-kind coverage: the `200/200 route handlers` line, one unit counted once. */
export const KindCoverageSchema = z.object({
  kind: AuditUnitKindSchema,
  unitsTotal: z.number().int().nonnegative(),
  unitsAudited: z.number().int().nonnegative(),
  skipped: z.array(z.object({ unitId: z.string(), reason: z.string() })).default([]),
});
/** Per-unit-kind coverage; see {@link KindCoverageSchema}. */
export type KindCoverage = z.infer<typeof KindCoverageSchema>;

/** The run-level unit count, over distinct units rather than per domain. */
export const UnitTotalsSchema = z.object({
  total: z.number().int().nonnegative(),
  audited: z.number().int().nonnegative(),
  skipped: z.number().int().nonnegative(),
  /**
   * How many units were lost to each cause; every cause present, at zero.
   *
   * Read back as a *partial* record and filled, because {@link SKIP_CAUSES} is
   * an open set in practice: `budget` was added to it, and an `audit.json`
   * written before that has no key for it. Requiring every cause on the way in
   * made every earlier run directory fail validation, which the report surfaced
   * as `audit.json is absent` — a sentence that is both false and quiet, and that
   * cost the dossier its per-unit-kind coverage and every model verdict. A cause
   * a document does not mention happened zero times; that is not a broken
   * artifact, and the next cause added must not break this one again.
   */
  byCause: z.partialRecord(SkipCauseSchema, z.number().int().nonnegative()).transform((counts) => {
    const filled = emptySkipCounts();
    for (const cause of SKIP_CAUSES) filled[cause] = counts[cause] ?? 0;
    return filled;
  }),
});
/** The run-level unit count; see {@link UnitTotalsSchema}. */
export type UnitTotals = z.infer<typeof UnitTotalsSchema>;

/** Domain order in every table: the declaration order of the contract's enum. */
const DOMAIN_RANK: ReadonlyMap<Domain, number> = new Map(
  DomainSchema.options.map((domain, index) => [domain, index]),
);

/** Unit-kind order in every table: the declaration order of the contract's enum. */
const KIND_RANK: ReadonlyMap<AuditUnitKind, number> = new Map(
  AUDIT_UNIT_KINDS.map((kind, index) => [kind, index]),
);

/**
 * The line a reader sees for a skipped unit: the cause, then the sentence.
 *
 * Mirrors phase 1's `coverageReason` on purpose — one coverage table ends up
 * holding both, and `batch-failed: the agent dispatch timed out after 240000ms`
 * should read the same way as `hadolint — skipped: the target has no
 * Dockerfile`. A cause with no sentence still says so rather than printing a
 * bare cause, because "not audited" without a reason is the silence this table
 * exists to prevent.
 */
export function skipReason(cause: SkipCause | undefined, reason: string | undefined): string {
  const cleaned = reason?.trim();
  const head = cause ?? "no-verdict";
  return cleaned === undefined || cleaned === ""
    ? `${head}: no reason given`
    : `${head}: ${cleaned}`;
}

/** One reason a group of units has no verdict, with how many share it. */
export interface SkipGroup {
  /** The reason exactly as `skipReason` rendered it, cause prefix included. */
  readonly reason: string;
  readonly units: number;
}

/**
 * Groups a coverage row's skipped units by the reason they share.
 *
 * Exists because bounding changed the scale of this list. A complete run over a
 * small application skips a dozen units, and naming each one is the right
 * rendering. A bounded run over a monorepo whose units number in the thousands
 * skips most of them, almost all for the *same* reason, and a table with a row per
 * skipped unit is a way of not telling the reader anything.
 *
 * The units are still named one by one in `findings.json` and `audit.json` —
 * that is rule 2 of `PLAN.md` and it does not bend — but a renderer with a page
 * to fill should print `4,500 × budget: the run reached its batch budget…` and
 * the handful of one-off reasons in full. This is the grouping to do it with, so
 * the CLI summary, the Markdown report and the PDF cannot each invent their own
 * and disagree about the count.
 */
export function groupSkipReasons(skipped: readonly { readonly reason: string }[]): SkipGroup[] {
  const counts = new Map<string, number>();
  for (const entry of skipped) counts.set(entry.reason, (counts.get(entry.reason) ?? 0) + 1);
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([reason, units]) => ({ reason, units }));
}

/**
 * The grouped reasons as the terminal prints them: `4,500 × budget: …`.
 *
 * Beside the grouping rather than in the CLI, because `analyze` and `status`
 * both print this list about the same run and a reader comparing the two should
 * not have to wonder whether two different counts mean two different things.
 */
export function formatSkipGroups(groups: readonly SkipGroup[]): string[] {
  return groups.map((group) => `${String(group.units).padStart(4)} × ${group.reason}`);
}

/** A zeroed counter for every cause, so a report table never has a missing row. */
export function emptySkipCounts(): Record<SkipCause, number> {
  const counts = {} as Record<SkipCause, number>;
  for (const cause of SKIP_CAUSES) counts[cause] = 0;
  return counts;
}

/**
 * Collapses several outcomes for the same unit into one.
 *
 * An audited outcome always wins: a unit one batch returned a verdict for was
 * audited, whatever a second batch did with it. Among skips, the first by
 * domain order wins, so the collapse does not depend on the order batches
 * happened to finish in.
 */
function fold(outcomes: readonly UnitOutcome[]): UnitOutcome[] {
  const best = new Map<string, UnitOutcome>();
  const ordered = [...outcomes].sort(
    (left, right) =>
      (DOMAIN_RANK.get(left.domain) ?? Number.MAX_SAFE_INTEGER) -
        (DOMAIN_RANK.get(right.domain) ?? Number.MAX_SAFE_INTEGER) ||
      left.unitId.localeCompare(right.unitId),
  );
  for (const outcome of ordered) {
    const current = best.get(outcome.unitId);
    if (current === undefined) {
      best.set(outcome.unitId, outcome);
      continue;
    }
    if (!current.audited && outcome.audited) best.set(outcome.unitId, outcome);
  }
  return [...best.values()];
}

/** Deduplicates the outcomes of one domain, keeping an audited one over a skip. */
function foldWithinDomain(outcomes: readonly UnitOutcome[]): UnitOutcome[] {
  const best = new Map<string, UnitOutcome>();
  for (const outcome of outcomes) {
    const current = best.get(outcome.unitId);
    if (current === undefined || (!current.audited && outcome.audited)) {
      best.set(outcome.unitId, outcome);
    }
  }
  return [...best.values()];
}

/**
 * Builds the contract's per-domain coverage from the phase's unit outcomes.
 *
 * `domains` is the run's scope. A domain outside it is absent from the table
 * entirely — the run never claimed it — while a domain *inside* it that no unit
 * belongs to reads `0/0`, which is the difference between "nothing of this kind
 * exists in the repository" and "this was never in scope". The same rule phase
 * 1's `buildCoverage` follows, so the two tables merge without a reader having
 * to know which phase produced a row.
 */
export function buildAuditCoverage(
  outcomes: readonly UnitOutcome[],
  domains?: readonly Domain[],
): Coverage[] {
  const byDomain = new Map<Domain, UnitOutcome[]>();
  for (const outcome of outcomes) {
    const bucket = byDomain.get(outcome.domain);
    if (bucket === undefined) byDomain.set(outcome.domain, [outcome]);
    else bucket.push(outcome);
  }

  const rows: Coverage[] = [];
  for (const domain of DomainSchema.options) {
    if (domains !== undefined && !domains.includes(domain)) continue;
    const bucket = byDomain.get(domain);
    if (bucket === undefined) {
      // In scope and empty is a claim worth printing; out of scope is not.
      if (domains !== undefined) {
        rows.push(CoverageSchema.parse({ domain, unitsTotal: 0, unitsAudited: 0, skipped: [] }));
      }
      continue;
    }

    const units = foldWithinDomain(bucket);
    const skipped = units
      .filter((unit) => !unit.audited)
      .map((unit) => ({ unitId: unit.unitId, reason: skipReason(unit.cause, unit.reason) }))
      .sort((left, right) => left.unitId.localeCompare(right.unitId));

    rows.push(
      CoverageSchema.parse({
        domain,
        unitsTotal: units.length,
        unitsAudited: units.length - skipped.length,
        skipped,
      }),
    );
  }
  return rows;
}

/**
 * Builds the per-unit-kind table, counting every unit exactly once.
 *
 * This is the table the report's sentences come from, so a unit two batches
 * looked at must not inflate it: the outcomes are folded by unit id first, and
 * a unit audited by any batch counts as audited.
 */
export function buildKindCoverage(outcomes: readonly UnitOutcome[]): KindCoverage[] {
  const units = fold(outcomes);
  const byKind = new Map<AuditUnitKind, UnitOutcome[]>();
  for (const unit of units) {
    const bucket = byKind.get(unit.kind);
    if (bucket === undefined) byKind.set(unit.kind, [unit]);
    else bucket.push(unit);
  }

  const rows: KindCoverage[] = [];
  for (const kind of AUDIT_UNIT_KINDS) {
    const bucket = byKind.get(kind);
    if (bucket === undefined) continue;
    const skipped = bucket
      .filter((unit) => !unit.audited)
      .map((unit) => ({ unitId: unit.unitId, reason: skipReason(unit.cause, unit.reason) }))
      .sort((left, right) => left.unitId.localeCompare(right.unitId));
    rows.push(
      KindCoverageSchema.parse({
        kind,
        unitsTotal: bucket.length,
        unitsAudited: bucket.length - skipped.length,
        skipped,
      }),
    );
  }
  return rows.sort(
    (left, right) => (KIND_RANK.get(left.kind) ?? 0) - (KIND_RANK.get(right.kind) ?? 0),
  );
}

/** Counts distinct units, and what the un-audited ones were lost to. */
export function buildUnitTotals(outcomes: readonly UnitOutcome[]): UnitTotals {
  const units = fold(outcomes);
  const byCause = emptySkipCounts();
  let audited = 0;
  for (const unit of units) {
    if (unit.audited) {
      audited += 1;
      continue;
    }
    byCause[unit.cause ?? "no-verdict"] += 1;
  }
  return UnitTotalsSchema.parse({
    total: units.length,
    audited,
    skipped: units.length - audited,
    byCause,
  });
}

/** A coverage row, whichever of the two tables it came from. */
interface ReconcilableRow {
  readonly unitsTotal: number;
  readonly unitsAudited: number;
  readonly skipped: readonly unknown[];
}

/**
 * True when every row adds up: audited plus skipped equals the total.
 *
 * Cheap enough to assert on the way out of the phase, which is where it is
 * called: a coverage table that does not reconcile is a report that overstates
 * what was checked, and that is the one bug this project cannot ship.
 */
export function coverageReconciles(rows: readonly ReconcilableRow[]): boolean {
  return rows.every((row) => row.unitsAudited + row.skipped.length === row.unitsTotal);
}

/** The subset of units that have a verdict, as a set of ids, for the assurance pass. */
export function auditedUnitIds(outcomes: readonly UnitOutcome[]): Set<string> {
  const ids = new Set<string>();
  for (const outcome of outcomes) if (outcome.audited) ids.add(outcome.unitId);
  return ids;
}

// ---------------------------------------------------------------------------
// Resuming a bounded run
// ---------------------------------------------------------------------------

/** The slice of `audit.json` a resume reads. `AuditReport` satisfies it. */
export interface PreviousCoverage {
  readonly kinds: readonly KindCoverage[];
}

/**
 * The units a previous attempt already returned a verdict for, by id.
 *
 * Derived rather than stored, and derivable exactly: the per-kind table counts
 * every unit once and names every unit it did *not* audit, so what is left is
 * what it did. That is what makes a budget-ended run resumable without a second
 * artifact to keep in sync — and what makes a resume that is handed a *different*
 * inventory degrade safely, because a unit id that is no longer enumerated
 * simply never matches.
 *
 * Note what is deliberately not carried over: a unit skipped as `inconclusive`,
 * `batch-failed`, `no-verdict` or `budget` has no verdict, so a resume asks
 * about it again. Only `audited` earns a pass.
 */
export function auditedUnitIdsOf(
  units: readonly { readonly id: string }[],
  previous: PreviousCoverage,
): Set<string> {
  const withoutVerdict = new Set<string>();
  for (const row of previous.kinds) {
    for (const skip of row.skipped) withoutVerdict.add(skip.unitId);
  }
  const audited = new Set<string>();
  for (const unit of units) {
    if (!withoutVerdict.has(unit.id)) audited.add(unit.id);
  }
  return audited;
}

/**
 * The units a resumed run still owes an answer for, in inventory order.
 *
 * The complement of {@link auditedUnitIdsOf}, as the list phase 3 is given. The
 * risk ordering is applied by the planner, not here: this function's only job is
 * to say *what is left*, and the planner's only job is to say *what comes
 * first*, so the two can be tested apart.
 */
export function pendingUnits<T extends { readonly id: string }>(
  units: readonly T[],
  previous: PreviousCoverage,
): T[] {
  const audited = auditedUnitIdsOf(units, previous);
  return units.filter((unit) => !audited.has(unit.id));
}

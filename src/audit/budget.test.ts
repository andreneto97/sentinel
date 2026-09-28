/**
 * The budget, its defaults and the one sentence they are disclosed through.
 *
 * The defaults are asserted against the cost model they were sized from rather
 * than against their own literals: a batch costs about a minute of wall clock at a
 * fan-out of two, a small application plans a dozen batches, and a repository whose
 * units number in the thousands plans a few hundred. Both scales appear below,
 * because a default that is invisible on the first and binding on the second is
 * the whole requirement, and a test that asserted `40` without asserting why would
 * not notice the day somebody changed the rate model.
 */

import { describe, expect, test } from "bun:test";
import {
  type AuditBound,
  BUDGET_STOPS,
  DEFAULT_AUDIT_BUDGET,
  DEFAULT_MAX_BATCHES,
  DEFAULT_MAX_WALL_CLOCK_MS,
  UNBOUNDED_BUDGET,
  auditBudgetFrom,
  buildAuditBound,
  describeBound,
  resolveBudget,
  selectWithinBudget,
  unboundedBound,
} from "./budget.ts";
import { RISK_ORDERING } from "./risk.ts";

/** Wall clock one batch costs, in seconds, at the rate the defaults are sized for. */
const SECONDS_PER_BATCH = 50;

/** Batches a small application's inventory plans. */
const SMALL_APP_BATCHES = 13;

/** Batches a monorepo of a few thousand units plans. */
const MONOREPO_BATCHES = 256;

/** A batch as the budget sees it: a priority and a size. */
function batch(risk: number, units = 20): { risk: number; units: readonly number[] } {
  return { risk, units: Array.from({ length: units }, (_, index) => index) };
}

describe("the defaults", () => {
  test("do not bind on a run the size of a small application's", () => {
    expect(SMALL_APP_BATCHES).toBeLessThan(DEFAULT_MAX_BATCHES);
    const smallAppMs = SMALL_APP_BATCHES * SECONDS_PER_BATCH * 1000;
    expect(smallAppMs).toBeLessThan(DEFAULT_MAX_WALL_CLOCK_MS);
  });

  test("do bind on a repository too large to audit whole", () => {
    expect(MONOREPO_BATCHES).toBeGreaterThan(DEFAULT_MAX_BATCHES);
    const wholeRepoMs = MONOREPO_BATCHES * SECONDS_PER_BATCH * 1000;
    // Better than three hours of a throttled subscription, which is what the
    // budget exists to refuse.
    expect(wholeRepoMs).toBeGreaterThan(3 * 60 * 60_000);
  });

  test("the wall clock leaves headroom over the batch budget at that rate", () => {
    // The batch count is the plan; the clock is the backstop. If the clock were
    // tighter than the batch budget it would always be the thing that fired, and
    // the batch count would be decoration.
    const atRate = DEFAULT_MAX_BATCHES * SECONDS_PER_BATCH * 1000;
    expect(atRate).toBeLessThan(DEFAULT_MAX_WALL_CLOCK_MS);
    expect(DEFAULT_MAX_WALL_CLOCK_MS).toBeLessThan(atRate * 2);
  });
});

describe("resolveBudget", () => {
  test("an omitted field takes the default; null turns that ceiling off", () => {
    expect(resolveBudget(undefined)).toEqual(DEFAULT_AUDIT_BUDGET);
    expect(resolveBudget({ maxBatches: null }).maxBatches).toBeNull();
    expect(resolveBudget({ maxBatches: null }).maxWallClockMs).toBe(DEFAULT_MAX_WALL_CLOCK_MS);
  });

  test("a nonsensical ceiling turns itself off rather than auditing nothing", () => {
    expect(resolveBudget({ maxBatches: 0 }).maxBatches).toBeNull();
    expect(resolveBudget({ maxBatches: -3 }).maxBatches).toBeNull();
    expect(resolveBudget({ maxUnits: Number.NaN }).maxUnits).toBeNull();
  });

  test("a fractional ceiling floors to a whole batch", () => {
    expect(resolveBudget({ maxBatches: 7.9 }).maxBatches).toBe(7);
  });
});

describe("auditBudgetFrom", () => {
  test("maps the three flags, minutes included", () => {
    expect(auditBudgetFrom({ maxBatches: 12, maxUnits: 300, maxMinutes: 5 })).toEqual({
      maxBatches: 12,
      maxUnits: 300,
      maxWallClockMs: 300_000,
    });
  });

  test("--no-budget turns every ceiling off", () => {
    expect(auditBudgetFrom({ unbounded: true })).toEqual(UNBOUNDED_BUDGET);
    expect(auditBudgetFrom({ unbounded: true, maxBatches: 3 })).toEqual(UNBOUNDED_BUDGET);
  });

  test("no flags at all is the default budget, not an unbounded run", () => {
    expect(auditBudgetFrom({})).toEqual(DEFAULT_AUDIT_BUDGET);
  });
});

describe("selectWithinBudget", () => {
  test("dispatches in risk order, whatever order the batches arrived in", () => {
    const low = batch(10);
    const high = batch(90);
    const middle = batch(50);
    const selection = selectWithinBudget([low, high, middle], UNBOUNDED_BUDGET);
    expect(selection.dispatched).toEqual([high, middle, low]);
    expect(selection.stop).toBe("complete");
    expect(selection.deferred).toEqual([]);
  });

  test("takes the highest-risk batches up to the batch budget and names the stop", () => {
    const batches = [batch(10), batch(90), batch(50), batch(70)];
    const selection = selectWithinBudget(batches, { ...UNBOUNDED_BUDGET, maxBatches: 2 });
    expect(selection.dispatched.map((entry) => entry.risk)).toEqual([90, 70]);
    expect(selection.deferred.map((entry) => entry.risk)).toEqual([50, 10]);
    expect(selection.stop).toBe("batch-budget");
  });

  test("a unit ceiling stops at a whole batch, never inside one", () => {
    const selection = selectWithinBudget([batch(90, 20), batch(80, 20), batch(70, 20)], {
      ...UNBOUNDED_BUDGET,
      maxUnits: 45,
    });
    expect(selection.dispatched).toHaveLength(2);
    expect(selection.stop).toBe("unit-budget");
    // 40, not 45: a batch is dispatched whole or not at all.
    expect(selection.dispatched.reduce((sum, entry) => sum + entry.units.length, 0)).toBe(40);
  });

  test("a unit ceiling below the first batch still audits that batch", () => {
    // A budget that audits nothing is a bug; a budget that overshoots by one
    // batch is a disclosure.
    const selection = selectWithinBudget([batch(90, 30)], { ...UNBOUNDED_BUDGET, maxUnits: 5 });
    expect(selection.dispatched).toHaveLength(1);
    expect(selection.stop).toBe("complete");
  });

  test("stops at the first batch that does not fit instead of reaching past it", () => {
    // Reaching past a big high-risk batch for a small low-risk one is exactly
    // the trade the risk ordering exists to refuse.
    const selection = selectWithinBudget([batch(90, 30), batch(10, 1)], {
      ...UNBOUNDED_BUDGET,
      maxUnits: 30,
    });
    expect(selection.dispatched).toHaveLength(1);
    expect(selection.deferred.map((entry) => entry.risk)).toEqual([10]);
  });

  test("nothing is lost: dispatched plus deferred is every batch, once", () => {
    const batches = [batch(10), batch(90), batch(50), batch(70), batch(30)];
    const selection = selectWithinBudget(batches, { ...UNBOUNDED_BUDGET, maxBatches: 2 });
    expect(selection.dispatched.length + selection.deferred.length).toBe(batches.length);
    expect(new Set([...selection.dispatched, ...selection.deferred]).size).toBe(batches.length);
  });

  test("equal risk keeps the input order, so the selection is reproducible", () => {
    const first = batch(50);
    const second = batch(50);
    expect(
      selectWithinBudget([first, second], { ...UNBOUNDED_BUDGET, maxBatches: 1 }).dispatched,
    ).toEqual([first]);
  });
});

describe("describeBound", () => {
  /** The bound a monorepo of a few thousand units produces under the default budget. */
  const monorepo: Omit<AuditBound, "statement"> = {
    stop: "batch-budget",
    limits: DEFAULT_AUDIT_BUDGET,
    unitsTotal: 5000,
    unitsDispatched: 800,
    unitsAudited: 800,
    unitsDeferred: 4200,
    unitsCarriedOver: 0,
    batchesPlanned: MONOREPO_BATCHES,
    batchesDispatched: 40,
    batchesDeferred: 216,
    ordering: RISK_ORDERING,
    reasons: [
      "reachable without authentication",
      "the handler performs no role or ownership check",
    ],
  };

  test("names the number, the total and the reason, in that order", () => {
    const statement = describeBound(monorepo);
    expect(statement).toStartWith("4,200 of 5,000 units were not audited: ");
    expect(statement).toContain("reached its batch budget of 40 batches");
    expect(statement).toContain("after the 800 highest-risk units");
    expect(statement).toContain("reachable without authentication");
  });

  test("a complete run says so without pretending a budget chose anything", () => {
    const statement = describeBound({ ...monorepo, stop: "complete", unitsAudited: 5000 });
    expect(statement).toBe("all 5,000 units were audited; the run reached no budget");
  });

  test("a complete run that still lost units does not blame the ordering", () => {
    // The units a complete run loses are `inconclusive`, not deferred: pointing at
    // the risk ordering would misattribute them.
    const statement = describeBound({
      ...monorepo,
      stop: "complete",
      unitsTotal: 200,
      unitsAudited: 188,
      unitsDeferred: 0,
    });
    expect(statement).toStartWith("12 of 200 units were not audited: ");
    expect(statement).toContain("each one without a verdict is listed with its own reason");
    expect(statement).not.toContain("chosen for");
  });

  test("what the budget covered is not confused with what came back", () => {
    // The failure this distinction was added for: when the transcript comes back
    // empty the budget still covered every unit it dispatched, and the sentence
    // used to read `after the 0 highest-risk units`.
    const statement = describeBound({ ...monorepo, unitsAudited: 0 });
    expect(statement).toStartWith("5,000 of 5,000 units were not audited: ");
    expect(statement).toContain("after the 800 highest-risk units");
    expect(statement).toContain("of those, 0 came back with a verdict");
    expect(statement).not.toContain("the 0 highest-risk");
  });

  test("a run whose every dispatched batch answered says nothing extra", () => {
    expect(describeBound(monorepo)).not.toContain("came back with a verdict");
  });

  test("carried-over units are not counted as this attempt's verdicts", () => {
    // 800 dispatched, 800 answered, 1,000 carried over from an earlier attempt:
    // the clause must not fire, because nothing fell short.
    const statement = describeBound({
      ...monorepo,
      unitsCarriedOver: 1000,
      unitsAudited: 1800,
    });
    expect(statement).not.toContain("came back with a verdict");
    expect(statement).toStartWith("3,200 of 5,000 units were not audited: ");
  });

  test("a wall-clock stop says how far it got in batches", () => {
    const statement = describeBound({ ...monorepo, stop: "wall-clock", batchesDispatched: 31 });
    expect(statement).toContain("45-minute ceiling after 31 batches of 256");
  });

  test("a usage limit is not confused with a ceiling the operator chose", () => {
    expect(describeBound({ ...monorepo, stop: "quota" })).toContain(
      "the subscription's usage limit was reached",
    );
  });

  test("a cancelled run says it was cancelled", () => {
    expect(describeBound({ ...monorepo, stop: "cancelled" })).toContain("the run was cancelled");
  });

  test("a unit ceiling quotes the ceiling it was given", () => {
    expect(
      describeBound({
        ...monorepo,
        stop: "unit-budget",
        limits: { ...DEFAULT_AUDIT_BUDGET, maxUnits: 800 },
      }),
    ).toContain("its ceiling of 800 units");
  });

  test("every stop reason produces a sentence rather than a bare enum token", () => {
    for (const stop of BUDGET_STOPS) {
      const statement = describeBound({ ...monorepo, stop });
      // The hyphenated ids are the ones a reader would see as machine output;
      // `cancelled` and `complete` are also English, and are allowed to be.
      expect(statement).not.toContain("batch-budget");
      expect(statement).not.toContain("unit-budget");
      expect(statement).not.toContain("wall-clock");
      expect(statement.length).toBeGreaterThan(30);
    }
  });
});

describe("buildAuditBound", () => {
  test("validates on the way out, so an invalid bound cannot exist as a value", () => {
    expect(() =>
      buildAuditBound({
        stop: "complete",
        limits: UNBOUNDED_BUDGET,
        unitsTotal: -1,
        unitsDispatched: 0,
        unitsAudited: 0,
        unitsDeferred: 0,
        unitsCarriedOver: 0,
        batchesPlanned: 0,
        batchesDispatched: 0,
        batchesDeferred: 0,
        ordering: RISK_ORDERING,
        reasons: [],
      }),
    ).toThrow();
  });

  test("the statement is derived, never passed in", () => {
    const bound = unboundedBound(200, 200);
    expect(bound.statement).toBe("all 200 units were audited; the run reached no budget");
    expect(bound.limits).toEqual(UNBOUNDED_BUDGET);
  });
});

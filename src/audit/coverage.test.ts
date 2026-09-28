import { describe, expect, test } from "bun:test";
import { type Domain, DomainSchema } from "../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, type AuditUnitKind } from "../contracts/inventory.ts";
import {
  DOMAIN_BY_UNIT_KIND,
  SKIP_CAUSES,
  type UnitOutcome,
  UnitTotalsSchema,
  auditedUnitIds,
  auditedUnitIdsOf,
  buildAuditCoverage,
  buildKindCoverage,
  buildUnitTotals,
  coverageReconciles,
  emptySkipCounts,
  groupSkipReasons,
  pendingUnits,
  skipReason,
} from "./coverage.ts";
import { domainsFor, isAuditedKind, unauditedReason } from "./prompts/index.ts";

/** An audited route unit in `appsec`, the shape most of these tests vary from. */
function audited(unitId: string, overrides: Partial<UnitOutcome> = {}): UnitOutcome {
  return { unitId, kind: "route", domain: "appsec", audited: true, ...overrides };
}

/** A unit with no verdict, with the cause the report will print. */
function skipped(unitId: string, overrides: Partial<UnitOutcome> = {}): UnitOutcome {
  return {
    unitId,
    kind: "route",
    domain: "appsec",
    audited: false,
    cause: "batch-failed",
    reason: "the agent dispatch timed out",
    ...overrides,
  };
}

describe("the kind-to-domain fallback", () => {
  test("names a domain for every unit kind the contract declares", () => {
    for (const kind of AUDIT_UNIT_KINDS) {
      expect(DomainSchema.options).toContain(DOMAIN_BY_UNIT_KIND[kind]);
    }
    expect(Object.keys(DOMAIN_BY_UNIT_KIND).sort()).toEqual([...AUDIT_UNIT_KINDS].sort());
  });
});

describe("skipReason", () => {
  test("prints the cause followed by the sentence", () => {
    expect(skipReason("no-verdict", "the agent returned no verdict for this unit")).toBe(
      "no-verdict: the agent returned no verdict for this unit",
    );
  });

  test("still names the cause when nobody gave a reason", () => {
    expect(skipReason("no-batch", undefined)).toBe("no-batch: no reason given");
    expect(skipReason("no-batch", "   ")).toBe("no-batch: no reason given");
  });
});

describe("buildAuditCoverage", () => {
  test("reconciles: audited plus skipped equals the total", () => {
    const rows = buildAuditCoverage([audited("a"), audited("b"), skipped("c")]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.unitsTotal).toBe(3);
    expect(rows[0]?.unitsAudited).toBe(2);
    expect(rows[0]?.skipped).toHaveLength(1);
    expect(coverageReconciles(rows)).toBe(true);
  });

  test("names each skipped unit with the cause and the sentence", () => {
    const rows = buildAuditCoverage([
      skipped("c", { reason: "the subscription limit was reached" }),
    ]);
    expect(rows[0]?.skipped[0]).toEqual({
      unitId: "c",
      reason: "batch-failed: the subscription limit was reached",
    });
  });

  test("counts a unit per domain, so two angles on one handler are two rows", () => {
    const rows = buildAuditCoverage([
      audited("handler", { domain: "appsec" }),
      skipped("handler", { domain: "api", cause: "no-verdict", reason: "no verdict came back" }),
    ]);
    const appsec = rows.find((row) => row.domain === "appsec");
    const api = rows.find((row) => row.domain === "api");
    expect(appsec).toMatchObject({ unitsTotal: 1, unitsAudited: 1 });
    expect(api).toMatchObject({ unitsTotal: 1, unitsAudited: 0 });
    expect(api?.skipped[0]?.reason).toBe("no-verdict: no verdict came back");
    expect(coverageReconciles(rows)).toBe(true);
  });

  test("an audited verdict wins over a skip for the same unit in the same domain", () => {
    const rows = buildAuditCoverage([skipped("handler"), audited("handler")]);
    expect(rows[0]).toMatchObject({ unitsTotal: 1, unitsAudited: 1, skipped: [] });
  });

  test("orders rows by the contract's domain order and skips by unit id", () => {
    const rows = buildAuditCoverage([
      skipped("z", { domain: "data", kind: "data-access" }),
      skipped("a", { domain: "data", kind: "data-access" }),
      audited("q", { domain: "appsec" }),
    ]);
    expect(rows.map((row) => row.domain)).toEqual(["appsec", "data"]);
    expect(rows[1]?.skipped.map((entry) => entry.unitId)).toEqual(["a", "z"]);
  });

  test("a domain in scope with no units reads 0/0; one out of scope is absent", () => {
    const rows = buildAuditCoverage([audited("a")], ["appsec", "data"]);
    expect(rows.map((row) => row.domain)).toEqual(["appsec", "data"]);
    expect(rows[1]).toMatchObject({ unitsTotal: 0, unitsAudited: 0, skipped: [] });
  });

  test("drops a domain the run's scope excluded rather than reporting it empty", () => {
    const rows = buildAuditCoverage(
      [audited("a"), skipped("b", { domain: "serverless", kind: "cron" })],
      ["appsec"],
    );
    expect(rows.map((row) => row.domain)).toEqual(["appsec"]);
  });

  test("claims nothing for a domain nobody looked at when no scope was given", () => {
    expect(buildAuditCoverage([audited("a")]).map((row) => row.domain)).toEqual(["appsec"]);
  });
});

describe("buildKindCoverage", () => {
  test("counts each unit once however many domains looked at it", () => {
    const rows = buildKindCoverage([
      audited("handler", { domain: "appsec" }),
      audited("handler", { domain: "api" }),
      skipped("other", { domain: "appsec" }),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ kind: "route", unitsTotal: 2, unitsAudited: 1 });
    expect(coverageReconciles(rows)).toBe(true);
  });

  test("a unit audited in any domain counts as audited", () => {
    const rows = buildKindCoverage([
      skipped("handler", { domain: "api", cause: "no-verdict" }),
      audited("handler", { domain: "appsec" }),
    ]);
    expect(rows[0]).toMatchObject({ unitsTotal: 1, unitsAudited: 1, skipped: [] });
  });

  test("orders kinds the way the contract declares them", () => {
    const rows = buildKindCoverage([
      audited("m", { kind: "migration", domain: "data" }),
      audited("r", { kind: "route" }),
      audited("d", { kind: "data-access", domain: "data" }),
    ]);
    expect(rows.map((row) => row.kind)).toEqual(["route", "data-access", "migration"]);
  });

  test("a skipped unit keeps the reason from the first domain that reported it", () => {
    const rows = buildKindCoverage([
      skipped("handler", { domain: "api", cause: "no-verdict", reason: "api batch said nothing" }),
      skipped("handler", {
        domain: "appsec",
        cause: "batch-failed",
        reason: "appsec batch failed",
      }),
    ]);
    expect(rows[0]?.skipped[0]?.reason).toBe("batch-failed: appsec batch failed");
  });
});

describe("buildUnitTotals", () => {
  test("counts distinct units and attributes every skip to a cause", () => {
    const totals = buildUnitTotals([
      audited("a", { domain: "appsec" }),
      audited("a", { domain: "api" }),
      skipped("b", { cause: "no-batch" }),
      skipped("c", { cause: "inconclusive" }),
    ]);
    expect(totals).toMatchObject({ total: 3, audited: 1, skipped: 2 });
    expect(totals.byCause["no-batch"]).toBe(1);
    expect(totals.byCause.inconclusive).toBe(1);
    expect(totals.audited + totals.skipped).toBe(totals.total);
  });

  test("carries a row for every cause, so a report table has no gaps", () => {
    const totals = buildUnitTotals([audited("a")]);
    expect(Object.keys(totals.byCause).sort()).toEqual([...SKIP_CAUSES].sort());
    expect(Object.keys(emptySkipCounts()).sort()).toEqual([...SKIP_CAUSES].sort());
  });

  test("reads back an artifact written before a cause existed, filling it with zero", () => {
    // `budget` was added to SKIP_CAUSES after runs had already been written.
    // Requiring it on the way in made every earlier `audit.json` fail validation,
    // which the report reported as "audit.json is absent" — losing the per-kind
    // coverage and every model verdict, and *raising* the score, because the
    // coverage penalty went missing with the data.
    const older = {
      total: 172,
      audited: 160,
      skipped: 12,
      byCause: {
        "no-batch": 0,
        "batch-failed": 0,
        "no-verdict": 0,
        inconclusive: 12,
        cancelled: 0,
      },
    };
    const parsed = UnitTotalsSchema.parse(older);
    expect(parsed.byCause.budget).toBe(0);
    expect(parsed.byCause.inconclusive).toBe(12);
    expect(Object.keys(parsed.byCause).sort()).toEqual([...SKIP_CAUSES].sort());
  });
});

describe("coverageReconciles", () => {
  test("rejects a row whose numbers do not add up", () => {
    expect(coverageReconciles([{ unitsTotal: 3, unitsAudited: 3, skipped: ["x"] }])).toBe(false);
    expect(coverageReconciles([{ unitsTotal: 3, unitsAudited: 2, skipped: ["x"] }])).toBe(true);
  });
});

describe("auditedUnitIds", () => {
  test("returns only the units a verdict was accepted for", () => {
    expect([...auditedUnitIds([audited("a"), skipped("b")])]).toEqual(["a"]);
  });
});

describe("the `budget` cause", () => {
  test("is a cause of its own, not a flavour of `no-batch`", () => {
    // A report that collapsed the two would tell a reader that the planner had
    // nothing to say about thousands of units, when what happened is that the run
    // could not afford them and `sentinel resume` will pick them up.
    expect(SKIP_CAUSES).toContain("budget");
    expect(skipReason("budget", "the run reached its batch budget of 40 batches")).toBe(
      "budget: the run reached its batch budget of 40 batches",
    );
    const totals = buildUnitTotals([
      audited("a"),
      skipped("b", { cause: "budget", reason: "the run reached its batch budget" }),
      skipped("c", { cause: "no-batch", reason: "no batch covered this unit" }),
    ]);
    expect(totals.byCause.budget).toBe(1);
    expect(totals.byCause["no-batch"]).toBe(1);
  });

  test("a budget-skipped unit still reconciles and is never counted as clean", () => {
    const rows = buildAuditCoverage([
      audited("a"),
      skipped("b", { cause: "budget", reason: "the run reached its batch budget" }),
    ]);
    expect(coverageReconciles(rows)).toBe(true);
    expect(rows[0]).toMatchObject({ unitsTotal: 2, unitsAudited: 1 });
    expect(rows[0]?.skipped[0]?.reason).toStartWith("budget: ");
  });
});

describe("resuming from a previous attempt", () => {
  /** `audit.json`'s per-kind table after a run that audited two of five units. */
  const previous = {
    kinds: [
      {
        kind: "route" as const,
        unitsTotal: 3,
        unitsAudited: 2,
        skipped: [{ unitId: "r3", reason: "budget: the run reached its batch budget" }],
      },
      {
        kind: "data-access" as const,
        unitsTotal: 2,
        unitsAudited: 0,
        skipped: [
          { unitId: "d1", reason: "budget: the run reached its batch budget" },
          { unitId: "d2", reason: "inconclusive: the agent declined to decide" },
        ],
      },
    ],
  };
  const units = [{ id: "r1" }, { id: "r2" }, { id: "r3" }, { id: "d1" }, { id: "d2" }];

  test("only a unit with a verdict is carried over", () => {
    expect([...auditedUnitIdsOf(units, previous)].sort()).toEqual(["r1", "r2"]);
  });

  test("an inconclusive unit is asked about again, exactly like a deferred one", () => {
    // `inconclusive` is a model saying it could not decide. That is not a
    // verdict, so it is not a pass, so a resume owes the unit another look.
    expect(pendingUnits(units, previous).map((unit) => unit.id)).toEqual(["r3", "d1", "d2"]);
  });

  test("a unit id the inventory no longer lists simply never matches", () => {
    const changed = [{ id: "r1" }, { id: "brand-new" }];
    expect([...auditedUnitIdsOf(changed, previous)].sort()).toEqual(["brand-new", "r1"]);
    // `brand-new` was never skipped by the previous attempt, so by this
    // derivation it counts as audited — which is why a resume that re-enumerated
    // a changed repository must re-plan rather than trust an old report. The CLI
    // refuses that case; this asserts the derivation does not crash on it.
    expect(pendingUnits(changed, previous)).toEqual([]);
  });

  test("a previous attempt that audited everything leaves nothing pending", () => {
    const complete = {
      kinds: [{ kind: "route" as const, unitsTotal: 2, unitsAudited: 2, skipped: [] }],
    };
    expect(pendingUnits([{ id: "r1" }, { id: "r2" }], complete)).toEqual([]);
  });
});

describe("groupSkipReasons", () => {
  test("collapses the thousands a budget defers into one line with its count", () => {
    const rows = buildAuditCoverage([
      audited("a"),
      skipped("b", { cause: "budget", reason: "the run reached its batch budget" }),
      skipped("c", { cause: "budget", reason: "the run reached its batch budget" }),
      skipped("d", { cause: "inconclusive", reason: "the agent declined to decide" }),
    ]);
    const groups = groupSkipReasons(rows[0]?.skipped ?? []);
    expect(groups).toEqual([
      { reason: "budget: the run reached its batch budget", units: 2 },
      { reason: "inconclusive: the agent declined to decide", units: 1 },
    ]);
    // Biggest first, so a renderer that prints only the top lines prints the
    // ones that account for the most units.
    expect(groups[0]?.units).toBeGreaterThanOrEqual(groups[1]?.units ?? 0);
  });

  test("the counts add up to the units it was given, so a renderer cannot lose one", () => {
    const skipped = [{ reason: "budget: x" }, { reason: "budget: x" }, { reason: "no-batch: y" }];
    const groups = groupSkipReasons(skipped);
    expect(groups.reduce((sum, group) => sum + group.units, 0)).toBe(skipped.length);
  });

  test("nothing skipped is no groups, not a zero row", () => {
    expect(groupSkipReasons([])).toEqual([]);
  });
});

describe("the registry's domain column, through this table", () => {
  /**
   * One unit per kind, with one outcome per domain the registry registers for
   * that kind — which is what the audit phase files, and the shape the D6 and D7
   * prompts changed by putting the same route in three domains at once.
   *
   * Driven off `domainsFor` rather than a list written here, so a row added to
   * the registry is exercised by these assertions without anybody remembering to
   * come back and add it.
   */
  function outcomesAcrossTheRegistry(
    decide: (kind: AuditUnitKind, domain: Domain, index: number) => boolean,
  ): UnitOutcome[] {
    const outcomes: UnitOutcome[] = [];
    for (const kind of AUDIT_UNIT_KINDS) {
      const domains = domainsFor(kind);
      // A kind no prompt covers is still counted, in the one domain its
      // fallback names, with the sentence the registry states.
      if (domains.length === 0) {
        outcomes.push({
          unitId: `${kind}-1`,
          kind,
          domain: DOMAIN_BY_UNIT_KIND[kind],
          audited: false,
          cause: "no-batch",
          reason: unauditedReason(kind),
        });
        continue;
      }
      for (const [index, domain] of domains.entries()) {
        const audited = decide(kind, domain, index);
        outcomes.push({
          unitId: `${kind}-1`,
          kind,
          domain,
          audited,
          ...(audited
            ? {}
            : { cause: "no-verdict" as const, reason: "the reply said nothing about this unit" }),
        });
      }
    }
    return outcomes;
  }

  test("every kind maps to a domain and a prompt, or states why it has neither", () => {
    for (const kind of AUDIT_UNIT_KINDS) {
      const domains = domainsFor(kind);
      if (isAuditedKind(kind)) {
        expect(domains.length).toBeGreaterThan(0);
        // The primary domain is the fallback, so a unit no batch reached lands
        // in the same table as one that was audited.
        expect(domains[0]).toBe(DOMAIN_BY_UNIT_KIND[kind]);
        continue;
      }
      expect(domains).toEqual([]);
      expect(unauditedReason(kind).length).toBeGreaterThan(20);
      expect(DomainSchema.options).toContain(DOMAIN_BY_UNIT_KIND[kind]);
    }
  });

  test("reconciles per domain when every kind is audited in every domain it has", () => {
    const rows = buildAuditCoverage(outcomesAcrossTheRegistry(() => true));
    expect(coverageReconciles(rows)).toBe(true);
    for (const row of rows) {
      expect(row.unitsAudited + row.skipped.length).toBe(row.unitsTotal);
    }
    // Every domain any prompt answers for is present, and so is the one the
    // unaudited kind falls back to.
    const present = new Set(rows.map((row) => row.domain));
    for (const kind of AUDIT_UNIT_KINDS) {
      for (const domain of domainsFor(kind)) expect(present.has(domain)).toBe(true);
      expect(present.has(DOMAIN_BY_UNIT_KIND[kind])).toBe(true);
    }
  });

  test("reconciles per domain when only the primary domain answered", () => {
    // The failure this arithmetic exists to catch: the secondary batches came
    // back empty, so each domain must count the unit against its own total
    // rather than leave it out and report a clean fraction of what it managed.
    const rows = buildAuditCoverage(
      outcomesAcrossTheRegistry((_kind, _domain, index) => index === 0),
    );
    expect(coverageReconciles(rows)).toBe(true);
    for (const kind of AUDIT_UNIT_KINDS) {
      for (const [index, domain] of domainsFor(kind).entries()) {
        const row = rows.find((candidate) => candidate.domain === domain);
        if (row === undefined) throw new Error(`no ${domain} row`);
        const skipped = row.skipped.some((skip) => skip.unitId === `${kind}-1`);
        expect(skipped).toBe(index > 0);
      }
    }
  });

  test("reconciles per domain when nothing was audited at all", () => {
    const rows = buildAuditCoverage(outcomesAcrossTheRegistry(() => false));
    expect(coverageReconciles(rows)).toBe(true);
    expect(rows.every((row) => row.unitsAudited === 0)).toBe(true);
    expect(rows.every((row) => row.skipped.length === row.unitsTotal)).toBe(true);
  });

  test("the per-kind table counts each unit once however many domains it feeds", () => {
    const rows = buildKindCoverage(
      outcomesAcrossTheRegistry((_kind, _domain, index) => index === 0),
    );
    expect(coverageReconciles(rows)).toBe(true);
    expect(rows).toHaveLength(AUDIT_UNIT_KINDS.length);
    for (const row of rows) {
      expect(row.unitsTotal).toBe(1);
      // Audited in any domain is audited; only the kind no prompt covers is not.
      expect(row.unitsAudited).toBe(isAuditedKind(row.kind) ? 1 : 0);
    }
    const totals = buildUnitTotals(outcomesAcrossTheRegistry((_k, _d, index) => index === 0));
    expect(totals.total).toBe(AUDIT_UNIT_KINDS.length);
    expect(totals.audited + totals.skipped).toBe(totals.total);
  });

  test("a kind with no prompt is reported as not audited, never dropped", () => {
    const rows = buildAuditCoverage(outcomesAcrossTheRegistry(() => true));
    const unaudited = AUDIT_UNIT_KINDS.filter((kind) => !isAuditedKind(kind));
    expect(unaudited.length).toBeGreaterThan(0);
    for (const kind of unaudited) {
      const row = rows.find((candidate) => candidate.domain === DOMAIN_BY_UNIT_KIND[kind]);
      const skip = row?.skipped.find((entry) => entry.unitId === `${kind}-1`);
      expect(skip).toBeDefined();
      // The reason is the registry's sentence, so "no prompt was written" and
      // "a model looked and found nothing" cannot read the same way.
      expect(skip?.reason).toContain(unauditedReason(kind));
    }
  });
});

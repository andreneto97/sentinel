import { describe, expect, test } from "bun:test";
import type { CodeRef } from "../contracts/findings.ts";
import {
  type AssertedCheck,
  MAX_ASSURANCE_EVIDENCE,
  UNIT_KIND_NOUN,
  assuranceId,
  buildAssurances,
  buildScope,
  pickStatement,
} from "./assurance.ts";
import type { UnitOutcome } from "./coverage.ts";

const CHECK_ID = "appsec.ownership-asserted-before-write";
const STATEMENT = "ownership asserted before write";

/** A check asserted by one route handler, with one verified citation. */
function check(unitId: string, overrides: Partial<AssertedCheck> = {}): AssertedCheck {
  return {
    unitId,
    kind: "route",
    domain: "appsec",
    checkId: CHECK_ID,
    statement: STATEMENT,
    evidence: [ref(`src/api/${unitId}.ts`, 12)],
    ...overrides,
  };
}

/** A citation that has already been verified against disk. */
function ref(file: string, line: number): CodeRef {
  return { file, line, snippet: `${line} | await db.order.update({ where: { ownerId } })` };
}

/** An audited route unit in `appsec`. */
function audited(unitId: string): UnitOutcome {
  return { unitId, kind: "route", domain: "appsec", audited: true };
}

/** A route unit no agent returned a verdict for. */
function skipped(unitId: string): UnitOutcome {
  return {
    unitId,
    kind: "route",
    domain: "appsec",
    audited: false,
    cause: "batch-failed",
    reason: "the dispatch timed out",
  };
}

describe("buildAssurances", () => {
  test("aggregates one row per check, with the units that asserted it", () => {
    const assurances = buildAssurances(
      [check("a"), check("b"), check("c")],
      [audited("a"), audited("b"), audited("c")],
    );
    expect(assurances).toHaveLength(1);
    expect(assurances[0]).toMatchObject({
      domain: "appsec",
      check: STATEMENT,
      scope: "3/3 route handlers",
      unitsChecked: 3,
    });
    expect(assurances[0]?.evidence).toHaveLength(3);
  });

  test("uses the noun the agent gave the population when it gave one", () => {
    const assurances = buildAssurances(
      [check("a", { subject: "mutation handlers" }), check("b", { subject: "mutation handlers" })],
      [audited("a"), audited("b")],
    );
    expect(assurances[0]?.scope).toBe("2/2 mutation handlers");
  });

  test("falls back to Sentinel's own noun for the kind", () => {
    const assurances = buildAssurances([check("a", { kind: "migration", domain: "data" })], []);
    expect(assurances[0]?.scope).toContain(UNIT_KIND_NOUN.migration);
  });

  test("says so when part of the population was never audited", () => {
    const assurances = buildAssurances(
      [check("a"), check("b")],
      [audited("a"), audited("b"), skipped("c"), skipped("d")],
    );
    expect(assurances[0]?.scope).toBe(
      "2/2 route handlers; 2 more were not audited and are outside this assurance",
    );
  });

  test("uses the singular when exactly one unit was not audited", () => {
    const assurances = buildAssurances([check("a")], [audited("a"), skipped("b")]);
    expect(assurances[0]?.scope).toBe(
      "1/1 route handlers; 1 more was not audited and is outside this assurance",
    );
  });

  test("denominates against the audited population, not against the assertions", () => {
    // Three handlers were audited; only one of them asserted this check.
    const assurances = buildAssurances([check("a")], [audited("a"), audited("b"), audited("c")]);
    expect(assurances[0]?.scope).toBe("1/3 route handlers");
    expect(assurances[0]?.unitsChecked).toBe(1);
  });

  test("counts a unit once even when it asserts the same check twice", () => {
    const assurances = buildAssurances([check("a"), check("a")], [audited("a")]);
    expect(assurances[0]?.unitsChecked).toBe(1);
  });

  test("de-duplicates evidence that two units cited identically", () => {
    const shared = ref("src/lib/guard.ts", 4);
    const assurances = buildAssurances(
      [check("a", { evidence: [shared] }), check("b", { evidence: [shared] })],
      [audited("a"), audited("b")],
    );
    expect(assurances[0]?.evidence).toHaveLength(1);
  });

  test("orders evidence by file and line", () => {
    const assurances = buildAssurances(
      [check("a", { evidence: [ref("src/b.ts", 9), ref("src/a.ts", 30), ref("src/a.ts", 2)] })],
      [audited("a")],
    );
    expect(assurances[0]?.evidence.map((entry) => `${entry.file}:${entry.line}`)).toEqual([
      "src/a.ts:2",
      "src/a.ts:30",
      "src/b.ts:9",
    ]);
  });

  test("samples evidence rather than pasting a hundred refs, and admits it", () => {
    const checks = Array.from({ length: 5 }, (_value, index) => check(`unit-${index}`));
    const assurances = buildAssurances(
      checks,
      checks.map((entry) => audited(entry.unitId)),
      {
        maxEvidence: 2,
      },
    );
    expect(assurances[0]?.evidence).toHaveLength(2);
    expect(assurances[0]?.scope).toBe("5/5 route handlers; evidence lists 2 of 5");
    expect(assurances[0]?.unitsChecked).toBe(5);
  });

  test("keeps a check asserted over two kinds as two claims", () => {
    const assurances = buildAssurances(
      [check("a"), check("q", { kind: "data-access", domain: "appsec" })],
      [audited("a")],
    );
    expect(assurances).toHaveLength(2);
    expect(assurances.map((entry) => entry.unitsChecked)).toEqual([1, 1]);
  });

  test("drops a check for a domain the run's scope excluded", () => {
    const assurances = buildAssurances(
      [check("a"), check("b", { domain: "data", kind: "data-access" })],
      [],
      { domains: ["appsec"] },
    );
    expect(assurances.map((entry) => entry.domain)).toEqual(["appsec"]);
  });

  test("ignores a check with no id rather than emitting an anonymous row", () => {
    expect(buildAssurances([check("a", { checkId: "  " })], [])).toEqual([]);
  });

  test("is deterministic: the input order cannot change the bytes", () => {
    const checks = [
      check("a"),
      check("b", { statement: "ownership asserted before write" }),
      check("c", { checkId: "appsec.input-validated", statement: "request body validated" }),
      check("d", { kind: "migration", domain: "data", checkId: "data.guarded-destructive" }),
    ];
    const outcomes = [audited("a"), audited("b"), audited("c")];
    const forwards = JSON.stringify(buildAssurances(checks, outcomes));
    const backwards = JSON.stringify(
      buildAssurances([...checks].reverse(), [...outcomes].reverse()),
    );
    expect(forwards).toBe(backwards);
  });

  test("defaults the evidence budget so a caller cannot forget it", () => {
    const checks = Array.from({ length: MAX_ASSURANCE_EVIDENCE + 3 }, (_value, index) =>
      check(`unit-${index}`),
    );
    const assurances = buildAssurances(checks, []);
    expect(assurances[0]?.evidence).toHaveLength(MAX_ASSURANCE_EVIDENCE);
  });
});

describe("assuranceId", () => {
  test("is stable across runs", () => {
    expect(assuranceId("appsec", CHECK_ID, "route")).toBe(assuranceId("appsec", CHECK_ID, "route"));
  });

  test("separates the same check over two populations", () => {
    expect(assuranceId("appsec", CHECK_ID, "route")).not.toBe(
      assuranceId("appsec", CHECK_ID, "data-access"),
    );
    expect(assuranceId("appsec", CHECK_ID, "route")).not.toBe(
      assuranceId("data", CHECK_ID, "route"),
    );
  });
});

describe("pickStatement", () => {
  test("takes the majority phrasing", () => {
    expect(pickStatement(["b", "a", "a"])).toBe("a");
  });

  test("breaks a tie lexicographically rather than by arrival", () => {
    expect(pickStatement(["b", "a"])).toBe("a");
    expect(pickStatement(["a", "b"])).toBe("a");
  });

  test("ignores blank phrasings", () => {
    expect(pickStatement(["", "   ", "real"])).toBe("real");
    expect(pickStatement([])).toBe("");
  });
});

describe("buildScope", () => {
  test("reads as a fraction of the audited population", () => {
    expect(buildScope(23, "mutation handlers", { audited: 23, skipped: 0 }, 23)).toBe(
      "23/23 mutation handlers",
    );
  });

  test("never denominates below the number of units that asserted the check", () => {
    // A caller that passes no population must not produce `3/0`.
    expect(buildScope(3, "route handlers", { audited: 0, skipped: 0 }, 3)).toBe(
      "3/3 route handlers",
    );
  });
});

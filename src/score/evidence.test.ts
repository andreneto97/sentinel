import { describe, expect, test } from "bun:test";
import { DomainSchema } from "../contracts/findings.ts";
import { AUDIT_UNIT_KINDS } from "../contracts/inventory.ts";
import { evidenceInput, inventorySignals } from "./__fixtures__/factories.ts";
import {
  UNIT_KINDS_BY_DOMAIN,
  describeAudited,
  describeUnits,
  domainEvidence,
  evidenceFrom,
  noEvidence,
} from "./evidence.ts";

/** A repository large enough that its data layer dwarfs everything a single check can say. */
const LARGE_REPO_UNITS = {
  route: 300,
  "data-access": 4000,
  "queue-consumer": 10,
  webhook: 20,
  migration: 500,
  sink: 400,
  "workflow-job": 30,
} as const;

describe("UNIT_KINDS_BY_DOMAIN", () => {
  test("covers every unit kind exactly once across every domain", () => {
    const claimed = DomainSchema.options.flatMap((domain) => UNIT_KINDS_BY_DOMAIN[domain]);
    expect([...claimed].sort()).toEqual([...AUDIT_UNIT_KINDS].sort());
  });

  test("gives the data layer its migrations and its data access", () => {
    expect([...UNIT_KINDS_BY_DOMAIN.data].sort()).toEqual(["data-access", "migration"]);
  });

  test("leaves the tool-only domains without unit kinds, so they keep being judged on checks", () => {
    expect(UNIT_KINDS_BY_DOMAIN.dependencies).toEqual([]);
    expect(UNIT_KINDS_BY_DOMAIN.deadcode).toEqual([]);
  });
});

describe("evidenceFrom", () => {
  test("takes the denominator from the inventory even when the audit never ran", () => {
    const input = evidenceFrom({ inventory: inventorySignals(LARGE_REPO_UNITS) });
    expect(input.auditRan).toBe(false);
    expect(input.units.migration).toEqual({ present: 500, verdicted: 0 });
    expect(input.units["data-access"]).toEqual({ present: 4000, verdicted: 0 });
  });

  test("counts the verdicts the audit returned, per kind", () => {
    const input = evidenceFrom({
      inventory: inventorySignals({ migration: 8, "data-access": 95 }),
      audit: {
        kinds: [
          { kind: "migration", unitsTotal: 8, unitsAudited: 7, skipped: [] },
          { kind: "data-access", unitsTotal: 95, unitsAudited: 87, skipped: [] },
        ],
      },
    });
    expect(input.auditRan).toBe(true);
    expect(input.units.migration).toEqual({ present: 8, verdicted: 7 });
    expect(input.units["data-access"]).toEqual({ present: 95, verdicted: 87 });
  });

  test("takes the larger total, so a unit the inventory missed still counts against the domain", () => {
    const input = evidenceFrom({
      inventory: inventorySignals({ route: 10 }),
      audit: { kinds: [{ kind: "route", unitsTotal: 14, unitsAudited: 14, skipped: [] }] },
    });
    expect(input.units.route).toEqual({ present: 14, verdicted: 14 });
  });

  test("never lets verdicts exceed the units that exist", () => {
    const input = evidenceFrom({
      inventory: inventorySignals({ route: 4 }),
      audit: { kinds: [{ kind: "route", unitsTotal: 4, unitsAudited: 9, skipped: [] }] },
    });
    expect(input.units.route).toEqual({ present: 4, verdicted: 4 });
  });

  test("omits a kind nobody enumerated, so `0 units` and `no such unit` stay distinct", () => {
    const input = evidenceFrom({ inventory: inventorySignals({ route: 3, cron: 0 }) });
    expect(input.units.cron).toBeUndefined();
  });

  test("claims nothing with neither artifact", () => {
    expect(evidenceFrom({})).toEqual({ units: {}, auditRan: false });
  });
});

describe("domainEvidence", () => {
  test("the bug: thousands of data-layer units exist and a --no-ai run examined none", () => {
    const evidence = domainEvidence("data", evidenceInput(LARGE_REPO_UNITS));
    expect(evidence.applies).toBe(true);
    expect(evidence.unitsPresent).toBe(4500);
    expect(evidence.unitsVerdicted).toBe(0);
    expect(evidence.ratio).toBe(0);
    expect(evidence.statement).toBe(
      "0 of its 4,500 units were examined: 4,000 data-access call sites and 500 migrations exist " +
        "and none of them were audited: the audit phase did not run in this run",
    );
  });

  test("names the kinds biggest first, with grouped thousands", () => {
    const evidence = domainEvidence("data", evidenceInput(LARGE_REPO_UNITS));
    expect(evidence.kinds.map((row) => row.kind)).toEqual(["data-access", "migration"]);
    expect(describeUnits(evidence.kinds)).toBe("4,000 data-access call sites and 500 migrations");
  });

  test("blames the batches, not the flag, when the audit did run and still returned nothing", () => {
    const evidence = domainEvidence(
      "data",
      evidenceFrom({
        inventory: inventorySignals({ migration: 8 }),
        audit: { kinds: [{ kind: "migration", unitsTotal: 8, unitsAudited: 0, skipped: [] }] },
      }),
    );
    expect(evidence.statement).toContain("no audit batch returned a verdict for any of them");
  });

  test("does not apply to a domain with no audit units", () => {
    const evidence = domainEvidence("dependencies", evidenceInput(LARGE_REPO_UNITS));
    expect(evidence.applies).toBe(false);
    expect(evidence.unitsPresent).toBe(0);
    expect(evidence.kinds).toEqual([]);
    expect(evidence.statement).toContain("no audit unit belongs to this domain");
  });

  test("does not apply to a domain whose kinds exist but whose repository has none of them", () => {
    expect(domainEvidence("serverless", evidenceInput({ route: 4 })).applies).toBe(false);
  });

  test("reports a fully audited domain as such", () => {
    const evidence = domainEvidence(
      "data",
      evidenceInput(
        { migration: 8, "data-access": 95 },
        {
          kinds: [
            { kind: "migration", unitsTotal: 8, unitsAudited: 8, skipped: [] },
            { kind: "data-access", unitsTotal: 95, unitsAudited: 95, skipped: [] },
          ],
        },
      ),
    );
    expect(evidence.ratio).toBe(1);
    expect(evidence.statement).toBe(
      "103 of its 103 units were examined: 95 data-access call sites and 8 migrations",
    );
  });

  test("claims nothing at all without an inventory, which is the pre-gate behaviour", () => {
    const evidence = domainEvidence("data", noEvidence());
    expect(evidence.applies).toBe(false);
    expect(evidence.ratio).toBe(0);
  });

  test("is byte-stable: the same input twice produces the same document", () => {
    const once = domainEvidence("appsec", evidenceInput(LARGE_REPO_UNITS));
    const twice = domainEvidence("appsec", evidenceInput(LARGE_REPO_UNITS));
    expect(JSON.stringify(once)).toBe(JSON.stringify(twice));
  });
});

describe("describeAudited", () => {
  test("spells out none rather than printing a second fraction", () => {
    expect(describeAudited({ unitsVerdicted: 0, unitsPresent: 500 })).toBe(
      "none of them were audited",
    );
  });

  test("says all when every unit came back", () => {
    expect(describeAudited({ unitsVerdicted: 8, unitsPresent: 8 })).toBe(
      "all of them were audited",
    );
  });

  test("gives the fraction in between", () => {
    expect(describeAudited({ unitsVerdicted: 1200, unitsPresent: 4000 })).toBe(
      "only 1,200 of 4,000 of them were audited",
    );
  });
});

import { describe, expect, test } from "bun:test";
import type { DomainView, ReportModel } from "./model.ts";
import { overlapNote } from "./section-coverage.ts";

/** A domain row carrying only what {@link overlapNote} reads off it. */
function domain(name: DomainView["domain"], skipped: number): DomainView {
  return {
    domain: name,
    coverage: {
      domain: name,
      unitsTotal: 100,
      unitsAudited: 100 - skipped,
      skipped: Array.from({ length: skipped }, (_unused, index) => ({
        unitId: `${name}-${index}`,
        reason: "inconclusive: the agent declined to decide",
      })),
    },
  } as unknown as DomainView;
}

/** A model carrying only the two things the note is computed from. */
function model(units: ReportModel["auditUnits"], domains: readonly DomainView[] = []): ReportModel {
  return { auditUnits: units, domains } as unknown as ReportModel;
}

describe("overlapNote", () => {
  test("reconciles a per-domain column that counts shared units more than once", () => {
    // Seven domain-slots went without a verdict across two domains, but only
    // five distinct units did: two of them were wanted by both.
    const note = overlapNote(
      model({ total: 1000, audited: 995 }, [domain("appsec", 4), domain("data", 3)]),
    );
    expect(note).toContain("this column sums to 7");
    expect(note).toContain("5 of the run's 1,000 units went unexamined in total");
  });

  test("says nothing when the column already agrees with the run", () => {
    // Volunteering "these two numbers differ" on a run where they do not is how
    // a reader learns to distrust a number that was never wrong.
    expect(overlapNote(model({ total: 1000, audited: 995 }, [domain("appsec", 5)]))).toBeNull();
  });

  test("says nothing when the column is below the run's own figure", () => {
    // A domain that reports fewer un-audited units than the run does is not a
    // contradiction a reader would go looking for.
    expect(overlapNote(model({ total: 1000, audited: 995 }, [domain("appsec", 2)]))).toBeNull();
  });

  test("says nothing when there was no audit to count units for", () => {
    expect(overlapNote(model(null, [domain("appsec", 4)]))).toBeNull();
  });

  test("groups thousands, so the sentence matches the headline it reconciles", () => {
    // The bound statement prints `12,345`; an unseparated `12345` two lines below
    // it reads as a different quantity.
    const note = overlapNote(
      model({ total: 12_345, audited: 10_345 }, [domain("appsec", 1500), domain("data", 1500)]),
    );
    expect(note).toContain("sums to 3,000");
    expect(note).toContain("2,000 of the run's 12,345 units");
  });
});

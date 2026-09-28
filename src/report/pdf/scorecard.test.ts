import { describe, expect, test } from "bun:test";
import { type DomainScore, adaptScorecard } from "./scorecard.ts";
import { COLOR, SEVERITY_COLOR, STRENGTH_COLOR } from "./theme.ts";

/** Phase 6's shape, as the PDF is allowed to assume it. */
function score(overrides: Partial<DomainScore> = {}): DomainScore {
  return {
    domain: "appsec",
    score: 72,
    band: "C",
    status: "scored",
    coverage: 0.94,
    confidence: "medium",
    ...overrides,
  };
}

describe("adaptScorecard", () => {
  test("renders a scored domain as a number, a band and a percentage", () => {
    const view = adaptScorecard([score()]);
    const appsec = view.domains.find((row) => row.domain === "appsec");
    expect(appsec?.score).toBe("72");
    expect(appsec?.band).toBe("C");
    expect(appsec?.bandColor).toBe(SEVERITY_COLOR.medium);
    expect(appsec?.coverage).toBe("94%");
    expect(appsec?.confidence).toBe("medium");
  });

  test("a coverage of 94 means the same as a coverage of 0.94", () => {
    expect(adaptScorecard([score({ coverage: 94 })]).domains[1]?.coverage).toBe("94%");
    expect(adaptScorecard([score({ coverage: 1 })]).domains[1]?.coverage).toBe("100%");
    expect(adaptScorecard([score({ coverage: 250 })]).domains[1]?.coverage).toBe("100%");
  });

  test("a not-assessed domain never acquires a zero", () => {
    const view = adaptScorecard([
      score({ domain: "reliability", status: "not-assessed", score: 0, coverage: null }),
    ]);
    const row = view.domains.find((entry) => entry.domain === "reliability");
    expect(row?.score).toBe("not assessed");
    expect(row?.band).toBe("—");
    expect(row?.coverage).toBe("—");
    expect(row?.bandColor).toBe(COLOR.muted);
  });

  test("a domain that was measured and then refused a score keeps its coverage", () => {
    // Coverage is not a score. `1 of 5 checks ran` is the number that says how
    // thin the evidence was, and it is the reader's only defence against taking
    // an empty findings column for a clean one — a dash here would hide it.
    const view = adaptScorecard([
      score({ domain: "delivery", status: "not-assessed", score: 0, coverage: 0.2 }),
    ]);
    const row = view.domains.find((entry) => entry.domain === "delivery");
    expect(row?.score).toBe("not assessed");
    expect(row?.coverage).toBe("20%");
  });

  test("a domain with no checks to count prints a dash, not 0%", () => {
    const view = adaptScorecard([
      score({ domain: "reliability", status: "not-assessed", score: 0, coverage: null }),
    ]);
    expect(view.domains.find((entry) => entry.domain === "reliability")?.coverage).toBe("—");
  });

  test("every domain of the contract gets a row, in contract order", () => {
    const view = adaptScorecard([score()]);
    expect(view.domains.map((row) => row.domain)).toEqual([
      "dependencies",
      "appsec",
      "data",
      "delivery",
      "serverless",
      "api",
      "reliability",
      "deadcode",
    ]);
    expect(view.domains.filter((row) => row.status === "not-assessed")).toHaveLength(7);
  });

  test("uses phase 6's own overall verdict when it publishes one", () => {
    const view = adaptScorecard({
      domains: [score({ score: 40, band: "F" })],
      overall: { score: 58, band: "F", confidence: "low" },
    });
    expect(view.overall).toEqual({
      score: "58",
      band: "F",
      color: SEVERITY_COLOR.critical,
      confidence: "low",
      derived: false,
    });
  });

  test("averages the scored domains when there is no overall, and admits it", () => {
    const view = adaptScorecard([
      score({ domain: "appsec", score: 70 }),
      score({ domain: "data", score: 90, band: "A" }),
      score({ domain: "reliability", status: "not-assessed", score: 0 }),
    ]);
    expect(view.overall.score).toBe("80");
    expect(view.overall.band).toBe("B");
    expect(view.overall.color).toBe(STRENGTH_COLOR);
    expect(view.overall.derived).toBe(true);
  });

  test("no scorecard at all reads as not assessed, not as a perfect score", () => {
    const view = adaptScorecard(undefined);
    expect(view.present).toBe(false);
    expect(view.overall.score).toBe("not assessed");
    expect(view.overall.band).toBe("—");
    expect(view.overall.derived).toBe(false);
    expect(view.domains.every((row) => row.status === "not-assessed")).toBe(true);
  });

  test("carries every ceiling through, because that is what caps the headline", () => {
    const view = adaptScorecard([
      score({ domain: "appsec", ceilingReason: "unrotated secret in git history" }),
      score({ domain: "data", ceilingReason: "   " }),
    ]);
    expect(view.ceilings).toEqual([
      { domain: "appsec", reason: "unrotated secret in git history" },
    ]);
    expect(view.domains.find((row) => row.domain === "appsec")?.ceilingReason).toBe(
      "unrotated secret in git history",
    );
  });

  test("a numeric confidence is shown as a percentage", () => {
    expect(adaptScorecard([score({ confidence: 0.82 })]).domains[1]?.confidence).toBe("82%");
    expect(adaptScorecard([score({ confidence: "" })]).domains[1]?.confidence).toBe("—");
  });
});

describe("adaptScorecard, on phase 6's evidence note", () => {
  const NOTE =
    "not assessed: 4,000 data-access call sites and 500 migrations exist and none of them were " +
    "audited in this run, so nothing examined this domain's evidence; 1 of 1 check ran, and a " +
    "check that ran is not a unit that was looked at";

  test("carries the note through, so the report can print the reason that is true", () => {
    const view = adaptScorecard([
      score({ domain: "data", status: "not-assessed", coverage: 0, evidenceNote: NOTE }),
    ]);
    expect(view.domains.find((row) => row.domain === "data")?.evidenceNote).toBe(NOTE);
  });

  test("still refuses the number itself", () => {
    const view = adaptScorecard([
      score({ domain: "data", status: "not-assessed", coverage: 0, evidenceNote: NOTE }),
    ]);
    const data = view.domains.find((row) => row.domain === "data");
    expect(data?.score).toBe("not assessed");
    expect(data?.band).toBe("—");
    expect(data?.coverage).toBe("0%");
  });

  test("omits the field entirely when phase 6 gave none, or gave whitespace", () => {
    expect(adaptScorecard([score()]).domains[1]?.evidenceNote).toBeUndefined();
    expect(
      adaptScorecard([score({ evidenceNote: "  " })]).domains[1]?.evidenceNote,
    ).toBeUndefined();
  });
});

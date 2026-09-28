import { describe, expect, test } from "bun:test";
import { SeveritySchema } from "../contracts/findings.ts";
import { finding, findings } from "./__fixtures__/factories.ts";
import {
  LOW_CONFIDENCE_WEIGHT,
  SEVERITY_POLICY,
  baseScoreFrom,
  computeDeductions,
  countBySeverity,
  emptySeverityCounts,
  totalDeduction,
} from "./deductions.ts";

describe("the severity policy", () => {
  test("prices every severity the contract declares", () => {
    expect(Object.keys(SEVERITY_POLICY).sort()).toEqual([...SeveritySchema.options].sort());
  });

  test("prices a worse severity higher than a lesser one, per finding and per tier", () => {
    const tiers = SeveritySchema.options.map((severity) => SEVERITY_POLICY[severity]);
    for (let index = 1; index < tiers.length; index += 1) {
      const worse = tiers[index - 1];
      const lesser = tiers[index];
      expect(worse?.perFinding).toBeGreaterThan(lesser?.perFinding ?? 0);
      expect(worse?.cap).toBeGreaterThan(lesser?.cap ?? 0);
    }
  });
});

describe("computeDeductions", () => {
  test("rows only the severities that are actually present, worst first", () => {
    const rows = computeDeductions([
      finding({ severity: "low", id: "a" }),
      finding({ severity: "critical", id: "b" }),
    ]);
    expect(rows.map((row) => row.severity)).toEqual(["critical", "low"]);
  });

  test("caps a tier and says it capped it", () => {
    const rows = computeDeductions(findings(100, { severity: "info" }));
    const info = rows[0];
    expect(info?.count).toBe(100);
    expect(info?.raw).toBe(50);
    expect(info?.applied).toBe(SEVERITY_POLICY.info.cap);
    expect(info?.capped).toBe(true);
  });

  test("counts a low-confidence finding at half weight and reports how many", () => {
    const rows = computeDeductions([
      finding({ severity: "high", id: "a" }),
      finding({ severity: "high", id: "b", confidence: "low" }),
    ]);
    const high = rows[0];
    expect(high?.discounted).toBe(1);
    expect(high?.raw).toBe(SEVERITY_POLICY.high.perFinding * (1 + LOW_CONFIDENCE_WEIGHT));
  });
});

describe("the rule that volume cannot outvote severity", () => {
  test("a hundred info findings leave a domain healthier than one critical", () => {
    const noise = baseScoreFrom(computeDeductions(findings(100, { severity: "info" })));
    const real = baseScoreFrom(computeDeductions([finding({ severity: "critical" })]));
    expect(noise).toBeGreaterThan(real);
    expect(noise).toBe(95);
    expect(real).toBe(75);
  });

  test("the whole low tier put together still costs less than one critical", () => {
    const lows = baseScoreFrom(computeDeductions(findings(50, { severity: "low" })));
    const critical = baseScoreFrom(computeDeductions([finding({ severity: "critical" })]));
    expect(lows).toBeGreaterThan(critical);
  });
});

describe("totals", () => {
  test("a clean domain deducts nothing and scores 100", () => {
    expect(computeDeductions([])).toEqual([]);
    expect(totalDeduction([])).toBe(0);
    expect(baseScoreFrom([])).toBe(100);
  });

  test("every tier at its cap floors the domain at zero rather than below it", () => {
    const everything = SeveritySchema.options.flatMap((severity) =>
      findings(40, { severity, id: severity }),
    );
    expect(totalDeduction(computeDeductions(everything))).toBe(100);
    expect(baseScoreFrom(computeDeductions(everything))).toBe(0);
  });
});

describe("countBySeverity", () => {
  test("names every severity, including the ones with nothing in them", () => {
    expect(countBySeverity([])).toEqual(emptySeverityCounts());
    expect(countBySeverity([finding({ severity: "high" })]).high).toBe(1);
  });
});

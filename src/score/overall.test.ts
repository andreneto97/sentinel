import { describe, expect, test } from "bun:test";
import { DomainSchema } from "../contracts/findings.ts";
import { domainScore } from "./__fixtures__/factories.ts";
import { DOMAIN_WEIGHTS, WORST_DOMAIN_HEADROOM, buildOverall, effectiveWeight } from "./overall.ts";

describe("the weights", () => {
  test("name every domain and sum to 100", () => {
    expect(Object.keys(DOMAIN_WEIGHTS).sort()).toEqual([...DomainSchema.options].sort());
    const total = Object.values(DOMAIN_WEIGHTS).reduce((sum, weight) => sum + weight, 0);
    expect(total).toBe(100);
  });

  test("rank application security above dead code, by a wide margin", () => {
    expect(DOMAIN_WEIGHTS.appsec).toBeGreaterThan(DOMAIN_WEIGHTS.data);
    expect(DOMAIN_WEIGHTS.data).toBeGreaterThan(DOMAIN_WEIGHTS.deadcode * 5);
  });

  test("scale a domain's weight by the fraction of its checks that ran", () => {
    expect(effectiveWeight("appsec", 1)).toBe(DOMAIN_WEIGHTS.appsec);
    expect(effectiveWeight("appsec", 0.5)).toBe(DOMAIN_WEIGHTS.appsec / 2);
    expect(effectiveWeight("appsec", 0)).toBe(0);
  });
});

describe("buildOverall", () => {
  test("weights the mean, so a heavy domain moves it more than a light one", () => {
    const overall = buildOverall([
      domainScore({ domain: "appsec", score: 60 }),
      domainScore({ domain: "deadcode", score: 100 }),
    ]);
    // (60*30 + 100*2) / 32
    expect(overall.weightedMean).toBe(62.5);
    expect(overall.score).toBe(63);
    expect(overall.band).toBe("C");
  });

  test("clamps to the worst scored domain plus the headroom, so one F is not averaged away", () => {
    const overall = buildOverall([
      domainScore({ domain: "appsec", score: 85 }),
      domainScore({ domain: "data", score: 85 }),
      domainScore({ domain: "dependencies", score: 85 }),
      domainScore({ domain: "api", score: 85 }),
      domainScore({ domain: "delivery", score: 30 }),
    ]);
    expect(overall.weightedMean).toBeGreaterThan(75);
    expect(overall.score).toBe(30 + WORST_DOMAIN_HEADROOM);
    expect(overall.band).toBe("D");
    expect(overall.clamp?.applied).toBe(true);
    expect(overall.clamp?.worstDomain).toBe("delivery");
    expect(overall.clamp?.reason).toContain("weakest scored domain at 30");
  });

  test("records the clamp even when it does not bite, so the rule is visible", () => {
    const overall = buildOverall([domainScore({ domain: "appsec", score: 80 })]);
    expect(overall.score).toBe(80);
    expect(overall.clamp?.applied).toBe(false);
    expect(overall.clamp?.reason).toContain("did not bite");
  });

  test("lets a thinly covered domain carry less of the mean", () => {
    const full = buildOverall([
      domainScore({ domain: "appsec", score: 40 }),
      domainScore({ domain: "dependencies", score: 100 }),
    ]);
    const thin = buildOverall([
      domainScore({ domain: "appsec", score: 40, coverageRatio: 0.6, status: "partial" }),
      domainScore({ domain: "dependencies", score: 100 }),
    ]);
    expect(thin.weightedMean ?? 0).toBeGreaterThan(full.weightedMean ?? 0);
    expect(thin.contributions[0]?.effectiveWeight).toBeLessThan(DOMAIN_WEIGHTS.appsec);
  });

  test("excludes an unscored domain from the mean and lists it with its reason", () => {
    const overall = buildOverall([
      domainScore({ domain: "appsec", score: 80 }),
      domainScore({
        domain: "delivery",
        score: null,
        statement: "not assessed: only 1 of 5 checks ran (20%)",
        findingsTotal: 2,
      }),
    ]);
    expect(overall.contributions.map((row) => row.domain)).toEqual(["appsec"]);
    expect(overall.unscored).toEqual([
      {
        domain: "delivery",
        reason: "not assessed: only 1 of 5 checks ran (20%)",
        findingsTotal: 2,
      },
    ]);
    expect(overall.score).toBe(80);
    expect(overall.status).toBe("partial");
    expect(overall.statement).toContain("1 not assessed and excluded from the mean: delivery");
  });

  test("is scored only when every domain in the table earned a full number", () => {
    const clean = buildOverall([
      domainScore({ domain: "appsec", score: 80 }),
      domainScore({ domain: "data", score: 90 }),
    ]);
    expect(clean.status).toBe("scored");

    const thin = buildOverall([
      domainScore({ domain: "appsec", score: 80 }),
      domainScore({ domain: "data", score: 90, coverageRatio: 0.6, status: "partial" }),
    ]);
    expect(thin.status).toBe("partial");
  });

  test("refuses a number when no domain earned one", () => {
    const overall = buildOverall([
      domainScore({ domain: "appsec", score: null }),
      domainScore({ domain: "data", score: null }),
    ]);
    expect(overall.status).toBe("not-assessed");
    expect(overall.score).toBeNull();
    expect(overall.band).toBeNull();
    expect(overall.weightedMean).toBeNull();
    expect(overall.clamp).toBeNull();
    expect(overall.statement).toContain("no domain had enough coverage");
  });

  test("breaks a tie for the weakest domain in the contract's order", () => {
    const overall = buildOverall([
      domainScore({ domain: "data", score: 40 }),
      domainScore({ domain: "appsec", score: 40 }),
    ]);
    expect(overall.clamp?.worstDomain).toBe("appsec");
  });

  test("never lets the clamp raise the number above 100", () => {
    const overall = buildOverall([domainScore({ domain: "appsec", score: 100 })]);
    expect(overall.clamp?.limit).toBe(100);
    expect(overall.score).toBe(100);
  });
});

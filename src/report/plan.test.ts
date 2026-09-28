import { describe, expect, test } from "bun:test";
import type { Finding } from "../contracts/findings.ts";
import {
  PLAN_PRIORITIES,
  buildPlan,
  classifyPriority,
  comparePlanOrder,
  planHeadline,
  priorityReason,
  worstPriority,
  worstSeverity,
} from "./plan.ts";

function finding(overrides: Partial<Finding> & Pick<Finding, "id">): Finding {
  return {
    domain: "appsec",
    rule: "appsec.missing-rate-limit",
    severity: "medium",
    confidence: "high",
    title: "A title",
    description: "A description.",
    location: { file: "src/a.ts", line: 10 },
    evidence: [],
    impact: "An impact.",
    recommendation: "A fix.",
    acceptanceCriteria: ["It is fixed."],
    cwe: [],
    owasp: [],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  };
}

describe("classifyPriority", () => {
  test("critical is always P1", () => {
    expect(classifyPriority(finding({ id: "a", severity: "critical", domain: "deadcode" }))).toBe(
      "P1",
    );
  });

  test("high is P1 on a surface something outside the process calls", () => {
    for (const domain of ["appsec", "api", "serverless"] as const) {
      expect(classifyPriority(finding({ id: "a", severity: "high", domain }))).toBe("P1");
    }
  });

  test("high is P2 where reaching it needs a precondition", () => {
    for (const domain of ["data", "dependencies", "delivery", "deadcode"] as const) {
      expect(classifyPriority(finding({ id: "a", severity: "high", domain }))).toBe("P2");
    }
  });

  test("medium is P2, low and info are P3", () => {
    expect(classifyPriority(finding({ id: "a", severity: "medium" }))).toBe("P2");
    expect(classifyPriority(finding({ id: "a", severity: "low" }))).toBe("P3");
    expect(classifyPriority(finding({ id: "a", severity: "info" }))).toBe("P3");
  });

  test("a data-loss rule is P1 whatever severity it carries", () => {
    const dropped = finding({
      id: "a",
      domain: "data",
      rule: "data.destructive-migration",
      severity: "info",
    });
    expect(classifyPriority(dropped)).toBe("P1");
    expect(priorityReason(dropped)).toContain("data.destructive-migration");
    expect(priorityReason(dropped)).toContain("destroys or corrupts stored data");
  });

  test("the reason names the surface for an externally reachable high", () => {
    expect(priorityReason(finding({ id: "a", severity: "high", domain: "serverless" }))).toContain(
      "serverless surface",
    );
  });
});

describe("comparePlanOrder", () => {
  const lossy = finding({
    id: "zzz",
    domain: "data",
    rule: "data.destructive-migration",
    severity: "info",
  });
  const medium = finding({ id: "aaa", severity: "medium" });
  const low = finding({ id: "bbb", severity: "low" });

  test("priority dominates severity", () => {
    expect(comparePlanOrder(lossy, medium)).toBeLessThan(0);
  });

  test("severity then confidence order within a bucket", () => {
    const sure = finding({ id: "a", severity: "low", confidence: "high" });
    const unsure = finding({ id: "b", severity: "low", confidence: "low" });
    expect(comparePlanOrder(sure, unsure)).toBeLessThan(0);
    expect(comparePlanOrder(medium, low)).toBeLessThan(0);
  });

  test("the id breaks the last tie, so the order is total", () => {
    const left = finding({ id: "aaa" });
    const right = finding({ id: "bbb" });
    expect(comparePlanOrder(left, right)).toBeLessThan(0);
    expect(comparePlanOrder(left, left)).toBe(0);
  });

  test("the order does not depend on the order it was given in", () => {
    const findings = [lossy, medium, low, finding({ id: "ccc", severity: "critical" })];
    const forward = [...findings].sort(comparePlanOrder).map((entry) => entry.id);
    const backward = [...findings]
      .reverse()
      .sort(comparePlanOrder)
      .map((entry) => entry.id);
    expect(backward).toEqual(forward);
  });
});

describe("buildPlan", () => {
  const findings = [
    finding({ id: "crit", severity: "critical" }),
    finding({ id: "med", severity: "medium" }),
    finding({ id: "info", severity: "info", domain: "deadcode", rule: "deadcode.unused-export" }),
  ];

  test("ranks every item once, across buckets", () => {
    const plan = buildPlan(findings);
    expect(plan.items.map((item) => item.rank)).toEqual([1, 2, 3]);
    expect(plan.items.map((item) => item.finding.id)).toEqual(["crit", "med", "info"]);
    expect(plan.counts).toEqual({ P1: 1, P2: 1, P3: 1 });
  });

  test("all three sections exist even when a bucket is empty", () => {
    const plan = buildPlan([finding({ id: "only", severity: "low" })]);
    expect(plan.sections.map((section) => section.priority)).toEqual([...PLAN_PRIORITIES]);
    expect(plan.sections[0]?.items).toEqual([]);
    expect(plan.sections[2]?.items).toHaveLength(1);
  });

  test("every item carries the reason for its bucket", () => {
    for (const item of buildPlan(findings).items) {
      expect(item.reason).toBe(priorityReason(item.finding));
      expect(item.reason.length).toBeGreaterThan(0);
    }
  });
});

describe("planHeadline", () => {
  test("an empty P1 is stated as a result, not left out", () => {
    const headline = planHeadline(buildPlan([finding({ id: "a", severity: "medium" })]));
    expect(headline).toContain("Nothing in this run is exploitable");
    expect(headline).toContain("1 should not ship");
  });

  test("a populated P1 counts it", () => {
    expect(planHeadline(buildPlan([finding({ id: "a", severity: "critical" })]))).toContain(
      "1 finding is exploitable now",
    );
  });

  test("no findings says so", () => {
    expect(planHeadline(buildPlan([]))).toBe("No findings, so there is nothing to prioritise.");
  });
});

describe("worst helpers", () => {
  test("pick the more urgent of two", () => {
    expect(worstSeverity("low", "critical")).toBe("critical");
    expect(worstSeverity("medium", "info")).toBe("medium");
    expect(worstPriority("P3", "P1")).toBe("P1");
    expect(worstPriority("P2", "P3")).toBe("P2");
  });
});

import { describe, expect, test } from "bun:test";
import {
  AgentCheckOutcomeSchema,
  AgentVerdictReportSchema,
  CHECK_RESULTS,
  CheckResultSchema,
} from "./verdict.ts";

/** The smallest finding the schema accepts, for tests that vary one field. */
function finding(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rule: "appsec.idor",
    title: "order loaded by id alone",
    description: "the id comes from the path and the query has no ownership predicate",
    severity: "high",
    location: { file: "src/api/orders.ts", line: 58 },
    impact: "any signed-in caller can delete any order",
    recommendation: "add the session's organisation to the predicate",
    ...overrides,
  };
}

describe("CheckResultSchema", () => {
  test("has exactly the three answers a check may carry", () => {
    expect(CHECK_RESULTS).toEqual(["pass", "fail", "not-applicable"]);
    expect(CheckResultSchema.safeParse("clean").success).toBe(false);
  });
});

describe("AgentCheckOutcomeSchema", () => {
  test("accepts the bare answer a model usually writes", () => {
    expect(AgentCheckOutcomeSchema.parse("pass")).toBe("pass");
  });

  test("accepts the object form, with the pointer that proves a pass", () => {
    const parsed = AgentCheckOutcomeSchema.parse({
      result: "pass",
      evidence: { file: "a.ts", line: 4, note: "scoped here" },
      note: "the predicate is applied by the helper",
    });
    expect(parsed).toEqual({
      result: "pass",
      evidence: { file: "a.ts", line: 4, note: "scoped here" },
      note: "the predicate is applied by the helper",
    });
  });

  test("refuses an answer that is neither form", () => {
    expect(AgentCheckOutcomeSchema.safeParse({ result: "maybe" }).success).toBe(false);
    expect(AgentCheckOutcomeSchema.safeParse(true).success).toBe(false);
  });
});

describe("AgentVerdictReportSchema", () => {
  test("defaults every list and the confidence a model may omit", () => {
    const parsed = AgentVerdictReportSchema.parse({
      verdicts: [{ unitId: "u1", checks: { "appsec.idor": "fail" }, findings: [finding()] }],
    });
    const first = parsed.verdicts[0]?.findings[0];
    expect(first?.confidence).toBe("medium");
    expect(first?.evidence).toEqual([]);
    expect(first?.acceptanceCriteria).toEqual([]);
    expect(first?.cwe).toEqual([]);
    expect(first?.owasp).toEqual([]);
    expect(parsed.verdicts[0]?.findings).toHaveLength(1);
  });

  test("a verdict with no findings is valid: the clean answer is the common one", () => {
    const parsed = AgentVerdictReportSchema.parse({
      verdicts: [{ unitId: "u1", checks: { "appsec.idor": "pass" } }],
    });
    expect(parsed.verdicts[0]?.findings).toEqual([]);
    expect(parsed.verdicts[0]?.notes).toBeUndefined();
  });

  test("refuses an empty unit id, so a verdict can always be attributed", () => {
    expect(
      AgentVerdictReportSchema.safeParse({ verdicts: [{ unitId: "", checks: {} }] }).success,
    ).toBe(false);
  });

  test("refuses a citation with no usable line", () => {
    for (const line of [0, -1, 1.5]) {
      const result = AgentVerdictReportSchema.safeParse({
        verdicts: [
          {
            unitId: "u1",
            checks: {},
            findings: [finding({ location: { file: "a.ts", line } })],
          },
        ],
      });
      expect(result.success).toBe(false);
    }
  });

  test("refuses a severity outside the rubric and a finding with no impact", () => {
    expect(
      AgentVerdictReportSchema.safeParse({
        verdicts: [{ unitId: "u1", checks: {}, findings: [finding({ severity: "urgent" })] }],
      }).success,
    ).toBe(false);
    expect(
      AgentVerdictReportSchema.safeParse({
        verdicts: [{ unitId: "u1", checks: {}, findings: [finding({ impact: "" })] }],
      }).success,
    ).toBe(false);
  });

  test("has nowhere to put a snippet, because snippets are read from disk", () => {
    const parsed = AgentVerdictReportSchema.parse({
      verdicts: [
        {
          unitId: "u1",
          checks: {},
          findings: [finding({ location: { file: "a.ts", line: 1, snippet: "await db.query()" } })],
        },
      ],
    });
    expect(parsed.verdicts[0]?.findings[0]?.location).toEqual({ file: "a.ts", line: 1 });
  });

  test("keeps the echoed batch id when there is one", () => {
    expect(AgentVerdictReportSchema.parse({ batchId: "route-abc", verdicts: [] }).batchId).toBe(
      "route-abc",
    );
    expect(AgentVerdictReportSchema.parse({ verdicts: [] }).batchId).toBeUndefined();
  });
});

import { describe, expect, test } from "bun:test";
import {
  TRIAGED_FINDINGS_FILE,
  TRIAGE_VERDICTS,
  TriageDocumentSchema,
  resolveSeverity,
} from "./triage.ts";

/** One verdict, with the fields a real triage file carries. */
function entry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "f934d9efac08df15",
    rule: "appsec.sql-injection",
    file: "libs/fleet-core/reports/ridership-report.service.ts",
    line: 68,
    reportedSeverity: "critical",
    verdict: "true",
    note: "Checked against the code: the interpolated value is not validated anywhere.",
    ...overrides,
  };
}

/** A document around a list of verdicts. */
function document(verdicts: readonly Record<string, unknown>[]): Record<string, unknown> {
  return {
    schemaVersion: "1.0",
    reviewer: "manual verification, 2026-09-23 (three reviewers, one slice each)",
    verdicts,
  };
}

describe("TriageDocumentSchema", () => {
  test("accepts a reviewer and one verdict per finding", () => {
    const parsed = TriageDocumentSchema.parse(
      document([
        entry(),
        entry({ id: "b", verdict: "false", note: "already validated at the route boundary" }),
        entry({ id: "c", verdict: "overstated", severity: "low", note: "real, but bounded" }),
        entry({ id: "d", verdict: "unclear", note: "needs the ingress config to decide" }),
      ]),
    );
    expect(parsed.reviewer).toContain("manual verification");
    expect(parsed.verdicts.map((verdict) => verdict.verdict)).toEqual([
      "true",
      "false",
      "overstated",
      "unclear",
    ]);
  });

  test("the four verdicts are the four a reviewer can reach", () => {
    expect(TRIAGE_VERDICTS).toEqual(["true", "false", "overstated", "unclear"]);
  });

  test("refuses two verdicts for the same finding, naming the earlier one", () => {
    const result = TriageDocumentSchema.safeParse(
      document([entry(), entry({ verdict: "false", note: "no, it does not hold" })]),
    );
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain("already has a verdict at verdicts[0]");
    expect(result.error?.issues[0]?.path).toEqual(["verdicts", 1, "id"]);
  });

  test("refuses an overstated verdict that names no corrected severity", () => {
    const result = TriageDocumentSchema.safeParse(
      document([entry({ verdict: "overstated", note: "too high" })]),
    );
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain("must name the corrected severity");
  });

  test("refuses a verdict with no reason, which is what a silent deletion looks like", () => {
    const result = TriageDocumentSchema.safeParse(
      document([entry({ verdict: "false", note: "" })]),
    );
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(["verdicts", 0, "note"]);
  });

  test("refuses a verdict word nobody defined", () => {
    const result = TriageDocumentSchema.safeParse(document([entry({ verdict: "probably" })]));
    expect(result.success).toBe(false);
  });

  test("refuses a document with no verdicts at all", () => {
    expect(TriageDocumentSchema.safeParse(document([])).success).toBe(false);
  });

  test("the adjusted document is written beside findings.json, not over it", () => {
    expect(TRIAGED_FINDINGS_FILE).toBe("findings.triaged.json");
  });
});

describe("resolveSeverity", () => {
  test("reads a bare severity", () => {
    expect(resolveSeverity("low")).toBe("low");
    expect(resolveSeverity("Critical")).toBe("critical");
  });

  test("reads the long form of info, which is what reviewers write", () => {
    expect(resolveSeverity("informational")).toBe("info");
    expect(resolveSeverity("info")).toBe("info");
  });

  test("reads a severity out of the sentence a reviewer actually writes", () => {
    // A reviewer answers in prose, and both shapes below are ordinary: a verb
    // before the severity, and a parenthesis that carries its own colon.
    // Refusing them would push the reviewer into editing findings.json by hand.
    expect(
      resolveSeverity("drop (or low, as a note that the seed script pins one station id)"),
    ).toBe("low");
    expect(resolveSeverity("medium (the description miscounts: 3 docks, not 9)")).toBe("medium");
  });

  test("names none when the text names none", () => {
    expect(resolveSeverity("drop")).toBeUndefined();
    expect(resolveSeverity(undefined)).toBeUndefined();
  });

  test("a severity inside another word is not a severity", () => {
    expect(resolveSeverity("lowercase the title")).toBeUndefined();
  });

  test("an accepted overstated verdict keeps the reviewer's prose in the note", () => {
    const parsed = TriageDocumentSchema.parse(
      document([
        entry({
          verdict: "overstated",
          severity: "drop (or low, as a note that the seed script pins one station id)",
          note: "Checked the migration: the column is NULL on every row when the UPDATE runs.",
        }),
      ]),
    );
    const verdict = parsed.verdicts[0];
    expect(resolveSeverity(verdict?.severity)).toBe("low");
    expect(verdict?.note).toContain("NULL on every row");
  });
});

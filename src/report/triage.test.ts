import { describe, expect, test } from "bun:test";
import type { Finding, FindingsDocument } from "../contracts/findings.ts";
import type { TriageDocument } from "../contracts/triage.ts";
import { TriageDocumentSchema } from "../contracts/triage.ts";
import {
  StaleTriageError,
  applyTriage,
  reviewIndex,
  reviewLabel,
  unreviewedStatement,
} from "./triage.ts";

function finding(overrides: Partial<Finding> & Pick<Finding, "id">): Finding {
  return {
    domain: "appsec",
    rule: "appsec.missing-tenant-scope",
    severity: "critical",
    confidence: "high",
    title: `Finding ${overrides.id}`,
    description: "A list query is not constrained by the authenticated principal.",
    location: { file: "src/api/memberships/list.ts", line: 31 },
    evidence: [],
    impact: "Every tenant's memberships are returned.",
    recommendation: "Constrain the query by the caller's organisation.",
    acceptanceCriteria: [],
    cwe: [],
    owasp: [],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  };
}

/** Five findings: four reviewed one way each, one nobody looked at. */
function document(): FindingsDocument {
  return {
    schemaVersion: "1.0",
    runId: "20260923T193048-83a72dc5",
    target: "/repo",
    findings: [
      finding({ id: "holds" }),
      finding({
        id: "sqli",
        rule: "appsec.sql-injection",
        location: { file: "libs/reports/purchase-report-service.ts", line: 68 },
      }),
      finding({
        id: "stream",
        domain: "api",
        rule: "api.response-leaks-fields",
        severity: "high",
        location: { file: "src/api/inventories/stream.ts", line: 133 },
      }),
      finding({
        id: "cron",
        domain: "data",
        rule: "data.destructive-migration",
        severity: "high",
        location: { file: "migrations/1703186603022-AddNotNull.ts", line: 8 },
      }),
      finding({
        id: "untouched",
        domain: "data",
        rule: "data.select-star",
        severity: "low",
        location: { file: "src/db/holds.ts", line: 39 },
      }),
    ],
    assurances: [],
    coverage: [
      { domain: "appsec", unitsTotal: 10, unitsAudited: 10, skipped: [] },
      { domain: "data", unitsTotal: 4, unitsAudited: 4, skipped: [] },
    ],
    droppedFindings: 0,
  };
}

/** The four verdicts over the document above, validated like a real file. */
function triage(overrides: readonly Record<string, unknown>[] = []): TriageDocument {
  return TriageDocumentSchema.parse({
    schemaVersion: "1.0",
    reviewer: "manual verification, 2026-03-04",
    verdicts: [
      {
        id: "holds",
        rule: "appsec.missing-tenant-scope",
        file: "src/api/memberships/list.ts",
        line: 31,
        reportedSeverity: "critical",
        verdict: "true",
        note: "Confirmed cross-tenant read, reachable by any authenticated caller.",
      },
      {
        id: "sqli",
        rule: "appsec.sql-injection",
        file: "libs/reports/purchase-report-service.ts",
        line: 68,
        reportedSeverity: "critical",
        verdict: "false",
        severity: "informational",
        note: "groupedBy is a three-value zod enum at the route boundary; not injectable.",
      },
      {
        id: "stream",
        rule: "api.response-leaks-fields",
        file: "src/api/inventories/stream.ts",
        line: 133,
        reportedSeverity: "high",
        verdict: "overstated",
        severity: "low",
        note: "The gap is real but the audience is admin impersonation sessions only.",
      },
      {
        id: "cron",
        rule: "data.destructive-migration",
        file: "migrations/1703186603022-AddNotNull.ts",
        line: 8,
        reportedSeverity: "high",
        verdict: "unclear",
        note: "Needs the deploy history of the environment to decide.",
      },
      ...overrides,
    ],
  });
}

describe("applyTriage", () => {
  const original = document();
  const { document: adjusted, summary } = applyTriage(original, triage());

  test("a false finding leaves the findings list", () => {
    expect(adjusted.findings.map((entry) => entry.id)).toEqual([
      "holds",
      "stream",
      "cron",
      "untouched",
    ]);
    expect(adjusted.findings.some((entry) => entry.id === "sqli")).toBe(false);
  });

  test("and is recorded with its rule, location, reported severity and the reason", () => {
    expect(summary.withheld).toHaveLength(1);
    const withheld = summary.withheld[0];
    expect(withheld?.id).toBe("sqli");
    expect(withheld?.rule).toBe("appsec.sql-injection");
    expect(withheld?.file).toBe("libs/reports/purchase-report-service.ts");
    expect(withheld?.line).toBe(68);
    expect(withheld?.reportedSeverity).toBe("critical");
    expect(withheld?.note).toContain("three-value zod enum");
  });

  test("the counts reconcile: before, after and withheld are one arithmetic", () => {
    expect(summary.findingsBefore).toBe(5);
    expect(summary.findingsAfter).toBe(4);
    expect(summary.findingsBefore - summary.withheld.length).toBe(summary.findingsAfter);
    expect(adjusted.findings).toHaveLength(summary.findingsAfter);
    expect(summary.reviewed).toBe(4);
    expect(summary.unreviewed).toBe(1);
    expect(
      summary.confirmed.length +
        summary.corrected.length +
        summary.contested.length +
        summary.unreviewed,
    ).toBe(summary.findingsAfter);
  });

  test("an overstated finding carries the corrected severity, and both are kept", () => {
    const stream = adjusted.findings.find((entry) => entry.id === "stream");
    expect(stream?.severity).toBe("low");
    const corrected = summary.corrected[0];
    expect(corrected?.reportedSeverity).toBe("high");
    expect(corrected?.severity).toBe("low");
  });

  test("a true finding is unchanged and marked confirmed", () => {
    const holds = adjusted.findings.find((entry) => entry.id === "holds");
    expect(holds?.severity).toBe("critical");
    expect(summary.confirmed.map((entry) => entry.id)).toEqual(["holds"]);
    expect(summary.confirmed[0]?.note).toContain("Confirmed cross-tenant read");
  });

  test("an unclear finding keeps its reported severity and is contested", () => {
    const cron = adjusted.findings.find((entry) => entry.id === "cron");
    expect(cron?.severity).toBe("high");
    expect(summary.contested.map((entry) => entry.id)).toEqual(["cron"]);
  });

  test("a finding nobody reviewed is untouched and carries no verdict", () => {
    expect(adjusted.findings.find((entry) => entry.id === "untouched")?.severity).toBe("low");
    expect(reviewIndex(summary).has("untouched")).toBe(false);
  });

  test("the input document is not mutated: the raw run stays auditable", () => {
    expect(original.findings).toHaveLength(5);
    expect(original.findings.find((entry) => entry.id === "stream")?.severity).toBe("high");
  });

  test("everything else about the document survives untouched", () => {
    expect(adjusted.coverage).toEqual(original.coverage);
    expect(adjusted.droppedFindings).toBe(0);
    expect(adjusted.runId).toBe(original.runId);
  });

  test("the statement says how far the review reached, and who did it", () => {
    expect(summary.statement).toContain("4 of 5 findings");
    expect(summary.statement).toContain("manual verification, 2026-03-04");
    expect(summary.statement).toContain("1 confirmed, 1 corrected, 1 withheld, 1 contested");
  });

  test("and the second sentence is the one about what was not reviewed", () => {
    expect(summary.unreviewedStatement).toContain("1 finding");
    expect(summary.unreviewedStatement).toContain("no human review");
  });

  test("the per-domain rows cover only the domains the review touched", () => {
    // Contract order, which is the order every table in the report uses.
    expect(summary.domains.map((row) => row.domain)).toEqual(["appsec", "data", "api"]);
    const appsec = summary.domains[0];
    expect(appsec?.reviewed).toBe(2);
    expect(appsec?.confirmed).toBe(1);
    expect(appsec?.withheld).toBe(1);
    expect(appsec?.findingsBefore).toBe(2);
    expect(appsec?.findingsAfter).toBe(1);
    expect(appsec?.severityBefore.critical).toBe(2);
    expect(appsec?.severityAfter.critical).toBe(1);
  });

  test("the api row shows the severity moving rather than the finding leaving", () => {
    const api = summary.domains.find((row) => row.domain === "api");
    expect(api?.findingsBefore).toBe(1);
    expect(api?.findingsAfter).toBe(1);
    expect(api?.severityBefore).toMatchObject({ high: 1, low: 0 });
    expect(api?.severityAfter).toMatchObject({ high: 0, low: 1 });
  });

  test("with no scorer, no score is invented", () => {
    expect(summary.domains[0]?.scoreBefore).toBeUndefined();
    expect(summary.domains[0]?.scoreAfter).toBeUndefined();
  });
});

describe("the scores a review moves", () => {
  test("the before and after numbers come from the caller's own scorer", () => {
    const { summary } = applyTriage(document(), triage(), {
      // Stands in for phase 6: a number that falls with every critical, so the
      // test asserts the wiring rather than the scoring policy.
      score: (source) =>
        ["appsec", "api", "data"].map((domain) => ({
          domain: domain as "appsec",
          score:
            100 -
            10 *
              source.findings.filter(
                (entry) => entry.domain === domain && entry.severity === "critical",
              ).length,
        })),
    });
    const appsec = summary.domains.find((row) => row.domain === "appsec");
    expect(appsec?.scoreBefore).toBe(80);
    expect(appsec?.scoreAfter).toBe(90);
  });

  test("a domain phase 6 refused to score reads as null, never as a zero", () => {
    const { summary } = applyTriage(document(), triage(), {
      score: () => [{ domain: "appsec", score: null }],
    });
    expect(summary.domains.find((row) => row.domain === "appsec")?.scoreAfter).toBeNull();
    // A domain the scorer said nothing about is unknown too, not zero.
    expect(summary.domains.find((row) => row.domain === "data")?.scoreAfter).toBeNull();
  });
});

describe("a triage that is not about this run", () => {
  test("a verdict for an unknown finding is refused, by id", () => {
    const stale = triage([
      {
        id: "gone",
        rule: "appsec.idor",
        file: "src/api/old.ts",
        line: 4,
        reportedSeverity: "high",
        verdict: "false",
        note: "not reachable",
      },
    ]);
    expect(() => applyTriage(document(), stale)).toThrow(StaleTriageError);
    try {
      applyTriage(document(), stale);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(StaleTriageError);
      const stopped = error as StaleTriageError;
      expect(stopped.unknownIds).toEqual(["gone"]);
      expect(stopped.message).toContain("gone");
      expect(stopped.message).toContain("belongs to one run");
    }
  });

  test("a verdict that describes the finding differently is refused too", () => {
    const moved = TriageDocumentSchema.parse({
      schemaVersion: "1.0",
      reviewer: "manual verification",
      verdicts: [
        {
          id: "holds",
          rule: "appsec.missing-tenant-scope",
          file: "src/api/memberships/list.ts",
          // The code moved: the reviewer read line 31, this run reports 31 at a
          // different line. Same finding id, different run.
          line: 44,
          reportedSeverity: "critical",
          verdict: "false",
          note: "already scoped by the middleware",
        },
      ],
    });
    try {
      applyTriage(document(), moved);
      expect.unreachable();
    } catch (error) {
      const stopped = error as StaleTriageError;
      expect(stopped.mismatches).toEqual([
        { id: "holds", field: "line", reviewed: "44", found: "31" },
      ]);
      expect(stopped.message).toContain("reviewed as line 44");
    }
  });

  test("nothing is withheld when the triage is refused", () => {
    const stale = triage([
      {
        id: "gone",
        rule: "appsec.idor",
        file: "src/api/old.ts",
        line: 4,
        reportedSeverity: "high",
        verdict: "false",
        note: "not reachable",
      },
    ]);
    const source = document();
    expect(() => applyTriage(source, stale)).toThrow();
    expect(source.findings).toHaveLength(5);
  });
});

describe("the words a finding is marked with", () => {
  const { summary } = applyTriage(document(), triage());
  const index = reviewIndex(summary);

  test("confirmed says a person checked it", () => {
    expect(reviewLabel(index.get("holds") as never)).toBe(
      "confirmed by human review against the code",
    );
  });

  test("corrected names both severities", () => {
    expect(reviewLabel(index.get("stream") as never)).toBe(
      "severity corrected by human review from high to low",
    );
  });

  test("contested says it was not decided", () => {
    expect(reviewLabel(index.get("cron") as never)).toContain("could not decide");
  });

  test("withheld is marked as withheld, wherever it is printed", () => {
    expect(reviewLabel(index.get("sqli") as never)).toContain("withheld by human review");
  });

  test("a fully reviewed run says so instead of pretending to have a remainder", () => {
    expect(unreviewedStatement(0)).toContain("Every finding in this dossier was examined");
  });
});

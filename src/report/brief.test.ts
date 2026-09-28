import { describe, expect, test } from "bun:test";
import type { Finding, FindingsDocument, Severity } from "../contracts/findings.ts";
import { TriageDocumentSchema } from "../contracts/triage.ts";
import {
  buildBriefModel,
  detailedVerificationSentence,
  groupLabel,
  isBriefDetailed,
  renderBriefMarkdown,
  representativeOf,
  severityMix,
} from "./brief.ts";
import { type ReportInput, buildReportModel } from "./pdf/model.ts";
import { applyTriage } from "./triage.ts";

/** A finding with a verified snippet, overridden field by field. */
function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "aaaa0000",
    domain: "appsec",
    rule: "appsec.hardcoded-secret",
    severity: "high",
    confidence: "high",
    title: "Hardcoded credential in .env.example",
    description: "A generated 64-character secret sits in a tracked template file.",
    location: {
      file: ".env.example",
      line: 129,
      snippet: "> 129 | MCP_AUTH0_CLIENT_SECRET=[REDACTED]",
    },
    evidence: [],
    exploitability: "Read access to the repository.",
    impact: "Anyone who can clone the repository can authenticate as this application.",
    recommendation: "Rotate the secret and read it from the environment.",
    acceptanceCriteria: ["The old value no longer authenticates"],
    cwe: ["CWE-798"],
    owasp: ["A07:2021"],
    source: { kind: "tool", name: "gitleaks" },
    ...overrides,
  };
}

/** `count` findings of one rule, numbered so their ids and lines are distinct. */
function many(count: number, overrides: Partial<Finding> & { file?: string } = {}): Finding[] {
  const { file, ...rest } = overrides;
  return Array.from({ length: count }, (_unused, index) =>
    finding({
      id: `${rest.rule ?? "rule"}-${index}`,
      ...rest,
      location: {
        file: file ?? `migrations/${index}.ts`,
        line: index + 1,
        snippet: `> ${index + 1} | ALTER TABLE`,
      },
    }),
  );
}

/** A findings document carrying exactly the findings a test cares about. */
function document(findings: readonly Finding[]): FindingsDocument {
  return {
    schemaVersion: "1.0",
    runId: "20260924T172226-18e1313b",
    target: "/repos/example-api",
    findings: [...findings],
    assurances: [],
    coverage: [],
    droppedFindings: 0,
  };
}

/** The dossier model a brief is built from. */
function model(findings: readonly Finding[], extra: Partial<ReportInput> = {}) {
  const input: ReportInput = {
    findings: document(findings),
    run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
    ...extra,
  };
  return buildReportModel(input);
}

/** One rule flooding the data layer: enough of it that the brief has to count rather than list. */
function lockingMigrations(): Finding[] {
  return [
    ...many(80, {
      domain: "data",
      rule: "data.locking-migration",
      severity: "medium",
      title: "Adds a NOT NULL column with a default",
    }),
    ...many(2, {
      domain: "data",
      rule: "data.locking-migration",
      severity: "low",
      title: "Creates an index without CONCURRENTLY",
      file: "migrations/late.ts",
    }),
  ];
}

describe("isBriefDetailed", () => {
  test("details critical and high, and nothing below them", () => {
    const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
    expect(severities.filter((severity) => isBriefDetailed(finding({ severity })))).toEqual([
      "critical",
      "high",
    ]);
  });
});

describe("groupLabel", () => {
  test("borrows the phrase every member's title already shares", () => {
    const members = [
      finding({ title: "Unused export candidate: parseRow" }),
      finding({ title: "Unused export candidate: toCsv" }),
    ];
    expect(groupLabel("deadcode.unused-export", members)).toBe("Unused export candidate");
  });

  test("reads the rule when the titles disagree, instead of printing the rule id", () => {
    // Every CVE title differs, so there is no shared phrase to borrow. Printing
    // `findings of \`dependencies.vulnerable-package\`` here duplicated the rule
    // column beside it and told a non-engineer nothing.
    const members = [
      finding({ title: "CVE-2026-75899 in fast-uri@3.1.5" }),
      finding({ title: "CVE-2026-75975 in fast-uri@3.1.5" }),
    ];
    expect(groupLabel("dependencies.vulnerable-package", members)).toBe("Vulnerable package");
  });

  test("keeps acronyms in capitals, so a client-facing table has no typos in it", () => {
    const members = [finding({ title: "a" }), finding({ title: "b" })];
    expect(groupLabel("delivery.ci.unpinned-action", members)).toBe("CI unpinned action");
    expect(groupLabel("appsec.idor", members)).toBe("IDOR");
    expect(groupLabel("data.missing-index-on-fk", members)).toBe("Missing index on FK");
    expect(groupLabel("appsec.injection.sql-built-from-variables", members)).toBe(
      "Injection SQL built from variables",
    );
  });
});

describe("representativeOf", () => {
  test("cites the worst member, from the file carrying the most of the rule", () => {
    const members = [
      finding({ id: "outlier", severity: "low", location: { file: "one.ts", line: 4 } }),
      finding({ id: "b", severity: "medium", location: { file: "busy.ts", line: 9 } }),
      finding({ id: "a", severity: "medium", location: { file: "busy.ts", line: 2 } }),
      finding({ id: "c", severity: "medium", location: { file: "quiet.ts", line: 1 } }),
    ];
    const pick = representativeOf(members);
    expect(pick.location.file).toBe("busy.ts");
    expect(pick.location.line).toBe(2);
  });
});

describe("severityMix", () => {
  test("names every severity present and leaves out the zeros", () => {
    const counts = {
      counts: { critical: 0, high: 0, medium: 80, low: 2, info: 0 },
      total: 82,
    } as const;
    expect(severityMix(counts)).toBe("80 medium, 2 low");
  });
});

describe("buildBriefModel", () => {
  test("details every critical and high in full and counts everything below", () => {
    const brief = buildBriefModel(
      model([
        finding({ id: "crit", severity: "critical", domain: "delivery" }),
        finding({ id: "high", severity: "high" }),
        ...lockingMigrations(),
      ]),
    );
    expect(brief.detailed.map((entry) => entry.id)).toEqual(["crit", "high"]);
    expect(brief.omissions.detailed).toBe(2);
    expect(brief.omissions.counted).toBe(82);
    // The invariant the omission page is checkable against.
    expect(brief.omissions.detailed + brief.omissions.counted).toBe(brief.omissions.total);
  });

  test("groups by rule across severities, so one rule is one row", () => {
    // 80 medium and 2 low of `data.locking-migration` are 82 locking migrations,
    // not two separate rows a reader has to add up.
    const brief = buildBriefModel(model(lockingMigrations()));
    expect(brief.groups).toHaveLength(1);
    const [group] = brief.groups;
    expect(group?.count).toBe(82);
    expect(group?.severity).toBe("medium");
    expect(group?.mix).toBe("80 medium, 2 low across 81 files");
    // The members' titles differ, so the label is read off the rule rather than
    // borrowed — and the count lives in its own column, so it is not repeated here.
    expect(group?.label).toBe("Locking migration");
  });

  test("keeps a rule's findings under their own domain", () => {
    const brief = buildBriefModel(
      model([
        ...many(3, { domain: "data", rule: "data.select-star", severity: "low" }),
        ...many(2, { domain: "delivery", rule: "delivery.dockerfile.DL3059", severity: "low" }),
      ]),
    );
    expect(brief.domains.map((entry) => entry.domain)).toEqual(["data", "delivery"]);
    expect(brief.domains.map((entry) => entry.count)).toEqual([3, 2]);
  });

  test("a domain with nothing to count gets no block at all", () => {
    const brief = buildBriefModel(model([finding({ severity: "critical" })]));
    expect(brief.domains).toEqual([]);
    expect(brief.omissions.counted).toBe(0);
  });

  test("with no review, it says so rather than staying silent", () => {
    const brief = buildBriefModel(model([finding({ severity: "critical" })]));
    expect(brief.verification).toBeNull();
    expect(brief.detailedVerificationSentence).toBeNull();
    expect(brief.detailedFullyReviewed).toBe(false);
    expect(brief.omissions.paragraphs.join(" ")).toContain("Nobody reviewed this run");
  });
});

describe("a reviewed run", () => {
  /** A brief over a run whose two severe findings were reviewed by hand. */
  function reviewed() {
    const findings = [
      finding({ id: "confirmed", severity: "critical", domain: "delivery" }),
      finding({ id: "contested", severity: "critical", domain: "delivery" }),
      finding({ id: "withdrawn", severity: "high" }),
      ...many(30, { domain: "data", rule: "data.select-star", severity: "low" }),
    ];
    const triage = TriageDocumentSchema.parse({
      schemaVersion: "1.0",
      reviewer: "two reviewers, by hand",
      verdicts: [
        {
          id: "confirmed",
          rule: "appsec.hardcoded-secret",
          file: ".env.example",
          line: 129,
          reportedSeverity: "critical",
          verdict: "true",
          note: "Checked against the code; it holds.",
        },
        {
          id: "contested",
          rule: "appsec.hardcoded-secret",
          file: ".env.example",
          line: 129,
          reportedSeverity: "critical",
          verdict: "unclear",
          note: "Two reviewers disagreed and it is kept at critical.",
        },
        {
          id: "withdrawn",
          rule: "appsec.hardcoded-secret",
          file: ".env.example",
          line: 129,
          reportedSeverity: "high",
          verdict: "false",
          note: "The value is the literal string `nobody`.",
        },
      ],
    });
    const applied = applyTriage(document(findings), triage);
    return buildBriefModel(
      buildReportModel({
        findings: applied.document,
        run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
        triage: applied.summary,
      }),
    );
  }

  test("a withheld finding leaves the counts and is still named", () => {
    const brief = reviewed();
    expect(brief.detailed.map((entry) => entry.id)).toEqual(["confirmed", "contested"]);
    expect(brief.omissions.withheld).toBe(1);
    expect(brief.omissions.paragraphs.join(" ")).toContain(
      "A further 1 claim this run made was withheld",
    );
  });

  test("a contested finding is never described as confirmed", () => {
    // "Verified by hand" over two findings, one of which the reviewer could not
    // decide, is the one overstatement this sentence exists to prevent.
    const brief = reviewed();
    expect(brief.detailedVerdicts).toEqual({
      confirmed: 1,
      corrected: 0,
      contested: 1,
      unreviewed: 0,
    });
    const sentence = brief.detailedVerificationSentence ?? "";
    expect(sentence).toContain("1 confirmed at the severity shown");
    expect(sentence).toContain("1 contested");
    expect(sentence).toContain("the reviewer could not decide");
  });

  test("the counted rows disclose how little of them a person examined", () => {
    const brief = reviewed();
    expect(brief.omissions.countedReviewed).toBe(0);
    expect(brief.omissions.countedUnreviewed).toBe(30);
    expect(brief.omissions.paragraphs.join(" ")).toContain("30 carry none");
  });
});

describe("detailedVerificationSentence", () => {
  test("says plainly when nobody looked", () => {
    const sentence = detailedVerificationSentence(4, {
      confirmed: 0,
      corrected: 0,
      contested: 0,
      unreviewed: 4,
    });
    expect(sentence).toContain("None of the 4 findings this brief details carries a human verdict");
  });

  test("names the unreviewed remainder when the review was partial", () => {
    const sentence = detailedVerificationSentence(5, {
      confirmed: 2,
      corrected: 1,
      contested: 0,
      unreviewed: 2,
    });
    expect(sentence).toContain("3 of the 5 findings");
    expect(sentence).toContain("The other 2 carry no verdict");
  });
});

describe("renderBriefMarkdown", () => {
  test("prints the severe findings in full and the rest as counts", () => {
    const markdown = renderBriefMarkdown(
      buildBriefModel(
        model([
          finding({ id: "severe", severity: "critical", title: "Manifest keys reach a shell" }),
          ...lockingMigrations(),
        ]),
      ),
    );
    expect(markdown).toContain("# Sentinel executive brief");
    expect(markdown).toContain("## Critical and high, in full (1)");
    expect(markdown).toContain("Manifest keys reach a shell");
    // The detail a counted finding does not get: its fix, its snippet, its block.
    expect(markdown).toContain("**Fix:** Rotate the secret and read it from the environment.");
    expect(markdown).toContain("## Medium and below, counted (82)");
    expect(markdown).toContain("| 82 | medium |");
    expect(markdown).toContain("## What this brief leaves out");
  });

  test("never prints a counted finding's own block", () => {
    const markdown = renderBriefMarkdown(
      buildBriefModel(
        model(
          many(30, {
            domain: "data",
            rule: "data.select-star",
            severity: "low",
            title: "Query selects every column",
            description: "THE COUNTED DESCRIPTION",
          }),
        ),
      ),
    );
    expect(markdown).not.toContain("THE COUNTED DESCRIPTION");
    expect(markdown).toContain("30 findings are not detailed here");
  });

  test("states that nothing reached critical or high when nothing did", () => {
    const markdown = renderBriefMarkdown(
      buildBriefModel(model(many(3, { domain: "data", severity: "low" }))),
    );
    expect(markdown).toContain("No finding in this run is critical or high");
    expect(markdown).toContain("this brief details nothing");
  });
});

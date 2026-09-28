import { describe, expect, test } from "bun:test";
import type { Finding, FindingsDocument } from "../../contracts/findings.ts";
import { TriageDocumentSchema } from "../../contracts/triage.ts";
import { buildBriefModel } from "../brief.ts";
import { applyTriage } from "../triage.ts";
import { decodePdfText, testCanvas } from "./_test-support.ts";
import { REPORT_BRIEF_PDF_FILE, renderBriefPdf, renderBriefSections } from "./brief.ts";
import { type ReportInput, buildReportModel } from "./model.ts";
import { renderSections } from "./render.ts";

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
      snippet: "  128 | MCP_AUTH0_CLIENT_ID=x\n> 129 | MCP_AUTH0_CLIENT_SECRET=[REDACTED]",
    },
    evidence: [{ file: "apps/mcp/src/index.ts", line: 48, note: "read as clientSecret" }],
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
function many(count: number, overrides: Partial<Finding> = {}): Finding[] {
  return Array.from({ length: count }, (_unused, index) =>
    finding({
      id: `${overrides.rule ?? "rule"}-${index}`,
      ...overrides,
      location: { file: `migrations/${index}.ts`, line: index + 1, snippet: `> ${index + 1} | x` },
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

/** Renderer input over a run with two severe findings and a hundred quiet ones. */
function input(extra: Partial<ReportInput> = {}): ReportInput {
  return {
    findings: document([
      finding({ id: "severe", severity: "critical", title: "Manifest keys reach a shell" }),
      finding({ id: "alsosevere", severity: "high" }),
      ...many(100, {
        domain: "data",
        rule: "data.locking-migration",
        severity: "medium",
        title: "Adds a NOT NULL column",
        description: "THE COUNTED DESCRIPTION",
        recommendation: "THE COUNTED FIX",
      }),
    ]),
    run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
    ...extra,
  };
}

describe("renderBriefPdf", () => {
  test("produces a PDF", async () => {
    const bytes = await renderBriefPdf(input());
    expect(new TextDecoder().decode(bytes.slice(0, 5))).toBe("%PDF-");
    expect(REPORT_BRIEF_PDF_FILE).toBe("report-brief.pdf");
  });

  test("is a small fraction of the dossier it summarises", async () => {
    // The whole promise of the document: the same findings render as a dossier
    // that prints all of them and as a brief that prints two.
    const canvas = testCanvas({ title: "Executive Brief", subject: "example-api" });
    renderBriefSections(canvas, buildBriefModel(buildReportModel(input())));
    const brief = canvas.pageCount;

    const full = testCanvas({ subject: "example-api" });
    renderSections(full, buildReportModel(input()));
    expect(brief).toBeLessThan(full.pageCount / 2);
  });
});

describe("the brief's pages", () => {
  /** Every string the brief stamps, for one run. */
  async function text(reportInput: ReportInput = input()): Promise<string> {
    const canvas = testCanvas({ title: "Executive Brief", subject: "example-api" });
    renderBriefSections(canvas, buildBriefModel(buildReportModel(reportInput)));
    return decodePdfText(await canvas.finish());
  }

  test("prints every critical and high in full", async () => {
    const stamped = await text();
    expect(stamped).toContain("Manifest keys reach a shell");
    expect(stamped).toContain("Critical and high");
    // The four prose fields a reader acts on, not a summary of them.
    expect(stamped).toContain("Preconditions");
    expect(stamped).toContain("Rotate the secret and read it from the environment.");
  });

  test("counts everything below without printing any of it", async () => {
    const stamped = await text();
    expect(stamped).toContain("Medium and below");
    expect(stamped).toContain("Locking migration");
    // Not one block of the hundred: neither their description nor their fix.
    expect(stamped).not.toContain("THE COUNTED DESCRIPTION");
    expect(stamped).not.toContain("THE COUNTED FIX");
  });

  test("ends with the page that states what it omits, in numbers", async () => {
    const stamped = await text();
    expect(stamped).toContain("What this brief omits");
    expect(stamped).toContain("This document is not the audit");
    expect(stamped).toContain("100");
    expect(stamped).toContain("findings.json");
    expect(stamped).toContain("report.pdf");
  });

  test("says on the cover that nobody reviewed an unreviewed run", async () => {
    const stamped = await text();
    expect(stamped).toContain("Nobody reviewed this run");
    expect(stamped).not.toContain("verified by hand");
  });

  test("carries the reviewer's verdict beside the finding it decided", async () => {
    const findings = [
      finding({ id: "severe", severity: "critical", title: "Manifest keys reach a shell" }),
      ...many(30, { domain: "data", rule: "data.select-star", severity: "low" }),
    ];
    const triage = TriageDocumentSchema.parse({
      schemaVersion: "1.0",
      reviewer: "two reviewers, by hand",
      verdicts: [
        {
          id: "severe",
          rule: "appsec.hardcoded-secret",
          file: ".env.example",
          line: 129,
          reportedSeverity: "critical",
          verdict: "unclear",
          note: "THE REVIEWER COULD NOT DECIDE THIS ONE",
        },
      ],
    });
    const applied = applyTriage(document(findings), triage);
    const stamped = await text({
      findings: applied.document,
      run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
      triage: applied.summary,
    });
    expect(stamped).toContain("THE REVIEWER COULD NOT DECIDE THIS ONE");
    // And the claim about the review is exact: contested is not confirmed.
    expect(stamped).toContain("1 contested");
    expect(stamped).toContain("0 confirmed at the severity shown");
  });
});

describe("a run with nothing severe in it", () => {
  test("says so instead of leaving an empty section", async () => {
    const canvas = testCanvas({ title: "Executive Brief", subject: "example-api" });
    renderBriefSections(
      canvas,
      buildBriefModel(
        buildReportModel({
          findings: document(many(30, { domain: "data", severity: "low" })),
          run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
        }),
      ),
    );
    const stamped = decodePdfText(await canvas.finish());
    // Said in words, not by leaving the section blank — and said twice, because
    // the omission page has to admit that the detailed section is empty too.
    expect(stamped).toContain("No finding in this run is critical or high");
    expect(stamped).toContain("this brief details nothing");
    expect(stamped).toContain("Medium and below");
  });
});

import { describe, expect, test } from "bun:test";
import type { AuditReport } from "../../audit/artifacts.ts";
import { buildAuditReport } from "../../audit/artifacts.ts";
import { unboundedBound } from "../../audit/budget.ts";
import type { Finding, FindingsDocument } from "../../contracts/findings.ts";
import { UNSCOPED_PHASES, buildAnalysisScope } from "../../contracts/scope.ts";
import { TriageDocumentSchema } from "../../contracts/triage.ts";
import { applyTriage } from "../triage.ts";
import { decodePdfText, testCanvas } from "./_test-support.ts";
import { type ReportInput, buildReportModel } from "./model.ts";
import { REPORT_PDF_FILE, renderReportPdf, renderSections, writeReportPdf } from "./render.ts";

/** A finding carrying the gutter-numbered snippet the verifier produces. */
function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "12af78bef6b64800",
    domain: "appsec",
    rule: "appsec.missing-rate-limit",
    severity: "medium",
    confidence: "medium",
    title: "Sign-in handler has no application-level attempt limiter",
    description: "signIn() checks the password on every submission with no throttle.",
    location: {
      file: "src/api/sessions.ts",
      line: 26,
      snippet:
        '  25 | const identity = await createIdentityClient();\n> 26 | const ok = await identity.verifyPassword(parsed.data.email, password);\n  27 | if (!ok) return { message: "Invalid credentials." };',
    },
    evidence: [
      {
        file: "src/api/sessions.ts",
        line: 26,
        note: "credential check with no preceding limiter",
      },
    ],
    exploitability: "An unauthenticated caller who can POST the sign-in route in a loop.",
    impact: "Online password guessing or credential stuffing against user accounts.",
    recommendation: "Add a per-IP and per-email sliding window before the credential check.",
    acceptanceCriteria: ["Repeated failed logins beyond a threshold are rejected"],
    cwe: ["CWE-307"],
    owasp: ["A07:2021"],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  };
}

/** A small run that still exercises every section. */
function document(overrides: Partial<FindingsDocument> = {}): FindingsDocument {
  return {
    schemaVersion: "1.0",
    runId: "20260304T093000-9f2c41ab",
    target: "/workspace/example-api",
    findings: [
      finding(),
      finding({ id: "b", domain: "data", severity: "low", title: "Query selects every column" }),
      finding({
        id: "c",
        domain: "api",
        severity: "info",
        title: "Origin header trusted for a redirect",
        exploitability: undefined,
      }),
    ],
    assurances: [
      {
        id: "9c3b90d3c9ac911e",
        domain: "appsec",
        check: "authorization is enforced by the handler itself",
        scope: "20/40 route handlers; evidence lists 12 of 20",
        unitsChecked: 20,
        evidence: [
          { file: "src/api/admin/orders.ts", line: 19 },
          { file: "src/api/admin/orders.ts", line: 31 },
          { file: "src/api/admin/shipments.ts", line: 20 },
          { file: "src/api/invoices.ts", line: 76 },
        ],
      },
    ],
    coverage: [
      { domain: "appsec", unitsTotal: 33, unitsAudited: 30, skipped: [] },
      { domain: "data", unitsTotal: 50, unitsAudited: 50, skipped: [] },
    ],
    droppedFindings: 1,
    ...overrides,
  };
}

/** The minimum a caller must supply. */
/**
 * A complete `audit.json` for a run that audited part of its inventory.
 *
 * The bound carries a real sentence, which is what section 4 sets in bold — so a
 * test that renders without an audit never exercises that paragraph at all.
 */
function auditReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return buildAuditReport({
    schemaVersion: "1.0",
    runId: "20260304T093000-9f2c41ab",
    target: "/workspace/example-api",
    bound: unboundedBound(1000, 600),
    aborted: false,
    durationMs: 10,
    runtime: { kind: "fixture", concurrency: 1, maxAttempts: 1, timeoutMs: 1000, synthetic: false },
    dispatches: 1,
    retries: 0,
    failures: {
      "malformed-output": 0,
      "truncated-output": 0,
      timeout: 0,
      quota: 0,
      transient: 0,
      refusal: 0,
    },
    quotaExhausted: false,
    usage: {
      inputTokens: 0,
      outputTokens: 0,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
      costUsd: 0,
    },
    batches: [],
    units: {
      total: 0,
      audited: 0,
      skipped: 0,
      byCause: {
        "no-batch": 0,
        "batch-failed": 0,
        "no-verdict": 0,
        inconclusive: 0,
        cancelled: 0,
        budget: 0,
      },
    },
    coverage: [],
    kinds: [],
    findingsKept: 0,
    assurances: 0,
    dropped: {
      unresolved: 0,
      unresolvedEvidence: 0,
      outOfSlice: 0,
      outOfSliceEvidence: 0,
      duplicates: 0,
      relocated: 0,
      strayVerdicts: 0,
      assuranceEvidence: 0,
      byReason: {},
    },
    ...overrides,
  } as never);
}

function input(overrides: Partial<ReportInput> = {}): ReportInput {
  return {
    findings: document(),
    run: {
      generatedAt: new Date("2026-03-04T09:30:00Z"),
      commit: { sha: "9f2c41ab7d3e5c608b1a", branch: "main", dirty: false },
    },
    ...overrides,
  };
}

/**
 * The same document `renderReportPdf` produces, with its content streams left
 * readable so a test can assert on the words on the page.
 */
async function renderText(source: ReportInput): Promise<{ bytes: Uint8Array; text: string }> {
  const model = buildReportModel(source);
  const canvas = testCanvas({
    subject: model.repository,
    runId: model.runId,
    createdAt: model.generatedAt,
  });
  renderSections(canvas, model);
  const bytes = await canvas.finish();
  return { bytes, text: decodePdfText(bytes) };
}

/**
 * The page's words with every line break collapsed to one space.
 *
 * A paragraph is stamped one wrapped line at a time, so a sentence long enough
 * to wrap never appears contiguously in the decoded stream; asserting on it
 * without this passes only for sentences short enough to fit, which is not a
 * property worth testing.
 */
function flatten(text: string): string {
  return text.replace(/\s+/g, " ");
}

/** The page count the PDF itself declares. */
function pageCount(bytes: Uint8Array): number {
  const raw = new TextDecoder("latin1").decode(bytes);
  const match = /\/Type \/Pages\s*\n\/Count (\d+)/.exec(raw);
  return match === null ? 0 : Number(match[1]);
}

describe("renderReportPdf", () => {
  test("produces a PDF with every section, in the plan's order", async () => {
    const { bytes, text } = await renderText(input());
    expect(new TextDecoder().decode(bytes.slice(0, 5))).toBe("%PDF-");
    const order = [
      "Backend Dossier",
      "Methodology",
      "Executive summary",
      "What is protected",
      "Coverage and exclusions",
      "Findings by domain",
      "Prioritised plan",
      "Appendix",
    ];
    let cursor = -1;
    for (const heading of order) {
      const at = text.indexOf(heading, cursor + 1);
      expect(at).toBeGreaterThan(cursor);
      cursor = at;
    }
  });

  test("no section leaks markdown syntax into the page", async () => {
    // The coverage section set the bound statement as `**...**`, and a PDF canvas
    // has no markdown: every dossier printed the asterisks around the sentence
    // that says how much of the repository was never audited.
    const { text } = await renderText(input({ audit: auditReport() }));
    // The sentence that paragraph sets, so the assertion cannot pass by absence.
    expect(text).toContain("400 of 1,000 units were not audited");
    expect(text).not.toContain("**");
  });

  test("the per-domain un-audited column is reconciled with the run's own figure", async () => {
    // One unit is evidence for several domains, so the column counts it once per
    // domain and sums above the number of units that actually went unexamined.
    // Both numbers are true; printing them without the sentence that relates
    // them makes section 4 look like it contradicts its own headline.
    const { text } = await renderText(
      input({
        findings: document({
          coverage: [
            {
              domain: "appsec",
              unitsTotal: 33,
              unitsAudited: 29,
              skipped: [
                { unitId: "a1", reason: "inconclusive: the agent declined to decide" },
                { unitId: "a2", reason: "inconclusive: the agent declined to decide" },
                { unitId: "a3", reason: "inconclusive: the agent declined to decide" },
                { unitId: "a4", reason: "inconclusive: the agent declined to decide" },
              ],
            },
            {
              domain: "data",
              unitsTotal: 50,
              unitsAudited: 47,
              skipped: [
                { unitId: "a1", reason: "inconclusive: the agent declined to decide" },
                { unitId: "a2", reason: "inconclusive: the agent declined to decide" },
                { unitId: "d1", reason: "inconclusive: the agent declined to decide" },
              ],
            },
          ],
        }),
        // Five distinct units went without a verdict; the two domains between
        // them report seven, because a1 and a2 are missing from both.
        audit: auditReport({ bound: unboundedBound(1000, 995) }),
      }),
    );
    // The opening words only: a paragraph is stamped one wrapped line at a time
    // with PDF operators between them, so the whole sentence is never
    // contiguous. `section-coverage.test.ts` asserts the arithmetic.
    expect(flatten(text)).toContain("The un-audited column is counted per domain");
  });

  test("the reconciling sentence is withheld when there is nothing to reconcile", async () => {
    // Saying "the column may exceed the total" on a run where it does not only
    // invites the doubt the sentence exists to answer.
    const { text } = await renderText(input({ audit: auditReport() }));
    expect(flatten(text)).not.toContain("The un-audited column is counted per domain");
  });

  test("a scoped run carries the bound on the cover, before any number", async () => {
    const { text } = await renderText({
      ...input(),
      analysisScope: buildAnalysisScope({
        runId: "20260304T093000-9f2c41ab",
        target: "/repo",
        paths: ["apps/api"],
        selectors: [{ selector: "apps/api", kind: "directory", paths: ["apps/api"] }],
        unmatched: [],
        units: {
          total: 5000,
          inScope: 300,
          outOfScope: 4700,
          byKind: [{ kind: "data-access", inScope: 0, outOfScope: 4700 }],
        },
        unscopedPhases: UNSCOPED_PHASES,
        findingsOutside: 2,
      }),
    });
    expect(text).toContain("This run analysed part of the repository");
    expect(text).toContain("the other 4,700 units");
    // Ahead of the executive summary: a cover a reader can skim without meeting
    // the bound would be the misreading this flag has to prevent.
    expect(text.indexOf("This run analysed part of the repository")).toBeLessThan(
      text.indexOf("Executive summary"),
    );
  });

  test("a whole-repository run's cover has no such callout", async () => {
    const { text } = await renderText(input());
    expect(text).not.toContain("This run analysed part of the repository");
  });

  test("puts what is protected before the findings, which is the whole point", async () => {
    const { text } = await renderText(input());
    expect(text.indexOf("What is protected")).toBeLessThan(text.indexOf("Findings by domain"));
  });

  test("renders the verified snippet with the file's own line numbers", async () => {
    const { text } = await renderText(input());
    expect(text).toContain(
      "const ok = await identity.verifyPassword(parsed.data.email, password);",
    );
    expect(text).toContain("26");
    // The gutter marker is not printed as code.
    expect(text).not.toContain("> 26 |");
  });

  test("states the preconditions, or says they are missing", async () => {
    const { text } = await renderText(input());
    expect(text).toContain("An unauthenticated caller who can POST the sign-in route in a loop.");
    expect(text).toContain("Not stated for this finding");
  });

  test("says what it dropped", async () => {
    const { text } = await renderText(input());
    expect(text).toContain("1 further claim was dropped");
  });

  test("the footer's total matches the document's real page count", async () => {
    const { bytes, text } = await renderText(input());
    const pages = pageCount(bytes);
    expect(pages).toBeGreaterThan(7);
    expect(text).toContain(`page ${pages - 1} of ${pages - 1}`);
    expect(text).not.toContain(`page ${pages} of`);
  });

  test("renders through the public entry point too, compressed", async () => {
    const bytes = await renderReportPdf(input());
    expect(new TextDecoder().decode(bytes.slice(0, 5))).toBe("%PDF-");
    expect(pageCount(bytes)).toBeGreaterThan(7);
    // Compression is on by default, which is why the assertions above read the
    // document through `renderSections` with it turned off.
    expect(new TextDecoder("latin1").decode(bytes)).toContain("/Filter /FlateDecode");
  });

  test("is deterministic: same artifacts in, same bytes out", async () => {
    const first = await renderReportPdf(input());
    const second = await renderReportPdf(input());
    expect(second).toEqual(first);
  });

  test("a domain nobody assessed says so in words, not as a zero", async () => {
    const { text } = await renderText(input());
    expect(text).toContain("Not assessed in this run");
    expect(text).toContain("not assessed");
  });

  test("renders a run with no findings at all without pretending it is clean", async () => {
    const { bytes, text } = await renderText(
      input({ findings: document({ findings: [], assurances: [], droppedFindings: 0 }) }),
    );
    expect(text).toContain("This run produced no findings");
    expect(text).toContain("This run produced no assurances");
    expect(text).toContain("Nothing in this tier.");
    expect(pageCount(bytes)).toBeGreaterThan(6);
  });

  test("renders when findings.json is the only artifact there is", async () => {
    const { text } = await renderText({
      findings: document(),
      run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
    });
    expect(text).toContain("not recorded");
    expect(text).toContain("No stack profile was found in this run directory");
    expect(text).toContain("No tool inventory was supplied");
  });

  test("a synthetic audit is declared on the cover", async () => {
    const { text } = await renderText(
      input({
        audit: {
          bound: unboundedBound(0, 0),
          schemaVersion: "1.0",
          runId: "20260304T093000-9f2c41ab",
          target: "/workspace/example-api",
          aborted: false,
          durationMs: 10,
          runtime: {
            kind: "fixture",
            concurrency: 1,
            maxAttempts: 1,
            timeoutMs: 1000,
            synthetic: true,
          },
          dispatches: 1,
          retries: 0,
          failures: {
            "malformed-output": 0,
            "truncated-output": 0,
            timeout: 0,
            quota: 0,
            transient: 0,
            refusal: 0,
          },
          quotaExhausted: false,
          usage: {
            inputTokens: 0,
            outputTokens: 0,
            cacheReadInputTokens: 0,
            cacheCreationInputTokens: 0,
            costUsd: 0,
          },
          batches: [],
          units: {
            total: 0,
            audited: 0,
            skipped: 0,
            byCause: {
              "no-batch": 0,
              "batch-failed": 0,
              "no-verdict": 0,
              inconclusive: 0,
              cancelled: 0,
              budget: 0,
            },
          },
          coverage: [],
          kinds: [],
          findingsKept: 0,
          assurances: 0,
          dropped: {
            unresolved: 0,
            unresolvedEvidence: 0,
            outOfSlice: 0,
            outOfSliceEvidence: 0,
            duplicates: 0,
            relocated: 0,
            strayVerdicts: 0,
            assuranceEvidence: 0,
            byReason: {},
          },
        },
      }),
    );
    expect(text).toContain("This run is synthetic");
  });

  test("the scorecard is rendered from phase 6 when it is there", async () => {
    const { text } = await renderText(
      input({
        scorecard: {
          domains: [
            {
              domain: "appsec",
              score: 74,
              band: "C",
              status: "partial",
              coverage: 0.9,
              confidence: "medium",
              ceilingReason: "a sign-in path with no attempt limiter caps this domain",
            },
          ],
          overall: { score: 58, band: "F", confidence: "low" },
        },
      }),
    );
    expect(text).toContain("OVERALL 58 / BAND F");
    expect(text).toContain("90%");
    // The reader's name for the domain, not the contract's identifier.
    expect(text).toContain("Score ceiling applied to application security");
    expect(text).not.toContain("Derived by this report");
  });
});

describe("writeReportPdf", () => {
  test("writes report.pdf into the run directory and returns its path", async () => {
    const written: { path: string; bytes: number }[] = [];
    const path = await writeReportPdf(
      {
        writeFile: async (target: string, data: string | Uint8Array) => {
          written.push({ path: target, bytes: data.length });
        },
      },
      "/tmp/run/20260304T093000-9f2c41ab",
      input(),
    );
    expect(path).toBe(`/tmp/run/20260304T093000-9f2c41ab/${REPORT_PDF_FILE}`);
    expect(written).toHaveLength(1);
    expect(written[0]?.bytes).toBeGreaterThan(10000);
  });

  test("a trailing slash on the run directory does not double up", async () => {
    const path = await writeReportPdf({ writeFile: async () => undefined }, "/tmp/run/x/", input());
    expect(path).toBe("/tmp/run/x/report.pdf");
  });
});

describe("a run a human reviewed", () => {
  const raw = document();
  const verdicts = TriageDocumentSchema.parse({
    schemaVersion: "1.0",
    reviewer: "manual verification, 2026-03-04",
    verdicts: [
      {
        id: "12af78bef6b64800",
        rule: "appsec.missing-rate-limit",
        file: "src/api/sessions.ts",
        line: 26,
        reportedSeverity: "medium",
        verdict: "overstated",
        severity: "low",
        note: "Real, but the endpoint is already behind the platform limiter.",
      },
      {
        id: "b",
        rule: "appsec.missing-rate-limit",
        file: "src/api/sessions.ts",
        line: 26,
        reportedSeverity: "low",
        verdict: "false",
        severity: "informational",
        note: "The column list is fixed by the type; nothing wide is selected.",
      },
      {
        id: "c",
        rule: "appsec.missing-rate-limit",
        file: "src/api/sessions.ts",
        line: 26,
        reportedSeverity: "info",
        verdict: "true",
        note: "Confirmed: the redirect target comes straight from the Origin header.",
      },
    ],
  });
  const applied = applyTriage(raw, verdicts);
  const reviewed = input({ findings: applied.document, triage: applied.summary });

  test("the section is there, after the coverage and before the findings", async () => {
    const { text } = await renderText(reviewed);
    expect(text).toContain("Human verification");
    // The section's own heading, not its name: the cover names the section too,
    // and the cover comes first on purpose.
    const section = text.indexOf("What the review changed");
    expect(section).toBeGreaterThan(text.indexOf("Coverage and exclusions"));
    expect(section).toBeLessThan(text.indexOf("Findings by domain"));
  });

  test("the cover says the run was reviewed, and how far", async () => {
    const { text } = await renderText(reviewed);
    expect(text).toContain("Part of this run was verified by hand");
    expect(text.indexOf("Part of this run was verified by hand")).toBeLessThan(
      text.indexOf("Executive summary"),
    );
    expect(text).toContain("3 of 3 findings in this run were");
  });

  test("and the section states what the review does not cover", async () => {
    const { text } = await renderText(reviewed);
    expect(text).toContain("What this review does not cover");
  });

  test("the withheld finding is in the withheld table with its reason", async () => {
    const { text } = await renderText(reviewed);
    expect(text).toContain("Withheld by review (1)");
    expect(text).toContain("Query selects every column");
    expect(text).toContain("The column list is fixed by the type");
  });

  test("and is not in the findings section, the plan or the counts", async () => {
    const { text } = await renderText(reviewed);
    const findings = text.slice(text.indexOf("Findings by domain"));
    expect(findings).not.toContain("Query selects every column");
    expect(text).toContain("2 findings, grouped by domain");
  });

  test("a confirmed finding is marked on the finding itself", async () => {
    const { text } = await renderText(reviewed);
    expect(text).toContain("Human review: confirmed by human review");
    expect(text).toContain("2 of the 2 findings in this section carry a human verdict");
  });

  test("a corrected severity is printed with both numbers", async () => {
    const { text } = await renderText(reviewed);
    expect(text).toContain("Severity corrected by review (1)");
    expect(text).toContain("Human review: severity corrected by human");
  });

  test("an unreviewed run says nothing about a review", async () => {
    const { text } = await renderText(input());
    expect(text).not.toContain("Human verification");
    expect(text).not.toContain("Human review");
    expect(text).not.toContain("verified by hand");
  });
});

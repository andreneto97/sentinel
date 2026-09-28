import { describe, expect, test } from "bun:test";
import { buildAuditReport } from "../audit/artifacts.ts";
import type { Finding, FindingsDocument } from "../contracts/findings.ts";
import { FindingsDocumentSchema } from "../contracts/findings.ts";
import { InventoryDocumentSchema, zeroCounts } from "../contracts/inventory.ts";
import { StackProfileSchema } from "../contracts/profile.ts";
import { ScopeDecisionSchema } from "../contracts/proposal.ts";
import { UNSCOPED_PHASES, buildAnalysisScope } from "../contracts/scope.ts";
import { TriageDocumentSchema } from "../contracts/triage.ts";
import { ScanReportSchema } from "../scan/artifacts.ts";
import type { DossierInput } from "./markdown.ts";
import { REPORT_MARKDOWN_FILE, buildDossierSummary, renderReportMarkdown } from "./markdown.ts";
import { applyTriage, unreviewedStatement } from "./triage.ts";

function finding(overrides: Partial<Finding> & Pick<Finding, "id">): Finding {
  return {
    domain: "appsec",
    rule: "appsec.missing-rate-limit",
    severity: "medium",
    confidence: "high",
    title: "Login has no limiter",
    description: "The handler calls the credential check with no throttle.",
    location: { file: "src/login.ts", line: 12, snippet: "> 12 | await signIn(email)" },
    evidence: [],
    impact: "Online password guessing.",
    recommendation: "Add a per-IP limiter.",
    acceptanceCriteria: ["Repeated failures are rejected."],
    cwe: [],
    owasp: [],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  };
}

function findingsDocument(findings: readonly Finding[], overrides = {}): FindingsDocument {
  return FindingsDocumentSchema.parse({
    schemaVersion: "1.0",
    runId: "20260304T093000-9f2c41ab",
    target: "/repo",
    findings,
    assurances: [
      {
        id: "assure-1",
        domain: "appsec",
        check: "authorization is enforced by the handler itself",
        scope: "20/37 route handlers",
        unitsChecked: 20,
        evidence: [
          { file: "src/admin.ts", line: 19 },
          { file: "src/admin.ts", line: 31 },
        ],
      },
    ],
    coverage: [
      {
        domain: "appsec",
        unitsTotal: 37,
        unitsAudited: 36,
        skipped: [{ unitId: "u1", reason: "inconclusive: the agent declined to decide" }],
      },
      { domain: "data", unitsTotal: 10, unitsAudited: 10, skipped: [] },
    ],
    droppedFindings: 0,
    ...overrides,
  });
}

const audit = buildAuditReport({
  schemaVersion: "1.0",
  runId: "20260304T093000-9f2c41ab",
  target: "/repo",
  aborted: false,
  durationMs: 669454,
  runtime: {
    kind: "claude-agent-sdk",
    concurrency: 2,
    maxAttempts: 3,
    timeoutMs: 240000,
    synthetic: false,
  },
  dispatches: 13,
  retries: 0,
  failures: {
    "malformed-output": 0,
    "truncated-output": 1,
    timeout: 0,
    quota: 0,
    transient: 0,
    refusal: 0,
  },
  quotaExhausted: false,
  usage: {},
  batches: [
    {
      batchId: "route-33cc047898aa",
      domain: "appsec",
      kinds: ["route"],
      units: 17,
      status: "audited",
      attempts: 1,
      verdicts: 17,
      findings: 5,
      durationMs: 127926,
      transcripts: [],
    },
    {
      batchId: "data-access-430b111e3688",
      domain: "data",
      kinds: ["data-access"],
      units: 27,
      status: "partial",
      reason: "5 of 27 units came back without a verdict",
      attempts: 1,
      verdicts: 22,
      findings: 2,
      durationMs: 340072,
      transcripts: [],
    },
  ],
  units: {
    total: 47,
    audited: 46,
    skipped: 1,
    byCause: {
      "no-batch": 0,
      "batch-failed": 0,
      "no-verdict": 0,
      inconclusive: 1,
      cancelled: 0,
      budget: 0,
    },
  },
  coverage: [{ domain: "appsec", unitsTotal: 37, unitsAudited: 36, skipped: [] }],
  kinds: [
    { kind: "route", unitsTotal: 37, unitsAudited: 37, skipped: [] },
    { kind: "data-access", unitsTotal: 10, unitsAudited: 9, skipped: [] },
  ],
  findingsKept: 7,
  assurances: 1,
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
});

const scan = ScanReportSchema.parse({
  schemaVersion: "1.0",
  runId: "20260304T093000-9f2c41ab",
  target: "/repo",
  aborted: false,
  durationMs: 3013,
  steps: [
    { step: "trivy", status: "ok", findings: 2, artifacts: [], durationMs: 2206 },
    {
      step: "hadolint",
      status: "skipped",
      reason: "the target has no Dockerfile",
      findings: 0,
      artifacts: [],
      durationMs: 0,
    },
  ],
  dropped: { findings: 0, evidence: 0, byReason: {} },
  relocated: 0,
  merged: [],
  escalations: [],
});

const inventory = InventoryDocumentSchema.parse({
  schemaVersion: "1.0",
  runId: "20260304T093000-9f2c41ab",
  target: "/repo",
  units: [],
  counts: zeroCounts(),
  enumerators: [
    { name: "routes", status: "ok", kinds: ["route"], units: 37 },
    {
      name: "queue-consumers",
      status: "skipped",
      reason: "no queue consumer is declared in this repository",
      kinds: ["queue-consumer"],
      units: 0,
    },
  ],
  dropped: [],
});

const profile = StackProfileSchema.parse({
  schemaVersion: "1.0",
  target: "/repo",
  facts: [
    {
      kind: "backend-framework",
      value: "next",
      confidence: "high",
      evidence: [{ file: "package.json", line: 2 }],
    },
    {
      kind: "data-layer",
      value: "drizzle",
      confidence: "high",
      evidence: [{ file: "package.json", line: 3 }],
    },
  ],
  absences: [],
  warnings: ["two lockfiles were found"],
  scan: { filesSeen: 100, filesRead: 100, truncated: false },
});

const scope = ScopeDecisionSchema.parse({
  enabledDomains: ["appsec", "data"],
  accepted: [],
  declined: [],
  untouched: [],
  notApplicable: [
    {
      id: "profile.absence.iac",
      domain: "delivery",
      category: "iac",
      reason: "No infrastructure-as-code.",
      evidence: [],
    },
  ],
  estimatedExtraSeconds: 0,
  usesAi: false,
});

const full: DossierInput = {
  findings: findingsDocument([
    finding({ id: "crit", severity: "critical", title: "Secret in source" }),
    finding({ id: "med" }),
    finding({
      id: "dead1",
      domain: "deadcode",
      rule: "deadcode.unused-export",
      severity: "info",
      title: "Unused export candidate: a",
      acceptanceCriteria: ["The export is removed."],
    }),
    finding({
      id: "dead2",
      domain: "deadcode",
      rule: "deadcode.unused-export",
      severity: "info",
      title: "Unused export candidate: b",
      location: { file: "src/b.ts", line: 3 },
      acceptanceCriteria: ["The export is removed."],
    }),
  ]),
  audit,
  scan,
  inventory,
  profile,
  scope,
};

describe("buildDossierSummary", () => {
  test("every severity is present, including the zeros", () => {
    const summary = buildDossierSummary(full);
    expect(summary.bySeverity).toEqual([
      { severity: "critical", count: 1 },
      { severity: "high", count: 0 },
      { severity: "medium", count: 1 },
      { severity: "low", count: 0 },
      { severity: "info", count: 2 },
    ]);
  });

  test("domains come out in contract order, with their worst severity", () => {
    const summary = buildDossierSummary(full);
    expect(summary.byDomain.map((row) => row.domain)).toEqual(["appsec", "data", "deadcode"]);
    const [appsec] = summary.byDomain;
    expect(appsec?.worst).toBe("critical");
    expect(appsec?.assurances).toBe(1);
    expect(appsec?.coverage?.unitsAudited).toBe(36);
    expect(summary.byDomain[2]?.coverage).toBeNull();
  });

  test("units are the distinct ones phase 4 counted when it counted them", () => {
    expect(buildDossierSummary(full).units).toEqual({
      total: 47,
      audited: 46,
      skipped: 1,
      source: "audit",
    });
  });

  test("without an audit the per-domain rows are summed, and say so", () => {
    const summary = buildDossierSummary({ findings: full.findings });
    expect(summary.units).toEqual({ total: 47, audited: 46, skipped: 1, source: "coverage" });
    expect(renderReportMarkdown({ findings: full.findings })).toContain("domain-unit pairs");
  });

  test("the plan counts travel with the summary", () => {
    expect(buildDossierSummary(full).priorities).toEqual({ P1: 1, P2: 1, P3: 2 });
  });

  test("a domain phase 6 could not score is marked, so its counts are not results", () => {
    const summary = buildDossierSummary({
      ...full,
      score: {
        overall: 76,
        band: "B",
        domains: [{ domain: "appsec", score: 70, band: "C" }],
        unscored: [{ domain: "data", reason: "not assessed: only 1 of 5 checks ran (20%)" }],
      },
    });
    expect(summary.byDomain.find((row) => row.domain === "appsec")?.assessed).toBe(true);
    expect(summary.byDomain.find((row) => row.domain === "data")?.assessed).toBe(false);
  });

  test("with no scorecard at all, no domain is claimed as unassessed", () => {
    // The report does not invent a verdict phase 6 never reached, in either
    // direction: absent scoring means the status column says nothing new.
    expect(buildDossierSummary(full).byDomain.every((row) => row.assessed)).toBe(true);
  });
});

describe("a domain the scorer refused", () => {
  // `data` has a coverage row and no findings, which is exactly the shape that
  // reads as a clean domain: `0` findings, `0` assurances, nothing to look at.
  const withUnscored = renderReportMarkdown({
    ...full,
    score: {
      overall: 76,
      band: "B",
      confidence: "medium",
      domains: [{ domain: "appsec", score: 70, band: "C" }],
      unscored: [
        {
          domain: "data",
          reason:
            "not assessed: only 1 of 5 checks ran (20%) — too little to stand behind a number",
        },
      ],
    },
  });

  /** Every row of a markdown table whose first cell is `domain`. */
  const rowsFor = (document: string, domain: string): string[] =>
    document.split("\n").filter((line) => line.startsWith(`| ${domain} |`));

  test("appears in the score table with the reason there is no number", () => {
    expect(withUnscored).toContain(
      "| data | not assessed | — | only 1 of 5 checks ran (20%) — too little to stand behind a number |",
    );
  });

  test("never shows a zero findings count, which would read as a clean domain", () => {
    const rows = rowsFor(withUnscored, "data");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toBe("| data | **no — not assessed** | — | — | — | 10/10 |");
    // The scored neighbour is untouched: a zero there is a real result.
    expect(rowsFor(renderReportMarkdown(full), "data")[0]).toBe(
      "| data | yes | 0 | — | 0 | 10/10 |",
    );
  });
});

describe("renderReportMarkdown", () => {
  const document = renderReportMarkdown(full);

  test("the file name is the one the run directory expects", () => {
    expect(REPORT_MARKDOWN_FILE).toBe("report.md");
  });

  test("every section of the dossier is present, in order", () => {
    const headings = document.split("\n").filter((line) => line.startsWith("## "));
    expect(headings).toEqual([
      "## Executive summary",
      "## Scope negotiation",
      "## Coverage",
      "## Findings",
      "## What is protected",
      "## Prioritised plan",
      "## GitHub issues",
      "## How this run went",
    ]);
  });

  describe("a run narrowed with --path", () => {
    const scope = buildAnalysisScope({
      runId: "20260304T093000-9f2c41ab",
      target: "/repo",
      paths: ["apps/api"],
      selectors: [
        { selector: "api", kind: "workspace", paths: ["apps/api"], note: "`apps/api` exists" },
      ],
      unmatched: [],
      units: {
        total: 5322,
        inScope: 314,
        outOfScope: 5008,
        byKind: [
          { kind: "route", inScope: 302, outOfScope: 14 },
          { kind: "data-access", inScope: 0, outOfScope: 4345 },
        ],
      },
      unscopedPhases: UNSCOPED_PHASES,
      findingsOutside: 3,
    });
    const scoped = renderReportMarkdown({ ...full, analysisScope: scope });

    test("says so in the title and in the line under it", () => {
      expect(scoped).toContain("# Sentinel dossier — `/repo`, scoped to `apps/api`");
      expect(scoped).toContain(`> **${scope.statement}**`);
    });

    test("shows how each selector resolved, and both sides of every kind", () => {
      expect(scoped).toContain("### Analysed subtree");
      expect(scoped).toContain("| `api` | `apps/api` | `apps/api` exists |");
      expect(scoped).toContain("| data-access | 0 | 4345 |");
    });

    test("owns up to the findings that came from outside it", () => {
      expect(scoped).toContain("3 of the findings below are in files outside `apps/api`");
      expect(scoped).toContain("they count against the scores");
    });

    test("names the phases the scope did not narrow", () => {
      expect(scoped).toContain("What `--path` did not narrow, and why:");
      expect(scoped).toContain("**dependency scan**");
      expect(scoped).toContain("**git-history secret scan**");
    });

    test("keeps the negotiated scope's own section intact beneath it", () => {
      const headings = scoped.split("\n").filter((line) => line.startsWith("## "));
      expect(headings).toEqual(
        renderReportMarkdown(full)
          .split("\n")
          .filter((line) => line.startsWith("## ")),
      );
      expect(scoped).toContain("Domains enabled:");
    });

    test("an unscoped run reads exactly as it did before the flag existed", () => {
      const whole = renderReportMarkdown({
        ...full,
        analysisScope: buildAnalysisScope({
          runId: "r",
          target: "/repo",
          paths: [],
          selectors: [],
          unmatched: [],
          units: { total: 47, inScope: 47, outOfScope: 0, byKind: [] },
          unscopedPhases: [],
          findingsOutside: 0,
        }),
      });
      expect(whole).toContain("This run analysed the whole repository");
      expect(whole).not.toContain("scoped to");
      expect(whole).not.toContain("did not narrow");
    });
  });

  test("the header states the run, the counts and the coverage", () => {
    expect(document).toContain("# Sentinel dossier — `/repo`");
    expect(document).toContain("Run `20260304T093000-9f2c41ab` · schema `1.0`");
    expect(document).toContain("4 findings · 1 assurance · 46/47 units audited");
  });

  test("the two trust rules are restated with this run's numbers", () => {
    expect(document).toContain("No finding was dropped for an unresolvable citation in this run.");
    expect(document).toContain("1 unit was skipped.");
    const dropped = renderReportMarkdown({
      ...full,
      findings: findingsDocument([finding({ id: "a" })], { droppedFindings: 3 }),
    });
    expect(dropped).toContain("3 findings were dropped because their citation did not resolve");
  });

  test("coverage names every unit that was not audited, with its reason", () => {
    expect(document).toContain("### By unit kind");
    expect(document).toContain("| route | 37/37 |");
    expect(document).toContain("### Units that were not audited");
    expect(document).toContain("inconclusive: the agent declined to decide");
  });

  test("coverage groups the un-audited units by reason with a count", () => {
    // The reason appears once, with how many units share it, rather than once per
    // unit: a bounded monorepo run would otherwise print thousands of rows.
    expect(document).toContain("| Domain | Units | Reason |");
    const rows = document
      .split("\n")
      .filter((line) => line.includes("inconclusive: the agent declined to decide"));
    expect(rows).toHaveLength(1);
  });

  test("coverage prints the audit's bound, so a budgeted run cannot read as complete", () => {
    // Derived from the report's own unit totals, so it agrees with the coverage
    // line above it instead of claiming zero.
    expect(document).toContain("**1 of 47 units were not audited");
  });

  test("an analyzer that did not run is disclosed, not omitted", () => {
    expect(document).toContain("| hadolint | skipped | 0 | the target has no Dockerfile |");
    expect(document).toContain("1 analyzer did not run normally");
  });

  test("an enumerator that was skipped is listed with the kinds it owns", () => {
    expect(document).toContain("| queue-consumers | skipped | 0 | no queue consumer is declared");
  });

  test("findings are grouped by domain and carry their evidence", () => {
    expect(document).toContain("### appsec (2)");
    expect(document).toContain("### deadcode (2)");
    expect(document).toContain("```text\n> 12 | await signIn(email)\n```");
    expect(document).toContain("**Impact:** Online password guessing.");
    expect(document).toContain("**Fix:** Add a per-IP limiter.");
  });

  test("each finding points at the issue that carries its checklist", () => {
    expect(document).toContain("**Issue:** `deadcode.unused-export@repo`");
    expect(document).toContain("checklist in `issues.md`");
  });

  test("the plan prints all three buckets and links each row to its issue", () => {
    expect(document).toContain("### P1 — exploitable now, or loses data — 1");
    expect(document).toContain("### P2 — a release should not ship without this — 1");
    expect(document).toContain("### P3 — hygiene — 2");
    expect(document).toContain("| `deadcode.unused-export@repo` |");
  });

  test("the issues section carries the delimited bodies, nested one level deeper", () => {
    expect(document).toContain("## GitHub issues");
    expect(document).toContain("<!-- sentinel:issue:start key=crit -->");
    expect(document).toContain("### [Security] Secret in source");
    expect(document).toContain("1 of them group 2 hygiene findings");
  });

  test("the volatile facts of the run are confined to the last section", () => {
    const index = document.indexOf("## How this run went");
    expect(index).toBeGreaterThan(0);
    const tail = document.slice(index);
    expect(tail).toContain("Audit: 11m 9s, 2 batches, 13 dispatches");
    expect(tail).toContain("Agent failures: truncated-output 1.");
    expect(tail).toContain("| `data-access-430b111e3688` | partial |");
    expect(tail).toContain("Profile warning: two lockfiles were found");
    expect(tail).toContain("Stack: backend-framework: `next` · data-layer: `drizzle`");
    expect(document.slice(0, index)).not.toContain("dispatches");
  });

  test("the same input renders the same bytes", () => {
    expect(renderReportMarkdown(full)).toBe(document);
  });

  test("it ends with exactly one newline", () => {
    expect(document.endsWith("\n")).toBe(true);
    expect(document.endsWith("\n\n")).toBe(false);
  });
});

describe("what the report says when a document is missing", () => {
  test("no scope decision is stated rather than skipped", () => {
    const document = renderReportMarkdown({ findings: findingsDocument([finding({ id: "a" })]) });
    expect(document).toContain("## Scope");
    expect(document).toContain("No scope decision was recorded for this run");
  });

  test("no assurances is not read as a clean bill of health", () => {
    const document = renderReportMarkdown({
      findings: findingsDocument([finding({ id: "a" })], { assurances: [] }),
    });
    expect(document).toContain("That is not a clean bill of health");
  });

  test("no findings is stated too", () => {
    const document = renderReportMarkdown({ findings: findingsDocument([]) });
    expect(document).toContain("No finding survived verification in this run.");
    expect(document).not.toContain("## GitHub issues");
    expect(document).not.toContain("## Prioritised plan");
  });

  test("a synthetic audit is disclosed where the coverage is claimed", () => {
    const synthetic = buildAuditReport({
      ...audit,
      runtime: { ...audit.runtime, kind: "fixture", synthetic: true },
    });
    const document = renderReportMarkdown({ ...full, audit: synthetic });
    expect(document).toContain("came from a recorded transcript, not from a live model");
  });

  test("a cancelled run says so where the timings are", () => {
    const document = renderReportMarkdown({
      ...full,
      audit: buildAuditReport({ ...audit, aborted: true, quotaExhausted: true }),
    });
    expect(document).toContain("**cancelled**");
    expect(document).toContain("**The subscription limit stopped the phase.**");
  });

  test("a truncated profile scan is disclosed", () => {
    const document = renderReportMarkdown({
      ...full,
      profile: StackProfileSchema.parse({
        ...profile,
        scan: { filesSeen: 100, filesRead: 40, truncated: true },
      }),
    });
    expect(document).toContain("The content scan stopped early: 40 of 100 candidate files");
  });

  test("a pipe in a finding title cannot break a table", () => {
    const document = renderReportMarkdown({
      findings: findingsDocument([finding({ id: "a", title: "a | b" })]),
    });
    for (const line of document.split("\n")) {
      if (!line.startsWith("| ")) continue;
      expect(line.split(/(?<!\\)\|/).length).toBeGreaterThan(2);
    }
    expect(document).toContain("a \\| b");
  });
});

describe("a rule loud enough to drown the dossier", () => {
  /** `count` dead-code findings of one rule, one per file. */
  function noise(count: number, overrides: Partial<Finding> = {}): Finding[] {
    return Array.from({ length: count }, (_, index) =>
      finding({
        id: `noise-${index}`,
        domain: "deadcode",
        rule: "deadcode.unused-export",
        severity: "info",
        confidence: "low",
        title: `Unused export candidate: symbol${index}`,
        location: { file: `src/dead-${index}.ts`, line: index + 1 },
        source: { kind: "tool", name: "knip" },
        ...overrides,
      }),
    );
  }

  const loud = renderReportMarkdown({
    findings: findingsDocument([
      finding({ id: "critical", severity: "critical", title: "SQL built from a variable" }),
      ...noise(400),
    ]),
  });

  test("the group is rendered once, with its real size", () => {
    expect(loud).toContain("400 Unused export candidates");
    expect(loud).toContain("400 findings of rule `deadcode.unused-export`");
    expect(loud).toContain("counted group of 400 findings across 400 files");
  });

  test("only the examples get a block of their own", () => {
    const section = loud.slice(loud.indexOf("## Findings"), loud.indexOf("## What is protected"));
    expect(section.match(/#### Unused export candidate: /g) ?? []).toHaveLength(0);
    // Five example rows in the group's table, and nothing else of the 400.
    expect(section.match(/Unused export candidate: symbol\d+/g) ?? []).toHaveLength(5);
  });

  test("the collapse says where every finding still is", () => {
    expect(loud).toContain("`findings.json`");
    expect(loud).toContain("raw/knip/");
    expect(loud).toContain("only the rendering is collapsed");
  });

  test("the counts above the fold are the real ones", () => {
    expect(loud).toContain("401 findings");
    expect(loud).toContain("| deadcode | yes | 400 |");
  });

  test("the critical finding is still rendered in full", () => {
    expect(loud).toContain("#### SQL built from a variable");
    expect(loud).toContain("> 12 | await signIn(email)");
  });

  test("a finding above low is never inside a group, however loud its rule is", () => {
    const mixed = renderReportMarkdown({
      findings: findingsDocument([
        ...noise(400),
        finding({
          id: "serious",
          domain: "deadcode",
          rule: "deadcode.unused-export",
          severity: "high",
          title: "Unused export candidate: dangerous",
        }),
      ]),
    });
    expect(mixed).toContain("#### Unused export candidate: dangerous");
    expect(mixed).toContain("400 Unused export candidates");
  });

  test("the plan does not repeat the members it already grouped", () => {
    expect(loud).toContain("are inside a counted group in the findings section");
    const planTable = loud.slice(loud.indexOf("## Prioritised plan"));
    expect((planTable.match(/Unused export candidate/g) ?? []).length).toBeLessThanOrEqual(10);
  });

  test("a small run says the threshold was never reached", () => {
    const quiet = renderReportMarkdown({ findings: findingsDocument([finding({ id: "a" })]) });
    expect(quiet).toContain("No rule passed 25 findings in a domain");
    expect(quiet).toContain("#### Login has no limiter");
  });
});

describe("a run a human reviewed", () => {
  const raw = findingsDocument([
    finding({ id: "crit", severity: "critical", title: "Secret in source" }),
    finding({ id: "med" }),
  ]);
  const verdicts = TriageDocumentSchema.parse({
    schemaVersion: "1.0",
    reviewer: "manual verification, 2026-03-04 (three reviewers, one slice each)",
    verdicts: [
      {
        id: "crit",
        rule: "appsec.missing-rate-limit",
        file: "src/login.ts",
        line: 12,
        reportedSeverity: "critical",
        verdict: "false",
        severity: "informational",
        note: "The value is a module constant; there is no request-controlled input.",
      },
      {
        id: "med",
        rule: "appsec.missing-rate-limit",
        file: "src/login.ts",
        line: 12,
        reportedSeverity: "medium",
        verdict: "true",
        note: "Confirmed: the handler calls signIn with no limiter in front of it.",
      },
    ],
  });
  const applied = applyTriage(raw, verdicts);
  const reviewed = renderReportMarkdown({
    ...full,
    findings: applied.document,
    triage: applied.summary,
  });

  test("the section is there, and before the findings it judged", () => {
    const headings = reviewed.split("\n").filter((line) => line.startsWith("## "));
    expect(headings).toEqual([
      "## Executive summary",
      "## Scope negotiation",
      "## Coverage",
      "## Human verification",
      "## Findings",
      "## What is protected",
      "## Prioritised plan",
      "## GitHub issues",
      "## How this run went",
    ]);
  });

  test("it says who reviewed, and how many of how many", () => {
    expect(reviewed).toContain("## Human verification");
    expect(reviewed).toContain(
      "2 of 2 findings in this run were verified against the code by hand",
    );
    expect(reviewed).toContain("manual verification, 2026-03-04 (three reviewers, one slice each)");
    expect(reviewed).toContain("1 confirmed, 0 corrected, 1 withheld, 0 contested");
  });

  test("it says, in bold, that the rest carries no human review", () => {
    // The sentence the whole section exists for: a couple of checked findings
    // must never read as a checked dossier.
    expect(reviewed).toContain("**Every finding in this dossier was examined by a human");
    const partial = renderReportMarkdown({
      ...full,
      findings: applied.document,
      triage: {
        ...applied.summary,
        unreviewed: 1_558,
        unreviewedStatement: unreviewedStatement(1_558),
      },
    });
    expect(partial).toContain("**The other 1558 findings in this dossier carry no human review");
  });

  test("a withheld finding is in the withheld table, with the reason", () => {
    expect(reviewed).toContain("### Withheld by review (1)");
    expect(reviewed).toContain("| critical | Secret in source | `src/login.ts:12` |");
    expect(reviewed).toContain("The value is a module constant");
  });

  test("and is absent from the findings, the plan and the issues", () => {
    const afterTheSection = reviewed.slice(reviewed.indexOf("## Findings"));
    expect(afterTheSection).not.toContain("Secret in source");
    expect(afterTheSection).not.toContain("id `crit`");
  });

  test("the counts a reader sees are the reviewed ones", () => {
    expect(reviewed).toContain("1 finding · 1 assurance");
    expect(reviewed).toContain("The findings count in this dossier is 1");
  });

  test("a confirmed finding says so on the finding itself", () => {
    expect(reviewed).toContain("**Human review:** confirmed by human review against the code.");
    expect(reviewed).toContain(
      "1 of the 1 findings below carry a human verdict, printed on the finding wherever it has a block of its own",
    );
  });

  test("the executive summary carries the review as a third claim", () => {
    const summary = reviewed.slice(
      reviewed.indexOf("## Executive summary"),
      reviewed.indexOf("## Scope"),
    );
    expect(summary).toContain("**Part of this run was verified by hand.**");
  });

  test("the header states it before any number", () => {
    expect(reviewed.indexOf("> **Human-reviewed.**")).toBeLessThan(
      reviewed.indexOf("## Executive summary"),
    );
  });

  test("a corrected severity travels with both numbers", () => {
    const corrected = applyTriage(
      raw,
      TriageDocumentSchema.parse({
        schemaVersion: "1.0",
        reviewer: "manual verification",
        verdicts: [
          {
            id: "crit",
            rule: "appsec.missing-rate-limit",
            file: "src/login.ts",
            line: 12,
            reportedSeverity: "critical",
            verdict: "overstated",
            severity: "low",
            note: "Real, but it needs an admin session to reach.",
          },
        ],
      }),
    );
    const document = renderReportMarkdown({
      ...full,
      findings: corrected.document,
      triage: corrected.summary,
    });
    expect(document).toContain("### Severity corrected by review (1)");
    expect(document).toContain("| critical | low | Secret in source |");
    expect(document).toContain(
      "**Human review:** severity corrected by human review from critical to low.",
    );
  });

  test("an unreviewed run says nothing about human verification at all", () => {
    const plain = renderReportMarkdown(full);
    expect(plain).not.toContain("Human verification");
    expect(plain).not.toContain("Human review");
    expect(plain).not.toContain("human review");
  });
});

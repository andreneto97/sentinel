import { describe, expect, test } from "bun:test";
import type { AuditReport } from "../../audit/artifacts.ts";
import { unboundedBound } from "../../audit/budget.ts";
import type { Assurance, Finding, FindingsDocument } from "../../contracts/findings.ts";
import type { InventoryDocument } from "../../contracts/inventory.ts";
import { zeroCounts } from "../../contracts/inventory.ts";
import type { StackProfile } from "../../contracts/profile.ts";
import type { ScopeDecision } from "../../contracts/proposal.ts";
import { UNSCOPED_PHASES, buildAnalysisScope } from "../../contracts/scope.ts";
import { TriageDocumentSchema } from "../../contracts/triage.ts";
import { planVolume } from "../../scan/_volume.ts";
import type { ScanReport } from "../../scan/artifacts.ts";
import { applyTriage } from "../triage.ts";
import { buildReportModel, evidenceNote, unitCount } from "./model.ts";
import type { DomainScore, ScorecardInput } from "./scorecard.ts";

/**
 * One synthetic run over an invented orders API, built to hold every shape the
 * model has to tell apart at once: a domain audited in full, one with units left
 * over, one whose checks barely ran, a domain that produced findings without
 * ever being in scope, and a domain nothing was enumerated for. A fixture whose
 * rows all reconcile exercises one branch, so these deliberately do not.
 */

/** A finding with the fields the report reads; the id is `stableFindingId`'s over those fields. */
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
      snippet: "> 26 | const ok = await identity.verifyPassword(parsed.data.email, password);",
    },
    evidence: [],
    exploitability: "An unauthenticated caller who can POST the sign-in route in a loop.",
    impact: "Online password guessing against user accounts.",
    recommendation: "Add a per-IP and per-email limiter.",
    acceptanceCriteria: ["Repeated failed logins are rejected"],
    cwe: ["CWE-307"],
    owasp: ["A07:2021"],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  };
}

/** An assurance whose scope is a fraction, because that is what the section has to print. */
function assurance(overrides: Partial<Assurance> = {}): Assurance {
  return {
    id: "9c3b90d3c9ac911e",
    domain: "appsec",
    check: "authorization is enforced by the handler itself",
    scope: "20/40 route handlers; evidence lists 12 of 20",
    unitsChecked: 20,
    evidence: [{ file: "src/api/admin/orders.ts", line: 19 }],
    ...overrides,
  };
}

/** `findings.json`, with a coverage row per domain that was in scope. */
function document(overrides: Partial<FindingsDocument> = {}): FindingsDocument {
  return {
    schemaVersion: "1.0",
    runId: "20260304T093000-9f2c41ab",
    target: "/workspace/example-api",
    findings: [
      finding(),
      finding({ id: "a1", domain: "api", severity: "low", title: "Origin header trusted" }),
      finding({ id: "a2", domain: "deadcode", severity: "info", title: "Unused file candidate" }),
      finding({ id: "a3", domain: "data", severity: "medium", title: "Destructive migration" }),
    ],
    assurances: [assurance()],
    coverage: [
      { domain: "dependencies", unitsTotal: 3, unitsAudited: 3, skipped: [] },
      {
        domain: "appsec",
        unitsTotal: 33,
        unitsAudited: 30,
        skipped: [
          { unitId: "1a2b", reason: "inconclusive: the agent declined to decide" },
          { unitId: "3c4d", reason: "inconclusive: the agent declined to decide" },
          { unitId: "5e6f", reason: "inconclusive: Sentinel mismatch" },
        ],
      },
      {
        domain: "data",
        unitsTotal: 50,
        unitsAudited: 45,
        skipped: [{ unitId: "7a8b", reason: "inconclusive: the agent declined to decide" }],
      },
      { domain: "delivery", unitsTotal: 5, unitsAudited: 1, skipped: [] },
      { domain: "serverless", unitsTotal: 2, unitsAudited: 2, skipped: [] },
      { domain: "deadcode", unitsTotal: 2, unitsAudited: 2, skipped: [] },
    ],
    droppedFindings: 0,
    ...overrides,
  };
}

/** A scope decision with six domains on and `api` and `reliability` never offered. */
function scope(): ScopeDecision {
  return {
    enabledDomains: ["dependencies", "appsec", "data", "delivery", "serverless", "deadcode"],
    accepted: [
      {
        proposal: {
          id: "serverless.iam-audit",
          title: "Serverless IAM and trigger permission audit",
          domain: "serverless",
          detected: { summary: "1 serverless platform(s): vercel", evidence: ["vercel.json"] },
          wouldCheck: "wildcard Action/Resource in a function role",
          cost: { estimatedSeconds: 180, usesAi: true },
          defaultAnswer: "on",
          aliases: ["iam"],
          attributes: { platforms: "vercel" },
        },
        outcome: "accepted",
        source: "defaults",
      },
    ],
    declined: [],
    untouched: [],
    notApplicable: [
      {
        id: "profile.absence.iac",
        domain: "delivery",
        category: "iac",
        reason: "No infrastructure-as-code: `trivy config` has nothing to scan beyond containers.",
        evidence: [],
      },
    ],
    unknownSelectors: [],
    blockedOnMissingTool: [],
    estimatedExtraSeconds: 180,
    usesAi: true,
  };
}

/** A stack with an app-router framework and an ORM, and no container, CI or IaC at all. */
function profile(): StackProfile {
  return {
    schemaVersion: "1.0",
    target: "/workspace/example-api",
    facts: [
      {
        kind: "package-manager",
        value: "pnpm",
        detail: "lockfile pnpm-lock.yaml",
        confidence: "high",
        evidence: [{ file: "pnpm-lock.yaml", line: 1 }],
      },
      {
        kind: "language",
        value: "typescript",
        detail: "200 TypeScript file(s)",
        confidence: "high",
        evidence: [{ file: "tsconfig.json", line: 1 }],
      },
      {
        kind: "backend-framework",
        value: "next",
        detail: "40 route handler(s), 12 server action file(s)",
        confidence: "high",
        evidence: [{ file: "package.json", line: 27 }],
      },
      {
        kind: "next-router",
        value: "app",
        confidence: "high",
        evidence: [{ file: "src/app/layout.tsx", line: 1 }],
      },
      {
        kind: "data-layer",
        value: "drizzle",
        detail: "drizzle-orm@^0.44.0",
        confidence: "high",
        evidence: [{ file: "package.json", line: 25 }],
      },
      {
        kind: "database-engine",
        value: "postgresql",
        confidence: "high",
        evidence: [{ file: "package.json", line: 28 }],
      },
      {
        kind: "serverless-platform",
        value: "vercel",
        confidence: "high",
        evidence: [{ file: "vercel.json", line: 1 }],
      },
    ],
    absences: [
      { kind: "container", searched: ["Dockerfile*", "docker-compose*.yml"] },
      { kind: "ci", searched: ["github-actions"] },
      {
        kind: "iac",
        searched: ["*.tf"],
        note: "No infrastructure-as-code: `trivy config` has nothing to scan beyond containers.",
      },
    ],
    warnings: ["3 data-access libraries coexist (drizzle, postgres-js, knex)"],
    scan: { filesSeen: 400, filesRead: 200, truncated: false },
  };
}

/** `scan-report.json`, with the four steps that had nothing to read. */
function scan(): ScanReport {
  return {
    schemaVersion: "1.0",
    runId: "20260304T093000-9f2c41ab",
    target: "/workspace/example-api",
    aborted: false,
    durationMs: 3000,
    steps: [
      {
        step: "trivy",
        status: "ok",
        reason:
          "misconfiguration: no Dockerfile, Kubernetes manifest, Helm chart or Terraform file",
        findings: 2,
        artifacts: [],
        durationMs: 2200,
      },
      { step: "knip", status: "ok", findings: 20, artifacts: [], durationMs: 400 },
      {
        step: "hadolint",
        status: "skipped",
        reason: "the target has no Dockerfile",
        findings: 0,
        artifacts: [],
        durationMs: 0,
      },
      { step: "future-analyzer", status: "ok", findings: 0, artifacts: [], durationMs: 0 },
    ],
    dropped: { findings: 0, evidence: 0, byReason: {} },
    relocated: 0,
    merged: [],
    escalations: [],
  };
}

/** `audit.json`, including a partial batch, which is the row the appendix has to explain. */
function audit(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    bound: unboundedBound(0, 0),
    schemaVersion: "1.0",
    runId: "20260304T093000-9f2c41ab",
    target: "/workspace/example-api",
    aborted: false,
    durationMs: 645000,
    runtime: {
      kind: "claude-agent-sdk",
      concurrency: 2,
      maxAttempts: 3,
      timeoutMs: 240000,
      synthetic: false,
    },
    dispatches: 12,
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
      inputTokens: 30,
      outputTokens: 150000,
      cacheReadInputTokens: 1200000,
      cacheCreationInputTokens: 15000,
      costUsd: 3.25,
    },
    batches: [
      {
        batchId: "route-9f2c41ab0c1d",
        domain: "appsec",
        kinds: ["route"],
        units: 20,
        status: "audited",
        attempts: 1,
        verdicts: 20,
        findings: 5,
        durationMs: 120000,
        transcripts: [],
      },
      {
        batchId: "role-gate-7b3e5a2c8d90",
        domain: "appsec",
        kinds: ["role-gate"],
        units: 8,
        status: "partial",
        reason: "3 of 8 units came back without a verdict",
        attempts: 1,
        verdicts: 5,
        findings: 0,
        durationMs: 540000,
        transcripts: [],
      },
      {
        batchId: "cron-2c4a6e8b0d13",
        domain: "serverless",
        kinds: ["cron"],
        units: 1,
        status: "audited",
        attempts: 1,
        verdicts: 1,
        findings: 2,
        durationMs: 480000,
        transcripts: [],
      },
    ],
    units: {
      total: 200,
      audited: 188,
      skipped: 12,
      byCause: {
        "no-batch": 0,
        "batch-failed": 0,
        "no-verdict": 0,
        inconclusive: 12,
        cancelled: 0,
        budget: 0,
      },
    },
    coverage: [],
    kinds: [
      { kind: "route", unitsTotal: 40, unitsAudited: 40, skipped: [] },
      {
        kind: "role-gate",
        unitsTotal: 8,
        unitsAudited: 5,
        skipped: [
          { unitId: "1a2b", reason: "inconclusive: the agent declined to decide" },
          { unitId: "3c4d", reason: "inconclusive: the agent declined to decide" },
          { unitId: "5e6f", reason: "inconclusive: Sentinel mismatch" },
        ],
      },
      { kind: "cron", unitsTotal: 1, unitsAudited: 1, skipped: [] },
    ],
    findingsKept: 40,
    assurances: 30,
    dropped: {
      unresolved: 0,
      unresolvedEvidence: 0,
      outOfSlice: 0,
      outOfSliceEvidence: 0,
      duplicates: 2,
      relocated: 0,
      strayVerdicts: 0,
      assuranceEvidence: 0,
      byReason: {},
    },
    ...overrides,
  };
}

/** `inventory.json`, reduced to the counts the methodology note reads. */
function inventory(): InventoryDocument {
  return {
    schemaVersion: "1.0",
    runId: "20260304T093000-9f2c41ab",
    target: "/workspace/example-api",
    units: [],
    counts: { ...zeroCounts(), route: 40, "role-gate": 8, sink: 20, cron: 1, webhook: 1 },
    enumerators: [],
    dropped: [],
  };
}

/**
 * Phase 6's verdict on this run: five domains scored, three without a number —
 * delivery because 1 of 5 checks is too thin, api and reliability because
 * nothing was enumerated for them.
 */
function scorecard(): ScorecardInput {
  return {
    domains: [
      { domain: "dependencies", score: 85, band: "B", status: "scored", coverage: 1, ...CONF },
      { domain: "appsec", score: 70, band: "C", status: "scored", coverage: 0.9091, ...CONF },
      { domain: "data", score: 70, band: "C", status: "scored", coverage: 0.9, ...CONF },
      {
        domain: "delivery",
        score: 0,
        band: "",
        status: "not-assessed",
        coverage: 0.2,
        ...CONF,
      },
      { domain: "serverless", score: 85, band: "B", status: "scored", coverage: 1, ...CONF },
      { domain: "api", score: 0, band: "", status: "not-assessed", coverage: null, ...CONF },
      {
        domain: "reliability",
        score: 0,
        band: "",
        status: "not-assessed",
        coverage: null,
        ...CONF,
      },
      { domain: "deadcode", score: 80, band: "B", status: "scored", coverage: 1, ...CONF },
    ],
    overall: { score: 75, band: "B", confidence: "medium" },
  };
}

/** The confidence every row of the fixture scorecard carries. */
const CONF = { confidence: "medium" } as const;

/** The whole run, as the renderer receives it. */
function input() {
  return {
    findings: document(),
    assurances: [assurance(), assurance({ id: "b2", domain: "data", unitsChecked: 16 })],
    profile: profile(),
    scope: scope(),
    scan: scan(),
    audit: audit(),
    inventory: inventory(),
    run: {
      generatedAt: new Date("2026-03-04T09:30:00Z"),
      commit: { sha: "9f2c41ab7d3e5c608b1a", branch: "main", dirty: false },
    },
  };
}

describe("domain assessment", () => {
  test("a domain that was audited in full reads as assessed", () => {
    const model = buildReportModel(input());
    const dependencies = model.domains.find((domain) => domain.domain === "dependencies");
    expect(dependencies?.assessment).toBe("assessed");
    expect(dependencies?.statusSentence).toBe("Assessed: 3 of 3 planned checks completed.");
  });

  test("a domain with units left over reads as partial, with the count", () => {
    const model = buildReportModel(input());
    const appsec = model.domains.find((domain) => domain.domain === "appsec");
    expect(appsec?.assessment).toBe("partial");
    expect(appsec?.statusSentence).toBe(
      "Partially assessed: 30 of 33 planned checks completed, 3 units un-audited.",
    );
  });

  test("a domain nobody checked says so, and never shows a zero", () => {
    const model = buildReportModel(input());
    const reliability = model.domains.find((domain) => domain.domain === "reliability");
    expect(reliability?.assessment).toBe("not-assessed");
    expect(reliability?.statusSentence).toContain("This is not a clean result");
    expect(reliability?.findings).toHaveLength(0);
    expect(reliability?.checksCompleted).toBeUndefined();
  });

  test("findings from a domain that was never in scope are reported as exactly that", () => {
    const model = buildReportModel(input());
    const api = model.domains.find((domain) => domain.domain === "api");
    expect(api?.assessment).toBe("out-of-scope");
    expect(api?.findings).toHaveLength(1);
    expect(api?.statusSentence).toContain("Not in this run's scope");
    expect(api?.statusSentence).toContain("1 finding reached the report");
  });

  test("a domain phase 6 refused to score never reads as assessed", () => {
    // Delivery ran 1 of 5 checks, which is above zero and below what phase 6
    // will score. Without the scorecard the model calls that
    // "partial" — a chip that reads as reviewed — so the refusal has to reach
    // it. This is the seam between `src/score` and the renderer.
    const model = buildReportModel({ ...input(), scorecard: scorecard() });
    const delivery = model.domains.find((domain) => domain.domain === "delivery");
    expect(delivery?.assessment).toBe("insufficient");
    expect(delivery?.statusSentence).toBe(
      "Not assessed: 1 of 5 planned checks completed (20%), which is too little of this domain " +
        "to stand behind a score. The checks that did not run are listed above; this is not a " +
        "clean result.",
    );
    // The fraction survives: it is the measure of how thin the evidence is.
    expect(delivery?.checksCompleted).toEqual({ done: 1, total: 5 });
  });

  test("phase 6 may only lower an assessment, never raise it", () => {
    // appsec is `scored` in phase 6 (91% is above its gate) but three units
    // came back without a verdict. The finer of the two claims wins: the report
    // still says partial, because it is the one that is true.
    const model = buildReportModel({ ...input(), scorecard: scorecard() });
    expect(model.domains.find((domain) => domain.domain === "appsec")?.assessment).toBe("partial");
    expect(model.domains.find((domain) => domain.domain === "dependencies")?.assessment).toBe(
      "assessed",
    );
  });

  test("a domain that was never checked stays not-assessed, not insufficient", () => {
    const model = buildReportModel({ ...input(), scorecard: scorecard() });
    const reliability = model.domains.find((domain) => domain.domain === "reliability");
    expect(reliability?.assessment).toBe("not-assessed");
    expect(reliability?.statusSentence).toContain("nothing was checked");
  });

  test("all eight domains get a view, in contract order", () => {
    const model = buildReportModel(input());
    expect(model.domains.map((domain) => domain.domain)).toEqual([
      "dependencies",
      "appsec",
      "data",
      "delivery",
      "serverless",
      "api",
      "reliability",
      "deadcode",
    ]);
  });
});

describe("the methodology mapping", () => {
  test("names the framework and the units that were enumerated for appsec", () => {
    const model = buildReportModel(input());
    const appsec = model.domains.find((domain) => domain.domain === "appsec");
    expect(appsec?.mapping).toContain("next (app router)");
    expect(appsec?.mapping).toContain("40 route handlers");
    expect(appsec?.mapping).toContain("20 unsafe-input sinks");
  });

  test("says delivery had nothing to read when container, CI and IaC are all absent", () => {
    const model = buildReportModel(input());
    const delivery = model.domains.find((domain) => domain.domain === "delivery");
    expect(delivery?.mapping).toContain("No Dockerfile");
    expect(delivery?.mapping).toContain("nothing to read");
    // A step that "ran" and found no Dockerfile must not be sold as a review of
    // a delivery pipeline.
    expect(delivery?.mapping).not.toContain("definitions were linted");
  });

  test("D6 and D7 name the units their own batch series audits", () => {
    // They used to print "the full endpoint matrix is a later milestone" and
    // "not yet a phase of its own" — sentences that were true before the D6 and
    // D7 prompts existed, and that turned a section holding a real audit of
    // every handler into what reads as an empty heading.
    const model = buildReportModel(input());
    const api = model.domains.find((domain) => domain.domain === "api");
    const reliability = model.domains.find((domain) => domain.domain === "reliability");

    for (const mapping of [api?.mapping, reliability?.mapping]) {
      expect(mapping).toBeDefined();
      expect(mapping).not.toContain("later milestone");
      expect(mapping).not.toContain("Not yet a phase");
      // The units are named, which is what makes the sentence a method and not
      // a promise: both domains audit the route handlers this fixture holds.
      expect(mapping).toContain("40 route handlers");
      expect(mapping).toContain("section 4");
    }
    // The kinds come from the registry, so D7 names the cron this fixture has
    // and D6, which does not audit a cron, does not.
    expect(reliability?.mapping).toContain("1 scheduled job");
    expect(api?.mapping).not.toContain("1 scheduled job");
  });

  test("counts one of something in the singular", () => {
    const model = buildReportModel(input());
    const serverless = model.domains.find((domain) => domain.domain === "serverless");
    expect(serverless?.mapping).toContain("1 scheduled job and 1 webhook receiver");
    expect(unitCount("cron", 1)).toBe("1 scheduled job");
    expect(unitCount("cron", 4)).toBe("4 scheduled jobs");
  });
});

describe("coverage lines", () => {
  test("carries the `40/40 route handlers` line, per unit kind", () => {
    const model = buildReportModel(input());
    const appsec = model.domains.find((domain) => domain.domain === "appsec");
    expect(appsec?.units.map((unit) => `${unit.audited}/${unit.total} ${unit.label}`)).toEqual([
      "40/40 route handlers",
      "5/8 role gates",
    ]);
  });

  test("collapses repeated skip reasons into one line with a count", () => {
    const model = buildReportModel(input());
    const gates = model.domains
      .find((domain) => domain.domain === "appsec")
      ?.units.find((unit) => unit.kind === "role-gate");
    expect(gates?.skipped).toEqual([
      { reason: "inconclusive: the agent declined to decide", units: 2 },
      { reason: "inconclusive: Sentinel mismatch", units: 1 },
    ]);
  });

  test("a domain that owns no unit kind still gets a row, from its own coverage", () => {
    // `route` is attributed to the batches that audited it, so a second domain
    // auditing the same handlers — `api` and `reliability` do, asking different
    // questions — owned no rows and rendered as a chip with nothing under it,
    // while its own line claimed units had gone un-audited.
    const model = buildReportModel(input());
    const data = model.domains.find((domain) => domain.domain === "data");
    expect(data?.units).toEqual([
      {
        label: "Data layer units",
        total: 50,
        audited: 45,
        skipped: [{ reason: "inconclusive: the agent declined to decide", units: 1 }],
      },
    ]);
  });

  test("the fallback row carries the domain's own totals, not the global per-kind ones", () => {
    // The whole reason for a domain-wide row: repeating `40 of 40 route
    // handlers` under a domain whose own line says 45 of 50 would have the
    // table contradict the sentence two inches above it.
    const model = buildReportModel(input());
    const data = model.domains.find((domain) => domain.domain === "data");
    expect(data?.units[0]?.kind).toBeUndefined();
    expect(data?.units[0]?.total).toBe(data?.coverage?.unitsTotal);
    expect(data?.units[0]?.audited).toBe(data?.coverage?.unitsAudited);
  });

  test("a domain with no units at all still gets no row", () => {
    // The fallback fills a gap; it does not invent a table for a domain that
    // enumerated nothing.
    const model = buildReportModel(input());
    const reliability = model.domains.find((domain) => domain.domain === "reliability");
    expect(reliability?.units).toEqual([]);
  });

  test("attaches each analyzer to the domains it reports into", () => {
    const model = buildReportModel(input());
    const steps = (name: string) =>
      model.domains.find((domain) => domain.domain === name)?.steps.map((step) => step.step);
    expect(steps("dependencies")).toEqual(["trivy", "knip"]);
    expect(steps("delivery")).toEqual(["trivy", "hadolint"]);
    expect(steps("deadcode")).toEqual(["knip"]);
    // An analyzer this table has never heard of is not silently attributed.
    expect(steps("appsec")).toEqual([]);
    expect(model.appendix.steps.map((step) => step.step)).toContain("future-analyzer");
  });

  test("declined and not-applicable checks land on their domain", () => {
    const model = buildReportModel(input());
    const delivery = model.domains.find((domain) => domain.domain === "delivery");
    expect(delivery?.notApplicable).toEqual([
      "No infrastructure-as-code: `trivy config` has nothing to scan beyond containers.",
    ]);
  });
});

describe("severity and priorities", () => {
  test("counts every severity, zeros included", () => {
    const model = buildReportModel(input());
    expect(model.severity).toEqual({
      counts: { critical: 0, high: 0, medium: 2, low: 1, info: 1 },
      total: 4,
    });
  });

  test("sorts findings worst first, then by file and line", () => {
    const model = buildReportModel(input());
    expect(model.findings.map((f) => f.severity)).toEqual(["medium", "medium", "low", "info"]);
  });

  test("tiers are severity and nothing else, and an empty tier still exists", () => {
    const model = buildReportModel(input());
    expect(model.priorities.map((group) => [group.id, group.findings.length])).toEqual([
      ["P1", 0],
      ["P2", 2],
      ["P3", 2],
    ]);
    expect(model.priorities[0]?.rule).toContain("Critical and high");
  });
});

describe("assurances", () => {
  test("prefers the assurances the caller read from assurances.json", () => {
    const model = buildReportModel(input());
    expect(model.assurances).toHaveLength(2);
    expect(model.unitsAssured).toBe(36);
  });

  test("falls back to the ones inside findings.json", () => {
    const model = buildReportModel({
      findings: document(),
      run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
    });
    expect(model.assurances).toHaveLength(1);
  });

  test("groups them onto their domain", () => {
    const model = buildReportModel(input());
    expect(model.domains.find((domain) => domain.domain === "data")?.assurances).toHaveLength(1);
  });
});

describe("run metadata", () => {
  test("shortens the commit and states the tree's condition", () => {
    expect(buildReportModel(input()).commitLabel).toBe("9f2c41ab7d3e (main, working tree clean)");
  });

  test("an absent commit is recorded as absent, not omitted", () => {
    const model = buildReportModel({
      findings: document(),
      run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
    });
    expect(model.commitLabel).toBe("not recorded");
  });

  test("a dirty tree says so, because the dossier is about a commit", () => {
    const model = buildReportModel({
      findings: document(),
      run: {
        generatedAt: new Date("2026-03-04T09:30:00Z"),
        commit: { sha: "abcdef1234567890", dirty: true },
      },
    });
    expect(model.commitLabel).toBe("abcdef123456 (uncommitted changes present)");
  });

  test("the scope summary counts what was on, accepted and not applicable", () => {
    const model = buildReportModel(input());
    expect(model.scopeSummary).toContain("6 of 8 domains in scope");
    expect(model.scopeSummary).toContain("1 optional check accepted");
    expect(model.scopeSummary).toContain("1 check not applicable");
  });

  test("the repository name comes from the analysed path", () => {
    expect(buildReportModel(input()).repository).toBe("example-api");
  });

  test("a whole-repository run carries no scope callout", () => {
    expect(buildReportModel(input()).analysisScope).toBeNull();
    expect(
      buildReportModel({
        ...input(),
        analysisScope: buildAnalysisScope({
          runId: "r",
          target: "/repo",
          paths: [],
          selectors: [],
          unmatched: [],
          units: { total: 200, inScope: 200, outOfScope: 0, byKind: [] },
          unscopedPhases: [],
          findingsOutside: 0,
        }),
      }).analysisScope,
    ).toBeNull();
  });

  test("a scoped run puts the subtree in front of the negotiated scope, and on the cover", () => {
    const model = buildReportModel({
      ...input(),
      analysisScope: buildAnalysisScope({
        runId: "r",
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
        findingsOutside: 12,
      }),
    });
    // The cover renders this as its own callout; `null` is what turns it off.
    expect(model.analysisScope).toContain("This run analysed `apps/api` (300 units)");
    expect(model.analysisScope).toContain("the other 4,700 units");
    // The scope line leads with the subtree: the fraction of the repository a
    // run covered outranks the list of domains it covered it with.
    expect(model.scopeSummary.startsWith("`apps/api` only — 300 of 5000 units")).toBe(true);
    expect(model.scopeSummary).toContain("domains in scope");
  });
});

describe("the appendix", () => {
  test("discloses the audit runtime and the verification it performed", () => {
    const model = buildReportModel(input());
    const labels = model.appendix.agent.map((row) => row.label);
    expect(labels).toContain("Runtime");
    expect(labels).toContain("Tokens");
    expect(model.appendix.verification.map((row) => row.value).join(" ")).toContain("2 duplicates");
    expect(model.appendix.batches).toHaveLength(3);
  });

  test("a synthetic run is labelled as one, everywhere it matters", () => {
    const model = buildReportModel({
      ...input(),
      audit: audit({
        runtime: {
          kind: "fixture",
          concurrency: 1,
          maxAttempts: 1,
          timeoutMs: 1000,
          synthetic: true,
        },
      }),
    });
    expect(model.synthetic).toBe(true);
    expect(model.appendix.agent.map((row) => row.label)).toContain("Synthetic run");
  });
});

describe("a run with nothing but findings.json", () => {
  test("still builds, and claims nothing it cannot support", () => {
    const model = buildReportModel({
      findings: document(),
      run: { generatedAt: new Date("2026-03-04T09:30:00Z") },
    });
    // With no scope artifact the coverage rows are the scope: a domain with a
    // row is claimed, a domain without one is not.
    expect(
      model.domains.filter((domain) => domain.assessment === "not-assessed").map((d) => d.domain),
    ).toEqual(["reliability"]);
    expect(model.domains.find((domain) => domain.domain === "api")?.assessment).toBe(
      "out-of-scope",
    );
    expect(model.stack.rows).toEqual([]);
    expect(model.appendix.steps).toEqual([]);
    expect(model.scorecard.present).toBe(false);
    expect(model.scopeSummary).toContain("no scope negotiation was recorded");
  });
});

describe("a domain the evidence, not the checks, held back", () => {
  /** Phase 6's sentence for a data layer with one check that ran and no unit examined. */
  const NOTE =
    "not assessed: 4,000 data-access call sites and 500 migrations exist and none of them were " +
    "audited in this run, so nothing examined this domain's evidence; 1 of 1 check ran, and a " +
    "check that ran is not a unit that was looked at";

  /** The same run, but with the data layer at 1/1 checks and phase 6 refusing it. */
  function withEvidenceNote(): ScorecardInput {
    const base = scorecard();
    const rows: readonly DomainScore[] = "domains" in base ? base.domains : base;
    const domains: DomainScore[] = rows.map((row) =>
      row.domain === "data"
        ? {
            ...row,
            score: 0,
            band: "",
            status: "not-assessed" as const,
            coverage: 0,
            evidenceNote: NOTE,
          }
        : row,
    );
    return { domains };
  }

  test("prints phase 6's reason instead of a sentence built from the misleading fraction", () => {
    const model = buildReportModel({ ...input(), scorecard: withEvidenceNote() });
    const data = model.domains.find((domain) => domain.domain === "data");
    expect(data?.assessment).toBe("insufficient");
    expect(data?.statusSentence).toContain("4,000 data-access call sites and 500 migrations exist");
    expect(data?.statusSentence).toContain("a check that ran is not a unit that was looked at.");
    // The sentence the report would otherwise have produced, which is the lie.
    expect(data?.statusSentence).not.toContain("too little of this domain");
  });

  test("raises the first letter and ends the sentence, so it reads as prose", () => {
    const model = buildReportModel({ ...input(), scorecard: withEvidenceNote() });
    const sentence = model.domains.find((domain) => domain.domain === "data")?.statusSentence ?? "";
    expect(sentence.startsWith("Not assessed:")).toBe(true);
    expect(sentence.endsWith(".")).toBe(true);
  });

  test("leaves every other domain's sentence alone", () => {
    const model = buildReportModel({ ...input(), scorecard: withEvidenceNote() });
    const delivery = model.domains.find((domain) => domain.domain === "delivery");
    expect(delivery?.statusSentence).toContain("1 of 5 planned checks completed (20%)");
  });
});

describe("evidenceNote", () => {
  test("passes undefined and blank through, so the caller can fall back with one ??", () => {
    expect(evidenceNote(undefined)).toBeUndefined();
    expect(evidenceNote("   ")).toBeUndefined();
  });

  test("does not add a second full stop", () => {
    expect(evidenceNote("nobody looked.")).toBe("Nobody looked.");
  });
});

describe("the volume policy reaches the PDF", () => {
  /** One domain, one rule, `count` low findings across `count` files. */
  function flood(count: number) {
    return Array.from({ length: count }, (_, index) =>
      finding({
        id: `dead-${index}`,
        domain: "deadcode",
        rule: "deadcode.unused-export",
        severity: "low",
        title: `Unused export candidate: symbol${index}`,
        location: { file: `src/generated/module-${index}.ts`, line: 1, snippet: "> 1 | export {}" },
        source: { kind: "tool", name: "knip" },
      }),
    );
  }

  test("a rule over the threshold is a counted group, not 400 blocks", () => {
    const model = buildReportModel({
      ...input(),
      findings: document({ findings: [finding(), ...flood(418)] }),
    });
    const deadcode = model.domains.find((domain) => domain.domain === "deadcode");

    expect(deadcode?.findings).toHaveLength(418);
    // This is the whole repair: what section 5 prints individually.
    expect(deadcode?.ungrouped).toHaveLength(0);
    expect(deadcode?.volumeGroups).toHaveLength(1);
    expect(deadcode?.volumeGroups[0]?.count).toBe(418);
    expect(deadcode?.volumeGroups[0]?.examples).toHaveLength(5);
    expect(deadcode?.volumeGroups[0]?.hidden).toBe(413);
    // Nothing was dropped from the model, only from the rendering.
    expect(model.findings.filter((f) => f.domain === "deadcode")).toHaveLength(418);
  });

  test("the PDF collapses exactly what report.md collapses", () => {
    const findings = [finding(), ...flood(418)];
    const model = buildReportModel({ ...input(), findings: document({ findings }) });
    expect(model.volume.groups.map((group) => group.key)).toEqual(
      planVolume(findings).groups.map((group) => group.key),
    );
  });

  test("a tier counts its collapsed members instead of listing them", () => {
    const model = buildReportModel({
      ...input(),
      findings: document({ findings: [finding(), ...flood(418)] }),
    });
    const housekeeping = model.priorities.find((group) => group.id === "P3");
    expect(housekeeping?.hidden).toBe(413);
    expect(housekeeping?.findings).toHaveLength(5);
    // The band prints `findings.length + hidden`, which must be the whole tier.
    expect((housekeeping?.findings.length ?? 0) + (housekeeping?.hidden ?? 0)).toBe(418);
  });

  test("below the threshold nothing is collapsed and every finding is its own block", () => {
    const model = buildReportModel(input());
    expect(model.volume.groups).toEqual([]);
    for (const domain of model.domains) {
      expect(domain.ungrouped).toEqual(domain.findings);
      expect(domain.volumeGroups).toEqual([]);
    }
    for (const group of model.priorities) expect(group.hidden).toBe(0);
  });

  test("P1 is never collapsed, whatever the volume", () => {
    const criticals = Array.from({ length: 60 }, (_, index) =>
      finding({
        id: `crit-${index}`,
        domain: "appsec",
        rule: "appsec.injection.sql-built-from-variables",
        severity: "critical",
        location: { file: `src/db/query-${index}.ts`, line: 3, snippet: "> 3 | db.query(sql)" },
      }),
    );
    const model = buildReportModel({ ...input(), findings: document({ findings: criticals }) });
    expect(model.volume.groups).toEqual([]);
    expect(model.priorities.find((group) => group.id === "P1")?.findings).toHaveLength(60);
    expect(model.priorities.find((group) => group.id === "P1")?.hidden).toBe(0);
  });
});

describe("a human review reaching the model", () => {
  test("an unreviewed run carries null, which is what renders as no review at all", () => {
    expect(buildReportModel(input()).triage).toBeNull();
  });

  test("a reviewed run carries the summary the sections print", () => {
    const raw = document();
    const applied = applyTriage(
      raw,
      TriageDocumentSchema.parse({
        schemaVersion: "1.0",
        reviewer: "manual verification, 2026-03-04",
        verdicts: [
          {
            id: "12af78bef6b64800",
            rule: "appsec.missing-rate-limit",
            file: "src/api/sessions.ts",
            line: 26,
            reportedSeverity: "medium",
            verdict: "true",
            note: "Confirmed: there is no limiter in front of the credential check.",
          },
        ],
      }),
    );
    const model = buildReportModel({
      ...input(),
      findings: applied.document,
      triage: applied.summary,
    });
    expect(model.triage?.confirmed).toHaveLength(1);
    expect(model.triage?.statement).toContain("1 of");
    // The findings the model renders are the adjusted ones, so nothing in the
    // document can disagree with the review about what is in it.
    expect(model.findings).toHaveLength(applied.document.findings.length);
  });
});

describe("the cover's account of an audit that stopped early", () => {
  /**
   * An audit can stop early without a budget having stopped it: a quota running
   * out ends the run just as a ceiling does. The cover headlined every early
   * stop "The audit stopped at its budget", which points the reader at a limit
   * nobody set, so the stop reason — not just the fact of it — reaches the model.
   */
  test("carries the reason the audit stopped, not just that it did", () => {
    const stopped = buildReportModel({
      ...input(),
      audit: audit({
        bound: {
          ...unboundedBound(1000, 600),
          stop: "quota",
          statement: "400 of 1,000 units were not audited: the usage limit was reached",
        },
      }),
    });
    expect(stopped.auditStoppedEarly).toBe(true);
    expect(stopped.auditStop).toBe("quota");
    // A statement a machine composed does not end in a full stop, and the cover
    // appends another sentence to it: "...with a verdict The units that were..."
    expect(stopped.auditBound?.endsWith("reached")).toBe(true);

    const clean = buildReportModel(input());
    expect(clean.auditStoppedEarly).toBe(false);
    expect(clean.auditStop).toBe("complete");
  });
});

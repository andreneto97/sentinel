import { describe, expect, test } from "bun:test";
import { DomainSchema, type FindingsDocument, SCHEMA_VERSION } from "../contracts/findings.ts";
import type { Domain } from "../contracts/findings.ts";
import {
  assurance,
  auditSignals,
  coverage,
  evidenceInput,
  finding,
  findings,
  inventorySignals,
  scanSignals,
} from "./__fixtures__/factories.ts";
import { buildScorecard, buildScorecardFromArtifacts, scoreDomain } from "./scorecard.ts";

/** The row for one domain, which is what most of these assertions are about. */
function row(card: ReturnType<typeof buildScorecard>, domain: Domain) {
  const found = card.domains.find((candidate) => candidate.domain === domain);
  if (found === undefined) throw new Error(`no row for ${domain}`);
  return found;
}

describe("buildScorecard", () => {
  test("gives every domain in the contract a row, in the contract's order", () => {
    const card = buildScorecard({
      runId: "r1",
      target: "/repo",
      findings: [],
      assurances: [],
      coverage: [],
    });
    expect(card.domains.map((domainRow) => domainRow.domain)).toEqual([...DomainSchema.options]);
    expect(card.schemaVersion).toBe(SCHEMA_VERSION);
    expect(card.runId).toBe("r1");
    expect(card.target).toBe("/repo");
  });

  test("scores a fully covered, clean domain at 100 and an unchecked one at nothing", () => {
    const card = buildScorecard({
      runId: "r1",
      target: "/repo",
      findings: [],
      assurances: [],
      coverage: [coverage({ domain: "appsec", unitsTotal: 20, unitsAudited: 20 })],
      scope: ["appsec", "data"],
    });

    expect(row(card, "appsec").score).toBe(100);
    expect(row(card, "appsec").band).toBe("A");

    const data = row(card, "data");
    expect(data.status).toBe("not-assessed");
    expect(data.score).toBeNull();
    expect(data.band).toBeNull();
    expect(data.bandLabel).toBeNull();
    expect(data.baseScore).toBeNull();
    expect(data.effectiveWeight).toBe(0);
    expect(data.statement).toContain("not assessed");
  });

  test("refuses a number for a domain with findings but no coverage, and keeps the findings", () => {
    const card = buildScorecard({
      runId: "r1",
      target: "/repo",
      findings: findings(10, { domain: "api", severity: "low", id: "api" }),
      assurances: [],
      coverage: [coverage({ domain: "appsec" })],
      scope: ["appsec"],
    });

    const api = row(card, "api");
    expect(api.status).toBe("not-assessed");
    expect(api.score).toBeNull();
    expect(api.findingsTotal).toBe(10);
    expect(api.findingsBySeverity.low).toBe(10);
    expect(api.statement).toContain("outside this run's scope");
    expect(api.statement).toContain("10 findings were reported for it anyway");
    expect(card.overall.unscored.find((entry) => entry.domain === "api")?.findingsTotal).toBe(10);
  });

  test("states the coverage next to the number when the domain is only partly covered", () => {
    const card = buildScorecard({
      runId: "r1",
      target: "/repo",
      findings: [],
      assurances: [],
      coverage: [coverage({ domain: "data", unitsTotal: 10, unitsAudited: 6 })],
    });
    const data = row(card, "data");
    expect(data.status).toBe("partial");
    expect(data.score).toBe(100);
    expect(data.statement).toContain("6 of 10 checks ran");
  });

  test("carries a hard ceiling through to the domain's number and its sentence", () => {
    const secret = finding({
      id: "secret-1",
      domain: "appsec",
      rule: "appsec.hardcoded-secret",
      severity: "critical",
      title: "Hardcoded cloud provider credential in src/lib/aws.ts",
      location: { file: "src/lib/aws.ts", line: 12 },
      source: { kind: "tool", name: "gitleaks" },
    });
    const card = buildScorecard({
      runId: "r1",
      target: "/repo",
      findings: [secret],
      assurances: [],
      coverage: [coverage({ domain: "appsec" })],
    });

    const appsec = row(card, "appsec");
    expect(appsec.baseScore).toBe(75);
    expect(appsec.score).toBe(50);
    expect(appsec.band).toBe("D");
    expect(appsec.ceilings[0]?.binding).toBe(true);
    expect(appsec.statement).toContain("capped at 50");
  });

  test("counts assurances and never pays points for them", () => {
    const base = {
      runId: "r1",
      target: "/repo",
      findings: [finding({ domain: "appsec", severity: "high" })],
      coverage: [coverage({ domain: "appsec" })],
    };
    const without = buildScorecard({ ...base, assurances: [] });
    const with_ = buildScorecard({
      ...base,
      assurances: [assurance(), assurance({ check: "input is validated", unitsChecked: 7 })],
    });

    expect(row(with_, "appsec").score).toBe(row(without, "appsec").score);
    expect(row(with_, "appsec").assurances).toBe(2);
    expect(row(with_, "appsec").assuranceUnits).toBe(17);
  });

  test("itemises the arithmetic that produced the number", () => {
    const card = buildScorecard({
      runId: "r1",
      target: "/repo",
      findings: [
        ...findings(2, { domain: "data", severity: "medium", id: "m" }),
        ...findings(7, { domain: "data", severity: "low", id: "l" }),
      ],
      assurances: [],
      coverage: [coverage({ domain: "data" })],
    });
    const data = row(card, "data");
    expect(data.deductions.map((deduction) => deduction.severity)).toEqual(["medium", "low"]);
    expect(data.deductionTotal).toBe(24);
    expect(data.baseScore).toBe(76);
    expect(data.deductions[1]?.capped).toBe(true);
  });

  test("is deterministic: the same input produces byte-identical documents", () => {
    const input = {
      runId: "r1",
      target: "/repo",
      findings: findings(5, { domain: "appsec", severity: "medium", id: "x" }),
      assurances: [assurance()],
      coverage: [coverage({ domain: "appsec", unitsTotal: 9, unitsAudited: 7 })],
    };
    expect(JSON.stringify(buildScorecard(input))).toBe(JSON.stringify(buildScorecard(input)));
  });

  test("defaults to a high-confidence run only when nothing says otherwise", () => {
    const card = buildScorecard({
      runId: "r1",
      target: "/repo",
      findings: [],
      assurances: [],
      coverage: [coverage({ domain: "appsec" })],
    });
    expect(card.confidence.level).toBe("high");
    expect(card.confidence.signals).toEqual([]);
  });
});

describe("scoreDomain", () => {
  test("keeps a ceiling on a not-assessed domain visible without inventing a number", () => {
    const scored = scoreDomain({
      domain: "appsec",
      findings: [
        finding({
          id: "secret-1",
          domain: "appsec",
          rule: "appsec.hardcoded-secret",
          severity: "critical",
          source: { kind: "tool", name: "gitleaks" },
        }),
      ],
      assurances: [],
      coverage: coverage({ domain: "appsec", unitsTotal: 5, unitsAudited: 1 }),
      inScope: true,
    });
    expect(scored.status).toBe("not-assessed");
    expect(scored.score).toBeNull();
    expect(scored.ceilings).toHaveLength(1);
    expect(scored.ceilings[0]?.binding).toBe(false);
  });
});

describe("buildScorecardFromArtifacts", () => {
  test("derives confidence from what the phases recorded, and scores the document", () => {
    const document: FindingsDocument = {
      schemaVersion: SCHEMA_VERSION,
      runId: "r2",
      target: "/repo",
      findings: findings(3, { domain: "appsec", severity: "medium", id: "a" }),
      assurances: [assurance()],
      coverage: [coverage({ domain: "appsec", unitsTotal: 10, unitsAudited: 10 })],
      droppedFindings: 0,
    };

    const clean = buildScorecardFromArtifacts({
      document,
      audit: auditSignals(),
      scan: scanSignals(),
      scope: ["appsec"],
    });
    expect(clean.confidence.level).toBe("high");
    expect(clean.runId).toBe("r2");
    expect(row(clean, "appsec").score).toBe(82);
    expect(clean.findingsTotal).toBe(3);
    expect(clean.assurancesTotal).toBe(1);

    const degraded = buildScorecardFromArtifacts({
      document,
      audit: auditSignals({
        units: {
          total: 40,
          audited: 30,
          skipped: 10,
          byCause: {
            "no-batch": 0,
            "batch-failed": 0,
            "no-verdict": 0,
            inconclusive: 10,
            cancelled: 0,
            budget: 0,
          },
        },
      }),
      scan: scanSignals(),
    });
    expect(degraded.confidence.level).toBe("medium");
    // The score is about the code; the confidence is about the run.
    expect(row(degraded, "appsec").score).toBe(row(clean, "appsec").score);
  });
});

// ---------------------------------------------------------------------------
// The defect: a domain scored 100 (A) with nothing audited
// ---------------------------------------------------------------------------

/**
 * A repository whose inventory dwarfs the checks planned over it.
 *
 * Phase 1 plans one data-layer analyzer step and it runs. Phase 2 enumerates
 * thousands of data-layer units. Phase 4 is never asked to look at one of them.
 * The appsec kinds are here too, because they are the other half of the rule: the
 * findings a deterministic run *does* produce are evidence of problems, and they
 * must keep lowering the score even though nothing certifies the domain.
 */
const LARGE_REPO_UNITS = {
  route: 300,
  "data-access": 4000,
  "queue-consumer": 10,
  webhook: 20,
  migration: 500,
  sink: 400,
  "workflow-job": 30,
} as const;

/** Phase 4 having audited every one of those units, which is the other direction. */
const EVERY_UNIT_AUDITED = {
  kinds: Object.entries(LARGE_REPO_UNITS).map(([kind, count]) => ({
    kind: kind as keyof typeof LARGE_REPO_UNITS,
    unitsTotal: count,
    unitsAudited: count,
    skipped: [],
  })),
};

/** The `--no-ai` run: every planned check ran, no unit was ever examined. */
function noAiCard(domainFindings: readonly ReturnType<typeof finding>[] = []) {
  return buildScorecard({
    runId: "example-api",
    target: "/repo",
    findings: domainFindings,
    assurances: [],
    coverage: [
      coverage({ domain: "dependencies", unitsTotal: 3, unitsAudited: 3 }),
      coverage({ domain: "appsec", unitsTotal: 2, unitsAudited: 2 }),
      coverage({ domain: "data", unitsTotal: 1, unitsAudited: 1 }),
      coverage({ domain: "delivery", unitsTotal: 5, unitsAudited: 5 }),
    ],
    scope: ["dependencies", "appsec", "data", "delivery"],
    evidence: evidenceInput(LARGE_REPO_UNITS),
  });
}

describe("deterministic analysis can lower a score but cannot certify one", () => {
  test("a domain with thousands of units and no verdicts no longer scores 100 (A)", () => {
    const card = noAiCard();
    const data = row(card, "data");
    // What the bug produced: score 100, band A, "1 of 1 check ran (100%)".
    expect(data.coverage.statement).toBe("1 of 1 check ran");
    expect(data.coverage.ratio).toBe(1);
    // What it produces now.
    expect(data.status).toBe("not-assessed");
    expect(data.score).toBeNull();
    expect(data.band).toBeNull();
    expect(data.assessedRatio).toBe(0);
  });

  test("and the reason is specific enough to act on", () => {
    const data = row(noAiCard(), "data");
    expect(data.statement).toContain("4,000 data-access call sites and 500 migrations exist");
    expect(data.statement).toContain("none of them were audited in this run");
    expect(data.statement).toContain("a check that ran is not a unit that was looked at");
  });

  test("the units it did not examine are counted, not hidden", () => {
    const data = row(noAiCard(), "data");
    expect(data.evidence.unitsPresent).toBe(4500);
    expect(data.evidence.unitsVerdicted).toBe(0);
    expect(data.evidence.kinds).toEqual([
      { kind: "data-access", present: 4000, verdicted: 0 },
      { kind: "migration", present: 500, verdicted: 0 },
    ]);
  });

  test("findings still lower a domain to F, because they are evidence of problems", () => {
    const appsecFindings = [
      ...findings(70, { domain: "appsec", severity: "critical", id: "crit" }),
      ...findings(30, { domain: "appsec", severity: "high", id: "high" }),
    ];
    const appsec = row(noAiCard(appsecFindings), "appsec");
    expect(appsec.findingsTotal).toBe(100);
    expect(appsec.status).toBe("partial");
    expect(appsec.score).toBe(0);
    expect(appsec.band).toBe("F");
    expect(appsec.statement).toContain("evidence of problems, not of health");
  });

  test("a clean domain nobody audited cannot climb past band C even with one finding", () => {
    const card = noAiCard([finding({ id: "only", domain: "data", severity: "info" })]);
    const data = row(card, "data");
    expect(data.baseScore).toBe(100);
    expect(data.score).toBe(74);
    expect(data.band).toBe("C");
    expect(data.ceilings.map((ceiling) => ceiling.id)).toEqual(["evidence.unexamined-units"]);
    expect(data.ceilings[0]?.binding).toBe(true);
  });

  test("a domain judged by tools rather than units is untouched", () => {
    const dependencies = row(noAiCard(), "dependencies");
    expect(dependencies.status).toBe("scored");
    expect(dependencies.score).toBe(100);
    expect(dependencies.evidence.applies).toBe(false);
    expect(dependencies.assessedRatio).toBe(1);
  });

  test("a domain outside the scope still discloses the units nobody looked at", () => {
    const serverless = row(noAiCard(), "serverless");
    expect(serverless.status).toBe("not-assessed");
    expect(serverless.evidence.unitsPresent).toBe(30);
    expect(serverless.statement).toContain("20 webhook receivers and 10 queue consumers");
  });

  test("the other direction: a full run that examined every unit and found nothing earns an A", () => {
    const card = buildScorecard({
      runId: "full",
      target: "/repo",
      findings: [],
      assurances: [],
      coverage: DomainSchema.options.map((domain) =>
        coverage({ domain, unitsTotal: 40, unitsAudited: 40 }),
      ),
      scope: [...DomainSchema.options],
      evidence: evidenceInput(LARGE_REPO_UNITS, EVERY_UNIT_AUDITED),
    });
    for (const domain of DomainSchema.options) {
      const scored = row(card, domain);
      expect(scored.status).toBe("scored");
      expect(scored.score).toBe(100);
      expect(scored.band).toBe("A");
      expect(scored.ceilings).toEqual([]);
    }
    expect(card.overall.score).toBe(100);
    expect(card.overall.band).toBe("A");
  });

  test("an unexamined domain carries no weight into the mean, but still clamps it", () => {
    const card = noAiCard(findings(4, { domain: "appsec", severity: "critical", id: "c" }));
    const appsec = row(card, "appsec");
    // Four criticals, capped at the tier's 60 points: a real number, arrived at
    // by findings alone, over units nobody examined.
    expect(appsec.score).toBe(40);
    // It weighs nothing, because there is no examined evidence to weigh...
    expect(appsec.effectiveWeight).toBe(0);
    // ...and it still sets the ceiling on the run, because 4 criticals are not
    // averaged away by a healthy supply chain.
    expect(card.overall.clamp?.worstDomain).toBe("appsec");
    expect(card.overall.clamp?.applied).toBe(true);
    expect(card.overall.score).toBe(55);
  });
});

describe("buildScorecardFromArtifacts, with an inventory", () => {
  const document: FindingsDocument = {
    schemaVersion: SCHEMA_VERSION,
    runId: "r3",
    target: "/repo",
    findings: [],
    assurances: [],
    coverage: [coverage({ domain: "data", unitsTotal: 1, unitsAudited: 1 })],
    droppedFindings: 0,
  };

  test("reads the denominator out of inventory.json on a run with no audit", () => {
    const card = buildScorecardFromArtifacts({
      document,
      scan: scanSignals(),
      inventory: inventorySignals({ migration: 500, "data-access": 4000 }),
      scope: ["data"],
    });
    expect(row(card, "data").score).toBeNull();
    expect(row(card, "data").evidence.unitsPresent).toBe(4500);
  });

  test("without an inventory it cannot know, and says only what the checks said", () => {
    const card = buildScorecardFromArtifacts({ document, scan: scanSignals(), scope: ["data"] });
    expect(row(card, "data").score).toBe(100);
    expect(row(card, "data").evidence.applies).toBe(false);
  });
});

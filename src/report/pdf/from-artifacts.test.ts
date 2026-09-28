import { describe, expect, test } from "bun:test";
import type { RunArtifacts } from "../../cli/_shared/run-artifacts.ts";
import type { FindingsDocument } from "../../contracts/findings.ts";
import { reportInputFromRunArtifacts, runIdTimestamp } from "./from-artifacts.ts";

/** `findings.json` as the loader hands it over. */
function findings(): FindingsDocument {
  return {
    schemaVersion: "1.0",
    runId: "20260304T093000-9f2c41ab",
    target: "/workspace/example-api",
    findings: [],
    assurances: [
      {
        id: "in-findings",
        domain: "appsec",
        check: "from findings.json",
        scope: "1/1 route handlers",
        unitsChecked: 1,
        evidence: [],
      },
    ],
    coverage: [],
    droppedFindings: 0,
  };
}

/** A run directory where only phase 1 left anything behind. */
function artifacts(overrides: Partial<RunArtifacts> = {}): RunArtifacts {
  return {
    runDir: "/workspace/example-api/sentinel/20260304T093000-9f2c41ab",
    runId: "20260304T093000-9f2c41ab",
    target: "/workspace/example-api",
    findings: findings(),
    assurances: null,
    audit: null,
    inventory: null,
    scan: null,
    profile: null,
    scope: null,
    analysisScope: null,
    rendered: [],
    unreadable: [],
    ...overrides,
  };
}

describe("runIdTimestamp", () => {
  test("reads the instant the run id encodes", () => {
    expect(runIdTimestamp("20260304T093000-9f2c41ab")?.toISOString()).toBe(
      "2026-03-04T09:30:00.000Z",
    );
  });

  test("returns nothing for an id that encodes no time", () => {
    expect(runIdTimestamp("not-a-run-id")).toBeUndefined();
    expect(runIdTimestamp("20261332T093000-9f2c41ab")?.toISOString()).not.toBe(
      "2026-13-32T09:30:00.000Z",
    );
  });
});

describe("reportInputFromRunArtifacts", () => {
  test("dates the report from the run id, not from the clock", () => {
    const input = reportInputFromRunArtifacts(artifacts());
    expect(input.run.generatedAt.toISOString()).toBe("2026-03-04T09:30:00.000Z");
  });

  test("an explicit date wins, for a caller that knows better", () => {
    const at = new Date("2027-01-01T00:00:00.000Z");
    expect(reportInputFromRunArtifacts(artifacts(), { generatedAt: at }).run.generatedAt).toBe(at);
  });

  test("leaves out every artifact the run did not produce", () => {
    const input = reportInputFromRunArtifacts(artifacts());
    expect(input.profile).toBeUndefined();
    expect(input.audit).toBeUndefined();
    expect(input.scope).toBeUndefined();
    expect(input.assurances).toBeUndefined();
    expect(input.findings.runId).toBe("20260304T093000-9f2c41ab");
  });

  test("prefers assurances.json over the copy inside findings.json", () => {
    const input = reportInputFromRunArtifacts(
      artifacts({
        assurances: {
          schemaVersion: "1.0",
          runId: "20260304T093000-9f2c41ab",
          target: "/workspace/example-api",
          assurances: [
            {
              id: "in-assurances",
              domain: "data",
              check: "from assurances.json",
              scope: "1/1 migrations",
              unitsChecked: 1,
              evidence: [],
            },
          ],
          coverage: [],
        },
      }),
    );
    expect(input.assurances?.map((entry) => entry.id)).toEqual(["in-assurances"]);
  });

  test("carries the context the run directory cannot know", () => {
    const input = reportInputFromRunArtifacts(artifacts(), {
      commit: { sha: "9f2c41ab7d3e", branch: "main" },
      sentinelVersion: "0.0.1",
      tools: [{ name: "trivy", version: "0.74.0", status: "ok" }],
      scorecard: [
        {
          domain: "appsec",
          score: 74,
          band: "C",
          status: "scored",
          coverage: 0.96,
          confidence: "medium",
        },
      ],
    });
    expect(input.run.commit?.sha).toBe("9f2c41ab7d3e");
    expect(input.run.tools).toHaveLength(1);
    expect(input.scorecard).toBeDefined();
  });

  test("refuses a run directory with no findings.json, by name", () => {
    expect(() => reportInputFromRunArtifacts(artifacts({ findings: null }))).toThrow(
      /findings\.json is missing/,
    );
  });

  test("falls back to the document's target when the loader recorded none", () => {
    expect(reportInputFromRunArtifacts(artifacts({ target: "" })).run.target).toBe(
      "/workspace/example-api",
    );
  });
});

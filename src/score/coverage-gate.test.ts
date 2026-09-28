import { describe, expect, test } from "bun:test";
import { coverage, evidenceInput } from "./__fixtures__/factories.ts";
import {
  PARTIAL_COVERAGE,
  SCORED_COVERAGE,
  gateDomain,
  statusForEvidence,
} from "./coverage-gate.ts";
import { domainEvidence } from "./evidence.ts";

describe("gateDomain", () => {
  test("scores a domain whose checks nearly all ran", () => {
    const result = gateDomain("appsec", coverage({ unitsTotal: 69, unitsAudited: 66 }), true);
    expect(result.status).toBe("scored");
    expect(result.coverage.ratio).toBe(0.9565);
    expect(result.statement).toBe("66 of 69 checks ran (96%)");
  });

  test("scores a thinner domain as partial, with the coverage in the sentence", () => {
    const result = gateDomain(
      "data",
      coverage({ domain: "data", unitsTotal: 10, unitsAudited: 6 }),
      true,
    );
    expect(result.status).toBe("partial");
    expect(result.statement).toContain("6 of 10 checks ran (60%)");
    expect(result.statement).toContain("that fraction only");
  });

  test("refuses a number when one check in five ran", () => {
    const result = gateDomain(
      "delivery",
      coverage({ domain: "delivery", unitsTotal: 5, unitsAudited: 1 }),
      true,
    );
    expect(result.status).toBe("not-assessed");
    expect(result.statement).toContain("only 1 of 5 checks ran (20%)");
    expect(result.statement).toContain("too little to stand behind a number");
  });

  test("refuses a number for a domain whose checks do not exist yet", () => {
    const result = gateDomain(
      "reliability",
      coverage({ domain: "reliability", unitsTotal: 0, unitsAudited: 0 }),
      true,
    );
    expect(result.status).toBe("not-assessed");
    expect(result.coverage.ratio).toBe(0);
    expect(result.statement).toContain("0 of 0");
  });

  test("distinguishes a domain the scope left out from one it kept and lost", () => {
    const outOfScope = gateDomain("api", undefined, false);
    const inScope = gateDomain("api", undefined, true);
    expect(outOfScope.status).toBe("not-assessed");
    expect(inScope.status).toBe("not-assessed");
    expect(outOfScope.statement).toContain("outside this run's scope");
    expect(inScope.statement).toContain("produced no coverage");
  });

  test("holds the thresholds at their boundaries", () => {
    const at = (audited: number, total: number) =>
      gateDomain("appsec", coverage({ unitsTotal: total, unitsAudited: audited }), true).status;
    expect(SCORED_COVERAGE).toBe(0.9);
    expect(PARTIAL_COVERAGE).toBe(0.5);
    expect(at(90, 100)).toBe("scored");
    expect(at(89, 100)).toBe("partial");
    expect(at(50, 100)).toBe("partial");
    expect(at(49, 100)).toBe("not-assessed");
  });

  test("carries the skipped count so a reader can go and read the reasons", () => {
    const row = coverage({
      unitsTotal: 3,
      unitsAudited: 2,
      skipped: [{ unitId: "u1", reason: "inconclusive: the agent declined to decide" }],
    });
    expect(gateDomain("appsec", row, true).coverage.skipped).toBe(1);
  });
});

describe("gateDomain, on examined evidence", () => {
  /** A data layer where one analyzer step ran and thousands of units went unexamined. */
  const dataEvidence = domainEvidence(
    "data",
    evidenceInput({ "data-access": 4000, migration: 500 }),
  );

  test("the bug: one shallow check at 1/1 no longer scores a domain nobody audited", () => {
    const result = gateDomain(
      "data",
      coverage({ domain: "data", unitsTotal: 1, unitsAudited: 1 }),
      true,
      dataEvidence,
      0,
    );
    expect(result.status).toBe("not-assessed");
    expect(result.coverage.ratio).toBe(1);
    expect(result.assessedRatio).toBe(0);
  });

  test("and the reason names the units, not the fraction", () => {
    const result = gateDomain(
      "data",
      coverage({ domain: "data", unitsTotal: 1, unitsAudited: 1 }),
      true,
      dataEvidence,
      0,
    );
    expect(result.statement).toBe(
      "not assessed: 4,000 data-access call sites and 500 migrations exist and none of them were " +
        "audited in this run, so nothing examined this domain's evidence; 1 of 1 check ran, and a " +
        "check that ran is not a unit that was looked at",
    );
  });

  test("findings keep a number alive, as an upper bound rather than a grade", () => {
    const evidence = domainEvidence("appsec", evidenceInput({ route: 300, sink: 400 }));
    const result = gateDomain(
      "appsec",
      coverage({ unitsTotal: 2, unitsAudited: 2 }),
      true,
      evidence,
      117,
    );
    expect(result.status).toBe("partial");
    expect(result.statement).toContain(
      "the 117 findings below are evidence of problems, not of health",
    );
    expect(result.statement).toContain("upper bound rather than a grade");
  });

  test("a domain the scope left out still says what it left out", () => {
    const evidence = domainEvidence(
      "serverless",
      evidenceInput({ "queue-consumer": 8, webhook: 25 }),
    );
    const result = gateDomain("serverless", undefined, false, evidence, 0);
    expect(result.status).toBe("not-assessed");
    expect(result.statement).toContain(
      "25 webhook receivers and 8 queue consumers of its kinds do exist",
    );
    expect(result.statement).toContain("none of them were audited");
  });

  test("an audited domain still scores, and says how much was examined", () => {
    const evidence = domainEvidence(
      "data",
      evidenceInput(
        { "data-access": 95, migration: 8 },
        {
          kinds: [
            { kind: "data-access", unitsTotal: 95, unitsAudited: 87, skipped: [] },
            { kind: "migration", unitsTotal: 8, unitsAudited: 7, skipped: [] },
          ],
        },
      ),
    );
    const result = gateDomain(
      "data",
      coverage({ domain: "data", unitsTotal: 104, unitsAudited: 95 }),
      true,
      evidence,
      9,
    );
    expect(result.status).toBe("scored");
    expect(result.assessedRatio).toBe(0.9126);
    expect(result.statement).toBe("95 of 104 checks ran (91%); 94 of its 103 units were examined");
  });

  test("the examined fraction can lower a status the checks would have allowed", () => {
    const evidence = domainEvidence(
      "data",
      evidenceInput(
        { migration: 100 },
        {
          kinds: [{ kind: "migration", unitsTotal: 100, unitsAudited: 60, skipped: [] }],
        },
      ),
    );
    const result = gateDomain(
      "data",
      coverage({ domain: "data", unitsTotal: 10, unitsAudited: 10 }),
      true,
      evidence,
      0,
    );
    expect(result.status).toBe("partial");
    expect(result.assessedRatio).toBe(0.6);
    expect(result.statement).toContain("60 of its 100 units were examined (60%)");
  });

  test("a domain with no audit units is not penalised for having none", () => {
    const evidence = domainEvidence("dependencies", evidenceInput({ migration: 500 }));
    const result = gateDomain(
      "dependencies",
      coverage({ domain: "dependencies", unitsTotal: 3, unitsAudited: 3 }),
      true,
      evidence,
      27,
    );
    expect(result.status).toBe("scored");
    expect(result.assessedRatio).toBe(1);
    expect(result.statement).toBe("3 of 3 checks ran (100%)");
  });

  test("the checks can still be the binding constraint when the units were all examined", () => {
    const evidence = domainEvidence(
      "delivery",
      evidenceInput(
        { "workflow-job": 4 },
        {
          kinds: [{ kind: "workflow-job", unitsTotal: 4, unitsAudited: 4, skipped: [] }],
        },
      ),
    );
    const result = gateDomain(
      "delivery",
      coverage({ domain: "delivery", unitsTotal: 5, unitsAudited: 1 }),
      true,
      evidence,
      0,
    );
    expect(result.status).toBe("not-assessed");
    expect(result.statement).toContain("only 1 of 5 checks ran (20%)");
    expect(result.statement).toContain("4 CI workflow jobs of its kinds do exist");
  });

  test("holds the evidence thresholds at the same boundaries as the checks", () => {
    const at = (audited: number, findings: number) => {
      const evidence = domainEvidence(
        "data",
        evidenceInput(
          { migration: 100 },
          {
            kinds: [{ kind: "migration", unitsTotal: 100, unitsAudited: audited, skipped: [] }],
          },
        ),
      );
      return gateDomain(
        "data",
        coverage({ domain: "data", unitsTotal: 4, unitsAudited: 4 }),
        true,
        evidence,
        findings,
      ).status;
    };
    expect(at(90, 0)).toBe("scored");
    expect(at(89, 0)).toBe("partial");
    expect(at(50, 0)).toBe("partial");
    expect(at(49, 0)).toBe("not-assessed");
    expect(at(49, 1)).toBe("partial");
    expect(at(0, 1)).toBe("partial");
    expect(at(0, 0)).toBe("not-assessed");
  });
});

describe("statusForEvidence", () => {
  const summary = (present: number, verdicted: number) =>
    domainEvidence(
      "data",
      evidenceInput(
        { migration: present },
        present === 0
          ? undefined
          : {
              kinds: [
                { kind: "migration", unitsTotal: present, unitsAudited: verdicted, skipped: [] },
              ],
            },
      ),
    );

  test("refuses a status it cannot support, and is not swayed by clean findings", () => {
    expect(statusForEvidence(summary(500, 0), 0)).toBe("not-assessed");
    expect(statusForEvidence(summary(500, 500), 0)).toBe("scored");
  });

  test("lets findings buy a partial, because a problem found is still evidence", () => {
    expect(statusForEvidence(summary(500, 0), 3)).toBe("partial");
  });

  test("passes a domain with no units through, because units are not its measure", () => {
    expect(statusForEvidence(summary(0, 0), 0)).toBe("scored");
  });
});

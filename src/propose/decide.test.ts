import { describe, expect, test } from "bun:test";
import type { Proposal, ProposalSet } from "../contracts/proposal.ts";
import { answersFromDecision, buildScopeProposalDocument, decideScope } from "./decide.ts";

function proposal(overrides: Partial<Proposal> & Pick<Proposal, "id">): Proposal {
  return {
    title: `Proposal ${overrides.id}`,
    domain: "delivery",
    detected: { summary: "something was detected", evidence: [] },
    wouldCheck: "would check something",
    cost: { estimatedSeconds: 60, usesAi: false },
    defaultAnswer: "on",
    aliases: [],
    attributes: {},
    ...overrides,
  };
}

const terraform = proposal({
  id: "delivery.iac.terraform",
  aliases: ["terraform", "iac"],
  cost: { estimatedSeconds: 40, usesAi: false, requiresTool: "trivy" },
});
const iam = proposal({
  id: "serverless.iam-audit",
  domain: "serverless",
  aliases: ["iam"],
  cost: { estimatedSeconds: 120, usesAi: true },
});
const migrations = proposal({
  id: "data.deep-migrations",
  domain: "data",
  aliases: ["migrations"],
  defaultAnswer: "off",
  cost: { estimatedSeconds: 300, usesAi: true },
});

const set: ProposalSet = {
  proposals: [terraform, iam, migrations],
  notApplicable: [
    {
      id: "appsec.client-side-authorization",
      domain: "appsec",
      category: "Client-side authorization",
      reason: "No frontend detected.",
      evidence: [],
    },
  ],
};

describe("decideScope", () => {
  test("with no answers at all, every proposal is untouched and therefore off", () => {
    const decision = decideScope(set);
    expect(decision.accepted).toEqual([]);
    expect(decision.declined).toEqual([]);
    expect(decision.untouched.map((entry) => entry.proposal.id)).toEqual([
      "delivery.iac.terraform",
      "serverless.iam-audit",
      "data.deep-migrations",
    ]);
    expect(decision.untouched.every((entry) => entry.source === "unanswered")).toBe(true);
    expect(decision.enabledDomains).toEqual([
      "dependencies",
      "appsec",
      "data",
      "delivery",
      "deadcode",
    ]);
    expect(decision.estimatedExtraSeconds).toBe(0);
    expect(decision.usesAi).toBe(false);
  });

  test("--include takes a proposal id, an alias or a domain name", () => {
    const decision = decideScope(set, { include: ["terraform", "serverless.iam-audit"] });
    expect(decision.accepted.map((entry) => entry.proposal.id)).toEqual([
      "delivery.iac.terraform",
      "serverless.iam-audit",
    ]);
    // Accepting a proposal turns its domain on.
    expect(decision.enabledDomains).toContain("serverless");
    expect(decision.estimatedExtraSeconds).toBe(160);
    expect(decision.usesAi).toBe(true);
  });

  test("a domain selector accepts every proposal in that domain and enables it", () => {
    const decision = decideScope(set, { include: ["serverless"] });
    expect(decision.accepted.map((entry) => entry.proposal.id)).toEqual(["serverless.iam-audit"]);
    expect(decision.enabledDomains).toContain("serverless");
  });

  test("--exclude on a domain removes it even though it is in the base scope", () => {
    const decision = decideScope(set, { exclude: ["data"] });
    expect(decision.enabledDomains).not.toContain("data");
    expect(decision.declined.map((entry) => entry.proposal.id)).toEqual(["data.deep-migrations"]);
  });

  test("--exclude beats --include when both name the same thing", () => {
    const decision = decideScope(set, { include: ["iac"], exclude: ["terraform"] });
    expect(decision.declined.map((entry) => entry.proposal.id)).toEqual(["delivery.iac.terraform"]);
    expect(decision.accepted).toEqual([]);
  });

  test("a selector that matches nothing is reported, not silently dropped", () => {
    const decision = decideScope(set, { include: ["terrafrom"], exclude: ["kubernets"] });
    expect(decision.unknownSelectors).toEqual(["terrafrom", "kubernets"]);
  });

  test("remembered answers from sentinel.config.json decide the rest", () => {
    const decision = decideScope(set, {
      previousAnswers: { "delivery.iac.terraform": "on", "data.deep-migrations": "off" },
    });
    expect(decision.accepted.map((entry) => entry.proposal.id)).toEqual(["delivery.iac.terraform"]);
    expect(decision.declined.map((entry) => entry.proposal.id)).toEqual(["data.deep-migrations"]);
    expect(decision.untouched.map((entry) => entry.proposal.id)).toEqual(["serverless.iam-audit"]);
    expect(decision.accepted[0]?.source).toBe("config");
  });

  test("a flag overrides what the config remembered", () => {
    const decision = decideScope(set, {
      previousAnswers: { "delivery.iac.terraform": "off" },
      include: ["terraform"],
    });
    expect(decision.accepted.map((entry) => entry.proposal.id)).toEqual(["delivery.iac.terraform"]);
    expect(decision.accepted[0]?.source).toBe("flag");
  });

  test("--yes answers every default, and never overrides a remembered answer", () => {
    const decision = decideScope(set, {
      acceptDefaults: true,
      previousAnswers: { "serverless.iam-audit": "off" },
    });
    expect(decision.accepted.map((entry) => entry.proposal.id)).toEqual(["delivery.iac.terraform"]);
    expect(decision.declined.map((entry) => entry.proposal.id)).toEqual([
      "serverless.iam-audit",
      "data.deep-migrations",
    ]);
    expect(decision.untouched).toEqual([]);
    expect(decision.declined[0]?.source).toBe("config");
    expect(decision.declined[1]?.source).toBe("defaults");
  });

  test("a `scope` proposal never adds a domain, it only widens the analysed paths", () => {
    const withPackage: ProposalSet = {
      proposals: [proposal({ id: "scope.package.apps-mobile", domain: "scope" })],
      notApplicable: [],
    };
    const decision = decideScope(withPackage, { include: ["scope.package.apps-mobile"] });
    expect(decision.accepted).toHaveLength(1);
    expect(decision.enabledDomains).toEqual([
      "dependencies",
      "appsec",
      "data",
      "delivery",
      "deadcode",
    ]);
  });

  test("accepted work whose tool is missing is flagged instead of quietly failing", () => {
    const decision = decideScope(set, { include: ["terraform"], availableTools: [] });
    expect(decision.blockedOnMissingTool).toEqual([
      { proposalId: "delivery.iac.terraform", tool: "trivy" },
    ]);
  });

  test("accepting the matching install proposal clears the block", () => {
    const withInstall: ProposalSet = {
      proposals: [
        terraform,
        proposal({ id: "tooling.install.trivy", attributes: { tool: "trivy" } }),
      ],
      notApplicable: [],
    };
    const decision = decideScope(withInstall, {
      include: ["terraform", "tooling.install.trivy"],
      availableTools: [],
    });
    expect(decision.blockedOnMissingTool).toEqual([]);
  });

  test("not-applicable declarations survive into the decision untouched", () => {
    expect(decideScope(set).notApplicable).toEqual(set.notApplicable);
  });
});

describe("answersFromDecision", () => {
  test("remembers accepted and declined, and deliberately forgets untouched", () => {
    const decision = decideScope(set, { include: ["terraform"], exclude: ["migrations"] });
    expect(answersFromDecision(decision)).toEqual({
      "delivery.iac.terraform": "on",
      "data.deep-migrations": "off",
    });
  });
});

describe("buildScopeProposalDocument", () => {
  test("produces a validated scope-proposal.json payload", () => {
    const document = buildScopeProposalDocument({
      runId: "run-1",
      target: "/repo",
      decision: decideScope(set, { include: ["terraform"] }),
    });
    expect(document.schemaVersion).toBe("1.0");
    expect(document.decision.accepted).toHaveLength(1);
    expect(document.decision.untouched).toHaveLength(2);
  });
});

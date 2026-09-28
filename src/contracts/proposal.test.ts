import { describe, expect, test } from "bun:test";
import { SCHEMA_VERSION } from "./findings.ts";
import {
  ProposalSchema,
  ScopeDecisionSchema,
  ScopeProposalDocumentSchema,
  SentinelConfigSchema,
} from "./proposal.ts";

const minimalProposal = {
  id: "delivery.iac.terraform",
  title: "Terraform present but not scanned",
  domain: "delivery",
  detected: { summary: "12 .tf files" },
  wouldCheck: "Run trivy config",
  cost: { estimatedSeconds: 40, usesAi: false },
  defaultAnswer: "on",
};

describe("ProposalSchema", () => {
  test("fills the collection defaults so generators stay terse", () => {
    const parsed = ProposalSchema.parse(minimalProposal);
    expect(parsed.aliases).toEqual([]);
    expect(parsed.attributes).toEqual({});
    expect(parsed.detected.evidence).toEqual([]);
    expect(parsed.detected.count).toBeUndefined();
    expect(parsed.cost.requiresTool).toBeUndefined();
  });

  test("accepts `scope` as a domain for proposals that widen the analysis", () => {
    const parsed = ProposalSchema.parse({ ...minimalProposal, domain: "scope" });
    expect(parsed.domain).toBe("scope");
  });

  test("rejects a domain that is neither an analysis domain nor `scope`", () => {
    expect(ProposalSchema.safeParse({ ...minimalProposal, domain: "vibes" }).success).toBe(false);
  });

  test("rejects an empty id, because the config remembers answers by id", () => {
    expect(ProposalSchema.safeParse({ ...minimalProposal, id: "" }).success).toBe(false);
  });

  test("rejects an answer outside on/off", () => {
    expect(ProposalSchema.safeParse({ ...minimalProposal, defaultAnswer: "maybe" }).success).toBe(
      false,
    );
  });
});

describe("ScopeDecisionSchema", () => {
  test("defaults the diagnostic lists", () => {
    const decision = ScopeDecisionSchema.parse({
      enabledDomains: ["appsec"],
      accepted: [],
      declined: [],
      untouched: [],
      notApplicable: [],
      estimatedExtraSeconds: 0,
      usesAi: false,
    });
    expect(decision.unknownSelectors).toEqual([]);
    expect(decision.blockedOnMissingTool).toEqual([]);
  });

  test("rejects `scope` in enabledDomains — it is not a real analysis domain", () => {
    const result = ScopeDecisionSchema.safeParse({
      enabledDomains: ["scope"],
      accepted: [],
      declined: [],
      untouched: [],
      notApplicable: [],
      estimatedExtraSeconds: 0,
      usesAi: false,
    });
    expect(result.success).toBe(false);
  });
});

describe("ScopeProposalDocumentSchema", () => {
  test("pins the schema version of the artifact on disk", () => {
    const base = {
      runId: "run-1",
      target: "/tmp/repo",
      decision: {
        enabledDomains: [],
        accepted: [],
        declined: [],
        untouched: [],
        notApplicable: [],
        estimatedExtraSeconds: 0,
        usesAi: false,
      },
    };
    expect(
      ScopeProposalDocumentSchema.parse({ ...base, schemaVersion: SCHEMA_VERSION }).schemaVersion,
    ).toBe(SCHEMA_VERSION);
    expect(ScopeProposalDocumentSchema.safeParse({ ...base, schemaVersion: "0.9" }).success).toBe(
      false,
    );
  });
});

describe("SentinelConfigSchema", () => {
  test("an empty config is a config with no memory", () => {
    const config = SentinelConfigSchema.parse({ schemaVersion: SCHEMA_VERSION });
    expect(config.answers).toEqual({});
    expect(config.domains).toEqual({ include: [], exclude: [] });
  });

  test("rejects an answer value it cannot act on", () => {
    const result = SentinelConfigSchema.safeParse({
      schemaVersion: SCHEMA_VERSION,
      answers: { "data.deep-migrations": "later" },
    });
    expect(result.success).toBe(false);
  });
});

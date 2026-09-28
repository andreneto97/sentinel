import { describe, expect, test } from "bun:test";
import type { ProposalGenerator } from "./generators.ts";
import { DEFAULT_DOMAINS } from "./policy.ts";
import { createProposalContext, proposeScope } from "./propose.ts";
import type { ProfileFact } from "./stack-profile-adapter.ts";
import { createProfileView } from "./stack-profile-adapter.ts";

function fact(kind: string, value: string, detail?: string): ProfileFact {
  return {
    kind,
    value,
    confidence: "high",
    evidence: [{ file: `${value}.txt` }],
    ...(detail === undefined ? {} : { detail }),
  };
}

function contextOf(facts: readonly ProfileFact[]) {
  return createProposalContext({
    profile: createProfileView(facts),
    availableTools: ["trivy", "gitleaks", "opengrep", "ast-grep", "hadolint", "actionlint"],
  });
}

const generatorFor = (id: string, domain: "delivery" | "data"): ProposalGenerator => {
  return () => ({
    proposals: [
      {
        id,
        title: id,
        domain,
        detected: { summary: "detected", evidence: [] },
        wouldCheck: "would check",
        cost: { estimatedSeconds: 10, usesAi: false },
        defaultAnswer: "on",
        aliases: [],
        attributes: {},
      },
    ],
    notApplicable: [],
  });
};

describe("createProposalContext", () => {
  test("defaults to the v1 scope, the repo root and an empty toolchain", () => {
    const ctx = createProposalContext({ profile: createProfileView([]) });
    expect([...ctx.baseDomains]).toEqual([...DEFAULT_DOMAINS]);
    expect(ctx.analysedPath).toBe(".");
    expect(ctx.availableTools.size).toBe(0);
    expect(ctx.scopedCategories.size).toBe(0);
  });
});

describe("proposeScope", () => {
  test("orders proposals by domain then id, with `scope` last", () => {
    const set = proposeScope(
      contextOf([
        fact("iac", "terraform"),
        fact("migrations-dir", "db/migrations", "40 migrations"),
        fact("workspace-package", "apps/mobile"),
        fact("language", "python", "31 file(s)"),
      ]),
    );
    // analysedPath defaults to ".", so the workspace package is already inside
    // the analysis and raises nothing.
    expect(set.proposals.map((p) => p.domain)).toEqual(["appsec", "data", "delivery"]);
    expect(set.proposals.map((p) => p.id)).toEqual([
      "appsec.sast-language.python",
      "data.deep-migrations",
      "delivery.iac.terraform",
    ]);
  });

  test("puts `scope` proposals last, after every analysis domain", () => {
    const ctx = {
      ...contextOf([fact("iac", "terraform"), fact("workspace-package", "apps/mobile")]),
      analysedPath: "apps/api",
    };
    const set = proposeScope(ctx);
    expect(set.proposals[set.proposals.length - 1]?.id).toBe("scope.package.apps-mobile");
  });

  test("the first generator to claim an id wins, so nothing is duplicated", () => {
    const set = proposeScope(contextOf([]), [
      generatorFor("delivery.duplicate", "delivery"),
      generatorFor("delivery.duplicate", "data"),
    ]);
    expect(set.proposals).toHaveLength(1);
    expect(set.proposals[0]?.domain).toBe("delivery");
  });

  test("a generator that emits an invalid proposal fails here, not in the report", () => {
    // An empty id typechecks but breaks the config's ability to remember an
    // answer, so the schema rejects it at the boundary of the phase.
    const broken: ProposalGenerator = () => ({
      proposals: [
        {
          id: "",
          title: "nameless",
          domain: "delivery",
          detected: { summary: "detected", evidence: [] },
          wouldCheck: "would check",
          cost: { estimatedSeconds: 10, usesAi: false },
          defaultAnswer: "on",
          aliases: [],
          attributes: {},
        },
      ],
      notApplicable: [],
    });
    expect(() => proposeScope(contextOf([]), [broken])).toThrow();
  });

  test("not-applicable declarations are deduplicated and sorted", () => {
    const declare: ProposalGenerator = () => ({
      proposals: [],
      notApplicable: [
        { id: "b", domain: "data", category: "b", reason: "b", evidence: [] },
        { id: "a", domain: "data", category: "a", reason: "a", evidence: [] },
        { id: "a", domain: "data", category: "a duplicate", reason: "a", evidence: [] },
      ],
    });
    const set = proposeScope(contextOf([]), [declare]);
    expect(set.notApplicable.map((entry) => entry.id)).toEqual(["a", "b"]);
    expect(set.notApplicable[0]?.category).toBe("a");
  });
});

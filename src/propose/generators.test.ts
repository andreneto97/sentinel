import { describe, expect, test } from "bun:test";
import type { Domain } from "../contracts/findings.ts";
import type { ProposalContext } from "./generators.ts";
import {
  absenceGenerator,
  ciGenerator,
  frontendGenerator,
  iacGenerator,
  migrationsGenerator,
  missingToolGenerator,
  monorepoGenerator,
  sastLanguageGenerator,
  serverlessIamGenerator,
} from "./generators.ts";
import { DEFAULT_DOMAINS } from "./policy.ts";
import { createProposalContext } from "./propose.ts";
import type { ProfileAbsence, ProfileFact } from "./stack-profile-adapter.ts";
import { createProfileView } from "./stack-profile-adapter.ts";

const ALL_TOOLS = ["trivy", "gitleaks", "opengrep", "ast-grep", "hadolint", "actionlint"];

function fact(
  kind: string,
  value: string,
  options: { files?: string[]; detail?: string } = {},
): ProfileFact {
  return {
    kind,
    value,
    confidence: "high",
    evidence: (options.files ?? []).map((file) => ({ file })),
    ...(options.detail === undefined ? {} : { detail: options.detail }),
  };
}

function ctxFor(
  facts: readonly ProfileFact[],
  overrides: Partial<Omit<ProposalContext, "profile">> = {},
  absences: readonly ProfileAbsence[] = [],
): ProposalContext {
  const base = createProposalContext({
    profile: createProfileView(facts, absences),
    // Assume a complete toolchain unless a test says otherwise, so the
    // install proposals do not pollute every other generator's output.
    availableTools: ALL_TOOLS,
  });
  return { ...base, ...overrides };
}

describe("iacGenerator", () => {
  test("offers one proposal per IaC flavour the profiler proved", () => {
    const { proposals } = iacGenerator(
      ctxFor([
        fact("iac", "terraform", { files: ["terraform/main.tf"], detail: "12 file(s)" }),
        fact("iac", "helm", { files: ["charts/api/Chart.yaml"], detail: "2 chart(s)" }),
      ]),
    );
    // values() sorts, so helm comes before terraform.
    expect(proposals.map((p) => p.id)).toEqual(["delivery.iac.helm", "delivery.iac.terraform"]);
    const terraform = proposals.find((p) => p.id === "delivery.iac.terraform");
    expect(terraform?.domain).toBe("delivery");
    expect(terraform?.cost.requiresTool).toBe("trivy");
    expect(terraform?.detected.count).toBe(12);
    expect(terraform?.detected.summary).toBe("Terraform detected (12 file(s))");
    expect(terraform?.detected.evidence).toEqual(["terraform/main.tf"]);
    expect(terraform?.aliases).toContain("terraform");
  });

  test("still offers a flavour it has no label for", () => {
    const { proposals } = iacGenerator(ctxFor([fact("iac", "pulumi", { files: ["Pulumi.yaml"] })]));
    expect(proposals[0]?.id).toBe("delivery.iac.pulumi");
    expect(proposals[0]?.detected.count).toBeUndefined();
  });

  test("stays silent when there is no IaC", () => {
    expect(iacGenerator(ctxFor([])).proposals).toEqual([]);
  });

  test("defaults off when trivy is missing, because accepting would buy nothing", () => {
    const { proposals } = iacGenerator(
      ctxFor([fact("iac", "terraform")], { availableTools: new Set<string>() }),
    );
    expect(proposals[0]?.defaultAnswer).toBe("off");
  });

  test("stays silent for a category the caller already has in scope", () => {
    const { proposals } = iacGenerator(
      ctxFor([fact("iac", "terraform")], {
        scopedCategories: new Set(["delivery.iac.terraform"]),
      }),
    );
    expect(proposals).toEqual([]);
  });
});

describe("serverlessIamGenerator", () => {
  test("offers the IAM audit and scales its estimate with the function count", () => {
    const { proposals } = serverlessIamGenerator(
      ctxFor([
        fact("serverless-platform", "supabase-functions", {
          files: ["supabase/functions/a/index.ts"],
          detail: "12 edge function(s)",
        }),
        fact("serverless-manifest", "serverless.yml", { files: ["serverless.yml"] }),
      ]),
    );
    const proposal = proposals[0];
    expect(proposal?.id).toBe("serverless.iam-audit");
    expect(proposal?.domain).toBe("serverless");
    expect(proposal?.cost.usesAi).toBe(true);
    expect(proposal?.cost.estimatedSeconds).toBe(120);
    expect(proposal?.detected.count).toBe(12);
    expect(proposal?.detected.evidence).toContain("serverless.yml");
    expect(proposal?.aliases).toContain("iam");
  });

  test("falls back to a flat estimate when no function count was proven", () => {
    const proposal = serverlessIamGenerator(
      ctxFor([fact("serverless-platform", "aws-cdk", { files: ["cdk.json"] })]),
    ).proposals[0];
    expect(proposal?.cost.estimatedSeconds).toBe(180);
    expect(proposal?.detected.count).toBeUndefined();
  });

  test("stays silent without serverless workloads", () => {
    expect(serverlessIamGenerator(ctxFor([])).proposals).toEqual([]);
  });
});

describe("migrationsGenerator", () => {
  test("offers deep analysis when the directory is proven large", () => {
    const proposal = migrationsGenerator(
      ctxFor([
        fact("migrations-dir", "prisma/migrations", {
          files: ["prisma/migrations/a.sql"],
          detail: "84 migrations",
        }),
      ]),
    ).proposals[0];
    expect(proposal?.id).toBe("data.deep-migrations");
    expect(proposal?.detected.count).toBe(84);
    expect(proposal?.detected.summary).toContain("84 migrations in prisma/migrations");
    expect(proposal?.cost.usesAi).toBe(true);
    // 84 * 2s, clamped into the sane range; inside the AI budget, so --yes takes it.
    expect(proposal?.cost.estimatedSeconds).toBe(168);
    expect(proposal?.defaultAnswer).toBe("on");
  });

  test("leaves a proven-small directory to the ordinary data-layer pass", () => {
    const result = migrationsGenerator(
      ctxFor([fact("migrations-dir", "db/migrations", { detail: "3 migrations" })]),
    );
    expect(result.proposals).toEqual([]);
  });

  test("offers rather than guesses when the profiler proved no count", () => {
    const proposal = migrationsGenerator(
      ctxFor([fact("migrations-dir", "prisma/migrations", { files: ["prisma/migrations/a.sql"] })]),
    ).proposals[0];
    expect(proposal?.id).toBe("data.deep-migrations");
    expect(proposal?.detected.count).toBeUndefined();
    expect(proposal?.cost.estimatedSeconds).toBe(180);
  });

  test("stays silent without migrations", () => {
    expect(migrationsGenerator(ctxFor([])).proposals).toEqual([]);
  });
});

describe("ciGenerator", () => {
  test("counts the configuration files it would audit", () => {
    const proposal = ciGenerator(
      ctxFor([
        fact("ci", "github-actions", {
          files: [".github/workflows/ci.yml", ".github/workflows/release.yml"],
          detail: "6 file(s)",
        }),
      ]),
    ).proposals[0];
    expect(proposal?.id).toBe("delivery.ci-deep-audit");
    expect(proposal?.detected.summary).toContain("6 file(s)");
    expect(proposal?.detected.summary).toContain("github-actions");
    expect(proposal?.cost.requiresTool).toBe("actionlint");
    expect(proposal?.cost.usesAi).toBe(false);
  });
});

describe("monorepoGenerator", () => {
  const facts = [
    fact("workspace-package", "apps/api", {
      files: ["apps/api/package.json"],
      detail: "@acme/api",
    }),
    fact("workspace-package", "apps/mobile", {
      files: ["apps/mobile/package.json"],
      detail: "@acme/mobile",
    }),
  ];

  test("offers only the packages outside the analysed path", () => {
    const { proposals } = monorepoGenerator(ctxFor(facts, { analysedPath: "apps/api" }));
    expect(proposals.map((p) => p.id)).toEqual(["scope.package.apps-mobile"]);
    const proposal = proposals[0];
    expect(proposal?.domain).toBe("scope");
    expect(proposal?.attributes.path).toBe("apps/mobile");
    expect(proposal?.attributes.name).toBe("@acme/mobile");
    expect(proposal?.title).toContain("@acme/mobile");
    expect(proposal?.defaultAnswer).toBe("off");
  });

  test("offers nothing when the whole repo is already analysed", () => {
    expect(monorepoGenerator(ctxFor(facts, { analysedPath: "." })).proposals).toEqual([]);
  });
});

describe("missingToolGenerator", () => {
  test("offers an install only for tools this repo would actually exercise", () => {
    const { proposals } = missingToolGenerator(
      ctxFor([fact("container", "dockerfile", { files: ["Dockerfile"] })], {
        availableTools: new Set<string>(),
      }),
    );
    const ids = proposals.map((p) => p.id);
    expect(ids).toContain("tooling.install.trivy");
    expect(ids).toContain("tooling.install.hadolint");
    // No CI configuration in this profile, so actionlint is not proposed.
    expect(ids).not.toContain("tooling.install.actionlint");
    expect(proposals.every((p) => p.defaultAnswer === "off")).toBe(true);
    expect(proposals.find((p) => p.id === "tooling.install.hadolint")?.attributes.tool).toBe(
      "hadolint",
    );
  });

  test("offers nothing when the toolchain is complete", () => {
    const { proposals } = missingToolGenerator(
      ctxFor([fact("container", "dockerfile")], { availableTools: new Set(ALL_TOOLS) }),
    );
    expect(proposals).toEqual([]);
  });
});

describe("sastLanguageGenerator", () => {
  test("proposes a community pack for a language opengrep can read", () => {
    const { proposals, notApplicable } = sastLanguageGenerator(
      ctxFor([fact("language", "python", { files: ["scripts/etl.py"], detail: "31 file(s)" })]),
    );
    const proposal = proposals[0];
    expect(proposal?.id).toBe("appsec.sast-language.python");
    expect(proposal?.detected.summary).toContain("31 file(s)");
    expect(proposal?.detected.count).toBe(31);
    expect(proposal?.cost.requiresTool).toBe("opengrep");
    expect(notApplicable).toEqual([]);
  });

  test("declares a language nobody can analyse as not applicable, not skipped", () => {
    const { proposals, notApplicable } = sastLanguageGenerator(
      ctxFor([fact("language", "cobol", { files: ["legacy/PAY.CBL"], detail: "4 file(s)" })]),
    );
    expect(proposals).toEqual([]);
    expect(notApplicable[0]?.id).toBe("appsec.sast-language.cobol");
    expect(notApplicable[0]?.reason).toContain("never analysed");
  });

  test("says nothing about the languages it covers first-class", () => {
    const result = sastLanguageGenerator(
      ctxFor([
        fact("language", "typescript", { files: ["src/index.ts"], detail: "240 file(s)" }),
        fact("language", "javascript", { files: ["a.js"], detail: "5 file(s)" }),
      ]),
    );
    expect(result.proposals).toEqual([]);
    expect(result.notApplicable).toEqual([]);
  });
});

describe("frontendGenerator", () => {
  test("offers appsec when a frontend exists and the domain is off", () => {
    const { proposals } = frontendGenerator(
      ctxFor([fact("frontend", "next", { files: ["app/page.tsx"] })], {
        baseDomains: new Set<Domain>(["dependencies"]),
      }),
    );
    expect(proposals[0]?.id).toBe("appsec.client-surface");
    expect(proposals[0]?.domain).toBe("appsec");
  });

  test("says nothing when the frontend is already covered", () => {
    const result = frontendGenerator(
      ctxFor([fact("frontend", "next")], { baseDomains: new Set(DEFAULT_DOMAINS) }),
    );
    expect(result.proposals).toEqual([]);
    expect(result.notApplicable).toEqual([]);
  });

  test("with no frontend, client-side authorization is declared not applicable", () => {
    const { proposals, notApplicable } = frontendGenerator(ctxFor([]));
    expect(proposals).toEqual([]);
    expect(notApplicable[0]?.id).toBe("appsec.client-side-authorization");
    expect(notApplicable[0]?.reason).toContain("No frontend detected");
  });

  test("prefers the profiler's own words about what the absence costs", () => {
    const { notApplicable } = frontendGenerator(
      ctxFor([], {}, [
        {
          kind: "frontend",
          searched: ["*.tsx"],
          note: "No user interface: role-gate and view-layer XSS checks are not applicable.",
        },
      ]),
    );
    expect(notApplicable[0]?.reason).toBe(
      "No user interface: role-gate and view-layer XSS checks are not applicable.",
    );
  });
});

describe("absenceGenerator", () => {
  test("turns a noted absence into a declaration in the right domain", () => {
    const { notApplicable } = absenceGenerator(
      ctxFor([], {}, [
        {
          kind: "iac",
          searched: ["*.tf"],
          note: "No infrastructure-as-code: `trivy config` has nothing to scan beyond containers.",
        },
      ]),
    );
    expect(notApplicable[0]?.id).toBe("profile.absence.iac");
    expect(notApplicable[0]?.domain).toBe("delivery");
    expect(notApplicable[0]?.reason).toContain("nothing to scan");
  });

  test("leaves the frontend absence to frontendGenerator", () => {
    const { notApplicable } = absenceGenerator(
      ctxFor([], {}, [{ kind: "frontend", searched: [], note: "No user interface." }]),
    );
    expect(notApplicable).toEqual([]);
  });

  test("ignores an absence the profiler did not annotate", () => {
    const { notApplicable } = absenceGenerator(
      ctxFor([], {}, [{ kind: "queue", searched: ["bullmq"] }]),
    );
    expect(notApplicable).toEqual([]);
  });
});

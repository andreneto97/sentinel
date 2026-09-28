import { describe, expect, test } from "bun:test";
import type { Proposal, ProposalSet } from "../contracts/proposal.ts";
import { buildScopeProposalDocument, decideScope } from "./decide.ts";
import {
  formatCost,
  formatDuration,
  renderProposalList,
  renderScopeProposalJson,
  renderScopeSection,
  renderScopeSummary,
} from "./render.ts";

const terraform: Proposal = {
  id: "delivery.iac.terraform",
  title: "Terraform present but not scanned",
  domain: "delivery",
  detected: { summary: "Terraform detected: terraform/main.tf", evidence: ["terraform/main.tf"] },
  wouldCheck: "Run trivy config over the terraform tree.",
  cost: { estimatedSeconds: 40, usesAi: false, requiresTool: "trivy" },
  defaultAnswer: "on",
  aliases: ["terraform"],
  attributes: {},
};

const migrations: Proposal = {
  id: "data.deep-migrations",
  title: "Deep migration analysis",
  domain: "data",
  detected: { summary: "84 migrations found", evidence: ["prisma/migrations"], count: 84 },
  wouldCheck: "Locking operations, destructive statements, drift and rollback paths.",
  cost: { estimatedSeconds: 300, usesAi: true },
  defaultAnswer: "off",
  aliases: ["migrations"],
  attributes: {},
};

const iam: Proposal = {
  id: "serverless.iam-audit",
  title: "Serverless IAM and trigger permission audit",
  domain: "serverless",
  detected: { summary: "12 serverless functions", evidence: ["serverless.yml"], count: 12 },
  wouldCheck: "Wildcard Action/Resource, shared roles, public function URLs.",
  cost: { estimatedSeconds: 120, usesAi: true },
  defaultAnswer: "on",
  aliases: ["iam"],
  attributes: {},
};

const set: ProposalSet = {
  proposals: [terraform, migrations, iam],
  notApplicable: [
    {
      id: "appsec.client-side-authorization",
      domain: "appsec",
      category: "Client-side authorization and role gates",
      reason: "No frontend detected in this repository.",
      evidence: [],
    },
  ],
};

describe("formatDuration and formatCost", () => {
  test("renders seconds, whole minutes and the remainder", () => {
    expect(formatDuration(40)).toBe("+40s");
    expect(formatDuration(120)).toBe("+2m");
    expect(formatDuration(150)).toBe("+2m 30s");
  });

  test("a cost line says the price in time, AI and tooling", () => {
    expect(formatCost(terraform.cost)).toBe("+40s · no AI · needs trivy");
    expect(formatCost(iam.cost)).toBe("+2m · AI");
  });
});

describe("renderProposalList", () => {
  const text = renderProposalList(set.proposals);

  test("numbers every proposal and prints the selector that answers it", () => {
    expect(text).toContain(" 1. Terraform present but not scanned");
    expect(text).toContain(" 2. Deep migration analysis");
    expect(text).toContain(" 3. Serverless IAM and trigger permission audit");
    expect(text).toContain("--include delivery.iac.terraform");
  });

  test("shows what was detected, the evidence, the cost and the default", () => {
    expect(text).toContain("84 migrations found");
    expect(text).toContain("prisma/migrations");
    expect(text).toContain("+40s · no AI · needs trivy");
    expect(text).toContain("Default   off");
  });

  test("states plainly that silence means off", () => {
    expect(text).toContain("an unanswered proposal stays off");
  });

  test("says so when there is nothing to negotiate", () => {
    expect(renderProposalList([])).toContain("nothing outside the current scope");
  });
});

describe("renderScopeSection", () => {
  const decision = decideScope(set, { include: ["terraform"], exclude: ["migrations"] });
  const markdown = renderScopeSection(decision);

  test("a declined proposal still appears in the report as offered, declined", () => {
    expect(markdown).toContain("### Declined");
    expect(markdown).toContain(
      "- **Deep migration analysis** (`data.deep-migrations`) — offered, declined",
    );
    // The cost of the road not taken is part of the record.
    expect(markdown).toContain("Cost if run: +5m · AI");
  });

  test("an unanswered proposal is reported as offered and off, never omitted", () => {
    expect(markdown).toContain("### Offered, never answered (stayed off)");
    expect(markdown).toContain(
      "- **Serverless IAM and trigger permission audit** (`serverless.iam-audit`) — " +
        "offered, not answered (stayed off)",
    );
  });

  test("accepted proposals say where the answer came from", () => {
    expect(markdown).toContain("offered, accepted (on the command line)");
  });

  test("not-applicable categories are declared, not skipped", () => {
    expect(markdown).toContain("### Not applicable");
    expect(markdown).toContain("**Client-side authorization and role gates**");
    expect(markdown).toContain("No frontend detected");
  });

  test("every offered proposal is accounted for exactly once", () => {
    const offered = decision.accepted.length + decision.declined.length + decision.untouched.length;
    expect(offered).toBe(set.proposals.length);
    for (const proposal of set.proposals) {
      expect(markdown).toContain(`\`${proposal.id}\``);
    }
  });

  test("a config-remembered decline reads as declined, with its provenance", () => {
    const remembered = renderScopeSection(
      decideScope(set, { previousAnswers: { "data.deep-migrations": "off" } }),
    );
    expect(remembered).toContain("offered, declined (remembered in sentinel.config.json)");
  });

  test("an accepted proposal blocked on a missing tool is called out", () => {
    const blocked = renderScopeSection(
      decideScope(set, { include: ["terraform"], availableTools: [] }),
    );
    expect(blocked).toContain("### Accepted but blocked");
    expect(blocked).toContain("`trivy` is not installed");
  });

  test("an unrecognised selector is surfaced instead of ignored", () => {
    const typo = renderScopeSection(decideScope(set, { include: ["terrafrom"] }));
    expect(typo).toContain("### Unrecognised selectors");
    expect(typo).toContain("`terrafrom` matched nothing");
  });
});

describe("renderScopeSummary", () => {
  test("lists each unanswered proposal by id so nothing disappears", () => {
    const summary = renderScopeSummary(decideScope(set, { include: ["terraform"] }));
    expect(summary).toContain("Never answered (off): 2");
    expect(summary).toContain("not answered, stayed off: data.deep-migrations");
    expect(summary).toContain("not answered, stayed off: serverless.iam-audit");
  });
});

describe("renderScopeProposalJson", () => {
  test("emits a validated, newline-terminated artifact that round-trips", () => {
    const document = buildScopeProposalDocument({
      runId: "run-1",
      target: "/repo",
      decision: decideScope(set, { include: ["terraform"] }),
    });
    const json = renderScopeProposalJson(document);
    expect(json.endsWith("\n")).toBe(true);
    expect(JSON.parse(json)).toEqual(document);
  });
});

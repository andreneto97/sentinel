import { describe, expect, test } from "bun:test";
import type { Domain, Finding } from "../contracts/findings.ts";
import {
  ISSUE_MARKER,
  buildIssues,
  groupKeyFor,
  indexIssuesByFinding,
  issueTitle,
  labelsFor,
  renderIssueDocument,
  renderIssuesMarkdown,
  tableOf,
} from "./issues.ts";

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
    acceptanceCriteria: ["Repeated failures are rejected before the credential check."],
    cwe: ["CWE-307"],
    owasp: ["A07:2021"],
    source: { kind: "agent", name: "audit" },
    ...overrides,
  };
}

function unusedExport(id: string, file: string, line: number): Finding {
  return finding({
    id,
    domain: "deadcode",
    rule: "deadcode.unused-export",
    severity: "info",
    title: `Unused export candidate: ${id}`,
    description: "knip found no importer.",
    location: { file, line, snippet: `> ${line} | export const ${id} = 1;` },
    impact: "Exports with no consumer widen a module's surface.",
    recommendation: "Delete it.",
    acceptanceCriteria: ["The export is removed.", "No importer breaks in the build."],
    cwe: [],
    owasp: [],
    source: { kind: "tool", name: "knip" },
  });
}

function outdated(id: string, pkg: string, line: number, rule: string): Finding {
  return finding({
    id,
    domain: "dependencies",
    rule,
    severity: "info",
    title: `${pkg} is a patch release behind`,
    description: `${pkg} is behind.`,
    location: { file: "package.json", line, snippet: `> ${line} | "${pkg}": "^1.0.0"` },
    impact: "Upstream fixes are not picked up.",
    recommendation: `Update ${pkg}.`,
    acceptanceCriteria: [`${pkg} resolves to the latest patch.`, "The lockfile is regenerated."],
    cwe: [],
    owasp: [],
    source: { kind: "tool", name: "package-manager" },
  });
}

function missingIndex(id: string, title: string, line: number): Finding {
  return finding({
    id,
    domain: "data",
    rule: "data.missing-index-on-fk",
    severity: "low",
    title,
    description: "The foreign key has no index.",
    location: { file: "migrations/001.sql", line, snippet: `> ${line} | ALTER TABLE ...` },
    impact: "Each delete scans the child table.",
    recommendation: "Add the index.",
    acceptanceCriteria: ["The index exists."],
    cwe: [],
    owasp: [],
    source: { kind: "agent", name: "audit" },
  });
}

describe("titles and labels", () => {
  test("appsec and serverless share the security prefix; every other domain has its own", () => {
    const expected: Record<Domain, string> = {
      appsec: "[Security]",
      serverless: "[Security]",
      data: "[Data]",
      dependencies: "[Deps]",
      delivery: "[Delivery]",
      deadcode: "[Dead code]",
      api: "[API]",
      reliability: "[Reliability]",
    };
    for (const [domain, prefix] of Object.entries(expected)) {
      expect(issueTitle(domain as Domain, "Something")).toBe(`${prefix} Something`);
    }
  });

  test("a long description is cut on a word boundary", () => {
    const title = issueTitle("data", "word ".repeat(60).trim());
    expect(title.length).toBeLessThanOrEqual(120);
    expect(title.endsWith("…")).toBe(true);
    expect(title).not.toContain("wor…");
  });

  test("labels are the domain, the severity, and security where it applies", () => {
    expect(labelsFor("appsec", "high")).toEqual(["appsec", "severity:high", "security"]);
    expect(labelsFor("serverless", "low")).toEqual(["serverless", "severity:low", "security"]);
    expect(labelsFor("data", "medium")).toEqual(["data", "severity:medium"]);
  });
});

describe("the grouping rule", () => {
  test("two hygiene findings of one family become one issue", () => {
    const issues = buildIssues([
      unusedExport("alpha", "src/a.ts", 1),
      unusedExport("beta", "src/b.ts", 2),
    ]);
    expect(issues).toHaveLength(1);
    const [issue] = issues;
    expect(issue?.grouping.kind).toBe("grouped");
    expect(issue?.title).toBe("[Dead code] 2 exported symbols have no importer");
    expect(issue?.findingIds).toEqual(["alpha", "beta"]);
  });

  test("a family with one member in this run is filed as an ordinary issue", () => {
    const issues = buildIssues([unusedExport("alpha", "src/a.ts", 1)]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.grouping.kind).toBe("single");
    expect(issues[0]?.title).toBe("[Dead code] Unused export candidate: alpha");
  });

  test("two rules may share a family; a type export groups with a value export", () => {
    const typeExport = {
      ...unusedExport("gamma", "src/c.ts", 3),
      rule: "deadcode.unused-type-export",
    };
    const issues = buildIssues([unusedExport("alpha", "src/a.ts", 1), typeExport]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.rules).toEqual(["deadcode.unused-export", "deadcode.unused-type-export"]);
  });

  test("a patch bump and a major upgrade stay apart: different work, different families", () => {
    const issues = buildIssues([
      outdated("p1", "left", 2, "dependencies.outdated-patch"),
      outdated("p2", "right", 3, "dependencies.outdated-patch"),
      outdated("m1", "left", 4, "dependencies.outdated-major"),
      outdated("m2", "right", 5, "dependencies.outdated-major"),
    ]);
    expect(issues).toHaveLength(2);
    expect(issues.map((issue) => issue.title).sort()).toEqual([
      "[Deps] 2 packages are a major release behind",
      "[Deps] 2 packages are a patch release behind",
    ]);
  });

  test("a licence family spans two rules, because it is one review", () => {
    const licence = (id: string, rule: string): Finding => ({
      ...outdated(id, "pkg", 2, rule),
      title: `${id} licence`,
    });
    const issues = buildIssues([
      licence("copyleft", "dependencies.copyleft-license"),
      licence("unknown", "dependencies.unknown-license"),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.title).toBe("[Deps] 2 dependency licences need a decision");
  });

  test("missing indexes group per table, never across tables", () => {
    const same = buildIssues([
      missingIndex("one", "shipments.order_id has no index", 10),
      missingIndex("two", "shipments.carrier_id has no index", 11),
    ]);
    expect(same).toHaveLength(1);
    expect(same[0]?.title).toBe("[Data] 2 columns on `shipments` are queried without an index");

    const across = buildIssues([
      missingIndex("one", "shipments.order_id has no index", 10),
      missingIndex("two", "refunds.created_by has no index", 11),
    ]);
    expect(across).toHaveLength(2);
    expect(across.every((issue) => issue.grouping.kind === "single")).toBe(true);
  });

  test("a schema finding whose title names no table groups by file instead", () => {
    const issues = buildIssues([
      missingIndex("one", "The lookup filters on an unindexed column", 10),
      missingIndex("two", "Another lookup filters on an unindexed column", 11),
    ]);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.key).toBe("data.missing-index@file:migrations/001.sql");
    expect(issues[0]?.title).toContain("in `migrations/001.sql`");
  });

  test("anything a release should not ship with is filed on its own", () => {
    // Same rule, same family — but medium severity is P2, so the gate refuses.
    const issues = buildIssues([
      { ...unusedExport("alpha", "src/a.ts", 1), severity: "medium" },
      { ...unusedExport("beta", "src/b.ts", 2), severity: "medium" },
    ]);
    expect(issues).toHaveLength(2);
    expect(issues.every((issue) => issue.grouping.kind === "single")).toBe(true);
  });

  test("a rule that is not on the table is never grouped", () => {
    const sink = (id: string): Finding =>
      finding({
        id,
        rule: "appsec.unsanitised-sink",
        severity: "info",
        location: { file: `src/${id}.ts`, line: 1 },
      });
    expect(buildIssues([sink("a"), sink("b"), sink("c")])).toHaveLength(3);
    expect(groupKeyFor(sink("a"))).toBeNull();
  });

  test("the group key is stable and readable", () => {
    const key = groupKeyFor(unusedExport("alpha", "src/a.ts", 1));
    expect(key?.id).toBe("deadcode.unused-export@repo");
    expect(key?.scope).toEqual({ kind: "run" });
  });
});

describe("tableOf", () => {
  test("reads the table from the first table.column token", () => {
    expect(tableOf(missingIndex("a", "shipments.carrier_id has no index", 1))).toBe("shipments");
    expect(tableOf(missingIndex("a", "Lookup filters on unindexed customers.status", 1))).toBe(
      "customers",
    );
  });

  test("a file name is not a table", () => {
    expect(tableOf(missingIndex("a", "package.json declares it", 1))).toBeNull();
    expect(tableOf(missingIndex("a", "No qualified token here", 1))).toBeNull();
  });
});

describe("the issue body", () => {
  const [issue] = buildIssues([
    finding({ id: "solo", exploitability: "An unauthenticated caller." }),
  ]);

  test("states the problem, the preconditions and the priority", () => {
    expect(issue?.body).toContain("The handler calls the credential check with no throttle.");
    expect(issue?.body).toContain("**Preconditions:** An unauthenticated caller.");
    expect(issue?.body).toContain("**Why P2:**");
  });

  test("missing preconditions are stated as unknown, not as none", () => {
    const [bare] = buildIssues([finding({ id: "bare" })]);
    expect(bare?.body).toContain("treat the preconditions as unknown rather than as none");
  });

  test("evidence is a file:line plus the verified snippet in a fence", () => {
    expect(issue?.body).toContain("`src/login.ts:12`");
    expect(issue?.body).toContain("```text\n> 12 | await signIn(email)\n```");
  });

  test("impact and fix are their own sections", () => {
    expect(issue?.body).toContain("### Impact\n\nOnline password guessing.");
    expect(issue?.body).toContain("### Suggested fix\n\nAdd a per-IP limiter.");
  });

  test("acceptance criteria are a real checklist", () => {
    expect(issue?.body).toContain(
      "- [ ] Repeated failures are rejected before the credential check.",
    );
  });

  test("the references name the finding, the rule and where it came from", () => {
    expect(issue?.body).toContain("CWE: CWE-307");
    expect(issue?.body).toContain("Sentinel finding `solo`");
    expect(issue?.body).toContain("source `agent:audit`");
  });

  test("a pointer with no snippet is still listed", () => {
    const [noSnippet] = buildIssues([
      finding({ id: "x", location: { file: "src/a.ts", line: 4 }, evidence: [] }),
    ]);
    expect(noSnippet?.body).toContain("`src/a.ts:4`");
    expect(noSnippet?.body).not.toContain("```");
  });
});

describe("the grouped issue body", () => {
  const [issue] = buildIssues([
    outdated("p1", "left", 2, "dependencies.outdated-patch"),
    outdated("p2", "right", 3, "dependencies.outdated-patch"),
  ]);

  test("states the grouping rule it applied", () => {
    expect(issue?.body).toContain("**Grouping:** Sentinel files one issue per rule family");
    expect(issue?.body).toContain("close as one task instead of 2");
  });

  test("lists every member with its location", () => {
    expect(issue?.body).toContain("- `package.json:2` — left is a patch release behind");
    expect(issue?.body).toContain("- `package.json:3` — right is a patch release behind");
  });

  test("shared prose is printed once, differing prose per member", () => {
    expect(issue?.body.match(/Upstream fixes are not picked up\./g)).toHaveLength(1);
    expect(issue?.body).toContain("- `package.json:2` — Update left.");
    expect(issue?.body).toContain("- `package.json:3` — Update right.");
  });

  test("each member gets its own box; a batch-wide criterion is stated once", () => {
    const checklist = (issue?.body ?? "").split("\n").filter((line) => line.startsWith("- [ ] "));
    expect(checklist).toEqual([
      "- [ ] `package.json:2` — left resolves to the latest patch.",
      "- [ ] `package.json:3` — right resolves to the latest patch.",
      "- [ ] The lockfile is regenerated.",
      "- [ ] A re-run of Sentinel reports none of the findings listed above, or records why each one stays.",
    ]);
  });

  test("evidence keeps one snippet per member", () => {
    expect(issue?.body).toContain('> 2 | "left": "^1.0.0"');
    expect(issue?.body).toContain('> 3 | "right": "^1.0.0"');
  });
});

describe("delimiters and ordering", () => {
  const findings = [
    finding({ id: "crit", severity: "critical", title: "Critical thing" }),
    unusedExport("alpha", "src/a.ts", 1),
    unusedExport("beta", "src/b.ts", 2),
    finding({ id: "med", severity: "medium", title: "Medium thing" }),
  ];

  test("each issue is delimited by a start and end marker carrying its key", () => {
    const [issue] = buildIssues([finding({ id: "solo" })]);
    const document = renderIssueDocument(issue ?? neverIssue());
    expect(document.startsWith(`<!-- ${ISSUE_MARKER}:start key=solo -->`)).toBe(true);
    expect(document.trimEnd().endsWith(`<!-- ${ISSUE_MARKER}:end key=solo -->`)).toBe(true);
  });

  test("the heading level is caller-chosen, so the report can nest the issues", () => {
    const [issue] = buildIssues([finding({ id: "solo" })]);
    expect(renderIssueDocument(issue ?? neverIssue(), 3)).toContain("### [Security] Login");
    expect(renderIssueDocument(issue ?? neverIssue(), 3)).toContain("#### Problem");
  });

  test("issues come out in plan order, worst first", () => {
    expect(buildIssues(findings).map((issue) => issue.priority)).toEqual(["P1", "P2", "P3"]);
  });

  test("the order does not depend on the order it was given in", () => {
    const forward = buildIssues(findings).map((issue) => issue.key);
    const backward = buildIssues([...findings].reverse()).map((issue) => issue.key);
    expect(backward).toEqual(forward);
  });

  test("a severity floor cuts the tail", () => {
    expect(buildIssues(findings, { minSeverity: "medium" }).map((issue) => issue.key)).toEqual([
      "crit",
      "med",
    ]);
  });

  test("the standalone file indexes every issue and contains every body", () => {
    const issues = buildIssues(findings);
    const document = renderIssuesMarkdown(issues, { runId: "run-1", target: "/repo" });
    expect(document).toContain("# GitHub issues");
    expect(document).toContain("Run `run-1` · target `/repo`");
    expect(document).toContain("3 issue(s) covering 4 finding(s).");
    expect(document).toContain("1 of them group 2 hygiene findings");
    for (const issue of issues) {
      expect(document).toContain(`<!-- ${ISSUE_MARKER}:start key=${issue.key} -->`);
      expect(document).toContain(`<!-- ${ISSUE_MARKER}:end key=${issue.key} -->`);
    }
    expect(document.endsWith("\n")).toBe(true);
  });

  test("a pipe in a title cannot break the index table", () => {
    const document = renderIssuesMarkdown(buildIssues([finding({ id: "pipe", title: "a | b" })]), {
      runId: "run-1",
      target: "/repo",
    });
    expect(document).toContain("[Security] a \\| b");
  });

  test("every finding is reachable from its issue", () => {
    const index = indexIssuesByFinding(buildIssues(findings));
    expect([...index.keys()].sort()).toEqual(["alpha", "beta", "crit", "med"]);
    expect(index.get("alpha")).toBe(index.get("beta"));
  });
});

/** Only reached if a fixture stops producing an issue; keeps the tests honest. */
function neverIssue(): never {
  throw new Error("expected an issue");
}

describe("an issue that covers hundreds of findings", () => {
  const members = Array.from({ length: 300 }, (_, index) =>
    unusedExport(`sym${index}`, `src/file-${index}.ts`, index + 1),
  );
  const [issue] = buildIssues(members);

  test("still covers every one of them", () => {
    expect(issue?.grouping.kind).toBe("grouped");
    expect(issue?.findingIds).toHaveLength(300);
    expect(issue?.title).toBe("[Dead code] 300 exported symbols have no importer");
  });

  test("prints five of them and says how many it did not print", () => {
    const body = issue?.body ?? "";
    expect(body.match(/`src\/file-\d+\.ts:\d+` — Unused export candidate/g) ?? []).toHaveLength(5);
    expect(body).toContain("…and 295 more of the same kind");
    expect(body).toContain("All 300 are in `findings.json`");
    expect(body).toContain("`raw/knip/`");
  });

  test("carries evidence for what it printed, and says so", () => {
    const body = issue?.body ?? "";
    expect((body.match(/```text/g) ?? []).length).toBe(5);
    expect(body).toContain("Evidence is shown for 5 of the 300 findings");
  });

  test("the checklist has a box per printed member and one for the rest", () => {
    const body = issue?.body ?? "";
    const boxes = body.match(/- \[ \] /g) ?? [];
    expect(boxes.length).toBeLessThan(12);
    expect(body).toContain("The remaining 295 findings this issue covers are triaged the same way");
  });

  test("a group under the threshold is still printed in full", () => {
    const small = Array.from({ length: 20 }, (_, index) =>
      unusedExport(`small${index}`, `src/small-${index}.ts`, index + 1),
    );
    const [full] = buildIssues(small);
    const body = full?.body ?? "";
    expect(body.match(/`src\/small-\d+\.ts:\d+` — Unused export candidate/g) ?? []).toHaveLength(
      20,
    );
    expect((body.match(/```text/g) ?? []).length).toBe(20);
    expect(body).not.toContain("more of the same kind");
  });
});

import { describe, expect, test } from "bun:test";
import type { Domain, Finding, Severity } from "../contracts/findings.ts";
import {
  VOLUME_EXAMPLES,
  VOLUME_THRESHOLD,
  isCollapsed,
  isHiddenByVolume,
  isVolumeExample,
  planVolume,
  rawLocationOf,
  volumeDisclosure,
  volumeGroupOf,
  volumeLogLines,
} from "./_volume.ts";

/** One finding, with only the fields the volume policy reads spelled out. */
function finding(overrides: Partial<Finding> & { id: string }): Finding {
  const { id } = overrides;
  return {
    domain: "deadcode" as Domain,
    rule: "deadcode.unused-export",
    severity: "info" as Severity,
    confidence: "low",
    title: `Unused export candidate: ${id}`,
    description: "knip found no importer.",
    location: { file: `src/${id}.ts`, line: 1 },
    evidence: [],
    impact: "Dead exports widen the module surface.",
    recommendation: "Delete it.",
    acceptanceCriteria: [],
    cwe: [],
    owasp: [],
    source: { kind: "tool", name: "knip" },
    ...overrides,
  };
}

/** `count` findings of one rule, spread over `files` files. */
function many(count: number, overrides: Partial<Finding> = {}, files = count): Finding[] {
  return Array.from({ length: count }, (_, index) =>
    finding({
      id: `f${index}`,
      location: { file: `src/file-${index % files}.ts`, line: index + 1 },
      ...overrides,
    }),
  );
}

describe("planVolume", () => {
  test("a rule under the threshold is not collapsed", () => {
    const plan = planVolume(many(VOLUME_THRESHOLD));

    expect(plan.groups).toEqual([]);
    expect(plan.collapsedFindings).toBe(0);
    expect(volumeDisclosure(plan)).toContain("rendered on its own");
  });

  test("a rule over the threshold becomes one counted group", () => {
    const findings = many(40);
    const plan = planVolume(findings);
    const [group] = plan.groups;

    expect(plan.groups).toHaveLength(1);
    expect(group?.count).toBe(40);
    expect(group?.fileCount).toBe(40);
    expect(group?.examples).toHaveLength(VOLUME_EXAMPLES);
    expect(group?.hidden).toBe(40 - VOLUME_EXAMPLES);
    expect(group?.findingIds).toHaveLength(40);
    expect(plan.collapsedFindings).toBe(40);
    expect(plan.hiddenFindings).toBe(35);
  });

  test("the group states its size, where the rest are, and what it cannot hide", () => {
    const [group] = planVolume(many(40)).groups;

    expect(group?.title).toBe("40 Unused export candidates");
    expect(group?.summary).toContain("40 findings of rule `deadcode.unused-export`");
    expect(group?.summary).toContain("across 40 files");
    expect(group?.summary).toContain("`findings.json`");
    expect(group?.summary).toContain("raw/knip/");
    expect(group?.summary).toContain("above `low` is never grouped");
    expect(group?.rawLocation).toBe("raw/knip/");
  });

  test("nothing above low is ever collapsed, whatever the rule", () => {
    const loud = many(40);
    const serious = finding({
      id: "critical-one",
      severity: "critical",
      location: { file: "src/file-0.ts", line: 99 },
    });
    const plan = planVolume([...loud, serious]);
    const [group] = plan.groups;

    expect(group?.count).toBe(40);
    expect(group?.findingIds).not.toContain("critical-one");
    expect(isCollapsed(plan, serious)).toBe(false);
    expect(isHiddenByVolume(plan, serious)).toBe(false);
    expect(volumeGroupOf(plan, serious)).toBeUndefined();
  });

  test("a medium finding of a collapsed rule stays on its own", () => {
    const medium = finding({ id: "medium-one", severity: "medium" });
    const plan = planVolume([...many(40), medium]);

    expect(isCollapsed(plan, medium)).toBe(false);
    for (const group of plan.groups) expect(group.severity).not.toBe("medium");
  });

  test("two rules that are each loud are two groups, never one", () => {
    const plan = planVolume([
      ...many(30),
      ...many(30, {
        rule: "deadcode.unused-file",
        severity: "low",
        title: "Unused file candidate: x",
      }),
    ]);

    expect(plan.groups.map((group) => group.rule).sort()).toEqual([
      "deadcode.unused-export",
      "deadcode.unused-file",
    ]);
    // The `low` group sorts ahead of the `info` one: worse first.
    expect(plan.groups[0]?.rule).toBe("deadcode.unused-file");
  });

  test("the same rule in two domains is counted per domain", () => {
    const plan = planVolume([
      ...many(30),
      ...many(30, { domain: "dependencies", rule: "deadcode.unused-export" }),
    ]);

    expect(plan.groups).toHaveLength(2);
    expect([...plan.groups.map((group) => group.domain)].sort()).toEqual([
      "deadcode",
      "dependencies",
    ]);
  });

  test("examples come from the files carrying the most of the rule, one each", () => {
    const concentrated = [
      ...Array.from({ length: 20 }, (_, index) =>
        finding({ id: `hot${index}`, location: { file: "src/hot.ts", line: index + 1 } }),
      ),
      ...Array.from({ length: 12 }, (_, index) =>
        finding({ id: `spread${index}`, location: { file: `src/cold-${index}.ts`, line: 1 } }),
      ),
    ];
    const [group] = planVolume(concentrated).groups;
    const files = group?.examples.map((example) => example.location.file) ?? [];

    expect(group?.count).toBe(32);
    expect(files[0]).toBe("src/hot.ts");
    expect(new Set(files).size).toBe(VOLUME_EXAMPLES);
  });

  test("every example is a member, and every member is in findings.json's set", () => {
    const findings = many(40);
    const plan = planVolume(findings);
    const [group] = plan.groups;
    const ids = new Set(findings.map((entry) => entry.id));

    for (const example of group?.examples ?? []) {
      expect(ids.has(example.id)).toBe(true);
      expect(isVolumeExample(plan, example)).toBe(true);
      expect(isHiddenByVolume(plan, example)).toBe(false);
    }
    expect(new Set(group?.findingIds).size).toBe(40);
  });

  test("the plan is the same for the same findings in a different order", () => {
    const findings = many(40);
    const forward = planVolume(findings);
    const backward = planVolume([...findings].reverse());

    expect(backward.groups[0]?.findingIds).toEqual(forward.groups[0]?.findingIds ?? []);
    expect(backward.groups[0]?.examples.map((entry) => entry.id)).toEqual(
      forward.groups[0]?.examples.map((entry) => entry.id) ?? [],
    );
  });

  test("the threshold and the example count are overridable, and stated", () => {
    const plan = planVolume(many(10), { threshold: 5, exampleLimit: 2 });

    expect(plan.groups[0]?.count).toBe(10);
    expect(plan.groups[0]?.examples).toHaveLength(2);
    expect(plan.groups[0]?.summary).toContain("passes 5 findings");
    expect(volumeDisclosure(plan)).toContain("passed 5 findings");
  });

  test("a rule from one of Sentinel's own rules points at findings.json alone", () => {
    const own = many(30, { source: { kind: "rule", name: "container-rules" } });
    const [group] = planVolume(own).groups;

    expect(group?.rawLocation).toBeNull();
    expect(group?.summary).not.toContain("raw/");
    expect(rawLocationOf(own[0] ?? finding({ id: "x" }))).toBeNull();
  });

  test("the log lines name the rule, the counts and where the rest are", () => {
    const [line] = volumeLogLines(planVolume(many(40)));

    expect(line).toContain("deadcode.unused-export: 40 findings in deadcode");
    expect(line).toContain("5 shown, 35 not shown");
    expect(line).toContain("findings.json");
  });

  test("a group whose members disagree about their title falls back to the rule id", () => {
    const mixed = many(30).map((entry, index) =>
      index % 2 === 0 ? entry : { ...entry, title: "Something else entirely" },
    );
    const [group] = planVolume(mixed).groups;

    expect(group?.title).toBe("30 `deadcode.unused-export` findings");
  });

  test("a file-kind title prefix is not a second noun", () => {
    // The seam between the two policies: the severity cap prefixes a title with
    // `In test code: `, and reading that as the rule's noun made 30 members of
    // one rule look like three rules and printed the bare rule id as a heading.
    const prefixed = many(30).map((entry, index) =>
      index % 3 === 0
        ? entry
        : {
            ...entry,
            title: `${index % 3 === 1 ? "In test code: " : "In test fixture code: "}${entry.title}`,
          },
    );
    const [group] = planVolume(prefixed).groups;

    expect(group?.title).toBe("30 Unused export candidates");
  });
});

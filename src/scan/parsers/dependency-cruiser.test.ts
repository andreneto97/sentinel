import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  type DependencyCruiserReport,
  cyclesOf,
  detectsCycles,
  detectsOrphans,
  orphansOf,
  parseDependencyCruiserReport,
} from "./dependency-cruiser.ts";

/** Real `depcruise 18.4.0 --output-type json` output over a demo repository. */
const REPORT = await Bun.file(
  join(import.meta.dir, "__fixtures__/dependency-cruiser-report.json"),
).text();

/** Real output over Sentinel's own `src/`, which carries two separate rings. */
const CYCLES = await Bun.file(
  join(import.meta.dir, "__fixtures__/dependency-cruiser-cycles.json"),
).text();

/** Parses a fixture, failing the test rather than the suite when it does not. */
function reportOf(raw: string): DependencyCruiserReport {
  const parsed = parseDependencyCruiserReport(raw);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
}

describe("parseDependencyCruiserReport", () => {
  test("accepts real dependency-cruiser output", () => {
    const report = reportOf(REPORT);
    expect(report.summary.totalCruised).toBe(5);
    expect(report.summary.violations).toHaveLength(2);
  });

  test("refuses output that is not JSON instead of throwing", () => {
    const parsed = parseDependencyCruiserReport("ERROR: Can't open a config file\n");
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.error).toContain("did not produce valid JSON");
  });

  test("refuses JSON of the wrong shape", () => {
    const parsed = parseDependencyCruiserReport('{"modules": {"src/a.ts": true}}');
    expect(parsed.ok).toBe(false);
  });
});

describe("cyclesOf", () => {
  test("reads the ring out of a real cycle violation, canonicalised", () => {
    expect(cyclesOf(reportOf(REPORT))).toEqual([
      { modules: ["src/a.ts", "src/b.ts"], key: "src/a.ts -> src/b.ts -> src/a.ts" },
    ]);
  });

  test("keeps two different rings apart", () => {
    const cycles = cyclesOf(reportOf(CYCLES));
    expect(cycles.map((cycle) => cycle.key)).toEqual([
      "src/cli/analyze.ts -> src/cli/index.ts -> src/cli/analyze.ts",
      "src/cli/index.ts -> src/cli/setup.ts -> src/cli/index.ts",
    ]);
  });

  test("the same ring reported from two entry points becomes one finding", () => {
    const report = reportOf(REPORT);
    const violation = report.summary.violations.find((entry) => entry.type === "cycle");
    if (violation === undefined) throw new Error("fixture has no cycle violation");
    // The same ring, as dependency-cruiser renders it when another module of
    // the ring is the entry point: rotated, and reported from that module.
    const rotated = {
      ...violation,
      from: "src/b.ts",
      to: "src/a.ts",
      cycle: [
        { name: "src/a.ts", dependencyTypes: [] },
        { name: "src/b.ts", dependencyTypes: [] },
      ],
    };
    const doubled: DependencyCruiserReport = {
      ...report,
      summary: { ...report.summary, violations: [violation, rotated] },
    };
    expect(cyclesOf(doubled)).toHaveLength(1);
  });

  test("a rule violation that is not a cycle is never counted as one", () => {
    const report = reportOf(CYCLES);
    const orphanViolations = report.summary.violations.filter((entry) => entry.type === "module");
    expect(orphanViolations.length).toBeGreaterThan(0);
    expect(cyclesOf(report)).toHaveLength(2);
  });
});

describe("orphansOf", () => {
  test("reads the orphan attribute off the graph", () => {
    expect(orphansOf(reportOf(REPORT))).toEqual(["src/orphan.ts"]);
  });

  test("falls back to the orphan violations when the attribute is absent", () => {
    const report = reportOf(REPORT);
    const withoutAttribute: DependencyCruiserReport = {
      ...report,
      modules: report.modules.map((module) => ({ source: module.source })),
    };
    expect(orphansOf(withoutAttribute)).toEqual(["src/orphan.ts"]);
  });

  test("does not report the same module twice", () => {
    const report = reportOf(CYCLES);
    expect(new Set(orphansOf(report)).size).toBe(orphansOf(report).length);
  });
});

describe("rule coverage", () => {
  test("the generated ruleset looks for both cycles and orphans", () => {
    const report = reportOf(REPORT);
    expect(detectsCycles(report)).toBe(true);
    expect(detectsOrphans(report)).toBe(true);
  });

  test("a ruleset without a circular rule is reported as not looking for cycles", () => {
    const report = reportOf(REPORT);
    const ruleSet = report.summary.ruleSetUsed;
    if (ruleSet === undefined) throw new Error("fixture has no ruleSetUsed");
    const narrowed: DependencyCruiserReport = {
      ...report,
      summary: {
        ...report.summary,
        ruleSetUsed: {
          ...ruleSet,
          forbidden: ruleSet.forbidden.filter((rule) => rule.to?.circular !== true),
        },
      },
    };
    expect(detectsCycles(narrowed)).toBe(false);
    expect(detectsOrphans(narrowed)).toBe(true);
  });
});

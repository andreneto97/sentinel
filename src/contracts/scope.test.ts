import { describe, expect, test } from "bun:test";
import type { AuditUnit } from "./findings.ts";
import { SCHEMA_VERSION } from "./findings.ts";
import type { AuditUnitKind } from "./inventory.ts";
import type { ScopeProbe } from "./scope.ts";
import {
  AnalysisScopeSchema,
  UNSCOPED_PHASES,
  buildAnalysisScope,
  countUnitsByKind,
  isGlobSelector,
  isWithinScope,
  normaliseScopePath,
  partitionUnits,
  renderScopePaths,
  resolveScopeSelectors,
  scopeStatement,
} from "./scope.ts";

/** A unit at a path; nothing else in this module reads any other field. */
function unit(kind: AuditUnitKind, file: string, line = 1): AuditUnit {
  return {
    id: `${kind}:${file}:${line}`,
    kind,
    label: `${kind} in ${file}`,
    location: { file, line },
    attributes: {},
  };
}

/** A probe over a literal set of directories and workspace packages. */
function probe(
  directories: readonly string[],
  workspaces: Record<string, string> = {},
): ScopeProbe {
  return {
    async isDirectory(path: string): Promise<boolean> {
      return directories.includes(path);
    },
    workspaces,
  };
}

describe("normaliseScopePath", () => {
  test("treats the many spellings of one subtree as that subtree", () => {
    for (const spelling of ["apps/api", "./apps/api", "apps/api/", "/apps/api", "apps\\api"]) {
      expect(normaliseScopePath(spelling)).toBe("apps/api");
    }
  });

  test("normalises the repository root to the empty scope", () => {
    expect(normaliseScopePath(".")).toBe("");
    expect(normaliseScopePath("./")).toBe("");
    expect(normaliseScopePath("  ")).toBe("");
  });
});

describe("isGlobSelector", () => {
  test("is only about the two characters a path cannot mean", () => {
    expect(isGlobSelector("apps/*")).toBe(true);
    expect(isGlobSelector("apps/**/src")).toBe(true);
    expect(isGlobSelector("apps/ap?")).toBe(true);
    // A directory really named `logs[1]` is likelier than a bracket expression.
    expect(isGlobSelector("logs[1]")).toBe(false);
    expect(isGlobSelector("apps/api")).toBe(false);
  });
});

describe("isWithinScope", () => {
  test("an empty scope is the whole repository", () => {
    expect(isWithinScope("libs/persistence/migrations/001.ts", [])).toBe(true);
  });

  test("a directory covers its subtree and stops at the segment boundary", () => {
    expect(isWithinScope("apps/api/src/main.ts", ["apps/api"])).toBe(true);
    expect(isWithinScope("apps/api", ["apps/api"])).toBe(true);
    // The bug a `startsWith` without the separator would ship:
    expect(isWithinScope("apps/api-gateway/src/main.ts", ["apps/api"])).toBe(false);
    expect(isWithinScope("libs/core/index.ts", ["apps/api"])).toBe(false);
  });

  test("`*` stops at a separator and `**` crosses it", () => {
    expect(isWithinScope("apps/api/src/main.ts", ["apps/*"])).toBe(true);
    expect(isWithinScope("libs/core/src/a.ts", ["apps/*"])).toBe(false);
    expect(isWithinScope("libs/domains/users/user.entity.ts", ["libs/**/entities"])).toBe(false);
    expect(isWithinScope("libs/domains/entities/user.ts", ["libs/**/entities"])).toBe(true);
    expect(isWithinScope("libs/entities/user.ts", ["libs/**/entities"])).toBe(true);
  });

  test("several paths are a union", () => {
    const scope = ["apps/api", "libs/shared"];
    expect(isWithinScope("libs/shared/src/a.ts", scope)).toBe(true);
    expect(isWithinScope("apps/api/src/a.ts", scope)).toBe(true);
    expect(isWithinScope("libs/other/src/a.ts", scope)).toBe(false);
  });
});

describe("resolveScopeSelectors", () => {
  test("resolves a directory as itself", async () => {
    const resolved = await resolveScopeSelectors(["apps/api"], probe(["apps/api"]));
    expect(resolved.paths).toEqual(["apps/api"]);
    expect(resolved.unmatched).toEqual([]);
    expect(resolved.selectors[0]?.kind).toBe("directory");
  });

  test("resolves a workspace package name to the directory it lives in", async () => {
    const resolved = await resolveScopeSelectors(
      ["@acme/api"],
      probe(["apps/api"], { "@acme/api": "apps/api" }),
    );
    expect(resolved.paths).toEqual(["apps/api"]);
    expect(resolved.selectors[0]?.kind).toBe("workspace");
    expect(resolved.selectors[0]?.note).toContain("apps/api");
  });

  test("resolves the tail of a scoped package name", async () => {
    const resolved = await resolveScopeSelectors(
      ["api"],
      probe(["apps/api"], { "@acme/api": "apps/api" }),
    );
    expect(resolved.paths).toEqual(["apps/api"]);
  });

  test("resolves an Nx project name through the conventional parents", async () => {
    // No package.json of its own, so no workspace fact: `apps/api` is all there is.
    const resolved = await resolveScopeSelectors(["api"], probe(["apps/api"]));
    expect(resolved.paths).toEqual(["apps/api"]);
    expect(resolved.selectors[0]?.kind).toBe("workspace");
    expect(resolved.selectors[0]?.note).toContain("`apps/api` exists");
  });

  test("refuses to pick a winner when a bare name matches two packages", async () => {
    const resolved = await resolveScopeSelectors(
      ["api"],
      probe([], { "@a/api": "apps/api", "@b/api": "services/api" }),
    );
    expect(resolved.paths).toEqual([]);
    expect(resolved.unmatched).toEqual(["api"]);
  });

  test("refuses to pick a winner when two conventional parents hold the name", async () => {
    const resolved = await resolveScopeSelectors(["api"], probe(["apps/api", "libs/api"]));
    expect(resolved.unmatched).toEqual(["api"]);
  });

  test("keeps a glob as written, without asking the filesystem about it", async () => {
    const resolved = await resolveScopeSelectors(["apps/*"], probe([]));
    expect(resolved.paths).toEqual(["apps/*"]);
    expect(resolved.selectors[0]?.kind).toBe("glob");
  });

  test("records a selector that matched nothing instead of widening the run", async () => {
    const resolved = await resolveScopeSelectors(["apps/nope"], probe(["apps/api"]));
    expect(resolved.paths).toEqual([]);
    expect(resolved.unmatched).toEqual(["apps/nope"]);
    expect(resolved.selectors[0]?.kind).toBe("unmatched");
  });

  test("`.` is the repository root and narrows nothing", async () => {
    const resolved = await resolveScopeSelectors(["."], probe([]));
    expect(resolved.paths).toEqual([]);
    expect(resolved.unmatched).toEqual([]);
    expect(resolved.selectors[0]?.note).toContain("not narrowed");
  });

  test("de-duplicates and sorts, so two spellings of one subtree are one path", async () => {
    const resolved = await resolveScopeSelectors(
      ["libs/shared", "./apps/api/", "apps/api"],
      probe(["apps/api", "libs/shared"]),
    );
    expect(resolved.paths).toEqual(["apps/api", "libs/shared"]);
  });
});

describe("partitionUnits", () => {
  const units = [
    unit("route", "apps/api/src/http/users.ts"),
    unit("route", "apps/mcp/src/http/tools.ts"),
    unit("data-access", "libs/core/users.service.ts"),
    unit("migration", "libs/persistence/migrations/001.ts"),
  ];

  test("an unscoped run keeps every unit", () => {
    expect(partitionUnits(units, []).inScope).toHaveLength(4);
    expect(partitionUnits(units, []).outOfScope).toHaveLength(0);
  });

  test("a scoped run splits the inventory and loses nothing", () => {
    const split = partitionUnits(units, ["apps/api"]);
    expect(split.inScope.map((entry) => entry.location.file)).toEqual([
      "apps/api/src/http/users.ts",
    ]);
    expect(split.outOfScope).toHaveLength(3);
    expect(split.inScope.length + split.outOfScope.length).toBe(units.length);
  });

  test("counts both sides per kind, in contract order", () => {
    const split = partitionUnits(units, ["apps/api"]);
    expect(countUnitsByKind(split.inScope, split.outOfScope)).toEqual([
      { kind: "route", inScope: 1, outOfScope: 1 },
      { kind: "data-access", inScope: 0, outOfScope: 1 },
      { kind: "migration", inScope: 0, outOfScope: 1 },
    ]);
  });
});

describe("renderScopePaths", () => {
  test("reads as a sentence, whatever the number of paths", () => {
    expect(renderScopePaths([])).toBe("the whole repository");
    expect(renderScopePaths(["apps/api"])).toBe("`apps/api`");
    expect(renderScopePaths(["apps/api", "libs/shared"])).toBe("`apps/api` and `libs/shared`");
    expect(renderScopePaths(["a", "b", "c"])).toBe("`a`, `b` and `c`");
  });
});

describe("scopeStatement", () => {
  test("a whole-repository run says so, with its own total", () => {
    const statement = scopeStatement({
      paths: [],
      units: { total: 172, inScope: 172, outOfScope: 0, byKind: [] },
    });
    expect(statement).toBe("This run analysed the whole repository (172 units of audit).");
  });

  test("a workspace bounded to one deployable: what was analysed, and what was not", () => {
    const statement = scopeStatement({
      paths: ["apps/api"],
      units: {
        total: 5300,
        inScope: 300,
        outOfScope: 5000,
        byKind: [
          { kind: "route", inScope: 290, outOfScope: 20 },
          { kind: "data-access", inScope: 0, outOfScope: 4000 },
          { kind: "migration", inScope: 0, outOfScope: 500 },
          { kind: "sink", inScope: 1, outOfScope: 400 },
          { kind: "queue-consumer", inScope: 0, outOfScope: 10 },
          { kind: "webhook", inScope: 9, outOfScope: 5 },
          { kind: "workflow-job", inScope: 0, outOfScope: 65 },
        ],
      },
    });
    expect(statement).toContain("This run analysed `apps/api` (300 units)");
    expect(statement).toContain("the other 5,000 units in this repository");
    expect(statement).toContain("4,000 data-access call sites");
    // The bracketed list never reads as exhaustive when it is not: the three
    // biggest kinds plus the remainder add up to the 5,000 in front of them.
    expect(statement).toContain("100 in 4 other kinds");
    expect(4000 + 500 + 400 + 100).toBe(5000);
  });

  test("a run that has not enumerated yet claims nothing about what it left out", () => {
    // `--propose-only` prints the scope before phase 2 exists, and an empty
    // repository reaches the same numbers: "every unit is inside that scope"
    // would be a claim about an inventory nobody has built.
    const statement = scopeStatement({
      paths: ["apps/api"],
      units: { total: 0, inScope: 0, outOfScope: 0, byKind: [] },
    });
    expect(statement).toBe(
      "This run analysed `apps/api`; no unit of audit was counted, so nothing can be said yet about what that left out.",
    );
  });

  test("a scope that happens to contain everything does not invent an exclusion", () => {
    const statement = scopeStatement({
      paths: ["src"],
      units: {
        total: 12,
        inScope: 12,
        outOfScope: 0,
        byKind: [{ kind: "route", inScope: 12, outOfScope: 0 }],
      },
    });
    expect(statement).toContain("every unit this repository contains is inside that scope");
  });
});

describe("buildAnalysisScope", () => {
  const units = {
    total: 1030,
    inScope: 314,
    outOfScope: 716,
    byKind: [{ kind: "route" as const, inScope: 302, outOfScope: 14 }],
  };

  test("derives the statement rather than trusting a caller's prose", () => {
    const scope = buildAnalysisScope({
      runId: "20240102T030405-abababab",
      target: "/repo",
      paths: ["apps/api"],
      selectors: [{ selector: "apps/api", kind: "directory", paths: ["apps/api"] }],
      unmatched: [],
      units,
      unscopedPhases: UNSCOPED_PHASES,
      findingsOutside: 12,
    });
    expect(scope.wholeRepository).toBe(false);
    expect(scope.statement).toBe(scopeStatement({ paths: ["apps/api"], units }));
    expect(scope.findingsOutside).toBe(12);
    expect(scope.unscopedPhases.length).toBe(UNSCOPED_PHASES.length);
    // Round-trips through its own schema: this document is written to disk.
    expect(AnalysisScopeSchema.parse(JSON.parse(JSON.stringify(scope)))).toEqual(scope);
    expect(scope.schemaVersion).toBe(SCHEMA_VERSION);
  });

  test("an unscoped run is marked as covering the repository and discloses no exemptions", () => {
    const scope = buildAnalysisScope({
      runId: "r",
      target: "/repo",
      paths: [],
      selectors: [],
      unmatched: [],
      units: { total: 12, inScope: 12, outOfScope: 0, byKind: [] },
      unscopedPhases: [],
      findingsOutside: 0,
    });
    expect(scope.wholeRepository).toBe(true);
    expect(scope.unscopedPhases).toEqual([]);
    expect(scope.statement).toContain("the whole repository");
  });
});

describe("UNSCOPED_PHASES", () => {
  test("names the dependency scan and the git-history secret scan, with reasons", () => {
    const phases = UNSCOPED_PHASES.map((entry) => entry.phase);
    expect(phases).toContain("dependency scan");
    expect(phases).toContain("git-history secret scan");
    for (const entry of UNSCOPED_PHASES) expect(entry.reason.length).toBeGreaterThan(20);
  });
});

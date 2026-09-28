import { describe, expect, test } from "bun:test";
import { SCHEMA_VERSION } from "../contracts/findings.ts";
import type { DetectedFact, StackProfile } from "../contracts/profile.ts";
import {
  absenceOf,
  bestFact,
  envVarNames,
  evidenceFiles,
  factsOf,
  findFact,
  hasAsyncWorkloads,
  hasFact,
  hasFrontend,
  isAbsent,
  isMonorepo,
  isPureApi,
  moduleSystem,
  nodeVersion,
  packageManager,
  validatesConfig,
  valuesOf,
} from "./accessors.ts";
import { ref } from "./fact-builder.ts";

function profileWith(facts: DetectedFact[], absences: StackProfile["absences"] = []): StackProfile {
  return {
    schemaVersion: SCHEMA_VERSION,
    target: "/repo",
    facts,
    absences,
    warnings: [],
    scan: { filesSeen: 1, filesRead: 1, truncated: false },
  };
}

const EMPTY = profileWith([]);

describe("accessors over an empty profile", () => {
  test("return nothing rather than throwing", () => {
    expect(factsOf(EMPTY, "data-layer")).toEqual([]);
    expect(valuesOf(EMPTY, "data-layer")).toEqual([]);
    expect(bestFact(EMPTY, "node-version")).toBeUndefined();
    expect(findFact(EMPTY, "ci", "github-actions")).toBeUndefined();
    expect(hasFact(EMPTY, "ci", "github-actions")).toBe(false);
    expect(packageManager(EMPTY)).toBeUndefined();
    expect(nodeVersion(EMPTY)).toBeUndefined();
    expect(moduleSystem(EMPTY)).toBeUndefined();
    expect(envVarNames(EMPTY)).toEqual([]);
    expect(evidenceFiles(EMPTY, "route-dir")).toEqual([]);
    expect(validatesConfig(EMPTY)).toBe(false);
    expect(hasAsyncWorkloads(EMPTY)).toBe(false);
    expect(isMonorepo(EMPTY)).toBe(false);
  });

  test("treat a repository with no frontend fact as a pure API", () => {
    expect(hasFrontend(EMPTY)).toBe(false);
    expect(isPureApi(EMPTY)).toBe(true);
  });

  test("distinguish 'not found' from 'never looked for'", () => {
    expect(isAbsent(EMPTY, "frontend")).toBe(false);
    const probed = profileWith([], [{ kind: "frontend", searched: ["react"] }]);
    expect(isAbsent(probed, "frontend")).toBe(true);
    expect(absenceOf(probed, "frontend")?.searched).toEqual(["react"]);
    expect(absenceOf(probed, "ci")).toBeUndefined();
  });
});

describe("bestFact", () => {
  test("prefers the stronger confidence over the earlier fact", () => {
    const profile = profileWith([
      { kind: "node-version", value: "18", confidence: "medium", evidence: [ref("Dockerfile")] },
      { kind: "node-version", value: "20", confidence: "high", evidence: [ref("package.json", 4)] },
    ]);
    expect(bestFact(profile, "node-version")?.value).toBe("20");
    expect(nodeVersion(profile)).toBe("20");
  });

  test("breaks a confidence tie on the amount of evidence", () => {
    const profile = profileWith([
      { kind: "database-engine", value: "mysql", confidence: "high", evidence: [ref("a.ts")] },
      {
        kind: "database-engine",
        value: "postgresql",
        confidence: "high",
        evidence: [ref("b.ts"), ref("c.ts")],
      },
    ]);
    expect(bestFact(profile, "database-engine")?.value).toBe("postgresql");
  });
});

describe("packageManager", () => {
  test("returns the single evidenced manager", () => {
    const profile = profileWith([
      { kind: "package-manager", value: "pnpm", confidence: "high", evidence: [ref("x.yaml")] },
    ]);
    expect(packageManager(profile)).toBe("pnpm");
  });

  test("falls back to the best-evidenced one when a repository has two lockfiles", () => {
    const profile = profileWith([
      { kind: "package-manager", value: "npm", confidence: "high", evidence: [ref("a.json")] },
      {
        kind: "package-manager",
        value: "pnpm",
        confidence: "high",
        evidence: [ref("pnpm-lock.yaml"), ref("package.json", 3)],
      },
    ]);
    expect(packageManager(profile)).toBe("pnpm");
  });
});

describe("evidenceFiles", () => {
  test("deduplicates and can narrow to one value", () => {
    const profile = profileWith([
      {
        kind: "ci",
        value: "github-actions",
        confidence: "high",
        evidence: [ref(".github/workflows/a.yml"), ref(".github/workflows/a.yml", 4)],
      },
      {
        kind: "ci",
        value: "circleci",
        confidence: "high",
        evidence: [ref(".circleci/config.yml")],
      },
    ]);
    expect(evidenceFiles(profile, "ci")).toEqual([
      ".circleci/config.yml",
      ".github/workflows/a.yml",
    ]);
    expect(evidenceFiles(profile, "ci", "circleci")).toEqual([".circleci/config.yml"]);
  });
});

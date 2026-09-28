import { describe, expect, test } from "bun:test";
import { createFixtureFileSystem, fixturePath } from "./__fixtures__/fixture-file-system.ts";
import type { ProfileDirEntry, ProfileFileSystem } from "./file-system-port.ts";
import {
  type DependencySignal,
  PackageJsonSchema,
  allDependencies,
  dependencyRef,
  factsFromDependencies,
  findDependency,
  hasDependency,
  loadManifests,
  rootManifest,
  signalLabels,
} from "./manifest.ts";
import { RepoSnapshot } from "./repo-snapshot.ts";

const fs = createFixtureFileSystem();

function singleFileSystem(tree: Record<string, string>): ProfileFileSystem {
  return {
    async readFile(path: string): Promise<string> {
      const content = tree[path];
      if (content === undefined) throw new Error(`ENOENT ${path}`);
      return content;
    },
    async exists(path: string): Promise<boolean> {
      return tree[path] !== undefined;
    },
    async readDir(): Promise<readonly ProfileDirEntry[]> {
      return Object.keys(tree).map((name) => ({ name, isFile: true, isDirectory: false }));
    },
  };
}

describe("PackageJsonSchema", () => {
  test("accepts both workspace shapes and ignores unknown keys", () => {
    expect(PackageJsonSchema.parse({ workspaces: ["apps/*"] }).workspaces).toEqual(["apps/*"]);
    expect(PackageJsonSchema.parse({ workspaces: { packages: ["apps/*"] } }).workspaces).toEqual({
      packages: ["apps/*"],
    });
    expect(PackageJsonSchema.parse({ somethingNew: true }).name).toBeUndefined();
  });

  test("rejects a manifest whose dependency map is not string-to-string", () => {
    expect(PackageJsonSchema.safeParse({ dependencies: { express: 4 } }).success).toBe(false);
  });
});

describe("loadManifests", () => {
  test("finds every package.json, root first", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("monorepo"));
    const { manifests, warnings } = await loadManifests(snapshot);
    expect(warnings).toEqual([]);
    expect(manifests.map((manifest) => manifest.path)).toEqual([
      "package.json",
      "apps/api/package.json",
      "packages/shared/package.json",
    ]);
    expect(manifests.map((manifest) => manifest.directory)).toEqual([
      ".",
      "apps/api",
      "packages/shared",
    ]);
    expect(rootManifest(manifests)?.data.name).toBe("acme");
  });

  test("warns instead of throwing when a manifest is unparseable", async () => {
    const snapshot = await RepoSnapshot.create(
      singleFileSystem({ "package.json": "{ broken" }),
      "",
    );
    const { manifests, warnings } = await loadManifests(snapshot);
    expect(manifests).toEqual([]);
    expect(warnings[0]).toContain("not valid JSON");
  });

  test("warns when a manifest parses but has the wrong shape", async () => {
    const snapshot = await RepoSnapshot.create(
      singleFileSystem({ "package.json": '{"dependencies": {"express": 4}}' }),
      "",
    );
    const { manifests, warnings } = await loadManifests(snapshot);
    expect(manifests).toEqual([]);
    expect(warnings[0]).toContain("expected package.json shape");
  });
});

describe("dependency evidence", () => {
  test("cites the line that declares the dependency", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("express-knex"));
    const { manifests } = await loadManifests(snapshot);
    const express = findDependency(manifests, "express");
    if (express === undefined) throw new Error("the express fixture lost its express dependency");
    expect(express.section).toBe("dependencies");
    const codeRef = dependencyRef(express);
    expect(codeRef.file).toBe("package.json");
    const lines = await snapshot.lines("package.json");
    expect(lines?.[codeRef.line - 1]).toContain('"express"');
  });

  test("lists dependencies from every section of every manifest", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("next-prisma"));
    const { manifests } = await loadManifests(snapshot);
    const names = allDependencies(manifests).map((hit) => hit.name);
    expect(names).toContain("next");
    expect(names).toContain("prisma");
    expect(hasDependency(manifests, (name) => name === "typescript")).toBe(true);
    expect(hasDependency(manifests, (name) => name === "svelte")).toBe(false);
  });

  test("matches signals by exact name and by prefix", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("monorepo"));
    const { manifests } = await loadManifests(snapshot);
    const signals: DependencySignal[] = [
      { value: "nestjs", prefixes: ["@nestjs/"] },
      { value: "bullmq", packages: ["bullmq"] },
      { value: "not-here", packages: ["svelte"] },
    ];
    const facts = factsFromDependencies(manifests, "backend-framework", signals);
    expect([...new Set(facts.map((detected) => detected.value))].sort()).toEqual([
      "bullmq",
      "nestjs",
    ]);
    expect(facts.every((detected) => detected.evidence.length > 0)).toBe(true);
    expect(signalLabels(signals)).toEqual(["@nestjs/*", "bullmq", "svelte"]);
  });
});

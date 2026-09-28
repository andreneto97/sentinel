import { describe, expect, test } from "bun:test";
import { createFixtureFileSystem, fixturePath } from "./__fixtures__/fixture-file-system.ts";
import type { ProfileDirEntry, ProfileFileSystem } from "./file-system-port.ts";
import { RepoSnapshot } from "./repo-snapshot.ts";

const fs = createFixtureFileSystem();

/** A filesystem built from a literal path → content map, for cases fixtures cannot express. */
function memoryFileSystem(tree: Record<string, string>): ProfileFileSystem {
  const normalise = (path: string): string => path.replace(/^\/+/, "").replace(/\/+$/, "");
  return {
    async readFile(path: string): Promise<string> {
      const content = tree[normalise(path)];
      if (content === undefined) throw new Error(`ENOENT ${path}`);
      return content;
    },
    async exists(path: string): Promise<boolean> {
      return tree[normalise(path)] !== undefined;
    },
    async readDir(path: string): Promise<readonly ProfileDirEntry[]> {
      const prefix = normalise(path) === "" ? "" : `${normalise(path)}/`;
      const names = new Map<string, ProfileDirEntry>();
      for (const file of Object.keys(tree)) {
        if (!file.startsWith(prefix)) continue;
        const rest = file.slice(prefix.length);
        if (rest.length === 0) continue;
        const slash = rest.indexOf("/");
        const name = slash === -1 ? rest : rest.slice(0, slash);
        names.set(name, { name, isFile: slash === -1, isDirectory: slash !== -1 });
      }
      return [...names.values()].sort((a, b) => a.name.localeCompare(b.name));
    },
  };
}

describe("RepoSnapshot", () => {
  test("walks a fixture repository into sorted, repo-relative paths", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("express-knex"));
    expect(snapshot.files).toContain("src/routes/users.js");
    expect(snapshot.files).toContain("package.json");
    expect([...snapshot.files]).toEqual([...snapshot.files].sort());
    expect(snapshot.has("src/middleware/auth.js")).toBe(true);
    expect(snapshot.has("src/middleware/nope.js")).toBe(false);
  });

  describe("scope", () => {
    const tree = {
      "package.json": "{}",
      "pnpm-lock.yaml": "lockfileVersion: 9",
      "apps/api/src/main.ts": "export const main = 1;",
      "apps/api/src/users.ts": "export const users = 1;",
      "apps/api-gateway/src/main.ts": "export const gateway = 1;",
      "libs/persistence/migrations/001.ts": "export const up = 1;",
    };

    test("lists the subtree, and only the subtree", async () => {
      const snapshot = await RepoSnapshot.create(memoryFileSystem(tree), "", {
        scope: ["apps/api"],
      });
      expect([...snapshot.files]).toEqual(["apps/api/src/main.ts", "apps/api/src/users.ts"]);
      // The boundary is a path segment, not a string prefix.
      expect(snapshot.files).not.toContain("apps/api-gateway/src/main.ts");
      expect(snapshot.sourceFiles()).toHaveLength(2);
      expect(snapshot.filesMatching(/migrations/)).toEqual([]);
    });

    test("keeps the whole repository walkable, because existence is not a scope question", async () => {
      const snapshot = await RepoSnapshot.create(memoryFileSystem(tree), "", {
        scope: ["apps/api"],
      });
      expect(snapshot.allFiles).toHaveLength(6);
      // A detector asking whether this repository has a lockfile deserves the
      // truth even when the analysis covers one app.
      expect(snapshot.has("pnpm-lock.yaml")).toBe(true);
      expect(snapshot.firstExisting(["pnpm-lock.yaml"])).toBe("pnpm-lock.yaml");
      expect(await snapshot.read("libs/persistence/migrations/001.ts")).toContain("up");
    });

    test("an empty scope is the whole repository", async () => {
      const snapshot = await RepoSnapshot.create(memoryFileSystem(tree), "", { scope: [] });
      expect(snapshot.files).toEqual(snapshot.allFiles);
      expect(snapshot.scope).toEqual([]);
    });

    test("filesWithin answers for any scope, on a snapshot that was not scoped", async () => {
      const snapshot = await RepoSnapshot.create(memoryFileSystem(tree), "");
      expect(snapshot.filesWithin(["apps/api"])).toHaveLength(2);
      expect(snapshot.filesWithin(["apps/*"])).toHaveLength(3);
      expect(snapshot.filesWithin([])).toHaveLength(6);
    });

    test("only the listing narrows, so the stats a profile reports stay comparable", async () => {
      const scoped = await RepoSnapshot.create(memoryFileSystem(tree), "", {
        scope: ["apps/api"],
      });
      expect(scoped.stats().filesSeen).toBe(2);
      expect(scoped.allFiles.length).toBe(6);
    });
  });

  test("never descends into an ignored directory", async () => {
    const snapshot = await RepoSnapshot.create(
      memoryFileSystem({
        "package.json": "{}",
        "node_modules/left-pad/index.js": "module.exports = 1;",
        "src/app.ts": "export const app = 1;",
        "dist/app.js": "1",
      }),
      "",
    );
    expect(snapshot.files).toEqual(["package.json", "src/app.ts"]);
  });

  test("selects files by name, pattern and source extension", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("monorepo"));
    expect(snapshot.filesNamed("package.json").sort()).toEqual([
      "apps/api/package.json",
      "package.json",
      "packages/shared/package.json",
    ]);
    expect(snapshot.filesMatching(/\.tf$/)).toEqual(["infra/main.tf"]);
    expect(snapshot.sourceFiles()).not.toContain("k8s/deployment.yaml");
    expect(snapshot.firstExisting(["nope.json", "turbo.json"])).toBe("turbo.json");
    expect(snapshot.firstExisting(["nope.json"])).toBeUndefined();
  });

  test("grep returns 1-based line numbers that resolve in the file", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("express-knex"));
    const hits = await snapshot.grep(/router\.(get|post)\s*\(/);
    expect(hits.length).toBeGreaterThanOrEqual(2);
    for (const hit of hits) {
      const lines = await snapshot.lines(hit.file);
      expect(lines?.[hit.line - 1]).toBe(hit.text);
    }
  });

  test("grep honours its limit and its file list", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("express-knex"));
    const limited = await snapshot.grep(/require\(/, { limit: 1 });
    expect(limited).toHaveLength(1);
    const scoped = await snapshot.grep(/require\(/, { files: ["src/middleware/auth.js"] });
    expect(scoped.every((hit) => hit.file === "src/middleware/auth.js")).toBe(true);
  });

  test("a missing file reads as undefined rather than throwing", async () => {
    const snapshot = await RepoSnapshot.create(fs, fixturePath("pure-api"));
    expect(await snapshot.read("does/not/exist.ts")).toBeUndefined();
    expect(await snapshot.lines("does/not/exist.ts")).toBeUndefined();
  });

  test("a file over the byte cap is skipped and the scan reports itself truncated", async () => {
    const snapshot = await RepoSnapshot.create(
      memoryFileSystem({ "big.ts": "x".repeat(1000), "small.ts": "export const a = 1;" }),
      "",
      { limits: { maxFileBytes: 100 } },
    );
    expect(await snapshot.read("big.ts")).toBeUndefined();
    expect(await snapshot.read("small.ts")).toBe("export const a = 1;");
    expect(snapshot.stats().truncated).toBe(true);
    expect(snapshot.stats().filesSeen).toBe(2);
    expect(snapshot.stats().filesRead).toBe(1);
  });

  test("reads each file once, however many detectors ask for it", async () => {
    let reads = 0;
    const counting: ProfileFileSystem = {
      ...memoryFileSystem({ "a.ts": "const a = 1;" }),
      async readFile(path: string): Promise<string> {
        reads += 1;
        if (path.replace(/^\/+/, "") !== "a.ts") throw new Error("ENOENT");
        return "const a = 1;";
      },
    };
    const snapshot = await RepoSnapshot.create(counting, "");
    await snapshot.read("a.ts");
    await snapshot.read("a.ts");
    await snapshot.lines("a.ts");
    expect(reads).toBe(1);
  });
});

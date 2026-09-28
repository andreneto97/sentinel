import { describe, expect, test } from "bun:test";
import type { ToolsLock } from "../contracts/tools.ts";
import { MemoryFileSystem } from "./_test-doubles.ts";
import { createToolResolver } from "./resolve.ts";

const CACHE = "/cache/sentinel";
const PATH_ENV = "/usr/local/bin:/usr/bin";

function fixtureLock(): ToolsLock {
  return {
    schemaVersion: "1.0",
    binaries: {
      hadolint: {
        version: "2.15.1",
        description: "Dockerfile linting.",
        platforms: {
          "darwin-arm64": {
            url: "https://example.test/hadolint",
            sha256: "a".repeat(64),
            archive: "raw",
            binaryPath: "hadolint",
          },
        },
      },
      opengrep: {
        version: "1.30.0",
        platforms: {
          "darwin-arm64": {
            url: "https://example.test/opengrep",
            sha256: null,
            archive: "raw",
            binaryPath: "opengrep",
          },
        },
      },
    },
    node: {
      "dependency-cruiser": {
        package: "dependency-cruiser",
        version: "18.4.0",
        binaryPath: "node_modules/.bin/depcruise",
      },
    },
  };
}

function resolverOver(fs: MemoryFileSystem) {
  return createToolResolver({
    lock: fixtureLock(),
    fs,
    cacheRoot: CACHE,
    platform: "darwin-arm64",
    pathEnv: PATH_ENV,
  });
}

describe("createToolResolver", () => {
  test("returns null rather than a PATH binary by default", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile("/usr/bin/hadolint", "system hadolint", { mode: 0o755 });

    expect(await resolverOver(fs).resolve("hadolint")).toBeNull();
  });

  test("returns the PATH binary only when allowPath is opted into", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile("/usr/bin/hadolint", "system hadolint", { mode: 0o755 });

    expect(await resolverOver(fs).resolve("hadolint", { allowPath: true })).toBe(
      "/usr/bin/hadolint",
    );
  });

  test("prefers the pinned cache copy over anything on PATH", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile("/usr/bin/hadolint", "system hadolint", { mode: 0o755 });
    await fs.writeFile(`${CACHE}/tools/hadolint/2.15.1/hadolint`, "pinned hadolint", {
      mode: 0o755,
    });

    const resolver = resolverOver(fs);
    expect(await resolver.resolve("hadolint")).toBe(`${CACHE}/tools/hadolint/2.15.1/hadolint`);
    expect(await resolver.resolve("hadolint", { allowPath: true })).toBe(
      `${CACHE}/tools/hadolint/2.15.1/hadolint`,
    );
  });

  test("ignores a PATH entry that is not executable", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile("/usr/bin/hadolint", "a data file, not the tool", { mode: 0o644 });

    expect(await resolverOver(fs).resolve("hadolint", { allowPath: true })).toBeNull();
  });

  test("never resolves a name the lockfile does not know, even with allowPath", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile("/usr/bin/semgrep", "system semgrep", { mode: 0o755 });

    expect(await resolverOver(fs).resolve("semgrep", { allowPath: true })).toBeNull();
  });

  test("resolves a Node tool from Sentinel's own prefix", async () => {
    const fs = new MemoryFileSystem();
    const binary = `${CACHE}/node/dependency-cruiser/18.4.0/node_modules/.bin/depcruise`;
    await fs.writeFile(binary, "#!/usr/bin/env node\n", { mode: 0o755 });

    expect(await resolverOver(fs).resolve("dependency-cruiser")).toBe(binary);
  });

  test("searches PATH under the executable name, not the lockfile key", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile("/usr/local/bin/depcruise", "system depcruise", { mode: 0o755 });

    expect(await resolverOver(fs).resolve("dependency-cruiser", { allowPath: true })).toBe(
      "/usr/local/bin/depcruise",
    );
  });

  test("returns null when the lockfile pins no artifact for this platform", async () => {
    const fs = new MemoryFileSystem();
    const resolver = createToolResolver({
      lock: fixtureLock(),
      fs,
      cacheRoot: CACHE,
      platform: "linux-x64",
      pathEnv: PATH_ENV,
    });

    expect(await resolver.resolve("hadolint", { allowPath: true })).toBeNull();
  });
});

describe("ToolResolver.status", () => {
  test("reports where a tool came from and whether it is pinned", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile(`${CACHE}/tools/hadolint/2.15.1/hadolint`, "pinned hadolint", {
      mode: 0o755,
    });
    await fs.writeFile("/usr/bin/opengrep", "system opengrep", { mode: 0o755 });

    const resolver = resolverOver(fs);

    expect(await resolver.status("hadolint")).toEqual({
      name: "hadolint",
      kind: "binary",
      version: "2.15.1",
      path: `${CACHE}/tools/hadolint/2.15.1/hadolint`,
      origin: "cache",
      pinned: true,
      description: "Dockerfile linting.",
    });
    expect(await resolver.status("opengrep", { allowPath: true })).toEqual({
      name: "opengrep",
      kind: "binary",
      version: "1.30.0",
      path: "/usr/bin/opengrep",
      origin: "path",
      pinned: false,
      description: null,
    });
  });

  test("reports a missing tool without inventing a path", async () => {
    const fs = new MemoryFileSystem();

    expect(await resolverOver(fs).status("hadolint")).toMatchObject({
      path: null,
      origin: null,
    });
  });

  test("returns null for a name outside the lockfile", async () => {
    expect(await resolverOver(new MemoryFileSystem()).status("semgrep")).toBeNull();
  });

  test("statusAll covers every tool in the lockfile, binaries first", async () => {
    const statuses = await resolverOver(new MemoryFileSystem()).statusAll();

    expect(statuses.map((entry) => entry.name)).toEqual([
      "hadolint",
      "opengrep",
      "dependency-cruiser",
    ]);
  });
});

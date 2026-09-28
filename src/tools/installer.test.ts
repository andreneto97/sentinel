import { describe, expect, test } from "bun:test";
import type { ToolsLock } from "../contracts/tools.ts";
import { serializeToolsLock } from "../contracts/tools.ts";
import type { FileSystem } from "../ports/file-system.ts";
import type { ProcessExecutor } from "../ports/process-executor.ts";
import { MemoryFileSystem, RecordingProcessExecutor, stubFetch } from "./_test-doubles.ts";
import {
  type FetchLike,
  NODE_INSTALL_MARKER,
  type ToolFileSystem,
  ToolInstallError,
  type ToolProcessExecutor,
  createToolInstaller,
  defaultCacheRoot,
  detectPlatform,
  loadToolsLock,
} from "./installer.ts";
import type { ResolverFileSystem } from "./resolve.ts";

const CACHE = "/cache/sentinel";
const RAW_URL = "https://example.test/hadolint-macos-arm64";
const TGZ_URL = "https://example.test/trivy.tar.gz";

/** The digests below are real SHA-256 values of these exact byte strings. */
const RAW_BYTES = new TextEncoder().encode("#!/bin/sh\necho sentinel\n");
const RAW_SHA256 = "76adcc28d0cb1f8aca1a2d04b80779bc487f3e15a4ac11cbe8b49d93b83152c8";
const TGZ_BYTES = new TextEncoder().encode("fake-tarball-bytes\n");
const TGZ_SHA256 = "a2520bf1ab17d39e16600c3886347f8b2b295ede083a9dff924f3f7e3ac6cdfc";

function baseLock(rawSha: string | null = RAW_SHA256): ToolsLock {
  return {
    schemaVersion: "1.0",
    binaries: {
      hadolint: {
        version: "2.15.1",
        platforms: {
          "darwin-arm64": { url: RAW_URL, sha256: rawSha, archive: "raw", binaryPath: "hadolint" },
        },
      },
      trivy: {
        version: "0.74.0",
        platforms: {
          "darwin-arm64": {
            url: TGZ_URL,
            sha256: TGZ_SHA256,
            archive: "tar.gz",
            binaryPath: "trivy",
          },
        },
      },
    },
    node: {
      knip: { package: "knip", version: "6.37.0", binaryPath: "node_modules/.bin/knip" },
    },
  };
}

interface Harness {
  fs: MemoryFileSystem;
  exec: RecordingProcessExecutor;
  calls: string[];
  installer: ReturnType<typeof createToolInstaller>;
}

function harness(
  options: {
    lock?: ToolsLock;
    routes?: Record<string, Uint8Array | number>;
    platform?: "darwin-arm64" | "linux-x64";
    exec?: RecordingProcessExecutor;
  } = {},
): Harness {
  const fs = new MemoryFileSystem();
  const exec = options.exec ?? new RecordingProcessExecutor();
  const { fetch, calls } = stubFetch(options.routes ?? { [RAW_URL]: RAW_BYTES });
  const installer = createToolInstaller({
    lock: options.lock ?? baseLock(),
    fs,
    exec,
    fetch,
    cacheRoot: CACHE,
    platform: options.platform ?? "darwin-arm64",
    randomId: () => "stage",
  });
  return { fs, exec, calls, installer };
}

async function capture(promise: Promise<unknown>): Promise<ToolInstallError> {
  const outcome = await promise.then(
    () => null,
    (error: unknown) => error,
  );
  expect(outcome).toBeInstanceOf(ToolInstallError);
  return outcome as ToolInstallError;
}

describe("createToolInstaller", () => {
  test("installs a raw binary, verifies the digest and marks it executable", async () => {
    const { fs, calls, installer } = harness();

    const result = await installer.installBinaryTool("hadolint");

    expect(result).toEqual({
      name: "hadolint",
      kind: "binary",
      version: "2.15.1",
      path: `${CACHE}/tools/hadolint/2.15.1/hadolint`,
      status: "installed",
    });
    expect(calls).toEqual([RAW_URL]);
    expect(fs.modeOf(result.path)).toBe(0o755);
    expect(await fs.isExecutable(result.path)).toBe(true);
    expect(await fs.readFile(result.path)).toBe("#!/bin/sh\necho sentinel\n");
    // A raw artifact never needs staging, so only the binary exists.
    expect(fs.filePaths()).toEqual([result.path]);
  });

  test("is idempotent: a second install downloads nothing", async () => {
    const { calls, installer } = harness();

    const first = await installer.installBinaryTool("hadolint");
    const second = await installer.installBinaryTool("hadolint");

    expect(first.status).toBe("installed");
    expect(second.status).toBe("already-installed");
    expect(second.path).toBe(first.path);
    expect(calls).toEqual([RAW_URL]);
  });

  test("force reinstalls even when the binary is already cached", async () => {
    const { calls, installer } = harness();

    await installer.installBinaryTool("hadolint");
    const again = await installer.installBinaryTool("hadolint", { force: true });

    expect(again.status).toBe("installed");
    expect(calls).toEqual([RAW_URL, RAW_URL]);
  });

  test("a digest mismatch aborts and leaves nothing behind", async () => {
    const { fs, installer } = harness({ lock: baseLock("0".repeat(64)) });

    const error = await capture(installer.installBinaryTool("hadolint"));

    expect(error.code).toBe("digest-mismatch");
    expect(error.message).toContain(RAW_SHA256);
    expect(fs.filePaths()).toEqual([]);
    expect(await fs.exists(`${CACHE}/tools/hadolint/2.15.1/hadolint`)).toBe(false);
    expect(await fs.exists(`${CACHE}/tmp/hadolint-2.15.1-stage`)).toBe(false);
  });

  test("refuses an unpinned entry unless allowUnpinned is passed", async () => {
    const { fs, calls, installer } = harness({ lock: baseLock(null) });

    const error = await capture(installer.installBinaryTool("hadolint"));
    expect(error.code).toBe("unpinned");
    expect(error.message).toContain("update-tools-lock");
    expect(calls).toEqual([]);
    expect(fs.filePaths()).toEqual([]);

    const result = await installer.installBinaryTool("hadolint", { allowUnpinned: true });
    expect(result.status).toBe("installed");
    expect(calls).toEqual([RAW_URL]);
  });

  test("surfaces an HTTP error with the url and status", async () => {
    const { fs, installer } = harness({ routes: {} });

    const error = await capture(installer.installBinaryTool("hadolint"));

    expect(error.code).toBe("download-failed");
    expect(error.message).toContain("HTTP 404");
    expect(error.message).toContain(RAW_URL);
    expect(fs.filePaths()).toEqual([]);
  });

  test("unpacks a tar.gz through the process executor and publishes the binary", async () => {
    const fs = new MemoryFileSystem();
    const exec = new RecordingProcessExecutor(async (call) => {
      const target = call.args[call.args.indexOf("-C") + 1] ?? "";
      await fs.writeFile(`${target}/trivy`, "trivy-binary");
      await fs.writeFile(`${target}/README.md`, "not the binary");
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const { fetch } = stubFetch({ [TGZ_URL]: TGZ_BYTES });
    const installer = createToolInstaller({
      lock: baseLock(),
      fs,
      exec,
      fetch,
      cacheRoot: CACHE,
      platform: "darwin-arm64",
      randomId: () => "stage",
    });

    const result = await installer.installBinaryTool("trivy");

    expect(result.path).toBe(`${CACHE}/tools/trivy/0.74.0/trivy`);
    expect(exec.calls).toEqual([
      {
        command: "tar",
        args: [
          "-xzf",
          `${CACHE}/tmp/trivy-0.74.0-stage/archive.tgz`,
          "-C",
          `${CACHE}/tmp/trivy-0.74.0-stage/unpacked`,
        ],
        cwd: null,
      },
    ]);
    expect(await fs.readFile(result.path)).toBe("trivy-binary");
    expect(fs.modeOf(result.path)).toBe(0o755);
    // The staging tree, including the archive and the sidecar README, is gone.
    expect(fs.filePaths()).toEqual([result.path]);
  });

  test("unpacks a zip with unzip", async () => {
    const fs = new MemoryFileSystem();
    const exec = new RecordingProcessExecutor(async (call) => {
      const target = call.args[call.args.indexOf("-d") + 1] ?? "";
      await fs.writeFile(`${target}/trivy`, "trivy-binary");
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const lock = baseLock();
    const trivy = lock.binaries.trivy?.platforms["darwin-arm64"];
    expect(trivy).toBeDefined();
    if (trivy !== undefined) trivy.archive = "zip";
    const { fetch } = stubFetch({ [TGZ_URL]: TGZ_BYTES });
    const installer = createToolInstaller({
      lock,
      fs,
      exec,
      fetch,
      cacheRoot: CACHE,
      platform: "darwin-arm64",
      randomId: () => "stage",
    });

    await installer.installBinaryTool("trivy");

    expect(exec.calls[0]?.command).toBe("unzip");
    expect(exec.calls[0]?.args).toContain(`${CACHE}/tmp/trivy-0.74.0-stage/archive.zip`);
  });

  test("a failing extractor aborts and leaves nothing behind", async () => {
    const exec = new RecordingProcessExecutor(() => ({
      exitCode: 2,
      stdout: "",
      stderr: "tar: unexpected end of file",
    }));
    const { fs, installer } = harness({ routes: { [TGZ_URL]: TGZ_BYTES }, exec });

    const error = await capture(installer.installBinaryTool("trivy"));

    expect(error.code).toBe("extract-failed");
    expect(error.message).toContain("unexpected end of file");
    expect(fs.filePaths()).toEqual([]);
  });

  test("an archive without the pinned binaryPath aborts and leaves nothing behind", async () => {
    const { fs, installer } = harness({ routes: { [TGZ_URL]: TGZ_BYTES } });

    const error = await capture(installer.installBinaryTool("trivy"));

    expect(error.code).toBe("binary-missing");
    expect(fs.filePaths()).toEqual([]);
  });

  test("reports a full disk as no-space rather than a generic failure", async () => {
    const fs = new MemoryFileSystem();
    // Same disk, but every write fails the way a full filesystem does.
    const full: ToolFileSystem = {
      readFile: (path) => fs.readFile(path),
      readFileBytes: (path) => fs.readFileBytes(path),
      mkdirp: (path) => fs.mkdirp(path),
      exists: (path) => fs.exists(path),
      remove: (path) => fs.remove(path),
      chmod: (path, mode) => fs.chmod(path, mode),
      writeFile: async () => {
        throw new Error("ENOSPC: no space left on device, write");
      },
    };
    const { fetch } = stubFetch({ [RAW_URL]: RAW_BYTES });
    const installer = createToolInstaller({
      lock: baseLock(),
      fs: full,
      exec: new RecordingProcessExecutor(),
      fetch,
      cacheRoot: CACHE,
      platform: "darwin-arm64",
      randomId: () => "stage",
    });

    const error = await capture(installer.installBinaryTool("hadolint"));

    expect(error.code).toBe("no-space");
  });

  test("rejects a platform the lockfile does not pin", async () => {
    const { calls, installer } = harness({ platform: "linux-x64" });

    const error = await capture(installer.installBinaryTool("hadolint"));

    expect(error.code).toBe("unsupported-platform");
    expect(calls).toEqual([]);
  });

  test("rejects a tool the lockfile does not know", async () => {
    const { installer } = harness();

    expect((await capture(installer.installBinaryTool("semgrep"))).code).toBe("unknown-tool");
    expect((await capture(installer.installNodeTool("eslint"))).code).toBe("unknown-tool");
  });

  test("installs a Node tool into a Sentinel-owned prefix, pinning the exact version", async () => {
    const fs = new MemoryFileSystem();
    const exec = new RecordingProcessExecutor(async (call) => {
      await fs.writeFile(`${call.cwd ?? "."}/node_modules/.bin/knip`, "#!/usr/bin/env node\n");
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const { fetch } = stubFetch({});
    const installer = createToolInstaller({
      lock: baseLock(),
      fs,
      exec,
      fetch,
      cacheRoot: CACHE,
      platform: "darwin-arm64",
      randomId: () => "stage",
    });

    const result = await installer.installNodeTool("knip");

    expect(result).toEqual({
      name: "knip",
      kind: "node",
      version: "6.37.0",
      path: `${CACHE}/node/knip/6.37.0/node_modules/.bin/knip`,
      status: "installed",
    });
    expect(exec.calls).toEqual([
      { command: "bun", args: ["install", "--no-summary"], cwd: `${CACHE}/node/knip/6.37.0` },
    ]);
    const manifest: unknown = JSON.parse(
      await fs.readFile(`${CACHE}/node/knip/6.37.0/package.json`),
    );
    expect(manifest).toMatchObject({ dependencies: { knip: "6.37.0" } });
    expect(await fs.exists(`${CACHE}/node/knip/6.37.0/${NODE_INSTALL_MARKER}`)).toBe(true);

    expect(await installer.installNodeTool("knip")).toMatchObject({ status: "already-installed" });
    expect(exec.calls).toHaveLength(1);
  });

  test("a Node prefix without the completion marker is reinstalled, not trusted", async () => {
    const fs = new MemoryFileSystem();
    const exec = new RecordingProcessExecutor(async (call) => {
      await fs.writeFile(`${call.cwd ?? "."}/node_modules/.bin/knip`, "#!/usr/bin/env node\n");
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    // A half-finished prefix: the bin link exists but the install never ended.
    await fs.writeFile(`${CACHE}/node/knip/6.37.0/node_modules/.bin/knip`, "stale");
    const { fetch } = stubFetch({});
    const installer = createToolInstaller({
      lock: baseLock(),
      fs,
      exec,
      fetch,
      cacheRoot: CACHE,
      platform: "darwin-arm64",
    });

    expect(await installer.installNodeTool("knip")).toMatchObject({ status: "installed" });
    expect(exec.calls).toHaveLength(1);
  });

  test("a failing bun install is reported and leaves no completion marker", async () => {
    const exec = new RecordingProcessExecutor(() => ({
      exitCode: 1,
      stdout: "",
      stderr: "error: package knip@6.37.0 not found",
    }));
    const { fs, installer } = harness({ routes: {}, exec });

    const error = await capture(installer.installNodeTool("knip"));

    expect(error.code).toBe("download-failed");
    expect(error.message).toContain("not found");
    expect(await fs.exists(`${CACHE}/node/knip/6.37.0/${NODE_INSTALL_MARKER}`)).toBe(false);
  });

  test("installAll walks binaries then node tools, in name order", async () => {
    const fs = new MemoryFileSystem();
    const exec = new RecordingProcessExecutor(async (call) => {
      if (call.command === "bun") {
        await fs.writeFile(`${call.cwd ?? "."}/node_modules/.bin/knip`, "#!/usr/bin/env node\n");
      } else {
        const target = call.args[call.args.indexOf("-C") + 1] ?? "";
        await fs.writeFile(`${target}/trivy`, "trivy-binary");
      }
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    const { fetch } = stubFetch({ [RAW_URL]: RAW_BYTES, [TGZ_URL]: TGZ_BYTES });
    const installer = createToolInstaller({
      lock: baseLock(),
      fs,
      exec,
      fetch,
      cacheRoot: CACHE,
      platform: "darwin-arm64",
      randomId: () => "stage",
    });

    const results = await installer.installAll();

    expect(results.map((entry) => entry.name)).toEqual(["hadolint", "trivy", "knip"]);
    expect(results.every((entry) => entry.status === "installed")).toBe(true);
  });
});

describe("loadToolsLock", () => {
  test("reads and validates a lockfile through the filesystem port", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile("/somewhere/tools.lock.json", serializeToolsLock(baseLock()));

    const lock = await loadToolsLock(fs, "/somewhere/tools.lock.json");

    expect(lock.binaries.hadolint?.version).toBe("2.15.1");
    expect(lock.node.knip?.package).toBe("knip");
  });

  test("rejects a lockfile that does not match the schema", async () => {
    const fs = new MemoryFileSystem();
    await fs.writeFile("/somewhere/tools.lock.json", `{"schemaVersion":"1.0"}`);

    await expect(loadToolsLock(fs, "/somewhere/tools.lock.json")).rejects.toThrow();
  });
});

describe("port conformance", () => {
  test("the real ports satisfy the slices the tools package declares", () => {
    // Compiling is the assertion: a signature drift in src/ports breaks here.
    const asInstallerFs: (port: FileSystem) => ToolFileSystem = (port) => port;
    const asResolverFs: (port: FileSystem) => ResolverFileSystem = (port) => port;
    const asExecutor: (port: ProcessExecutor) => ToolProcessExecutor = (port) => port;
    const asFetch: FetchLike = fetch;

    expect(
      [asInstallerFs, asResolverFs, asExecutor, asFetch].every((fn) => typeof fn === "function"),
    ).toBe(true);
  });
});

describe("platform and cache helpers", () => {
  test("detectPlatform returns a pinned platform on the machines Sentinel targets", () => {
    const platform = detectPlatform();
    expect(
      platform === null ||
        ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"].includes(platform),
    ).toBe(true);
  });

  test("defaultCacheRoot honours XDG_CACHE_HOME", () => {
    expect(defaultCacheRoot({ XDG_CACHE_HOME: "/xdg" })).toBe("/xdg/sentinel");
    expect(defaultCacheRoot({ HOME: "/home/x" })).toMatch(/\/\.cache\/sentinel$/);
  });
});

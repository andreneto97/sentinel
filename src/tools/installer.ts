import { homedir, arch as osArch, platform as osPlatform } from "node:os";
import { join } from "node:path";
import {
  type Platform,
  type ToolArtifact,
  type ToolsLock,
  parseToolsLock,
} from "../contracts/tools.ts";
import { createFileSystem } from "../ports/file-system.ts";

/**
 * The slice of `src/ports/file-system.ts` the installer needs. Declared
 * structurally — with the port's own method names — so nothing under
 * `src/tools/` imports `node:fs`, and so tests can supply an in-memory disk.
 */
export interface ToolFileSystem {
  readFile(path: string): Promise<string>;
  readFileBytes(path: string): Promise<Uint8Array>;
  /** Atomic in the real port: temp file, fsync, rename. */
  writeFile(path: string, data: string | Uint8Array, options?: { mode?: number }): Promise<void>;
  mkdirp(path: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  remove(path: string): Promise<void>;
  chmod(path: string, mode: number): Promise<void>;
}

/** The outcome fields of a command run that the installer reads. */
export interface ToolProcessResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

/** The slice of `src/ports/process-executor.ts` the installer needs. */
export interface ToolProcessExecutor {
  run(
    command: string,
    args?: readonly string[],
    options?: { cwd?: string },
  ): Promise<ToolProcessResult>;
}

/** The subset of `fetch` the downloader uses; injected so tests need no network. */
export type FetchLike = (url: string, init?: { redirect?: "follow" }) => Promise<Response>;

/** Why an install refused or failed; the CLI maps these to exit codes and hints. */
export type ToolInstallErrorCode =
  | "unknown-tool"
  | "unsupported-platform"
  | "unpinned"
  | "download-failed"
  | "digest-mismatch"
  | "extract-failed"
  | "binary-missing"
  | "no-space"
  | "io-error";

/** An install that could not complete, tagged with a machine-readable reason. */
export class ToolInstallError extends Error {
  readonly code: ToolInstallErrorCode;
  readonly tool: string;

  constructor(
    code: ToolInstallErrorCode,
    tool: string,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "ToolInstallError";
    this.code = code;
    this.tool = tool;
  }
}

/** Map the running process onto one of Sentinel's pinned platforms, or null. */
export function detectPlatform(): Platform | null {
  const os = osPlatform();
  const cpu = osArch();
  if (os !== "darwin" && os !== "linux") return null;
  if (cpu !== "arm64" && cpu !== "x64") return null;
  return `${os}-${cpu}`;
}

/** Root of Sentinel's tool cache: `${XDG_CACHE_HOME:-~/.cache}/sentinel`. */
export function defaultCacheRoot(env: Record<string, string | undefined> = process.env): string {
  const xdg = env.XDG_CACHE_HOME;
  const base = xdg !== undefined && xdg.length > 0 ? xdg : join(homedir(), ".cache");
  return join(base, "sentinel");
}

/** Directory a pinned binary tool version is installed into. */
export function binaryToolDir(cacheRoot: string, name: string, version: string): string {
  return join(cacheRoot, "tools", name, version);
}

/** Directory a pinned Node tool version is installed into. */
export function nodeToolDir(cacheRoot: string, name: string, version: string): string {
  return join(cacheRoot, "node", name, version);
}

/**
 * Written last in a Node tool prefix. `bun install` populates a directory in
 * place, so the marker — not the directory — is what says the prefix is whole.
 */
export const NODE_INSTALL_MARKER = ".sentinel-installed";

/** Location of the lockfile shipped next to this module. */
export const TOOLS_LOCK_PATH = join(import.meta.dir, "tools.lock.json");

/** Read and validate `tools.lock.json` through the filesystem port. */
export async function loadToolsLock(
  fs: ToolFileSystem,
  path: string = TOOLS_LOCK_PATH,
): Promise<ToolsLock> {
  return parseToolsLock(await fs.readFile(path));
}

/**
 * Composition-root convenience for the CLI: read the shipped lockfile with the
 * real filesystem port. Prefer {@link loadToolsLock} anywhere a port is already
 * in hand.
 */
export async function readToolsLock(path: string = TOOLS_LOCK_PATH): Promise<ToolsLock> {
  return loadToolsLock(createFileSystem(), path);
}

/** What an install did, and where the executable ended up. */
export interface InstallResult {
  name: string;
  kind: "binary" | "node";
  version: string;
  path: string;
  status: "installed" | "already-installed";
}

export interface InstallOptions {
  /**
   * Allow installing an artifact whose `sha256` is null. Off by default: an
   * unverified download is exactly the supply-chain risk Sentinel reports on.
   */
  allowUnpinned?: boolean;
  /** Reinstall even when the executable is already in the cache. */
  force?: boolean;
}

export interface ToolInstaller {
  installBinaryTool(name: string, options?: InstallOptions): Promise<InstallResult>;
  installNodeTool(name: string, options?: InstallOptions): Promise<InstallResult>;
  /** Installs every tool in the lockfile, in name order, failing on the first error. */
  installAll(options?: InstallOptions): Promise<InstallResult[]>;
}

export interface ToolInstallerDeps {
  lock: ToolsLock;
  fs: ToolFileSystem;
  exec: ToolProcessExecutor;
  fetch: FetchLike;
  cacheRoot?: string;
  platform?: Platform;
  /** Injected so tests get deterministic staging directory names. */
  randomId?: () => string;
}

function describe(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

/** ENOSPC surfaces as a plain I/O error otherwise, which reads as a Sentinel bug. */
function toInstallError(tool: string, cause: unknown, context: string): ToolInstallError {
  if (cause instanceof ToolInstallError) return cause;
  const message = describe(cause);
  if (message.includes("ENOSPC") || message.includes("no space left")) {
    return new ToolInstallError(
      "no-space",
      tool,
      `${context}: no space left on the tool cache filesystem.`,
      { cause },
    );
  }
  return new ToolInstallError("io-error", tool, `${context}: ${message}`, { cause });
}

function concatChunks(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Build an installer bound to a lockfile, the OS ports and a cache root. */
export function createToolInstaller(deps: ToolInstallerDeps): ToolInstaller {
  const { lock, fs, exec } = deps;
  const fetchImpl = deps.fetch;
  const cacheRoot = deps.cacheRoot ?? defaultCacheRoot();
  const platform = deps.platform ?? detectPlatform();
  const nextId = deps.randomId ?? (() => Math.random().toString(36).slice(2, 10));

  /**
   * Fetch an artifact, hashing it as the bytes arrive, and hand back the bytes
   * only once the digest matches. An unverified artifact never reaches disk.
   */
  async function downloadVerified(tool: string, artifact: ToolArtifact): Promise<Uint8Array> {
    let response: Response;
    try {
      response = await fetchImpl(artifact.url, { redirect: "follow" });
    } catch (cause) {
      throw new ToolInstallError(
        "download-failed",
        tool,
        `Could not reach ${artifact.url}: ${describe(cause)}`,
        { cause },
      );
    }
    if (!response.ok) {
      const hint =
        response.status === 404
          ? " The pinned release may have been withdrawn; re-run scripts/update-tools-lock.ts."
          : "";
      throw new ToolInstallError(
        "download-failed",
        tool,
        `GET ${artifact.url} returned HTTP ${response.status} ${response.statusText}.${hint}`,
      );
    }
    const body = response.body;
    if (body === null) {
      throw new ToolInstallError(
        "download-failed",
        tool,
        `GET ${artifact.url} returned an empty body.`,
      );
    }

    const hasher = new Bun.CryptoHasher("sha256");
    const chunks: Uint8Array[] = [];
    let total = 0;
    const reader = body.getReader();
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        hasher.update(chunk.value);
        chunks.push(chunk.value);
        total += chunk.value.byteLength;
      }
    } catch (cause) {
      throw new ToolInstallError(
        "download-failed",
        tool,
        `Transfer of ${artifact.url} failed after ${total} bytes: ${describe(cause)}`,
        { cause },
      );
    }

    const digest = hasher.digest("hex");
    if (artifact.sha256 !== null && digest !== artifact.sha256) {
      throw new ToolInstallError(
        "digest-mismatch",
        tool,
        `SHA-256 mismatch for ${artifact.url}: expected ${artifact.sha256}, got ${digest}. Refusing to install.`,
      );
    }
    return concatChunks(chunks, total);
  }

  async function unpack(
    tool: string,
    artifact: ToolArtifact,
    archivePath: string,
    extractDir: string,
  ): Promise<void> {
    const [command, args] =
      artifact.archive === "zip"
        ? (["unzip", ["-q", "-o", archivePath, "-d", extractDir]] as const)
        : (["tar", ["-xzf", archivePath, "-C", extractDir]] as const);

    let result: ToolProcessResult;
    try {
      result = await exec.run(command, args);
    } catch (cause) {
      throw new ToolInstallError(
        "extract-failed",
        tool,
        `Could not run "${command}" to unpack ${archivePath}: ${describe(cause)}`,
        { cause },
      );
    }
    if (result.exitCode !== 0) {
      const detail = result.stderr.trim() || result.stdout.trim();
      throw new ToolInstallError(
        "extract-failed",
        tool,
        `"${command}" exited ${result.exitCode} unpacking ${archivePath}: ${detail}`,
      );
    }
  }

  /** Publish a verified executable at its final path; the port's write is atomic. */
  async function publish(tool: string, destination: string, bytes: Uint8Array): Promise<void> {
    try {
      await fs.writeFile(destination, bytes, { mode: 0o755 });
      // umask can clear bits from the create mode, so state them again.
      await fs.chmod(destination, 0o755);
    } catch (cause) {
      throw toInstallError(tool, cause, `Writing ${destination} failed`);
    }
  }

  async function installBinaryTool(
    name: string,
    options: InstallOptions = {},
  ): Promise<InstallResult> {
    const tool = lock.binaries[name];
    if (tool === undefined) {
      throw new ToolInstallError(
        "unknown-tool",
        name,
        `tools.lock.json has no binary tool named "${name}".`,
      );
    }
    if (platform === null) {
      throw new ToolInstallError(
        "unsupported-platform",
        name,
        `Sentinel has no pinned build for ${osPlatform()}/${osArch()}.`,
      );
    }
    const artifact = tool.platforms[platform];
    if (artifact === undefined) {
      throw new ToolInstallError(
        "unsupported-platform",
        name,
        `tools.lock.json pins no ${name} ${tool.version} artifact for ${platform}.`,
      );
    }

    const binary = join(binaryToolDir(cacheRoot, name, tool.version), artifact.binaryPath);
    if (options.force !== true && (await fs.exists(binary))) {
      return {
        name,
        kind: "binary",
        version: tool.version,
        path: binary,
        status: "already-installed",
      };
    }
    if (artifact.sha256 === null && options.allowUnpinned !== true) {
      throw new ToolInstallError(
        "unpinned",
        name,
        `${name} ${tool.version} has no pinned SHA-256 for ${platform}. Run "bun run scripts/update-tools-lock.ts" to pin it, or pass allowUnpinned to install without integrity verification.`,
      );
    }

    const bytes = await downloadVerified(name, artifact);

    if (artifact.archive === "raw") {
      await publish(name, binary, bytes);
      return { name, kind: "binary", version: tool.version, path: binary, status: "installed" };
    }

    // An archive has to touch disk for tar/unzip, so it goes to a staging
    // directory that is torn down however this ends.
    const staging = join(cacheRoot, "tmp", `${name}-${tool.version}-${nextId()}`);
    const unpacked = join(staging, "unpacked");
    const archivePath = join(staging, artifact.archive === "zip" ? "archive.zip" : "archive.tgz");
    try {
      await fs.mkdirp(unpacked);
      try {
        await fs.writeFile(archivePath, bytes);
      } catch (cause) {
        throw toInstallError(name, cause, `Staging ${artifact.url} at ${archivePath} failed`);
      }
      await unpack(name, artifact, archivePath, unpacked);

      const staged = join(unpacked, artifact.binaryPath);
      if (!(await fs.exists(staged))) {
        throw new ToolInstallError(
          "binary-missing",
          name,
          `${artifact.url} did not contain "${artifact.binaryPath}".`,
        );
      }
      await publish(name, binary, await fs.readFileBytes(staged));
    } finally {
      await fs.remove(staging).catch(() => undefined);
    }

    return { name, kind: "binary", version: tool.version, path: binary, status: "installed" };
  }

  async function installNodeTool(
    name: string,
    options: InstallOptions = {},
  ): Promise<InstallResult> {
    const tool = lock.node[name];
    if (tool === undefined) {
      throw new ToolInstallError(
        "unknown-tool",
        name,
        `tools.lock.json has no Node tool named "${name}".`,
      );
    }

    const installDir = nodeToolDir(cacheRoot, name, tool.version);
    const binary = join(installDir, tool.binaryPath);
    const marker = join(installDir, NODE_INSTALL_MARKER);
    if (options.force !== true && (await fs.exists(marker)) && (await fs.exists(binary))) {
      return {
        name,
        kind: "node",
        version: tool.version,
        path: binary,
        status: "already-installed",
      };
    }

    // A prefix Sentinel owns: an audit never adds anything to the target repo's
    // node_modules or lockfile. A half-finished prefix is thrown away first,
    // because `bun install` would otherwise build on top of it.
    try {
      await fs.remove(installDir);
      await fs.mkdirp(installDir);
      const manifest = {
        name: `sentinel-tool-${name}`,
        version: "0.0.0",
        private: true,
        dependencies: { [tool.package]: tool.version },
      };
      await fs.writeFile(
        join(installDir, "package.json"),
        `${JSON.stringify(manifest, null, 2)}\n`,
      );
    } catch (cause) {
      throw toInstallError(name, cause, `Preparing the ${name} prefix at ${installDir} failed`);
    }

    let result: ToolProcessResult;
    try {
      result = await exec.run("bun", ["install", "--no-summary"], { cwd: installDir });
    } catch (cause) {
      throw toInstallError(name, cause, `Could not run "bun install" in ${installDir}`);
    }
    if (result.exitCode !== 0) {
      const detail = result.stderr.trim() || result.stdout.trim();
      throw new ToolInstallError(
        "download-failed",
        name,
        `"bun install" exited ${result.exitCode} installing ${tool.package}@${tool.version}: ${detail}`,
      );
    }

    if (!(await fs.exists(binary))) {
      throw new ToolInstallError(
        "binary-missing",
        name,
        `${tool.package}@${tool.version} did not provide "${tool.binaryPath}".`,
      );
    }
    try {
      await fs.writeFile(marker, `${tool.package}@${tool.version}\n`);
    } catch (cause) {
      throw toInstallError(name, cause, `Marking the ${name} prefix complete failed`);
    }

    return { name, kind: "node", version: tool.version, path: binary, status: "installed" };
  }

  async function installAll(options: InstallOptions = {}): Promise<InstallResult[]> {
    const results: InstallResult[] = [];
    for (const name of Object.keys(lock.binaries).sort()) {
      results.push(await installBinaryTool(name, options));
    }
    for (const name of Object.keys(lock.node).sort()) {
      results.push(await installNodeTool(name, options));
    }
    return results;
  }

  return { installBinaryTool, installNodeTool, installAll };
}

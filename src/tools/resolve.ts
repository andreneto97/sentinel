import { basename, join } from "node:path";
import type { Platform, ToolsLock } from "../contracts/tools.ts";
import { createFileSystem } from "../ports/file-system.ts";
import {
  binaryToolDir,
  defaultCacheRoot,
  detectPlatform,
  nodeToolDir,
  readToolsLock,
} from "./installer.ts";

/** The slice of `src/ports/file-system.ts` the resolver needs. */
export interface ResolverFileSystem {
  exists(path: string): Promise<boolean>;
  /** Used for PATH candidates: a non-executable file of the right name is not the tool. */
  isExecutable(path: string): Promise<boolean>;
}

export interface ResolveOptions {
  /**
   * Fall back to the first match on PATH when the pinned build is not cached.
   * Off by default: a PATH binary is an unknown version with an unknown
   * provenance, which would make the run unreproducible without saying so.
   */
  allowPath?: boolean;
}

/** What `sentinel doctor` prints for one tool. */
export interface ToolStatus {
  name: string;
  kind: "binary" | "node";
  /** The version the lockfile pins, which is not necessarily the one on PATH. */
  version: string;
  /** Absolute path to the executable, or null when it is unavailable. */
  path: string | null;
  origin: "cache" | "path" | null;
  /** False when the lockfile carries no SHA-256 for this platform. */
  pinned: boolean;
  /** What the tool buys the report, for the missing-coverage disclosure. */
  description: string | null;
}

export interface ToolResolver {
  /** Absolute path to a tool's executable, or null when it is not available. */
  resolve(name: string, options?: ResolveOptions): Promise<string | null>;
  /** Availability of one tool, or null when the lockfile does not know the name. */
  status(name: string, options?: ResolveOptions): Promise<ToolStatus | null>;
  /** Availability of every tool in the lockfile, binaries first, each name-sorted. */
  statusAll(options?: ResolveOptions): Promise<ToolStatus[]>;
}

export interface ToolResolverDeps {
  lock: ToolsLock;
  fs: ResolverFileSystem;
  cacheRoot?: string;
  platform?: Platform;
  /** PATH to search when `allowPath` is set; defaults to the process PATH. */
  pathEnv?: string;
}

/** Build a resolver over the tool cache described by a lockfile. */
export function createToolResolver(deps: ToolResolverDeps): ToolResolver {
  const { lock, fs } = deps;
  const cacheRoot = deps.cacheRoot ?? defaultCacheRoot();
  const platform = deps.platform ?? detectPlatform();
  const pathEnv = deps.pathEnv ?? process.env.PATH ?? "";

  /** The cache path for a tool, or null when the lockfile cannot place it there. */
  function cacheCandidate(name: string): string | null {
    const binary = lock.binaries[name];
    if (binary !== undefined) {
      if (platform === null) return null;
      const artifact = binary.platforms[platform];
      if (artifact === undefined) return null;
      return join(binaryToolDir(cacheRoot, name, binary.version), artifact.binaryPath);
    }
    const node = lock.node[name];
    if (node !== undefined) {
      return join(nodeToolDir(cacheRoot, name, node.version), node.binaryPath);
    }
    return null;
  }

  /** The executable name a tool goes by on PATH, which can differ from its key. */
  function executableName(name: string): string | null {
    const binary = lock.binaries[name];
    if (binary !== undefined) {
      if (platform === null) return null;
      const artifact = binary.platforms[platform];
      return artifact === undefined ? null : basename(artifact.binaryPath);
    }
    const node = lock.node[name];
    return node === undefined ? null : basename(node.binaryPath);
  }

  async function searchPath(executable: string): Promise<string | null> {
    for (const entry of pathEnv.split(":")) {
      if (entry.length === 0) continue;
      const candidate = join(entry, executable);
      if (await fs.isExecutable(candidate)) return candidate;
    }
    return null;
  }

  async function resolve(name: string, options: ResolveOptions = {}): Promise<string | null> {
    const candidate = cacheCandidate(name);
    if (candidate !== null && (await fs.exists(candidate))) return candidate;
    if (options.allowPath !== true) return null;
    const executable = executableName(name);
    if (executable === null) return null;
    return searchPath(executable);
  }

  async function status(name: string, options: ResolveOptions = {}): Promise<ToolStatus | null> {
    const binary = lock.binaries[name];
    const node = lock.node[name];
    if (binary === undefined && node === undefined) return null;

    const found = await resolve(name, options);
    const origin = found === null ? null : found.startsWith(`${cacheRoot}/`) ? "cache" : "path";

    if (binary !== undefined) {
      const artifact = platform === null ? undefined : binary.platforms[platform];
      return {
        name,
        kind: "binary",
        version: binary.version,
        path: found,
        origin,
        pinned: artifact !== undefined && artifact.sha256 !== null,
        description: binary.description ?? null,
      };
    }
    if (node === undefined) return null;
    return {
      name,
      kind: "node",
      version: node.version,
      path: found,
      origin,
      // An npm package is pinned by its exact version; there is no artifact digest.
      pinned: true,
      description: node.description ?? null,
    };
  }

  async function statusAll(options: ResolveOptions = {}): Promise<ToolStatus[]> {
    const names = [...Object.keys(lock.binaries).sort(), ...Object.keys(lock.node).sort()];
    const statuses: ToolStatus[] = [];
    for (const name of names) {
      const entry = await status(name, options);
      if (entry !== null) statuses.push(entry);
    }
    return statuses;
  }

  return { resolve, status, statusAll };
}

/**
 * Composition-root convenience for the CLI and `doctor`: resolve a pinned tool
 * using the shipped lockfile, the default cache and the real filesystem port.
 * Prefer {@link createToolResolver} anywhere a lockfile and a port are already
 * in hand — this reads the lockfile on every call.
 */
export async function resolveTool(
  name: string,
  options: ResolveOptions = {},
): Promise<string | null> {
  const resolver = createToolResolver({ lock: await readToolsLock(), fs: createFileSystem() });
  return resolver.resolve(name, options);
}

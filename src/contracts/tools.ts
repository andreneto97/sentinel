import { z } from "zod";

/** Bumped on every breaking change to the shape of `tools.lock.json`. */
export const TOOLS_LOCK_SCHEMA_VERSION = "1.0";

/**
 * The platforms Sentinel pins tool binaries for. Kept in this exact order so
 * the lockfile serialiser produces a stable diff.
 */
export const PLATFORMS = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"] as const;

/** One of Sentinel's four supported `<os>-<arch>` targets. */
export const PlatformSchema = z.enum(PLATFORMS);
export type Platform = z.infer<typeof PlatformSchema>;

/** How a downloaded artifact is unpacked; `raw` is a bare executable. */
export const ArchiveKindSchema = z.enum(["tar.gz", "zip", "raw"]);
export type ArchiveKind = z.infer<typeof ArchiveKindSchema>;

/** Lowercase hex SHA-256 of a release artifact. */
export const Sha256Schema = z
  .string()
  .regex(/^[0-9a-f]{64}$/, "expected 64 lowercase hex characters");

/**
 * One platform's release artifact. `sha256` is `null` only for an entry that
 * has not been pinned yet; the installer refuses those unless explicitly told
 * otherwise, so an unpinned entry can never be downloaded by accident.
 */
export const ToolArtifactSchema = z.object({
  url: z.url(),
  sha256: Sha256Schema.nullable(),
  archive: ArchiveKindSchema,
  /** Path of the executable inside the unpacked archive (the file name for `raw`). */
  binaryPath: z.string().min(1),
});
export type ToolArtifact = z.infer<typeof ToolArtifactSchema>;

/**
 * Per-platform artifacts, spelled out rather than built from a record so a
 * missing platform is a typed `undefined` the installer has to handle.
 */
export const PlatformArtifactsSchema = z.object({
  "darwin-arm64": ToolArtifactSchema.optional(),
  "darwin-x64": ToolArtifactSchema.optional(),
  "linux-arm64": ToolArtifactSchema.optional(),
  "linux-x64": ToolArtifactSchema.optional(),
});
export type PlatformArtifacts = z.infer<typeof PlatformArtifactsSchema>;

/** A tool Sentinel downloads as a pre-built binary from a GitHub release. */
export const BinaryToolSchema = z.object({
  version: z.string().min(1),
  /** What the tool buys the report; `sentinel doctor` prints it when it is missing. */
  description: z.string().optional(),
  platforms: PlatformArtifactsSchema,
});
export type BinaryTool = z.infer<typeof BinaryToolSchema>;

/**
 * A tool Sentinel installs from npm into its own cache prefix. Never installed
 * into the target repository, so an audit cannot mutate what it is auditing.
 */
export const NodeToolSchema = z.object({
  /** npm package name, kept separate from the lockfile key. */
  package: z.string().min(1),
  /** Exact version — a range would make a run unreproducible. */
  version: z.string().regex(/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/, "expected an exact version"),
  description: z.string().optional(),
  /** Executable path relative to the install prefix, e.g. `node_modules/.bin/knip`. */
  binaryPath: z.string().min(1),
});
export type NodeTool = z.infer<typeof NodeToolSchema>;

/** The whole `tools.lock.json` document. */
export const ToolsLockSchema = z.object({
  schemaVersion: z.literal(TOOLS_LOCK_SCHEMA_VERSION),
  binaries: z.record(z.string(), BinaryToolSchema),
  node: z.record(z.string(), NodeToolSchema),
});
export type ToolsLock = z.infer<typeof ToolsLockSchema>;

/** Parse a tools lockfile from raw JSON text, rejecting anything malformed. */
export function parseToolsLock(raw: string): ToolsLock {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw new Error(`tools.lock.json is not valid JSON: ${detail}`);
  }
  return ToolsLockSchema.parse(parsed);
}

/**
 * Serialise a lockfile deterministically — tool keys sorted, platforms and
 * fields in canonical order — so regenerating it produces an empty diff when
 * nothing changed.
 */
export function serializeToolsLock(lock: ToolsLock): string {
  const binaries: Record<string, unknown> = {};
  for (const name of Object.keys(lock.binaries).sort()) {
    const tool = lock.binaries[name];
    if (tool === undefined) continue;
    const platforms: Record<string, ToolArtifact> = {};
    for (const platform of PLATFORMS) {
      const artifact = tool.platforms[platform];
      if (artifact === undefined) continue;
      platforms[platform] = {
        url: artifact.url,
        sha256: artifact.sha256,
        archive: artifact.archive,
        binaryPath: artifact.binaryPath,
      };
    }
    binaries[name] = {
      version: tool.version,
      ...(tool.description === undefined ? {} : { description: tool.description }),
      platforms,
    };
  }

  const node: Record<string, unknown> = {};
  for (const name of Object.keys(lock.node).sort()) {
    const tool = lock.node[name];
    if (tool === undefined) continue;
    node[name] = {
      package: tool.package,
      version: tool.version,
      ...(tool.description === undefined ? {} : { description: tool.description }),
      binaryPath: tool.binaryPath,
    };
  }

  return `${JSON.stringify({ schemaVersion: lock.schemaVersion, binaries, node }, null, 2)}\n`;
}

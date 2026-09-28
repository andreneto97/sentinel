#!/usr/bin/env bun
/**
 * Regenerates `src/tools/tools.lock.json`: downloads every pinned release
 * artifact, hashes it while it streams, and rewrites the lockfile
 * deterministically. This is the only supported way to fill in a `sha256:
 * null` entry — Sentinel never invents a digest, and the installer refuses to
 * install an entry that has none.
 *
 *   bun run scripts/update-tools-lock.ts                 # pin anything unpinned
 *   bun run scripts/update-tools-lock.ts --force         # re-hash everything
 *   bun run scripts/update-tools-lock.ts --only trivy    # one tool (repeatable, comma-separated)
 *   bun run scripts/update-tools-lock.ts --check         # verify, write nothing, exit 1 on drift
 *
 * It reads and writes exactly one file, before the filesystem port exists in a
 * run, so it uses Bun's file APIs directly instead of taking a port.
 */
import {
  PLATFORMS,
  type Platform,
  type ToolArtifact,
  type ToolsLock,
  parseToolsLock,
  serializeToolsLock,
} from "../src/contracts/tools.ts";

const LOCK_PATH = new URL("../src/tools/tools.lock.json", import.meta.url).pathname;

/** Command-line options for a regeneration run. */
export interface UpdateOptions {
  only: ReadonlySet<string>;
  force: boolean;
  check: boolean;
  help: boolean;
}

/** One artifact a run will download and hash. */
export interface ArtifactTarget {
  tool: string;
  platform: Platform;
  artifact: ToolArtifact;
}

const USAGE = `Usage: bun run scripts/update-tools-lock.ts [--only <tool,tool>] [--force] [--check]

  --only <names>  Restrict the run to these lockfile keys (comma-separated).
  --force         Re-download and re-hash artifacts that are already pinned.
  --check         Verify pinned digests without writing; exits 1 on drift.
  --help, -h      Show this message.`;

/** Parse the script's arguments; throws on anything it does not recognise. */
export function parseUpdateArgs(argv: readonly string[]): UpdateOptions {
  const only = new Set<string>();
  let force = false;
  let check = false;
  let help = false;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      help = true;
    } else if (arg === "--force") {
      force = true;
    } else if (arg === "--check") {
      check = true;
    } else if (arg === "--only") {
      index += 1;
      const value = argv[index];
      if (value === undefined || value.startsWith("--")) {
        throw new Error("--only needs a comma-separated list of tool names");
      }
      for (const name of value.split(",")) {
        const trimmed = name.trim();
        if (trimmed.length > 0) only.add(trimmed);
      }
    } else {
      throw new Error(`unknown argument: ${String(arg)}`);
    }
  }

  return { only, force, check, help };
}

/**
 * The artifacts a run touches, in canonical order. An unpinned artifact is
 * always included: leaving one unpinned is what makes a tool uninstallable.
 */
export function selectTargets(lock: ToolsLock, options: UpdateOptions): ArtifactTarget[] {
  const targets: ArtifactTarget[] = [];
  for (const tool of Object.keys(lock.binaries).sort()) {
    if (options.only.size > 0 && !options.only.has(tool)) continue;
    const entry = lock.binaries[tool];
    if (entry === undefined) continue;
    for (const platform of PLATFORMS) {
      const artifact = entry.platforms[platform];
      if (artifact === undefined) continue;
      const needsDigest = artifact.sha256 === null;
      if (!needsDigest && !options.force && !options.check) continue;
      targets.push({ tool, platform, artifact });
    }
  }
  return targets;
}

/** Stream a URL and return its SHA-256 without holding the artifact in memory. */
async function hashUrl(url: string): Promise<{ sha256: string; bytes: number }> {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) {
    throw new Error(`GET ${url} returned HTTP ${response.status} ${response.statusText}`);
  }
  const body = response.body;
  if (body === null) throw new Error(`GET ${url} returned an empty body`);

  const hasher = new Bun.CryptoHasher("sha256");
  const reader = body.getReader();
  let bytes = 0;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    hasher.update(chunk.value);
    bytes += chunk.value.byteLength;
  }
  return { sha256: hasher.digest("hex"), bytes };
}

/** Confirm an npm package really publishes the exact version the lockfile pins. */
async function checkNodeVersion(pkg: string, version: string): Promise<boolean> {
  const response = await fetch(`https://registry.npmjs.org/${pkg}/${version}`, {
    redirect: "follow",
  });
  return response.ok;
}

function megabytes(bytes: number): string {
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

async function main(argv: readonly string[]): Promise<number> {
  let options: UpdateOptions;
  try {
    options = parseUpdateArgs(argv);
  } catch (cause) {
    console.error(cause instanceof Error ? cause.message : String(cause));
    console.error(USAGE);
    return 2;
  }

  if (options.help) {
    console.log(USAGE);
    return 0;
  }

  const original = await Bun.file(LOCK_PATH).text();
  const lock = parseToolsLock(original);
  const targets = selectTargets(lock, options);

  if (targets.length === 0) {
    console.error("Every selected artifact is already pinned. Nothing to do.");
  }

  const drift: string[] = [];
  const failures: string[] = [];

  for (const { tool, platform, artifact } of targets) {
    const label = `${tool} ${platform}`;
    try {
      const { sha256, bytes } = await hashUrl(artifact.url);
      if (artifact.sha256 !== null && artifact.sha256 !== sha256) {
        drift.push(`${label}: pinned ${artifact.sha256}, downloaded ${sha256}`);
        console.error(`DRIFT   ${label} (${megabytes(bytes)})`);
      } else {
        console.error(
          `${artifact.sha256 === null ? "pinned " : "ok     "} ${label} ${sha256} (${megabytes(bytes)})`,
        );
      }
      if (!options.check) artifact.sha256 = sha256;
    } catch (cause) {
      const detail = cause instanceof Error ? cause.message : String(cause);
      failures.push(`${label}: ${detail}`);
      console.error(`FAILED  ${label}: ${detail}`);
    }
  }

  for (const name of Object.keys(lock.node).sort()) {
    if (options.only.size > 0 && !options.only.has(name)) continue;
    const tool = lock.node[name];
    if (tool === undefined) continue;
    const published = await checkNodeVersion(tool.package, tool.version);
    if (published) {
      console.error(`ok      ${name} ${tool.package}@${tool.version}`);
    } else {
      failures.push(`${name}: ${tool.package}@${tool.version} is not published on npm`);
      console.error(`FAILED  ${name}: ${tool.package}@${tool.version} is not published on npm`);
    }
  }

  if (options.check) {
    if (drift.length > 0 || failures.length > 0) {
      console.error(`\n${drift.length} drifted, ${failures.length} unreachable.`);
      return 1;
    }
    console.error("\nEvery pinned digest matches the published artifact.");
    return 0;
  }

  if (failures.length > 0) {
    console.error(`\nRefusing to write the lockfile: ${failures.length} artifact(s) failed.`);
    return 1;
  }

  const updated = serializeToolsLock(lock);
  if (updated === original) {
    console.error("\ntools.lock.json is unchanged.");
    return 0;
  }
  await Bun.write(LOCK_PATH, updated);
  console.error("\nWrote src/tools/tools.lock.json.");
  return 0;
}

if (import.meta.main) {
  process.exitCode = await main(process.argv.slice(2));
}

/**
 * Which files the four delivery-domain steps analyse.
 *
 * Phase 0 proves the facts, but it caps the evidence it carries per fact, so a
 * repository with thirty workflows would only hand twenty of them to phase 1
 * and the coverage claim would be quietly wrong. This module reads the profile
 * *and* offers a glob pass, and merges the two.
 */

import type { StackProfile } from "../contracts/profile.ts";
import { evidenceFiles } from "../profile/accessors.ts";

/** The glob operation the discovery needs; `src/ports/file-system.ts` satisfies it. */
export interface DeliveryGlobFileSystem {
  glob(
    patterns: string | readonly string[],
    options?: { cwd?: string; onlyFiles?: boolean; dot?: boolean },
  ): Promise<string[]>;
}

/** The delivery artifacts phase 1 knows how to analyse, repo-relative and sorted. */
export interface DeliveryFileSets {
  readonly workflows: string[];
  readonly dockerfiles: string[];
  readonly composeFiles: string[];
}

/** Directories whose contents are never the repository's own delivery config. */
const IGNORED_SEGMENTS: readonly string[] = [
  "node_modules/",
  ".git/",
  "dist/",
  "build/",
  "out/",
  "vendor/",
  ".next/",
  "coverage/",
  ".venv/",
];

/** Cap per category, so a pathological monorepo cannot turn phase 1 into a crawl. */
export const MAX_DELIVERY_FILES = 200;

/** Drops vendored and generated paths, de-duplicates, sorts and caps. */
function usable(files: readonly string[]): string[] {
  return [...new Set(files)]
    .filter((file) => !IGNORED_SEGMENTS.some((segment) => file.includes(segment)))
    .sort()
    .slice(0, MAX_DELIVERY_FILES);
}

/** GitHub Actions workflows the profile proved. */
export function workflowFilesOf(profile: StackProfile | undefined): string[] {
  return profile === undefined ? [] : evidenceFiles(profile, "ci", "github-actions");
}

/** Dockerfiles the profile proved. */
export function dockerfilesOf(profile: StackProfile | undefined): string[] {
  return profile === undefined ? [] : evidenceFiles(profile, "container", "dockerfile");
}

/** Compose files the profile proved. */
export function composeFilesOf(profile: StackProfile | undefined): string[] {
  return profile === undefined ? [] : evidenceFiles(profile, "container", "docker-compose");
}

/** Everything the profile alone can say about the delivery surface. */
export function deliveryFilesFromProfile(profile: StackProfile | undefined): DeliveryFileSets {
  return {
    workflows: usable(workflowFilesOf(profile)),
    dockerfiles: usable(dockerfilesOf(profile)),
    composeFiles: usable(composeFilesOf(profile)),
  };
}

/**
 * Globs the target for delivery artifacts and merges the result with whatever
 * the profile already proved, so nothing is lost in either direction.
 */
export async function discoverDeliveryFiles(
  fs: DeliveryGlobFileSystem,
  targetDir: string,
  profile?: StackProfile | undefined,
): Promise<DeliveryFileSets> {
  const scan = async (patterns: readonly string[]): Promise<string[]> => {
    try {
      return await fs.glob(patterns, { cwd: targetDir, onlyFiles: true, dot: true });
    } catch {
      // A glob that cannot run is a discovery gap, not a reason to fail phase 1;
      // the profile's own list still carries the run.
      return [];
    }
  };

  const proven = deliveryFilesFromProfile(profile);
  const workflows = await scan([".github/workflows/*.yml", ".github/workflows/*.yaml"]);
  const dockerfiles = await scan(["**/Dockerfile", "**/Dockerfile.*", "**/*.Dockerfile"]);
  const composeFiles = await scan([
    "**/docker-compose.yml",
    "**/docker-compose.yaml",
    "**/docker-compose.*.yml",
    "**/docker-compose.*.yaml",
    "**/compose.yml",
    "**/compose.yaml",
    "**/compose.*.yml",
    "**/compose.*.yaml",
  ]);

  return {
    workflows: usable([...workflows, ...proven.workflows]),
    dockerfiles: usable([...dockerfiles, ...proven.dockerfiles]),
    composeFiles: usable([...composeFiles, ...proven.composeFiles]),
  };
}

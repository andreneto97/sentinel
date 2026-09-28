import { z } from "zod";
import type { CodeRef, Confidence } from "../contracts/findings.ts";
import type { DetectedFact, FactKind } from "../contracts/profile.ts";
import { fact, ref } from "./fact-builder.ts";
import type { RepoSnapshot } from "./repo-snapshot.ts";
import { lineOfJsonKey } from "./text.ts";

const DependencyMapSchema = z.record(z.string(), z.string());

/**
 * The parts of `package.json` phase 0 reads.
 *
 * Loose on purpose (unknown keys are ignored, every field optional): a manifest
 * Sentinel cannot fully understand must still yield the dependency list rather
 * than failing the whole profile.
 */
export const PackageJsonSchema = z.object({
  name: z.string().optional(),
  version: z.string().optional(),
  type: z.enum(["module", "commonjs"]).optional(),
  private: z.boolean().optional(),
  packageManager: z.string().optional(),
  workspaces: z
    .union([z.array(z.string()), z.object({ packages: z.array(z.string()).optional() })])
    .optional(),
  engines: DependencyMapSchema.optional(),
  scripts: DependencyMapSchema.optional(),
  dependencies: DependencyMapSchema.optional(),
  devDependencies: DependencyMapSchema.optional(),
  peerDependencies: DependencyMapSchema.optional(),
  optionalDependencies: DependencyMapSchema.optional(),
});
/** A validated `package.json`, with every field optional. */
export type PackageJson = z.infer<typeof PackageJsonSchema>;

/** The dependency sections searched for evidence, in the order they are reported. */
export const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
] as const;
/** One of the `package.json` dependency sections. */
export type DependencySection = (typeof DEPENDENCY_SECTIONS)[number];

/** A parsed `package.json`, kept next to its raw lines so evidence can cite a line. */
export interface PackageManifest {
  /** Repo-relative path, e.g. `package.json` or `apps/api/package.json`. */
  readonly path: string;
  /** Repo-relative directory holding the manifest; `.` for the root package. */
  readonly directory: string;
  readonly lines: readonly string[];
  readonly data: PackageJson;
}

/** Maximum number of manifests read, so a huge monorepo cannot stall phase 0. */
export const MAX_MANIFESTS = 60;

/** Result of reading every `package.json` in the repository. */
export interface ManifestLoad {
  readonly manifests: readonly PackageManifest[];
  readonly warnings: readonly string[];
}

/** Reads and validates every `package.json` in the snapshot, root first. */
export async function loadManifests(snapshot: RepoSnapshot): Promise<ManifestLoad> {
  const paths = snapshot
    .filesNamed("package.json")
    .sort((a, b) => a.split("/").length - b.split("/").length || a.localeCompare(b))
    .slice(0, MAX_MANIFESTS);
  const manifests: PackageManifest[] = [];
  const warnings: string[] = [];
  for (const manifestPath of paths) {
    const lines = await snapshot.lines(manifestPath);
    if (lines === undefined) {
      warnings.push(`Could not read ${manifestPath}`);
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(lines.join("\n")) as unknown;
    } catch {
      warnings.push(`${manifestPath} is not valid JSON; its dependencies were not inspected`);
      continue;
    }
    const result = PackageJsonSchema.safeParse(parsed);
    if (!result.success) {
      warnings.push(`${manifestPath} does not match the expected package.json shape`);
      continue;
    }
    const directory = manifestPath.includes("/")
      ? manifestPath.slice(0, manifestPath.lastIndexOf("/"))
      : ".";
    manifests.push({ path: manifestPath, directory, lines, data: result.data });
  }
  return { manifests, warnings };
}

/** The root `package.json`, when the repository has one. */
export function rootManifest(manifests: readonly PackageManifest[]): PackageManifest | undefined {
  return manifests.find((manifest) => manifest.path === "package.json");
}

/** A dependency as found in one manifest section. */
export interface DependencyHit {
  readonly manifest: PackageManifest;
  readonly section: DependencySection;
  readonly name: string;
  readonly range: string;
}

function sectionOf(manifest: PackageManifest, section: DependencySection): Record<string, string> {
  switch (section) {
    case "dependencies":
      return manifest.data.dependencies ?? {};
    case "devDependencies":
      return manifest.data.devDependencies ?? {};
    case "peerDependencies":
      return manifest.data.peerDependencies ?? {};
    case "optionalDependencies":
      return manifest.data.optionalDependencies ?? {};
  }
}

/** Every declared dependency across every manifest and section. */
export function allDependencies(manifests: readonly PackageManifest[]): DependencyHit[] {
  const hits: DependencyHit[] = [];
  for (const manifest of manifests) {
    for (const section of DEPENDENCY_SECTIONS) {
      for (const [name, range] of Object.entries(sectionOf(manifest, section))) {
        hits.push({ manifest, section, name, range });
      }
    }
  }
  return hits;
}

/** A `CodeRef` pointing at the line that declares a dependency. */
export function dependencyRef(hit: DependencyHit): CodeRef {
  return ref(hit.manifest.path, lineOfJsonKey(hit.manifest.lines, hit.name) ?? 1, hit.section);
}

/**
 * A dependency that proves a fact.
 *
 * Dependencies are the strongest deterministic evidence available in phase 0:
 * a declared package is a fact about the repository, whereas a file name that
 * resembles a framework is a guess.
 */
export interface DependencySignal {
  /** The normalised fact value, e.g. "prisma". */
  readonly value: string;
  /** Exact package names that prove it. */
  readonly packages?: readonly string[];
  /** Package name prefixes that prove it, e.g. `@clerk/` or `@nestjs/`. */
  readonly prefixes?: readonly string[];
  readonly detail?: string;
  readonly confidence?: Confidence;
}

function matches(signal: DependencySignal, name: string): boolean {
  if (signal.packages?.includes(name) === true) return true;
  return signal.prefixes?.some((prefix) => name.startsWith(prefix)) === true;
}

/** Turns dependency signals into facts of `kind`, one per matched package declaration. */
export function factsFromDependencies(
  manifests: readonly PackageManifest[],
  kind: FactKind,
  signals: readonly DependencySignal[],
): DetectedFact[] {
  const facts: DetectedFact[] = [];
  for (const hit of allDependencies(manifests)) {
    for (const signal of signals) {
      if (!matches(signal, hit.name)) continue;
      facts.push(
        fact({
          kind,
          value: signal.value,
          confidence: signal.confidence ?? "high",
          evidence: [dependencyRef(hit)],
          detail: signal.detail ?? `${hit.name}@${hit.range}`,
        }),
      );
    }
  }
  return facts;
}

/** Every package name or prefix a set of signals looks for, for the probe log. */
export function signalLabels(signals: readonly DependencySignal[]): string[] {
  const labels = new Set<string>();
  for (const signal of signals) {
    for (const name of signal.packages ?? []) labels.add(name);
    for (const prefix of signal.prefixes ?? []) labels.add(`${prefix}*`);
  }
  return [...labels].sort();
}

/** True when any manifest declares a package matching `predicate`. */
export function hasDependency(
  manifests: readonly PackageManifest[],
  predicate: (name: string) => boolean,
): boolean {
  return allDependencies(manifests).some((hit) => predicate(hit.name));
}

/** The first declaration of `name` across the manifests, with its line. */
export function findDependency(
  manifests: readonly PackageManifest[],
  name: string,
): DependencyHit | undefined {
  return allDependencies(manifests).find((hit) => hit.name === name);
}

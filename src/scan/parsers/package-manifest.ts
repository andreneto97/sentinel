/**
 * Manifest and lockfile reading for the dependency-hygiene half of phase 1.
 *
 * The `package.json` schema and the line-finding helpers come from phase 0
 * (`src/profile/`); what is added here is the override/resolution surface and
 * the lockfile questions phase 1 asks: which manager owns this repository, is
 * there exactly one lockfile, and does it cover everything the manifest
 * declares.
 */

import { z } from "zod";
import { PackageJsonSchema, escapeRegExp } from "../../profile/index.ts";
import { type ParseOutcome, parseJsonWith } from "./_parse-outcome.ts";
import type { PackageManagerName } from "./package-manager.ts";

/** An override entry is either a pin or a nested map of pins. */
type OverrideTree = string | { [key: string]: OverrideTree };

const OverrideTreeSchema: z.ZodType<OverrideTree> = z.lazy(() =>
  z.union([z.string(), z.record(z.string(), OverrideTreeSchema)]),
);

const OverrideMapSchema = z.record(z.string(), OverrideTreeSchema);

/**
 * `package.json` as phase 1 reads it: phase 0's schema plus the three places a
 * repository can force a transitive dependency to a fixed version.
 */
export const ScanPackageJsonSchema = PackageJsonSchema.extend({
  overrides: OverrideMapSchema.optional(),
  resolutions: OverrideMapSchema.optional(),
  pnpm: z.object({ overrides: OverrideMapSchema.optional() }).optional(),
});
/** A validated `package.json`, with every field optional. */
export type ScanPackageJson = z.infer<typeof ScanPackageJsonSchema>;

/** Parse a `package.json`; a malformed manifest is a value, not an exception. */
export function parsePackageJson(raw: string): ParseOutcome<ScanPackageJson> {
  return parseJsonWith(raw, ScanPackageJsonSchema, "package.json");
}

/** The manifest sections that declare a dependency of the package itself. */
export const DECLARED_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
] as const;
/** One of the sections {@link declaredDependencies} reads. */
export type DeclaredSection = (typeof DECLARED_SECTIONS)[number];

/** A dependency the manifest declares, with the range it declares. */
export interface DeclaredDependency {
  readonly name: string;
  readonly range: string;
  readonly section: DeclaredSection;
}

/** Every dependency the package declares for itself, peers excluded. */
export function declaredDependencies(manifest: ScanPackageJson): DeclaredDependency[] {
  const declared: DeclaredDependency[] = [];
  for (const section of DECLARED_SECTIONS) {
    for (const [name, range] of Object.entries(manifest[section] ?? {})) {
      declared.push({ name, range, section });
    }
  }
  return declared;
}

/** Matches the closing brace of a `package.json` section at any indentation. */
const SECTION_END_RE = /^\s*\},?\s*$/;

/**
 * The 1-based line a key sits on inside a `package.json` section, falling back
 * to the first match anywhere in the file and finally to line 1.
 *
 * Scoping the search to the section keeps a dependency called `build` from
 * citing the `scripts` entry of the same name.
 */
export function manifestLineOf(
  lines: readonly string[],
  section: string | null,
  key: string,
): number {
  const keyPattern = new RegExp(`^\\s*"${escapeRegExp(key)}"\\s*:`);
  const start =
    section === null
      ? 0
      : lines.findIndex((line) => new RegExp(`^\\s*"${escapeRegExp(section)}"\\s*:`).test(line));

  if (start >= 0) {
    for (let index = start; index < lines.length; index += 1) {
      const line = lines[index];
      if (line === undefined) continue;
      if (index > start && SECTION_END_RE.test(line)) break;
      if (index > start && keyPattern.test(line)) return index + 1;
    }
  }

  const anywhere = lines.findIndex((line) => keyPattern.test(line));
  return anywhere === -1 ? 1 : anywhere + 1;
}

/** Where a forced version came from; each manager spells it differently. */
export type OverrideSection = "overrides" | "resolutions" | "pnpm.overrides";

/** One dependency forced to a fixed version, wherever it sits in the tree. */
export interface OverridePin {
  readonly section: OverrideSection;
  /** The key path as written, e.g. `foo` or `foo > bar`. */
  readonly path: string;
  /** The package the pin applies to, with any version selector stripped. */
  readonly name: string;
  /** The version or range the pin forces. */
  readonly spec: string;
}

/** Strips the `@<selector>` suffix pnpm allows on an override key. */
function overrideKeyToName(key: string): string {
  const separator = key.lastIndexOf("@");
  if (separator <= 0) return key;
  return key.slice(0, separator);
}

/** Walks one override map, flattening nested maps into `parent > child` paths. */
function collectPins(
  section: OverrideSection,
  tree: Record<string, OverrideTree>,
  prefix: readonly string[],
  into: OverridePin[],
): void {
  for (const [key, value] of Object.entries(tree)) {
    const path = [...prefix, key];
    if (typeof value === "string") {
      // npm's `"."` key means "this package itself", not a child.
      const target = key === "." ? (prefix.at(-1) ?? key) : key;
      into.push({
        section,
        path: path.join(" > "),
        name: overrideKeyToName(target),
        spec: value,
      });
      continue;
    }
    collectPins(section, value, path, into);
  }
}

/** Every version pin the manifest forces, from all three override surfaces. */
export function overridePins(manifest: ScanPackageJson): OverridePin[] {
  const pins: OverridePin[] = [];
  collectPins("overrides", manifest.overrides ?? {}, [], pins);
  collectPins("resolutions", manifest.resolutions ?? {}, [], pins);
  collectPins("pnpm.overrides", manifest.pnpm?.overrides ?? {}, [], pins);
  return pins;
}

/** A lockfile Sentinel recognises, and the manager that writes it. */
export interface LockfileKind {
  readonly file: string;
  readonly manager: PackageManagerName;
  /** How {@link declaredInLockfile} has to read it. */
  readonly format: "npm-json" | "yarn-v1" | "pnpm-yaml" | "bun-text" | "binary";
}

/** Every lockfile phase 1 looks for, in the order it reports them. */
export const LOCKFILES: readonly LockfileKind[] = [
  { file: "package-lock.json", manager: "npm", format: "npm-json" },
  { file: "npm-shrinkwrap.json", manager: "npm", format: "npm-json" },
  { file: "yarn.lock", manager: "yarn", format: "yarn-v1" },
  { file: "pnpm-lock.yaml", manager: "pnpm", format: "pnpm-yaml" },
  { file: "bun.lock", manager: "bun", format: "bun-text" },
  { file: "bun.lockb", manager: "bun", format: "binary" },
];

/** Whether a lockfile covers a dependency, or whether that cannot be read. */
export type LockCoverage = "present" | "absent" | "unknown";

const NpmLockSchema = z.object({
  lockfileVersion: z.number().optional(),
  packages: z.record(z.string(), z.unknown()).optional(),
  dependencies: z.record(z.string(), z.unknown()).optional(),
});

/** Looks a dependency up in an npm lockfile, v1 (`dependencies`) or v2+ (`packages`). */
function npmLockDeclares(content: string, name: string): LockCoverage {
  const lock = parseJsonWith(content, NpmLockSchema, "package-lock.json");
  if (!lock.ok) return "unknown";
  const packages = lock.value.packages;
  if (packages !== undefined) {
    const suffix = `node_modules/${name}`;
    for (const key of Object.keys(packages)) {
      if (key === suffix || key.endsWith(`/${suffix}`)) return "present";
    }
    // A v2+ lockfile lists every installed package, so absence is meaningful.
    return "absent";
  }
  if (lock.value.dependencies !== undefined) {
    return name in lock.value.dependencies ? "present" : "absent";
  }
  return "unknown";
}

/**
 * Whether a dependency name appears as a package key in a text lockfile.
 *
 * This is a name search, not a resolution: it answers "did this manager ever
 * lock anything called that", which is enough to catch a dependency added to
 * `package.json` without regenerating the lockfile, and is why the findings
 * built on it are reported at medium confidence.
 */
function textLockDeclares(content: string, name: string): LockCoverage {
  const pattern = new RegExp(`(^|["'\\s/])${escapeRegExp(name)}(["'@:\\s])`, "m");
  return pattern.test(content) ? "present" : "absent";
}

/** Whether a lockfile covers a declared dependency, given its format. */
export function declaredInLockfile(
  format: LockfileKind["format"],
  content: string,
  name: string,
): LockCoverage {
  switch (format) {
    case "npm-json":
      return npmLockDeclares(content, name);
    case "yarn-v1":
    case "pnpm-yaml":
    case "bun-text":
      return textLockDeclares(content, name);
    case "binary":
      // bun.lockb is a binary format; Sentinel will not guess at its contents.
      return "unknown";
  }
}

/**
 * Just enough semver to classify how far behind a dependency is and to find the
 * floor of a range.
 *
 * Sentinel does not depend on `semver` (a banned-by-default runtime dependency
 * for a tool that must stay installable from source), and the two questions
 * phase 1 asks of a version string are small enough to answer here: "is this a
 * patch, minor or major gap?" and "what is the lowest version this range
 * accepts?".
 */

/** A parsed `MAJOR.MINOR.PATCH` version, with any prerelease tag kept aside. */
export interface ParsedVersion {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  /** `-rc.1` and the like, without the leading dash; empty for a release. */
  readonly prerelease: string;
}

const VERSION_RE = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Parses an exact version, or `null` when the string is not one. */
export function parseVersion(raw: string): ParsedVersion | null {
  const match = VERSION_RE.exec(raw.trim());
  if (match === null) return null;
  const [, major, minor, patch, prerelease] = match;
  if (major === undefined) return null;
  return {
    major: Number(major),
    minor: Number(minor ?? "0"),
    patch: Number(patch ?? "0"),
    prerelease: prerelease ?? "",
  };
}

/**
 * Orders two versions: negative when `a` is older. A prerelease sorts before
 * the release it leads to, which is all the precedence phase 1 needs.
 */
export function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === "") return 1;
  if (b.prerelease === "") return -1;
  return a.prerelease < b.prerelease ? -1 : 1;
}

/** How far a dependency is behind: nothing, a patch, a minor or a major release. */
export type VersionGap = "none" | "patch" | "minor" | "major";

/**
 * Classifies the distance from `current` to `latest`. Returns `null` when
 * either string is not an exact version, so the caller can say so rather than
 * guess.
 */
export function versionGap(current: string, latest: string): VersionGap | null {
  const from = parseVersion(current);
  const to = parseVersion(latest);
  if (from === null || to === null) return null;
  if (compareVersions(to, from) <= 0) return "none";
  if (to.major !== from.major) return "major";
  if (to.minor !== from.minor) return "minor";
  return "patch";
}

/** Range prefixes that do not change the floor of the range. */
const RANGE_PREFIX_RE = /^(?:[\^~]|>=?|=)?\s*/;

/**
 * The lowest version a range accepts, or `null` for a range with no floor
 * (`*`, `latest`, `workspace:*`) or one this module does not understand.
 *
 * Only the first comparator of a range is read: `>=1.2.3 <2` has floor 1.2.3,
 * and an `||` union's floor is the floor of its first branch.
 */
export function minVersionOfRange(range: string): ParsedVersion | null {
  const firstBranch = range.split("||")[0]?.trim() ?? "";
  const alias = /^npm:(?:@[^/]+\/)?[^@]+@(.+)$/.exec(firstBranch);
  const body = (alias?.[1] ?? firstBranch).trim();
  const firstComparator = body.split(/\s+/)[0] ?? "";
  if (firstComparator === "" || firstComparator === "*" || firstComparator.startsWith("<")) {
    return null;
  }
  const bare = firstComparator.replace(RANGE_PREFIX_RE, "");
  const normalised = bare.replace(/\.[xX*]/g, ".0");
  if (normalised === "" || normalised === "x" || normalised === "X") return null;
  return parseVersion(normalised);
}

/** Renders a parsed version back to `MAJOR.MINOR.PATCH`, dropping build metadata. */
export function formatVersion(version: ParsedVersion): string {
  const core = `${version.major}.${version.minor}.${version.patch}`;
  return version.prerelease === "" ? core : `${core}-${version.prerelease}`;
}

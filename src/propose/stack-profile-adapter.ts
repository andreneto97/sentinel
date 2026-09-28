import type { StackProfile } from "../contracts/profile.ts";

/**
 * The only module in `src/propose/` that knows the profiler's contract.
 * Everything downstream works against `ProfileView`, so a change to
 * `StackProfile` is absorbed here instead of in nine generators.
 */

/** A single fact phase 0 proved about the repository. */
export interface ProfileFact {
  readonly kind: string;
  readonly value: string;
  /** Human-readable extra; often carries a file count ("12 file(s)"). */
  readonly detail?: string | undefined;
  readonly confidence: "high" | "medium" | "low";
  readonly evidence: ReadonlyArray<{ readonly file: string }>;
}

/** A fact kind phase 0 probed for and did not find. */
export interface ProfileAbsence {
  readonly kind: string;
  readonly searched: readonly string[];
  /** The profiler's own words on what the absence costs, when it wrote any. */
  readonly note?: string | undefined;
}

/** A query surface over one profile run, tolerant of kind spelling. */
export interface ProfileView {
  readonly facts: readonly ProfileFact[];
  readonly absences: readonly ProfileAbsence[];
  /** Facts whose kind matches any of the given topics. */
  select(...topics: readonly string[]): readonly ProfileFact[];
  /** Distinct, sorted fact values for the given topics. */
  values(...topics: readonly string[]): readonly string[];
  /** True when at least one fact matches. */
  has(...topics: readonly string[]): boolean;
  /** The absence record for a kind, when the profiler probed and found nothing. */
  absence(kind: string): ProfileAbsence | undefined;
}

/**
 * Fact kinds each generator reads. These are `FactKind` values from
 * `contracts/profile.ts`; the extra spellings are forward compatibility for
 * kinds the profiler has not split out yet (per-function, per-workflow).
 */
export const PROFILE_TOPICS = {
  iac: ["iac"],
  ci: ["ci", "ci-workflow"],
  container: ["container"],
  migrationsDir: ["migrations-dir", "migration"],
  workspacePackage: ["workspace-package", "monorepo-package"],
  language: ["language"],
  frontend: ["frontend"],
  serverlessPlatform: ["serverless-platform"],
  serverlessManifest: ["serverless-manifest"],
  serverlessFunction: ["serverless-function"],
} as const satisfies Record<string, readonly string[]>;

/** Lower-cases and folds separator characters so kinds compare predictably. */
function normalizeKind(kind: string): string {
  return kind
    .trim()
    .toLowerCase()
    .replace(/[\s_:/]+/g, "-");
}

/**
 * A kind matches a topic when it equals it, or when the topic is its first or
 * last dot-separated segment. Segment matching (rather than `startsWith`)
 * keeps `migration-tool` from being counted as a migration.
 */
export function kindMatchesTopic(kind: string, topic: string): boolean {
  const k = normalizeKind(kind);
  const t = normalizeKind(topic);
  if (k === t) return true;
  const segments = k.split(".");
  if (segments.length < 2) return false;
  return segments[0] === t || segments[segments.length - 1] === t;
}

/** De-duplicated, sorted evidence paths for a set of facts, capped for display. */
export function evidencePaths(facts: readonly ProfileFact[], limit = 5): string[] {
  const seen = new Set<string>();
  for (const fact of facts) {
    for (const ref of fact.evidence) {
      const file = ref.file.trim();
      if (file.length > 0) seen.add(file);
    }
  }
  return [...seen].sort().slice(0, limit);
}

/**
 * Splits a `name:count` fact value. Some detectors report `python:31`; a plain
 * value yields no count.
 */
export function parseCountedValue(value: string): { name: string; count: number | undefined } {
  const match = /^(.*?):(\d+)$/.exec(value.trim());
  if (match === null) return { name: value.trim(), count: undefined };
  const [, name = "", digits = "0"] = match;
  return { name: name.trim(), count: Number.parseInt(digits, 10) };
}

// "12 file(s)", "240 TypeScript file(s)", "5 edge function(s)", "3 chart(s)".
const COUNT_IN_DETAIL =
  /(\d+)\s+(?:\w+\s+){0,2}(?:files?|charts?|functions?|migrations?|workflows?|packages?)\b/i;

/**
 * How many things a fact stands for, or `undefined` when the profiler did not
 * say. Evidence length is deliberately *not* a fallback: it is capped for
 * display, so counting it would under-report and read as a fact.
 */
export function factCount(fact: ProfileFact): number | undefined {
  const fromDetail = fact.detail === undefined ? null : COUNT_IN_DETAIL.exec(fact.detail);
  if (fromDetail !== null) {
    const parsed = Number.parseInt(fromDetail[1] ?? "", 10);
    if (Number.isFinite(parsed)) return parsed;
  }
  return parseCountedValue(fact.value).count;
}

/** Sums the counts of the facts that carry one; `undefined` when none do. */
export function totalCount(facts: readonly ProfileFact[]): number | undefined {
  let total: number | undefined;
  for (const fact of facts) {
    const count = factCount(fact);
    if (count !== undefined) total = (total ?? 0) + count;
  }
  return total;
}

/** Builds a `ProfileView` over already-parsed facts; the shape tests use. */
export function createProfileView(
  facts: readonly ProfileFact[],
  absences: readonly ProfileAbsence[] = [],
): ProfileView {
  const select = (...topics: readonly string[]): readonly ProfileFact[] =>
    facts.filter((fact) => topics.some((topic) => kindMatchesTopic(fact.kind, topic)));

  const values = (...topics: readonly string[]): readonly string[] => {
    const seen = new Set<string>();
    for (const fact of select(...topics)) {
      const value = fact.value.trim();
      if (value.length > 0) seen.add(value);
    }
    return [...seen].sort();
  };

  return {
    facts,
    absences,
    select,
    values,
    has: (...topics) => select(...topics).length > 0,
    absence: (kind) => absences.find((entry) => kindMatchesTopic(entry.kind, kind)),
  };
}

/** Adapts the profiler's `StackProfile` into the view the generators consume. */
export function toProfileView(profile: StackProfile): ProfileView {
  return createProfileView(profile.facts, profile.absences);
}

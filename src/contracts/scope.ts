import { z } from "zod";
import { type AuditUnit, SCHEMA_VERSION } from "./findings.ts";
import {
  AUDIT_UNIT_KINDS,
  type AuditUnitKind,
  AuditUnitKindSchema,
  countUnits,
  groupThousands,
} from "./inventory.ts";

/**
 * `--path` — the subtree a run analysed, and everything it therefore did not.
 *
 * On a single-service repository this document is one line long and says "the
 * whole repository". It exists for the other case: a workspace where the useful
 * question is "audit `apps/api`", the deployable that serves HTTP, and not
 * "audit every file in the workspace, including years of applied migrations".
 * Bounding a run that way is legitimate; letting the bounded run *read* like a
 * whole-repo run is not, so this artifact carries, in one place and in the run's
 * own numbers:
 *
 * - what the operator asked for, and what each selector actually resolved to
 *   (a directory, a workspace package name, a glob — or nothing at all);
 * - how many units of audit fell inside the scope and how many fell outside,
 *   broken down by kind, because "the other 5,000 units" is a number somebody
 *   has to have counted;
 * - which phases ignored the scope on purpose. A lockfile and a leaked
 *   credential belong to the whole repository, so the dependency scan and the
 *   git-history secret scan are never narrowed — and that is stated here
 *   rather than left for a reader to assume either way.
 *
 * Everything in this module is pure. It is the contract three layers share:
 * the CLI resolves the flag against the repository, the run writes the
 * document, and every renderer prints {@link AnalysisScope.statement} verbatim.
 */

/** File name of the scope artifact inside a run directory. */
export const ANALYSIS_SCOPE_FILE = "analysis-scope.json";

/** How one `--path` selector was understood. */
export const ScopeSelectorKindSchema = z.enum(["directory", "workspace", "glob", "unmatched"]);
/** How one selector was understood; see {@link ScopeSelectorKindSchema}. */
export type ScopeSelectorKind = z.infer<typeof ScopeSelectorKindSchema>;

/**
 * One `--path` value, and what the repository turned it into.
 *
 * A selector that matched nothing is kept with `kind: "unmatched"` rather than
 * dropped: a typo that silently analysed the whole repository — or nothing at
 * all — is the failure mode this record exists to make impossible.
 */
export const ResolvedSelectorSchema = z.object({
  /** Exactly what the operator typed. */
  selector: z.string().min(1),
  kind: ScopeSelectorKindSchema,
  /** Repo-relative POSIX paths or globs it resolved to; empty when unmatched. */
  paths: z.array(z.string()).default([]),
  /** Why it resolved this way, in the sentence the CLI prints. */
  note: z.string().optional(),
});
/** One resolved `--path` value; see {@link ResolvedSelectorSchema}. */
export type ResolvedSelector = z.infer<typeof ResolvedSelectorSchema>;

/** One unit kind's split across the scope boundary. */
export const ScopeKindCountSchema = z.object({
  kind: AuditUnitKindSchema,
  inScope: z.number().int().nonnegative(),
  outOfScope: z.number().int().nonnegative(),
});
/** One unit kind's split; see {@link ScopeKindCountSchema}. */
export type ScopeKindCount = z.infer<typeof ScopeKindCountSchema>;

/**
 * The inventory, cut in two by the scope.
 *
 * `total` is the whole repository's enumeration, which is why phase 2 keeps
 * running over everything: a bound that cannot say what it excluded is a bound
 * nobody can check.
 */
export const ScopeUnitCountsSchema = z.object({
  total: z.number().int().nonnegative(),
  inScope: z.number().int().nonnegative(),
  outOfScope: z.number().int().nonnegative(),
  /** Per-kind, in contract order, kinds with nothing on either side omitted. */
  byKind: z.array(ScopeKindCountSchema).default([]),
});
/** The inventory cut in two; see {@link ScopeUnitCountsSchema}. */
export type ScopeUnitCounts = z.infer<typeof ScopeUnitCountsSchema>;

/** A phase that deliberately read the whole repository, and the reason it must. */
export const UnscopedPhaseSchema = z.object({
  phase: z.string().min(1),
  reason: z.string().min(1),
});
/** A phase the scope does not narrow; see {@link UnscopedPhaseSchema}. */
export type UnscopedPhase = z.infer<typeof UnscopedPhaseSchema>;

/** The `analysis-scope.json` artifact. */
export const AnalysisScopeSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  runId: z.string().min(1),
  /** Absolute path of the repository; the scope is relative to it. */
  target: z.string().min(1),
  /** True when no `--path` was given: the analysis covered everything. */
  wholeRepository: z.boolean(),
  /** Every `--path` value, in the order it was given, with what it resolved to. */
  selectors: z.array(ResolvedSelectorSchema).default([]),
  /** The resolved subtrees and globs, sorted and de-duplicated. Empty means the whole repo. */
  paths: z.array(z.string()).default([]),
  /** Selectors that matched nothing. A run with one of these is a run to re-type. */
  unmatched: z.array(z.string()).default([]),
  units: ScopeUnitCountsSchema,
  /** Phases that read the whole repository whatever the scope says. */
  unscopedPhases: z.array(UnscopedPhaseSchema).default([]),
  /** Findings the whole-repository analyzers reported in files outside the scope. */
  findingsOutside: z.number().int().nonnegative().default(0),
  /** The sentence every renderer prints; see {@link scopeStatement}. */
  statement: z.string().min(1),
});
/** The scope artifact; see {@link AnalysisScopeSchema}. */
export type AnalysisScope = z.infer<typeof AnalysisScopeSchema>;

/**
 * Normalise one selector to a repo-relative POSIX path.
 *
 * `./apps/api/`, `apps\\api` and `/apps/api` are the same subtree; `.` and the
 * empty string are the whole repository, which is expressed as "no scope" and
 * so normalises to the empty string.
 */
export function normaliseScopePath(value: string): string {
  const cleaned = value
    .trim()
    .replaceAll("\\", "/")
    .replace(/^\.\/+/, "")
    .replace(/^\/+/, "")
    .replace(/\/+$/, "");
  return cleaned === "." ? "" : cleaned;
}

/**
 * True when the selector is a glob rather than a path.
 *
 * Only `*`, `**` and `?` count. Character classes and braces are deliberately
 * not a glob syntax here: a directory really named `logs[1]` is far more likely
 * than an operator reaching for a bracket expression, and a selector Sentinel
 * misreads is a run that analysed the wrong subtree.
 */
export function isGlobSelector(value: string): boolean {
  return value.includes("*") || value.includes("?");
}

/**
 * Compile one scope entry into a matcher over repo-relative POSIX paths.
 *
 * A plain path matches itself and everything under it — `apps/api` covers
 * `apps/api/src/main.ts` but not `apps/api-gateway/main.ts`. A glob is matched
 * segment-aware: `*` and `?` stop at `/`, `**` crosses it, and a trailing `**`
 * is implied for a pattern that ends in a directory separator.
 */
function compileScopeEntry(entry: string): (file: string) => boolean {
  if (!isGlobSelector(entry)) {
    const prefix = `${entry}/`;
    return (file) => file === entry || file.startsWith(prefix);
  }
  const source = entry
    .split("/")
    .map((segment) => {
      if (segment === "**") return "\u0000";
      return segment
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replaceAll("?", "[^/]")
        .replaceAll("*", "[^/]*");
    })
    .join("/")
    // `**` absorbs the separator on one side, so `a/**/b` also matches `a/b`.
    .replaceAll("/\u0000/", "(?:/.*)?/")
    .replaceAll("\u0000/", "(?:.*/)?")
    .replaceAll("/\u0000", "(?:/.*)?")
    .replaceAll("\u0000", ".*");
  const pattern = new RegExp(`^${source}(?:/.*)?$`);
  return (file) => pattern.test(file);
}

/**
 * A reusable predicate over repo-relative paths.
 *
 * An empty scope is the whole repository and answers `true` for everything,
 * which is what keeps every call site free of "if the run was scoped" branches.
 */
export function scopeMatcher(paths: readonly string[]): (file: string) => boolean {
  const entries = paths.map(normaliseScopePath).filter((entry) => entry !== "");
  if (entries.length === 0) return () => true;
  const matchers = entries.map(compileScopeEntry);
  return (file) => {
    const normalised = normaliseScopePath(file);
    return matchers.some((matches) => matches(normalised));
  };
}

/** True when `file` falls inside `paths`; an empty scope contains everything. */
export function isWithinScope(file: string, paths: readonly string[]): boolean {
  return scopeMatcher(paths)(file);
}

/** What the caller must be able to answer about the repository to resolve a selector. */
export interface ScopeProbe {
  /** True when this repo-relative path is a directory. */
  isDirectory(path: string): Promise<boolean>;
  /** Workspace packages the profile proved: package name to repo-relative path. */
  readonly workspaces?: Readonly<Record<string, string>> | undefined;
}

/** What {@link resolveScopeSelectors} produced. */
export interface ResolvedScope {
  readonly selectors: readonly ResolvedSelector[];
  /** Sorted, de-duplicated paths and globs. Empty means the whole repository. */
  readonly paths: readonly string[];
  readonly unmatched: readonly string[];
}

/**
 * Turn what the operator typed into subtrees of this repository.
 *
 * Three ways a selector can land, in the order they are tried:
 *
 * 1. a directory that exists — the ordinary `--path apps/api`;
 * 2. a **workspace package name** — `--path @acme/api`, or `--path api` when
 *    the workspace is called that. In an Nx workspace the thing a person knows
 *    is the project name, and `apps/api` has no `package.json` of its own, so
 *    refusing the name they know would be pedantry;
 * 3. a glob — `--path 'apps/**'` — which is kept as written, because whether
 *    it matches anything is a question about files, not directories.
 *
 * Anything else is `unmatched` and is reported. Nothing is guessed: a selector
 * that resolves to nothing never silently widens the run to the whole
 * repository, and the CLI refuses to start when every selector is unmatched.
 */
export async function resolveScopeSelectors(
  selectors: readonly string[],
  probe: ScopeProbe,
): Promise<ResolvedScope> {
  const resolved: ResolvedSelector[] = [];
  const paths: string[] = [];
  const unmatched: string[] = [];
  const workspaces = probe.workspaces ?? {};

  for (const raw of selectors) {
    const selector = raw.trim();
    if (selector === "") continue;
    const path = normaliseScopePath(selector);
    if (path === "") {
      resolved.push({
        selector,
        kind: "directory",
        paths: [],
        note: "the repository root: this run was not narrowed",
      });
      continue;
    }
    if (isGlobSelector(path)) {
      resolved.push({ selector, kind: "glob", paths: [path] });
      paths.push(path);
      continue;
    }
    if (await probe.isDirectory(path)) {
      resolved.push({ selector, kind: "directory", paths: [path] });
      paths.push(path);
      continue;
    }
    const workspace = matchWorkspace(selector, workspaces);
    if (workspace !== undefined) {
      resolved.push({
        selector,
        kind: "workspace",
        paths: [workspace.path],
        note: `workspace package \`${workspace.name}\` lives in \`${workspace.path}\``,
      });
      paths.push(workspace.path);
      continue;
    }
    const conventional = await matchConventionalDirectory(path, probe);
    if (conventional !== undefined) {
      resolved.push({
        selector,
        kind: "workspace",
        paths: [conventional],
        note: `no \`${path}\` at the repository root, but \`${conventional}\` exists`,
      });
      paths.push(conventional);
      continue;
    }
    resolved.push({
      selector,
      kind: "unmatched",
      paths: [],
      note: "no such directory, and no workspace package or project by that name",
    });
    unmatched.push(selector);
  }

  return { selectors: resolved, paths: [...new Set(paths)].sort(), unmatched };
}

/**
 * The directories a workspace-layout repository keeps its projects in.
 *
 * An Nx project has a `project.json` and usually no `package.json` of its own,
 * so there is no workspace fact to match `api` against — but `apps/api` is
 * where it lives, and `--path api` meaning `apps/api` is the reading an
 * operator intends. The guess only fires for a bare name that matched nothing
 * else, resolves to exactly one existing directory, and is reported in the
 * selector's note, so it is a convenience and never a silent redirection.
 */
const WORKSPACE_PARENTS: readonly string[] = ["apps", "libs", "packages", "services", "modules"];

/** `api` -> `apps/api`, when exactly one conventional parent holds a directory by that name. */
async function matchConventionalDirectory(
  name: string,
  probe: ScopeProbe,
): Promise<string | undefined> {
  if (name.includes("/")) return undefined;
  const found: string[] = [];
  for (const parent of WORKSPACE_PARENTS) {
    const candidate = `${parent}/${name}`;
    if (await probe.isDirectory(candidate)) found.push(candidate);
  }
  return found.length === 1 ? found[0] : undefined;
}

/**
 * Find the workspace a name refers to.
 *
 * Exact package name first, then the last segment of a scoped name (`api` for
 * `@acme/api`), then the last segment of the package's own path (`api` for
 * `apps/api` in a workspace whose packages have no manifest of their own). A
 * name that matches two packages resolves to neither: an ambiguous scope is a
 * question for the operator, not something to pick a winner for.
 */
function matchWorkspace(
  selector: string,
  workspaces: Readonly<Record<string, string>>,
): { readonly name: string; readonly path: string } | undefined {
  const entries = Object.entries(workspaces);
  const wanted = selector.trim();
  const exact = entries.filter(([name]) => name === wanted);
  const candidates =
    exact.length > 0
      ? exact
      : entries.filter(([name, path]) => {
          const tail = name.includes("/") ? (name.split("/").at(-1) ?? name) : name;
          const dir = path.split("/").at(-1) ?? path;
          return tail === wanted || dir === wanted;
        });
  if (candidates.length !== 1) return undefined;
  const only = candidates[0];
  if (only === undefined) return undefined;
  return { name: only[0], path: only[1] };
}

/** Split an enumerated inventory along the scope boundary. */
export function partitionUnits(
  units: readonly AuditUnit[],
  paths: readonly string[],
): { readonly inScope: readonly AuditUnit[]; readonly outOfScope: readonly AuditUnit[] } {
  const matches = scopeMatcher(paths);
  const inScope: AuditUnit[] = [];
  const outOfScope: AuditUnit[] = [];
  for (const unit of units) (matches(unit.location.file) ? inScope : outOfScope).push(unit);
  return { inScope, outOfScope };
}

/** Per-kind counts on both sides of the boundary, in contract order. */
export function countUnitsByKind(
  inScope: readonly AuditUnit[],
  outOfScope: readonly AuditUnit[],
): ScopeKindCount[] {
  const counts = new Map<AuditUnitKind, { inScope: number; outOfScope: number }>();
  const bump = (kind: AuditUnitKind, side: "inScope" | "outOfScope"): void => {
    const entry = counts.get(kind) ?? { inScope: 0, outOfScope: 0 };
    entry[side] += 1;
    counts.set(kind, entry);
  };
  for (const unit of inScope) bump(unit.kind, "inScope");
  for (const unit of outOfScope) bump(unit.kind, "outOfScope");
  return AUDIT_UNIT_KINDS.flatMap((kind) => {
    const entry = counts.get(kind);
    if (entry === undefined) return [];
    return [{ kind, inScope: entry.inScope, outOfScope: entry.outOfScope }];
  });
}

/** `` `apps/api` `` / `` `apps/api` and `libs/shared` ``, for a sentence. */
export function renderScopePaths(paths: readonly string[]): string {
  const quoted = paths.map((path) => `\`${path}\``);
  if (quoted.length === 0) return "the whole repository";
  if (quoted.length === 1) return quoted[0] ?? "the whole repository";
  return `${quoted.slice(0, -1).join(", ")} and ${quoted.at(-1)}`;
}

/**
 * The one sentence every renderer prints.
 *
 * "this run analysed `apps/api` (300 units); the other 5,000 units in this
 * repository were not analysed" — a scoped run's headline, in the numbers the
 * inventory counted, so it cannot be mistaken for a whole-repository run in a
 * terminal, a PDF cover, a markdown report or a diff of two runs.
 */
export function scopeStatement(input: {
  readonly paths: readonly string[];
  readonly units: ScopeUnitCounts;
}): string {
  const units = input.units;
  if (input.paths.length === 0) {
    return `This run analysed the whole repository (${groupThousands(units.total)} ${
      units.total === 1 ? "unit" : "units"
    } of audit).`;
  }
  if (units.total === 0) {
    // Nothing has been enumerated: `--propose-only` stops before phase 2, and a
    // repository can genuinely hold no unit of audit. Either way the exclusion
    // is not a claim this document is entitled to make yet.
    return `This run analysed ${renderScopePaths(
      input.paths,
    )}; no unit of audit was counted, so nothing can be said yet about what that left out.`;
  }
  const head = `This run analysed ${renderScopePaths(input.paths)} (${groupThousands(
    units.inScope,
  )} ${units.inScope === 1 ? "unit" : "units"})`;
  if (units.outOfScope === 0) {
    return `${head}; every unit this repository contains is inside that scope.`;
  }
  // Biggest kinds first, and never a list that reads as exhaustive when it is
  // not: the trailing "and N in K other kinds" accounts for the remainder, so the
  // numbers inside the brackets always add up to the number in front of them.
  const excluded = [...input.units.byKind]
    .filter((entry) => entry.outOfScope > 0)
    .sort(
      (left, right) => right.outOfScope - left.outOfScope || left.kind.localeCompare(right.kind),
    );
  const rest = excluded.slice(3);
  const restTotal = rest.reduce((sum, entry) => sum + entry.outOfScope, 0);
  const parts = [
    ...excluded.slice(0, 3).map((entry) => countUnits(entry.kind, entry.outOfScope)),
    ...(rest.length === 0
      ? []
      : [
          `${groupThousands(restTotal)} in ${rest.length} other ${
            rest.length === 1 ? "kind" : "kinds"
          }`,
        ]),
  ];
  const detail = parts.length === 0 ? "" : ` (${parts.join(", ")})`;
  return `${head}; the other ${groupThousands(units.outOfScope)} ${
    units.outOfScope === 1 ? "unit" : "units"
  } in this repository${detail} were not analysed.`;
}

/**
 * Build the artifact.
 *
 * The statement is derived here rather than passed in, so no caller can write
 * a scope document whose prose and whose numbers disagree.
 */
export function buildAnalysisScope(input: {
  readonly runId: string;
  readonly target: string;
  readonly paths: readonly string[];
  readonly selectors: readonly ResolvedSelector[];
  readonly unmatched: readonly string[];
  readonly units: ScopeUnitCounts;
  readonly unscopedPhases: readonly UnscopedPhase[];
  readonly findingsOutside: number;
}): AnalysisScope {
  return AnalysisScopeSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: input.runId,
    target: input.target,
    wholeRepository: input.paths.length === 0,
    selectors: [...input.selectors],
    paths: [...input.paths],
    unmatched: [...input.unmatched],
    units: input.units,
    unscopedPhases: [...input.unscopedPhases],
    findingsOutside: input.findingsOutside,
    statement: scopeStatement({ paths: input.paths, units: input.units }),
  } satisfies AnalysisScope);
}

/**
 * The phases a `--path` never narrows, with the reason each one must read the
 * whole repository.
 *
 * Stated as data so the run output, the artifact and the dossier make the same
 * disclosure in the same words. Two of these are the plan's own rule — a
 * lockfile and a leaked credential belong to the repository — and the third is
 * a correctness argument: an export used only from outside the scope would be
 * reported as dead if the dead-code graph stopped at the scope boundary.
 */
export const UNSCOPED_PHASES: readonly UnscopedPhase[] = [
  {
    phase: "dependency scan",
    reason:
      "a lockfile, its CVEs and its licences belong to the whole repository, not to a subtree of it",
  },
  {
    phase: "git-history secret scan",
    reason:
      "a credential committed anywhere in this repository's history is leaked for the whole repository",
  },
  {
    phase: "delivery scan",
    reason:
      "the Dockerfiles, compose files and CI workflows that build and ship a subtree usually live above it",
  },
  {
    phase: "dead-code and SAST scan",
    reason:
      "an export used only from outside the scope would read as unused if the module graph stopped at the scope boundary",
  },
  {
    phase: "stack profile",
    reason:
      "the stack is a property of the repository: in a workspace layout the manifests, lockfile and tsconfig that prove it sit above the analysed subtree",
  },
];

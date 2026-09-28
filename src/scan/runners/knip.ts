/**
 * Phase 1 runner for knip: unused files, exports, types and dependencies.
 *
 * Everything knip reports is a *candidate*. knip cannot see a dynamic import, a
 * framework file convention or a barrel re-export, so each finding says so in
 * its own text; the phase 5 agent is what turns a candidate into a claim.
 * Unused dependencies are emitted under D1 rather than D8, because removing one
 * is a supply-chain win and not a tidy-up.
 *
 * **knip is only as good as its entry points.** It starts from entry files and
 * calls everything it cannot reach unused, and its default entry list is
 * `{index,cli,main}.ts` at the root and under `src/` — which in a monorepo whose
 * projects live in `apps/`, `libs/` and `lambdas/` matches nothing at all. When
 * no entry point resolves there is nothing to walk from, so knip reports the
 * whole repository as unreachable, every application's own `main.ts` included,
 * and the result says more about the configuration than about the code. So when
 * the target is a monorepo and has no knip configuration of its own, this runner
 * generates one **in the run directory** — never in the analysed repository —
 * declaring the workspaces and the entry points it can prove from the profile
 * and from the project markers on disk. What it declared is written to
 * `raw/knip/knip.config.json`, counted in the step's reason, and repeated in
 * every finding's text, because an entry point Sentinel chose is a premise of
 * every "unreachable" claim below it.
 *
 * Evidence strength follows the same line: a candidate from a monorepo knip read
 * as a single package is weaker than one from a package it read correctly, and
 * weaker again when the target's dependencies are not installed, so the runner
 * downgrades `confidence` and says which of the two applies.
 */

import { join } from "node:path";
import { z } from "zod";
import type { Confidence, Domain, Finding, Severity } from "../../contracts/findings.ts";
import { PackageJsonSchema, isMonorepo, valuesOf, workspacePackages } from "../../profile/index.ts";
import { VOLUME_THRESHOLD } from "../_volume.ts";
import {
  type KnipCandidate,
  type KnipCandidateKind,
  knipCandidates,
  parseKnipReport,
} from "../parsers/knip.ts";
import type { StepOutcome } from "../types.ts";
import {
  type RunnerContext,
  type RunnerFileSystem,
  briefly,
  failedStep,
  joinReasons,
  makeFinding,
  outcome,
  skipped,
  verifyStepFindings,
  writeRaw,
} from "./_runner-support.ts";

/** Step name, matching the tool it drives. */
export const KNIP_STEP = "knip";

/** Lockfile name in `tools.lock.json`; the resolver maps it to the pinned binary. */
export const KNIP_TOOL = "knip";

/** knip walks the whole module graph; it needs more than a linter's budget. */
export const KNIP_DEFAULT_TIMEOUT_MS = 300_000;

/**
 * Ceiling on candidates turned into findings.
 *
 * It exists to stop a pathological repository from filling memory, not to keep
 * the report short — the report's length is the volume policy's job
 * (`src/scan/_volume.ts`), which collapses the *rendering* of a noisy rule
 * while `findings.json` keeps every finding. A ceiling low enough to double as a
 * report-length limit does the second job badly: a repository with more
 * candidates than the ceiling loses the overflow before the volume policy ever
 * sees it, so this one sits far above any count a real repository produces. A
 * truncated list is still reported as `degraded` with the count, and
 * `raw/knip/knip.json` still holds every line knip wrote.
 */
export const KNIP_MAX_CANDIDATES = 20_000;

/** The sentence every knip finding ends with, so no reader mistakes one for a verdict. */
const CANDIDATE_CAVEAT =
  "This is a candidate, not a verdict: knip cannot see dynamic imports, framework file conventions or re-exported barrels, so phase 5 re-checks it with an agent before it is proposed for removal.";

/** How one knip category becomes a finding. */
interface CandidateSpec {
  readonly domain: Domain;
  readonly rule: string;
  readonly severity: Severity;
  readonly noun: string;
  readonly describe: (candidate: KnipCandidate) => string;
  readonly impact: string;
  readonly recommendation: string;
  readonly acceptanceCriteria: readonly string[];
}

const SPECS: Readonly<Record<KnipCandidateKind, CandidateSpec>> = {
  "unused-file": {
    domain: "deadcode",
    rule: "deadcode.unused-file",
    severity: "low",
    noun: "Unused file candidate",
    describe: (candidate) =>
      `knip reached no entry point that imports \`${candidate.file}\`, so nothing in the analysed graph loads it.`,
    impact:
      "Unreachable files enlarge the review and bundle surface and make it harder to tell which code actually runs.",
    recommendation:
      "Confirm no dynamic import, route convention or build step loads the file, then delete it.",
    acceptanceCriteria: [
      "The file is deleted, or knip's configuration records why it has to stay.",
      "The build and the test suite still resolve after the change.",
    ],
  },
  "unused-export": {
    domain: "deadcode",
    rule: "deadcode.unused-export",
    severity: "info",
    noun: "Unused export candidate",
    describe: (candidate) =>
      `\`${candidate.name}\` is exported from \`${candidate.file}\` but knip found no importer.`,
    impact:
      "Exports with no consumer widen a module's public surface and keep code alive that no caller depends on.",
    recommendation:
      "Confirm nothing imports the symbol dynamically or through a barrel, then make it module-private or delete it.",
    acceptanceCriteria: [
      "The export is removed or downgraded to a module-private binding.",
      "No importer breaks in the build or the test suite.",
    ],
  },
  "unused-type-export": {
    domain: "deadcode",
    rule: "deadcode.unused-type-export",
    severity: "info",
    noun: "Unused type export candidate",
    describe: (candidate) =>
      `The type \`${candidate.name}\` is exported from \`${candidate.file}\` but knip found no importer.`,
    impact:
      "Unused exported types drift away from the code they were written for and mislead the next reader.",
    recommendation:
      "Confirm no declaration file or downstream package refers to the type, then unexport or delete it.",
    acceptanceCriteria: [
      "The type export is removed or made module-private.",
      "Typechecking still passes across the workspace.",
    ],
  },
  "unused-dependency": {
    domain: "dependencies",
    rule: "dependencies.unused-dependency",
    severity: "low",
    noun: "Unused dependency candidate",
    describe: (candidate) =>
      `\`${candidate.name}\` is declared in \`${candidate.file}\` but knip found no import of it in the analysed sources.`,
    impact:
      "A declared dependency is installed, may run install scripts and counts towards the CVE surface even when no code imports it.",
    recommendation:
      "Confirm nothing loads the package at runtime or through configuration, then remove it from the manifest and refresh the lockfile.",
    acceptanceCriteria: [
      "The dependency is removed from `package.json` and the lockfile is regenerated.",
      "Install, build and tests still pass without it.",
    ],
  },
  "unused-dev-dependency": {
    domain: "dependencies",
    rule: "dependencies.unused-dev-dependency",
    severity: "info",
    noun: "Unused dev dependency candidate",
    describe: (candidate) =>
      `\`${candidate.name}\` is declared as a dev dependency in \`${candidate.file}\` but knip found no import or script that uses it.`,
    impact:
      "Unused dev dependencies slow installs and keep unreviewed code in the development tree.",
    recommendation:
      "Confirm no script, config file or CI job invokes it, then remove it from the manifest.",
    acceptanceCriteria: [
      "The dev dependency is removed and the lockfile is regenerated.",
      "Every `package.json` script and CI job still runs.",
    ],
  },
  "unlisted-dependency": {
    domain: "deadcode",
    rule: "deadcode.unlisted-dependency",
    severity: "low",
    noun: "Undeclared dependency",
    describe: (candidate) =>
      `\`${candidate.file}\` imports \`${candidate.name}\`, which no \`package.json\` in the workspace declares.`,
    impact:
      "The import only resolves while another package happens to hoist it, so the build breaks on a clean install or under a different package manager.",
    recommendation:
      "Declare the package explicitly in the manifest of the workspace that imports it.",
    acceptanceCriteria: [
      "The package appears in the importing workspace's `dependencies` or `devDependencies`.",
      "A clean install followed by a build succeeds.",
    ],
  },
  "unresolved-import": {
    domain: "deadcode",
    rule: "deadcode.unresolved-import",
    severity: "low",
    noun: "Unresolved import",
    describe: (candidate) =>
      `knip could not resolve \`${candidate.name}\` referenced from \`${candidate.file}\`.`,
    impact:
      "An unresolvable specifier is either dead configuration or a build that only works by accident on one machine.",
    recommendation:
      "Fix the path or the package name, or remove the reference if it is left over from a deleted module.",
    acceptanceCriteria: [
      "The specifier resolves from a clean checkout.",
      "knip reports no unresolved import for the file.",
    ],
  },
};

// ---------------------------------------------------------------------------
// Configuration: making knip read a monorepo as a monorepo
// ---------------------------------------------------------------------------

/** The filesystem the config planner needs on top of {@link RunnerFileSystem}. */
export interface KnipFileSystem extends RunnerFileSystem {
  /** Expands glob patterns to repo-relative paths; the real port satisfies it. */
  glob(
    patterns: string | readonly string[],
    options?: { cwd?: string; onlyFiles?: boolean; absolute?: boolean },
  ): Promise<string[]>;
}

/** The context this runner takes: a {@link RunnerContext} whose fs can glob. */
export interface KnipContext extends RunnerContext {
  readonly fs: KnipFileSystem;
}

/** Configuration file names knip discovers on its own, in knip's own order. */
export const KNIP_CONFIG_NAMES: readonly string[] = [
  "knip.json",
  "knip.jsonc",
  ".knip.json",
  ".knip.jsonc",
  "knip.ts",
  "knip.js",
  "knip.config.ts",
  "knip.config.js",
];

/** Name of the configuration Sentinel generates inside the run directory. */
export const GENERATED_CONFIG_NAME = "knip.config.json";

/** knip's own default entry patterns; a generated config replaces them, so it repeats them. */
const KNIP_DEFAULT_ENTRY: readonly string[] = [
  "{index,cli,main}.{js,mjs,cjs,jsx,ts,tsx,mts,cts}",
  "src/{index,cli,main}.{js,mjs,cjs,jsx,ts,tsx,mts,cts}",
];

/**
 * File names that are an entry point by convention in a Node project.
 *
 * knip's own three, plus `bootstrap` and `handler`, which is how a Lambda or a
 * serverless bundle names the file its runtime invokes. Deliberately short: a
 * file wrongly declared as an entry point is a file whose own unused exports
 * knip stops reporting, so this list only holds names that are an entry point
 * *because of their name* rather than because they happen to be one here.
 */
const PROJECT_ENTRY_BASENAMES: readonly string[] = ["index", "cli", "main", "bootstrap", "handler"];

/** Source extensions the conventional entry probe accepts. */
const ENTRY_EXTENSIONS: readonly string[] = ["ts", "tsx", "mts", "cts", "js", "mjs", "cjs", "jsx"];

/** Directory names that are never a project root, whatever marker they contain. */
const NOT_A_PROJECT = /(^|\/)(node_modules|dist|build|out|coverage|\.next|\.turbo|\.output)(\/|$)/;

/** Test-runner packages whose presence makes `*.test.*` files entry points. */
const TEST_RUNNERS: readonly string[] = [
  "jest",
  "ts-jest",
  "vitest",
  "mocha",
  "ava",
  "tap",
  "node-tap",
  "@jest/core",
  "@swc/jest",
];

/** Glob that matches the test and spec files a runner loads directly. */
const TEST_ENTRY_PATTERN = "**/*.{test,spec}.{js,mjs,cjs,jsx,ts,tsx,mts,cts}";

/** Where the configuration knip ran under came from. */
export type KnipConfigSource =
  /** The target repository has one of its own; Sentinel does not second-guess it. */
  | "target"
  /** Sentinel generated one in the run directory for a monorepo knip cannot see. */
  | "generated"
  /** knip ran on its own defaults, which is right for a single-package repository. */
  | "default";

/** What the planner decided, and everything the report has to disclose about it. */
export interface KnipConfigPlan {
  readonly source: KnipConfigSource;
  /** Absolute path passed as `--config`, or null when knip discovers its own. */
  readonly configPath: string | null;
  /** The generated document, ready to write; null unless `source` is `generated`. */
  readonly document: string | null;
  /** Workspace directories the generated config declares, `.` included. */
  readonly workspaces: readonly string[];
  /** Entry patterns the generated config declares, workspace-relative. */
  readonly entryPatterns: readonly string[];
  /** True when the repository is a monorepo; drives the confidence downgrade. */
  readonly monorepo: boolean;
  /** How the entry points were derived, one clause per source, for the reason line. */
  readonly derivations: readonly string[];
}

/** Absolute path of the target's own knip configuration, or null when it has none. */
async function targetConfig(ctx: KnipContext): Promise<string | null> {
  for (const name of KNIP_CONFIG_NAMES) {
    const candidate = join(ctx.targetDir, name);
    if (await ctx.fs.exists(candidate)) return candidate;
  }
  return null;
}

/**
 * The root `package.json` as this runner reads it: phase 0's schema plus the
 * `knip` key, which is one of the places knip accepts a configuration.
 */
const KnipRootManifestSchema = PackageJsonSchema.extend({ knip: z.unknown().optional() });
/** A validated root manifest; every field is optional. */
type KnipRootManifest = z.infer<typeof KnipRootManifestSchema>;

/** The root manifest, or null when it cannot be read or does not parse. */
async function rootManifestOf(ctx: KnipContext): Promise<KnipRootManifest | null> {
  try {
    const raw = await ctx.fs.readFile(join(ctx.targetDir, "package.json"));
    const result = KnipRootManifestSchema.safeParse(JSON.parse(raw) as unknown);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

/** True when a test runner is declared, so `*.test.*` files are entry points. */
function declaresTestRunner(manifest: KnipRootManifest | null): boolean {
  if (manifest === null) return false;
  const declared = new Set([
    ...Object.keys(manifest.dependencies ?? {}),
    ...Object.keys(manifest.devDependencies ?? {}),
  ]);
  return TEST_RUNNERS.some((runner) => declared.has(runner));
}

/**
 * Files that mean "several projects live in this repository", beyond the
 * package-manager workspace list knip already reads.
 *
 * These are what separate an *integrated* monorepo — Nx, Turborepo, Rush, one
 * `package.json` at the root and the projects declared some other way — from a
 * plain single package. knip sees the second and cannot see the first.
 */
const MONOREPO_MARKERS: readonly string[] = [
  "nx.json",
  "turbo.json",
  "lerna.json",
  "rush.json",
  "pnpm-workspace.yaml",
  "workspace.json",
];

/**
 * True when a `pnpm-workspace.yaml` actually lists packages.
 *
 * pnpm 10 keeps unrelated settings in that file — `ignoredBuiltDependencies`,
 * catalogs, `onlyBuiltDependencies` — so its mere existence proves nothing. A
 * single package can carry one with no `packages:` key at all, and treating its
 * presence as a monorepo marker would rewrite that repository's knip
 * configuration for no reason.
 */
function declaresPnpmPackages(text: string): boolean {
  const lines = text.split("\n");
  for (const [index, line] of lines.entries()) {
    const inline = /^packages:\s*\[(.*)\]\s*$/.exec(line);
    if (inline !== null) return inline[1]?.trim() !== "";
    if (!/^packages:\s*$/.test(line)) continue;
    return lines.slice(index + 1).some((next) => /^\s+-\s*\S/.test(next));
  }
  return false;
}

/**
 * Whether it is worth asking the repository how many projects it holds.
 *
 * Cheap checks only, and in this order on purpose: the profile's own verdict,
 * then the manifest's workspace list, then a marker file. A single-package
 * repository answers false without a single glob, so nothing walks a large
 * `node_modules` to prove what the absence of `nx.json` already says. A `true`
 * here is a reason to look, not a verdict — {@link planKnipConfig} still wants
 * a second project before it treats the repository as a monorepo.
 */
async function mayHoldSeveralProjects(
  ctx: KnipContext,
  manifest: KnipRootManifest | null,
): Promise<boolean> {
  const profile = ctx.profile;
  if (
    profile !== undefined &&
    (isMonorepo(profile) || valuesOf(profile, "monorepo-tool").length > 0)
  ) {
    return true;
  }
  if (manifest?.workspaces !== undefined) return true;
  for (const marker of MONOREPO_MARKERS) {
    if (!(await ctx.fs.exists(join(ctx.targetDir, marker)))) continue;
    if (marker !== "pnpm-workspace.yaml") return true;
    try {
      if (declaresPnpmPackages(await ctx.fs.readFile(join(ctx.targetDir, marker)))) return true;
    } catch {
      // Unreadable: it proves nothing either way, so it proves nothing.
    }
  }
  return false;
}

/**
 * The directories that hold a project of their own.
 *
 * Nx and its relatives mark a project with `project.json` while keeping a single
 * `package.json` at the root, so the package manager's workspace list — the only
 * thing knip reads — is empty and every project looks like a subdirectory of one
 * big package. The search is bounded to three levels and skips build output, so
 * it cannot wander into `node_modules`.
 */
async function projectRoots(ctx: KnipContext): Promise<string[]> {
  const markers = await ctx.fs.glob(
    ["project.json", "*/project.json", "*/*/project.json", "*/*/*/project.json"],
    { cwd: ctx.targetDir, onlyFiles: true },
  );
  const roots = new Set<string>();
  for (const marker of markers) {
    if (NOT_A_PROJECT.test(marker)) continue;
    const slash = marker.lastIndexOf("/");
    roots.add(slash === -1 ? "." : marker.slice(0, slash));
  }
  return [...roots].sort();
}

/**
 * The conventional entry files that exist under one directory.
 *
 * Existence is checked rather than guessed: the generated config lists the files
 * it found, so a reader can see which premise every "unreachable" finding rests
 * on instead of reading a glob and hoping.
 */
async function conventionalEntries(ctx: KnipContext, dir: string): Promise<string[]> {
  const prefix = dir === "." ? "" : `${dir}/`;
  const patterns = [
    `${prefix}{${PROJECT_ENTRY_BASENAMES.join(",")}}.{${ENTRY_EXTENSIONS.join(",")}}`,
    `${prefix}src/{${PROJECT_ENTRY_BASENAMES.join(",")}}.{${ENTRY_EXTENSIONS.join(",")}}`,
  ];
  const found = await ctx.fs.glob(patterns, { cwd: ctx.targetDir, onlyFiles: true });
  return found.filter((path) => !NOT_A_PROJECT.test(path)).sort();
}

/** Strips a workspace prefix, so a pattern can be written relative to its workspace. */
function relativeTo(workspace: string, path: string): string {
  if (workspace === "." || !path.startsWith(`${workspace}/`)) return path;
  return path.slice(workspace.length + 1);
}

/** An absolute path inside the target, as the report cites it. */
function repoRelative(ctx: KnipContext, absolute: string): string {
  return relativeTo(ctx.targetDir, absolute);
}

/**
 * Plans the configuration knip runs under.
 *
 * The target's own configuration always wins: a repository that has told knip
 * what its entry points are knows better than a profile does. Otherwise a
 * monorepo gets a generated configuration and a single package gets knip's
 * defaults, which is what knip's defaults are for.
 */
export async function planKnipConfig(ctx: KnipContext): Promise<KnipConfigPlan> {
  const manifest = await rootManifestOf(ctx);
  const profile = ctx.profile;

  /** What every early return that is not a monorepo answers. */
  const untouched = (monorepo: boolean): KnipConfigPlan => ({
    source: "default",
    configPath: null,
    document: null,
    workspaces: [],
    entryPatterns: [],
    monorepo,
    derivations: [],
  });

  const worthLooking = await mayHoldSeveralProjects(ctx, manifest);
  const own = await targetConfig(ctx);
  if (own !== null || manifest?.knip !== undefined) {
    return {
      source: "target",
      configPath: null,
      document: null,
      workspaces: [],
      entryPatterns: [],
      monorepo: worthLooking,
      derivations: [
        own === null
          ? "the target declares its own knip configuration under the `knip` key of package.json"
          : `the target has its own knip configuration (${repoRelative(ctx, own)})`,
      ],
    };
  }

  if (!worthLooking) return untouched(false);

  const derivations: string[] = [];
  const rootEntries = new Set<string>(KNIP_DEFAULT_ENTRY);

  const roots = await projectRoots(ctx);
  const packages = profile === undefined ? [] : workspacePackages(profile);
  const workspaceEntries = new Map<string, Set<string>>();

  const nestedPackages = new Set<string>();
  for (const dir of packages) {
    if (dir === "." || dir === "") continue;
    if (!(await ctx.fs.exists(join(ctx.targetDir, dir, "package.json")))) continue;
    nestedPackages.add(dir);
    workspaceEntries.set(dir, new Set(KNIP_DEFAULT_ENTRY));
  }

  // A marker file was a reason to look; a second project is the proof. Without
  // one this is a single package with a monorepo tool installed, and knip's
  // defaults are exactly right for it — a pnpm 10 settings file or a Turborepo
  // task runner must not change how a one-package repository is analysed.
  const monorepo =
    nestedPackages.size > 0 ||
    roots.filter((root) => root !== ".").length > 0 ||
    manifest?.workspaces !== undefined ||
    (profile !== undefined && isMonorepo(profile));
  if (!monorepo) return untouched(false);

  if (nestedPackages.size > 0) {
    derivations.push(
      `${nestedPackages.size} nested package(s) declared as workspaces of their own, so each manifest's dependencies are judged against its own sources`,
    );
  }

  let projectEntryCount = 0;
  for (const root of roots) {
    const entries = await conventionalEntries(ctx, root);
    if (entries.length === 0) continue;
    const owner = [...nestedPackages].find((dir) => root === dir || root.startsWith(`${dir}/`));
    for (const entry of entries) {
      projectEntryCount += 1;
      if (owner === undefined) rootEntries.add(entry);
      else workspaceEntries.get(owner)?.add(relativeTo(owner, entry));
    }
  }
  if (projectEntryCount > 0) {
    derivations.push(
      `${projectEntryCount} conventional entry file(s) named ${PROJECT_ENTRY_BASENAMES.join("/")} across ${roots.length} project director${roots.length === 1 ? "y" : "ies"}`,
    );
  }

  if (declaresTestRunner(manifest)) {
    rootEntries.add(TEST_ENTRY_PATTERN);
    derivations.push(
      "test and spec files, because the root manifest declares a test runner that loads them directly",
    );
  }

  const migrationDirs = profile === undefined ? [] : valuesOf(profile, "migrations-dir");
  for (const dir of migrationDirs) {
    rootEntries.add(`${dir}/*.{js,mjs,cjs,ts,mts,cts}`);
  }
  if (migrationDirs.length > 0) {
    derivations.push(
      `migrations in ${migrationDirs.join(", ")}, which a migration runner loads by path rather than by import`,
    );
  }

  // Nothing was derived, so a generated configuration would say no more than
  // knip's defaults already do. Writing one anyway would claim the monorepo had
  // been configured; instead the run says it could not be, and every candidate
  // is graded down for it.
  if (derivations.length === 0) return untouched(monorepo);

  // The root workspace is always declared, and it has to be: as soon as a knip
  // configuration has a `workspaces` object, a root not listed inside it falls
  // back to knip's defaults and every pattern derived above is silently ignored.
  // Omitting `.` therefore makes every root-level file unreachable at once,
  // which in most repositories is the bulk of the report.
  const workspaces: Record<string, { entry: string[] }> = {
    ".": { entry: [...rootEntries].sort() },
  };
  for (const [dir, entries] of [...workspaceEntries].sort((left, right) =>
    left[0].localeCompare(right[0]),
  )) {
    workspaces[dir] = { entry: [...entries].sort() };
  }

  // Only keys knip's own schema declares: it refuses a configuration with an
  // unknown property, so the file cannot carry a "generated by" marker of its
  // own. Its name, its place under `raw/` and the step's reason say where it
  // came from instead.
  const document = `${JSON.stringify({ workspaces }, null, 2)}\n`;

  return {
    source: "generated",
    configPath: join(ctx.runDir, "raw", KNIP_STEP, GENERATED_CONFIG_NAME),
    document,
    workspaces: Object.keys(workspaces),
    entryPatterns: [...rootEntries].sort(),
    monorepo,
    derivations,
  };
}

// ---------------------------------------------------------------------------
// Evidence strength
// ---------------------------------------------------------------------------

/** How much a knip candidate is worth, and the sentence that says why. */
export interface KnipEvidence {
  readonly confidence: Confidence;
  /** Appended to every finding's description; never empty. */
  readonly caveat: string;
  /** The same fact in the step's own words, for the analyzers table. */
  readonly note: string;
}

/**
 * Grades what knip saw.
 *
 * Two things weaken a dead-code candidate, and both are facts about the run
 * rather than about the code: a monorepo knip read as one package reports what
 * another project imports as unused, and a repository whose dependencies are not
 * installed hides the framework plugins that declare entry points, so files a
 * framework loads by convention look unreachable. Either one drops the finding
 * to `low`, and the reason travels with the finding instead of staying in a log.
 */
export function knipEvidence(plan: KnipConfigPlan, dependenciesInstalled: boolean): KnipEvidence {
  const weaknesses: string[] = [];
  if (plan.monorepo && plan.source === "default") {
    weaknesses.push(
      "knip ran on its default single-package configuration over a monorepo, so a symbol that another project in the repository imports is reported here as unused",
    );
  }
  if (!dependenciesInstalled) {
    weaknesses.push(
      "the target's dependencies are not installed, so knip could neither resolve external imports nor load the framework plugins that declare entry points of their own",
    );
  }
  if (weaknesses.length > 0) {
    return {
      confidence: "low",
      caveat: `Low confidence, and why: ${weaknesses.join("; and ")}.`,
      note: `dead-code candidates are low confidence because ${weaknesses.join("; and ")}`,
    };
  }
  if (plan.source === "generated") {
    return {
      confidence: "medium",
      caveat: `knip ran under a configuration Sentinel generated for this monorepo (${plan.workspaces.length} workspace(s), ${plan.entryPatterns.length} root entry pattern(s), written to \`raw/${KNIP_STEP}/${GENERATED_CONFIG_NAME}\`), because the repository declares none of its own; a file reachable only through a path that configuration does not declare can still appear here.`,
      note: `entry points were declared by a Sentinel-generated configuration (raw/${KNIP_STEP}/${GENERATED_CONFIG_NAME})`,
    };
  }
  if (plan.source === "target") {
    return {
      confidence: "medium",
      caveat:
        "knip ran under the repository's own configuration, so its entry points are the ones the repository declares.",
      note: "the repository's own knip configuration was used",
    };
  }
  return {
    confidence: "medium",
    caveat:
      "knip ran on its own defaults over a single-package repository, which is what those defaults are for.",
    note: "knip ran on its own defaults",
  };
}

/** Turns one knip candidate into an unverified finding. */
export function knipFinding(candidate: KnipCandidate, evidence: KnipEvidence): Finding {
  const spec = SPECS[candidate.kind];
  return makeFinding({
    domain: spec.domain,
    rule: spec.rule,
    severity: spec.severity,
    confidence: evidence.confidence,
    title: `${spec.noun}: ${candidate.name}`,
    description: `${spec.describe(candidate)} ${CANDIDATE_CAVEAT} ${evidence.caveat}`,
    impact: spec.impact,
    recommendation: spec.recommendation,
    acceptanceCriteria: spec.acceptanceCriteria,
    file: candidate.file,
    line: candidate.line,
    symbol: candidate.name,
    source: { kind: "tool", name: KNIP_STEP },
  });
}

/** The arguments knip is always run with: machine-readable, and never a failing exit. */
export function knipArgs(configPath: string | null = null): string[] {
  const args = ["--reporter", "json", "--no-exit-code"];
  return configPath === null ? args : [...args, "--config", configPath];
}

/** Rules whose candidate count crossed the volume threshold, as a reason clause. */
function volumeNote(findings: readonly Finding[]): string | null {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    counts.set(finding.rule, (counts.get(finding.rule) ?? 0) + 1);
  }
  const loud = [...counts]
    .filter(([, count]) => count > VOLUME_THRESHOLD)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  if (loud.length === 0) return null;
  const listed = loud.map(([rule, count]) => `${rule} (${count})`).join(", ");
  return `over the volume threshold of ${VOLUME_THRESHOLD} per rule, so the dossier renders ${loud.length === 1 ? "it" : "them"} as a counted group with examples while findings.json keeps every one: ${listed}`;
}

/**
 * Runs knip over the target and normalises its report into findings. Never
 * throws: a missing tool or a repository with no manifest is `skipped`, output
 * that cannot be trusted is `failed`, and anything the reader has to know about
 * the configuration, the entry points or a truncated list is `degraded` with the
 * reason spelled out.
 */
export async function runKnip(ctx: KnipContext): Promise<StepOutcome> {
  const startedAt = performance.now();
  const timeoutMs = ctx.timeoutMs ?? KNIP_DEFAULT_TIMEOUT_MS;

  if (!(await ctx.fs.exists(join(ctx.targetDir, "package.json")))) {
    return skipped(KNIP_STEP, startedAt, "the target has no package.json");
  }

  const binary = await ctx.tools.resolve(KNIP_TOOL, { allowPath: ctx.allowPathTools === true });
  if (binary === null) {
    return skipped(
      KNIP_STEP,
      startedAt,
      "knip is not installed; run `sentinel setup` (unused files, exports and dependencies will not be reported)",
    );
  }

  const artifacts: string[] = [];
  const notes: (string | null)[] = [];

  const plan = await planKnipConfig(ctx);
  if (plan.document !== null && plan.configPath !== null) {
    await ctx.fs.writeFile(plan.configPath, plan.document);
    artifacts.push(plan.configPath);
    notes.push(
      `this monorepo declares no knip configuration, so knip ran under one Sentinel generated in the run directory (raw/${KNIP_STEP}/${GENERATED_CONFIG_NAME}): ${plan.workspaces.length} workspace(s) and ${plan.entryPatterns.length} entry pattern(s) from ${plan.derivations.join(", ")}`,
    );
    notes.push(
      "knip does not report unused exports inside a file it treats as an entry point, so those are outside this step; re-run knip with `--include-entry-exports` against that configuration to see them",
    );
  }

  const dependenciesInstalled = await ctx.fs.exists(join(ctx.targetDir, "node_modules"));
  const evidence = knipEvidence(plan, dependenciesInstalled);
  notes.push(evidence.note);

  const args = knipArgs(plan.configPath);
  const result = await ctx.exec.run(binary, args, {
    cwd: ctx.targetDir,
    timeoutMs,
    env: { NO_COLOR: "1" },
  });

  if (result.stdout !== "") {
    artifacts.push(await writeRaw(ctx, KNIP_STEP, "knip.json", result.stdout));
  }
  if (result.stderr.trim() !== "") {
    artifacts.push(await writeRaw(ctx, KNIP_STEP, "knip.stderr.log", result.stderr));
  }

  if (result.notFound) {
    return skipped(KNIP_STEP, startedAt, `knip is not executable at ${binary}`);
  }
  if (result.timedOut) {
    return failedStep(KNIP_STEP, startedAt, `knip timed out after ${timeoutMs} ms`, artifacts);
  }
  if (result.truncated) {
    return failedStep(
      KNIP_STEP,
      startedAt,
      "knip output exceeded the capture limit and was truncated",
      artifacts,
    );
  }

  const stdout = result.stdout.trim();
  if (stdout === "") {
    return failedStep(
      KNIP_STEP,
      startedAt,
      `knip exited ${result.exitCode} without output: ${briefly(result.stderr, 200) || "no stderr"}`,
      artifacts,
    );
  }

  const report = parseKnipReport(stdout);
  if (!report.ok) {
    return failedStep(KNIP_STEP, startedAt, report.error, artifacts);
  }

  // knip prints its own errors and still reports what it could analyse; the
  // findings are usable, the coverage behind them is not complete.
  if (result.stderr.includes("ERROR")) {
    notes.push(
      `knip reported an error while loading the target's own toolchain, so any entry point that configuration would have declared is missing: ${briefly(result.stderr, 200)}`,
    );
  }

  const candidates = knipCandidates(report.value);
  if (candidates.length > KNIP_MAX_CANDIDATES) {
    notes.push(
      `knip reported ${candidates.length} candidates; only the first ${KNIP_MAX_CANDIDATES}, sorted by file, were turned into findings — the rest are in raw/${KNIP_STEP}/knip.json`,
    );
  }

  const verified = await verifyStepFindings(
    candidates.slice(0, KNIP_MAX_CANDIDATES).map((candidate) => knipFinding(candidate, evidence)),
    ctx,
  );
  if (verified.droppedFindings > 0) {
    notes.push(
      `${verified.droppedFindings} candidate(s) dropped: the file knip named does not resolve to a readable file in the repository`,
    );
  }
  notes.push(volumeNote(verified.kept));

  // A generated configuration is not a degradation — it is what makes the run
  // trustworthy, and its reason line says what it declared. What degrades the
  // step is evidence Sentinel knows to be weak: a truncated candidate list, a
  // dropped citation, an error from knip itself, or a run whose candidates could
  // not be graded above `low`.
  const degraded =
    candidates.length > KNIP_MAX_CANDIDATES ||
    verified.droppedFindings > 0 ||
    result.stderr.includes("ERROR") ||
    evidence.confidence === "low";
  return outcome(
    KNIP_STEP,
    degraded ? "degraded" : "ok",
    joinReasons(notes),
    verified.kept,
    artifacts,
    startedAt,
  );
}

import { isAbsolute, join, resolve } from "node:path";
import { z } from "zod";
import { type Domain, SCHEMA_VERSION } from "./findings.ts";
import { type ProposalAnswer, SentinelConfigSchema } from "./proposal.ts";

/**
 * `sentinel.config.json` — the file Sentinel writes into the target repository
 * so a second run does not re-ask the scope questions of phase 0.5.
 *
 * The answers and domain overrides are `SentinelConfigSchema` from
 * `contracts/proposal.ts`, extended here (rather than restated) with the two
 * sections the CLI owns: tool overrides and analyze defaults. One schema, so
 * the phase that writes the answers and the CLI that reads them cannot drift.
 *
 * Precedence everywhere: CLI flags > config file > defaults.
 */

/** File name Sentinel reads and writes at the root of the analysed repo. */
export const CONFIG_FILE_NAME = "sentinel.config.json";

/** Per-tool escape hatch: pin a path, pin a version, or turn the tool off. */
export const ToolOverrideSchema = z.object({
  path: z.string().optional(),
  version: z.string().optional(),
  enabled: z.boolean().optional(),
});
export type ToolOverride = z.infer<typeof ToolOverrideSchema>;

/** Run defaults the repository wants, each overridable by a flag. */
export const AnalyzeDefaultsSchema = z.object({
  /** Output root; a relative path resolves against the repo the config lives in. */
  out: z.string().optional(),
  /**
   * `--path`: the subtrees this repository wants analysed, repo-relative.
   *
   * Remembered so the second run on a monorepo does not have to re-type the
   * one deployable worth auditing — and so a *change* of scope shows up as a
   * line in `git diff` on this file rather than as an unexplained jump in the
   * next run's unit count. An empty array and an absent key both mean "the
   * whole repository"; `--path` on the command line replaces this list rather
   * than adding to it, because a scope that silently grew would be the same
   * bug in the other direction.
   */
  path: z.array(z.string()).optional(),
  maxParallel: z.number().int().positive().optional(),
  ai: z.boolean().optional(),
  skipScan: z.boolean().optional(),
  /** Render `report.pdf` at the end of a run. `report.md` and `issues.md` are not optional. */
  pdf: z.boolean().optional(),
});
export type AnalyzeDefaults = z.infer<typeof AnalyzeDefaultsSchema>;

/** The whole config document: proposal answers plus the CLI-owned sections. */
export const ConfigFileSchema = SentinelConfigSchema.extend({
  /** Tool overrides, keyed by tool name. */
  tools: z.record(z.string(), ToolOverrideSchema).default({}),
  analyze: AnalyzeDefaultsSchema.default({}),
});
export type ConfigFile = z.infer<typeof ConfigFileSchema>;

/** What a caller may hand {@link saveConfig}: defaults are filled in on the way out. */
export type ConfigFileInput = z.input<typeof ConfigFileSchema>;

/** Default AI batch fan-out. Deliberately low: the subscription runtime is the bottleneck. */
export const DEFAULT_MAX_PARALLEL = 2;

/** Directory created inside the target repo to hold run directories. */
export const DEFAULT_OUT_DIR_NAME = "sentinel";

/** A config with nothing decided yet: every proposal will be asked. */
export function emptyConfigFile(): ConfigFile {
  return ConfigFileSchema.parse({ schemaVersion: SCHEMA_VERSION });
}

/** Flag values that override the config file; an absent key defers to it. */
export interface AnalyzeFlagOverrides {
  readonly out?: string;
  /** `--path`, repeatable: directories, workspace package names or globs. */
  readonly path?: readonly string[];
  readonly include?: readonly string[];
  readonly exclude?: readonly string[];
  readonly proposeOnly?: boolean;
  readonly yes?: boolean;
  readonly ai?: boolean;
  readonly maxParallel?: number;
  /** `--max-batches`: batches phase 4 may dispatch. */
  readonly maxBatches?: number;
  /** `--max-units`: units phase 4 may put in front of a model. */
  readonly maxUnits?: number;
  /** `--max-audit-minutes`: wall clock phase 4's dispatch loop may spend. */
  readonly maxAuditMinutes?: number;
  /** `--no-budget`: audit every unit in scope, however long it takes. */
  readonly noBudget?: boolean;
  /** `--save-scope`: write this run's `--path` into the target's config file. */
  readonly saveScope?: boolean;
  readonly skipScan?: boolean;
  readonly pdf?: boolean;
  readonly json?: boolean;
  readonly verbose?: boolean;
  readonly quiet?: boolean;
}

/**
 * Everything phase 0.5 needs to answer its proposals, gathered from the flags
 * and the config file. Structurally a `ScopeOptions` (`propose/decide.ts`), so
 * the CLI resolves precedence and the propose phase owns the decision —
 * neither module has to import the other.
 */
export interface ScopeInput {
  /** `--include` selectors: a proposal id, an alias, or a domain name. */
  readonly include: readonly string[];
  /** `--exclude` selectors, which beat `--include`. */
  readonly exclude: readonly string[];
  /** `--yes`: answer every otherwise-unanswered proposal with its default. */
  readonly acceptDefaults: boolean;
  /** Answers remembered from a previous run. */
  readonly previousAnswers: Readonly<Record<string, ProposalAnswer>>;
  /** Domains the config forces on or off regardless of the proposals. */
  readonly domainOverrides: {
    readonly include: readonly Domain[];
    readonly exclude: readonly Domain[];
  };
}

/** Fully resolved analyze settings: flags over config over defaults. */
export interface ResolvedAnalyzeOptions {
  /** Absolute path of the repository under analysis. */
  readonly target: string;
  /** Absolute path of the directory that holds run directories. */
  readonly outDir: string;
  /**
   * `--path` selectors, as typed, before the repository resolves them.
   *
   * Unresolved on purpose: turning `apps/api` into a subtree needs the
   * filesystem and the workspace packages phase 0 proved, and this module
   * neither reads files nor knows what a workspace is. Empty means the whole
   * repository. See `contracts/scope.ts`.
   */
  readonly pathSelectors: readonly string[];
  /** True when the selectors came from `--path`, not from the config file. */
  readonly pathFromFlag: boolean;
  /**
   * A scope a previous run wrote into `sentinel.config.json` that this run did
   * **not** apply, because no `--path` was given. Reported so the caller can
   * opt back into it deliberately.
   */
  readonly carriedScope: readonly string[];
  /** Write this run's `--path` scope into the target's config. Off by default. */
  readonly saveScope: boolean;
  readonly scope: ScopeInput;
  readonly proposeOnly: boolean;
  readonly ai: boolean;
  readonly maxParallel: number;
  /**
   * The ceilings phase 4 runs under, as the flags gave them.
   *
   * Left unresolved on purpose, and declared structurally rather than imported:
   * turning these four into a budget is `auditBudgetFrom` in
   * `src/audit/budget.ts`, which is where `--max-batches 0` means *off* rather
   * than "dispatch nothing", and this layer neither knows nor decides that. The
   * shape is `AuditBudgetFlags`, so the CLI hands this object straight to it.
   */
  readonly auditBudget: {
    readonly maxBatches?: number | undefined;
    readonly maxUnits?: number | undefined;
    readonly maxMinutes?: number | undefined;
    readonly unbounded?: boolean | undefined;
  };
  readonly skipScan: boolean;
  /** False under `--no-pdf`: phases 6 and 7 still run, the PDF is just not written. */
  readonly pdf: boolean;
  readonly json: boolean;
  readonly verbose: boolean;
  readonly quiet: boolean;
  readonly toolOverrides: Readonly<Record<string, ToolOverride>>;
}

/** Input for {@link resolveAnalyzeOptions}. */
export interface AnalyzeResolutionInput {
  /** Repository to analyse; resolved against `cwd` when relative. */
  readonly target: string;
  /** Directory the user typed the command in, which `--out` is relative to. */
  readonly cwd: string;
  readonly flags: AnalyzeFlagOverrides;
  readonly config?: ConfigFile;
}

/**
 * Trim path selectors, dropping the empty ones.
 *
 * Deliberately not lower-cased, unlike the proposal selectors below: `apps/API`
 * and `apps/api` are two different directories on a case-sensitive filesystem,
 * and a scope Sentinel silently rewrote would analyse a subtree the operator
 * did not name.
 */
function normalisePaths(paths: readonly string[] | undefined): readonly string[] {
  return (paths ?? []).map((path) => path.trim()).filter((path) => path.length > 0);
}

/** Trim and lowercase selectors, dropping the empty ones. */
function normaliseSelectors(selectors: readonly string[] | undefined): readonly string[] {
  return (selectors ?? [])
    .map((selector) => selector.trim().toLowerCase())
    .filter((selector) => selector.length > 0);
}

/**
 * Collapse defaults, the config file and the CLI flags into one settled object.
 * A `--out` flag is relative to where the user typed it; a config `analyze.out`
 * is relative to the repository whose config file it is.
 */
export function resolveAnalyzeOptions(input: AnalyzeResolutionInput): ResolvedAnalyzeOptions {
  const config = input.config ?? emptyConfigFile();
  const flags = input.flags;
  const target = resolve(input.cwd, input.target);

  const flagOut = flags.out;
  const configOut = config.analyze.out;
  const outDir =
    flagOut !== undefined
      ? resolve(input.cwd, flagOut)
      : configOut !== undefined
        ? isAbsolute(configOut)
          ? configOut
          : resolve(target, configOut)
        : join(target, DEFAULT_OUT_DIR_NAME);

  const flagPaths = normalisePaths(flags.path);
  const configPaths = normalisePaths(config.analyze.path);

  return {
    target,
    outDir,
    // A remembered scope never narrows a run on its own. Narrowing is the one
    // decision that decides what a dossier does *not* cover, so it has to be
    // made in the invocation that produces it: `sentinel analyze <repo>` with
    // no `--path` covers the repository, whatever a config file from an
    // earlier run says. The remembered value is still reported, so the caller
    // can opt back into it (`carriedScope` below).
    pathSelectors: flagPaths,
    pathFromFlag: flags.path !== undefined,
    /** A scope a previous run remembered, which this run deliberately did not apply. */
    carriedScope: flags.path === undefined ? configPaths : [],
    saveScope: flags.saveScope ?? false,
    scope: {
      include: normaliseSelectors(flags.include),
      exclude: normaliseSelectors(flags.exclude),
      acceptDefaults: flags.yes ?? false,
      previousAnswers: config.answers,
      domainOverrides: config.domains,
    },
    proposeOnly: flags.proposeOnly ?? false,
    ai: flags.ai ?? config.analyze.ai ?? true,
    maxParallel: flags.maxParallel ?? config.analyze.maxParallel ?? DEFAULT_MAX_PARALLEL,
    auditBudget: {
      ...(flags.maxBatches === undefined ? {} : { maxBatches: flags.maxBatches }),
      ...(flags.maxUnits === undefined ? {} : { maxUnits: flags.maxUnits }),
      ...(flags.maxAuditMinutes === undefined ? {} : { maxMinutes: flags.maxAuditMinutes }),
      ...(flags.noBudget === undefined ? {} : { unbounded: flags.noBudget }),
    },
    skipScan: flags.skipScan ?? config.analyze.skipScan ?? false,
    pdf: flags.pdf ?? config.analyze.pdf ?? true,
    json: flags.json ?? false,
    verbose: flags.verbose ?? false,
    quiet: flags.quiet ?? false,
    toolOverrides: config.tools,
  };
}

/**
 * The slice of the filesystem port this module needs, declared structurally so
 * the contracts layer never imports the port itself.
 */
export interface ConfigFileSystem {
  readFile(path: string): Promise<string>;
  writeFile(path: string, data: string): Promise<void>;
  exists(path: string): Promise<boolean>;
}

/** Outcome of reading `sentinel.config.json`; an unreadable config is never guessed at. */
export type ConfigLoadResult =
  | { readonly status: "missing"; readonly path: string; readonly config: ConfigFile }
  | { readonly status: "loaded"; readonly path: string; readonly config: ConfigFile }
  | { readonly status: "invalid"; readonly path: string; readonly error: string };

/** Absolute path of the config file for a target repository. */
export function configPath(targetDir: string): string {
  return join(resolve(targetDir), CONFIG_FILE_NAME);
}

/** Render Zod issues as one line, so the CLI can say why a config was rejected. */
function describeIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.join(".");
      return path.length > 0 ? `${path}: ${issue.message}` : issue.message;
    })
    .join("; ");
}

/**
 * Read and validate `sentinel.config.json`. A missing file is not an error —
 * it means "nothing decided yet" — but a malformed one is reported rather than
 * partially believed.
 */
export async function loadConfig(
  fs: ConfigFileSystem,
  targetDir: string,
): Promise<ConfigLoadResult> {
  const path = configPath(targetDir);
  if (!(await fs.exists(path))) return { status: "missing", path, config: emptyConfigFile() };

  const raw = await fs.readFile(path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { status: "invalid", path, error: `not valid JSON (${message})` };
  }

  const result = ConfigFileSchema.safeParse(parsed);
  if (!result.success) return { status: "invalid", path, error: describeIssues(result.error) };
  return { status: "loaded", path, config: result.data };
}

/** Serialise a config: validated, keys stable, newline-terminated. */
export function serializeConfig(config: ConfigFileInput): string {
  const validated = ConfigFileSchema.parse(config);
  const answers = Object.fromEntries(
    Object.entries(validated.answers).sort(([left], [right]) => left.localeCompare(right)),
  );
  return `${JSON.stringify({ ...validated, answers }, null, 2)}\n`;
}

/**
 * Write `sentinel.config.json`. The port's `writeFile` is atomic (temp file →
 * rename), so an interrupted run can never leave the target repo holding a
 * truncated config.
 */
export async function saveConfig(
  fs: ConfigFileSystem,
  targetDir: string,
  config: ConfigFileInput,
): Promise<string> {
  const path = configPath(targetDir);
  await fs.writeFile(path, serializeConfig(config));
  return path;
}

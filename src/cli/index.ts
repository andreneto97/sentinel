import { resolve } from "node:path";
// Type-only, so the modules these come from are still loaded on demand below:
// `import type` is erased, and only the verbs that need them pay for them.
import type { CitedRanges } from "../audit/batch.ts";
import type { AnalyzeFlagOverrides } from "../contracts/config.ts";
import { type Clock, createSystemClock } from "../ports/clock.ts";
import type { Logger } from "../ports/logger.ts";
import type { ToolResolver } from "../tools/resolve.ts";
import {
  type CommandSpec,
  type ParsedArgs,
  type UsageError,
  flagBoolean,
  flagList,
  flagNumber,
  flagProvided,
  flagString,
  parseArgs,
  renderCommandHelp,
  renderFlagLines,
} from "./_shared/args.ts";
import type { RunPhaseName } from "./_shared/run-artifacts.ts";
import { type RandomSource, cryptoRandom } from "./_shared/run-dir.ts";
import type { ReportFormat, ReportInvocation } from "./report.ts";
import type { ResumeInvocation } from "./resume.ts";
import type { StatusInvocation } from "./status.ts";

/**
 * The Sentinel command surface: parse, validate, dispatch. `runCli` never calls
 * `process.exit` and never touches the filesystem — it returns an exit code,
 * which is what makes every verb testable — and each verb's real work lives
 * behind an injectable handler.
 */

/** Process exit codes. Anything outside this table is a bug. */
export const EXIT = {
  /** The run completed. */
  ok: 0,
  /** The run started and failed. */
  failure: 1,
  /** A required preflight check failed (missing tool, unwritable output). */
  preflight: 2,
  /** The command line could not be understood. */
  usage: 64,
  /** Interrupted by SIGINT/SIGTERM. */
  interrupted: 130,
} as const;

/** One of the five exit codes Sentinel can return. */
export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

/** Kept in step with `package.json`; a generated version module can replace it. */
export const SENTINEL_VERSION = "0.0.1";

/** Everything a command handler is allowed to reach outside itself. */
export interface CliContext {
  /** Write to stdout; newlines are the caller's business. */
  readonly write: (text: string) => void;
  /** Write to stderr. */
  readonly writeError: (text: string) => void;
  readonly cwd: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly clock: Clock;
  readonly random: RandomSource;
  readonly version: string;
}

/** Reporting flags every parsed verb accepts. */
export interface OutputFlags {
  readonly json: boolean;
  readonly verbose: boolean;
  readonly quiet: boolean;
}

/** A parsed `sentinel analyze` invocation, before the config file is consulted. */
export interface AnalyzeInvocation {
  /** Absolute path of the repository to analyse. */
  readonly target: string;
  readonly cwd: string;
  /** Flags only; the handler merges them over `sentinel.config.json`. */
  readonly flags: AnalyzeFlagOverrides;
}

/** A parsed `sentinel setup` invocation. */
export interface SetupInvocation {
  /** Install only this tool instead of the whole pinned set. */
  readonly only?: string;
  /** Re-download and re-verify even when the tool is already present. */
  readonly force: boolean;
  readonly output: OutputFlags;
}

/** A parsed `resume` / `status` / `report` invocation. */
export interface RunDirInvocation {
  /** The `<run-dir>` argument as typed: a run directory or an output directory. */
  readonly runDir: string;
  readonly cwd: string;
  readonly output: OutputFlags;
}

/**
 * The real implementation behind each verb. `doctor` takes raw argv because it
 * owns its own parsing (`src/cli/doctor.ts`); the three run-directory verbs take
 * their own invocation shapes, each of which extends {@link RunDirInvocation}
 * with the flags only that verb has.
 */
export interface CommandHandlers {
  analyze(context: CliContext, invocation: AnalyzeInvocation): Promise<number>;
  setup(context: CliContext, invocation: SetupInvocation): Promise<number>;
  doctor(context: CliContext, argv: readonly string[]): Promise<number>;
  resume(context: CliContext, invocation: ResumeInvocation): Promise<number>;
  status(context: CliContext, invocation: StatusInvocation): Promise<number>;
  report(context: CliContext, invocation: ReportInvocation): Promise<number>;
}

/** Overrides for {@link runCli}; both default to the real process and the real verbs. */
export interface RunCliOptions {
  readonly context?: Partial<CliContext>;
  readonly handlers?: Partial<CommandHandlers>;
}

const OUTPUT_FLAGS = {
  json: { kind: "boolean", description: "Emit machine-readable JSON on stdout" },
  verbose: { kind: "boolean", short: "v", description: "Log every step" },
  quiet: { kind: "boolean", short: "q", description: "Only report failures" },
} as const;

/**
 * `--format` values `sentinel report` accepts. Declared here so validating a
 * command line does not load the renderer, and checked against the renderer's
 * own union by `satisfies` so the two cannot drift apart.
 */
const REPORT_FORMATS = [
  "all",
  "pdf",
  "md",
  "issues",
  "brief",
] as const satisfies readonly ReportFormat[];

/** Phase names `--force-phase` accepts; see {@link REPORT_FORMATS} about the duplication. */
const RESUMABLE_PHASES = [
  "profile",
  "propose",
  "scan",
  "inventory",
  "audit",
  "report",
] as const satisfies readonly RunPhaseName[];

const RUN_DIR_POSITIONAL = {
  name: "run-dir",
  description: "A run directory, or an output directory with a .latest pointer",
  required: true,
} as const;

/** Specs for every verb, in the order the root help lists them. */
export const COMMAND_SPECS: readonly CommandSpec[] = [
  {
    name: "analyze",
    summary: "Profile a repository, negotiate scope, and produce the backend dossier.",
    positionals: [
      { name: "target", description: "Path to the repository to analyse", required: true },
    ],
    flags: {
      out: {
        kind: "string",
        short: "o",
        placeholder: "dir",
        description: "Where runs are written (default <target>/sentinel)",
      },
      path: {
        kind: "list",
        short: "p",
        placeholder: "glob-or-dir",
        description:
          "Analyse only these subtrees (repeatable: a directory, a workspace name or a glob)",
      },
      include: {
        kind: "list",
        placeholder: "list",
        description: "Domains or proposal ids to enable",
      },
      exclude: {
        kind: "list",
        placeholder: "list",
        description: "Domains or proposal ids to leave out",
      },
      "propose-only": {
        kind: "boolean",
        description: "Print the scope proposals and exit without analysing",
      },
      yes: {
        kind: "boolean",
        short: "y",
        description: "Accept every proposal default without asking",
      },
      ai: {
        kind: "boolean",
        negatable: true,
        helpName: "--no-ai",
        description: "Skip the AI phases (audit, dead-code verification)",
      },
      "max-parallel": {
        kind: "number",
        placeholder: "n",
        description: "Concurrent agent batches (default 2)",
      },
      "max-batches": {
        kind: "number",
        placeholder: "n",
        description: "Audit at most this many batches, highest risk first (default 40)",
      },
      "max-units": {
        kind: "number",
        placeholder: "n",
        description: "Audit at most this many units",
      },
      "max-audit-minutes": {
        kind: "number",
        placeholder: "n",
        description: "Stop dispatching audit batches after this long (default 45)",
      },
      budget: {
        kind: "boolean",
        negatable: true,
        helpName: "--no-budget",
        description: "Audit every unit in scope, with no batch, unit or time ceiling",
      },
      "save-scope": {
        kind: "boolean",
        description: "Remember --path in the target's sentinel.config.json (off by default)",
      },
      "skip-scan": { kind: "boolean", description: "Reuse the previous run's raw tool output" },
      pdf: {
        kind: "boolean",
        negatable: true,
        helpName: "--no-pdf",
        description: "Skip report.pdf; the scorecard, report.md and issues.md are still produced",
      },
      ...OUTPUT_FLAGS,
    },
  },
  {
    name: "setup",
    summary: "Download and hash-verify the pinned analysis tools into the Sentinel cache.",
    flags: {
      only: { kind: "string", placeholder: "tool", description: "Install just this tool" },
      force: { kind: "boolean", short: "f", description: "Re-download even if already installed" },
      ...OUTPUT_FLAGS,
    },
  },
  {
    // Mirrors the surface `src/cli/doctor.ts` parses; `sentinel help doctor`
    // asks that module for its own usage text rather than reprinting this.
    name: "doctor",
    summary: "Report which tools are present and what coverage each missing one costs.",
    positionals: [
      { name: "target", description: "Repository to check (default: the current directory)" },
    ],
    flags: {
      out: {
        kind: "string",
        short: "o",
        placeholder: "dir",
        description: "Output directory to test for writability",
      },
      json: {
        kind: "boolean",
        description: "Print the machine-readable report instead of the table",
      },
    },
  },
  {
    name: "resume",
    summary: "Re-enter a run at its first incomplete phase.",
    positionals: [RUN_DIR_POSITIONAL],
    flags: {
      "force-phase": {
        kind: "string",
        placeholder: "name",
        description: `Redo this phase even though it finished (${RESUMABLE_PHASES.join(", ")})`,
      },
      "retry-failed": {
        kind: "boolean",
        description: "Re-dispatch only what this run has no verdict for",
      },
      "max-parallel": {
        kind: "number",
        placeholder: "n",
        description: "Concurrent agent batches if the audit runs (default 2)",
      },
      ...OUTPUT_FLAGS,
    },
  },
  {
    name: "status",
    summary: "Show which phases of a run completed, and what each produced.",
    positionals: [RUN_DIR_POSITIONAL],
    flags: { ...OUTPUT_FLAGS },
  },
  {
    name: "report",
    summary: "Re-render the report from an existing run's artifacts, spending no AI.",
    positionals: [RUN_DIR_POSITIONAL],
    flags: {
      format: {
        kind: "string",
        placeholder: "fmt",
        description: `Which files to render: ${REPORT_FORMATS.join(" | ")} (default all)`,
      },
      out: {
        kind: "string",
        short: "o",
        placeholder: "dir",
        description: "Write the rendered files here instead of into the run directory",
      },
      triage: {
        kind: "string",
        placeholder: "file",
        description:
          "Apply a reviewer's verdicts: writes findings.triaged.json beside findings.json and states what the review changed",
      },
      brief: {
        kind: "boolean",
        description:
          "Also write report-brief.pdf and report-brief.md: every critical and high in full, everything below as counts",
      },
      ...OUTPUT_FLAGS,
    },
  },
];

/** Look up a verb by name. */
export function findCommandSpec(name: string): CommandSpec | undefined {
  return COMMAND_SPECS.find((spec) => spec.name === name);
}

/** The root `sentinel --help` page. */
export function renderRootHelp(version = SENTINEL_VERSION): string {
  const width = COMMAND_SPECS.reduce((max, spec) => Math.max(max, spec.name.length), 0);
  const commands = COMMAND_SPECS.map((spec) => `  ${spec.name.padEnd(width)}  ${spec.summary}`);
  const globals = renderFlagLines({
    help: { kind: "boolean", short: "h", description: "Show help for a command" },
    version: { kind: "boolean", helpName: "--version", description: "Print the Sentinel version" },
  });
  return [
    `Sentinel ${version} — a backend dossier for Node.js/TypeScript repositories.`,
    "",
    "Usage: sentinel <command> [options]",
    "",
    "Commands:",
    ...commands,
    "",
    "Global options:",
    ...globals,
    "",
    "Run `sentinel <command> --help` for the flags of one command.",
    "",
  ].join("\n");
}

/** Default context: the real process, the real clock, real randomness. */
export function defaultContext(): CliContext {
  return {
    write: (text: string) => {
      process.stdout.write(text);
    },
    writeError: (text: string) => {
      process.stderr.write(text);
    },
    cwd: process.cwd(),
    env: process.env,
    clock: createSystemClock(),
    random: cryptoRandom,
    version: SENTINEL_VERSION,
  };
}

/** Mutable view of an options object, used while collecting optional flags. */
type Writable<T> = { -readonly [K in keyof T]: T[K] };

/** Read the three reporting flags. */
function outputFlags(args: ParsedArgs): OutputFlags {
  return {
    json: flagBoolean(args, "json"),
    verbose: flagBoolean(args, "verbose"),
    quiet: flagBoolean(args, "quiet"),
  };
}

/** Collect the analyze flags that were actually provided, so config can fill the rest. */
export function analyzeFlagOverrides(args: ParsedArgs): AnalyzeFlagOverrides {
  const overrides: Writable<AnalyzeFlagOverrides> = {};
  const out = flagString(args, "out");
  if (out !== undefined) overrides.out = out;
  // `--path` replaces the config file's list rather than extending it, so an
  // empty `--path=` is a usage error rather than a silent widening: absent
  // means "whatever the config says", and present means "exactly this".
  if (flagProvided(args, "path")) overrides.path = flagList(args, "path");
  const include = flagList(args, "include");
  if (include.length > 0) overrides.include = include;
  const exclude = flagList(args, "exclude");
  if (exclude.length > 0) overrides.exclude = exclude;
  if (flagProvided(args, "propose-only")) overrides.proposeOnly = flagBoolean(args, "propose-only");
  if (flagProvided(args, "yes")) overrides.yes = flagBoolean(args, "yes");
  if (flagProvided(args, "ai")) overrides.ai = flagBoolean(args, "ai", true);
  const maxParallel = flagNumber(args, "max-parallel");
  if (maxParallel !== undefined) overrides.maxParallel = maxParallel;
  const maxBatches = flagNumber(args, "max-batches");
  if (maxBatches !== undefined) overrides.maxBatches = maxBatches;
  const maxUnits = flagNumber(args, "max-units");
  if (maxUnits !== undefined) overrides.maxUnits = maxUnits;
  const maxAuditMinutes = flagNumber(args, "max-audit-minutes");
  if (maxAuditMinutes !== undefined) overrides.maxAuditMinutes = maxAuditMinutes;
  // `--no-budget` is the only way this flag is given, so its presence means the
  // ceilings are off; `--budget` on its own is accepted and means the default.
  if (flagProvided(args, "budget")) overrides.noBudget = !flagBoolean(args, "budget", true);
  if (flagProvided(args, "save-scope")) overrides.saveScope = flagBoolean(args, "save-scope");
  if (flagProvided(args, "skip-scan")) overrides.skipScan = flagBoolean(args, "skip-scan");
  if (flagProvided(args, "pdf")) overrides.pdf = flagBoolean(args, "pdf", true);
  const output = outputFlags(args);
  overrides.json = output.json;
  overrides.verbose = output.verbose;
  overrides.quiet = output.quiet;
  return overrides;
}

/** Print a usage error the way a shell user expects, and return exit code 64. */
function reportUsageError(context: CliContext, error: UsageError): number {
  context.writeError(`sentinel: ${error.message}\n`);
  const hint = error.command === undefined ? "sentinel --help" : `sentinel ${error.command} --help`;
  context.writeError(`Run \`${hint}\` for usage.\n`);
  return EXIT.usage;
}

/** The usage error all three run-directory verbs share. */
function missingRunDir(context: CliContext, command: string): number {
  return reportUsageError(context, {
    kind: "missing-positional",
    message: `${command} requires <run-dir>`,
    command,
  });
}

/**
 * Run the real `analyze`. Loaded on demand, like `doctor`, and handed the four
 * things it refuses to reach for itself: the filesystem port, the tool
 * resolver's view of what is installed, phase 1 with the ports *it* needs, and
 * — only when a human is actually at the terminal — a way to ask them about
 * the scope proposals.
 *
 * The tool resolver is built once and shared, so the scope proposal and the
 * scan can never disagree about which analyzers exist. Both accept a binary
 * found on PATH, matching what `sentinel doctor` reports; refusing it in one
 * place and accepting it in the other would let a run offer a check and then
 * silently skip it.
 */
async function defaultAnalyzeHandler(
  context: CliContext,
  invocation: AnalyzeInvocation,
): Promise<number> {
  const [analyze, fileSystem, ask] = await Promise.all([
    import("./analyze.ts"),
    import("../ports/file-system.ts"),
    import("./_shared/ask.ts"),
  ]);
  const fs = fileSystem.createFileSystem();
  const interactive = process.stdin.isTTY === true && process.stdout.isTTY === true;

  let resolver: Promise<ToolResolver> | undefined;
  const toolResolver = (): Promise<ToolResolver> => {
    resolver ??= (async () => {
      const [resolve, installer] = await Promise.all([
        import("../tools/resolve.ts"),
        import("../tools/installer.ts"),
      ]);
      return resolve.createToolResolver({ lock: await installer.readToolsLock(), fs });
    })();
    return resolver;
  };

  /**
   * One logger for every phase: structured lines on stderr, quiet by default.
   * The tables on stdout are what a human reads; `SENTINEL_LOG=debug` is what a
   * bug report needs.
   */
  const buildLogger = async (): Promise<Logger> => {
    const logging = await import("../ports/logger.ts");
    return logging.createJsonLogger({
      level: logging.parseLogThreshold(
        context.env.SENTINEL_LOG,
        invocation.flags.verbose === true ? "info" : "warn",
      ),
      write: (line: string) => {
        context.writeError(`${line}\n`);
      },
    });
  };

  /**
   * Runs `work` with Ctrl-C wired to an abort signal.
   *
   * Every long phase takes the same treatment: the scan turns an abort into
   * `killAll` on the process port, phase 2 forwards it to ast-grep, and phase 4
   * forwards it to every in-flight agent dispatch. The handlers are removed
   * afterwards so three phases in one run do not stack three listeners.
   */
  const withCancellation = async <T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> => {
    const controller = new AbortController();
    const onSignal = (): void => controller.abort();
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
    try {
      return await work(controller.signal);
    } finally {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
    }
  };

  return analyze.analyzeCommand(context, invocation, {
    fs,
    availableTools: async () => {
      // A missing or unreadable lockfile means "nothing is installed", not a
      // failed run: every tool-dependent proposal then defaults off and says so.
      try {
        const statuses = await (await toolResolver()).statusAll({ allowPath: true });
        return statuses.filter((status) => status.path !== null).map((status) => status.name);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        context.writeError(`sentinel: could not read the pinned tool list (${message})\n`);
        return [];
      }
    },
    scan: async (request) => {
      const [scan, processExecutor, logger] = await Promise.all([
        import("../scan/scan.ts"),
        import("../ports/process-executor.ts"),
        buildLogger(),
      ]);
      const tools = await toolResolver();
      const exec = processExecutor.createProcessExecutor();
      // Ctrl-C has to reach the analyzers themselves; the scan turns an abort
      // into `killAll` on the process port, which signals each process group.
      return await withCancellation((signal) =>
        scan.runScan(
          {
            fs,
            exec,
            tools,
            targetDir: request.targetDir,
            runDir: request.runDir,
            runId: request.runId,
            profile: request.profile,
            logger,
            signal,
            allowPathTools: true,
          },
          // The scope is passed, not applied: every analyzer here reasons about
          // a repository-level artifact, so phase 1 reads all of it and counts
          // how much of what it found lies outside the analysed subtree.
          { domains: request.domains, scope: request.paths },
        ),
      );
    },
    /**
     * Phase 2. Writes `inventory.json` and, when the repository has a schema to
     * reconstruct, `schema-model.json` beside it — which is the file phase 3
     * reads to give the data-layer prompts their schema excerpt.
     */
    inventory: async (request) => {
      const [inventory, processExecutor] = await Promise.all([
        import("../inventory/inventory.ts"),
        import("../ports/process-executor.ts"),
      ]);
      const tools = await toolResolver();
      const exec = processExecutor.createProcessExecutor();
      const result = await withCancellation((signal) =>
        inventory.runInventory({
          fs,
          exec,
          tools,
          targetDir: request.targetDir,
          runDir: request.runDir,
          runId: request.runId,
          profile: request.profile,
          allowPathTools: true,
          signal,
        }),
      );
      return {
        document: result.document,
        artifacts: result.artifacts,
        durationMs: result.durationMs,
      };
    },
    /**
     * Phases 3 and 4.
     *
     * The planner is built once so its last plan can be read back: phase 4's
     * planner seam returns batches only, and the units phase 3 chose not to
     * batch — a kind no model audits, a citation that no longer resolves — are
     * needed for the summary. `shown` is the exact gate: the lines each prompt
     * actually printed, parsed out of the slicer's own gutter, so a citation to
     * an elided line is refused the same way an invented file is.
     */
    audit: async (request) => {
      const [audit, batch, verdict, agents, logger] = await Promise.all([
        import("../audit/audit.ts"),
        import("../audit/batch.ts"),
        import("../audit/verdict.ts"),
        import("../agents/index.ts"),
        buildLogger(),
      ]);
      // The planner gets the run-level ceilings because that is where the
      // risk ordering and the deferral list are produced; `runAudit` gets the
      // clock. Both halves come from the same resolved budget, so the bound the
      // dossier prints cannot disagree with the one the loop enforced.
      const planner = batch.createBatchPlanner({ spend: request.budget });
      const ranges = new Map<string, CitedRanges>();
      return await withCancellation(async (signal) => {
        const runtime = agents.createClaudeAgentRuntime({
          fs,
          runDir: request.runDir,
          concurrency: request.maxParallel,
          logger,
          signal,
        });
        const result = await audit.runAudit(
          {
            fs,
            targetDir: request.targetDir,
            runDir: request.runDir,
            runId: request.runId,
            profile: request.profile,
            logger,
            signal,
          },
          {
            runtime,
            verdicts: verdict.verdictSource(),
            batches: planner,
            prompt: batch.buildPrompt,
            units: request.units,
            domains: request.domains,
            maxWallClockMs: request.budget.maxWallClockMs,
            ...(request.progress === undefined ? {} : { progress: request.progress }),
            shown: (dispatched) => {
              let own = ranges.get(dispatched.id);
              if (own === undefined) {
                const planned = planner
                  .plan()
                  ?.batches.find((candidate) => candidate.id === dispatched.id);
                if (planned !== undefined) {
                  own = batch.citedRanges(planned);
                  ranges.set(dispatched.id, own);
                }
              }
              const index = own;
              // A batch the planner cannot be matched to falls back to the
              // extent gate `runAudit` applies anyway; it is never opened up.
              return index === undefined
                ? () => true
                : (file, line) => batch.wasShown(index, file, line);
            },
          },
        );
        return { result, plan: planner.plan() };
      });
    },
    ...(interactive
      ? { ask: ask.createAsker(ask.createLineReader(process.stdin), context.write) }
      : {}),
  });
}

/**
 * Run the real `setup`. The installer gets `fetch` injected like every other
 * port, so nothing below this line reaches the network on its own.
 */
async function defaultSetupHandler(
  context: CliContext,
  invocation: SetupInvocation,
): Promise<number> {
  const [setup, fileSystem, processExecutor, installer] = await Promise.all([
    import("./setup.ts"),
    import("../ports/file-system.ts"),
    import("../ports/process-executor.ts"),
    import("../tools/installer.ts"),
  ]);
  const fs = fileSystem.createFileSystem();
  const exec = processExecutor.createProcessExecutor();
  return setup.setupCommand(context, invocation, {
    fs,
    exec: { run: (command, args, options) => exec.run(command, args ?? [], options) },
    fetch: (url, init) => fetch(url, init),
    lock: await installer.readToolsLock(),
  });
}

/**
 * Run the real `doctor`. It is loaded on demand — and given the ports it needs
 * here, at the composition root — so the rest of the CLI neither imports the
 * preflight nor pays for its module graph on every other verb.
 */
async function defaultDoctorHandler(context: CliContext, argv: readonly string[]): Promise<number> {
  const [doctor, fileSystem, processExecutor] = await Promise.all([
    import("./doctor.ts"),
    import("../ports/file-system.ts"),
    import("../ports/process-executor.ts"),
  ]);
  const fs = fileSystem.createFileSystem();
  return doctor.doctorCommand(argv, {
    cwd: context.cwd,
    fs: {
      exists: (path: string) => fs.exists(path),
      isDirectory: async (path: string) => (await fs.stat(path))?.isDirectory ?? false,
      listDirectory: async (path: string) => (await fs.readDir(path)).map((entry) => entry.name),
      ensureDirectory: (path: string) => fs.mkdirp(path),
      writeFile: (path: string, contents: string) => fs.writeFile(path, contents),
      remove: (path: string) => fs.remove(path),
    },
    proc: processExecutor.createProcessExecutor(),
    stdout: context.write,
    stderr: context.writeError,
    bunVersion: Bun.version,
  });
}

/**
 * Run the real `report`. It gets the filesystem port and nothing else: phase 7
 * reads a run directory and writes three files, and a verb that cannot reach a
 * process executor, a tool resolver or an agent runtime cannot accidentally
 * spend anything.
 */
async function defaultReportHandler(
  context: CliContext,
  invocation: ReportInvocation,
): Promise<number> {
  const [report, fileSystem] = await Promise.all([
    import("./report.ts"),
    import("../ports/file-system.ts"),
  ]);
  return report.reportCommand(context, invocation, { fs: fileSystem.createFileSystem() });
}

/** Run the real `status`. Read-only, like `report`, and for the same reason. */
async function defaultStatusHandler(
  context: CliContext,
  invocation: StatusInvocation,
): Promise<number> {
  const [status, fileSystem] = await Promise.all([
    import("./status.ts"),
    import("../ports/file-system.ts"),
  ]);
  return status.statusCommand(context, invocation, { fs: fileSystem.createFileSystem() });
}

/**
 * Run the real `resume`.
 *
 * Unlike the other two, this verb can re-enter any phase, so it needs every port
 * `analyze` needs. They are built in `src/cli/_resume/runners.ts` — one runner
 * per phase, each created lazily — so a resume that only renders the report
 * never constructs an agent runtime.
 */
async function defaultResumeHandler(
  context: CliContext,
  invocation: ResumeInvocation,
): Promise<number> {
  const [resume, runners, fileSystem] = await Promise.all([
    import("./resume.ts"),
    import("./_resume/runners.ts"),
    import("../ports/file-system.ts"),
  ]);
  return resume.resumeCommand(context, invocation, {
    fs: fileSystem.createFileSystem(),
    runners: runners.createResumeRunners(context, {
      verbose: invocation.output.verbose,
      quiet: invocation.output.quiet,
      json: invocation.output.json,
      ...(invocation.maxParallel === undefined ? {} : { defaultParallel: invocation.maxParallel }),
    }),
  });
}

/** Parse `argv` (without the program name), dispatch, and return an exit code. */
export async function runCli(
  argv: readonly string[],
  options: RunCliOptions = {},
): Promise<number> {
  const context: CliContext = { ...defaultContext(), ...options.context };
  const handlers = options.handlers ?? {};
  const doctor = handlers.doctor ?? defaultDoctorHandler;

  const first = argv[0];
  if (first === undefined) {
    context.writeError(renderRootHelp(context.version));
    return EXIT.usage;
  }

  if (first === "--version" || first === "-V") {
    context.write(`${context.version}\n`);
    return EXIT.ok;
  }

  if (first === "--help" || first === "-h" || first === "help") {
    const topic = argv[1];
    // Doctor prints its own usage, so the two can never drift apart.
    if (topic === "doctor") return doctor(context, ["--help"]);
    const spec = topic === undefined ? undefined : findCommandSpec(topic);
    context.write(spec === undefined ? renderRootHelp(context.version) : renderCommandHelp(spec));
    return EXIT.ok;
  }

  if (first.startsWith("-")) {
    return reportUsageError(context, { kind: "unknown-flag", message: `unknown flag "${first}"` });
  }

  const spec = findCommandSpec(first);
  if (spec === undefined) {
    return reportUsageError(context, {
      kind: "unknown-command",
      message: `unknown command "${first}"`,
    });
  }

  const rest = argv.slice(1);
  try {
    // `doctor` parses its own argv; everything else goes through the shared parser.
    if (spec.name === "doctor") return await doctor(context, rest);

    const parsed = parseArgs(spec, rest);
    if (!parsed.ok) return reportUsageError(context, parsed.error);
    const args = parsed.value;

    if (flagBoolean(args, "help")) {
      context.write(renderCommandHelp(spec));
      return EXIT.ok;
    }

    const output = outputFlags(args);
    if (output.verbose && output.quiet) {
      return reportUsageError(context, {
        kind: "conflicting-flags",
        message: "--verbose and --quiet cannot be combined",
        command: spec.name,
      });
    }

    return await dispatch(context, handlers, spec.name, args, output);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    context.writeError(`sentinel: ${spec.name} failed: ${message}\n`);
    const stack = error instanceof Error ? error.stack : undefined;
    if (stack !== undefined && argv.includes("--verbose")) context.writeError(`${stack}\n`);
    return EXIT.failure;
  }
}

/** Route one parsed command line to its handler. */
async function dispatch(
  context: CliContext,
  handlers: Partial<CommandHandlers>,
  command: string,
  args: ParsedArgs,
  output: OutputFlags,
): Promise<number> {
  switch (command) {
    case "analyze": {
      const target = args.positionals[0];
      if (target === undefined || target.trim().length === 0) {
        return reportUsageError(context, {
          kind: "missing-positional",
          message: "analyze requires <target>",
          command,
        });
      }
      const maxParallel = flagNumber(args, "max-parallel");
      if (maxParallel !== undefined && maxParallel < 1) {
        return reportUsageError(context, {
          kind: "invalid-value",
          message: "--max-parallel must be at least 1",
          command,
        });
      }
      const invocation: AnalyzeInvocation = {
        target: resolve(context.cwd, target),
        cwd: context.cwd,
        flags: analyzeFlagOverrides(args),
      };
      const handler = handlers.analyze ?? defaultAnalyzeHandler;
      return handler(context, invocation);
    }
    case "setup": {
      const invocation: Writable<SetupInvocation> = { force: flagBoolean(args, "force"), output };
      const only = flagString(args, "only");
      if (only !== undefined) invocation.only = only;
      const handler = handlers.setup ?? defaultSetupHandler;
      return handler(context, invocation);
    }
    case "status": {
      const runDir = args.positionals[0];
      if (runDir === undefined || runDir.trim().length === 0)
        return missingRunDir(context, command);
      const invocation: StatusInvocation = { runDir, cwd: context.cwd, output };
      const handler = handlers.status ?? defaultStatusHandler;
      return handler(context, invocation);
    }
    case "report": {
      const runDir = args.positionals[0];
      if (runDir === undefined || runDir.trim().length === 0)
        return missingRunDir(context, command);
      const raw = flagString(args, "format") ?? "all";
      if (!(REPORT_FORMATS as readonly string[]).includes(raw)) {
        return reportUsageError(context, {
          kind: "invalid-value",
          message: `--format must be one of ${REPORT_FORMATS.join(", ")}`,
          command,
        });
      }
      const invocation: Writable<ReportInvocation> = {
        runDir,
        cwd: context.cwd,
        output,
        format: raw as ReportFormat,
      };
      const out = flagString(args, "out");
      if (out !== undefined) invocation.out = out;
      const triage = flagString(args, "triage");
      // An empty `--triage=` is a usage error rather than a silent raw render: a
      // reviewer who asked for their verdicts to be applied must never be handed
      // a dossier that ignored them.
      if (flagProvided(args, "triage") && (triage === undefined || triage.trim() === "")) {
        return reportUsageError(context, {
          kind: "invalid-value",
          message: "--triage needs the path of a triage file",
          command,
        });
      }
      if (triage !== undefined) invocation.triage = triage;
      // `--brief` adds a document; `--format brief` asks for that document alone.
      // Both are recorded, so `--format brief` needs no second flag to work.
      if (flagProvided(args, "brief")) invocation.brief = flagBoolean(args, "brief");
      const handler = handlers.report ?? defaultReportHandler;
      return handler(context, invocation);
    }
    case "resume": {
      const runDir = args.positionals[0];
      if (runDir === undefined || runDir.trim().length === 0)
        return missingRunDir(context, command);
      const phase = flagString(args, "force-phase");
      if (phase !== undefined && !(RESUMABLE_PHASES as readonly string[]).includes(phase)) {
        return reportUsageError(context, {
          kind: "invalid-value",
          message: `--force-phase must name a phase: ${RESUMABLE_PHASES.join(", ")}`,
          command,
        });
      }
      const maxParallel = flagNumber(args, "max-parallel");
      if (maxParallel !== undefined && maxParallel < 1) {
        return reportUsageError(context, {
          kind: "invalid-value",
          message: "--max-parallel must be at least 1",
          command,
        });
      }
      const invocation: Writable<ResumeInvocation> = {
        runDir,
        cwd: context.cwd,
        output,
        retryFailed: flagBoolean(args, "retry-failed"),
      };
      if (phase !== undefined) invocation.forcePhase = phase as RunPhaseName;
      if (maxParallel !== undefined) invocation.maxParallel = maxParallel;
      const handler = handlers.resume ?? defaultResumeHandler;
      return handler(context, invocation);
    }
    default:
      return reportUsageError(context, {
        kind: "unknown-command",
        message: `unknown command "${command}"`,
      });
  }
}

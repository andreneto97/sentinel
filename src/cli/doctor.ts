import { join, resolve as resolvePath } from "node:path";
import {
  DOCTOR_EXIT_BLOCKED,
  DOCTOR_EXIT_OK,
  type DoctorCheck,
  type DoctorReport,
  type DoctorStatus,
  type DoctorTier,
  doctorExitCode,
} from "../contracts/doctor.ts";
import {
  type DoctorFileSystemPort,
  type DoctorProcessPort,
  type ToolProbe,
  runDoctor,
} from "../tools/doctor.ts";

/** Parsed `sentinel doctor` invocation. */
export interface DoctorCliOptions {
  readonly target: string;
  readonly outputDir: string;
  readonly json: boolean;
  readonly help: boolean;
}

/** Either the parsed options or the usage error to print. */
export type DoctorArgsResult =
  | { readonly ok: true; readonly value: DoctorCliOptions }
  | { readonly ok: false; readonly error: string };

/** Ports and sinks the command needs; nothing is reached for directly. */
export interface DoctorCliDeps {
  readonly cwd: string;
  readonly fs: DoctorFileSystemPort;
  readonly proc: DoctorProcessPort;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly tools?: ToolProbe | undefined;
  readonly cacheDir?: string | undefined;
  readonly bunVersion?: string | undefined;
  readonly now?: (() => Date) | undefined;
  readonly probeNetwork?: (() => Promise<boolean>) | undefined;
}

/** Help text for `sentinel doctor`. */
export const DOCTOR_USAGE = `Usage: sentinel doctor [target] [options]

Checks everything an analysis needs before it starts: the runtime, the target,
the output directory, every pinned analysis tool, and what coverage is lost for
each tool that is missing.

Arguments:
  target            Repository to analyse (default: the current directory)

Options:
  --out <dir>       Output directory to test for writability
                    (default: <target>/sentinel)
  --json            Print the machine-readable report instead of the table
  -h, --help        Show this help

Exit codes:
  0                 Ready; warnings may still reduce coverage
  2                 A required check failed, or the arguments were invalid`;

/** Parses argv (without the runtime and script), resolving paths against `cwd`. */
export function parseDoctorArgs(argv: readonly string[], cwd: string): DoctorArgsResult {
  let target: string | null = null;
  let outputDir: string | null = null;
  let json = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index] ?? "";
    if (argument === "-h" || argument === "--help") {
      return {
        ok: true,
        value: { target: cwd, outputDir: join(cwd, "sentinel"), json, help: true },
      };
    }
    if (argument === "--json") {
      json = true;
      continue;
    }
    if (argument === "--out" || argument === "-o") {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("-")) {
        return { ok: false, error: "--out needs a directory" };
      }
      outputDir = value;
      index += 1;
      continue;
    }
    if (argument.startsWith("--out=")) {
      const value = argument.slice("--out=".length);
      if (value.length === 0) {
        return { ok: false, error: "--out needs a directory" };
      }
      outputDir = value;
      continue;
    }
    if (argument.startsWith("-")) {
      return { ok: false, error: `unknown option: ${argument}` };
    }
    if (target !== null) {
      return { ok: false, error: `unexpected extra argument: ${argument}` };
    }
    target = argument;
  }

  const resolvedTarget = resolvePath(cwd, target ?? ".");
  return {
    ok: true,
    value: {
      target: resolvedTarget,
      outputDir:
        outputDir === null ? join(resolvedTarget, "sentinel") : resolvePath(cwd, outputDir),
      json,
      help: false,
    },
  };
}

const TIER_TITLES: Readonly<Record<DoctorTier, string>> = {
  required: "REQUIRED",
  tools: "ANALYSIS TOOLS",
  optional: "OPTIONAL",
};

const TIER_ORDER: readonly DoctorTier[] = ["required", "tools", "optional"];

const LINE_WIDTH = 96;

/** Fixed-width status marker; words, not colour, so piped output stays readable. */
function statusTag(status: DoctorStatus): string {
  if (status === "ok") {
    return "[ ok ]";
  }
  return status === "warn" ? "[warn]" : "[fail]";
}

/** Greedy word wrap; long unbreakable tokens are allowed to overflow. */
function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  let current = "";
  for (const word of text.split(/\s+/).filter((part) => part.length > 0)) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + 1 + word.length <= width) {
      current = `${current} ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current.length > 0) {
    lines.push(current);
  }
  return lines.length > 0 ? lines : [""];
}

/** Renders one check as its status line plus any wrapped detail and hint lines. */
function renderCheck(item: DoctorCheck, labelWidth: number): string[] {
  const head = `  ${statusTag(item.status)}  ${item.label.padEnd(labelWidth)}  `;
  const continuation = " ".repeat(head.length);
  const detailWidth = Math.max(24, LINE_WIDTH - head.length);
  const lines = wrap(item.detail, detailWidth).map((line, position) =>
    position === 0 ? `${head}${line}` : `${continuation}${line}`,
  );
  if (item.remediation !== undefined) {
    const hint = wrap(`fix: ${item.remediation}`, detailWidth);
    for (const line of hint) {
      lines.push(`${continuation}${line}`);
    }
  }
  return lines;
}

/** Plural helper for the summary line. */
function count(value: number, singular: string): string {
  return `${value} ${value === 1 ? singular : `${singular}s`}`;
}

/** Renders the report as the table `sentinel doctor` prints without `--json`. */
export function renderDoctorReport(report: DoctorReport): string {
  const labelWidth = Math.min(
    24,
    report.checks.reduce((widest, item) => Math.max(widest, item.label.length), 0),
  );
  const lines: string[] = [
    "Sentinel doctor",
    `  target   ${report.target}`,
    `  output   ${report.outputDir}`,
    `  tools    ${report.cacheDir}`,
    `  runtime  bun ${report.environment.bunVersion} on ${report.environment.platform}/${report.environment.arch}`,
  ];

  for (const tier of TIER_ORDER) {
    const tierChecks = report.checks.filter((item) => item.tier === tier);
    if (tierChecks.length === 0) {
      continue;
    }
    lines.push("", TIER_TITLES[tier]);
    for (const item of tierChecks) {
      lines.push(...renderCheck(item, labelWidth));
    }
  }

  if (report.coverageLoss.length > 0) {
    lines.push("", "COVERAGE LOST");
    for (const loss of report.coverageLoss) {
      const wrapped = wrap(loss.sentence, LINE_WIDTH - 4);
      lines.push(
        ...wrapped.map((line, position) => (position === 0 ? `  - ${line}` : `    ${line}`)),
      );
    }
  }

  const { ok, warn, fail } = report.summary;
  lines.push(
    "",
    `${count(ok, "check")} ok, ${count(warn, "warning")}, ${count(fail, "failure")}.`,
    report.ready
      ? "Ready to analyse. Coverage is reduced wherever a warning says so."
      : "Not ready: fix the required checks above before running an analysis.",
  );
  return lines.join("\n");
}

/**
 * Runs the preflight and prints it; returns the exit code instead of calling
 * `process.exit`, so the CLI entry point owns process lifetime and tests do not
 * have to fork.
 */
export async function doctorCommand(argv: readonly string[], deps: DoctorCliDeps): Promise<number> {
  const parsed = parseDoctorArgs(argv, deps.cwd);
  if (!parsed.ok) {
    deps.stderr(`sentinel doctor: ${parsed.error}\n\n${DOCTOR_USAGE}`);
    return DOCTOR_EXIT_BLOCKED;
  }
  if (parsed.value.help) {
    deps.stdout(DOCTOR_USAGE);
    return DOCTOR_EXIT_OK;
  }

  const report = await runDoctor({
    target: parsed.value.target,
    outputDir: parsed.value.outputDir,
    fs: deps.fs,
    proc: deps.proc,
    tools: deps.tools,
    cacheDir: deps.cacheDir,
    bunVersion: deps.bunVersion,
    now: deps.now,
    probeNetwork: deps.probeNetwork,
  });

  deps.stdout(parsed.value.json ? JSON.stringify(report, null, 2) : renderDoctorReport(report));
  return doctorExitCode(report);
}

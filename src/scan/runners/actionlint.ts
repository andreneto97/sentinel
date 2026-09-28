/**
 * Phase 1 runner for actionlint — GitHub Actions workflow linting for the
 * delivery domain.
 *
 * actionlint has no severity of its own, only a `kind`, so the kind drives both
 * the rule id (`delivery.workflow.expression`) and the severity, with the
 * script-injection warnings promoted: they are the one class of actionlint
 * finding that is an exploitable vulnerability rather than a defect.
 */

import { z } from "zod";
import type { Finding, Severity } from "../../contracts/findings.ts";
import { workflowFilesOf } from "../_delivery-files.ts";
import { type ParseOutcome, parseJsonWith } from "../parsers/_parse-outcome.ts";
import type { StepOutcome } from "../types.ts";
import {
  type RunnerContext,
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
export const ACTIONLINT_STEP = "actionlint";

/** Lockfile name in `tools.lock.json`; the resolver maps it to the pinned binary. */
export const ACTIONLINT_TOOL = "actionlint";

/** Rule ids keep actionlint's `kind` as the leaf: the closest thing it has to a rule id. */
const RULE_PREFIX = "delivery.workflow";

/** Linting a handful of YAML files is fast; a minute is already generous. */
export const ACTIONLINT_DEFAULT_TIMEOUT_MS = 120_000;

/** Workflows per invocation; keeps argv well inside every platform's limit. */
const MAX_FILES_PER_INVOCATION = 100;

/** Exit statuses that still mean "actionlint ran": 0 = clean, 1 = problems found. */
const RAN_EXIT_CODES: readonly number[] = [0, 1];

/**
 * One actionlint error, as `-format '{{json .}}'` prints it. Non-strict: a
 * future actionlint may add fields, which is not a reason to lose the scan.
 */
const ActionlintErrorSchema = z.object({
  message: z.string(),
  filepath: z.string().min(1),
  line: z.number().int(),
  column: z.number().int(),
  kind: z.string(),
  /** actionlint's own excerpt with a caret ruler; context only, never a snippet. */
  snippet: z.string().optional(),
  end_column: z.number().int().optional(),
});
/** One actionlint error, as the tool prints it. */
export type ActionlintError = z.infer<typeof ActionlintErrorSchema>;

/** actionlint's payload: a flat array across every workflow it was given. */
export const ActionlintReportSchema = z.array(ActionlintErrorSchema);
/** Every error of one actionlint invocation. */
export type ActionlintReport = z.infer<typeof ActionlintReportSchema>;

/** Validates actionlint's stdout; a usage error comes back as `ok: false`. */
export function parseActionlintReport(raw: string): ParseOutcome<ActionlintReport> {
  return parseJsonWith(raw, ActionlintReportSchema, "actionlint");
}

/**
 * Severity by kind. actionlint reports only real errors, so the scale runs from
 * "this workflow does not do what it reads as" (medium) down to style (low);
 * `credentials` and untrusted-input expressions are the security findings.
 */
const KIND_SEVERITY: Readonly<Record<string, Severity>> = {
  credentials: "high",
  action: "medium",
  "env-var": "medium",
  events: "medium",
  expression: "medium",
  "job-needs": "medium",
  matrix: "medium",
  permissions: "medium",
  "syntax-check": "medium",
  "webhook-event": "medium",
  "workflow-call": "medium",
  "deprecated-commands": "low",
  glob: "low",
  id: "low",
  pyflakes: "low",
  "runner-label": "low",
  shellcheck: "low",
};

/** Unknown kinds land here: reported, but never louder than what is understood. */
const DEFAULT_SEVERITY: Severity = "low";

/** actionlint's wording for "an attacker controls this value". */
const UNTRUSTED_MARKER = "is potentially untrusted";

/** True when the error is actionlint's script-injection warning. */
export function isUntrustedInput(error: ActionlintError): boolean {
  return error.kind === "expression" && error.message.includes(UNTRUSTED_MARKER);
}

/** Maps an actionlint error onto Sentinel's severity scale. */
export function severityOf(error: ActionlintError): Severity {
  if (isUntrustedInput(error)) return "high";
  return KIND_SEVERITY[error.kind] ?? DEFAULT_SEVERITY;
}

/** Pulls the `SC####` code out of a shellcheck-forwarded message, when there is one. */
function shellcheckCode(message: string): string | null {
  return /\b(SC\d{4})\b/.exec(message)?.[1] ?? null;
}

/** The rule id for an error: the kind, refined by the shellcheck code when present. */
export function ruleOf(error: ActionlintError): string {
  if (isUntrustedInput(error)) return `${RULE_PREFIX}.script-injection`;
  if (error.kind === "shellcheck") {
    const code = shellcheckCode(error.message);
    if (code !== null) return `${RULE_PREFIX}.shellcheck.${code}`;
  }
  return `${RULE_PREFIX}.${error.kind}`;
}

/** The expression actionlint named, e.g. `github.event.pull_request.title`. */
function quotedSubject(message: string): string | null {
  return /"([^"]+)"/.exec(message)?.[1] ?? null;
}

/** First sentence of an actionlint message, for a title that fits a table row. */
function firstSentence(message: string): string {
  const collapsed = message.replace(/\s+/g, " ").trim();
  const stop = collapsed.search(/\.(\s|$)/);
  const head = stop === -1 ? collapsed : collapsed.slice(0, stop);
  return head.length <= 110 ? head : `${head.slice(0, 109).trimEnd()}...`;
}

/** The consequence of an error; actionlint states the problem, not its impact. */
function impactOf(error: ActionlintError): string {
  if (isUntrustedInput(error)) {
    const subject = quotedSubject(error.message) ?? "an attacker-controlled context value";
    return `${subject} is interpolated into the shell command before it runs, so whoever sets that value runs arbitrary commands on the runner — with every secret and token the job holds.`;
  }
  switch (error.kind) {
    case "credentials":
      return "A credential is written into the workflow file, so it is readable by everyone with repository access and it survives in git history after any rotation.";
    case "permissions":
      return "The job's GITHUB_TOKEN carries more authority than the job needs, widening what a compromised step or action can do to the repository.";
    case "syntax-check":
      return "GitHub cannot run this workflow as written, so the checks it is supposed to enforce silently do not run.";
    case "action":
      return "The step passes inputs the action does not declare, so the step does not do what the workflow reads as doing.";
    case "runner-label":
      return "No runner matches this label, so the job queues indefinitely instead of failing loudly.";
    case "deprecated-commands":
      return "The workflow command has been removed from the runner, so the step will stop working without any code change.";
    default:
      return "actionlint rejects this workflow, so the pipeline does not behave the way the file reads.";
  }
}

/** The fix. Falls back to actionlint's own wording, which usually is the fix. */
function recommendationOf(error: ActionlintError): string {
  if (isUntrustedInput(error)) {
    const subject = quotedSubject(error.message) ?? "the untrusted value";
    return `Bind ${subject} to an \`env:\` variable on the step and reference it as a quoted shell variable, so the value is never spliced into the script text.`;
  }
  if (error.kind === "credentials") {
    return "Move the value into a repository or environment secret, reference it through the `secrets` context, and rotate the exposed credential.";
  }
  return error.message.trim().replace(/\.?$/, ".");
}

/** Turns one actionlint error into a finding, before its citation is verified. */
export function toFinding(error: ActionlintError): Finding {
  // actionlint is 1-based; the clamp keeps a malformed payload from producing a
  // citation the CodeRef contract would reject.
  const line = error.line > 0 ? error.line : 1;
  const untrusted = isUntrustedInput(error);
  return makeFinding({
    domain: "delivery",
    rule: ruleOf(error),
    severity: severityOf(error),
    confidence: "high",
    title: untrusted
      ? `Script injection: ${quotedSubject(error.message) ?? "an untrusted context"} reaches a run: block`
      : `${error.kind}: ${firstSentence(error.message)}`,
    description: `actionlint reports: ${error.message}`,
    file: error.filepath,
    line,
    symbol: `${error.kind}:${line}:${error.column}`,
    impact: impactOf(error),
    recommendation: recommendationOf(error),
    ...(untrusted
      ? {
          exploitability:
            "No credentials needed: any outside contributor who can open a pull request, file an issue or leave a comment controls the value.",
          cwe: ["CWE-94", "CWE-78"],
          owasp: ["A03:2021-Injection"],
        }
      : {}),
    ...(error.kind === "credentials" ? { cwe: ["CWE-798"] } : {}),
    acceptanceCriteria: [`actionlint reports no ${error.kind} error in ${error.filepath}`],
    source: { kind: "tool", name: ACTIONLINT_STEP },
  });
}

/** Splits the file list into invocations that fit comfortably in argv. */
function chunk(files: readonly string[], size: number): string[][] {
  const chunks: string[][] = [];
  for (let index = 0; index < files.length; index += size) {
    chunks.push([...files.slice(index, index + size)]);
  }
  return chunks;
}

/**
 * Builds the command line.
 *
 * shellcheck and pyflakes are disabled by passing an empty command name.
 * Neither is one of Sentinel's pinned tools, so leaving the integration on
 * would make the findings depend on whether the machine happens to have them
 * on PATH — the run would stop being reproducible without saying so.
 */
function actionlintArgs(files: readonly string[], shellcheck: string, pyflakes: string): string[] {
  return [
    "-format",
    "{{json .}}",
    "-no-color",
    `-shellcheck=${shellcheck}`,
    `-pyflakes=${pyflakes}`,
    ...files,
  ];
}

/** Lets the orchestrator hand in the file list, and opt the integrations back in. */
export interface ActionlintOptions {
  /** Repo-relative workflow files; defaults to the ones phase 0 proved. */
  readonly files?: readonly string[] | undefined;
  /** Path to a `shellcheck` for `run:` analysis; disabled when unset. */
  readonly shellcheckPath?: string | undefined;
  /** Path to a `pyflakes` for python `run:` steps; disabled when unset. */
  readonly pyflakesPath?: string | undefined;
}

/**
 * Runs actionlint over the target's workflows and normalises every error into
 * a verified `Finding`. A missing binary, a timeout or output that is not the
 * expected JSON all come back as a non-`ok` {@link StepOutcome}.
 */
export async function runActionlint(
  ctx: RunnerContext,
  options: ActionlintOptions = {},
): Promise<StepOutcome> {
  const startedAt = performance.now();
  const timeoutMs = ctx.timeoutMs ?? ACTIONLINT_DEFAULT_TIMEOUT_MS;
  const files = [...new Set(options.files ?? workflowFilesOf(ctx.profile))].sort();

  if (files.length === 0) {
    return skipped(ACTIONLINT_STEP, startedAt, "the target has no GitHub Actions workflow");
  }

  const binary = await ctx.tools.resolve(ACTIONLINT_TOOL, {
    allowPath: ctx.allowPathTools === true,
  });
  if (binary === null) {
    return skipped(
      ACTIONLINT_STEP,
      startedAt,
      "actionlint is not installed; run `sentinel setup` (CI coverage falls back to Sentinel's own rules)",
    );
  }

  const shellcheck = options.shellcheckPath ?? "";
  const pyflakes = options.pyflakesPath ?? "";
  const errors: ActionlintError[] = [];
  const artifacts: string[] = [];
  const notes: Array<string | null> = [];
  const batches = chunk(files, MAX_FILES_PER_INVOCATION);

  for (const [index, batch] of batches.entries()) {
    const result = await ctx.exec.run(binary, actionlintArgs(batch, shellcheck, pyflakes), {
      cwd: ctx.targetDir,
      timeoutMs,
      env: { NO_COLOR: "1" },
    });

    const suffix = batches.length === 1 ? "" : `.${index + 1}`;
    if (result.stdout !== "") {
      artifacts.push(
        await writeRaw(ctx, ACTIONLINT_STEP, `actionlint${suffix}.json`, result.stdout),
      );
    }
    if (result.stderr.trim() !== "") {
      artifacts.push(
        await writeRaw(ctx, ACTIONLINT_STEP, `actionlint${suffix}.stderr.log`, result.stderr),
      );
    }

    if (result.notFound) {
      return skipped(ACTIONLINT_STEP, startedAt, `actionlint is not executable at ${binary}`);
    }
    if (result.timedOut) {
      return failedStep(
        ACTIONLINT_STEP,
        startedAt,
        `actionlint timed out after ${timeoutMs} ms`,
        artifacts,
      );
    }
    if (result.truncated) {
      return failedStep(
        ACTIONLINT_STEP,
        startedAt,
        "actionlint output exceeded the capture limit and was truncated",
        artifacts,
      );
    }

    const stdout = result.stdout.trim();
    if (stdout === "") {
      // Exit 2 is a usage error and exit 3 a fatal one; both print to stderr only.
      return failedStep(
        ACTIONLINT_STEP,
        startedAt,
        `actionlint exited ${result.exitCode} without output: ${briefly(result.stderr, 200) || "no stderr"}`,
        artifacts,
      );
    }

    const report = parseActionlintReport(stdout);
    if (!report.ok) {
      return failedStep(ACTIONLINT_STEP, startedAt, report.error, artifacts);
    }
    if (!RAN_EXIT_CODES.includes(result.exitCode)) {
      notes.push(
        `actionlint exited ${result.exitCode} on ${batch.length} workflow(s): ${briefly(result.stderr, 120) || "no stderr"}`,
      );
    }
    errors.push(...report.value);
  }

  const verified = await verifyStepFindings(errors.map(toFinding), ctx);
  if (verified.droppedFindings > 0) {
    notes.push(
      `${verified.droppedFindings} error(s) cited a line Sentinel could not resolve on disk and were dropped`,
    );
  }

  const integrations =
    shellcheck === "" && pyflakes === ""
      ? "shellcheck and pyflakes integrations are off because neither is a pinned tool, so `run:` scripts are not shell-linted"
      : null;

  return outcome(
    ACTIONLINT_STEP,
    notes.length === 0 ? "ok" : "degraded",
    joinReasons([`${files.length} workflow(s) linted`, integrations, ...notes]),
    verified.kept,
    artifacts,
    startedAt,
  );
}

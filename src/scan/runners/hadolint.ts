/**
 * Phase 1 runner for hadolint — Dockerfile linting for the delivery domain.
 *
 * hadolint's own rule id is preserved (`delivery.dockerfile.DL3007`) so a
 * reader can look the check up upstream, and its level is mapped onto
 * Sentinel's severity scale with a small override table for the handful of
 * checks whose consequence is security rather than style.
 */

import { z } from "zod";
import type { Finding, Severity } from "../../contracts/findings.ts";
import { dockerfilesOf } from "../_delivery-files.ts";
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
export const HADOLINT_STEP = "hadolint";

/** Lockfile name in `tools.lock.json`; the resolver maps it to the pinned binary. */
export const HADOLINT_TOOL = "hadolint";

/** Rule ids are namespaced under the domain, with hadolint's code kept intact. */
const RULE_PREFIX = "delivery.dockerfile";

/** A Dockerfile lint is fast; a minute is already generous. */
export const HADOLINT_DEFAULT_TIMEOUT_MS = 120_000;

/** Dockerfiles per invocation; keeps argv well inside every platform's limit. */
const MAX_FILES_PER_INVOCATION = 100;

/**
 * One hadolint hit. Non-strict on purpose: a future hadolint may add fields,
 * and an unknown field is not a reason to lose the whole scan.
 */
const HadolintHitSchema = z.object({
  code: z.string().min(1),
  file: z.string().min(1),
  line: z.number().int(),
  column: z.number().int(),
  level: z.string(),
  message: z.string(),
});
/** One hadolint hit, as `--format json` prints it. */
export type HadolintHit = z.infer<typeof HadolintHitSchema>;

/** hadolint's payload: a flat array across every file it was given. */
export const HadolintReportSchema = z.array(HadolintHitSchema);
/** Every hit of one hadolint invocation. */
export type HadolintReport = z.infer<typeof HadolintReportSchema>;

/** Validates hadolint's stdout; a Haskell backtrace comes back as `ok: false`. */
export function parseHadolintReport(raw: string): ParseOutcome<HadolintReport> {
  return parseJsonWith(raw, HadolintReportSchema, "hadolint");
}

/** hadolint's own levels, mapped onto Sentinel's severity scale. */
const LEVEL_SEVERITY: Readonly<Record<string, Severity>> = {
  error: "high",
  warning: "medium",
  info: "low",
  style: "info",
};

/** Extra context for the checks whose consequence is security, not tidiness. */
interface CodeNote {
  /** Overrides the level mapping when the check is a security finding. */
  readonly severity?: Severity;
  readonly impact?: string;
  readonly cwe?: readonly string[];
}

/**
 * hadolint grades by style, not by blast radius. These are the checks where
 * the two disagree enough that taking the level at face value would bury a
 * real finding under the linting noise.
 */
const CODE_NOTES: Readonly<Record<string, CodeNote>> = {
  DL3002: {
    severity: "high",
    impact:
      "The container's main process runs as root, so a remote code execution in the application is root inside the container and one runtime escape away from root on the host.",
    cwe: ["CWE-250"],
  },
  DL3004: {
    severity: "medium",
    impact: "sudo inside a build layer escalates privileges in an environment that has no TTY.",
    cwe: ["CWE-250"],
  },
  DL3026: {
    severity: "high",
    impact:
      "The base image comes from a registry outside the allow-list, so the build trusts an image nobody has vetted.",
    cwe: ["CWE-1357"],
  },
  DL3064: {
    severity: "high",
    impact:
      "ARG and ENV values are recorded in the image metadata and survive in every layer, so anyone who can pull the image reads the credential.",
    cwe: ["CWE-798", "CWE-532"],
  },
  DL3007: {
    impact:
      "A floating base tag makes the build unreproducible: the same Dockerfile produces a different image tomorrow, with a different set of CVEs.",
    cwe: ["CWE-1104"],
  },
  DL3008: {
    impact:
      "Unpinned apt packages make the image unreproducible and silently pull whatever version the mirror carries at build time.",
    cwe: ["CWE-1104"],
  },
};

/** The upstream page that explains a check, which the recommendation links to. */
function wikiUrl(code: string): string {
  return code.startsWith("SC")
    ? `https://www.shellcheck.net/wiki/${code}`
    : `https://github.com/hadolint/hadolint/wiki/${code}`;
}

/** Maps a hadolint level, honouring the security overrides. */
export function severityOf(hit: HadolintHit): Severity {
  const override = CODE_NOTES[hit.code]?.severity;
  if (override !== undefined) return override;
  return LEVEL_SEVERITY[hit.level.toLowerCase()] ?? "low";
}

/** First sentence of a hadolint message, for a title that fits a table row. */
function firstSentence(message: string): string {
  const collapsed = message.replace(/\s+/g, " ").trim();
  const stop = collapsed.search(/\.(\s|$)/);
  const head = stop === -1 ? collapsed : collapsed.slice(0, stop);
  return head.length <= 110 ? head : `${head.slice(0, 109).trimEnd()}...`;
}

/** Turns one hadolint hit into a finding, before its citation is verified. */
export function toFinding(hit: HadolintHit): Finding {
  const note = CODE_NOTES[hit.code];
  // hadolint reports whole-instruction problems at column 1; a non-positive
  // line would fail the CodeRef contract, and line 1 is always a real line.
  const line = hit.line > 0 ? hit.line : 1;
  return makeFinding({
    domain: "delivery",
    rule: `${RULE_PREFIX}.${hit.code}`,
    severity: severityOf(hit),
    confidence: "high",
    title: `${hit.code}: ${firstSentence(hit.message)}`,
    description: `hadolint reports: ${hit.message}`,
    file: hit.file,
    line,
    symbol: `${hit.code}:${line}:${hit.column}`,
    impact:
      note?.impact ??
      `hadolint classifies this as ${hit.level}: it weakens the image's reproducibility or its runtime posture.`,
    recommendation: `${hit.message.trim().replace(/\.?$/, ".")} See ${wikiUrl(hit.code)}.`,
    acceptanceCriteria: [`hadolint reports no ${hit.code} for ${hit.file}`],
    ...(note?.cwe === undefined ? {} : { cwe: note.cwe }),
    source: { kind: "tool", name: HADOLINT_STEP },
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
 * `--no-fail` makes a lint hit exit 0, so a non-zero status always means
 * hadolint itself failed rather than "the Dockerfile has problems".
 */
function hadolintArgs(files: readonly string[]): string[] {
  return ["--no-fail", "--no-color", "--format", "json", ...files];
}

/** Lets the orchestrator hand in the file list it discovered. */
export interface HadolintOptions {
  /** Repo-relative Dockerfiles; defaults to the ones phase 0 proved. */
  readonly files?: readonly string[] | undefined;
}

/**
 * Runs hadolint over the target's Dockerfiles and normalises every hit into a
 * verified `Finding`. A missing binary, a timeout or output that is not the
 * expected JSON all come back as a non-`ok` {@link StepOutcome}.
 */
export async function runHadolint(
  ctx: RunnerContext,
  options: HadolintOptions = {},
): Promise<StepOutcome> {
  const startedAt = performance.now();
  const timeoutMs = ctx.timeoutMs ?? HADOLINT_DEFAULT_TIMEOUT_MS;
  const files = [...new Set(options.files ?? dockerfilesOf(ctx.profile))].sort();

  if (files.length === 0) {
    return skipped(HADOLINT_STEP, startedAt, "the target has no Dockerfile");
  }

  const binary = await ctx.tools.resolve(HADOLINT_TOOL, { allowPath: ctx.allowPathTools === true });
  if (binary === null) {
    return skipped(
      HADOLINT_STEP,
      startedAt,
      "hadolint is not installed; run `sentinel setup` (Dockerfile coverage falls back to Sentinel's own rules)",
    );
  }

  const hits: HadolintHit[] = [];
  const artifacts: string[] = [];
  const notes: Array<string | null> = [];
  const batches = chunk(files, MAX_FILES_PER_INVOCATION);

  for (const [index, batch] of batches.entries()) {
    const result = await ctx.exec.run(binary, hadolintArgs(batch), {
      cwd: ctx.targetDir,
      timeoutMs,
      env: { NO_COLOR: "1" },
    });

    const suffix = batches.length === 1 ? "" : `.${index + 1}`;
    if (result.stdout !== "") {
      artifacts.push(await writeRaw(ctx, HADOLINT_STEP, `hadolint${suffix}.json`, result.stdout));
    }
    if (result.stderr.trim() !== "") {
      artifacts.push(
        await writeRaw(ctx, HADOLINT_STEP, `hadolint${suffix}.stderr.log`, result.stderr),
      );
    }

    if (result.notFound) {
      return skipped(HADOLINT_STEP, startedAt, `hadolint is not executable at ${binary}`);
    }
    if (result.timedOut) {
      return failedStep(
        HADOLINT_STEP,
        startedAt,
        `hadolint timed out after ${timeoutMs} ms`,
        artifacts,
      );
    }
    if (result.truncated) {
      return failedStep(
        HADOLINT_STEP,
        startedAt,
        "hadolint output exceeded the capture limit and was truncated",
        artifacts,
      );
    }

    const stdout = result.stdout.trim();
    if (stdout === "") {
      return failedStep(
        HADOLINT_STEP,
        startedAt,
        `hadolint exited ${result.exitCode} without output: ${briefly(result.stderr, 200) || "no stderr"}`,
        artifacts,
      );
    }

    const report = parseHadolintReport(stdout);
    if (!report.ok) {
      return failedStep(HADOLINT_STEP, startedAt, report.error, artifacts);
    }
    if (result.exitCode !== 0) {
      // The JSON parsed, so the hits are usable; the status still deserves a note.
      notes.push(
        `hadolint exited ${result.exitCode} on ${batch.length} file(s): ${briefly(result.stderr, 120) || "no stderr"}`,
      );
    }
    hits.push(...report.value);
  }

  const verified = await verifyStepFindings(hits.map(toFinding), ctx);
  if (verified.droppedFindings > 0) {
    notes.push(
      `${verified.droppedFindings} hit(s) cited a line Sentinel could not resolve on disk and were dropped`,
    );
  }

  return outcome(
    HADOLINT_STEP,
    notes.length === 0 ? "ok" : "degraded",
    joinReasons([`${files.length} Dockerfile(s) linted`, ...notes]),
    verified.kept,
    artifacts,
    startedAt,
  );
}

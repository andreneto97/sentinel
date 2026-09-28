/**
 * The bridge from a run directory to {@link ReportInput}.
 *
 * `src/cli/_shared/run-artifacts.ts` already knows how to read a run directory
 * and validate every artifact against its schema; there is no reason for the PDF
 * to learn it again. The import is type-only, so this file adds no runtime
 * dependency on the CLI — it exists so that rendering a run directory is one call
 * instead of eight field assignments, and so that the coupling to the CLI's
 * loader is in one place if either side moves.
 *
 * The report is dated from the **run id**, not from the clock: re-rendering a
 * run next week must not claim the repository was examined next week.
 */

import type { RunArtifacts } from "../../cli/_shared/run-artifacts.ts";
import type { TriageSummary } from "../triage.ts";
import type { CommitInfo, ReportInput, ToolVersion } from "./model.ts";
import type { ScorecardInput } from "./scorecard.ts";

/** What the run directory cannot tell the report. */
export interface RenderContext {
  /** Defaults to the timestamp encoded in the run id. */
  readonly generatedAt?: Date | undefined;
  readonly commit?: CommitInfo | undefined;
  readonly sentinelVersion?: string | undefined;
  readonly tools?: readonly ToolVersion[] | undefined;
  /** Phase 6's output, when it ran. */
  readonly scorecard?: ScorecardInput | undefined;
  /**
   * What a human verified, when `--triage` was given.
   *
   * It does not come from the run directory: the verdicts are the reviewer's
   * file, applied by the caller, and `findings` here is already the document
   * they adjusted.
   */
  readonly triage?: TriageSummary | undefined;
}

/** `20260304T093000-9f2c41ab` — the shape `src/cli/_shared/run-dir.ts` mints. */
const RUN_ID = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})-[0-9a-f]+$/;

/**
 * The instant a run id encodes, or undefined when it encodes none.
 *
 * Parsed here rather than imported so this module keeps its type-only stance
 * toward the CLI; the format is fixed by the contract that mints the id.
 */
export function runIdTimestamp(runId: string): Date | undefined {
  const match = RUN_ID.exec(runId);
  if (match === null) return undefined;
  const [, year, month, day, hour, minute, second] = match;
  const at = new Date(
    Date.UTC(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second),
    ),
  );
  return Number.isNaN(at.getTime()) ? undefined : at;
}

/**
 * Turns a loaded run directory into renderer input.
 *
 * Throws when `findings.json` is absent: that is the one artifact the dossier
 * cannot be written without, and a PDF of an empty document would be a
 * confident-looking lie.
 */
export function reportInputFromRunArtifacts(
  artifacts: RunArtifacts,
  context: RenderContext = {},
): ReportInput {
  const findings = artifacts.findings;
  if (findings === null) {
    throw new Error(
      `${artifacts.runDir}/findings.json is missing - the dossier cannot be rendered without it`,
    );
  }

  const generatedAt = context.generatedAt ?? runIdTimestamp(artifacts.runId) ?? new Date(0);

  return {
    findings,
    run: {
      generatedAt,
      runId: artifacts.runId,
      target: artifacts.target === "" ? findings.target : artifacts.target,
      ...(context.commit === undefined ? {} : { commit: context.commit }),
      ...(context.sentinelVersion === undefined
        ? {}
        : { sentinelVersion: context.sentinelVersion }),
      ...(context.tools === undefined ? {} : { tools: context.tools }),
    },
    // `assurances.json` is the phase 4 artifact and carries the same list;
    // preferring it means a run whose merge into `findings.json` was interrupted
    // still shows what was proved.
    ...(artifacts.assurances === null ? {} : { assurances: artifacts.assurances.assurances }),
    ...(artifacts.profile === null ? {} : { profile: artifacts.profile }),
    ...(artifacts.scope === null ? {} : { scope: artifacts.scope.decision }),
    ...(artifacts.analysisScope === null ? {} : { analysisScope: artifacts.analysisScope }),
    ...(artifacts.scan === null ? {} : { scan: artifacts.scan }),
    ...(artifacts.audit === null ? {} : { audit: artifacts.audit }),
    // The whole repository's enumeration, even on a scoped run: see
    // `renderDossier` for why narrowing this denominator would let a bounded run
    // score an A for a domain it never looked at.
    ...(artifacts.inventory === null ? {} : { inventory: artifacts.inventory }),
    ...(context.scorecard === undefined ? {} : { scorecard: context.scorecard }),
    ...(context.triage === undefined ? {} : { triage: context.triage }),
  };
}

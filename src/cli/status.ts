/**
 * `sentinel status <run-dir>` — what a run contains, and how far it got.
 *
 * This is the verb that answers the only question an operator has after a run
 * finishes: *can I send this to the client?* So it does not print a progress
 * log. It prints the phases with their own reasons, the units by kind, the
 * findings by domain and severity, the coverage, everything that was skipped
 * with the sentence the phase wrote about it, and then a verdict line that
 * commits to yes or no and lists what is missing when it is no.
 *
 * It reads and never writes, and it spends nothing: the run directory is the
 * only input.
 *
 * The exit code carries the verdict — `0` when the run is complete enough to
 * share, `1` when it is not — so `sentinel report <dir> && sentinel status
 * <dir>` is a usable gate in CI. A run directory that cannot be read at all is
 * a different failure and exits `2`.
 */

import type { KindCoverage } from "../audit/coverage.ts";
import { formatSkipGroups, groupSkipReasons } from "../audit/coverage.ts";
import type { Coverage, Domain, Finding } from "../contracts/findings.ts";
import { DomainSchema } from "../contracts/findings.ts";
import type { AnalysisScope } from "../contracts/scope.ts";
import { renderScopePaths } from "../contracts/scope.ts";
import type { RunPhase, RunVerdict, SeverityCounts } from "./_shared/run-artifacts.ts";
import {
  type RunArtifactFileSystem,
  SEVERITY_ORDER,
  assessRun,
  countBySeverity,
  describeRunPhases,
  formatRunDate,
  loadRunArtifacts,
} from "./_shared/run-artifacts.ts";
import { type RunDirFileSystem, resolveRunDir } from "./_shared/run-dir.ts";
import type { CliContext, OutputFlags } from "./index.ts";
import { EXIT } from "./index.ts";
import { describeRunDirFailure } from "./report.ts";

/** A parsed `sentinel status` invocation. */
export interface StatusInvocation {
  readonly runDir: string;
  readonly cwd: string;
  readonly output: OutputFlags;
}

/** The filesystem surface status needs; it writes nothing. */
export interface StatusFileSystem extends RunArtifactFileSystem, RunDirFileSystem {}

/** Everything the command reaches outside itself. */
export interface StatusDeps {
  readonly fs: StatusFileSystem;
}

/** One domain's row of the findings table. */
export interface DomainRow {
  readonly domain: Domain;
  readonly findings: number;
  readonly bySeverity: SeverityCounts;
  readonly coverage: Coverage | undefined;
  /** False when the scope left this domain out, so nothing in it was checked. */
  readonly inScope: boolean;
}

/**
 * One row per domain the run says anything about.
 *
 * A domain that was in scope and found nothing gets a row at zero: `0 findings,
 * 4/4 checked` and `nothing was checked here` are the two claims this table
 * exists to keep apart, and omitting the row collapses them.
 */
export function buildDomainRows(
  findings: readonly Finding[],
  coverage: readonly Coverage[],
  enabled: readonly Domain[] | undefined,
): DomainRow[] {
  const rows: DomainRow[] = [];
  for (const domain of DomainSchema.options) {
    const own = findings.filter((finding) => finding.domain === domain);
    const row = coverage.find((entry) => entry.domain === domain);
    const inScope = enabled === undefined || enabled.includes(domain);
    if (!inScope && own.length === 0 && row === undefined) continue;
    rows.push({
      domain,
      findings: own.length,
      bySeverity: countBySeverity(own),
      coverage: row,
      inScope,
    });
  }
  return rows;
}

/** What `--json` prints. */
export interface StatusJson {
  readonly runId: string;
  readonly runDir: string;
  readonly target: string;
  readonly startedAt: string;
  readonly phases: readonly RunPhase[];
  /**
   * `--path`: the subtree the run analysed, when it recorded one.
   *
   * `null` both for a whole-repository run and for one written before the scope
   * artifact existed. The two are distinguishable in the document itself; what
   * matters here is that a bounded run is never silent about being bounded.
   */
  readonly analysisScope: AnalysisScope | null;
  readonly units: {
    readonly total: number;
    readonly byKind: Readonly<Record<string, number>>;
  };
  readonly findings: {
    readonly total: number;
    readonly bySeverity: SeverityCounts;
    readonly byDomain: readonly DomainRow[];
    readonly dropped: number;
  };
  readonly assurances: {
    readonly total: number;
    readonly unitsChecked: number;
    readonly byDomain: Readonly<Record<string, number>>;
  };
  readonly coverage: readonly Coverage[];
  readonly kinds: readonly KindCoverage[];
  /** Everything a phase declined to do, with the reason it gave. */
  readonly skipped: readonly { readonly what: string; readonly reason: string }[];
  readonly verdict: RunVerdict;
}

/** Two-space JSON with a trailing newline, matching every other artifact. */
function serialise(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** Status marker per phase: aligned, and readable without colour. */
const PHASE_MARK: Readonly<Record<RunPhase["status"], string>> = {
  complete: "[done]",
  partial: "[part]",
  missing: "[  - ]",
};

/** Groups reasons into one line each with a count, worst-repeated first. */
function summarise(reasons: readonly string[]): string[] {
  return formatSkipGroups(groupSkipReasons(reasons.map((reason) => ({ reason }))));
}

/** Everything a phase declined to do, in the phase's own words. */
export function collectSkipped(
  artifacts: Awaited<ReturnType<typeof loadRunArtifacts>>,
): { what: string; reason: string }[] {
  const skipped: { what: string; reason: string }[] = [];
  for (const step of artifacts.scan?.steps ?? []) {
    if (step.status === "skipped" || step.status === "failed") {
      skipped.push({
        what: `analyzer ${step.step}`,
        reason: `${step.status}: ${step.reason ?? "no reason given"}`,
      });
    }
  }
  for (const enumerator of artifacts.inventory?.enumerators ?? []) {
    if (enumerator.status !== "ok") {
      skipped.push({
        what: `enumerator ${enumerator.name}`,
        reason: `${enumerator.status}: ${enumerator.reason ?? "no reason given"}`,
      });
    }
  }
  for (const batch of artifacts.audit?.batches ?? []) {
    if (batch.status !== "audited") {
      skipped.push({
        what: `batch ${batch.batchId}`,
        reason: `${batch.status}: ${batch.reason ?? batch.failure ?? "no reason given"}`,
      });
    }
  }
  for (const entry of artifacts.scope?.decision.declined ?? []) {
    skipped.push({
      what: `proposal ${entry.proposal.id}`,
      reason: "declined at scope negotiation",
    });
  }
  for (const entry of artifacts.scope?.decision.blockedOnMissingTool ?? []) {
    skipped.push({
      what: `proposal ${entry.proposalId}`,
      reason: `accepted but ${entry.tool} is not installed`,
    });
  }
  return skipped;
}

/** Severity counts as one line: `medium 10   low 28   info 38`. */
function severityLine(counts: SeverityCounts): string {
  return SEVERITY_ORDER.map((severity) => `${severity} ${counts[severity]}`).join("   ");
}

/** The findings table: one row per domain, with its severities and its coverage. */
function renderDomainTable(rows: readonly DomainRow[]): string[] {
  if (rows.length === 0) return ["  (no findings)"];
  const width = rows.reduce((max, row) => Math.max(max, row.domain.length), 6);
  const header = `  ${"domain".padEnd(width)}  ${"total".padStart(5)}  ${SEVERITY_ORDER.map((s) => s.slice(0, 4).padStart(5)).join("")}   checked`;
  const lines = rows.map((row) => {
    if (!row.inScope) {
      return `  ${row.domain.padEnd(width)}  ${String(row.findings).padStart(5)}  off — outside this run's scope, so nothing in it was checked`;
    }
    const severities = SEVERITY_ORDER.map((severity) =>
      String(row.bySeverity[severity]).padStart(5),
    ).join("");
    const checked =
      row.coverage === undefined
        ? "  —"
        : `  ${row.coverage.unitsAudited}/${row.coverage.unitsTotal}`;
    return `  ${row.domain.padEnd(width)}  ${String(row.findings).padStart(5)}  ${severities}${checked}`;
  });
  return [header, ...lines];
}

/** Reads a run directory and says what is in it and whether it can be shared. */
export async function statusCommand(
  context: CliContext,
  invocation: StatusInvocation,
  deps: StatusDeps,
): Promise<number> {
  const resolution = await resolveRunDir(deps.fs, invocation.runDir, invocation.cwd);
  if (!resolution.ok) {
    context.writeError(`sentinel: ${describeRunDirFailure(resolution, invocation.runDir)}\n`);
    return EXIT.preflight;
  }
  const runDir = resolution.runDir.dir;
  const artifacts = await loadRunArtifacts(deps.fs, runDir);
  const phases = describeRunPhases(artifacts);
  const verdict = assessRun(artifacts, phases);

  const findings = artifacts.findings?.findings ?? [];
  const assurances = artifacts.findings?.assurances ?? artifacts.assurances?.assurances ?? [];
  const bySeverity = countBySeverity(findings);
  const coverage = artifacts.findings?.coverage ?? [];
  const domainRows = buildDomainRows(findings, coverage, artifacts.scope?.decision.enabledDomains);
  const kinds = artifacts.audit?.kinds ?? [];
  const skipped = collectSkipped(artifacts);
  const assuranceByDomain: Record<string, number> = {};
  let assuranceUnits = 0;
  for (const assurance of assurances) {
    assuranceByDomain[assurance.domain] = (assuranceByDomain[assurance.domain] ?? 0) + 1;
    assuranceUnits += assurance.unitsChecked;
  }

  if (invocation.output.json) {
    const payload: StatusJson = {
      runId: artifacts.runId,
      runDir,
      target: artifacts.target,
      startedAt: formatRunDate(artifacts.runId),
      phases,
      analysisScope: artifacts.analysisScope,
      units: {
        total: artifacts.inventory?.units.length ?? 0,
        byKind: artifacts.inventory?.counts ?? {},
      },
      findings: {
        total: findings.length,
        bySeverity,
        byDomain: domainRows,
        dropped: artifacts.findings?.droppedFindings ?? 0,
      },
      assurances: {
        total: assurances.length,
        unitsChecked: assuranceUnits,
        byDomain: assuranceByDomain,
      },
      coverage,
      kinds,
      skipped,
      verdict,
    };
    context.write(serialise(payload));
    return verdict.shareable ? EXIT.ok : EXIT.failure;
  }

  if (invocation.output.quiet) {
    context.write(
      `${verdict.shareable ? "shareable" : "incomplete"} ${artifacts.runId} ${runDir}\n`,
    );
    return verdict.shareable ? EXIT.ok : EXIT.failure;
  }

  const lines: string[] = [
    `Run ${artifacts.runId}`,
    `  target     ${artifacts.target === "" ? "(unknown: no artifact recorded it)" : artifacts.target}`,
    `  directory  ${runDir}`,
    `  started    ${formatRunDate(artifacts.runId)}`,
    // A scoped run says so on the third line, beside the repository it names.
    // `status` is how a run is inspected weeks later, by someone who did not
    // choose the scope and would otherwise read these counts as the repository's.
    ...(artifacts.analysisScope === null || artifacts.analysisScope.wholeRepository
      ? []
      : [`  scope      ${artifacts.analysisScope.statement}`]),
    "",
    "Phases",
  ];
  const phaseWidth = phases.reduce((max, phase) => Math.max(max, phase.name.length), 0);
  for (const phase of phases) {
    lines.push(`  ${PHASE_MARK[phase.status]} ${phase.name.padEnd(phaseWidth)}  ${phase.detail}`);
  }

  const units = artifacts.inventory;
  const scope = artifacts.analysisScope;
  lines.push(
    "",
    `Units of audit (${units?.units.length ?? 0})`,
    // The counts below are the repository's enumeration, which is what makes the
    // exclusion countable; this is the line that keeps them from being read as
    // the run's.
    ...(scope === null || scope.wholeRepository
      ? []
      : [
          `  enumerated across the whole repository; ${scope.units.inScope} of them are inside ${renderScopePaths(scope.paths)} and only those were analysed`,
        ]),
  );
  if (units === null || units === undefined) {
    lines.push("  (no inventory: nothing was enumerated, so no coverage can be proven)");
  } else {
    const entries = Object.entries(units.counts).filter(([, count]) => count > 0);
    const width = entries.reduce((max, [kind]) => Math.max(max, kind.length), 0);
    if (entries.length === 0) lines.push("  (no units were enumerated)");
    for (const [kind, count] of entries) {
      const row = kinds.find((candidate) => candidate.kind === kind);
      const audited = row === undefined ? "" : `   ${row.unitsAudited}/${row.unitsTotal} audited`;
      lines.push(`  ${kind.padEnd(width)}  ${String(count).padStart(5)}${audited}`);
    }
  }

  lines.push("", `Findings (${findings.length})`, `  ${severityLine(bySeverity)}`, "");
  lines.push(...renderDomainTable(domainRows));
  if ((artifacts.findings?.droppedFindings ?? 0) > 0) {
    lines.push(
      `  ${artifacts.findings?.droppedFindings} claim(s) were dropped: the citation did not resolve on disk, or pointed at code the model was never shown`,
    );
  }

  lines.push(
    "",
    `Assurances (${assurances.length})`,
    assurances.length === 0
      ? "  (none: an assurance is a model's answer that Sentinel verified against the code)"
      : `  ${Object.entries(assuranceByDomain)
          .map(([domain, count]) => `${domain} ${count}`)
          .join("   ")}   —   ${assuranceUnits} unit-checks covered`,
  );

  const noVerdict = kinds.flatMap((row) => row.skipped.map((entry) => entry.reason));
  if (noVerdict.length > 0) {
    lines.push(
      "",
      `Units without a verdict (${noVerdict.length})`,
      ...summarise(noVerdict).map((l) => `  ${l}`),
    );
  }

  if (skipped.length > 0) {
    lines.push("", `Skipped or not run (${skipped.length})`);
    const width = skipped.reduce((max, entry) => Math.max(max, entry.what.length), 0);
    for (const entry of skipped) lines.push(`  ${entry.what.padEnd(width)}  ${entry.reason}`);
  }

  lines.push(
    "",
    "Verdict",
    verdict.shareable
      ? "  Yes — this run is complete enough to share with a client."
      : "  No — this run is not complete enough to share with a client.",
  );
  if (verdict.blockers.length > 0) {
    lines.push("  Missing:");
    for (const blocker of verdict.blockers) lines.push(`    - ${blocker}`);
  }
  if (verdict.warnings.length > 0) {
    lines.push("  Disclose when sharing:");
    for (const warning of verdict.warnings) lines.push(`    - ${warning}`);
  }

  context.write(`${lines.join("\n")}\n`);
  return verdict.shareable ? EXIT.ok : EXIT.failure;
}

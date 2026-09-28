/**
 * A finished run, read back off disk.
 *
 * `resume`, `status` and `report` all start the same way: they are handed a
 * directory and have to work out what is in it and how far the run got. This
 * module is that step, and it holds three rules the three verbs share.
 *
 * - **Every artifact is validated against its own schema.** A run directory is
 *   external input — it may have been produced by an older Sentinel, copied
 *   half-way, or hand-edited — so nothing here trusts a file because its name
 *   is right. An artifact that does not parse is reported as unreadable, by
 *   name and with the violation, rather than feeding a report that silently
 *   lost half its findings.
 * - **An absent artifact is a phase that did not run, not an error.** Only the
 *   verb knows which files it actually needs; `report` refuses without
 *   `findings.json`, `status` prints the gap, `resume` re-enters at it.
 * - **A partial phase never reads as a complete one.** {@link describeRunPhases}
 *   distinguishes "complete", "partial" and "missing", and the reason a phase
 *   is not complete is carried with it, in the phase's own words where the
 *   artifact recorded one.
 */

import { basename, join } from "node:path";
import type { z } from "zod";
import {
  ASSURANCES_FILE,
  AUDIT_FILE,
  type AssurancesDocument,
  AssurancesDocumentSchema,
  type AuditReport,
  AuditReportSchema,
} from "../../audit/artifacts.ts";
import {
  type Domain,
  DomainSchema,
  type Finding,
  type FindingsDocument,
  FindingsDocumentSchema,
  type Severity,
} from "../../contracts/findings.ts";
import {
  INVENTORY_FILE,
  type InventoryDocument,
  InventoryDocumentSchema,
} from "../../contracts/inventory.ts";
import { type StackProfile, StackProfileSchema } from "../../contracts/profile.ts";
import {
  type ScopeProposalDocument,
  ScopeProposalDocumentSchema,
} from "../../contracts/proposal.ts";
import {
  ANALYSIS_SCOPE_FILE,
  type AnalysisScope,
  AnalysisScopeSchema,
} from "../../contracts/scope.ts";
import {
  FINDINGS_FILE,
  SCAN_REPORT_FILE,
  type ScanReport,
  ScanReportSchema,
} from "../../scan/artifacts.ts";
import { PARTIAL_COVERAGE } from "../../score/coverage-gate.ts";
import { isRunId } from "./run-dir.ts";

/**
 * Phase 0's artifact. The name is `analyze`'s — it is repeated rather than
 * imported so `status` does not pull the whole analyze pipeline into its module
 * graph to learn a filename.
 */
export const STACK_PROFILE_FILE = "stack-profile.json";

/** Phase 0.5's artifact; see {@link STACK_PROFILE_FILE} about the duplication. */
export const SCOPE_PROPOSAL_FILE = "scope-proposal.json";

/** The rendered dossier. */
export const REPORT_MD_FILE = "report.md";

/** The rendered dossier, as a document a client can be sent. */
export const REPORT_PDF_FILE = "report.pdf";

/** One GitHub issue per finding, ready to paste. */
export const ISSUES_MD_FILE = "issues.md";

/** The three files phase 7 renders. */
export const REPORT_FILES: readonly string[] = [REPORT_PDF_FILE, REPORT_MD_FILE, ISSUES_MD_FILE];

/** The filesystem surface reading a run needs; the real port satisfies it. */
export interface RunArtifactFileSystem {
  readFile(path: string): Promise<string>;
  exists(path: string): Promise<boolean>;
}

/**
 * An artifact a verb cannot work without. It names the file, because "the run
 * directory is incomplete" is not something a reader can act on.
 */
export class MissingArtifactError extends Error {
  /** Artifact file name, e.g. `findings.json`. */
  readonly file: string;
  /** Absolute path of the run directory it is missing from. */
  readonly runDir: string;

  constructor(runDir: string, file: string, consequence: string) {
    super(`${join(runDir, file)} is missing — ${consequence}`);
    this.name = "MissingArtifactError";
    this.file = file;
    this.runDir = runDir;
  }
}

/** An artifact that exists but could not be used, with the reason it could not. */
export interface UnreadableArtifact {
  readonly file: string;
  readonly reason: string;
}

/** Everything one run directory holds, validated; `null` means the phase left none. */
export interface RunArtifacts {
  /** Absolute path of the run directory itself. */
  readonly runDir: string;
  readonly runId: string;
  /** Absolute path of the repository the run is about; empty when nothing recorded it. */
  readonly target: string;
  readonly findings: FindingsDocument | null;
  readonly assurances: AssurancesDocument | null;
  readonly audit: AuditReport | null;
  readonly inventory: InventoryDocument | null;
  readonly scan: ScanReport | null;
  readonly profile: StackProfile | null;
  readonly scope: ScopeProposalDocument | null;
  /**
   * `--path`: which subtree the run analysed, and what that left out.
   *
   * `null` for a run written before this artifact existed — which is not the
   * same as a whole-repository run, and is why the renderers treat it as "the
   * scope is unknown" rather than as "the scope was everything".
   */
  readonly analysisScope: AnalysisScope | null;
  /** Rendered report files that already exist, in {@link REPORT_FILES} order. */
  readonly rendered: readonly string[];
  /** Artifacts present on disk that did not survive their schema. */
  readonly unreadable: readonly UnreadableArtifact[];
}

/** Names the first schema violation in a way a CLI error can print. */
function violation(error: z.ZodError): string {
  const issue = error.issues[0];
  const path = issue === undefined ? "" : issue.path.map(String).join(".");
  return `${path === "" ? "(root)" : path}: ${issue?.message ?? "invalid"}`;
}

/** Reads and validates one optional artifact; a broken one is reported, not thrown. */
async function readArtifact<S extends z.ZodType>(
  fs: RunArtifactFileSystem,
  runDir: string,
  file: string,
  schema: S,
  unreadable: UnreadableArtifact[],
): Promise<z.infer<S> | null> {
  const path = join(runDir, file);
  if (!(await fs.exists(path))) return null;
  let raw: string;
  try {
    raw = await fs.readFile(path);
  } catch (error) {
    unreadable.push({ file, reason: error instanceof Error ? error.message : String(error) });
    return null;
  }
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    unreadable.push({ file, reason: `not valid JSON: ${detail}` });
    return null;
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    unreadable.push({ file, reason: `not a valid document: ${violation(parsed.error)}` });
    return null;
  }
  return parsed.data;
}

/**
 * Reads every artifact a run directory may hold.
 *
 * Nothing is required here. The verb decides what it cannot do without, so one
 * loader serves `status` (which wants the gaps), `report` (which needs
 * `findings.json`) and `resume` (which needs whatever the next phase consumes).
 */
export async function loadRunArtifacts(
  fs: RunArtifactFileSystem,
  runDir: string,
): Promise<RunArtifacts> {
  const unreadable: UnreadableArtifact[] = [];
  const [findings, assurances, audit, inventory, scan, profile, scope, analysisScope] =
    await Promise.all([
      readArtifact(fs, runDir, FINDINGS_FILE, FindingsDocumentSchema, unreadable),
      readArtifact(fs, runDir, ASSURANCES_FILE, AssurancesDocumentSchema, unreadable),
      readArtifact(fs, runDir, AUDIT_FILE, AuditReportSchema, unreadable),
      readArtifact(fs, runDir, INVENTORY_FILE, InventoryDocumentSchema, unreadable),
      readArtifact(fs, runDir, SCAN_REPORT_FILE, ScanReportSchema, unreadable),
      readArtifact(fs, runDir, STACK_PROFILE_FILE, StackProfileSchema, unreadable),
      readArtifact(fs, runDir, SCOPE_PROPOSAL_FILE, ScopeProposalDocumentSchema, unreadable),
      readArtifact(fs, runDir, ANALYSIS_SCOPE_FILE, AnalysisScopeSchema, unreadable),
    ]);

  const rendered: string[] = [];
  for (const file of REPORT_FILES) {
    if (await fs.exists(join(runDir, file))) rendered.push(file);
  }

  const name = basename(runDir);
  const runId =
    (isRunId(name) ? name : undefined) ??
    findings?.runId ??
    audit?.runId ??
    scan?.runId ??
    scope?.runId ??
    analysisScope?.runId ??
    name;
  const target =
    findings?.target ??
    audit?.target ??
    scan?.target ??
    profile?.target ??
    scope?.target ??
    analysisScope?.target ??
    "";

  return {
    runDir,
    runId,
    target,
    findings,
    assurances,
    audit,
    inventory,
    scan,
    profile,
    scope,
    analysisScope,
    rendered,
    unreadable: [...unreadable].sort((left, right) => left.file.localeCompare(right.file)),
  };
}

/** `findings.json`, or a {@link MissingArtifactError} naming it. */
export function requireFindings(artifacts: RunArtifacts): FindingsDocument {
  if (artifacts.findings !== null) return artifacts.findings;
  const broken = artifacts.unreadable.find((entry) => entry.file === FINDINGS_FILE);
  if (broken !== undefined) {
    throw new Error(`${join(artifacts.runDir, FINDINGS_FILE)} ${broken.reason}`);
  }
  throw new MissingArtifactError(
    artifacts.runDir,
    FINDINGS_FILE,
    "there is nothing to report on. Run `sentinel analyze <target>` first",
  );
}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

/** The phases a run directory can be at, in the order `resume` walks them. */
export const RUN_PHASES = ["profile", "propose", "scan", "inventory", "audit", "report"] as const;

/** One of the six resumable phases. */
export type RunPhaseName = (typeof RUN_PHASES)[number];

/**
 * `complete` — the phase ran and finished. `partial` — it ran and did not
 * finish, so re-running it would add something. `missing` — it never ran.
 */
export type PhaseStatus = "complete" | "partial" | "missing";

/** What one phase left behind, and whether that is all of it. */
export interface RunPhase {
  readonly name: RunPhaseName;
  readonly status: PhaseStatus;
  /** Artifacts of this phase that exist, by file name. */
  readonly artifacts: readonly string[];
  /** Artifacts it owes and did not write. */
  readonly missing: readonly string[];
  /** One sentence: what it produced, or why it is not complete. */
  readonly detail: string;
  /** True when re-running it dispatches agents and spends the subscription. */
  readonly spendsAi: boolean;
}

/** `1 finding` / `4 findings`, with `-es` after a sibilant. */
function plural(count: number, noun: string): string {
  if (count === 1) return `${count} ${noun}`;
  return `${count} ${noun}${/(?:s|x|z|ch|sh)$/.test(noun) ? "es" : "s"}`;
}

/** The scan phase's state: `findings.json` plus the report that says what ran. */
function scanPhase(artifacts: RunArtifacts): RunPhase {
  const present: string[] = [];
  const missing: string[] = [];
  for (const [file, document] of [
    [FINDINGS_FILE, artifacts.findings],
    [SCAN_REPORT_FILE, artifacts.scan],
  ] as const) {
    (document === null ? missing : present).push(file);
  }
  if (present.length === 0) {
    return {
      name: "scan",
      status: "missing",
      artifacts: [],
      missing,
      detail: "no analyzer ran",
      spendsAi: false,
    };
  }
  const report = artifacts.scan;
  const failed = report?.steps.filter((step) => step.status === "failed") ?? [];
  const aborted = report?.aborted === true;
  const status: PhaseStatus =
    missing.length > 0 || aborted || failed.length > 0 ? "partial" : "complete";
  const detail = aborted
    ? "the scan was cancelled before every step finished"
    : failed.length > 0
      ? `${plural(failed.length, "step")} failed: ${failed.map((step) => step.step).join(", ")}`
      : missing.length > 0
        ? `${missing.join(", ")} was not written`
        : `${plural(report?.steps.length ?? 0, "step")}, ${plural(artifacts.findings?.findings.length ?? 0, "finding")}`;
  return { name: "scan", status, artifacts: present, missing, detail, spendsAi: false };
}

/** The inventory phase's state: units enumerated, and enumerators that failed. */
function inventoryPhase(artifacts: RunArtifacts): RunPhase {
  const document = artifacts.inventory;
  if (document === null) {
    return {
      name: "inventory",
      status: "missing",
      artifacts: [],
      missing: [INVENTORY_FILE],
      detail: "nothing was enumerated, so no coverage can be proven",
      spendsAi: false,
    };
  }
  const failed = document.enumerators.filter((entry) => entry.status === "failed");
  return {
    name: "inventory",
    status: failed.length > 0 ? "partial" : "complete",
    artifacts: [INVENTORY_FILE],
    missing: [],
    detail:
      failed.length > 0
        ? `${plural(failed.length, "enumerator")} failed: ${failed.map((entry) => entry.name).join(", ")}`
        : `${plural(document.units.length, "unit")} of audit`,
    spendsAi: false,
  };
}

/**
 * The audit phase's state.
 *
 * A batch that failed, a batch that came back about only some of its units, a
 * cancelled phase and an exhausted subscription are all `partial`: the units
 * behind them have no verdict, and re-running is the only thing that gives them
 * one. Everything else about this phase is `complete` — including units the
 * agent declined to judge, which is an answer, not a gap in the run.
 */
function auditPhase(artifacts: RunArtifacts): RunPhase {
  const report = artifacts.audit;
  if (report === null) {
    return {
      name: "audit",
      status: "missing",
      artifacts: [],
      missing: [AUDIT_FILE],
      detail: "no model has looked at this repository",
      spendsAi: true,
    };
  }
  const present = [AUDIT_FILE, ...(artifacts.assurances === null ? [] : [ASSURANCES_FILE])];
  const failed = report.batches.filter((batch) => batch.status === "failed");
  const partial = report.batches.filter((batch) => batch.status === "partial");
  const incomplete = failed.length > 0 || report.aborted || report.quotaExhausted;
  // Most specific cause first. `aborted` is also set by a retry that left units
  // no batch ever reached (`mergeRetryIntoAudit`), so reading it first reported
  // "the audit was cancelled" for a run that was not cancelled but had one batch
  // time out — the concrete cause is the one an operator can act on.
  const detail = report.quotaExhausted
    ? "the subscription's usage limit stopped the phase"
    : failed.length > 0
      ? `${plural(failed.length, "batch")} failed`
      : report.aborted
        ? "the audit did not reach every unit"
        : `${report.units.audited}/${report.units.total} units audited, ${plural(report.findingsKept, "finding")}, ${plural(report.assurances, "assurance")}${
            partial.length > 0 ? `; ${plural(partial.length, "batch")} answered partially` : ""
          }`;
  return {
    name: "audit",
    status: incomplete ? "partial" : "complete",
    artifacts: present,
    missing: artifacts.assurances === null ? [ASSURANCES_FILE] : [],
    detail,
    spendsAi: true,
  };
}

/** The report phase's state: the three rendered files. */
function reportPhase(artifacts: RunArtifacts): RunPhase {
  const missing = REPORT_FILES.filter((file) => !artifacts.rendered.includes(file));
  const status: PhaseStatus =
    missing.length === 0
      ? "complete"
      : missing.length === REPORT_FILES.length
        ? "missing"
        : "partial";
  return {
    name: "report",
    status,
    artifacts: artifacts.rendered,
    missing,
    detail:
      status === "complete"
        ? `${REPORT_FILES.length} files rendered`
        : `${missing.join(", ")} ${missing.length === 1 ? "is" : "are"} not rendered`,
    spendsAi: false,
  };
}

/** Every phase's state, in {@link RUN_PHASES} order. */
export function describeRunPhases(artifacts: RunArtifacts): RunPhase[] {
  const profile: RunPhase = {
    name: "profile",
    status: artifacts.profile === null ? "missing" : "complete",
    artifacts: artifacts.profile === null ? [] : [STACK_PROFILE_FILE],
    missing: artifacts.profile === null ? [STACK_PROFILE_FILE] : [],
    detail:
      artifacts.profile === null
        ? "the stack was never detected"
        : `${plural(artifacts.profile.facts.length, "stack fact")}`,
    spendsAi: false,
  };
  const propose: RunPhase = {
    name: "propose",
    status: artifacts.scope === null ? "missing" : "complete",
    artifacts: artifacts.scope === null ? [] : [SCOPE_PROPOSAL_FILE],
    missing: artifacts.scope === null ? [SCOPE_PROPOSAL_FILE] : [],
    detail:
      artifacts.scope === null
        ? "the scope was never negotiated"
        : `${artifacts.scope.decision.enabledDomains.length}/${DomainSchema.options.length} domains enabled`,
    spendsAi: false,
  };
  return [
    profile,
    propose,
    scanPhase(artifacts),
    inventoryPhase(artifacts),
    auditPhase(artifacts),
    reportPhase(artifacts),
  ];
}

/** The first phase that did not finish, or `undefined` when the run is done. */
export function firstIncompletePhase(phases: readonly RunPhase[]): RunPhase | undefined {
  return phases.find((phase) => phase.status !== "complete");
}

/** Look one phase up by name. */
export function phaseByName(phases: readonly RunPhase[], name: RunPhaseName): RunPhase | undefined {
  return phases.find((phase) => phase.name === name);
}

// ---------------------------------------------------------------------------
// Summarising what a run found
// ---------------------------------------------------------------------------

/** Severities from worst to least, the order every table in Sentinel uses. */
export const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

/** A count per severity, every severity keyed even at zero. */
export type SeverityCounts = Readonly<Record<Severity, number>>;

/** Counts per severity; a severity nothing matched reads `0`, never absent. */
export function countBySeverity(findings: readonly Finding[]): SeverityCounts {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/** One count per domain that has at least one finding. */
function countByDomain(findings: readonly Finding[]): Map<Domain, number> {
  const counts = new Map<Domain, number>();
  for (const finding of findings) counts.set(finding.domain, (counts.get(finding.domain) ?? 0) + 1);
  return counts;
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/** Whether a run is complete enough to hand to a client, and what is missing. */
export interface RunVerdict {
  /** True only when no blocker applies. */
  readonly shareable: boolean;
  /** Reasons the run must not be shared as a finished dossier. */
  readonly blockers: readonly string[];
  /** Things a reader has to be told, which do not by themselves block sharing. */
  readonly warnings: readonly string[];
}

/**
 * Judges a run the way a reader would.
 *
 * A blocker is a claim the dossier cannot make: no scan, no inventory (so
 * coverage is unprovable), no model verdict, a phase that stopped early, or a
 * report that was never rendered. A warning is something the report must
 * disclose but which does not make it dishonest — units the agent could not
 * decide about, findings whose citations were refused, domains the operator
 * deliberately left out.
 */
export function assessRun(artifacts: RunArtifacts, phases: readonly RunPhase[]): RunVerdict {
  const blockers: string[] = [];
  const warnings: string[] = [];

  for (const entry of artifacts.unreadable) {
    blockers.push(`${entry.file} is on disk but unusable (${entry.reason})`);
  }

  if (artifacts.findings === null) {
    blockers.push(`${FINDINGS_FILE} is missing: the run produced no findings document`);
  }

  const scan = phaseByName(phases, "scan");
  if (scan?.status === "missing") blockers.push("no analyzer ran: the scan phase is missing");
  else if (scan?.status === "partial") blockers.push(`the scan did not finish — ${scan.detail}`);

  const inventory = phaseByName(phases, "inventory");
  if (inventory?.status === "missing") {
    blockers.push("no inventory: coverage cannot be proven, only claimed");
  } else if (inventory?.status === "partial") {
    warnings.push(`the inventory is incomplete — ${inventory.detail}`);
  }

  const audit = phaseByName(phases, "audit");
  if (audit?.status === "missing") {
    blockers.push("no model audited this run: nothing here carries a D2 or D3 verdict");
  } else if (audit?.status === "partial") {
    blockers.push(`the audit did not finish — ${audit.detail}`);
  }

  const report = artifacts.audit;
  if (report !== null) {
    if (report.runtime.synthetic) {
      blockers.push(
        "the audit's answers came from a recorded transcript, not a live model: this run is a wiring check, not evidence",
      );
    }
    const partial = report.batches.filter((batch) => batch.status === "partial").length;
    if (partial > 0) {
      warnings.push(
        `${partial} batch(es) answered about only some of their units; those units are listed as not audited`,
      );
    }
    const notAudited = report.units.total - report.units.audited;
    if (notAudited > 0) {
      warnings.push(`${notAudited} of ${report.units.total} units came back without a verdict`);
    }
  }

  if ((artifacts.findings?.droppedFindings ?? 0) > 0) {
    warnings.push(
      `${artifacts.findings?.droppedFindings} claim(s) were dropped because their citation did not resolve on disk or was never shown to the model`,
    );
  }

  const enabled = artifacts.scope?.decision.enabledDomains;
  if (enabled !== undefined) {
    const excluded = DomainSchema.options.filter((domain) => !enabled.includes(domain));
    const counted = countByDomain(artifacts.findings?.findings ?? []);
    const silent = excluded.filter((domain) => (counted.get(domain) ?? 0) === 0);
    if (silent.length > 0) {
      warnings.push(
        `${silent.join(", ")} ${silent.length === 1 ? "was" : "were"} outside this run's scope and ${silent.length === 1 ? "was" : "were"} not checked`,
      );
    }
    // A domain nobody enabled that still produced findings is worth a line of
    // its own: those findings are real, but no phase claims to have covered the
    // domain, so the coverage table has no row for them.
    for (const domain of excluded) {
      const count = counted.get(domain) ?? 0;
      if (count > 0) {
        warnings.push(
          `${domain} was outside this run's scope, yet ${count} finding(s) were reported in it; they are real but that domain has no coverage row`,
        );
      }
    }
  }

  // A domain that was in scope, ran some of its checks, and came back too thin
  // for phase 6 to score is the disclosure most easily forgotten: it has a
  // coverage row, so it does not look excluded, and it often has no findings,
  // so it does not look broken. Both are exactly why it has to be said out loud
  // in the list someone pastes into an email.
  for (const row of artifacts.findings?.coverage ?? []) {
    if (row.unitsTotal === 0) continue;
    const ratio = row.unitsAudited / row.unitsTotal;
    if (ratio >= PARTIAL_COVERAGE) continue;
    warnings.push(
      `${row.domain} earned no score: only ${row.unitsAudited} of ${row.unitsTotal} checks ran, which is too little to stand behind a number — read it as unknown, not as clean`,
    );
  }

  const rendered = phaseByName(phases, "report");
  if (rendered !== undefined && rendered.status !== "complete") {
    blockers.push(
      `the dossier is not rendered: ${rendered.missing.join(", ")} — run \`sentinel report ${artifacts.runDir}\``,
    );
  }

  return { shareable: blockers.length === 0, blockers, warnings };
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

/**
 * The instant a run started, taken from its own id.
 *
 * Deliberately not the wall clock: a report re-rendered next week is about the
 * same run, and dating it "today" would make two renders of one run disagree
 * about when the repository was examined — and stop them being byte-identical.
 */
export function runStartedAt(runId: string): Date | undefined {
  const match = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})-[0-9a-f]{8}$/.exec(runId);
  if (match === null) return undefined;
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const stamp = Date.UTC(year, month - 1, day, hour, minute, second);
  return Number.isNaN(stamp) ? undefined : new Date(stamp);
}

/** `2026-09-23 00:40 UTC`, or the run id itself when it carries no timestamp. */
export function formatRunDate(runId: string): string {
  const date = runStartedAt(runId);
  if (date === undefined) return runId;
  const iso = date.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

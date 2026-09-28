/**
 * The view model: every number and every sentence the PDF prints, computed once,
 * before a single point is drawn.
 *
 * The sections below this file are layout and nothing else. That split is what
 * makes the report's claims testable — "delivery reads as not assessed, never as
 * a zero" is an assertion about a value in here, not about ink on a page — and
 * it is the only way the two rules from the plan can be enforced in one place:
 * every finding carries a citation Sentinel verified, and coverage is
 * enumerated, so a domain nobody audited has to say so in words.
 *
 * Input is the run directory's own artifacts, in the shapes their contracts
 * publish. Everything except `findings.json` is optional: a report of a partial
 * run is exactly the case that must not silently look complete.
 */

import type { AuditReport } from "../../audit/artifacts.ts";
import type { BudgetStop } from "../../audit/budget.ts";
import { type SkipGroup, groupSkipReasons } from "../../audit/coverage.ts";
import { domainsFor } from "../../audit/prompts/index.ts";
import type {
  Assurance,
  Coverage,
  Domain,
  Finding,
  FindingsDocument,
  Severity,
} from "../../contracts/findings.ts";
import { DomainSchema, SeveritySchema } from "../../contracts/findings.ts";
import type { AuditUnitKind, InventoryDocument } from "../../contracts/inventory.ts";
import { AUDIT_UNIT_KINDS, AUDIT_UNIT_NOUN, countUnits } from "../../contracts/inventory.ts";
import type { DetectedFact, FactKind, StackProfile } from "../../contracts/profile.ts";
import type { ScopeDecision } from "../../contracts/proposal.ts";
import type { AnalysisScope } from "../../contracts/scope.ts";
import { renderScopePaths } from "../../contracts/scope.ts";
import type { VolumeGroup, VolumePlan } from "../../scan/_volume.ts";
import { isCollapsed, isHiddenByVolume, planVolume } from "../../scan/_volume.ts";
import type { ScanReport } from "../../scan/artifacts.ts";
import type { TriageSummary } from "../triage.ts";
import { type ScorecardInput, type ScorecardView, adaptScorecard } from "./scorecard.ts";
import { formatCount, formatDuration, plural, repositoryName } from "./text.ts";
import { SEVERITY_COLOR } from "./theme.ts";

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/** A tool the run depended on, and what it turned out to be. */
export interface ToolVersion {
  readonly name: string;
  readonly version?: string | undefined;
  /** `ok` ran, `degraded` ran with less than it needs, `missing` did not run. */
  readonly status: "ok" | "degraded" | "missing";
  /** What was observed, or what its absence costs. */
  readonly detail?: string | undefined;
}

/** The commit the dossier is about. */
export interface CommitInfo {
  readonly sha: string;
  readonly branch?: string | undefined;
  /** True when the working tree had uncommitted changes, which the cover states. */
  readonly dirty?: boolean | undefined;
  readonly committedAt?: string | undefined;
}

/** Facts about the run that no artifact carries. */
export interface RunMetadata {
  readonly generatedAt: Date;
  /** Defaults to `findings.json`'s run id. */
  readonly runId?: string | undefined;
  /** Defaults to `findings.json`'s target. */
  readonly target?: string | undefined;
  /** Defaults to the last segment of the target path. */
  readonly repository?: string | undefined;
  readonly commit?: CommitInfo | undefined;
  readonly sentinelVersion?: string | undefined;
  readonly tools?: readonly ToolVersion[] | undefined;
}

/** Everything the PDF renderer reads. Only `findings` and `run` are required. */
export interface ReportInput {
  readonly findings: FindingsDocument;
  readonly run: RunMetadata;
  /** Overrides `findings.assurances`, for a caller that read `assurances.json`. */
  readonly assurances?: readonly Assurance[] | undefined;
  readonly profile?: StackProfile | undefined;
  readonly scope?: ScopeDecision | undefined;
  /**
   * `--path`: the subtree the run analysed, and what that left out.
   *
   * Drives the cover's scope line and, for a narrowed run, a callout the reader
   * meets before the first number. Absent means no scope artifact was recorded,
   * which the cover states as unknown rather than as "the whole repository".
   */
  readonly analysisScope?: AnalysisScope | undefined;
  readonly scan?: ScanReport | undefined;
  readonly audit?: AuditReport | undefined;
  readonly inventory?: InventoryDocument | undefined;
  readonly scorecard?: ScorecardInput | undefined;
  /**
   * `--triage`: what a human verified, and what that changed.
   *
   * Absent means nobody reviewed this run, and the document then says nothing
   * about human verification at all — a dossier that hints at a review it did
   * not have is worse than one that admits it had none.
   */
  readonly triage?: TriageSummary | undefined;
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/** The plan's own numbering, so the report and PLAN.md name the same things. */
export const DOMAIN_LABEL: Readonly<Record<Domain, string>> = {
  dependencies: "Dependencies & supply chain",
  appsec: "Application security",
  data: "Data layer",
  delivery: "Delivery & infrastructure",
  serverless: "Serverless & async workloads",
  api: "API surface & contracts",
  reliability: "Reliability & observability",
  deadcode: "Dead code & maintainability",
};

/** `D2`, as the plan numbers the domains. */
export const DOMAIN_CODE: Readonly<Record<Domain, string>> = {
  dependencies: "D1",
  appsec: "D2",
  data: "D3",
  delivery: "D4",
  serverless: "D5",
  api: "D6",
  reliability: "D7",
  deadcode: "D8",
};

/**
 * The plural noun for each unit kind, from the contract that owns the kinds.
 *
 * These are the exact words `src/audit` writes into an assurance's scope
 * (`"20/37 route handlers"`) and the words the score phase uses to name the units
 * a domain was not audited against, so the coverage section, the assurances and
 * the scorecard cannot describe the same units differently.
 */
export const UNIT_LABEL: Readonly<Record<AuditUnitKind, string>> = Object.fromEntries(
  AUDIT_UNIT_KINDS.map((kind) => [kind, AUDIT_UNIT_NOUN[kind][1]]),
) as Readonly<Record<AuditUnitKind, string>>;

/** The singular of each unit kind, for the sentences that count one of them. */
export const UNIT_LABEL_SINGULAR: Readonly<Record<AuditUnitKind, string>> = Object.fromEntries(
  AUDIT_UNIT_KINDS.map((kind) => [kind, AUDIT_UNIT_NOUN[kind][0]]),
) as Readonly<Record<AuditUnitKind, string>>;

/** `1 scheduled job` / `500 migrations`, in the audit's own vocabulary. */
export const unitCount = countUnits;

/**
 * Which domain each phase 1 step reports into.
 *
 * `scan-report.json` records a step's name but not the domains it serves — that
 * lives on the step definition — so the mapping is restated here against the
 * names the report actually contains. A step this table does not know is listed
 * in the appendix rather than dropped, which is what keeps a new analyzer
 * visible instead of silently uncounted.
 */
export const STEP_DOMAINS: Readonly<Record<string, readonly Domain[]>> = {
  trivy: ["dependencies", "delivery"],
  gitleaks: ["appsec"],
  opengrep: ["appsec"],
  knip: ["deadcode", "dependencies"],
  "dependency-cruiser": ["deadcode"],
  "package-manager": ["dependencies"],
  actionlint: ["delivery"],
  hadolint: ["delivery"],
  "ci-rules": ["delivery"],
  "container-rules": ["delivery"],
};

// ---------------------------------------------------------------------------
// Derived shapes
// ---------------------------------------------------------------------------

/** Counts per severity, with the total, in palette order. */
export interface SeverityCounts {
  readonly counts: Readonly<Record<Severity, number>>;
  readonly total: number;
}

/**
 * How much of a domain this run can speak to.
 *
 * Two of these mean "there is no score", and the difference between them is the
 * whole point of the distinction:
 *
 * - `not-assessed` — nothing was checked. Every cell for the domain is unknown.
 * - `insufficient` — checks ran, but too few of them for phase 6 to stand
 *   behind a number, so it refused one. The fraction that *did* run is printed,
 *   because it is the measure of how thin the evidence is, and the domain still
 *   reads as unscored rather than as clean.
 *
 * `assessed` and `partial` answer a finer question than phase 6 does — did every
 * enumerated unit come back with a verdict — so a domain can be `partial` here
 * and `scored` there. What cannot happen is the reverse: a domain phase 6
 * refused to score never reads as assessed.
 */
export type DomainAssessment =
  | "assessed"
  | "partial"
  | "insufficient"
  | "out-of-scope"
  | "not-assessed";

/** True for the two assessments that mean "phase 6 published no number". */
export function isUnscored(assessment: DomainAssessment): boolean {
  return assessment === "not-assessed" || assessment === "insufficient";
}

/** One step's line in the coverage section. */
export interface StepLine {
  readonly step: string;
  readonly status: ScanReport["steps"][number]["status"];
  readonly reason?: string | undefined;
  readonly findings: number;
}

/** One `37/37 route handlers` line. */
export interface UnitLine {
  /**
   * The unit kind this row counts, or `undefined` for a domain-wide row.
   *
   * A kind is attributed to the domain of the batches that audited it, and one
   * kind is audited by several domains — a route handler is examined for
   * `appsec`, for `api` and for `reliability`, each asking a different question
   * of the same file. The audit publishes per-kind counts once, globally, and
   * per-domain counts without a kind breakdown, so a domain that shares all its
   * kinds with another gets no per-kind row it could honestly print. It gets
   * this one instead, built from its own coverage: fewer details, but its own
   * numbers rather than another domain's.
   */
  readonly kind?: AuditUnitKind | undefined;
  readonly label: string;
  readonly total: number;
  readonly audited: number;
  /** Why units went un-audited, collapsed to one line per distinct reason. */
  readonly skipped: readonly SkipGroup[];
}

/** Everything the report says about one domain. */
export interface DomainView {
  readonly domain: Domain;
  readonly code: string;
  readonly label: string;
  readonly assessment: DomainAssessment;
  /** Why the domain reads the way it does, in one sentence. */
  readonly statusSentence: string;
  /**
   * True when the *evidence* gate, not thin check coverage, is why this domain
   * has no number.
   *
   * The two read nothing alike, and conflating them produced the summary
   * sentence "checked too thinly to score — data layer, where 1 of 1 planned
   * check completed (100%)", which contradicts itself in its own clause. A
   * domain held back by evidence ran all of its checks; what it lacks is a unit
   * somebody looked at.
   */
  readonly heldBackByEvidence: boolean;
  readonly findings: readonly Finding[];
  /**
   * The findings this domain renders as a block of their own: everything except
   * the members of a collapsed group. See {@link ReportModel.volume}.
   */
  readonly ungrouped: readonly Finding[];
  /** The rules of this domain the volume policy renders as a counted group. */
  readonly volumeGroups: readonly VolumeGroup[];
  readonly severity: SeverityCounts;
  readonly assurances: readonly Assurance[];
  readonly coverage?: Coverage | undefined;
  /** Merged phase 1 + phase 4 completion, as `findings.json` reports it. */
  readonly checksCompleted?: { readonly done: number; readonly total: number } | undefined;
  readonly steps: readonly StepLine[];
  readonly units: readonly UnitLine[];
  /** Offers declined or never answered at scope negotiation. */
  readonly declined: readonly { readonly title: string; readonly reason: string }[];
  /** Checks that cannot apply to this stack, in the profiler's own words. */
  readonly notApplicable: readonly string[];
  /** How this domain was mapped onto the detected stack. */
  readonly mapping: string;
}

/** A row of the prioritised plan. */
export interface PriorityGroup {
  readonly id: "P1" | "P2" | "P3";
  readonly title: string;
  readonly color: string;
  /** What the tier means, so the grouping is not a mystery. */
  readonly rule: string;
  /** The rows printed for this tier: members of a counted group are not among them. */
  readonly findings: readonly Finding[];
  /** Members of this tier folded into a counted group; `findings.length + hidden` is the tier. */
  readonly hidden: number;
}

/** The stack, in the words the cover and the methodology note use. */
export interface StackView {
  readonly summary: string;
  readonly rows: readonly { readonly label: string; readonly value: string }[];
  readonly warnings: readonly string[];
}

/** The appendix's key-value blocks. */
export interface AppendixView {
  readonly run: readonly { readonly label: string; readonly value: string }[];
  readonly agent: readonly { readonly label: string; readonly value: string }[];
  readonly verification: readonly { readonly label: string; readonly value: string }[];
  readonly tools: readonly ToolVersion[];
  readonly steps: readonly StepLine[];
  readonly batches: readonly AuditReport["batches"][number][];
}

/** The whole report, computed. */
export interface ReportModel {
  readonly title: string;
  readonly repository: string;
  readonly runId: string;
  readonly target: string;
  readonly generatedAt: Date;
  readonly commitLabel: string;
  readonly severity: SeverityCounts;
  readonly findings: readonly Finding[];
  /**
   * Which rules are rendered as a counted group instead of one block each.
   *
   * The same plan `report.md` renders from, computed from the same findings, so
   * the two documents cannot disagree about what was collapsed. It is a
   * *rendering* decision: `findings.json` still holds every member, and a group
   * states its own size, so nothing is hidden — only counted.
   */
  readonly volume: VolumePlan;
  readonly assurances: readonly Assurance[];
  readonly unitsAssured: number;
  readonly domains: readonly DomainView[];
  readonly scorecard: ScorecardView;
  readonly stack: StackView;
  readonly priorities: readonly PriorityGroup[];
  readonly appendix: AppendixView;
  readonly scopeSummary: string;
  /**
   * The one sentence a scoped run's cover has to carry, or `null`.
   *
   * `null` for a whole-repository run and for a run with no scope artifact, so
   * the cover renders the callout on exactly the runs that were narrowed.
   */
  readonly analysisScope: string | null;
  /**
   * What the audit's own ceilings left unaudited, or `null` when there was no
   * audit to bound.
   *
   * The scope sentence above says which part of the repository this run was
   * about; this one says how much of that part a model actually reached. A
   * budgeted run needs both, and for the same reason: a reader who is given only
   * one of them reads the dossier as a complete audit of something.
   */
  readonly auditBound: string | null;
  /**
   * The run's units counted once each, or `null` when there was no audit.
   *
   * The per-domain coverage rows count a unit once per domain that examined it
   * — one route handler is evidence for `appsec`, `api` and `reliability` — so
   * their `un-audited` column sums well above the number of units that actually
   * went unexamined. Both figures are true and they answer different questions,
   * which is precisely why a reader who adds the column up needs the run-wide
   * one printed beside it; without it the section looks like it contradicts its
   * own headline.
   */
  readonly auditUnits: { readonly total: number; readonly audited: number } | null;
  /** True when a ceiling, not the end of the work, is what stopped the audit. */
  readonly auditStoppedEarly: boolean;
  /**
   * Why the audit stopped, when it stopped early.
   *
   * An audit can stop early without a budget having stopped it: a quota can run
   * out on a run launched with no budget at all. The cover used to headline every
   * early stop as "The audit stopped at its budget", and a reader told the wrong
   * cause reaches for the wrong remedy.
   */
  readonly auditStop: BudgetStop | null;
  readonly droppedFindings: number;
  /** True when the audit answers came from a recorded transcript, not a live run. */
  readonly synthetic: boolean;
  /**
   * What a human verified, or `null` when nobody did.
   *
   * `null` is what an unreviewed run renders as: no cover line, no section, no
   * verdict beside a finding. The one thing this field must never allow is a
   * document that reads as reviewed because a small fraction of its findings was.
   */
  readonly triage: TriageSummary | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Severity rank, worst first; the report's primary sort everywhere. */
const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Counts the severities of a list of findings. */
export function countSeverities(findings: readonly Finding[]): SeverityCounts {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const finding of findings) counts[finding.severity] += 1;
  return { counts, total: findings.length };
}

/** Worst severity first, then file, then line: stable and useful. */
export function compareFindings(a: Finding, b: Finding): number {
  const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (bySeverity !== 0) return bySeverity;
  if (a.location.file !== b.location.file) return a.location.file < b.location.file ? -1 : 1;
  if (a.location.line !== b.location.line) return a.location.line - b.location.line;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/** Severity data for the charts, in palette order, zeros included. */
export function severityChartData(
  counts: SeverityCounts,
): readonly { key: string; label: string; value: number; color: string }[] {
  return SeveritySchema.options.map((severity) => ({
    key: severity,
    label: severity.charAt(0).toUpperCase() + severity.slice(1),
    value: counts.counts[severity],
    color: SEVERITY_COLOR[severity],
  }));
}

/** Every fact of one kind, in the order the profiler proved them. */
function facts(profile: StackProfile | undefined, kind: FactKind): DetectedFact[] {
  return (profile?.facts ?? []).filter((fact) => fact.kind === kind);
}

/** The values of every fact of one kind, e.g. `["drizzle", "postgres-js"]`. */
function factValues(profile: StackProfile | undefined, kind: FactKind): string[] {
  return facts(profile, kind).map((fact) => fact.value);
}

/** A human list: `a`, `a and b`, `a, b and c`. */
export function listSentence(values: readonly string[]): string {
  if (values.length === 0) return "";
  if (values.length === 1) return values[0] ?? "";
  return `${values.slice(0, -1).join(", ")} and ${values.at(-1) ?? ""}`;
}

/**
 * How the run's scope reads in one line.
 *
 * The analysed subtree comes first when there is one: the domains a run checked
 * are worth less to a reader than the fraction of the repository it checked them
 * over, and the cover has one line for both.
 */
function scopeSentence(
  scope: ScopeDecision | undefined,
  domains: readonly Domain[],
  analysis: AnalysisScope | undefined,
): string {
  const head =
    analysis === undefined || analysis.wholeRepository
      ? ""
      : `${renderScopePaths(analysis.paths)} only — ${analysis.units.inScope} of ${
          analysis.units.total
        } units in this repository. `;
  return `${head}${negotiatedSentence(scope, domains)}`;
}

/** The phase 0.5 half of the scope line: domains on, offers declined, checks n/a. */
function negotiatedSentence(scope: ScopeDecision | undefined, domains: readonly Domain[]): string {
  if (scope === undefined) {
    return `${domains.length} ${plural(domains.length, "domain")} analysed; no scope negotiation was recorded for this run.`;
  }
  const enabled = scope.enabledDomains.map((domain) => DOMAIN_LABEL[domain]);
  const parts = [`${enabled.length} of 8 domains in scope: ${listSentence(enabled)}.`];
  if (scope.accepted.length > 0) {
    parts.push(
      `${scope.accepted.length} optional ${plural(scope.accepted.length, "check")} accepted at scope negotiation.`,
    );
  }
  const off = scope.declined.length + scope.untouched.length;
  if (off > 0) parts.push(`${off} declined or unanswered.`);
  if (scope.notApplicable.length > 0) {
    parts.push(
      `${scope.notApplicable.length} ${plural(scope.notApplicable.length, "check")} not applicable to this stack.`,
    );
  }
  return parts.join(" ");
}

/**
 * How one domain was mapped onto the detected stack.
 *
 * This is the sentence the methodology note owes the reader: not "we checked
 * application security" but "these 37 handlers, in this framework, are what
 * application security meant here".
 */
function domainMapping(
  domain: Domain,
  profile: StackProfile | undefined,
  inventory: InventoryDocument | undefined,
  steps: readonly StepLine[],
): string {
  const counts = inventory?.counts;
  const unitPhrase = (kinds: readonly AuditUnitKind[]): string => {
    const parts = kinds
      .map((kind) => ({ kind, total: counts?.[kind] ?? 0 }))
      .filter((entry) => entry.total > 0)
      .map((entry) => unitCount(entry.kind, entry.total));
    return listSentence(parts);
  };
  // Read off the prompt registry rather than written down here, so a domain that
  // gains or loses a unit kind cannot leave this paragraph describing the old
  // shape of the audit. That is precisely how D6 and D7 came to print "a later
  // milestone" and "not yet a phase of its own" over a section that had just
  // audited every handler in the repository.
  const auditedKinds = (of: Domain): readonly AuditUnitKind[] =>
    AUDIT_UNIT_KINDS.filter((kind) => domainsFor(kind).includes(of));
  const absent = (kind: FactKind): boolean =>
    (profile?.absences ?? []).some((absence) => absence.kind === kind);
  const toolPhrase = (): string => {
    const ran = steps.filter((step) => step.status === "ok" || step.status === "degraded");
    return ran.length === 0 ? "" : `Tools: ${ran.map((step) => step.step).join(", ")}.`;
  };
  const framework = factValues(profile, "backend-framework");
  const router = factValues(profile, "next-router");
  const dataLayers = factValues(profile, "data-layer");
  const engine = factValues(profile, "database-engine");
  const platforms = factValues(profile, "serverless-platform");
  const packageManager = factValues(profile, "package-manager");

  switch (domain) {
    case "dependencies": {
      const manager = packageManager[0] ?? "the detected package manager";
      return `Resolved through the ${manager} lockfile: CVEs and licences from the SBOM, outdated packages from the registry, unused dependencies from the module graph. ${toolPhrase()}`.trim();
    }
    case "appsec": {
      const stack =
        framework.length === 0
          ? "the detected backend"
          : `${listSentence(framework)}${router.length > 0 ? ` (${listSentence(router)} router)` : ""}`;
      const enumerated = unitPhrase(["route", "role-gate", "sink"]);
      // Enumerating is this phase's claim; auditing is phase 4's, and section 4
      // is where it is counted. Naming a count of route handlers here reads as a
      // claim that that many handlers were audited, which on a --no-ai run is
      // false.
      return `The five access-control categories re-expressed for ${stack}. Units are enumerated first and then audited one by one; this run enumerated ${enumerated || "no units"}, and section 4 states how many of them a verdict examined. ${toolPhrase()}`.trim();
    }
    case "data": {
      const layers = dataLayers.length === 0 ? "the detected data layer" : listSentence(dataLayers);
      const on = engine.length === 0 ? "" : ` on ${listSentence(engine)}`;
      const enumerated = unitPhrase(["data-access", "migration"]);
      return `Every call site of ${layers}${on}, plus the migration history; this run enumerated ${enumerated || "no units"}. Schema, query performance and migration safety are judged against the code that reads the tables, not against the schema alone.`;
    }
    case "delivery": {
      // What is *absent* decides this sentence. A step that "ran" here can be a
      // step that ran and found no Dockerfile to read, which is not the same as
      // a repository whose delivery pipeline was reviewed.
      const missing = (["container", "ci", "iac"] as const).filter((kind) => absent(kind));
      if (missing.length === 3) {
        return "No Dockerfile, compose file, CI workflow or infrastructure-as-code was found in this repository, so the container, pipeline and IaC checks had nothing to read. What remains in scope for this domain is the runtime configuration surface: the environment variables the application reads and how they are validated.";
      }
      const found = (["container", "ci", "iac"] as const).filter((kind) => !absent(kind));
      // With nothing missing there is no absence clause: an empty subject
      // renders as " are absent, so the checks that need them did not run",
      // which is a sentence about nothing.
      const absences =
        missing.length === 0
          ? ""
          : ` ${listSentence(missing)} ${missing.length === 1 ? "is" : "are"} absent, so the checks that need ${missing.length === 1 ? "it" : "them"} did not run.`;
      return `Present in the repository: ${listSentence(found)}. Those definitions were linted and scanned for misconfiguration.${absences} ${toolPhrase()}`.trim();
    }
    case "serverless": {
      const platform = platforms.length === 0 ? "no serverless platform" : listSentence(platforms);
      const enumerated = unitPhrase(["serverless-function", "cron", "webhook", "queue-consumer"]);
      return `Detected platform: ${platform}. Everything that runs outside a request/response cycle is enumerated and then audited; this run enumerated ${enumerated || "nothing of the kind"}, and section 4 states how many of them a verdict examined.`;
    }
    case "api": {
      const stack = framework.length === 0 ? "the detected backend" : listSentence(framework);
      const enumerated = unitPhrase(auditedKinds("api"));
      return `The request boundary of ${stack} read as a contract: whether an endpoint states who may call it, bounds what it returns, serialises only the fields it means to publish, and answers with the status code its own behaviour implies. Its own batch series over those endpoints, asked separately from the access-control pass so a contract question and an authorization question are never traded off against each other; this run enumerated ${enumerated || "no units"}, and section 4 states how many of them a verdict examined.`;
    }
    case "reliability": {
      const enumerated = unitPhrase(auditedKinds("reliability"));
      return `What happens when a dependency is slow, answers twice or fails halfway: outbound timeouts, retry and backoff, idempotency, transaction boundaries, error propagation, log hygiene, correlation ids and cache-key scope. Asked of every unit that performs I/O, in its own batch series over the same units the access-control and data passes read; this run enumerated ${enumerated || "nothing that performs I/O"}, and section 4 states how many of them a verdict examined.`;
    }
    case "deadcode":
      return `Unused files, exports and types from the module graph, plus circular and orphan modules. Each one is a candidate rather than a verdict: a dynamic import, a framework file convention or a barrel re-export can keep code alive in ways a static graph cannot see. ${toolPhrase()}`.trim();
  }
}

/** `1 of 5 planned checks completed (20%)`, the measure of how thin a domain is. */
export function coverageFraction(checks: {
  readonly done: number;
  readonly total: number;
}): string {
  const percent = checks.total === 0 ? 0 : Math.round((checks.done / checks.total) * 100);
  return `${checks.done} of ${checks.total} planned ${plural(checks.total, "check")} completed (${percent}%)`;
}

/**
 * One domain's unit rows, falling back to its own coverage when it owns no kind.
 *
 * Kinds are attributed to the domain of the batches that audited them, and that
 * attribution is one-to-one: `route` belongs to `appsec`, so `api` and
 * `reliability` — which audit the same handlers asking different questions — end
 * up with no rows at all and render as a chip with nothing under it, while every
 * other domain gets a table. The reader is then told that dozens of units went
 * un-audited in the API surface and given no way to see what they were.
 *
 * The per-kind numbers cannot simply be repeated under each domain: the audit
 * publishes one global row per kind (`300 of 320` routes), and the API surface
 * audited those same routes to a different depth (`260 of 320`). Printing the
 * global row under the domain would contradict the domain's own line two inches
 * above it. So a domain with no kind of its own gets a single row built from its
 * own coverage: no kind breakdown, but its own totals and its own skip reasons.
 */
function domainUnitLines(
  domain: Domain,
  owned: readonly UnitLine[],
  coverage: Coverage | undefined,
): UnitLine[] {
  if (owned.length > 0) return [...owned];
  if (coverage === undefined || coverage.unitsTotal === 0) return [];
  return [
    {
      label: `${DOMAIN_LABEL[domain]} units`,
      total: coverage.unitsTotal,
      audited: coverage.unitsAudited,
      skipped: groupSkipReasons(coverage.skipped),
    },
  ];
}

/** The sentence that explains a domain's assessment, and never reads as a zero. */
function statusSentence(
  assessment: DomainAssessment,
  view: {
    readonly findings: number;
    readonly checks?: { readonly done: number; readonly total: number } | undefined;
    readonly skipped: number;
  },
): string {
  switch (assessment) {
    case "assessed":
      return view.checks === undefined
        ? "Assessed."
        : `Assessed: ${view.checks.done} of ${view.checks.total} planned ${plural(view.checks.total, "check")} completed.`;
    case "partial":
      return `Partially assessed: ${view.checks?.done ?? 0} of ${view.checks?.total ?? 0} planned checks completed, ${view.skipped} ${plural(view.skipped, "unit")} un-audited.`;
    case "insufficient":
      // The fraction leads, because it is the reason there is no score. The
      // last clause is the one a reader skimming a column of dashes needs.
      return `Not assessed: ${view.checks === undefined ? "too few checks completed" : coverageFraction(view.checks)}, which is too little of this domain to stand behind a score. The checks that did not run are listed above; this is not a clean result.`;
    case "out-of-scope":
      // "in section 5", not "below": this sentence is printed on three
      // different pages, and only one of them has the findings underneath it.
      return `Not in this run's scope. ${view.findings} ${plural(view.findings, "finding")} reached the report while another domain was being audited, and ${view.findings === 1 ? "it is" : "they are"} reported in section 5.`;
    case "not-assessed":
      return "Not assessed in this run. This is not a clean result: nothing was checked.";
  }
}

/**
 * Phase 6's sentence, as a sentence: first letter raised, full stop added.
 *
 * Undefined in, undefined out, so the caller can fall through to the report's own
 * wording with one `??` rather than a branch.
 */
export function evidenceNote(statement: string | undefined): string | undefined {
  if (statement === undefined) return undefined;
  const trimmed = statement.trim();
  if (trimmed === "") return undefined;
  const raised = `${trimmed.charAt(0).toUpperCase()}${trimmed.slice(1)}`;
  return raised.endsWith(".") ? raised : `${raised}.`;
}

// ---------------------------------------------------------------------------
// The builder
// ---------------------------------------------------------------------------

/** Builds every number and sentence the PDF prints. */
export function buildReportModel(input: ReportInput): ReportModel {
  const document = input.findings;
  const runId = input.run.runId ?? document.runId;
  const target = input.run.target ?? document.target;
  const repository = input.run.repository ?? repositoryName(target);
  const assurances = [...(input.assurances ?? document.assurances)].sort(
    (a, b) =>
      DomainSchema.options.indexOf(a.domain) - DomainSchema.options.indexOf(b.domain) ||
      (a.check < b.check ? -1 : 1),
  );
  const findings = [...document.findings].sort(compareFindings);
  const severity = countSeverities(findings);
  // Planned once, here, and read by section 5 and section 6. The same call
  // `report.md` makes, over the same findings, so the PDF cannot collapse a
  // different set than the markdown does.
  const volume = planVolume(findings);

  const coverageByDomain = new Map<Domain, Coverage>();
  for (const entry of document.coverage) coverageByDomain.set(entry.domain, entry);

  const stepsByDomain = new Map<Domain, StepLine[]>();
  for (const step of input.scan?.steps ?? []) {
    const line: StepLine = {
      step: step.step,
      status: step.status,
      ...(step.reason === undefined ? {} : { reason: step.reason }),
      findings: step.findings,
    };
    for (const domain of STEP_DOMAINS[step.step] ?? []) {
      const list = stepsByDomain.get(domain) ?? [];
      list.push(line);
      stepsByDomain.set(domain, list);
    }
  }

  const unitsByDomain = new Map<Domain, UnitLine[]>();
  for (const kindCoverage of input.audit?.kinds ?? []) {
    // A kind belongs to the domain of the batches that audited it; the audit
    // report already grouped coverage by domain, so the kind's domain is taken
    // from the batch that carried it rather than re-derived here.
    const domain =
      input.audit?.batches.find((batch) => batch.kinds.includes(kindCoverage.kind))?.domain ??
      "appsec";
    const line: UnitLine = {
      kind: kindCoverage.kind,
      label: UNIT_LABEL[kindCoverage.kind],
      total: kindCoverage.unitsTotal,
      audited: kindCoverage.unitsAudited,
      skipped: groupSkipReasons(kindCoverage.skipped),
    };
    const list = unitsByDomain.get(domain) ?? [];
    list.push(line);
    unitsByDomain.set(domain, list);
  }

  const declinedByDomain = new Map<Domain, { title: string; reason: string }[]>();
  for (const decided of [...(input.scope?.declined ?? []), ...(input.scope?.untouched ?? [])]) {
    const domain = decided.proposal.domain;
    if (domain === "scope") continue;
    const list = declinedByDomain.get(domain) ?? [];
    list.push({
      title: decided.proposal.title,
      reason:
        decided.outcome === "untouched"
          ? "offered and never answered, so it stayed off"
          : `declined (${decided.source})`,
    });
    declinedByDomain.set(domain, list);
  }

  const notApplicableByDomain = new Map<Domain, string[]>();
  for (const entry of input.scope?.notApplicable ?? []) {
    if (entry.domain === "scope") continue;
    const list = notApplicableByDomain.get(entry.domain) ?? [];
    list.push(entry.reason);
    notApplicableByDomain.set(entry.domain, list);
  }

  // Built before the domains, because phase 6's verdict is what decides whether
  // a domain is allowed to read as assessed at all.
  const scorecard = adaptScorecard(input.scorecard);
  const refusedByScorer = new Set<Domain>(
    scorecard.present
      ? scorecard.domains.filter((row) => row.status === "not-assessed").map((row) => row.domain)
      : [],
  );
  // Phase 6's sentence for the domains whose *evidence* was the binding
  // constraint. This report's own sentences are built from the coverage
  // fraction, and for exactly these domains the fraction is the thing that
  // lies: `1 of 1 checks ran (100%)` over a repository nobody audited.
  const evidenceNotes = new Map<Domain, string>();
  for (const row of scorecard.domains) {
    if (row.evidenceNote !== undefined) evidenceNotes.set(row.domain, row.evidenceNote);
  }

  const enabled = new Set<Domain>(input.scope?.enabledDomains ?? []);
  const domains: DomainView[] = DomainSchema.options.map((domain) => {
    const domainFindings = findings.filter((finding) => finding.domain === domain);
    const coverage = coverageByDomain.get(domain);
    const steps = stepsByDomain.get(domain) ?? [];
    const units = domainUnitLines(domain, unitsByDomain.get(domain) ?? [], coverage);
    const skipped = coverage?.skipped.length ?? 0;
    const checks =
      coverage === undefined
        ? undefined
        : { done: coverage.unitsAudited, total: coverage.unitsTotal };

    const inScope = enabled.size === 0 ? coverage !== undefined : enabled.has(domain);
    const covered: DomainAssessment = !inScope
      ? domainFindings.length > 0
        ? "out-of-scope"
        : "not-assessed"
      : coverage === undefined || (coverage.unitsTotal === 0 && steps.length === 0)
        ? "not-assessed"
        : coverage.unitsAudited < coverage.unitsTotal
          ? "partial"
          : "assessed";

    // Phase 6 may only ever *lower* this. It answers a coarser question — was
    // there enough here to defend a number — so a domain it scored can still be
    // `partial` (units came back without a verdict), but a domain it refused
    // must not print a chip that reads as reviewed.
    const assessment: DomainAssessment =
      refusedByScorer.has(domain) && (covered === "assessed" || covered === "partial")
        ? "insufficient"
        : covered;

    return {
      domain,
      code: DOMAIN_CODE[domain],
      label: DOMAIN_LABEL[domain],
      assessment,
      heldBackByEvidence: evidenceNotes.has(domain),
      statusSentence:
        evidenceNote(evidenceNotes.get(domain)) ??
        statusSentence(assessment, {
          findings: domainFindings.length,
          checks,
          skipped,
        }),
      findings: domainFindings,
      ungrouped: domainFindings.filter((finding) => !isCollapsed(volume, finding)),
      volumeGroups: volume.groups.filter((group) => group.domain === domain),
      severity: countSeverities(domainFindings),
      assurances: assurances.filter((assurance) => assurance.domain === domain),
      coverage,
      checksCompleted: checks,
      steps,
      units,
      declined: declinedByDomain.get(domain) ?? [],
      notApplicable: notApplicableByDomain.get(domain) ?? [],
      mapping: domainMapping(domain, input.profile, input.inventory, steps),
    };
  });

  /**
   * One tier, with the members of a counted group taken out of the table and
   * counted instead.
   *
   * A tier is a worklist, and hundreds of rows of `Unused export candidate` is
   * the one shape that stops it being one. Only `low` and `info` findings can be
   * collapsed, so P1 and P2 are never touched by this.
   */
  const tier = (
    id: PriorityGroup["id"],
    title: string,
    color: string,
    rule: string,
    matches: (finding: Finding) => boolean,
  ): PriorityGroup => {
    const all = findings.filter(matches);
    const shown = all.filter((finding) => !isHiddenByVolume(volume, finding));
    return { id, title, color, rule, findings: shown, hidden: all.length - shown.length };
  };

  const priorities: PriorityGroup[] = [
    tier(
      "P1",
      "Fix now",
      SEVERITY_COLOR.critical,
      "Critical and high severity: exploitable, or damaging enough that the exposure window matters.",
      (finding) => finding.severity === "critical" || finding.severity === "high",
    ),
    tier(
      "P2",
      "Plan into the next cycle",
      SEVERITY_COLOR.medium,
      "Medium severity: real weaknesses whose exploitation needs a precondition, or whose damage is bounded.",
      (finding) => finding.severity === "medium",
    ),
    tier(
      "P3",
      "Housekeeping",
      SEVERITY_COLOR.low,
      "Low and informational: hygiene, maintainability and hardening that can ride along with other work.",
      (finding) => finding.severity === "low" || finding.severity === "info",
    ),
  ];

  const stack = buildStackView(input.profile);

  return {
    title: "Backend Dossier",
    repository,
    runId,
    target,
    generatedAt: input.run.generatedAt,
    commitLabel: commitLabel(input.run.commit),
    severity,
    findings,
    volume,
    assurances,
    unitsAssured: assurances.reduce((sum, assurance) => sum + assurance.unitsChecked, 0),
    domains,
    scorecard,
    stack,
    priorities,
    appendix: buildAppendix(input, runId, target),
    scopeSummary: scopeSentence(
      input.scope,
      document.coverage.map((entry) => entry.domain),
      input.analysisScope,
    ),
    analysisScope:
      input.analysisScope === undefined || input.analysisScope.wholeRepository
        ? null
        : input.analysisScope.statement,
    auditBound: input.audit?.bound.statement ?? null,
    auditUnits:
      input.audit === undefined
        ? null
        : { total: input.audit.bound.unitsTotal, audited: input.audit.bound.unitsAudited },
    auditStoppedEarly:
      input.audit !== undefined &&
      (input.audit.bound.stop !== "complete" || input.audit.bound.unitsDeferred > 0),
    auditStop: input.audit?.bound.stop ?? null,
    droppedFindings: document.droppedFindings,
    synthetic: input.audit?.runtime.synthetic ?? false,
    triage: input.triage ?? null,
  };
}

/** `a1b2c3d4 (main, working tree clean)`, or an honest absence. */
function commitLabel(commit: CommitInfo | undefined): string {
  if (commit === undefined || commit.sha.trim() === "") return "not recorded";
  const short = commit.sha.trim().slice(0, 12);
  const parts: string[] = [];
  if (commit.branch !== undefined && commit.branch !== "") parts.push(commit.branch);
  if (commit.dirty === true) parts.push("uncommitted changes present");
  else if (commit.dirty === false) parts.push("working tree clean");
  return parts.length === 0 ? short : `${short} (${parts.join(", ")})`;
}

/** The stack table the cover prints under the methodology note. */
export function buildStackView(profile: StackProfile | undefined): StackView {
  const rows: { label: string; value: string }[] = [];
  const add = (label: string, values: readonly string[], details?: readonly string[]): void => {
    if (values.length === 0) return;
    const value =
      details === undefined || details.length === 0
        ? listSentence(values)
        : listSentence(
            values.map((entry, index) => {
              const detail = details[index];
              return detail === undefined || detail === "" ? entry : `${entry} (${detail})`;
            }),
          );
    rows.push({ label, value });
  };

  const detailsOf = (kind: FactKind): string[] =>
    facts(profile, kind).map((fact) => fact.detail ?? "");

  add("Package manager", factValues(profile, "package-manager"), detailsOf("package-manager"));
  add("Repository layout", factValues(profile, "repo-layout"), detailsOf("repo-layout"));
  add("Languages", factValues(profile, "language"), detailsOf("language"));
  const framework = factValues(profile, "backend-framework");
  const router = factValues(profile, "next-router");
  add(
    "Backend framework",
    framework.map((value) =>
      router.length > 0 ? `${value} (${router.join(", ")} router)` : value,
    ),
    detailsOf("backend-framework"),
  );
  add("Data layer", factValues(profile, "data-layer"), detailsOf("data-layer"));
  add("Database", factValues(profile, "database-engine"), detailsOf("database-engine"));
  add("Migrations", factValues(profile, "migrations-dir"), detailsOf("migrations-dir"));
  const auth = [...factValues(profile, "auth-provider"), ...factValues(profile, "auth-helper")];
  add("Authentication", auth);
  add("Frontend", factValues(profile, "frontend"), detailsOf("frontend"));
  add("Serverless platform", factValues(profile, "serverless-platform"));
  add("Scheduled jobs", factValues(profile, "scheduled-job"), detailsOf("scheduled-job"));
  add(
    "Config validation",
    factValues(profile, "config-validation"),
    detailsOf("config-validation"),
  );

  const envVars = factValues(profile, "env-var").length;
  if (envVars > 0) {
    rows.push({
      label: "Environment surface",
      value: `${envVars} ${plural(envVars, "variable")} read by the application`,
    });
  }

  const absences = (profile?.absences ?? [])
    .filter((absence) => ["container", "ci", "iac"].includes(absence.kind))
    .map((absence) => absence.kind);
  if (absences.length > 0) {
    rows.push({
      label: "Not present",
      value: `${listSentence(absences)} (searched for, not found)`,
    });
  }

  const framework0 = framework[0];
  const summary =
    framework0 === undefined
      ? "The stack could not be profiled for this run, so every domain mapping below is generic."
      : `${framework0}${router.length > 0 ? ` (${router.join(", ")} router)` : ""} on ${listSentence(factValues(profile, "language"))}, ${listSentence(factValues(profile, "data-layer"))} over ${listSentence(factValues(profile, "database-engine")) || "an unidentified database"}.`;

  return { summary, rows, warnings: profile?.warnings ?? [] };
}

/** The appendix: everything a reader needs to reproduce or distrust the run. */
function buildAppendix(input: ReportInput, runId: string, target: string): AppendixView {
  const scan = input.scan;
  const audit = input.audit;
  const run: { label: string; value: string }[] = [
    { label: "Run id", value: runId },
    { label: "Target", value: target },
    { label: "Schema version", value: input.findings.schemaVersion },
  ];
  if (input.run.sentinelVersion !== undefined) {
    run.push({ label: "Sentinel version", value: input.run.sentinelVersion });
  }
  if (scan !== undefined) {
    run.push({
      label: "Phase 1 (scan)",
      value: `${formatDuration(scan.durationMs)}${scan.aborted ? ", aborted" : ""}, ${scan.steps.length} steps`,
    });
  }
  if (audit !== undefined) {
    run.push({
      label: "Phase 4 (audit)",
      value: `${formatDuration(audit.durationMs)}${audit.aborted ? ", aborted" : ""}, ${audit.batches.length} batches, ${audit.units.audited}/${audit.units.total} units`,
    });
  }
  if (input.inventory !== undefined) {
    run.push({
      label: "Inventory",
      value: `${input.inventory.units.length} units from ${input.inventory.enumerators.length} enumerators`,
    });
  }
  if (input.profile !== undefined) {
    run.push({
      label: "Profile scan",
      value: `${input.profile.scan.filesRead} of ${input.profile.scan.filesSeen} files read${input.profile.scan.truncated ? " (truncated)" : ""}`,
    });
  }

  const agent: { label: string; value: string }[] = [];
  if (audit !== undefined) {
    agent.push({ label: "Runtime", value: audit.runtime.kind });
    if (audit.runtime.model !== undefined)
      agent.push({ label: "Model", value: audit.runtime.model });
    agent.push({
      label: "Concurrency",
      value: `${audit.runtime.concurrency} in flight, up to ${audit.runtime.maxAttempts} attempts, ${formatDuration(audit.runtime.timeoutMs)} per dispatch`,
    });
    agent.push({
      label: "Dispatches",
      value: `${audit.dispatches} (${audit.retries} ${plural(audit.retries, "retry", "retries")})`,
    });
    agent.push({
      label: "Tokens",
      value: `${formatCount(audit.usage.inputTokens)} in, ${formatCount(audit.usage.outputTokens)} out, ${formatCount(audit.usage.cacheReadInputTokens)} cache read`,
    });
    agent.push({
      label: "Subscription",
      value: audit.quotaExhausted
        ? "a usage limit stopped the phase before every batch ran"
        : "no usage limit was reached",
    });
    if (audit.runtime.synthetic) {
      agent.push({
        label: "Synthetic run",
        value: "the audit answers came from a recorded transcript, not from a live model",
      });
    }
  }

  const verification: { label: string; value: string }[] = [
    {
      label: "Citations dropped",
      value: `${input.findings.droppedFindings} ${plural(input.findings.droppedFindings, "finding")} whose citation did not resolve on disk`,
    },
  ];
  if (scan !== undefined) {
    verification.push({
      label: "Phase 1 verification",
      value: `${scan.dropped.findings} findings and ${scan.dropped.evidence} evidence refs dropped, ${scan.relocated} relocated, ${scan.merged.length} merged, ${scan.escalations.length} escalated`,
    });
  }
  if (audit !== undefined) {
    verification.push({
      label: "Phase 4 verification",
      value: `${audit.dropped.unresolved} unresolved, ${audit.dropped.outOfSlice} outside the provided slices, ${audit.dropped.duplicates} duplicates, ${audit.dropped.strayVerdicts} stray verdicts`,
    });
  }

  const steps: StepLine[] = (scan?.steps ?? []).map((step) => ({
    step: step.step,
    status: step.status,
    ...(step.reason === undefined ? {} : { reason: step.reason }),
    findings: step.findings,
  }));

  return {
    run,
    agent,
    verification,
    tools: input.run.tools ?? [],
    steps,
    batches: [...(audit?.batches ?? [])],
  };
}

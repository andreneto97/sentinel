import { mergeCoverage } from "../audit/artifacts.ts";
import type { AuditResult } from "../audit/audit.ts";
import type { BatchPlan } from "../audit/batch.ts";
import {
  type AuditBound,
  type ResolvedAuditBudget,
  auditBudgetFrom,
  unboundedBound,
} from "../audit/budget.ts";
import { formatSkipGroups, groupSkipReasons } from "../audit/coverage.ts";
import { type AuditProgress, createProgressWriter } from "../audit/progress.ts";
import type { ConfigFileSystem, ResolvedAnalyzeOptions } from "../contracts/config.ts";
import {
  CONFIG_FILE_NAME,
  loadConfig,
  resolveAnalyzeOptions,
  saveConfig,
} from "../contracts/config.ts";
import type { AuditUnit, Coverage, Domain } from "../contracts/findings.ts";
import { DomainSchema, SCHEMA_VERSION } from "../contracts/findings.ts";
import type { DroppedUnit, EnumeratorReport, InventoryDocument } from "../contracts/inventory.ts";
import { AUDIT_UNIT_KINDS } from "../contracts/inventory.ts";
import type { StackProfile } from "../contracts/profile.ts";
import { StackProfileSchema } from "../contracts/profile.ts";
import type { Proposal, ProposalSet, ScopeDecision } from "../contracts/proposal.ts";
import type { AnalysisScope, ScopeUnitCounts } from "../contracts/scope.ts";
import {
  ANALYSIS_SCOPE_FILE,
  AnalysisScopeSchema,
  UNSCOPED_PHASES,
  buildAnalysisScope,
  countUnitsByKind,
  partitionUnits,
  renderScopePaths,
  resolveScopeSelectors,
} from "../contracts/scope.ts";
import type { Scorecard } from "../contracts/scorecard.ts";
import type { ProfileFileSystem } from "../profile/file-system-port.ts";
import { RepoSnapshot, profileStack, withAnalysisScope } from "../profile/index.ts";
import {
  buildScopeProposalDocument,
  createProposalContext,
  decideScope,
  formatCost,
  proposeScope,
  renderProposalList,
  renderScopeProposalJson,
  renderScopeSummary,
  toProfileView,
} from "../propose/index.ts";
import type { StepReport } from "../scan/artifacts.ts";
import type { ScanResult } from "../scan/scan.ts";
import type { Asker } from "./_shared/ask.ts";
import { loadRunArtifacts } from "./_shared/run-artifacts.ts";
import { createRunDir, createRunId } from "./_shared/run-dir.ts";
import type { AnalyzeInvocation, CliContext } from "./index.ts";
import { EXIT } from "./index.ts";
import { renderDossier, renderScorecardLines, writeDossier } from "./report.ts";

/**
 * `sentinel analyze` — phase 0 (profile), phase 0.5 (scope negotiation), phase 1
 * (the deterministic scan), phase 2 (the inventory) and phases 3-4 (batching and
 * the AI audit).
 *
 * This is the glue between modules that do not know about each other: the
 * profiler produces a `StackProfile`, the propose phase turns it into the gap
 * between what the repo contains and what the scope will check, the operator
 * answers, the scan runs exactly the steps that survived the answer, phase 2
 * enumerates every unit of audit, and phases 3 and 4 batch those units and ask
 * a model about each one.
 *
 * Three rules this command is responsible for, because nothing below it can be:
 *
 * - **The scope decision is honoured by every phase.** A domain the operator
 *   left out is not scanned, not audited, and is reported as `off` rather than
 *   as clean. Phase 4 is handed the same `enabledDomains` phase 1 got.
 * - **A phase that did not run says so.** `--no-ai` skips phases 3 and 4
 *   entirely and the summary prints the reason on the batch, verdict, finding
 *   and assurance lines. A crashed phase is reported and drops the exit code;
 *   it never leaves a shorter table that reads as a cleaner repository.
 * - **Coverage is merged, never overwritten.** Phase 1 counts steps and phase 4
 *   counts units; the domain table adds them through `mergeCoverage` so one row
 *   per domain still satisfies `audited + skipped === total`.
 *
 * - **Every run ends with a dossier.** Phases 6 and 7 run from `finish`, which
 *   is the single exit after phase 1, so a cancelled scan and a crashed audit
 *   produce a scored, rendered document about what did run instead of a bare
 *   directory of JSON. Rendering is free and reads only the run directory, so
 *   it cannot fail the run: a renderer that throws costs a warning.
 */

/** The phase 0 artifact, written beside the findings so a run is self-describing. */
export const STACK_PROFILE_FILE = "stack-profile.json";

/** The phase 0.5 artifact: what was offered, what was accepted, what stayed out. */
export const SCOPE_PROPOSAL_FILE = "scope-proposal.json";

/**
 * Zeroed unit counts, for a run that is scoped but has not enumerated yet.
 *
 * `analysis-scope.json` is written before phase 1 and rewritten once phase 2
 * has counted, so a run that dies in the middle still leaves a directory that
 * says which subtree it was about. A zero here is "not counted yet", and the
 * document it belongs to says so by being rewritten.
 */
function emptyUnitCounts(): ScopeUnitCounts {
  return { total: 0, inScope: 0, outOfScope: 0, byKind: [] };
}

/**
 * The filesystem surface analyze needs: the profiler's reads, the config file's,
 * the run dir's, and — for phases 6 and 7 — the bytes of a PDF.
 */
export interface AnalyzeFileSystem extends ProfileFileSystem, ConfigFileSystem {
  /** Creates the run directory and every missing parent. */
  mkdirp(path: string): Promise<void>;
  /** Widened over `ConfigFileSystem`'s: `report.pdf` is not text. */
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
}

/** What analyze hands phase 1 once the scope is settled. */
export interface ScanRequest {
  readonly runId: string;
  /** `<out>/<runId>`; `raw/` already exists under it. */
  readonly runDir: string;
  /** Absolute path of the repository to scan. */
  readonly targetDir: string;
  readonly profile: StackProfile;
  /**
   * The domains the scope decision turned on. A step contributing to none of
   * them is not planned, so an excluded domain costs nothing and is reported
   * as excluded rather than as clean.
   */
  readonly domains: readonly Domain[];
  /**
   * `--path`: the subtrees this run analyses, repo-relative. Empty is the whole
   * repository.
   *
   * Phase 1 still reads all of it — see `ScanOptions.scope` for why a lockfile,
   * a git history and a module graph have no meaningful subtree — and uses this
   * only to count how many of its findings came from files outside the scope.
   */
  readonly paths: readonly string[];
}

/**
 * Phase 1, injected.
 *
 * The scan needs the whole filesystem port, the process port, a tool resolver
 * and a logger; the composition root owns all four. Keeping it behind a
 * function means this command still takes the three-method filesystem the
 * profiler and the config file share, and a test can drive the command end to
 * end without a disk or a subprocess.
 */
export type ScanRunner = (request: ScanRequest) => Promise<ScanResult>;

/** What analyze hands phase 2. The same four fields every later phase gets. */
export interface InventoryRequest {
  readonly runId: string;
  readonly runDir: string;
  /** Absolute path of the repository to enumerate. Read, never written. */
  readonly targetDir: string;
  readonly profile: StackProfile;
  /**
   * `--path`: the subtrees this run analyses. Empty is the whole repository.
   *
   * Phase 2 is expected to enumerate the **whole** repository even when this is
   * set, and that is deliberate: enumerating is deterministic and costs seconds,
   * while the sentence a bounded run owes its reader — "the other units in this
   * repository were not analysed, and there are this many of them" — is only
   * sayable by a run that counted them. `analyze` partitions the result along this boundary and hands phase 4
   * the units inside it, which is where the hours were going. A runner that can
   * narrow its own work without losing the count may still read this.
   */
  readonly paths: readonly string[];
}

/** What phase 2 returned: the document, and the artifacts it left behind. */
export interface InventoryOutcome {
  readonly document: InventoryDocument;
  /** Absolute paths phase 2 wrote — `inventory.json`, and the schema model when there is one. */
  readonly artifacts: readonly string[];
  readonly durationMs: number;
}

/**
 * Phase 2, injected.
 *
 * Like phase 1: the enumerators need a process executor and a tool resolver for
 * ast-grep, and the composition root owns both. Behind a function, this command
 * still takes the four-method filesystem the profiler and the config file share,
 * and a test can drive all four phases without a subprocess.
 */
export type InventoryRunner = (request: InventoryRequest) => Promise<InventoryOutcome>;

/** What analyze hands phases 3 and 4 once the inventory exists. */
export interface AuditRequest {
  readonly runId: string;
  readonly runDir: string;
  readonly targetDir: string;
  readonly profile: StackProfile;
  /** Every unit phase 2 enumerated. Phase 4 must account for all of them. */
  readonly units: readonly AuditUnit[];
  /** The scope decision, so a batch for an excluded domain is never dispatched. */
  readonly domains: readonly Domain[];
  /** Batches in flight at once; `--max-parallel`. */
  readonly maxParallel: number;
  /**
   * How much of the in-scope inventory phase 4 may spend on a model.
   *
   * Resolved here rather than left to the runner, so that the ceiling the report
   * discloses and the ceiling the dispatch loop enforces are the same object.
   * `--path` decides *which* units are candidates; this decides how many of them
   * a throttled subscription actually gets through.
   */
  readonly budget: ResolvedAuditBudget;
  /**
   * Where phase 4 reports each finished batch, so the phase that takes an hour
   * is not the one phase that says nothing while it runs.
   *
   * Built here, from this run's output flags and the CLI's own two streams,
   * because the streams belong to the command and `src/audit/` is not allowed to
   * reach for them. Absent under `--quiet`, which is what turns the reporting
   * off rather than formatting lines nobody will see. The runner forwards it to
   * `runAudit`'s `progress` option; see `src/audit/progress.ts`.
   */
  readonly progress?: AuditProgress | undefined;
}

/**
 * What phases 3 and 4 returned.
 *
 * The plan comes back beside the result because phase 4's planner seam returns
 * batches and nothing else, and the units phase 3 deliberately did not batch —
 * a kind no model audits, a file that no longer reads — are a line in the
 * summary, not something to drop on the floor.
 */
export interface AuditOutcome {
  readonly result: AuditResult;
  /** The full plan phase 3 produced, when the planner exposed it. */
  readonly plan: BatchPlan | undefined;
}

/** Phases 3 and 4, injected: the batch plan and the AI audit over it. */
export type AuditRunner = (request: AuditRequest) => Promise<AuditOutcome>;

/** Everything the command reaches outside itself; the CLI passes the real ones. */
export interface AnalyzeDeps {
  readonly fs: AnalyzeFileSystem;
  /**
   * Tools resolvable right now. A proposal whose tool is missing defaults off
   * and is reported as blocked instead of silently doing nothing.
   */
  readonly availableTools: () => Promise<readonly string[]>;
  /** Runs phase 1 over the negotiated scope. */
  readonly scan: ScanRunner;
  /** Runs phase 2 over the whole target. */
  readonly inventory: InventoryRunner;
  /** Runs phases 3 and 4. Never called under `--no-ai`. */
  readonly audit: AuditRunner;
  /** Asks the operator one question; absent means non-interactive (nothing is asked). */
  readonly ask?: Asker | undefined;
}

/** The phase 1 section of `--json`: what ran, what it cost, and what it found. */
export interface AnalyzeScanJson {
  readonly runId: string;
  readonly runDir: string;
  /** True when the run was cancelled before every step finished. */
  readonly aborted: boolean;
  readonly durationMs: number;
  readonly steps: readonly StepReport[];
  readonly findings: number;
  /** Finding count per domain, including the enabled domains that found nothing. */
  readonly byDomain: Readonly<Record<string, number>>;
  /**
   * Per-domain coverage, so a `byDomain` zero can be told apart from a domain
   * phase 1 has no step for — that one reads `unitsTotal: 0`.
   */
  readonly coverage: readonly Coverage[];
  /** Domains the scope left out; nothing was checked in them. */
  readonly domainsOff: readonly Domain[];
  /** Findings a step produced for a domain outside the scope, counted and dropped. */
  readonly outOfScope: number;
  /** Findings whose citation did not resolve on disk. */
  readonly droppedFindings: number;
  readonly artifacts: readonly string[];
}

/** The phase 2 section of `--json`: what was enumerated, and what was lost. */
export interface AnalyzeInventoryJson {
  readonly units: number;
  /** Count per unit kind, every kind present, in contract order. */
  readonly byKind: Readonly<Record<string, number>>;
  /** Units whose citation did not resolve on disk, or that two enumerators claimed. */
  readonly dropped: number;
  readonly enumerators: readonly EnumeratorReport[];
  readonly durationMs: number;
  readonly artifacts: readonly string[];
}

/** The phase 3/4 section of `--json`: what was asked, answered and kept. */
export interface AnalyzeAuditJson {
  /** True when phases 3 and 4 did not run at all; `reason` says why. */
  readonly skipped: boolean;
  readonly reason?: string;
  /** Batches phase 3 planned, before the scope filter. */
  readonly batchesPlanned: number;
  /** Batches phase 4 dispatched, and how many came back usable. */
  readonly batchesRun: number;
  readonly batchesFailed: number;
  /** Units phase 3 deliberately did not batch, with phase 3's own reasons. */
  readonly unitsNotBatched: number;
  readonly unitsAudited: number;
  readonly unitsTotal: number;
  readonly findings: number;
  readonly assurances: number;
  /** Agent claims Sentinel refused: unresolvable citations, and out-of-slice ones. */
  readonly droppedFindings: number;
  readonly aborted: boolean;
  readonly durationMs: number;
  readonly artifacts: readonly string[];
  /** Disclosures about the plan itself: trimmed context, shared files not quoted. */
  readonly notes: readonly string[];
  /**
   * What the run's ceilings left unaudited, and the sentence that says so.
   *
   * On the `--json` surface for the same reason it is in the terminal: a
   * consumer that reads `unitsAudited` and `unitsTotal` without this field can
   * compute the gap but cannot tell a budget from forty failed batches.
   */
  readonly bound: AuditBound;
}

/** What `--json` prints: the profile's own summary, the negotiated scope, and each phase. */
export interface AnalyzeProposalJson {
  readonly schemaVersion: string;
  readonly target: string;
  readonly proposeOnly: boolean;
  readonly profile: {
    readonly facts: StackProfile["facts"];
    readonly absences: StackProfile["absences"];
    readonly warnings: readonly string[];
    readonly scan: StackProfile["scan"];
  };
  readonly proposals: ProposalSet["proposals"];
  readonly notApplicable: ProposalSet["notApplicable"];
  readonly decision: ScopeDecision;
  /**
   * `--path`: which subtree the run analysed, and what that left out.
   *
   * Always present, including on a whole-repository run, where it says so —
   * a consumer that has to check whether the key exists before it can tell a
   * bounded run from a complete one is a consumer that will forget.
   */
  readonly analysisScope: AnalysisScope;
  /** Absent when no scan ran: `--propose-only` or `--skip-scan`. */
  readonly scan?: AnalyzeScanJson;
  /** Absent when phase 2 did not run or crashed. */
  readonly inventory?: AnalyzeInventoryJson;
  /** Absent when phase 2 never produced units for it to consume. */
  readonly audit?: AnalyzeAuditJson;
  /** Per-domain coverage with every phase's contribution added together. */
  readonly coverage?: readonly Coverage[];
  /** Phase 6's scorecard. Absent when the dossier could not be rendered. */
  readonly scorecard?: Scorecard;
  /** The dossier files phase 7 wrote, absolute. */
  readonly report?: readonly string[];
}

/** One line per fact kind: `framework  express, fastify`, capped for the terminal. */
function renderProfileSummary(profile: StackProfile, verbose: boolean): string {
  const byKind = new Map<string, string[]>();
  for (const fact of profile.facts) {
    const values = byKind.get(fact.kind) ?? [];
    values.push(fact.detail === undefined ? fact.value : `${fact.value} (${fact.detail})`);
    byKind.set(fact.kind, values);
  }
  const width = [...byKind.keys()].reduce((max, kind) => Math.max(max, kind.length), 0);
  const limit = verbose ? Number.POSITIVE_INFINITY : 4;
  const lines = [...byKind.entries()].map(([kind, values]) => {
    const shown = values.slice(0, limit);
    const rest = values.length - shown.length;
    const text = rest > 0 ? `${shown.join(", ")} and ${rest} more` : shown.join(", ");
    return `  ${kind.padEnd(width)}  ${text}`;
  });
  const scan = `${profile.scan.filesSeen} file(s) seen, ${profile.scan.filesRead} read${
    profile.scan.truncated ? " (scan hit its limits)" : ""
  }`;
  return [
    `Profiled ${profile.target}`,
    `  ${scan}`,
    "",
    lines.length === 0 ? "  (no stack facts detected)" : lines.join("\n"),
    ...(profile.warnings.length > 0 ? ["", ...profile.warnings.map((w) => `  warning: ${w}`)] : []),
  ].join("\n");
}

/**
 * Workspace package name to repo-relative directory, from the profile's facts.
 *
 * This is what lets `--path @acme/api` mean the directory that package lives
 * in. Phase 0 records a `workspace-package` fact per non-root manifest, whose
 * value is the directory and whose detail is the declared name; a package
 * without a name is keyed by its directory so it is still addressable.
 */
function workspacePackages(profile: StackProfile): Record<string, string> {
  const packages: Record<string, string> = {};
  for (const fact of profile.facts) {
    if (fact.kind !== "workspace-package") continue;
    packages[fact.detail ?? fact.value] = fact.value;
  }
  return packages;
}

/**
 * The `--path` block, printed before anything else a scoped run says.
 *
 * Three things, in this order: what was analysed, what that leaves out, and
 * which phases ignored the boundary anyway. A reader who stops after the first
 * line has still been told the run was narrowed; a reader who stops after the
 * second has been told what it cost. Nothing below this point in the run has to
 * repeat the caveat for the output to be honest — but the footer, the artifact
 * and the dossier repeat it anyway, because the terminal scrolls.
 */
function renderScopeBanner(scope: AnalysisScope, profile: StackProfile): string {
  const files = profile.analysis;
  const covered =
    files === undefined
      ? `  ${renderScopePaths(scope.paths)}`
      : `  ${renderScopePaths(scope.paths)}  —  ${files.filesInScope} of ${files.filesTotal} files in this repository`;

  const selectors = scope.selectors
    .filter((entry) => entry.note !== undefined)
    .map((entry) => `    ${entry.selector} -> ${renderScopePaths(entry.paths)} (${entry.note})`);

  return [
    "Analysis scope — this run was narrowed with --path",
    covered,
    ...selectors,
    "",
    "  What --path does not narrow, and why:",
    ...UNSCOPED_PHASES.map((entry) => `    ${entry.phase}: ${entry.reason}`),
  ].join("\n");
}

/**
 * What a scoped run has to say once the numbers exist.
 *
 * The statement is the artifact's own sentence, printed verbatim rather than
 * rebuilt, so the terminal, `analysis-scope.json`, the markdown and the PDF
 * cover cannot end up disagreeing about how much of the repository this run
 * actually looked at.
 */
function renderScopeNotes(scope: AnalysisScope): string[] {
  if (scope.wholeRepository) return [];
  const notes = [`  ${scope.statement}`];
  if (scope.findingsOutside > 0) {
    const one = scope.findingsOutside === 1;
    notes.push(
      [
        `  ${plural(scope.findingsOutside, "finding")} below ${one ? "is" : "are"}`,
        `in files outside ${renderScopePaths(scope.paths)}:`,
        `the whole-repository analyzers found ${one ? "it" : "them"} and`,
        `${one ? "it is" : "they are"} reported, but nothing else about those files was analysed`,
      ].join(" "),
    );
  }
  return notes;
}

/** The `not applicable` block: categories Sentinel declares it will not check. */
function renderNotApplicable(set: ProposalSet): string {
  if (set.notApplicable.length === 0) return "";
  const lines = set.notApplicable.map((entry) => `  - ${entry.category}: ${entry.reason}`);
  return [
    "",
    `Declared not applicable (${set.notApplicable.length}) — nothing here can be checked in this repo:`,
    ...lines,
  ].join("\n");
}

/** The question one proposal asks, with the price of saying yes. */
function questionFor(proposal: Proposal): string {
  return `  Analyse this too? ${proposal.title} (${formatCost(proposal.cost)})`;
}

/** Answers collected from the operator, as `decideScope` selectors. */
interface Answers {
  readonly include: readonly string[];
  readonly exclude: readonly string[];
}

/**
 * Asks about every proposal the flags and the config file left unanswered.
 * Already-answered proposals are skipped: re-asking a remembered answer would
 * make `sentinel.config.json` pointless.
 */
async function askAboutProposals(
  ask: Asker,
  set: ProposalSet,
  options: ResolvedAnalyzeOptions,
): Promise<Answers> {
  const decided = new Set<string>([
    ...options.scope.include,
    ...options.scope.exclude,
    ...Object.keys(options.scope.previousAnswers),
  ]);
  const include: string[] = [];
  const exclude: string[] = [];
  for (const proposal of set.proposals) {
    if (decided.has(proposal.id)) continue;
    const accepted = await ask(questionFor(proposal), proposal.defaultAnswer === "on");
    (accepted ? include : exclude).push(proposal.id);
  }
  return { include, exclude };
}

// ---------------------------------------------------------------------------
// Phase 1 reporting
// ---------------------------------------------------------------------------

/** Status marker per step: aligned, and readable without colour. */
const STEP_MARK: Readonly<Record<string, string>> = {
  ok: "[ ok ]",
  degraded: "[warn]",
  skipped: "[skip]",
  failed: "[fail]",
};

/** Milliseconds a human reads at a glance: `840ms`, `12.4s`, `3m 05s`. */
export function formatMillis(ms: number): string {
  if (ms < 1_000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1_000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1_000);
  return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
}

/**
 * `1 finding` / `4 findings` — the plural is not worth an inline ternary each
 * time. A noun ending in a sibilant takes `-es`, so `batch` does not print as
 * `batchs`.
 */
export function plural(count: number, noun: string): string {
  if (count === 1) return `${count} ${noun}`;
  return `${count} ${noun}${/(?:s|x|z|ch|sh)$/.test(noun) ? "es" : "s"}`;
}

/**
 * One line per planned step: how it ended, what it contributed, how long it
 * took, and — for anything that is not `ok` — the step's own sentence about
 * why. A step that ran and found nothing is not the same as one that never
 * ran, and this is the line where the difference has to be visible.
 */
function renderStepSummary(result: ScanResult): string {
  const width = result.outcomes.reduce((max, outcome) => Math.max(max, outcome.step.length), 0);
  const lines = result.outcomes.map((outcome) => {
    const mark = STEP_MARK[outcome.status] ?? `[${outcome.status}]`;
    const counted = plural(outcome.findings.length, "finding").padStart(12);
    const duration = formatMillis(outcome.durationMs).padStart(7);
    const reason =
      outcome.status === "ok" || outcome.reason === undefined ? "" : `  ${outcome.reason}`;
    return `  ${mark}  ${outcome.step.padEnd(width)}  ${counted}  ${duration}${reason}`;
  });
  return [
    `Scan ${result.runId} — ${plural(result.outcomes.length, "step")} in ${formatMillis(result.durationMs)}`,
    ...lines,
  ].join("\n");
}

/** Findings per domain, including the enabled domains that produced none. */
function countByDomain(findings: readonly { readonly domain: Domain }[]): Map<Domain, number> {
  const counts = new Map<Domain, number>();
  for (const finding of findings) {
    counts.set(finding.domain, (counts.get(finding.domain) ?? 0) + 1);
  }
  return counts;
}

/**
 * The per-domain block.
 *
 * Every domain in the contract gets a line, including the ones the scope left
 * out: a domain that was off has to say it was off. Reporting it by omission —
 * or as `0 findings` — would be indistinguishable from a domain that was
 * checked and came back clean, which is the one confusion this whole command
 * exists to prevent.
 */
function renderDomainCounts(
  coverage: readonly Coverage[],
  findings: readonly { readonly domain: Domain }[],
  enabled: readonly Domain[],
): string {
  const counts = countByDomain(findings);
  const on = new Set<Domain>(enabled);
  const width = DomainSchema.options.reduce((max, domain) => Math.max(max, domain.length), 0);

  const lines = DomainSchema.options.map((domain) => {
    const name = domain.padEnd(width);
    if (!on.has(domain)) {
      return `  ${name}  off — outside this run's scope, so nothing in it was checked`;
    }
    const row = coverage.find((entry) => entry.domain === domain);
    if (row === undefined || row.unitsTotal === 0) {
      return `  ${name}  on, but no phase has a check for it yet — nothing in it was checked`;
    }
    const counted = plural(counts.get(domain) ?? 0, "finding");
    const checks = `${row.unitsAudited}/${row.unitsTotal} checked`;
    const gap = row.unitsTotal - row.unitsAudited;
    const skipped = gap > 0 ? `  (${gap} not checked)` : "";
    return `  ${name}  ${counted.padEnd(14)}  ${checks.padEnd(16)}${skipped}`;
  });

  return ["Domains", ...lines].join("\n");
}

/**
 * The closing block: what was discarded, and what was written.
 *
 * `findings` is the run's final count — phase 4 merges its own into
 * `findings.json` — so this footer is written once, after the last phase, and
 * never from phase 1's number alone.
 */
function renderRunFooter(input: {
  readonly scan: ScanResult;
  readonly runDirPath: string;
  readonly findings: number;
  readonly artifacts: readonly string[];
  readonly droppedFindings: number;
  /** What `--path` left out, in the scope document's own words; empty when unscoped. */
  readonly scopeNotes: readonly string[];
}): string {
  const notes: string[] = [...input.scopeNotes];
  if (input.scan.outOfScope > 0) {
    notes.push(
      `  ${plural(input.scan.outOfScope, "finding")} belonged to a domain this run left out and ${
        input.scan.outOfScope === 1 ? "was" : "were"
      } discarded`,
    );
  }
  if (input.droppedFindings > 0) {
    notes.push(
      `  ${plural(input.droppedFindings, "finding")} cited a file or line that does not resolve on disk, or code that was never provided, and ${
        input.droppedFindings === 1 ? "was" : "were"
      } dropped`,
    );
  }
  if (input.scan.aborted) notes.push("  the run was cancelled before every step finished");

  return [
    ...(notes.length > 0 ? ["", ...notes] : []),
    "",
    `Wrote ${input.runDirPath}`,
    `  ${plural(input.findings, "finding")} in findings.json, ${plural(input.artifacts.length, "artifact")} in total`,
  ].join("\n");
}

/** Builds the `--json` phase 1 section from the scan's own result. */
function scanJson(
  result: ScanResult,
  enabled: readonly Domain[],
  runDirPath: string,
): AnalyzeScanJson {
  const counts = countByDomain(result.findings);
  const on = new Set<Domain>(enabled);
  return {
    runId: result.runId,
    runDir: runDirPath,
    aborted: result.aborted,
    durationMs: result.durationMs,
    steps: result.report.steps,
    findings: result.findings.length,
    byDomain: Object.fromEntries(
      DomainSchema.options.filter((domain) => on.has(domain)).map((d) => [d, counts.get(d) ?? 0]),
    ),
    coverage: result.coverage,
    domainsOff: DomainSchema.options.filter((domain) => !on.has(domain)),
    outOfScope: result.outOfScope,
    droppedFindings: result.document.droppedFindings,
    artifacts: result.artifacts,
  };
}

// ---------------------------------------------------------------------------
// Phase 2 reporting
// ---------------------------------------------------------------------------

/** Units per kind, in contract order, with the kinds that found nothing omitted. */
function renderUnitCounts(document: InventoryDocument): string {
  const width = AUDIT_UNIT_KINDS.reduce((max, kind) => Math.max(max, kind.length), 0);
  const lines = AUDIT_UNIT_KINDS.filter((kind) => (document.counts[kind] ?? 0) > 0).map((kind) => {
    const count = document.counts[kind] ?? 0;
    return `  ${kind.padEnd(width)}  ${String(count).padStart(5)}`;
  });
  return lines.length === 0 ? "  (no units were enumerated)" : lines.join("\n");
}

/**
 * The enumerators that did not simply work.
 *
 * A skipped enumerator is the normal case — most repositories have no queue
 * consumer — and it carries the sentence that says so. It is reported because
 * "no queue consumers exist here" and "the queue enumerator never ran" are
 * different claims, and only the enumerator knows which one it is making.
 */
function renderEnumeratorNotes(document: InventoryDocument, verbose: boolean): string[] {
  const notable = document.enumerators.filter(
    (entry) => entry.status === "failed" || (verbose && entry.status !== "ok"),
  );
  return notable.map((entry) => {
    const reason = entry.reason === undefined ? "" : `: ${entry.reason}`;
    return `  [${entry.status}] ${entry.name}${reason}`;
  });
}

/** One line per unit phase 2 refused to keep, capped so a broken repo cannot flood. */
function renderDroppedUnits(dropped: readonly DroppedUnit[]): string[] {
  if (dropped.length === 0) return [];
  const shown = dropped.slice(0, 5);
  const lines = shown.map(
    (entry) =>
      `    ${entry.kind} at ${entry.location.file}:${entry.location.line} (${entry.enumerator}): ${entry.reason}`,
  );
  const rest = dropped.length - shown.length;
  return [
    `  ${plural(dropped.length, "unit")} did not survive verification and ${
      dropped.length === 1 ? "was" : "were"
    } dropped:`,
    ...lines,
    ...(rest > 0 ? [`    and ${rest} more`] : []),
  ];
}

/** The whole phase 2 block. */
function renderInventorySummary(outcome: InventoryOutcome, verbose: boolean): string {
  const { document } = outcome;
  return [
    `Inventory — ${plural(document.units.length, "unit")} in ${formatMillis(outcome.durationMs)}`,
    renderUnitCounts(document),
    ...renderEnumeratorNotes(document, verbose),
    ...renderDroppedUnits(document.dropped),
  ].join("\n");
}

/** Builds the `--json` phase 2 section. */
function inventoryJson(outcome: InventoryOutcome): AnalyzeInventoryJson {
  return {
    units: outcome.document.units.length,
    byKind: outcome.document.counts,
    dropped: outcome.document.dropped.length,
    enumerators: outcome.document.enumerators,
    durationMs: outcome.durationMs,
    artifacts: outcome.artifacts,
  };
}

// ---------------------------------------------------------------------------
// Phase 3 and 4 reporting
// ---------------------------------------------------------------------------

/** Units per kind that came back with a verdict: the `200/200 handlers` line. */
function renderKindCoverage(result: AuditResult): string[] {
  const width = result.kinds.reduce((max, row) => Math.max(max, row.kind.length), 0);
  return result.kinds
    .filter((row) => row.unitsTotal > 0)
    .map((row) => {
      const ratio = `${row.unitsAudited}/${row.unitsTotal}`;
      return `    ${row.kind.padEnd(width)}  ${ratio.padStart(9)} audited`;
    });
}

/** The whole phase 3 + 4 block, for a run where they actually ran. */
function renderAuditSummary(outcome: AuditOutcome, verbose: boolean): string {
  const { result, plan } = outcome;
  const failed = result.batches.filter((batch) => batch.status === "failed").length;
  const partial = result.batches.filter((batch) => batch.status === "partial").length;
  const notBatched = plan?.skipped.length ?? 0;

  const head = [
    `Audit — ${plural(result.batches.length, "batch")} in ${formatMillis(result.durationMs)}`,
    `  batches     ${result.batches.length - failed} usable, ${failed} failed${
      partial > 0 ? `, ${partial} partial` : ""
    }`,
    `  verdicts    ${result.units.audited}/${result.units.total} units audited`,
    ...renderKindCoverage(result),
    `  findings    ${result.findings.length} kept${
      result.dropped.unresolved + result.dropped.outOfSlice > 0
        ? `, ${result.dropped.unresolved} unresolvable and ${result.dropped.outOfSlice} out-of-slice claim(s) refused`
        : ""
    }`,
    `  assurances  ${result.assurances.length}`,
    // The bound, on its own line and always: a run that stopped at its budget
    // and does not say so in the terminal is the failure this sentence exists to
    // prevent. On a complete run it reads "all N units were audited; the run
    // reached no budget", which is the same disclosure with nothing to disclose.
    `  bound       ${result.bound.statement}`,
  ];

  const notes: string[] = [];
  if (notBatched > 0) {
    notes.push(
      `  ${plural(notBatched, "unit")} ${
        notBatched === 1 ? "was" : "were"
      } not batched, so no model looked at ${notBatched === 1 ? "it" : "them"}:`,
    );
    for (const reason of summariseSkips(plan?.skipped ?? [])) notes.push(`    ${reason}`);
  }
  for (const batch of result.batches) {
    if (batch.status === "failed") {
      notes.push(
        `  batch ${batch.batchId} failed (${batch.failure}): ${batch.reason ?? "no reason"}`,
      );
    }
  }
  if (verbose) {
    notes.push(`  ordering: ${result.bound.ordering}`);
    for (const note of plan?.notes ?? []) notes.push(`  ${note}`);
  }
  if (result.stats.quotaExhausted) {
    notes.push(
      "  the subscription's usage limit was reached; the batches after it were not dispatched",
    );
  }

  return [...head, ...notes].join("\n");
}

/** Groups phase 3's per-unit skip reasons into one line each, with a count. */
function summariseSkips(skipped: readonly { readonly reason: string }[]): string[] {
  return formatSkipGroups(groupSkipReasons(skipped));
}

/** Builds the `--json` phase 3/4 section for a run where they ran. */
function auditJson(outcome: AuditOutcome): AnalyzeAuditJson {
  const { result, plan } = outcome;
  const failed = result.batches.filter((batch) => batch.status === "failed").length;
  return {
    skipped: false,
    batchesPlanned: plan?.batches.length ?? result.batches.length,
    batchesRun: result.batches.length,
    batchesFailed: failed,
    unitsNotBatched: plan?.skipped.length ?? 0,
    unitsAudited: result.units.audited,
    unitsTotal: result.units.total,
    findings: result.findings.length,
    assurances: result.assurances.length,
    droppedFindings: result.dropped.unresolved + result.dropped.outOfSlice,
    aborted: result.aborted,
    durationMs: result.durationMs,
    artifacts: result.artifacts,
    notes: plan?.notes ?? [],
    bound: result.bound,
  };
}

/** The `--json` phase 3/4 section for a run where they did not run at all. */
function skippedAuditJson(reason: string): AnalyzeAuditJson {
  return {
    skipped: true,
    reason,
    batchesPlanned: 0,
    batchesRun: 0,
    batchesFailed: 0,
    unitsNotBatched: 0,
    unitsAudited: 0,
    unitsTotal: 0,
    findings: 0,
    assurances: 0,
    droppedFindings: 0,
    aborted: false,
    durationMs: 0,
    artifacts: [],
    notes: [],
    // Nothing ran, so nothing was bounded: an unbounded bound over zero units,
    // rather than a missing field a consumer would have to special-case.
    bound: unboundedBound(0, 0),
  };
}

/**
 * The phase 3/4 block for a run that skipped them.
 *
 * Every line the audit would have filled is printed with the reason instead of
 * a number. A `--no-ai` run that simply omitted this block would be
 * indistinguishable from one where a model audited everything and found nothing.
 */
function renderSkippedAudit(reason: string, units: number): string {
  return [
    `Audit — skipped (${reason})`,
    "  batches     none planned; batching exists only to feed the audit",
    `  verdicts    0/${units} units audited`,
    "  findings    none from a model; the findings above are the analyzers' own",
    "  assurances  none; an assurance is a model's answer that Sentinel verified",
  ].join("\n");
}

/**
 * An accepted proposal whose tool is missing.
 *
 * `decideScope` can tell that the work cannot run, but only the command can
 * say it out loud: accepting a check and then not running it has to be a line
 * on stderr, never a silent gap in the coverage table.
 */
function blockedNote(proposalId: string, tool: string): string {
  return `sentinel: ${proposalId} was accepted but ${tool} is not installed; that work did not run. Install it with \`sentinel setup\`.\n`;
}

/** Two-space JSON with a trailing newline, matching every other artifact. */
function serialise(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/** Resolve the target, profile it, propose the gap, scan what survived, and report. */
export async function analyzeCommand(
  context: CliContext,
  invocation: AnalyzeInvocation,
  deps: AnalyzeDeps,
): Promise<number> {
  const loaded = await loadConfig(deps.fs, invocation.target);
  if (loaded.status === "invalid") {
    context.writeError(`sentinel: ${loaded.path} is unusable: ${loaded.error}\n`);
    return EXIT.preflight;
  }
  const options = resolveAnalyzeOptions({
    target: invocation.target,
    cwd: invocation.cwd,
    flags: invocation.flags,
    config: loaded.config,
  });

  if (!(await deps.fs.exists(options.target))) {
    context.writeError(`sentinel: ${options.target} does not exist\n`);
    return EXIT.preflight;
  }
  try {
    await deps.fs.readDir(options.target);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    context.writeError(`sentinel: ${options.target} is not a readable directory (${reason})\n`);
    return EXIT.preflight;
  }

  // One walk, shared: the profiler reads the whole repository from it, and the
  // `--path` resolution below needs the same listing to tell `apps/api` from a
  // typo and to count the files on each side of the boundary.
  const snapshot = await RepoSnapshot.create(deps.fs, options.target);
  const profiled = await profileStack(deps.fs, options.target, { snapshot });

  // `--path` is resolved after the profile because a selector may be a
  // workspace package name, and the packages are something phase 0 proves.
  const resolvedScope = await resolveScopeSelectors(options.pathSelectors, {
    // A directory of the repository as the walk sees it: `node_modules` and the
    // other ignored trees do not exist for this purpose, which is the same
    // repository every other phase is looking at.
    isDirectory: async (candidate) =>
      snapshot.allFiles.some((file) => file === candidate || file.startsWith(`${candidate}/`)),
    workspaces: workspacePackages(profiled),
  });

  if (resolvedScope.unmatched.length > 0) {
    // Nothing is guessed. A `--path` that matched nothing would otherwise
    // either analyse the whole repository or analyse nothing at all, and both
    // of those are a run whose scope line is a lie.
    for (const selector of resolvedScope.unmatched) {
      context.writeError(
        [
          `sentinel: --path ${selector}: no such directory in ${options.target},`,
          "and no workspace package or project by that name.",
          "Pass a repo-relative directory, a workspace package name, or a glob.\n",
        ].join(" "),
      );
    }
    return EXIT.preflight;
  }

  const scopePaths = resolvedScope.paths;
  const profile = withAnalysisScope(profiled, snapshot, scopePaths);
  const availableTools = await deps.availableTools();
  const set = proposeScope(
    createProposalContext({
      profile: toProfileView(profile),
      availableTools,
      // Phase 0.5 takes one path, so it only gets the scope when the scope is
      // one path: with several, every workspace package would read as outside
      // whichever one was picked, and the proposals would be about the wrong
      // boundary. The scope banner names the excluded work either way.
      analysedPath: scopePaths.length === 1 ? (scopePaths[0] ?? ".") : ".",
    }),
  );

  // Asking is the point of phase 0.5, but only a human can answer: no TTY, a
  // machine-readable run, `--yes` or `--propose-only` all skip the questions.
  const interactive =
    deps.ask !== undefined &&
    !options.proposeOnly &&
    !options.json &&
    !options.quiet &&
    !options.scope.acceptDefaults &&
    set.proposals.length > 0;

  const speaks = !options.json && !options.quiet;

  /** The scope document, rebuilt as each phase learns more about it. */
  const scopeDocument = (input: {
    readonly runId: string;
    readonly units: ScopeUnitCounts;
    readonly findingsOutside: number;
  }): AnalysisScope =>
    buildAnalysisScope({
      runId: input.runId,
      target: options.target,
      paths: scopePaths,
      selectors: resolvedScope.selectors,
      unmatched: resolvedScope.unmatched,
      units: input.units,
      unscopedPhases: scopePaths.length === 0 ? [] : UNSCOPED_PHASES,
      findingsOutside: input.findingsOutside,
    });

  /**
   * The scope as currently known. Reassigned — never mutated — as the run id
   * appears, phase 1 counts the findings outside the boundary and phase 2
   * counts the units on each side of it. Everything that prints or writes the
   * scope reads this, so there is one version of the claim per moment.
   */
  let analysisScope = scopeDocument({
    runId: "not-started",
    units: emptyUnitCounts(),
    findingsOutside: 0,
  });

  if (speaks) {
    context.write(`${renderProfileSummary(profile, options.verbose)}\n\n`);
    if (scopePaths.length > 0) {
      context.write(`${renderScopeBanner(analysisScope, profile)}\n\n`);
    }
    context.write(`${renderProposalList([...set.proposals])}\n`);
    const notApplicable = renderNotApplicable(set);
    if (notApplicable !== "") context.write(`${notApplicable}\n`);
    if (interactive) context.write("\n");
  }

  const answers =
    interactive && deps.ask !== undefined
      ? await askAboutProposals(deps.ask, set, options)
      : { include: [], exclude: [] };

  const decision = decideScope(set, {
    include: [...options.scope.include, ...answers.include],
    exclude: [...options.scope.exclude, ...answers.exclude],
    acceptDefaults: options.scope.acceptDefaults,
    previousAnswers: options.scope.previousAnswers,
    domainOverrides: options.scope.domainOverrides,
    availableTools,
  });

  if (speaks) context.write(`\n${renderScopeSummary(decision)}\n`);

  /** Everything `--json` prints beyond the profile and the scope; filled as phases finish. */
  interface PhaseSections {
    readonly scan?: AnalyzeScanJson;
    readonly inventory?: AnalyzeInventoryJson;
    readonly audit?: AnalyzeAuditJson;
    readonly coverage?: readonly Coverage[];
    readonly scorecard?: Scorecard;
    readonly report?: readonly string[];
  }

  /** The `--json` document, emitted once, with whichever phase sections ran. */
  const emitJson = (phases: PhaseSections = {}): void => {
    if (!options.json) return;
    const payload: AnalyzeProposalJson = {
      schemaVersion: SCHEMA_VERSION,
      target: options.target,
      proposeOnly: options.proposeOnly,
      profile: {
        facts: profile.facts,
        absences: profile.absences,
        warnings: profile.warnings,
        scan: profile.scan,
      },
      proposals: set.proposals,
      notApplicable: set.notApplicable,
      decision,
      analysisScope,
      ...(phases.scan === undefined ? {} : { scan: phases.scan }),
      ...(phases.inventory === undefined ? {} : { inventory: phases.inventory }),
      ...(phases.audit === undefined ? {} : { audit: phases.audit }),
      ...(phases.coverage === undefined ? {} : { coverage: phases.coverage }),
      ...(phases.scorecard === undefined ? {} : { scorecard: phases.scorecard }),
      ...(phases.report === undefined ? {} : { report: phases.report }),
    };
    context.write(serialise(payload));
  };

  if (options.proposeOnly) {
    emitJson();
    if (speaks) {
      context.write(
        "\n--propose-only: nothing was analysed and nothing was written. " +
          "Re-run without it, or answer with --include/--exclude/--yes.\n",
      );
    }
    return EXIT.ok;
  }

  if (options.skipScan) {
    emitJson();
    // Honest rather than convenient: the later phases that could consume a
    // previous run's raw output are not wired, so there is nothing for
    // `--skip-scan` to reuse and nothing was produced.
    context.writeError(
      "sentinel: --skip-scan: phase 1 did not run, so no findings were produced and no run " +
        "directory was written. The phases that would reuse a previous run's raw output are " +
        'not wired yet — see PLAN.md ("Build order").\n',
    );
    return EXIT.ok;
  }

  const runId = createRunId(context.clock, context.random);
  const runDir = await createRunDir(deps.fs, { outDir: options.outDir, runId });
  await deps.fs.writeFile(
    runDir.artifact(STACK_PROFILE_FILE),
    serialise(StackProfileSchema.parse(profile)),
  );
  await deps.fs.writeFile(
    runDir.artifact(SCOPE_PROPOSAL_FILE),
    renderScopeProposalJson(
      buildScopeProposalDocument({ runId, target: options.target, decision }),
    ),
  );

  analysisScope = scopeDocument({ runId, units: emptyUnitCounts(), findingsOutside: 0 });

  /**
   * Writes `analysis-scope.json`.
   *
   * Written before phase 1 and rewritten whenever the numbers improve, because
   * every exit after this point has to leave a run directory that says which
   * subtree it was about — including the ones that end early. The write is
   * atomic through the port, so a rewrite can never leave half a document.
   */
  const writeScope = async (): Promise<string> => {
    const path = runDir.artifact(ANALYSIS_SCOPE_FILE);
    await deps.fs.writeFile(path, serialise(AnalysisScopeSchema.parse(analysisScope)));
    return path;
  };
  await writeScope();

  /**
   * Whether this run has a new scope to remember.
   *
   * Only a `--path` on the command line writes: a run that took its scope from
   * the config has nothing new to say, and a run with no scope at all must not
   * quietly erase one. `--path .` is the deliberate exception — it widens the
   * run back to the whole repository, and a config that still said `apps/api`
   * would silently re-narrow the next one — but it only rewrites a config that
   * actually holds a scope, so widening never creates a file.
   */
  // Writing into the repository under analysis is intrusive — it is often
  // someone's work tree, and an untracked file appearing there after an audit
  // is a surprise the audit did not ask permission for. So the scope is
  // remembered only when the caller says to (`--save-scope`).
  const rememberScope =
    options.saveScope &&
    options.pathFromFlag &&
    (scopePaths.length > 0
      ? (loaded.config.analyze.path ?? []).join("\u0000") !== scopePaths.join("\u0000")
      : (loaded.config.analyze.path ?? []).length > 0);

  // A scope an earlier run left behind is announced, never applied silently.
  if (speaks && options.carriedScope.length > 0) {
    context.write(
      `\nNote: \`${CONFIG_FILE_NAME}\` in the target remembers the scope \`${options.carriedScope.join(", ")}\` from an earlier run. This run did not apply it - pass --path to narrow deliberately.\n`,
    );
  }

  // Remembered in the target repo so the next run over this monorepo does not
  // have to re-type the one deployable worth auditing — and so a *change* of
  // scope is a line in `git diff`, not an unexplained jump in a unit count.
  if (rememberScope) {
    try {
      const saved = await saveConfig(deps.fs, options.target, {
        ...loaded.config,
        analyze: { ...loaded.config.analyze, path: [...scopePaths] },
      });
      if (speaks) {
        context.write(
          scopePaths.length === 0
            ? `\nCleared the remembered scope in ${saved}: this run covered the whole repository\n`
            : `\nRemembered this scope in ${saved}\n`,
        );
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      context.writeError(
        `sentinel: the scope could not be written to ${options.target}'s sentinel.config.json ` +
          `(${detail}); this run is unaffected, but the next one will need --path again.\n`,
      );
    }
  }

  if (speaks) context.write(`\nScanning ${options.target}\n`);

  const result = await deps.scan({
    runId,
    runDir: runDir.dir,
    targetDir: options.target,
    profile,
    domains: decision.enabledDomains,
    paths: scopePaths,
  });

  analysisScope = scopeDocument({
    runId,
    units: analysisScope.units,
    findingsOutside: result.outsideScope,
  });

  if (speaks) context.write(`\n${renderStepSummary(result)}\n`);
  for (const blocked of decision.blockedOnMissingTool) {
    context.writeError(blockedNote(blocked.proposalId, blocked.tool));
  }

  /** Everything written under the run directory, in the order the phases ran. */
  const artifacts: string[] = [
    runDir.artifact(STACK_PROFILE_FILE),
    runDir.artifact(SCOPE_PROPOSAL_FILE),
    runDir.artifact(ANALYSIS_SCOPE_FILE),
    ...result.artifacts,
  ];

  /**
   * Phases 6 and 7, over whatever phases 1 to 4 left on disk.
   *
   * Deliberately re-reads the run directory rather than passing the in-memory
   * result along: `sentinel report` scores the same files, and reading them the
   * same way is what guarantees the dossier a run produces is byte-identical to
   * the one a re-render produces. It also means a run that ended early still
   * gets a document, and that document says it ended early.
   *
   * Nothing here can fail the run. The findings are already written and
   * rendering is free, so a renderer that throws costs a warning and a
   * suggestion to re-run `sentinel report`, never the run's exit code.
   */
  const renderReport = async (): Promise<Scorecard | undefined> => {
    try {
      const loaded = await loadRunArtifacts(deps.fs, runDir.dir);
      const rendered = await renderDossier(loaded, {
        // No brief: a run produces the dossier, and the short version is asked
        // for deliberately with `sentinel report <run-dir> --brief`, which costs
        // nothing and can be re-run against this directory at any time.
        select: { pdf: options.pdf, markdown: true, issues: true, brief: false },
        sentinelVersion: context.version,
      });
      const written = await writeDossier(deps.fs, runDir.dir, rendered);
      artifacts.push(...written.map((entry) => entry.path));
      return rendered.scorecard;
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      context.writeError(
        `sentinel: the dossier could not be rendered (${detail}); the run's artifacts were still ` +
          `written. Re-run \`sentinel report ${runDir.dir}\` once the cause is fixed — it costs nothing.\n`,
      );
      return undefined;
    }
  };

  /**
   * Scores and renders, prints the domain table, the scorecard and the footer,
   * then returns the code. Every exit after phase 1 goes through here, so no
   * path can forget the table that says which domains were left unchecked — or
   * leave a run directory without the dossier it was asked for.
   */
  const finish = async (input: {
    readonly coverage: readonly Coverage[];
    readonly findings: readonly { readonly domain: Domain }[];
    readonly droppedFindings: number;
    readonly phases: PhaseSections;
    readonly code: number;
    /** What this run could not do, given how far it got. */
    readonly note: string;
  }): Promise<number> => {
    // Rewritten before the dossier is rendered, never after: phases 6 and 7 read
    // the run directory, and the scope they read has to be the one this run
    // ended with rather than the one it started with.
    await writeScope();
    if (speaks) context.write("\nScoring and rendering the dossier\n");
    const before = artifacts.length;
    const card = await renderReport();
    const report = artifacts.slice(before);

    if (options.json) {
      emitJson({
        ...input.phases,
        coverage: input.coverage,
        ...(card === undefined ? {} : { scorecard: card }),
        ...(report.length === 0 ? {} : { report }),
      });
    } else if (speaks) {
      context.write(
        `\n${renderDomainCounts(input.coverage, input.findings, decision.enabledDomains)}\n`,
      );
      if (card !== undefined) {
        context.write(`\n${renderScorecardLines(card, analysisScope)}\n`);
      }
      context.write(
        `${renderRunFooter({
          scan: result,
          runDirPath: runDir.dir,
          findings: input.findings.length,
          artifacts,
          droppedFindings: input.droppedFindings,
          scopeNotes: renderScopeNotes(analysisScope),
        })}\n`,
      );
    }
    if (input.note !== "") context.writeError(`sentinel: ${input.note}\n`);
    return input.code;
  };

  /** A complete run has nothing left to disclose. */
  const AFTER_AUDIT = "";

  /** The disclosure for a run that stopped before the audit could contribute. */
  const WITHOUT_AUDIT =
    "no model audited this run, so nothing here carries a D2 or D3 verdict; the dossier was " +
    "still scored and rendered from what did run, and it states that gap rather than hiding it.";

  // A cancelled scan stops the run here. Enumerating the repository for an
  // audit whose input is already known to be partial would spend minutes to
  // produce a coverage table nobody should trust.
  if (result.aborted) {
    context.writeError("sentinel: the scan was cancelled; the run directory is incomplete.\n");
    return await finish({
      coverage: result.coverage,
      findings: result.findings,
      droppedFindings: result.document.droppedFindings,
      phases: { scan: scanJson(result, decision.enabledDomains, runDir.dir) },
      code: EXIT.interrupted,
      note: WITHOUT_AUDIT,
    });
  }

  // -------------------------------------------------------------------------
  // Phase 2 — the inventory
  // -------------------------------------------------------------------------

  if (speaks) context.write("\nEnumerating the units of audit\n");
  let inventory: InventoryOutcome;
  try {
    inventory = await deps.inventory({
      runId,
      runDir: runDir.dir,
      targetDir: options.target,
      profile,
      paths: scopePaths,
    });
  } catch (error) {
    // Phase 2 is designed not to throw — a failing enumerator is a reported
    // enumerator — so reaching here is a bug, not a repository problem. The
    // scan's artifacts are already on disk and stay there; what does not happen
    // is an audit over an inventory that does not exist.
    const detail = error instanceof Error ? error.message : String(error);
    context.writeError(
      `sentinel: the inventory phase failed (${detail}); nothing was audited. The scan's findings were still written.\n`,
    );
    return await finish({
      coverage: result.coverage,
      findings: result.findings,
      droppedFindings: result.document.droppedFindings,
      phases: { scan: scanJson(result, decision.enabledDomains, runDir.dir) },
      code: EXIT.failure,
      note: WITHOUT_AUDIT,
    });
  }

  artifacts.push(...inventory.artifacts);
  if (speaks) context.write(`\n${renderInventorySummary(inventory, options.verbose)}\n`);

  /**
   * The inventory, cut along the `--path` boundary.
   *
   * Phase 2 enumerated the whole repository — it costs seconds and it is the
   * only way to state what a bounded run left out — and this is where the bound
   * is actually applied: phase 4, the phase that costs hours of a throttled
   * subscription, is handed the units inside the scope and nothing else. On an
   * unscoped run the partition is the identity and this costs one pass over an
   * array.
   */
  const partition = partitionUnits(inventory.document.units, scopePaths);
  const units = partition.inScope;
  analysisScope = scopeDocument({
    runId,
    units: {
      total: inventory.document.units.length,
      inScope: partition.inScope.length,
      outOfScope: partition.outOfScope.length,
      byKind: countUnitsByKind(partition.inScope, partition.outOfScope),
    },
    findingsOutside: result.outsideScope,
  });
  if (speaks && scopePaths.length > 0) {
    context.write(`\n  ${analysisScope.statement}\n`);
  }

  const scanPhases: PhaseSections = {
    scan: scanJson(result, decision.enabledDomains, runDir.dir),
    inventory: inventoryJson(inventory),
  };

  // -------------------------------------------------------------------------
  // Phases 3 and 4 — batching and the AI audit
  // -------------------------------------------------------------------------

  /** Why the audit did not run, when it did not. */
  const auditOff = !options.ai
    ? "--no-ai"
    : units.length > 0
      ? undefined
      : inventory.document.units.length === 0
        ? "phase 2 enumerated no units, so there is nothing to audit"
        : // Not "nothing to audit": the repository has units, and this run was
          // told not to look at any of them. A reader has to be able to tell the
          // empty repository from the mis-typed scope.
          `every one of the ${inventory.document.units.length} units this repository has is outside ${renderScopePaths(
            scopePaths,
          )}, so this run had nothing in scope to audit`;

  if (auditOff !== undefined) {
    if (speaks) context.write(`\n${renderSkippedAudit(auditOff, units.length)}\n`);
    return await finish({
      coverage: result.coverage,
      findings: result.findings,
      droppedFindings: result.document.droppedFindings,
      phases: { ...scanPhases, audit: skippedAuditJson(auditOff) },
      code: EXIT.ok,
      note: WITHOUT_AUDIT,
    });
  }

  /**
   * The per-batch progress writer, built from this run's flags and streams.
   *
   * `--quiet` produces nothing, `--json` produces one object per batch on
   * stderr — never into the document on stdout — and `--verbose` adds the batch
   * id and every unit kind. It is `undefined` only under `--quiet`, which is the
   * one case where phase 4 should not even do the accounting.
   */
  const progress = createProgressWriter({
    write: context.write,
    writeError: context.writeError,
    json: options.json,
    verbose: options.verbose,
    quiet: options.quiet,
  });

  if (speaks) {
    const fanOut = `${options.maxParallel} at a time`;
    // The second line is the fix for "I'm not seeing anything": a reader who
    // knows a line is coming per batch can tell a live run from a wedged one.
    context.write(
      [
        `\nAuditing ${plural(units.length, "unit")} on the Claude subscription, ${fanOut}`,
        "  one line per batch as it finishes; the time left comes from the batches already done",
        "",
      ].join("\n"),
    );
  }
  let audit: AuditOutcome;
  try {
    audit = await deps.audit({
      runId,
      runDir: runDir.dir,
      targetDir: options.target,
      profile,
      units,
      domains: decision.enabledDomains,
      maxParallel: options.maxParallel,
      budget: auditBudgetFrom(options.auditBudget),
      ...(progress === undefined ? {} : { progress }),
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    context.writeError(
      `sentinel: the audit phase failed (${detail}); the scan and the inventory were still written.\n`,
    );
    return await finish({
      coverage: result.coverage,
      findings: result.findings,
      droppedFindings: result.document.droppedFindings,
      phases: scanPhases,
      code: EXIT.failure,
      note: WITHOUT_AUDIT,
    });
  }

  artifacts.push(...audit.result.artifacts);
  if (speaks) context.write(`\n${renderAuditSummary(audit, options.verbose)}\n`);

  // Phase 4 rewrote `findings.json` with its own findings merged in, and that
  // document's coverage is already the merged table. Falling back to merging
  // here keeps the summary correct when writing was turned off.
  const document = audit.result.document;
  const coverage = document?.coverage ?? mergeCoverage(result.coverage, audit.result.coverage);
  const findings = document?.findings ?? [...result.findings, ...audit.result.findings];
  const droppedFindings =
    document?.droppedFindings ??
    result.document.droppedFindings +
      audit.result.dropped.unresolved +
      audit.result.dropped.outOfSlice;

  const code = audit.result.aborted ? EXIT.interrupted : EXIT.ok;
  if (audit.result.aborted) {
    context.writeError(
      "sentinel: the audit did not finish; the units it never reached are listed as skipped.\n",
    );
  }
  return await finish({
    coverage,
    findings,
    droppedFindings,
    phases: { ...scanPhases, audit: auditJson(audit) },
    code,
    note: AFTER_AUDIT,
  });
}

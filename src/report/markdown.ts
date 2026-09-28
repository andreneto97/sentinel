/**
 * `report.md` — the dossier as markdown.
 *
 * The PDF is what gets sent; this is what gets diffed. Two runs of the same
 * repository produce two markdown files whose difference is exactly what
 * changed in the code, which is something a PDF cannot do, so the two carry
 * the same content and this one is deliberately stable: every number here is
 * read from an artifact, nothing is sampled, and the volatile facts of a run —
 * durations, token spend, retries — are confined to the last section so a
 * diff of the substance is not drowned by them.
 *
 * The input is the set of documents a run leaves on disk. All of them except
 * `findings.json` are optional, and an absent one is *stated* rather than
 * skipped: a report that does not know its coverage has to say so.
 */

import type { AuditReport } from "../audit/artifacts.ts";
import { groupSkipReasons } from "../audit/coverage.ts";
import type {
  Assurance,
  CodeRef,
  Coverage,
  Domain,
  Finding,
  Severity,
} from "../contracts/findings.ts";
import { DomainSchema, SeveritySchema } from "../contracts/findings.ts";
import type { InventoryDocument } from "../contracts/inventory.ts";
import type { StackProfile } from "../contracts/profile.ts";
import type { ScopeDecision } from "../contracts/proposal.ts";
import type { AnalysisScope } from "../contracts/scope.ts";
import { renderScopePaths } from "../contracts/scope.ts";
import { renderScopeSection } from "../propose/render.ts";
import {
  type VolumeGroup,
  type VolumePlan,
  isCollapsed,
  isHiddenByVolume,
  planVolume,
  volumeDisclosure,
} from "../scan/_volume.ts";
import type { ScanReport } from "../scan/artifacts.ts";
import type { IssueDraft } from "./issues.ts";
import { ISSUES_FILE, buildIssues, indexIssuesByFinding, renderIssueDocument } from "./issues.ts";
import type { Plan, PlanPriority } from "./plan.ts";
import { buildPlan, domainRank, planHeadline, severityRank } from "./plan.ts";
import type { ReviewedFinding, TriageSummary } from "./triage.ts";
import { reviewIndex, reviewLabel } from "./triage.ts";

/** File name of the markdown dossier inside a run directory. */
export const REPORT_MARKDOWN_FILE = "report.md";

/**
 * The scoring phase's output, as the report consumes it.
 *
 * Declared structurally and optional because phase 6 is not this module's, and
 * a report that cannot be written until scoring exists is a report that blocks
 * on someone else's file. A score that is absent is printed as absent.
 */
export interface DossierScore {
  /** 0–100, run level. */
  readonly overall: number;
  /** A–F band for {@link overall}. */
  readonly band: string;
  /** Run-level confidence: how much of the repository the run actually saw. */
  readonly confidence?: string | undefined;
  readonly domains: readonly {
    readonly domain: Domain;
    readonly score: number;
    readonly band: string;
  }[];
  /**
   * The domains that earned no number, with the reason each one did not.
   *
   * A score table that silently lists only the domains it could score invites
   * the reader to assume the rest were fine. These rows are printed beside the
   * scored ones, and every count for a domain named here is rendered as unknown
   * rather than as a result.
   */
  readonly unscored?: readonly { readonly domain: Domain; readonly reason: string }[] | undefined;
  /** Hard ceilings that capped a score, with the finding that caused each. */
  readonly ceilings?: readonly { readonly reason: string; readonly cap: number }[] | undefined;
}

/**
 * The findings half of the input.
 *
 * Declared structurally rather than as `FindingsDocument` so a caller that
 * already assembled a view model can pass it without rebuilding the document;
 * `FindingsDocument` satisfies it as it stands.
 */
export interface DossierFindings {
  readonly runId: string;
  readonly target: string;
  readonly findings: readonly Finding[];
  readonly assurances: readonly Assurance[];
  readonly coverage: readonly Coverage[];
  /** Findings dropped because their citation did not resolve; unknown when absent. */
  readonly droppedFindings?: number | undefined;
  readonly schemaVersion?: string | undefined;
}

/** Every document the dossier can draw on; only `findings` is required. */
export interface DossierInput {
  readonly findings: DossierFindings;
  readonly profile?: StackProfile | undefined;
  readonly inventory?: InventoryDocument | undefined;
  readonly scan?: ScanReport | undefined;
  readonly audit?: AuditReport | undefined;
  readonly scope?: ScopeDecision | undefined;
  /**
   * `--path`: the subtree the run analysed, and what that left out.
   *
   * Absent for a run written before the artifact existed, which reads as "not
   * recorded" rather than as "everything": the one thing this document must
   * never do is let a bounded run pass for a complete one.
   */
  readonly analysisScope?: AnalysisScope | undefined;
  readonly score?: DossierScore | undefined;
  /** Prebuilt issues; when absent they are built from the findings. */
  readonly issues?: readonly IssueDraft[] | undefined;
  /**
   * `--triage`: what a human verified, and what that changed.
   *
   * Absent means nobody reviewed this run, and the document says nothing about
   * human verification — which is the only honest rendering of a raw run. When
   * it is present, every finding it withheld is named in its own section, and
   * the findings it did not reach are stated as unreviewed.
   */
  readonly triage?: TriageSummary | undefined;
}

/** One row of the severity distribution; every severity is present, even at zero. */
export interface SeverityCount {
  readonly severity: Severity;
  readonly count: number;
}

/** One row of the per-domain distribution. */
export interface DomainCount {
  readonly domain: Domain;
  readonly count: number;
  readonly worst: Severity | null;
  readonly assurances: number;
  readonly coverage: Coverage | null;
  /**
   * False when phase 6 published no score for this domain.
   *
   * It is what stops `0` from appearing in the findings column of a domain
   * nobody could assess: the count is real, but as a *result* it is unknown,
   * and the two are not the same claim. True when no scorecard was supplied —
   * this report does not invent a verdict phase 6 never reached.
   */
  readonly assessed: boolean;
}

/**
 * The numbers both renderers put on the page: the donut, the bars, the header
 * counters and the coverage line all come from here, so the PDF and the
 * markdown cannot disagree about them.
 */
export interface DossierSummary {
  readonly runId: string;
  readonly target: string;
  readonly totalFindings: number;
  readonly totalAssurances: number;
  readonly droppedFindings: number;
  readonly bySeverity: readonly SeverityCount[];
  readonly byDomain: readonly DomainCount[];
  readonly priorities: Readonly<Record<PlanPriority, number>>;
  readonly units: UnitTotals;
}

/**
 * Units enumerated and audited.
 *
 * `source` matters and is printed. `audit` means these are *distinct* units, as
 * phase 4 counted them. `coverage` means they are the per-domain rows added up,
 * and a unit audited under two domains is counted twice — a route is an appsec
 * unit and its query is a data unit — so the total is larger than the
 * inventory. Presenting the second as the first is the easiest way for a report
 * to overstate what it looked at.
 */
export interface UnitTotals {
  readonly total: number;
  readonly audited: number;
  readonly skipped: number;
  readonly source: "audit" | "coverage";
}

/** Counts, distributions and coverage totals, computed once for both renderers. */
export function buildDossierSummary(input: DossierInput): DossierSummary {
  const { findings, assurances, coverage } = input.findings;
  const plan = buildPlan(findings);
  const bySeverity = SeveritySchema.options.map((severity) => ({
    severity,
    count: findings.filter((finding) => finding.severity === severity).length,
  }));
  const domains = new Set<Domain>([
    ...findings.map((finding) => finding.domain),
    ...assurances.map((assurance) => assurance.domain),
    ...coverage.map((row) => row.domain),
  ]);
  const unscored = new Set<Domain>((input.score?.unscored ?? []).map((row) => row.domain));
  const byDomain = [...domains]
    .sort((left, right) => domainRank(left) - domainRank(right))
    .map((domain) => {
      const owned = findings.filter((finding) => finding.domain === domain);
      return {
        domain,
        count: owned.length,
        worst: worstOf(owned),
        assurances: assurances.filter((assurance) => assurance.domain === domain).length,
        coverage: coverage.find((row) => row.domain === domain) ?? null,
        assessed: !unscored.has(domain),
      };
    });
  const units = unitTotals(input, coverage);
  return {
    runId: input.findings.runId,
    target: input.findings.target,
    totalFindings: findings.length,
    totalAssurances: assurances.length,
    droppedFindings: input.findings.droppedFindings ?? 0,
    bySeverity,
    byDomain,
    priorities: plan.counts,
    units,
  };
}

/** Distinct units when phase 4 counted them, the summed coverage rows otherwise. */
function unitTotals(input: DossierInput, coverage: readonly Coverage[]): UnitTotals {
  const counted = input.audit?.units;
  if (counted !== undefined) {
    return {
      total: counted.total,
      audited: counted.audited,
      skipped: counted.skipped,
      source: "audit",
    };
  }
  return coverage.reduce<UnitTotals>(
    (totals, row) => ({
      total: totals.total + row.unitsTotal,
      audited: totals.audited + row.unitsAudited,
      skipped: totals.skipped + row.skipped.length,
      source: "coverage",
    }),
    { total: 0, audited: 0, skipped: 0, source: "coverage" },
  );
}

function worstOf(findings: readonly Finding[]): Severity | null {
  let worst: Severity | null = null;
  for (const finding of findings) {
    if (worst === null || severityRank(finding.severity) < severityRank(worst)) {
      worst = finding.severity;
    }
  }
  return worst;
}

// ---------------------------------------------------------------------------
// Markdown primitives
// ---------------------------------------------------------------------------

function cell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();
}

function table(headers: readonly string[], rows: readonly (readonly string[])[]): string[] {
  if (rows.length === 0) return [];
  return [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(cell).join(" | ")} |`),
  ];
}

function fence(code: string): string[] {
  return ["```text", code, "```"];
}

function refLabel(ref: CodeRef): string {
  return ref.endLine === undefined || ref.endLine === ref.line
    ? `${ref.file}:${ref.line}`
    : `${ref.file}:${ref.line}-${ref.endLine}`;
}

function pluralise(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** The coverage headline, which says what the denominator actually counts. */
export function unitSentence(summary: DossierSummary): string {
  const { audited, total, source } = summary.units;
  return source === "audit"
    ? `${audited} of ${total} enumerated units were audited.`
    : `${audited} of ${total} domain-unit pairs were audited; a unit audited under two domains is counted once per domain, because this run recorded no distinct unit total.`;
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/** Renders the whole dossier as markdown, ready to be written to `report.md`. */
export function renderReportMarkdown(input: DossierInput): string {
  const summary = buildDossierSummary(input);
  const plan = buildPlan(input.findings.findings);
  const issues = input.issues ?? buildIssues(input.findings.findings);
  // One volume decision for the whole document: the findings section, the plan
  // and the issues all collapse the same rules, or the reader would have to
  // reconcile three different totals.
  const volume = planVolume(input.findings.findings);
  const parts = [
    header(input, summary),
    executiveSummary(input, summary, plan),
    scopeSection(input),
    coverageSection(input, summary),
    // Before the findings, because it decides how the findings are to be read:
    // nineteen of them were checked by a person and the rest were not.
    triageSection(input),
    findingsSection(input, issues, volume),
    assurancesSection(input),
    planSection(plan, issues, volume),
    issuesSection(issues),
    runSection(input),
  ].filter((part) => part !== "");
  return `${parts.join("\n\n")}\n`;
}

function header(input: DossierInput, summary: DossierSummary): string {
  const scope = input.analysisScope;
  const lines = [
    scope !== undefined && !scope.wholeRepository
      ? `# Sentinel dossier — \`${summary.target}\`, scoped to ${renderScopePaths(scope.paths)}`
      : `# Sentinel dossier — \`${summary.target}\``,
    "",
    // Immediately under the title, before any number: a reader who takes one
    // line from this document takes the one that says how much of the
    // repository it is about.
    ...(scope === undefined || scope.wholeRepository ? [] : [`> **${scope.statement}**`, ""]),
    `Run \`${summary.runId}\`${input.findings.schemaVersion === undefined ? "" : ` · schema \`${input.findings.schemaVersion}\``}`,
    "",
    `${pluralise(summary.totalFindings, "finding")} · ${pluralise(summary.totalAssurances, "assurance")} · ${summary.units.audited}/${summary.units.total} units audited`,
  ];
  if (input.triage !== undefined) {
    // A reviewed dossier says so where the counts are, and says how far the
    // review reached in the same breath: the counts above are already the
    // reviewed ones, and a reader who stops here must not read them as a
    // document a human checked end to end.
    lines.push(
      "",
      `> **Human-reviewed.** ${input.triage.statement} ${input.triage.unreviewedStatement}`,
    );
  }
  if (input.score !== undefined) {
    const score = input.score;
    lines.push(
      "",
      `Score **${score.overall}/100 (${score.band})**${score.confidence === undefined ? "" : ` · confidence ${score.confidence}`}`,
    );
  }
  return lines.join("\n");
}

function executiveSummary(input: DossierInput, summary: DossierSummary, plan: Plan): string {
  const lines = ["## Executive summary", "", planHeadline(plan), ""];

  const worst = plan.items.slice(0, 5);
  if (worst.length > 0) {
    lines.push("The five findings this run would fix first:", "");
    lines.push(
      ...table(
        ["#", "Priority", "Severity", "Finding", "Location"],
        worst.map((item) => [
          String(item.rank),
          item.priority,
          item.finding.severity,
          item.finding.title,
          `\`${refLabel(item.finding.location)}\``,
        ]),
      ),
      "",
    );
  }

  lines.push(
    ...table(
      ["Severity", "Findings"],
      summary.bySeverity.map((row) => [row.severity, String(row.count)]),
    ),
    "",
  );

  lines.push(
    ...table(
      // "Scored", not "Status": the flag answers whether phase 6 published a
      // number, which is a coarser question than the units-audited fraction in
      // the last column. Conflating the two would let `appsec 66/69` read as a
      // different verdict here than in the PDF's coverage chip.
      ["Domain", "Scored", "Findings", "Worst", "Assurances", "Units audited"],
      summary.byDomain.map((row) => [
        row.domain,
        row.assessed ? "yes" : "**no — not assessed**",
        // A count of zero for a domain nobody could assess is the one cell in
        // this table that reads as a clean bill of health, so it is withheld.
        // A count above zero is still printed: those findings exist.
        row.assessed || row.count > 0 ? String(row.count) : "—",
        row.worst ?? "—",
        row.assessed || row.assurances > 0 ? String(row.assurances) : "—",
        row.coverage === null
          ? "not counted"
          : `${row.coverage.unitsAudited}/${row.coverage.unitsTotal}`,
      ]),
    ),
    "",
  );

  const score = input.score;
  if (score !== undefined && (score.domains.length > 0 || (score.unscored ?? []).length > 0)) {
    lines.push(
      ...table(
        ["Domain", "Score", "Band", "Why"],
        [
          ...score.domains.map((row) => [row.domain, String(row.score), row.band, ""]),
          ...(score.unscored ?? []).map((row) => [
            row.domain,
            "not assessed",
            "—",
            row.reason.replace(/^not assessed: /, ""),
          ]),
        ],
      ),
      "",
    );
    for (const ceiling of score.ceilings ?? []) {
      // The reason already opens with the cap; see `src/score/ceilings.ts`.
      lines.push(`- ${ceiling.reason}`);
    }
    if ((score.ceilings ?? []).length > 0) lines.push("");
  }

  lines.push(
    "Two rules govern everything below.",
    "",
    `**Every citation was verified against disk.** Sentinel opened each cited file, checked the line existed and extracted the snippet itself; no snippet in this report was written by a model. ${summary.droppedFindings === 0 ? "No finding was dropped for an unresolvable citation in this run." : `${pluralise(summary.droppedFindings, "finding")} ${summary.droppedFindings === 1 ? "was" : "were"} dropped because their citation did not resolve, and ${summary.droppedFindings === 1 ? "is" : "are"} not shown.`}`,
    "",
    `**Coverage is enumerated, not sampled.** The units below were listed before they were audited, and every unit that was not audited is named with its reason. ${summary.units.skipped === 0 ? "Nothing was skipped." : `${pluralise(summary.units.skipped, "unit")} ${summary.units.skipped === 1 ? "was" : "were"} skipped.`}`,
  );
  if (input.triage !== undefined) {
    // The third claim of the page, and the only one a human made. It is stated
    // here rather than only in its own section because this is the page that
    // gets quoted, and "reviewed" is the word most easily over-read.
    lines.push(
      "",
      `**Part of this run was verified by hand.** ${input.triage.statement} ${input.triage.unreviewedStatement} What the review withheld, corrected and confirmed is in "Human verification" below.`,
    );
  }
  return lines.join("\n").trimEnd();
}

/**
 * The `--path` block of the scope section.
 *
 * Every number in it is the scope artifact's own, and the closing list is the
 * one disclosure a narrowed run cannot leave to the reader's imagination: which
 * phases ignored the boundary, so a finding from outside it is not a surprise.
 */
function analysisScopeSection(scope: AnalysisScope): string[] {
  if (scope.wholeRepository) {
    return ["### Analysed subtree", "", "This run analysed the whole repository.", ""];
  }
  const lines = [
    "### Analysed subtree",
    "",
    `**${scope.statement}**`,
    "",
    ...table(
      ["--path", "Resolved to", "How"],
      scope.selectors.map((entry) => [
        `\`${entry.selector}\``,
        entry.paths.length === 0 ? "—" : renderScopePaths(entry.paths),
        entry.note ?? entry.kind,
      ]),
    ),
    "",
  ];
  if (scope.units.outOfScope > 0) {
    lines.push(
      ...table(
        ["Unit kind", "Analysed", "Not analysed"],
        scope.units.byKind.map((entry) => [
          entry.kind,
          String(entry.inScope),
          String(entry.outOfScope),
        ]),
      ),
      "",
    );
  }
  if (scope.findingsOutside > 0) {
    lines.push(
      `${scope.findingsOutside} of the findings below ${scope.findingsOutside === 1 ? "is" : "are"} in files outside ${renderScopePaths(
        scope.paths,
      )}. They are reported because a problem Sentinel saw is a problem whatever \`--path\` said, and they count against the scores; they are not evidence that those files were analysed.`,
      "",
    );
  }
  if (scope.unscopedPhases.length > 0) {
    lines.push("What `--path` did not narrow, and why:", "");
    for (const entry of scope.unscopedPhases) lines.push(`- **${entry.phase}** — ${entry.reason}`);
    lines.push("");
  }
  return lines;
}

function scopeSection(input: DossierInput): string {
  const analysis = input.analysisScope;
  const head = analysis === undefined ? [] : analysisScopeSection(analysis);
  if (input.scope === undefined) {
    return [
      "## Scope",
      "",
      ...head,
      "No scope decision was recorded for this run, so what was offered and what was declined cannot be stated. Treat the coverage below as the whole of what ran.",
    ].join("\n");
  }
  if (head.length === 0) return renderScopeSection(input.scope).trimEnd();
  const rendered = renderScopeSection(input.scope).trimEnd();
  // The negotiated scope's own section starts with `## Scope`; the `--path`
  // block belongs inside it, directly under that heading.
  const [heading, ...rest] = rendered.split("\n");
  return [heading ?? "## Scope", "", ...head, ...rest].join("\n").trimEnd();
}

function coverageSection(input: DossierInput, summary: DossierSummary): string {
  const lines = ["## Coverage", ""];
  lines.push(`${unitSentence(summary)}`, "");

  // The audit's own bound, in bold, directly under the unit sentence. The
  // sentence above says how many units were audited; this one says how many were
  // not and why, which is the difference between a scoped, budgeted run and a
  // dossier that reads as a complete audit of the repository.
  const bound = input.audit?.bound;
  if (bound !== undefined) {
    lines.push(`**${bound.statement}**`, "");
    if (bound.unitsDeferred > 0 || bound.stop !== "complete") {
      // `RISK_ORDERING` already begins "ordered by", so prefixing "ordered"
      // printed "Units were ordered ordered by exposure and blast radius".
      lines.push(`Units were ${bound.ordering}.`, "");
    }
  }

  lines.push(
    ...table(
      ["Domain", "Units", "Audited", "Skipped"],
      input.findings.coverage.map((row) => [
        row.domain,
        String(row.unitsTotal),
        String(row.unitsAudited),
        String(row.skipped.length),
      ]),
    ),
    "",
  );

  const kinds = input.audit?.kinds ?? [];
  if (kinds.length > 0) {
    lines.push("### By unit kind", "");
    lines.push(
      ...table(
        ["Kind", "Audited"],
        kinds.map((row) => [row.kind, `${row.unitsAudited}/${row.unitsTotal}`]),
      ),
      "",
    );
  }

  // Grouped, not listed. A bounded run over a monorepo leaves four and a half
  // thousand units without a verdict, almost all of them for the same reason, and
  // a four-thousand-row table is a way of not telling the reader anything. The
  // units are still named one by one in `findings.json` and `audit.json`, which
  // is where rule 2 of PLAN.md is satisfied; this is the page a person reads.
  const notAudited = input.findings.coverage.flatMap((row) =>
    row.skipped.length === 0
      ? []
      : groupSkipReasons(row.skipped).map((group) => [
          row.domain,
          String(group.units),
          group.reason,
        ]),
  );
  if (notAudited.length > 0) {
    lines.push("### Units that were not audited", "");
    lines.push(...table(["Domain", "Units", "Reason"], notAudited), "");
  }

  if (input.inventory !== undefined) {
    lines.push("### Enumerators", "");
    lines.push(
      ...table(
        ["Enumerator", "Status", "Units", "Note"],
        input.inventory.enumerators.map((entry) => [
          entry.name,
          entry.status,
          String(entry.units),
          entry.reason ?? "",
        ]),
      ),
      "",
    );
  }

  if (input.scan !== undefined) {
    lines.push("### Analyzers", "");
    lines.push(
      ...table(
        ["Step", "Status", "Findings", "Note"],
        input.scan.steps.map((step) => [
          step.step,
          step.status,
          String(step.findings),
          step.reason ?? "",
        ]),
      ),
      "",
    );
    const missing = input.scan.steps.filter((step) => step.status !== "ok");
    if (missing.length > 0) {
      lines.push(
        `${pluralise(missing.length, "analyzer")} did not run normally; every domain ${missing.length === 1 ? "it feeds" : "they feed"} is short by exactly that much.`,
        "",
      );
    }
  }

  if (input.audit?.runtime.synthetic === true) {
    lines.push(
      "> **This run's audit answers came from a recorded transcript, not from a live model.** It proves the wiring, not the code.",
      "",
    );
  }
  return lines.join("\n").trimEnd();
}

/**
 * The human verification section.
 *
 * Empty string when no triage was applied: a raw run must not carry a section
 * about a review that never happened, and its absence is the difference between
 * a reviewed dossier and an unreviewed one.
 *
 * The order inside it is deliberate. What the review reached comes first, what
 * it did **not** reach comes immediately after — the sentence that stops a
 * handful of checked findings out of thousands from reading as a checked
 * document — and only
 * then the tables. The withheld ones lead the tables, because a claim that was
 * made and taken back is the one thing a reader cannot reconstruct from
 * anything else in this file.
 */
function triageSection(input: DossierInput): string {
  const triage = input.triage;
  if (triage === undefined) return "";
  const lines = [
    "## Human verification",
    "",
    triage.statement,
    "",
    `**${triage.unreviewedStatement}**`,
    "",
    ...table(
      ["Reviewed", "Confirmed", "Corrected", "Withheld", "Contested", "Not reviewed"],
      [
        [
          `${triage.reviewed} of ${triage.findingsBefore}`,
          String(triage.confirmed.length),
          String(triage.corrected.length),
          String(triage.withheld.length),
          String(triage.contested.length),
          String(triage.unreviewed),
        ],
      ],
    ),
    "",
    `The findings count in this dossier is ${triage.findingsAfter}: the ${triage.findingsBefore} this run produced, less the ${pluralise(triage.withheld.length, "finding")} the review withheld. Every score below is recomputed from the findings as corrected here.`,
    "",
  ];

  const scored = triage.domains.some((row) => row.scoreAfter !== undefined);
  lines.push(
    "### What the review changed, by domain",
    "",
    ...table(
      [
        "Domain",
        "Reviewed",
        "Confirmed",
        "Corrected",
        "Withheld",
        "Contested",
        "Findings",
        ...(scored ? ["Score"] : []),
      ],
      triage.domains.map((row) => [
        row.domain,
        String(row.reviewed),
        String(row.confirmed),
        String(row.corrected),
        String(row.withheld),
        String(row.contested),
        `${row.findingsBefore} → ${row.findingsAfter}`,
        ...(scored ? [`${scoreLabel(row.scoreBefore)} → ${scoreLabel(row.scoreAfter)}`] : []),
      ]),
    ),
    "",
  );

  if (triage.withheld.length > 0) {
    lines.push(
      `### Withheld by review (${triage.withheld.length})`,
      "",
      `${pluralise(triage.withheld.length, "finding")} below ${triage.withheld.length === 1 ? "was" : "were"} reported by this run and did not survive verification. ${triage.withheld.length === 1 ? "It is" : "They are"} not in the findings, not in the counts and not in the scores — and ${triage.withheld.length === 1 ? "it is" : "they are"} listed here, with the reason, because a reader cannot otherwise tell a claim that was withdrawn from one that was never made.`,
      "",
      ...table(
        ["Reported as", "Finding", "Location", "Rule", "Why it was withheld"],
        triage.withheld.map((entry) => [
          entry.reportedSeverity,
          entry.title,
          `\`${entry.file}:${entry.line}\``,
          `\`${entry.rule}\``,
          entry.note,
        ]),
      ),
      "",
    );
  }

  if (triage.corrected.length > 0) {
    lines.push(
      `### Severity corrected by review (${triage.corrected.length})`,
      "",
      "Real findings at the wrong severity. Both numbers are kept: the scores are computed from the corrected one.",
      "",
      ...table(
        ["Reported", "Corrected", "Finding", "Location", "Why"],
        triage.corrected.map((entry) => [
          entry.reportedSeverity,
          entry.severity,
          entry.title,
          `\`${entry.file}:${entry.line}\``,
          entry.note,
        ]),
      ),
      "",
    );
  }

  if (triage.confirmed.length > 0) {
    lines.push(
      `### Confirmed by review (${triage.confirmed.length})`,
      "",
      "Checked against the real code and they hold, at the severity reported. These are the findings to act on first.",
      "",
      ...table(
        ["Severity", "Finding", "Location", "Rule", "What the reviewer checked"],
        triage.confirmed.map((entry) => [
          entry.severity,
          entry.title,
          `\`${entry.file}:${entry.line}\``,
          `\`${entry.rule}\``,
          entry.note,
        ]),
      ),
      "",
    );
  }

  if (triage.contested.length > 0) {
    lines.push(
      `### Contested (${triage.contested.length})`,
      "",
      "The review could not decide these. They are kept at the severity this run reported, because an undecided finding is neither confirmed nor withdrawn.",
      "",
      ...table(
        ["Severity", "Finding", "Location", "Rule", "What is unresolved"],
        triage.contested.map((entry) => [
          entry.severity,
          entry.title,
          `\`${entry.file}:${entry.line}\``,
          `\`${entry.rule}\``,
          entry.note,
        ]),
      ),
      "",
    );
  }

  return lines.join("\n").trimEnd();
}

/** A domain score, or the words phase 6 uses when it published no number. */
function scoreLabel(score: number | null | undefined): string {
  return score === null || score === undefined ? "not assessed" : String(score);
}

function findingsSection(
  input: DossierInput,
  issues: readonly IssueDraft[],
  volume: VolumePlan,
): string {
  const { findings } = input.findings;
  if (findings.length === 0) {
    return ["## Findings", "", "No finding survived verification in this run."].join("\n");
  }
  const index = indexIssuesByFinding(issues);
  // Which of these a person actually checked. A finding with no entry here is
  // unreviewed, and the section above says so in a sentence; marking the
  // reviewed ones individually is what keeps the reader from having to hold
  // nineteen ids in their head while they read.
  const reviews = input.triage === undefined ? undefined : reviewIndex(input.triage);
  const lines = ["## Findings", "", volumeDisclosure(volume), ""];
  if (input.triage !== undefined) {
    lines.push(
      // "wherever it has a block of its own", not "on the finding": a reviewed
      // finding inside a counted group has no block to print the verdict on, and
      // its verdict is in the section above with all the others.
      `${input.triage.confirmed.length + input.triage.corrected.length + input.triage.contested.length} of the ${findings.length} findings below carry a human verdict, printed on the finding wherever it has a block of its own; the other ${input.triage.unreviewed} carry none. Every verdict is also in "Human verification" above.`,
      "",
    );
  }
  for (const domain of DomainSchema.options) {
    const owned = findings
      .filter((finding) => finding.domain === domain)
      .sort(
        (left, right) =>
          severityRank(left.severity) - severityRank(right.severity) ||
          left.location.file.localeCompare(right.location.file) ||
          left.location.line - right.location.line ||
          left.id.localeCompare(right.id),
      );
    if (owned.length === 0) continue;
    const groups = volume.groups.filter((group) => group.domain === domain);
    const alone = owned.filter((finding) => !isCollapsed(volume, finding));
    lines.push(`### ${domain} (${owned.length})`, "");
    if (groups.length > 0) {
      const grouped = owned.length - alone.length;
      lines.push(
        `${alone.length} of these ${owned.length} findings are rendered on their own below; the other ${grouped} are in ${groups.length} counted ${groups.length === 1 ? "group" : "groups"} at the end of this section, every one of them still in \`findings.json\`.`,
        "",
      );
    }
    lines.push(
      ...table(
        ["Severity", "Finding", "Location", "Rule", "Confidence"],
        [
          ...alone.map((finding) => [
            finding.severity,
            finding.title,
            `\`${refLabel(finding.location)}\``,
            `\`${finding.rule}\``,
            finding.confidence,
          ]),
          ...groups.map((group) => [
            group.severity,
            `${group.title} (counted group)`,
            `${group.fileCount} ${group.fileCount === 1 ? "file" : "files"}`,
            `\`${group.rule}\``,
            group.confidence,
          ]),
        ],
      ),
      "",
    );
    for (const finding of alone) {
      lines.push(...findingDetail(finding, index, reviews?.get(finding.id)), "");
    }
    for (const group of groups) lines.push(...groupDetail(group, index), "");
  }
  return lines.join("\n").trimEnd();
}

/**
 * One collapsed group, rendered as the count it is.
 *
 * It carries what the individual blocks would have carried once — the rule's
 * impact and its fix are the same sentence in all of them — plus the examples,
 * their ids, and the sentence that says how many members are not printed and
 * where they are. Nothing here is a summary of a *finding*: every member still
 * exists in full in `findings.json` under the id the example rows cite.
 */
function groupDetail(group: VolumeGroup, index: ReadonlyMap<string, IssueDraft>): string[] {
  const [first] = group.examples;
  const issue = first === undefined ? undefined : index.get(first.id);
  const lines = [
    `#### ${group.title}`,
    "",
    `\`${group.severity}\` · \`${group.rule}\` · ${group.confidence} confidence · counted group of ${group.count} findings across ${group.fileCount} ${group.fileCount === 1 ? "file" : "files"}`,
    "",
    group.summary,
    "",
  ];
  if (group.examples.length > 0) {
    lines.push(
      `The ${group.examples.length} shown here are the ones in the files carrying the most of this rule:`,
      "",
      ...table(
        ["Severity", "Finding", "Location", "Finding id"],
        group.examples.map((finding) => [
          finding.severity,
          finding.title,
          `\`${refLabel(finding.location)}\``,
          `\`${finding.id}\``,
        ]),
      ),
      "",
    );
  }
  if (first !== undefined) {
    lines.push(`**Impact:** ${first.impact}`, "", `**Fix:** ${first.recommendation}`);
  }
  if (issue !== undefined) {
    lines.push(
      "",
      `**Issue:** \`${issue.key}\` — ${issue.title} (checklist in \`${ISSUES_FILE}\`)`,
    );
  }
  return lines;
}

function findingDetail(
  finding: Finding,
  index: ReadonlyMap<string, IssueDraft>,
  review?: ReviewedFinding | undefined,
): string[] {
  const issue = index.get(finding.id);
  const lines = [
    `#### ${finding.title}`,
    "",
    `\`${finding.severity}\` · \`${finding.rule}\` · ${finding.confidence} confidence · source \`${finding.source.kind}:${finding.source.name}\` · id \`${finding.id}\``,
    "",
    finding.description,
    "",
  ];
  // Directly under the description, before the evidence: whether a person
  // checked this claim changes how the rest of the block is read.
  if (review !== undefined) {
    lines.push(`**Human review:** ${reviewLabel(review)}. ${review.note}`, "");
  }
  if (finding.exploitability !== undefined) {
    lines.push(`**Preconditions:** ${finding.exploitability}`, "");
  }
  const refs = [finding.location, ...finding.evidence];
  const seen = new Set<string>();
  for (const ref of refs) {
    const key = refLabel(ref);
    if (seen.has(key)) continue;
    seen.add(key);
    lines.push(`\`${key}\`${ref.note === undefined ? "" : ` — ${ref.note}`}`, "");
    if (ref.snippet !== undefined && ref.snippet.trim() !== "")
      lines.push(...fence(ref.snippet), "");
  }
  lines.push(`**Impact:** ${finding.impact}`, "", `**Fix:** ${finding.recommendation}`);
  const references: string[] = [];
  if (finding.cwe.length > 0) references.push(`CWE ${finding.cwe.join(", ")}`);
  if (finding.owasp.length > 0) references.push(`OWASP ${finding.owasp.join(", ")}`);
  if (references.length > 0) lines.push("", `**References:** ${references.join(" · ")}`);
  if (issue !== undefined) {
    lines.push(
      "",
      `**Issue:** \`${issue.key}\` — ${issue.title} (checklist in \`${ISSUES_FILE}\`)`,
    );
  }
  return lines;
}

function assurancesSection(input: DossierInput): string {
  const { assurances } = input.findings;
  if (assurances.length === 0) {
    return [
      "## What is protected",
      "",
      "This run produced no assurances. That is not a clean bill of health: it means no check passed with evidence, which usually means the audit phase did not run.",
    ].join("\n");
  }
  const lines = [
    "## What is protected",
    "",
    `${pluralise(assurances.length, "check")} passed with evidence. Each one names the units it covers, so a fraction can never be read as the whole.`,
    "",
  ];
  for (const domain of DomainSchema.options) {
    const owned = assurances.filter((assurance) => assurance.domain === domain);
    if (owned.length === 0) continue;
    lines.push(`### ${domain}`, "");
    lines.push(
      ...table(
        ["Check", "Scope", "Units", "Evidence"],
        owned.map((assurance) => [
          assurance.check,
          assurance.scope,
          String(assurance.unitsChecked),
          evidenceLabel(assurance),
        ]),
      ),
      "",
    );
  }
  return lines.join("\n").trimEnd();
}

function evidenceLabel(assurance: Assurance): string {
  if (assurance.evidence.length === 0) return "none recorded";
  const shown = assurance.evidence.slice(0, 3).map((ref) => `\`${refLabel(ref)}\``);
  const rest = assurance.evidence.length - shown.length;
  return rest > 0 ? `${shown.join(", ")} (+${rest})` : shown.join(", ");
}

function planSection(plan: Plan, issues: readonly IssueDraft[], volume: VolumePlan): string {
  if (plan.items.length === 0) return "";
  const index = indexIssuesByFinding(issues);
  const lines = ["## Prioritised plan", "", planHeadline(plan), ""];
  for (const section of plan.sections) {
    lines.push(`### ${section.label} — ${section.items.length}`, "", section.description, "");
    if (section.items.length === 0) {
      lines.push("Nothing in this bucket.", "");
      continue;
    }
    // A finding inside a counted group keeps its rank and its place in the
    // count above; what it does not get is a row of its own, because the plan
    // would otherwise be the same two thousand lines the findings section is
    // there to spare the reader.
    const listed = section.items.filter((item) => !isHiddenByVolume(volume, item.finding));
    const collapsed = section.items.length - listed.length;
    if (collapsed > 0) {
      lines.push(
        `${collapsed} of these ${section.items.length} are inside a counted group in the findings section and are not listed again here; they are in \`findings.json\` and in the group that names them.`,
        "",
      );
    }
    lines.push(
      ...table(
        ["#", "Severity", "Domain", "Finding", "Location", "Issue"],
        listed.map((item) => [
          String(item.rank),
          item.finding.severity,
          item.finding.domain,
          item.finding.title,
          `\`${refLabel(item.finding.location)}\``,
          `\`${index.get(item.finding.id)?.key ?? "—"}\``,
        ]),
      ),
      "",
    );
  }
  return lines.join("\n").trimEnd();
}

function issuesSection(issues: readonly IssueDraft[]): string {
  if (issues.length === 0) return "";
  const grouped = issues.filter((issue) => issue.grouping.kind === "grouped");
  const lines = [
    "## GitHub issues",
    "",
    `${pluralise(issues.length, "issue")}, ready to paste. The same content is in \`${ISSUES_FILE}\` on its own.`,
    "",
  ];
  if (grouped.length > 0) {
    const covered = grouped.reduce((total, issue) => total + issue.findingIds.length, 0);
    lines.push(
      `${grouped.length} of them group ${covered} hygiene findings that share a rule family and a scope, so the tracker gets one task per fix rather than one per occurrence.`,
      "",
    );
  }
  for (const issue of issues) lines.push(renderIssueDocument(issue, 3), "");
  return lines.join("\n").trimEnd();
}

function runSection(input: DossierInput): string {
  const lines = ["## How this run went", ""];
  lines.push(
    "Everything in this section differs between two runs of unchanged code. It is last so that a diff of the report reads as a diff of the repository.",
    "",
  );
  if (input.profile !== undefined) {
    const stack = input.profile.facts
      .filter((fact) => STACK_FACTS.has(fact.kind))
      .map((fact) => `${fact.kind}: \`${fact.value}\``);
    if (stack.length > 0) lines.push(`Stack: ${unique(stack).join(" · ")}`, "");
    if (input.profile.scan.truncated) {
      lines.push(
        `> The content scan stopped early: ${input.profile.scan.filesRead} of ${input.profile.scan.filesSeen} candidate files were read, so the profile may be incomplete.`,
        "",
      );
    }
    for (const warning of input.profile.warnings) lines.push(`- Profile warning: ${warning}`);
    if (input.profile.warnings.length > 0) lines.push("");
  }
  if (input.scan !== undefined) {
    lines.push(
      `Scan: ${formatMs(input.scan.durationMs)}${input.scan.aborted ? ", **cancelled before every step finished**" : ""}. Citations relocated: ${input.scan.relocated}. Findings dropped: ${input.scan.dropped.findings}.`,
      "",
    );
  }
  if (input.audit !== undefined) {
    const audit = input.audit;
    const failures = Object.entries(audit.failures)
      .filter(([, count]) => count > 0)
      .map(([kind, count]) => `${kind} ${count}`);
    lines.push(
      `Audit: ${formatMs(audit.durationMs)}, ${pluralise(audit.batches.length, "batch", "batches")}, ${audit.dispatches} dispatches, ${audit.retries} retries${audit.aborted ? ", **cancelled**" : ""}.`,
      "",
      `Runtime: \`${audit.runtime.kind}\`${audit.runtime.model === undefined ? "" : ` (${audit.runtime.model})`}, concurrency ${audit.runtime.concurrency}, ${audit.runtime.synthetic ? "**synthetic transcript**" : "live"}.`,
      "",
      `Spend: ${audit.usage.inputTokens} in, ${audit.usage.outputTokens} out, ${formatCost(audit.usage.costUsd)}.${audit.quotaExhausted ? " **The subscription limit stopped the phase.**" : ""}`,
      "",
    );
    if (failures.length > 0) lines.push(`Agent failures: ${failures.join(", ")}.`, "");
    const partial = audit.batches.filter((batch) => batch.status !== "audited");
    if (partial.length > 0) {
      lines.push(
        ...table(
          ["Batch", "Status", "Units", "Verdicts", "Reason"],
          partial.map((batch) => [
            `\`${batch.batchId}\``,
            batch.status,
            String(batch.units),
            String(batch.verdicts),
            batch.reason ?? "",
          ]),
        ),
        "",
      );
    }
  }
  return lines.join("\n").trimEnd();
}

/** Profile fact kinds worth one line in the run section; the rest is noise here. */
const STACK_FACTS: ReadonlySet<string> = new Set([
  "package-manager",
  "backend-framework",
  "data-layer",
  "database-engine",
  "auth-provider",
  "serverless-platform",
  "ci",
  "container",
]);

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function formatMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function formatCost(usd: number): string {
  return usd === 0 ? "$0 (subscription)" : `$${usd.toFixed(4)}`;
}

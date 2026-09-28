/**
 * The prioritised plan: the one ordering `report.md`, `report.pdf` and the
 * GitHub issues all agree on.
 *
 * Three buckets, and the boundary between them is about *consequence*, not
 * about the severity word a tool happened to print:
 *
 * - **P1** — exploitable now, or loses data. Either an attacker reaches it
 *   from outside the process today, or applying the code as written destroys
 *   or corrupts stored rows.
 * - **P2** — a release should not ship without it. A known defect of real
 *   size that is not reachable today: it becomes P1 the moment the route is
 *   exposed, the flag is flipped or the data grows.
 * - **P3** — hygiene. Worth doing, worth batching, not worth blocking on.
 *
 * Nothing here re-scores a finding. Severity is phase 6's job and is taken as
 * given; this module only decides what a reader should do first.
 */

import type { Domain, Finding, Severity } from "../contracts/findings.ts";
import { ConfidenceSchema, DomainSchema, SeveritySchema } from "../contracts/findings.ts";

/** The three plan buckets, worst first. */
export const PLAN_PRIORITIES = ["P1", "P2", "P3"] as const;
/** One of the three plan buckets; see {@link PLAN_PRIORITIES}. */
export type PlanPriority = (typeof PLAN_PRIORITIES)[number];

/** Section heading for each bucket, used verbatim by both renderers. */
export const PRIORITY_LABEL: Readonly<Record<PlanPriority, string>> = {
  P1: "P1 — exploitable now, or loses data",
  P2: "P2 — a release should not ship without this",
  P3: "P3 — hygiene",
};

/** One sentence per bucket, printed under its heading. */
export const PRIORITY_DESCRIPTION: Readonly<Record<PlanPriority, string>> = {
  P1: "Reachable by an attacker as the code stands, or destructive to stored data. Fix before the next deploy.",
  P2: "A defect of real size that today needs a precondition an attacker does not control. Fix before the next release.",
  P3: "Low-consequence work. Batch it: the issues below group findings of the same kind into one task.",
};

const SEVERITY_RANK: ReadonlyMap<Severity, number> = new Map(
  SeveritySchema.options.map((severity, index) => [severity, index]),
);

const CONFIDENCE_RANK: ReadonlyMap<string, number> = new Map(
  ConfidenceSchema.options.map((confidence, index) => [confidence, index]),
);

const DOMAIN_RANK: ReadonlyMap<Domain, number> = new Map(
  DomainSchema.options.map((domain, index) => [domain, index]),
);

/**
 * Domains whose findings sit on a surface something outside this process can
 * call: an HTTP request, a queue message, a scheduled trigger, a webhook. A
 * high-severity defect here needs no further precondition to be reached, which
 * is what separates P1 from P2.
 */
export const EXTERNALLY_REACHABLE_DOMAINS: ReadonlySet<Domain> = new Set<Domain>([
  "appsec",
  "api",
  "serverless",
]);

/**
 * Rules whose consequence is destroyed or corrupted rows, at any severity.
 *
 * This is the "or loses data" arm of P1 and it deliberately ignores the
 * severity label: a migration that drops a column before its values are copied
 * anywhere loses the column whether a scanner called it medium or not. It is
 * an allowlist, so a rule the pack adds later is P2 until it is listed here —
 * which is the safe direction to be wrong in.
 */
export const DATA_LOSS_RULES: ReadonlySet<string> = new Set<string>([
  "data.destructive-migration",
  "data.migration-without-rollback",
]);

/** Which bucket a finding belongs to; the only classifier in the codebase. */
export function classifyPriority(finding: Finding): PlanPriority {
  if (DATA_LOSS_RULES.has(finding.rule)) return "P1";
  if (finding.severity === "critical") return "P1";
  if (finding.severity === "high" && EXTERNALLY_REACHABLE_DOMAINS.has(finding.domain)) return "P1";
  if (finding.severity === "low" || finding.severity === "info") return "P3";
  return "P2";
}

/** Why this finding landed in that bucket, in one sentence a reader can check. */
export function priorityReason(finding: Finding): string {
  if (DATA_LOSS_RULES.has(finding.rule)) {
    return `\`${finding.rule}\` destroys or corrupts stored data when it runs, whatever its severity label.`;
  }
  if (finding.severity === "critical") {
    return "Critical severity: treat it as reachable and already known.";
  }
  if (finding.severity === "high" && EXTERNALLY_REACHABLE_DOMAINS.has(finding.domain)) {
    return `High severity on the ${finding.domain} surface, which something outside the process already calls.`;
  }
  if (finding.severity === "high" || finding.severity === "medium") {
    return `${titleCase(finding.severity)} severity, and reaching it needs a precondition an attacker does not control today.`;
  }
  return `${titleCase(finding.severity)} severity: no consequence that blocks a release.`;
}

function titleCase(value: string): string {
  return value.length === 0 ? value : `${value[0]?.toUpperCase() ?? ""}${value.slice(1)}`;
}

/**
 * Plan order, and why it is nothing cleverer than this.
 *
 * Bucket, then severity, then confidence, then domain (contract order), then
 * rule, file, line, and finally the finding id. Every key is a field the
 * finding already carries, so two runs over unchanged code emit the same plan
 * in the same order and `report.md` diffs cleanly; and because the last key is
 * the stable id, the order is total — no pair of distinct findings can tie.
 * Nothing is weighted or blended, because a reader who disagrees with a
 * position has to be able to point at the field that produced it.
 */
export function comparePlanOrder(left: Finding, right: Finding): number {
  const byPriority =
    PLAN_PRIORITIES.indexOf(classifyPriority(left)) -
    PLAN_PRIORITIES.indexOf(classifyPriority(right));
  if (byPriority !== 0) return byPriority;
  const bySeverity = severityRank(left.severity) - severityRank(right.severity);
  if (bySeverity !== 0) return bySeverity;
  const byConfidence =
    (CONFIDENCE_RANK.get(left.confidence) ?? Number.MAX_SAFE_INTEGER) -
    (CONFIDENCE_RANK.get(right.confidence) ?? Number.MAX_SAFE_INTEGER);
  if (byConfidence !== 0) return byConfidence;
  const byDomain = domainRank(left.domain) - domainRank(right.domain);
  if (byDomain !== 0) return byDomain;
  const byRule = left.rule.localeCompare(right.rule);
  if (byRule !== 0) return byRule;
  const byFile = left.location.file.localeCompare(right.location.file);
  if (byFile !== 0) return byFile;
  const byLine = left.location.line - right.location.line;
  if (byLine !== 0) return byLine;
  return left.id.localeCompare(right.id);
}

/** Rank of a severity, 0 for `critical`; unknown values sort last. */
export function severityRank(severity: Severity): number {
  return SEVERITY_RANK.get(severity) ?? Number.MAX_SAFE_INTEGER;
}

/** Rank of a domain in contract declaration order; unknown values sort last. */
export function domainRank(domain: Domain): number {
  return DOMAIN_RANK.get(domain) ?? Number.MAX_SAFE_INTEGER;
}

/** The worse of two severities. */
export function worstSeverity(left: Severity, right: Severity): Severity {
  return severityRank(left) <= severityRank(right) ? left : right;
}

/** The more urgent of two priorities. */
export function worstPriority(left: PlanPriority, right: PlanPriority): PlanPriority {
  return PLAN_PRIORITIES.indexOf(left) <= PLAN_PRIORITIES.indexOf(right) ? left : right;
}

/** One line of the plan: a finding, where it sits, and why. */
export interface PlanItem {
  readonly priority: PlanPriority;
  /** 1-based position across the whole plan, not within the bucket. */
  readonly rank: number;
  readonly reason: string;
  readonly finding: Finding;
}

/** One bucket of the plan, with its heading and the items in plan order. */
export interface PlanSection {
  readonly priority: PlanPriority;
  readonly label: string;
  readonly description: string;
  readonly items: readonly PlanItem[];
}

/** The prioritised plan; every renderer takes its ordering from here. */
export interface Plan {
  /** Every item, in plan order, P1 first. */
  readonly items: readonly PlanItem[];
  /** The same items bucketed; all three sections are present, even when empty. */
  readonly sections: readonly PlanSection[];
  readonly counts: Readonly<Record<PlanPriority, number>>;
}

/** Classifies, orders and buckets every finding into the plan both renderers use. */
export function buildPlan(findings: readonly Finding[]): Plan {
  const ordered = [...findings].sort(comparePlanOrder);
  const items: PlanItem[] = ordered.map((finding, index) => ({
    priority: classifyPriority(finding),
    rank: index + 1,
    reason: priorityReason(finding),
    finding,
  }));
  const counts = { P1: 0, P2: 0, P3: 0 } satisfies Record<PlanPriority, number>;
  for (const item of items) counts[item.priority] += 1;
  const sections = PLAN_PRIORITIES.map((priority) => ({
    priority,
    label: PRIORITY_LABEL[priority],
    description: PRIORITY_DESCRIPTION[priority],
    items: items.filter((item) => item.priority === priority),
  }));
  return { items, sections, counts };
}

/**
 * The plan in one sentence, for the executive summary.
 *
 * An empty P1 is stated as a result rather than left out: "nothing is
 * exploitable today" is a finding of its own, and only means anything next to
 * the coverage numbers.
 */
export function planHeadline(plan: Plan): string {
  const { P1, P2, P3 } = plan.counts;
  if (P1 + P2 + P3 === 0) return "No findings, so there is nothing to prioritise.";
  const head =
    P1 === 0
      ? "Nothing in this run is exploitable as the code stands, and nothing destroys stored data"
      : P1 === 1
        ? "1 finding is exploitable now or destroys stored data"
        : `${P1} findings are exploitable now or destroy stored data`;
  return `${head}; ${P2} should not ship in a release; ${P3} ${P3 === 1 ? "is" : "are"} hygiene.`;
}

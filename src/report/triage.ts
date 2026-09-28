/**
 * Applying a human review to a run.
 *
 * The reviewed verdicts arrive as a document (`src/contracts/triage.ts`); this
 * module turns them into the two things the rest of the pipeline needs: an
 * adjusted `FindingsDocument` to score and render, and a summary of what the
 * review did, which the dossier prints.
 *
 * Four rules, and the first one is the whole point:
 *
 * - **A false finding is withheld, not deleted.** It leaves the findings list
 *   and every count derived from it, and it is recorded here with its rule, its
 *   location, the severity it was reported at and the reviewer's reason. A
 *   reader can see that twelve claims were made and taken back; with a
 *   hand-edited `findings.json` they could not, which is the failure mode this
 *   tool exists to refuse.
 * - **An overstated finding keeps both numbers.** The severity becomes the
 *   corrected one — so the scores, which are recomputed from these findings,
 *   move with it — and the original is kept beside it.
 * - **A confirmed finding is marked.** "A human checked this and it holds" is
 *   the most valuable sentence in the document, and a dossier that discards it
 *   reads exactly like one nobody reviewed.
 * - **An unclear finding is contested, not confirmed.** It stays at its
 *   reported severity and is listed as undecided.
 *
 * Nothing here mutates its input: the adjusted document is a new value, and the
 * caller writes it beside `findings.json` rather than over it.
 */

import type {
  CodeRef,
  Domain,
  Finding,
  FindingsDocument,
  Severity,
} from "../contracts/findings.ts";
import type { TriageDocument, TriageEntry, TriageVerdict } from "../contracts/triage.ts";
import { resolveSeverity } from "../contracts/triage.ts";
import { domainRank, severityRank } from "./plan.ts";

/** One finding a human looked at, and what they decided about it. */
export interface ReviewedFinding {
  readonly id: string;
  readonly domain: Domain;
  readonly rule: string;
  readonly title: string;
  readonly file: string;
  readonly line: number;
  readonly verdict: TriageVerdict;
  /** The severity the run reported before the review. */
  readonly reportedSeverity: Severity;
  /** What it carries now: the correction for `overstated`, the reported one otherwise. */
  readonly severity: Severity;
  /** The reviewer's reason, verbatim. */
  readonly note: string;
}

/** What the review changed in one domain, before and after. */
export interface TriageDomainChange {
  readonly domain: Domain;
  readonly reviewed: number;
  readonly confirmed: number;
  readonly corrected: number;
  readonly withheld: number;
  readonly contested: number;
  readonly findingsBefore: number;
  readonly findingsAfter: number;
  readonly severityBefore: Readonly<Record<Severity, number>>;
  readonly severityAfter: Readonly<Record<Severity, number>>;
  /**
   * Phase 6's number for this domain before the review, and after it.
   *
   * Absent when the caller supplied no scorer, `null` when phase 6 published no
   * number for the domain — which is not a zero and must never be rendered as
   * one.
   */
  readonly scoreBefore?: number | null | undefined;
  readonly scoreAfter?: number | null | undefined;
}

/** Everything the report says about the review itself. */
export interface TriageSummary {
  /** Who reviewed, in the reviewer's own words. */
  readonly reviewer: string;
  /** Verdicts applied: how many findings a human actually examined. */
  readonly reviewed: number;
  /** Findings in the run before the review. */
  readonly findingsBefore: number;
  /** Findings after it: the withheld ones are gone. */
  readonly findingsAfter: number;
  /** Findings still in the dossier that no human looked at. */
  readonly unreviewed: number;
  readonly confirmed: readonly ReviewedFinding[];
  readonly corrected: readonly ReviewedFinding[];
  readonly withheld: readonly ReviewedFinding[];
  readonly contested: readonly ReviewedFinding[];
  /** Only the domains the review touched; an untouched domain has nothing to say. */
  readonly domains: readonly TriageDomainChange[];
  /** How far the review reached, in one sentence both renderers print. */
  readonly statement: string;
  /** What the rest of the dossier is, in one sentence. The disclosure that matters. */
  readonly unreviewedStatement: string;
}

/** An adjusted document and the record of what adjusted it. */
export interface TriageResult {
  readonly document: FindingsDocument;
  readonly summary: TriageSummary;
}

/** One field the reviewer and the run disagree about for the same finding. */
export interface TriageMismatch {
  readonly id: string;
  readonly field: "rule" | "file" | "line" | "reportedSeverity";
  /** What the triage says. */
  readonly reviewed: string;
  /** What this run says. */
  readonly found: string;
}

/**
 * A triage that is not about this run.
 *
 * Reported by id rather than counted: "the triage does not match" leaves the
 * reviewer nothing to act on, while a list of ids tells them whether they are
 * one run behind or looking at another repository entirely. Ignoring these
 * verdicts is the one thing this must not do — a verdict that silently applied
 * to nothing would leave the reviewer believing a finding was withheld when it
 * is still in the document.
 */
export class StaleTriageError extends Error {
  /** Verdicts for findings this run does not contain. */
  readonly unknownIds: readonly string[];
  /** Verdicts whose finding exists but is not the one the reviewer described. */
  readonly mismatches: readonly TriageMismatch[];

  constructor(unknownIds: readonly string[], mismatches: readonly TriageMismatch[]) {
    super(describeStaleTriage(unknownIds, mismatches));
    this.name = "StaleTriageError";
    this.unknownIds = unknownIds;
    this.mismatches = mismatches;
  }
}

/** The sentence a {@link StaleTriageError} carries; one line, every id named. */
function describeStaleTriage(
  unknownIds: readonly string[],
  mismatches: readonly TriageMismatch[],
): string {
  const parts: string[] = [];
  if (unknownIds.length > 0) {
    parts.push(
      `the triage carries ${pluralise(unknownIds.length, "verdict")} for ${unknownIds.length === 1 ? "a finding" : "findings"} this run does not contain: ${unknownIds.join(", ")}`,
    );
  }
  for (const mismatch of mismatches) {
    parts.push(
      `${mismatch.id} was reviewed as ${mismatch.field} ${mismatch.reviewed}, but this run reports ${mismatch.found}`,
    );
  }
  return `${parts.join("; ")}. A triage file belongs to one run: re-verify against this run's findings, or render the run the verdicts were written for`;
}

/** `1 finding` / `4 findings`. */
function pluralise(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** Every severity at zero, the shape a before/after comparison counts into. */
function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/** Counts the severities of a list of findings. */
function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts = emptyCounts();
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/**
 * How one run is scored, so the before/after numbers are phase 6's own.
 *
 * Passed in rather than computed here: scoring a document needs the run's other
 * artifacts — the audit, the inventory, the negotiated scope — and a second
 * scorer built from the findings alone would print a number next to the
 * scorecard that disagreed with it.
 */
export type DomainScorer = (
  document: FindingsDocument,
) => readonly { readonly domain: Domain; readonly score: number | null }[];

/** Options for {@link applyTriage}. */
export interface TriageOptions {
  readonly score?: DomainScorer | undefined;
}

/** Report order: worst domain first, then worst severity, then the citation. */
function compareReviewed(left: ReviewedFinding, right: ReviewedFinding): number {
  return (
    domainRank(left.domain) - domainRank(right.domain) ||
    severityRank(left.reportedSeverity) - severityRank(right.reportedSeverity) ||
    left.file.localeCompare(right.file) ||
    left.line - right.line ||
    left.id.localeCompare(right.id)
  );
}

/** The finding's citation as the reviewer would read it back. */
function locationOf(location: CodeRef): { file: string; line: number } {
  return { file: location.file, line: location.line };
}

/** Which fields of a verdict must describe the finding it names. */
function mismatchesOf(entry: TriageEntry, finding: Finding): TriageMismatch[] {
  const found: TriageMismatch[] = [];
  const add = (field: TriageMismatch["field"], reviewed: string, actual: string): void => {
    if (reviewed !== actual) found.push({ id: entry.id, field, reviewed, found: actual });
  };
  add("rule", entry.rule, finding.rule);
  add("file", entry.file, finding.location.file);
  add("line", String(entry.line), String(finding.location.line));
  add("reportedSeverity", entry.reportedSeverity, finding.severity);
  return found;
}

/**
 * Applies a human review to a run.
 *
 * Throws {@link StaleTriageError} when a verdict names a finding this run does
 * not contain, or describes it differently from the way the run reports it.
 * Both mean the same thing — the reviewer read a different run — and both have
 * to stop the render rather than quietly apply to nothing.
 */
export function applyTriage(
  document: FindingsDocument,
  triage: TriageDocument,
  options: TriageOptions = {},
): TriageResult {
  const byId = new Map(document.findings.map((finding) => [finding.id, finding]));
  const unknownIds: string[] = [];
  const mismatches: TriageMismatch[] = [];
  for (const entry of triage.verdicts) {
    const finding = byId.get(entry.id);
    if (finding === undefined) {
      unknownIds.push(entry.id);
      continue;
    }
    mismatches.push(...mismatchesOf(entry, finding));
  }
  if (unknownIds.length > 0 || mismatches.length > 0) {
    throw new StaleTriageError(unknownIds, mismatches);
  }

  const verdicts = new Map(triage.verdicts.map((entry) => [entry.id, entry]));
  const reviewed: ReviewedFinding[] = [];
  const findings: Finding[] = [];

  for (const finding of document.findings) {
    const entry = verdicts.get(finding.id);
    if (entry === undefined) {
      findings.push(finding);
      continue;
    }
    // Only an `overstated` verdict moves a severity. `unclear` deliberately does
    // not: a finding nobody could decide keeps the severity it was reported at,
    // because lowering it would be the review making a claim it just declined to
    // make.
    const correction = entry.verdict === "overstated" ? resolveSeverity(entry.severity) : undefined;
    const severity = correction ?? finding.severity;
    reviewed.push({
      id: finding.id,
      domain: finding.domain,
      rule: finding.rule,
      title: finding.title,
      ...locationOf(finding.location),
      verdict: entry.verdict,
      reportedSeverity: finding.severity,
      severity,
      note: entry.note,
    });
    // The one place a finding leaves the document. Everything downstream — the
    // counts, the charts, the plan, the scores — is computed from this list, so
    // a withheld finding is absent from all of them and present only in the
    // summary below.
    if (entry.verdict === "false") continue;
    findings.push(severity === finding.severity ? finding : { ...finding, severity });
  }

  const adjusted: FindingsDocument = { ...document, findings };
  const pick = (verdict: TriageVerdict): ReviewedFinding[] =>
    reviewed.filter((entry) => entry.verdict === verdict).sort(compareReviewed);
  const confirmed = pick("true");
  const corrected = pick("overstated");
  const withheld = pick("false");
  const contested = pick("unclear");

  const scorer = options.score;
  const before = scorer === undefined ? undefined : scoreMap(scorer(document));
  const after = scorer === undefined ? undefined : scoreMap(scorer(adjusted));

  const touched = [...new Set(reviewed.map((entry) => entry.domain))].sort(
    (left, right) => domainRank(left) - domainRank(right),
  );
  const domains: TriageDomainChange[] = touched.map((domain) => {
    const owned = reviewed.filter((entry) => entry.domain === domain);
    const originals = document.findings.filter((finding) => finding.domain === domain);
    const remaining = findings.filter((finding) => finding.domain === domain);
    return {
      domain,
      reviewed: owned.length,
      confirmed: owned.filter((entry) => entry.verdict === "true").length,
      corrected: owned.filter((entry) => entry.verdict === "overstated").length,
      withheld: owned.filter((entry) => entry.verdict === "false").length,
      contested: owned.filter((entry) => entry.verdict === "unclear").length,
      findingsBefore: originals.length,
      findingsAfter: remaining.length,
      severityBefore: countBySeverity(originals),
      severityAfter: countBySeverity(remaining),
      ...(before === undefined ? {} : { scoreBefore: before.get(domain) ?? null }),
      ...(after === undefined ? {} : { scoreAfter: after.get(domain) ?? null }),
    };
  });

  const findingsBefore = document.findings.length;
  const unreviewed = findings.length - (confirmed.length + corrected.length + contested.length);
  const summary: TriageSummary = {
    reviewer: triage.reviewer,
    reviewed: reviewed.length,
    findingsBefore,
    findingsAfter: findings.length,
    unreviewed,
    confirmed,
    corrected,
    withheld,
    contested,
    domains,
    statement: reviewStatement(triage.reviewer, {
      reviewed: reviewed.length,
      findingsBefore,
      confirmed: confirmed.length,
      corrected: corrected.length,
      withheld: withheld.length,
      contested: contested.length,
    }),
    unreviewedStatement: unreviewedStatement(unreviewed),
  };
  return { document: adjusted, summary };
}

/** A scorer's answer as a lookup, so a domain with no number stays `null`. */
function scoreMap(
  rows: readonly { readonly domain: Domain; readonly score: number | null }[],
): Map<Domain, number | null> {
  return new Map(rows.map((row) => [row.domain, row.score]));
}

/** How far the review reached: the sentence the cover, the summary and the section share. */
export function reviewStatement(
  reviewer: string,
  counts: {
    readonly reviewed: number;
    readonly findingsBefore: number;
    readonly confirmed: number;
    readonly corrected: number;
    readonly withheld: number;
    readonly contested: number;
  },
): string {
  const outcomes = [
    `${counts.confirmed} confirmed`,
    `${counts.corrected} corrected`,
    `${counts.withheld} withheld`,
    `${counts.contested} contested`,
  ].join(", ");
  return `${counts.reviewed} of ${pluralise(counts.findingsBefore, "finding")} in this run ${counts.reviewed === 1 ? "was" : "were"} verified against the code by hand (reviewer: ${reviewer}): ${outcomes}.`;
}

/** What the unreviewed remainder is — the sentence a reviewed dossier cannot omit. */
export function unreviewedStatement(unreviewed: number): string {
  if (unreviewed === 0) {
    return "Every finding in this dossier was examined by a human; none of it is unreviewed model output.";
  }
  return `The other ${pluralise(unreviewed, "finding")} in this dossier ${unreviewed === 1 ? "carries" : "carry"} no human review: ${unreviewed === 1 ? "it is" : "they are"} this run's own output as generated, and nothing in this document says a person checked ${unreviewed === 1 ? "it" : "them"}.`;
}

/** Every reviewed finding by id, for a renderer marking findings as it prints them. */
export function reviewIndex(summary: TriageSummary): ReadonlyMap<string, ReviewedFinding> {
  const index = new Map<string, ReviewedFinding>();
  for (const entry of [
    ...summary.confirmed,
    ...summary.corrected,
    ...summary.withheld,
    ...summary.contested,
  ]) {
    index.set(entry.id, entry);
  }
  return index;
}

/** What one verdict did, in the words both renderers print beside the finding. */
export function reviewLabel(review: ReviewedFinding): string {
  switch (review.verdict) {
    case "true":
      return "confirmed by human review against the code";
    case "overstated":
      return `severity corrected by human review from ${review.reportedSeverity} to ${review.severity}`;
    case "unclear":
      return `contested: human review could not decide this one, and it is kept at ${review.reportedSeverity}`;
    case "false":
      return `withheld by human review; reported as ${review.reportedSeverity}`;
  }
}

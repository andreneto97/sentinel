/**
 * Phase 6's artifact: one number per domain, and everything a reader needs to
 * argue with it.
 *
 * Four invariants are enforced by this schema rather than by the code that
 * fills it, because they are the difference between a dossier and a sales
 * sheet:
 *
 * 1. **A domain that was not assessed has `score: null`, never `0` and never
 *    `100`.** The gate lives in the type: there is no number to render, so no
 *    renderer can accidentally print one. `status` says which of the three
 *    cases it is and `statement` says it in a sentence.
 * 2. **A number never travels without its coverage.** Every {@link DomainScore}
 *    carries the fraction of its checks that ran, so `82` and `82 (12 of 30
 *    checks ran)` cannot be confused in the report.
 * 3. **Every deduction and every ceiling is itemised.** The arithmetic that
 *    produced the score is in the document: the per-severity rows that were
 *    subtracted, the cap each tier hit, and — for a ceiling — the reason it
 *    applied, in the prose the report prints.
 * 4. **A score requires examined evidence, not executed checks.** Every
 *    {@link DomainScore} carries an {@link EvidenceSummary} beside its coverage:
 *    how many audit units of the domain's kinds exist, and how many a verdict
 *    actually looked at. Deterministic analysis can *lower* a score; it cannot
 *    certify one, so a domain whose units nobody examined is at best `partial`
 *    and, with no findings either, `not-assessed`.
 *
 * The score phase is pure: it reads no files and writes none. `SCORECARD_FILE`
 * names where a caller that wants this document on disk should put it.
 */

import { z } from "zod";
import { ConfidenceSchema, DomainSchema, SCHEMA_VERSION, SeveritySchema } from "./findings.ts";
import { AuditUnitKindSchema } from "./inventory.ts";

/** Where a caller that persists the scorecard writes it, next to `findings.json`. */
export const SCORECARD_FILE = "scorecard.json";

/** A–F, from the band table in `src/score/bands.ts`. */
export const ScoreBandSchema = z.enum(["A", "B", "C", "D", "F"]);
/** A–F; see {@link ScoreBandSchema}. */
export type ScoreBand = z.infer<typeof ScoreBandSchema>;

/** Every band, best first, for exhaustive rendering and tests. */
export const SCORE_BANDS: readonly ScoreBand[] = ScoreBandSchema.options;

/**
 * Whether a domain earned a number, and how much of it to believe.
 *
 * - `scored` — enough of the domain's checks ran to stand behind the number.
 * - `partial` — a number, with the coverage stated next to it everywhere it
 *   appears. It is a real score over a stated fraction of the domain.
 * - `not-assessed` — **no number at all.** Too few checks ran, the domain was
 *   outside the run's scope, or the checks do not exist yet. This is never a
 *   clean score and never a zero: `score` is `null`.
 */
export const DomainStatusSchema = z.enum(["scored", "partial", "not-assessed"]);
/** Whether a domain earned a number; see {@link DomainStatusSchema}. */
export type DomainStatus = z.infer<typeof DomainStatusSchema>;

/** Every status, for exhaustive rendering and tests. */
export const DOMAIN_STATUSES: readonly DomainStatus[] = DomainStatusSchema.options;

/** Findings counted by severity; every severity present, at zero. */
export const SeverityCountsSchema = z.record(SeveritySchema, z.number().int().nonnegative());
/** Findings counted by severity; see {@link SeverityCountsSchema}. */
export type SeverityCounts = z.infer<typeof SeverityCountsSchema>;

/**
 * What a domain's coverage was when it was scored.
 *
 * `ratio` is `unitsAudited / unitsTotal`, or `0` for a domain with nothing to
 * count — which is the `0/0` row that means "no check for this exists yet",
 * not "everything passed".
 */
export const CoverageSummarySchema = z.object({
  unitsTotal: z.number().int().nonnegative(),
  unitsAudited: z.number().int().nonnegative(),
  /** Units enumerated that produced no verdict, listed in `findings.json`. */
  skipped: z.number().int().nonnegative(),
  ratio: z.number().min(0).max(1),
  /** The sentence the report prints beside the number: `45 of 50 checks ran`. */
  statement: z.string(),
});
/** A domain's coverage at scoring time; see {@link CoverageSummarySchema}. */
export type CoverageSummary = z.infer<typeof CoverageSummarySchema>;

/** One unit kind's share of a domain's evidence: units that exist, units examined. */
export const EvidenceKindSchema = z.object({
  kind: AuditUnitKindSchema,
  /** Units of this kind the inventory enumerated. */
  present: z.number().int().nonnegative(),
  /** Of those, how many an accepted verdict actually examined. */
  verdicted: z.number().int().nonnegative(),
});
/** One unit kind's share of a domain's evidence; see {@link EvidenceKindSchema}. */
export type EvidenceKind = z.infer<typeof EvidenceKindSchema>;

/**
 * How much of a domain's evidence was **examined**, as opposed to how many of
 * its checks *ran*.
 *
 * This is the distinction the fourth invariant of the scorecard rests on, and
 * the one whose absence let a repository whose migrations and data-access sites
 * number in the thousands score 100 (A) for its data layer, because the one
 * analyzer step planned for that domain executed and had nothing to say.
 *
 * A check that ran is not evidence of health. A linter finding nothing is
 * evidence that a linter ran. Only an **audited unit** — a model verdict
 * Sentinel verified, or a rule that actually examined that unit — is evidence
 * about the unit. So the score phase counts both: {@link CoverageSummary} says
 * what ran, and this says what was looked at.
 *
 * `applies` is `false` for a domain that has no audit units at all — supply
 * chain is judged by trivy over the whole lockfile, not unit by unit — and in
 * that case the checks are the only coverage there is and `ratio` is `0` because
 * there is nothing to divide. Read `applies` before `ratio`; or read
 * `DomainScore.assessedRatio`, which has already combined the two.
 */
export const EvidenceSummarySchema = z.object({
  /** False when this domain has no audit units, so examined evidence is not its measure. */
  applies: z.boolean(),
  /** Units of this domain's kinds that the inventory enumerated. */
  unitsPresent: z.number().int().nonnegative(),
  /** Of those, how many came back with a verdict Sentinel accepted. */
  unitsVerdicted: z.number().int().nonnegative(),
  /** `unitsVerdicted / unitsPresent`; `0` when `applies` is false. */
  ratio: z.number().min(0).max(1),
  /** Per-kind breakdown, biggest first — the detail the reason sentence names. */
  kinds: z.array(EvidenceKindSchema),
  /** `0 of 4,500 units audited: 4,000 data-access call sites and 500 migrations exist…`. */
  statement: z.string(),
});
/** How much of a domain's evidence was examined; see {@link EvidenceSummarySchema}. */
export type EvidenceSummary = z.infer<typeof EvidenceSummarySchema>;

/**
 * One severity tier's contribution to a domain's deduction.
 *
 * `raw` is what the findings would subtract unbounded; `applied` is what they
 * actually subtracted after the tier's cap. When the two differ, `capped` is
 * true and the report can say so — that is the sentence which explains why
 * forty `info` findings did not sink the domain.
 */
export const SeverityDeductionSchema = z.object({
  severity: SeveritySchema,
  count: z.number().int().nonnegative(),
  /** Of `count`, how many were low-confidence and so counted at half weight. */
  discounted: z.number().int().nonnegative(),
  perFinding: z.number().nonnegative(),
  raw: z.number().nonnegative(),
  cap: z.number().nonnegative(),
  applied: z.number().nonnegative(),
  capped: z.boolean(),
});
/** One severity tier's deduction; see {@link SeverityDeductionSchema}. */
export type SeverityDeduction = z.infer<typeof SeverityDeductionSchema>;

/**
 * A hard ceiling that fired, and why.
 *
 * `binding` separates "this ceiling caught the score" from "this ceiling fired
 * but the deductions had already taken the score below it". Both are recorded,
 * because the finding that triggered it is worth naming either way, and only
 * the first is an explanation of the number.
 */
export const AppliedCeilingSchema = z.object({
  /** Stable id from the ceiling table, e.g. `appsec.committed-secret`. */
  id: z.string(),
  domain: DomainSchema,
  cap: z.number().int().min(0).max(100),
  title: z.string(),
  /** The prose the report renders: what fired it, and why that caps the domain. */
  reason: z.string(),
  /** True when the cap actually lowered the score. */
  binding: z.boolean(),
  /** Ids of the findings that fired it, so a reader can go and read them. */
  triggeredBy: z.array(z.string()),
});
/** A hard ceiling that fired; see {@link AppliedCeilingSchema}. */
export type AppliedCeiling = z.infer<typeof AppliedCeilingSchema>;

/**
 * One domain's verdict.
 *
 * `score`, `band`, `bandLabel` and `baseScore` are all `null` together, exactly
 * when `status` is `not-assessed`. `baseScore` is `100` minus the deductions,
 * before any ceiling, so a reader can see what the ceiling cost.
 *
 * `deductions` and `ceilings` are itemised even for a domain with no number:
 * the findings exist, and what they would have cost is information, not a
 * score. A renderer must not reconstruct `100 - deductionTotal` for a
 * `not-assessed` domain — that number was refused on purpose.
 */
export const DomainScoreSchema = z.object({
  domain: DomainSchema,
  status: DomainStatusSchema,
  /** `null` when the domain was not assessed. Never `0` in that case. */
  score: z.number().int().min(0).max(100).nullable(),
  band: ScoreBandSchema.nullable(),
  /** The band's prose label, for a reader who does not read letters. */
  bandLabel: z.string().nullable(),
  /** The score the deductions alone produced, before ceilings. */
  baseScore: z.number().int().min(0).max(100).nullable(),
  coverage: CoverageSummarySchema,
  /** What was *examined*, as opposed to what ran; see {@link EvidenceSummarySchema}. */
  evidence: EvidenceSummarySchema,
  /**
   * The fraction the number actually speaks for: the lesser of the checks that
   * ran and the units that were examined. This is the one ratio a renderer
   * should print beside a score, because it is the only one that cannot be
   * satisfied by a check nobody looked through.
   */
  assessedRatio: z.number().min(0).max(1),
  deductions: z.array(SeverityDeductionSchema),
  deductionTotal: z.number().nonnegative(),
  ceilings: z.array(AppliedCeilingSchema),
  findingsTotal: z.number().int().nonnegative(),
  findingsBySeverity: SeverityCountsSchema,
  /** Checks that ran and passed. They are reported, and they never add points. */
  assurances: z.number().int().nonnegative(),
  assuranceUnits: z.number().int().nonnegative(),
  /** This domain's share of the overall mean, before coverage scales it. */
  weight: z.number().nonnegative(),
  /** `weight * coverage.ratio`; `0` for a domain that does not contribute. */
  effectiveWeight: z.number().nonnegative(),
  /** The sentence the report prints: the caveat, or the reason there is no number. */
  statement: z.string(),
});
/** One domain's verdict; see {@link DomainScoreSchema}. */
export type DomainScore = z.infer<typeof DomainScoreSchema>;

/** One scored domain's share of the overall mean. */
export const DomainContributionSchema = z.object({
  domain: DomainSchema,
  score: z.number().int().min(0).max(100),
  status: DomainStatusSchema,
  weight: z.number().nonnegative(),
  /** The domain's `assessedRatio`: checks that ran *and* units that were examined. */
  coverageRatio: z.number().min(0).max(1),
  effectiveWeight: z.number().nonnegative(),
});
/** One domain's share of the overall mean; see {@link DomainContributionSchema}. */
export type DomainContribution = z.infer<typeof DomainContributionSchema>;

/** A domain left out of the overall number, and why it was left out. */
export const UnscoredDomainSchema = z.object({
  domain: DomainSchema,
  reason: z.string(),
  /** Findings reported for it anyway. They are listed; they are not scored. */
  findingsTotal: z.number().int().nonnegative(),
});
/** A domain excluded from the overall number; see {@link UnscoredDomainSchema}. */
export type UnscoredDomain = z.infer<typeof UnscoredDomainSchema>;

/** The clamp that stops four good domains from averaging away one failing one. */
export const OverallClampSchema = z.object({
  /** True when the clamp actually lowered the mean. */
  applied: z.boolean(),
  /** `worstScore + 15`: the highest the overall number is allowed to be. */
  limit: z.number().int().min(0).max(100),
  worstDomain: DomainSchema,
  worstScore: z.number().int().min(0).max(100),
  reason: z.string(),
});
/** The overall clamp; see {@link OverallClampSchema}. */
export type OverallClamp = z.infer<typeof OverallClampSchema>;

/** The run-level number, and the domains it does and does not speak for. */
export const OverallScoreSchema = z.object({
  status: DomainStatusSchema,
  /** `null` when no domain earned a number. */
  score: z.number().int().min(0).max(100).nullable(),
  band: ScoreBandSchema.nullable(),
  bandLabel: z.string().nullable(),
  /** The weighted mean before the clamp, to one decimal. */
  weightedMean: z.number().min(0).max(100).nullable(),
  clamp: OverallClampSchema.nullable(),
  contributions: z.array(DomainContributionSchema),
  unscored: z.array(UnscoredDomainSchema),
  statement: z.string(),
});
/** The run-level number; see {@link OverallScoreSchema}. */
export type OverallScore = z.infer<typeof OverallScoreSchema>;

/** One thing that happened in this run which costs confidence, and what it cost. */
export const ConfidenceSignalSchema = z.object({
  /** Stable id, e.g. `units.partially-audited`. */
  id: z.string(),
  /** What happened, with the numbers that prove it. */
  detail: z.string(),
  penalty: z.number().int().nonnegative(),
});
/** One signal that costs confidence; see {@link ConfidenceSignalSchema}. */
export type ConfidenceSignal = z.infer<typeof ConfidenceSignalSchema>;

/**
 * The raw counters confidence was derived from, echoed so the report can print
 * `180 of 200 units audited` rather than the word "medium" on its own.
 */
export const ConfidenceBasisSchema = z.object({
  unitsTotal: z.number().int().nonnegative(),
  unitsAudited: z.number().int().nonnegative(),
  batchesTotal: z.number().int().nonnegative(),
  batchesPartial: z.number().int().nonnegative(),
  batchesFailed: z.number().int().nonnegative(),
  /** Citations the verifier had to move to match the code on disk. */
  relocatedCitations: z.number().int().nonnegative(),
  /** Claims dropped because they did not resolve, or pointed outside the slices. */
  droppedCitations: z.number().int().nonnegative(),
  analyzersTotal: z.number().int().nonnegative(),
  /** Analyzers that ran with less than they need, or whose output failed. */
  analyzersDegraded: z.number().int().nonnegative(),
  findingsTotal: z.number().int().nonnegative(),
  lowConfidenceFindings: z.number().int().nonnegative(),
  /** True when the answers came from a recorded transcript, not from a live model. */
  synthetic: z.boolean(),
  aborted: z.boolean(),
  quotaExhausted: z.boolean(),
});
/** The counters confidence was derived from; see {@link ConfidenceBasisSchema}. */
export type ConfidenceBasis = z.infer<typeof ConfidenceBasisSchema>;

/** How much of this run's evidence is worth leaning on. */
export const RunConfidenceSchema = z.object({
  level: ConfidenceSchema,
  /** Sum of the signals' penalties; `0` is a clean run. */
  penalty: z.number().int().nonnegative(),
  signals: z.array(ConfidenceSignalSchema),
  basis: ConfidenceBasisSchema,
  statement: z.string(),
});
/** Run-level confidence; see {@link RunConfidenceSchema}. */
export type RunConfidence = z.infer<typeof RunConfidenceSchema>;

/** The phase 6 artifact. */
export const ScorecardSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  runId: z.string(),
  target: z.string(),
  overall: OverallScoreSchema,
  /** One row per domain in the contract's order, scored or not. */
  domains: z.array(DomainScoreSchema),
  confidence: RunConfidenceSchema,
  findingsTotal: z.number().int().nonnegative(),
  findingsBySeverity: SeverityCountsSchema,
  assurancesTotal: z.number().int().nonnegative(),
});
/** The phase 6 artifact; see {@link ScorecardSchema}. */
export type Scorecard = z.infer<typeof ScorecardSchema>;

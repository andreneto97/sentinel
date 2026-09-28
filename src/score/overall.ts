/**
 * The run-level number: a weighted mean of the domains that earned one, then
 * clamped so the mean cannot bury the worst of them.
 *
 * Two rules, and the second one is why this file is not a one-liner.
 *
 * **Weighting.** Domains do not matter equally — an unauthenticated admin route
 * is not an unused export — so {@link DOMAIN_WEIGHTS} sets their shares. Each
 * share is then scaled by `DomainScore.assessedRatio`: the fraction of that
 * domain's checks that ran *and* of its units that were examined, whichever is
 * smaller. A domain assessed over half of itself carries half its weight. The
 * scaling is continuous on purpose: there is no cliff where 91% coverage counts
 * fully and 89% counts at 0.89, and no incentive for a run to sit just above a
 * threshold.
 *
 * **The clamp.** A mean is an averaging machine, and averaging is exactly how a
 * failing domain disappears: four `B`s and one `F` average to a `C`, which
 * reads as "some work to do" rather than "one of these is on fire". So the
 * overall number may never exceed the **worst scored domain plus 15**. Four
 * 85s and one 30 report 45, not 74. The clamp records which domain set it and
 * what the mean was before it applied, because a number that was pulled down
 * by one domain should say which one.
 *
 * Domains with no number are never folded in at zero — a zero is a claim, and
 * "we did not look" is not one. They are excluded and listed, each with the
 * reason the coverage gate gave.
 */

import { type Domain, DomainSchema } from "../contracts/findings.ts";
import {
  type DomainContribution,
  DomainContributionSchema,
  type DomainScore,
  type OverallClamp,
  type OverallScore,
  OverallScoreSchema,
  type UnscoredDomain,
} from "../contracts/scorecard.ts";
import { bandFor, bandLabel } from "./bands.ts";

/**
 * Each domain's share of the overall number. They sum to 100, which makes them
 * readable as percentages, though only their ratios matter.
 */
export const DOMAIN_WEIGHTS: Readonly<Record<Domain, number>> = {
  appsec: 30,
  data: 20,
  dependencies: 15,
  api: 12,
  delivery: 8,
  serverless: 8,
  reliability: 5,
  deadcode: 2,
};

/** How far above the weakest scored domain the overall number may sit. */
export const WORST_DOMAIN_HEADROOM = 15;

/** A domain's weight scaled by the fraction of its checks that ran. */
export function effectiveWeight(domain: Domain, coverageRatio: number): number {
  return Math.round(DOMAIN_WEIGHTS[domain] * Math.min(1, Math.max(0, coverageRatio)) * 100) / 100;
}

/** Domain order for every list in the scorecard: the contract's enum order. */
const DOMAIN_RANK: ReadonlyMap<Domain, number> = new Map(
  DomainSchema.options.map((domain, index) => [domain, index]),
);

/** The weakest scored domain; ties go to the first in contract order. */
function weakest(contributions: readonly DomainContribution[]): DomainContribution | null {
  let worst: DomainContribution | null = null;
  for (const contribution of contributions) {
    if (worst === null || contribution.score < worst.score) {
      worst = contribution;
      continue;
    }
    if (contribution.score === worst.score) {
      const rank = DOMAIN_RANK.get(contribution.domain) ?? Number.MAX_SAFE_INTEGER;
      const worstRank = DOMAIN_RANK.get(worst.domain) ?? Number.MAX_SAFE_INTEGER;
      if (rank < worstRank) worst = contribution;
    }
  }
  return worst;
}

/** The sentence that explains the clamp, whether or not it bit. */
function clampReason(
  worst: DomainContribution,
  limit: number,
  applied: boolean,
  mean: number,
): string {
  const head = `${worst.domain} is the weakest scored domain at ${worst.score}, so the overall number may not exceed ${limit}`;
  return applied
    ? `${head}. The weighted mean was ${mean}; one failing domain is not averaged away by the healthy ones.`
    : `${head}. The weighted mean of ${mean} is already below that, so the cap did not bite.`;
}

/** What the report prints under the overall number. */
function statementFor(
  score: number | null,
  contributions: readonly DomainContribution[],
  unscored: readonly UnscoredDomain[],
): string {
  if (score === null) {
    return `not assessed: no domain had enough coverage to earn a number (${unscored.length} ${unscored.length === 1 ? "domain" : "domains"} not assessed)`;
  }
  const scored = `${score} (${bandFor(score)}) across ${contributions.length} scored ${contributions.length === 1 ? "domain" : "domains"}`;
  if (unscored.length === 0) return scored;
  return `${scored}; ${unscored.length} not assessed and excluded from the mean: ${unscored.map((row) => row.domain).join(", ")}`;
}

/**
 * Builds the overall number from the per-domain rows.
 *
 * Domains arrive already gated, so this function never decides whether one
 * counts — it only reads `score === null` — and that keeps the coverage rule in
 * exactly one place.
 */
export function buildOverall(domains: readonly DomainScore[]): OverallScore {
  const contributions: DomainContribution[] = [];
  const unscored: UnscoredDomain[] = [];

  for (const row of domains) {
    if (row.score === null) {
      unscored.push({
        domain: row.domain,
        reason: row.statement,
        findingsTotal: row.findingsTotal,
      });
      continue;
    }
    contributions.push(
      DomainContributionSchema.parse({
        domain: row.domain,
        score: row.score,
        status: row.status,
        weight: row.weight,
        // The assessed ratio, not the check ratio: a domain whose single planned
        // check ran over units nobody examined must not carry its full weight
        // into the mean on the strength of that one check.
        coverageRatio: row.assessedRatio,
        effectiveWeight: row.effectiveWeight,
      }),
    );
  }

  // `weakest` is null exactly when nothing contributed, which is also the only
  // case with no number to report — one check rather than two that could drift.
  const worst = weakest(contributions);
  if (worst === null) {
    return OverallScoreSchema.parse({
      status: "not-assessed",
      score: null,
      band: null,
      bandLabel: null,
      weightedMean: null,
      clamp: null,
      contributions,
      unscored,
      statement: statementFor(null, contributions, unscored),
    });
  }

  const totalWeight = contributions.reduce((sum, row) => sum + row.effectiveWeight, 0);
  const rawMean =
    totalWeight > 0
      ? contributions.reduce((sum, row) => sum + row.score * row.effectiveWeight, 0) / totalWeight
      : contributions.reduce((sum, row) => sum + row.score, 0) / contributions.length;
  const mean = Math.round(rawMean * 10) / 10;

  const limit = Math.min(100, worst.score + WORST_DOMAIN_HEADROOM);
  const applied = mean > limit;
  const score = Math.round(Math.min(mean, limit));

  const clamp: OverallClamp = {
    applied,
    limit,
    worstDomain: worst.domain,
    worstScore: worst.score,
    reason: clampReason(worst, limit, applied, mean),
  };

  const partial = contributions.some((row) => row.status === "partial");
  const status = unscored.length > 0 || partial ? "partial" : "scored";

  return OverallScoreSchema.parse({
    status,
    score,
    band: bandFor(score),
    bandLabel: bandLabel(bandFor(score)),
    weightedMean: mean,
    clamp,
    contributions,
    unscored,
    statement: statementFor(score, contributions, unscored),
  });
}

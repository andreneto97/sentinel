/**
 * The rule that matters most: coverage decides whether a domain gets a number
 * at all — and coverage is now two questions, not one.
 *
 * **Did the checks run?** A domain where one of five checks ran has not earned a
 * good score. It has earned *no* score, and the failure mode this file exists to
 * prevent is the one where it quietly earns a great one because four checks that
 * never ran found nothing to deduct.
 *
 * **Was any of the evidence examined?** That first question, alone, missed the
 * same failure in a worse form. A domain that plans *one* shallow check, runs it,
 * and hears nothing is at `1/1` — perfect coverage by the only measure there
 * was — and a repository whose migrations and data-access sites number in the
 * thousands therefore scored `100 (A)` for its data layer on a run where no model
 * audited anything. So the gate also reads {@link EvidenceSummary}: how many audit units
 * of the domain's kinds exist, and how many a verdict actually looked at.
 *
 * The principle, which is larger than the bug: **deterministic analysis can
 * lower a score; it cannot certify one.** Findings are evidence of problems.
 * Only an examined unit is evidence of health. The status a domain may reach is
 * therefore the stricter of what its checks earned and what its evidence
 * supports:
 *
 * - **`scored`** — at least {@link SCORED_COVERAGE} of the domain's checks ran
 *   *and* at least that fraction of its units was examined. The number stands on
 *   its own.
 * - **`partial`** — at least {@link PARTIAL_COVERAGE} of both. There is a number,
 *   and the coverage travels with it everywhere it is printed. A domain whose
 *   units were *not* examined can also land here — but only when it has findings,
 *   and then its score is a ceiling rather than a grade (see `ceilings.ts`).
 * - **`not-assessed`** — anything less, including a `0/0` domain whose checks do
 *   not exist yet, a domain the run's scope left out, and a domain with units,
 *   no verdicts and no findings. There is **no number**: `score` is `null`, not
 *   `0`, and the reason is a sentence that names the units nobody looked at.
 *
 * The unit of *check* coverage is whatever `findings.json` counted for that
 * domain — phase 1 counts analyzer steps, phase 4 counts audited units, and the
 * merged row holds both. The unit of *evidence* is the audit unit, counted from
 * `inventory.json` whether or not phase 4 ever ran.
 */

import type { Coverage, Domain } from "../contracts/findings.ts";
import {
  type CoverageSummary,
  CoverageSummarySchema,
  type DomainStatus,
  type EvidenceSummary,
} from "../contracts/scorecard.ts";
import {
  describeAudited,
  describeUnits,
  describeUnitsExamined,
  domainEvidence,
  noEvidence,
} from "./evidence.ts";

/** At or above this fraction of checks, a domain's number stands on its own. */
export const SCORED_COVERAGE = 0.9;

/** Below this fraction, there is no number at all. */
export const PARTIAL_COVERAGE = 0.5;

/** The gate's verdict for one domain: its status, both coverages, and the sentence. */
export interface GateResult {
  readonly status: DomainStatus;
  readonly coverage: CoverageSummary;
  readonly evidence: EvidenceSummary;
  /**
   * The lesser of the two fractions: what the number actually speaks for. This
   * is the ratio that weights the overall mean and the one a renderer prints.
   */
  readonly assessedRatio: number;
  /** What the report prints next to the score, or instead of it. */
  readonly statement: string;
}

/** `91%`, the way a coverage fraction is spoken about in prose. */
function percent(ratio: number): string {
  return `${Math.round(ratio * 100)}%`;
}

/** `45 of 50 checks ran` — the phrase a number is never printed without. */
function summarise(unitsTotal: number, unitsAudited: number): string {
  if (unitsTotal === 0) return "no check for this domain ran in this run";
  return `${unitsAudited} of ${unitsTotal} ${unitsTotal === 1 ? "check" : "checks"} ran`;
}

/** Builds the coverage summary carried by every domain row, scored or not. */
function summaryOf(row: Coverage | undefined): CoverageSummary {
  const unitsTotal = row?.unitsTotal ?? 0;
  const unitsAudited = row?.unitsAudited ?? 0;
  // Four decimals: enough to weight the mean, few enough that the artifact
  // diffs cleanly between two runs of the same repository.
  const ratio =
    unitsTotal === 0 ? 0 : Math.round(Math.min(1, unitsAudited / unitsTotal) * 10_000) / 10_000;
  return CoverageSummarySchema.parse({
    unitsTotal,
    unitsAudited,
    skipped: row?.skipped.length ?? 0,
    ratio,
    statement: summarise(unitsTotal, unitsAudited),
  });
}

/** Strictness order, so "the stricter of two statuses" is one comparison. */
const STATUS_RANK: Readonly<Record<DomainStatus, number>> = {
  scored: 2,
  partial: 1,
  "not-assessed": 0,
};

/** The stricter of two statuses. */
function stricter(left: DomainStatus, right: DomainStatus): DomainStatus {
  return STATUS_RANK[left] <= STATUS_RANK[right] ? left : right;
}

/** The band a fraction of ran-checks earns, before the evidence is consulted. */
function statusForChecks(coverage: CoverageSummary): DomainStatus {
  if (coverage.unitsTotal === 0) return "not-assessed";
  if (coverage.ratio >= SCORED_COVERAGE) return "scored";
  if (coverage.ratio >= PARTIAL_COVERAGE) return "partial";
  return "not-assessed";
}

/**
 * The best status a domain's **examined evidence** can support.
 *
 * Above {@link PARTIAL_COVERAGE} the fractions read like check coverage, for the
 * same reason: a number over half the units, stated as such, is a real number.
 * Below it the domain has no evidence of health at all, and the only question
 * left is whether it has evidence of *problems*: findings mean `partial` — a
 * capped upper bound, which is what deterministic analysis is entitled to
 * assert — and no findings mean there is nothing to say, so nothing is said.
 *
 * `applies: false` returns `scored` because it is not an opinion: the domain has
 * no audit units, so examined units are not its measure and the checks decide
 * alone. `dependencies` is judged by trivy over the entire resolved tree, and
 * demanding audit units of it would be a different lie.
 */
export function statusForEvidence(evidence: EvidenceSummary, findingsTotal: number): DomainStatus {
  if (!evidence.applies) return "scored";
  if (evidence.ratio >= SCORED_COVERAGE) return "scored";
  if (evidence.ratio >= PARTIAL_COVERAGE) return "partial";
  return findingsTotal > 0 ? "partial" : "not-assessed";
}

/** `4,000 data-access call sites and 500 migrations`, empty when there are none. */
function unitsPhrase(evidence: EvidenceSummary): string {
  return describeUnits(evidence.kinds);
}

/**
 * The clause appended to a statement the *checks* decided, naming the units.
 *
 * Nothing is ever printed without it when a domain has units, because the whole
 * defect was a sentence about checks standing in for a statement about code.
 */
function unitsTail(evidence: EvidenceSummary, refused: boolean): string {
  if (!evidence.applies) return "";
  if (refused) {
    return `; ${unitsPhrase(evidence)} of its kinds do exist and ${describeAudited(evidence)}`;
  }
  return `; ${describeUnitsExamined(evidence)}`;
}

/** The sentence for a domain the evidence, not the checks, held back. */
function evidenceStatement(input: {
  readonly status: DomainStatus;
  readonly coverage: CoverageSummary;
  readonly evidence: EvidenceSummary;
  readonly findingsTotal: number;
}): string {
  const { coverage, evidence, findingsTotal } = input;
  const units = unitsPhrase(evidence);
  const audited = describeAudited(evidence);
  const ran = coverage.unitsTotal === 0 ? "no analyzer check ran" : coverage.statement;

  if (input.status === "not-assessed") {
    return (
      `not assessed: ${units} exist and ${audited} in this run, ` +
      `so nothing examined this domain's evidence; ${ran}, and a check that ran is not a unit that was looked at`
    );
  }

  const plural = findingsTotal === 1 ? "finding" : "findings";
  if (evidence.ratio < PARTIAL_COVERAGE) {
    return (
      `partial: ${units} exist and ${audited} in this run; ` +
      `the ${findingsTotal} ${plural} below are evidence of problems, not of health, ` +
      `so the number is an upper bound rather than a grade (${ran})`
    );
  }

  return (
    `partial: ${describeUnitsExamined(evidence)} (${percent(evidence.ratio)}); ` +
    `the score speaks for that fraction only (${ran})`
  );
}

/**
 * Decides whether a domain earned a number, from its check coverage, the
 * evidence somebody examined, and whether the run's scope included it at all.
 *
 * A domain with no coverage row is never scored: `inScope` only changes the
 * sentence — "the scope left it out" reads differently from "the scope included
 * it and no coverage came back", and the second one is a bug worth seeing. Its
 * *units* are named either way, which is how a `serverless` domain nobody
 * enabled still tells the reader that 25 webhook receivers and 8 queue consumers
 * are sitting there unexamined.
 */
export function gateDomain(
  domain: Domain,
  row: Coverage | undefined,
  inScope: boolean,
  evidence: EvidenceSummary = domainEvidence(domain, noEvidence()),
  findingsTotal = 0,
): GateResult {
  const coverage = summaryOf(row);
  const checks = statusForChecks(coverage);
  const supported = statusForEvidence(evidence, findingsTotal);
  const status = stricter(checks, supported);
  // The number speaks for the smaller of the two fractions. A domain with no
  // audit units is not penalised for lacking them: its evidence does not apply,
  // so the checks carry the whole weight.
  const assessedRatio = evidence.applies
    ? Math.min(coverage.ratio, evidence.ratio)
    : coverage.ratio;
  const base = { coverage, evidence, assessedRatio };

  if (row === undefined) {
    const head = inScope
      ? `not assessed: this run produced no coverage for ${domain}, so there is nothing to score against`
      : `not assessed: ${domain} was outside this run's scope, so none of its checks were enumerated`;
    // Out of scope and still full of units is the disclosure most worth making:
    // the scope report says what was offered, and this says what it was offered
    // *about*.
    return { ...base, status: "not-assessed", statement: `${head}${unitsTail(evidence, true)}` };
  }

  // The evidence is the binding constraint: say so in its own words, because
  // "1 of 1 checks ran" is true and would read as a clean bill of health.
  if (STATUS_RANK[supported] < STATUS_RANK[checks]) {
    return {
      ...base,
      status,
      statement: evidenceStatement({ status, coverage, evidence, findingsTotal }),
    };
  }

  const tail = unitsTail(evidence, status === "not-assessed");

  if (coverage.unitsTotal === 0) {
    return {
      ...base,
      status,
      statement: `not assessed: no ${domain} check ran in this run (0 of 0) — the checks are either off or not built yet${tail}`,
    };
  }

  if (coverage.ratio < PARTIAL_COVERAGE) {
    return {
      ...base,
      status,
      statement: `not assessed: only ${coverage.statement} (${percent(coverage.ratio)}) — too little to stand behind a number${tail}`,
    };
  }

  if (coverage.ratio < SCORED_COVERAGE) {
    return {
      ...base,
      status,
      statement: `partial: ${coverage.statement} (${percent(coverage.ratio)}); the score speaks for that fraction only${tail}`,
    };
  }

  // Both measures are satisfied. The evidence clause is still printed when there
  // is evidence to speak of, because `150 of 150 units examined` is the sentence
  // that makes the number worth reading.
  return {
    ...base,
    status,
    statement: `${coverage.statement} (${percent(coverage.ratio)})${tail}`,
  };
}

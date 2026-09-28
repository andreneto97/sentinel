/**
 * How findings become a number: weight per severity, and a cap per tier.
 *
 * The cap is the interesting half. Without it, volume decides the score — and
 * volume is the one thing an analyzer is best at producing. Forty `info`
 * findings about unused exports are not worse than one unpatched RCE, so each
 * tier can only take so much off no matter how many findings it holds: the
 * whole `info` tier is worth 5 points, the whole `low` tier 12, while a single
 * `critical` takes 25. A domain can therefore be dragged to `F` by three
 * criticals and never by a hundred `info`s, which is the ordering a reader
 * assumes the number has.
 *
 * The other rule here is smaller and pulls the other way: a **low-confidence
 * finding counts at half weight**. Sentinel says `low` when it is reporting a
 * lead rather than a fact, and charging full price for a lead is its own kind
 * of dishonesty — it makes the number pessimistic in exactly the cases where
 * the evidence is thinnest.
 *
 * Nothing in here gives points back. Assurances are counted and reported per
 * domain, never added to the score: a domain cannot buy its way out of a
 * finding by passing other checks, and the only thing that moves a score up is
 * having fewer problems.
 */

import type { Finding, Severity } from "../contracts/findings.ts";
import { SeveritySchema } from "../contracts/findings.ts";
import {
  type SeverityCounts,
  type SeverityDeduction,
  SeverityDeductionSchema,
} from "../contracts/scorecard.ts";

/** What one severity tier costs, and the most it can cost in total. */
export interface SeverityPolicy {
  /** Points one finding of this severity subtracts. */
  readonly perFinding: number;
  /** The most this tier can subtract from one domain, however many it holds. */
  readonly cap: number;
}

/**
 * The severity table. One `critical` (25) outweighs the entire `low` tier (12)
 * and the entire `info` tier (5) put together.
 */
export const SEVERITY_POLICY: Readonly<Record<Severity, SeverityPolicy>> = {
  critical: { perFinding: 25, cap: 60 },
  high: { perFinding: 12, cap: 40 },
  medium: { perFinding: 6, cap: 25 },
  low: { perFinding: 2, cap: 12 },
  info: { perFinding: 0.5, cap: 5 },
};

/** A low-confidence finding is a lead, not a fact, and costs half. */
export const LOW_CONFIDENCE_WEIGHT = 0.5;

/** Two decimals, so the arithmetic in the artifact is readable and stable. */
function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

/** Every severity at zero: the starting point of any count. */
export function emptySeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/** Counts findings by severity, with every severity present. */
export function countBySeverity(findings: readonly Finding[]): SeverityCounts {
  const counts = emptySeverityCounts();
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/**
 * Turns one domain's findings into the per-tier rows that explain its score.
 *
 * Only tiers that hold findings get a row — an empty `critical` row would be
 * four zeroes and a cap nobody needs to read — and the rows come back in
 * severity order, so the table renders worst-first without the report sorting
 * it.
 */
export function computeDeductions(findings: readonly Finding[]): SeverityDeduction[] {
  const rows: SeverityDeduction[] = [];

  for (const severity of SeveritySchema.options) {
    const matching = findings.filter((finding) => finding.severity === severity);
    if (matching.length === 0) continue;

    const policy = SEVERITY_POLICY[severity];
    const discounted = matching.filter((finding) => finding.confidence === "low").length;
    const weighted = matching.length - discounted * (1 - LOW_CONFIDENCE_WEIGHT);
    const raw = round2(weighted * policy.perFinding);
    const applied = round2(Math.min(raw, policy.cap));

    rows.push(
      SeverityDeductionSchema.parse({
        severity,
        count: matching.length,
        discounted,
        perFinding: policy.perFinding,
        raw,
        cap: policy.cap,
        applied,
        capped: applied < raw,
      }),
    );
  }

  return rows;
}

/** What the rows subtract in total, clamped to the 0–100 range a score lives in. */
export function totalDeduction(rows: readonly SeverityDeduction[]): number {
  const total = rows.reduce((sum, row) => sum + row.applied, 0);
  return round2(Math.min(100, total));
}

/** `100` minus the deductions, rounded to the integer a score is reported as. */
export function baseScoreFrom(rows: readonly SeverityDeduction[]): number {
  return Math.round(Math.max(0, 100 - totalDeduction(rows)));
}

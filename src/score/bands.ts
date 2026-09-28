/**
 * The A–F band table, and the one place a number is turned into words.
 *
 * Every label is written for the person paying for the dossier, not for the
 * engineer who will fix it, and every one of them is hedged by what Sentinel
 * actually did: an `A` says *no material weakness in what was checked*, because
 * a band is a statement about the checks that ran and nothing else. What "ran"
 * means is the coverage that travels with the score — see
 * `src/score/coverage-gate.ts`.
 *
 * {@link NOT_ASSESSED_LABEL} is exported so no renderer has to invent its own
 * word for "there is no number here", and {@link describeScore} is the single
 * formatter: given `null` it prints that label, and it can never print `0`.
 */

import { type ScoreBand, ScoreBandSchema } from "../contracts/scorecard.ts";

/** One band: the letter, the lowest score that earns it, and what it means. */
export interface BandDefinition {
  readonly band: ScoreBand;
  /** Inclusive lower bound. */
  readonly min: number;
  /** The sentence a client reads instead of the letter. */
  readonly label: string;
}

/**
 * The bands, best first. A (90+) / B (75–89) / C (60–74) / D (40–59) / F (<40).
 */
export const BAND_TABLE: readonly BandDefinition[] = [
  {
    band: "A",
    min: 90,
    label: "Strong — nothing material found in what was checked",
  },
  {
    band: "B",
    min: 75,
    label: "Solid — real issues, none of them urgent",
  },
  {
    band: "C",
    min: 60,
    label: "Mixed — several issues that need scheduled work",
  },
  {
    band: "D",
    min: 40,
    label: "Weak — material problems; fix before the next release",
  },
  {
    band: "F",
    min: 0,
    label: "Failing — at least one issue that should block release",
  },
];

/** What the report prints where a score would be, when there is none. */
export const NOT_ASSESSED_LABEL = "not assessed";

/** The band a score falls in; scores outside 0–100 are clamped first. */
export function bandFor(score: number): ScoreBand {
  const clamped = Math.min(100, Math.max(0, score));
  for (const definition of BAND_TABLE) {
    if (clamped >= definition.min) return definition.band;
  }
  // BAND_TABLE ends at 0, so this is unreachable for any finite number.
  return "F";
}

/** The prose label for a band. */
export function bandLabel(band: ScoreBand): string {
  return BAND_TABLE.find((definition) => definition.band === band)?.label ?? "";
}

/**
 * The one way a score reaches a reader: `82 (B)` or, for a domain that was not
 * assessed, {@link NOT_ASSESSED_LABEL}. A `null` score can never come out of
 * here as a number, which is the whole point of passing it through.
 */
export function describeScore(score: number | null): string {
  if (score === null) return NOT_ASSESSED_LABEL;
  return `${score} (${bandFor(score)})`;
}

/** Every band in the table, best first — for exhaustive rendering and tests. */
export const BANDS: readonly ScoreBand[] = ScoreBandSchema.options;

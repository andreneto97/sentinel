/**
 * The one place the PDF knows anything about `src/score`.
 *
 * Phase 6 is owned by another module and lands beside this one; the report is
 * written against the shape it publishes — `{ domain, score, band, status,
 * ceilingReason?, coverage, confidence }` — and nothing else. Every sentence the
 * PDF says about a score is derived here, so a change in phase 6 is a change in
 * this file and not a hunt through seven sections.
 *
 * The adapter is deliberately forgiving about *units* and strict about
 * *meaning*: a coverage of `0.94` and a coverage of `94` are both read as 94%,
 * because either is a plausible thing for a scorer to emit, while a domain
 * whose status is `not-assessed` never acquires a number — not a zero, not a
 * dash that could be mistaken for one, but the words "not assessed".
 */

import type { Domain } from "../../contracts/findings.ts";
import { DomainSchema } from "../../contracts/findings.ts";
import { COLOR, bandColor } from "./theme.ts";

/** How much of a domain phase 6 was able to judge. */
export type ScoreStatus = "scored" | "partial" | "not-assessed";

/** One domain's score, as phase 6 publishes it. */
export interface DomainScore {
  readonly domain: Domain;
  readonly score: number;
  readonly band: string;
  readonly status: ScoreStatus;
  /** Why the score could not rise above a cap, e.g. an unrotated secret. */
  readonly ceilingReason?: string | undefined;
  /**
   * Fraction of the domain's units that were audited, 0..1 (or 0..100).
   *
   * `null` means there is no coverage figure at all — the domain has no checks
   * to count — which is a different statement from `0`, and the one case where
   * the column prints a dash. A domain that was checked and *then* refused a
   * score still has a real fraction, and hiding it behind a dash would lose the
   * only number that says how thin the evidence was.
   */
  readonly coverage: number | null;
  /** A word (`high`/`medium`/`low`) or a fraction; both are rendered. */
  readonly confidence: string | number;
  /**
   * Phase 6's own sentence, set **only** when what held the domain back was the
   * evidence nobody examined rather than the checks that did not run.
   *
   * The report's own sentence is built from the coverage fraction, and that
   * fraction is exactly what cannot be trusted here: a domain at `1 of 1 checks
   * ran (100%)` which phase 6 refused to score would otherwise be printed as
   * "1 of 1 planned checks completed (100%), which is too little of this domain
   * to stand behind a score". Phase 6 knows the real reason — the domain's
   * migrations and data-access sites, not one of which anybody audited — so when
   * it supplies one, it wins.
   */
  readonly evidenceNote?: string | undefined;
}

/** The run-level score, when phase 6 publishes one. */
export interface OverallScore {
  readonly score: number;
  readonly band: string;
  readonly confidence?: string | number | undefined;
}

/** What the renderer accepts: the bare domain list, or a document around it. */
export type ScorecardInput =
  | readonly DomainScore[]
  | {
      readonly domains: readonly DomainScore[];
      readonly overall?: OverallScore | undefined;
    };

/** One row of the scorecard, with every number already turned into a string. */
export interface DomainScoreView {
  readonly domain: Domain;
  readonly status: ScoreStatus;
  /** `"72"`, or the words for a domain with no number. */
  readonly score: string;
  readonly band: string;
  readonly bandColor: string;
  /** `"94%"`, or an em dash when there is nothing to report. */
  readonly coverage: string;
  readonly confidence: string;
  readonly ceilingReason?: string | undefined;
  /** Phase 6's sentence, when the evidence and not the checks held this domain back. */
  readonly evidenceNote?: string | undefined;
}

/** The whole scorecard, ready to render. */
export interface ScorecardView {
  /** False when phase 6 produced nothing; the report then says so out loud. */
  readonly present: boolean;
  readonly domains: readonly DomainScoreView[];
  readonly overall: {
    readonly score: string;
    readonly band: string;
    readonly color: string;
    readonly confidence: string;
    /**
     * True when the overall band is this module's arithmetic rather than phase
     * 6's own verdict. The report prints the difference.
     */
    readonly derived: boolean;
  };
  /** Every hard ceiling the scorer applied, for the executive summary. */
  readonly ceilings: readonly { readonly domain: Domain; readonly reason: string }[];
}

/** The words a status is allowed to print. Never a number, never a zero. */
const STATUS_WORDS: Readonly<Record<ScoreStatus, string>> = {
  scored: "scored",
  partial: "partial",
  "not-assessed": "not assessed",
};

/** Bands for a derived overall score, in the usual academic cuts. */
function deriveBand(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Reads a coverage number that may be a fraction or a percentage.
 *
 * Deliberately independent of the status: coverage is not a score, and `20%`
 * beside the words "not assessed" is the sentence the reader needs. Only an
 * absent figure prints a dash.
 */
function coverageLabel(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (!Number.isFinite(value) || value < 0) return "—";
  const percent = value <= 1 ? value * 100 : Math.min(value, 100);
  return `${Math.round(percent)}%`;
}

/** Renders a confidence that may be a word or a fraction. */
function confidenceLabel(value: string | number | undefined): string {
  if (value === undefined) return "—";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return "—";
    const percent = value <= 1 ? value * 100 : Math.min(value, 100);
    return `${Math.round(percent)}%`;
  }
  const trimmed = value.trim();
  return trimmed === "" ? "—" : trimmed;
}

/** Normalises either accepted input shape into a list and an optional overall. */
function split(input: ScorecardInput): {
  domains: readonly DomainScore[];
  overall: OverallScore | undefined;
} {
  if (Array.isArray(input)) return { domains: input, overall: undefined };
  const document = input as { domains: readonly DomainScore[]; overall?: OverallScore | undefined };
  return { domains: document.domains, overall: document.overall };
}

/**
 * Turns phase 6's output into the strings the report prints.
 *
 * With no scorecard at all, every domain reads `not assessed` and the overall
 * band says the same — which is the honest rendering of a run whose scoring
 * phase did not happen, and is what the report shows while phase 6 is still
 * being written.
 */
export function adaptScorecard(input: ScorecardInput | undefined): ScorecardView {
  const { domains, overall } =
    input === undefined ? { domains: [], overall: undefined } : split(input);
  const byDomain = new Map<Domain, DomainScore>();
  for (const entry of domains) byDomain.set(entry.domain, entry);

  const rows: DomainScoreView[] = DomainSchema.options.map((domain) => {
    const entry = byDomain.get(domain);
    if (entry === undefined) {
      return {
        domain,
        status: "not-assessed",
        score: STATUS_WORDS["not-assessed"],
        band: "—",
        bandColor: COLOR.muted,
        coverage: "—",
        confidence: "—",
      };
    }
    const assessed = entry.status !== "not-assessed";
    return {
      domain,
      status: entry.status,
      score:
        assessed && Number.isFinite(entry.score)
          ? String(Math.round(entry.score))
          : STATUS_WORDS[entry.status],
      band: assessed ? entry.band : "—",
      bandColor: assessed ? bandColor(entry.band) : COLOR.muted,
      coverage: coverageLabel(entry.coverage),
      confidence: assessed ? confidenceLabel(entry.confidence) : "—",
      ...(entry.ceilingReason === undefined ? {} : { ceilingReason: entry.ceilingReason }),
      ...(entry.evidenceNote === undefined || entry.evidenceNote.trim() === ""
        ? {}
        : { evidenceNote: entry.evidenceNote.trim() }),
    };
  });

  const ceilings = domains
    .filter(
      (entry): entry is DomainScore & { ceilingReason: string } =>
        typeof entry.ceilingReason === "string" && entry.ceilingReason.trim() !== "",
    )
    .map((entry) => ({ domain: entry.domain, reason: entry.ceilingReason }));

  const scored = domains.filter(
    (entry) => entry.status !== "not-assessed" && Number.isFinite(entry.score),
  );

  if (overall !== undefined) {
    return {
      present: true,
      domains: rows,
      overall: {
        score: Number.isFinite(overall.score) ? String(Math.round(overall.score)) : "—",
        band: overall.band,
        color: bandColor(overall.band),
        confidence: confidenceLabel(overall.confidence),
        derived: false,
      },
      ceilings,
    };
  }

  if (scored.length === 0) {
    return {
      present: domains.length > 0,
      domains: rows,
      overall: {
        score: STATUS_WORDS["not-assessed"],
        band: "—",
        color: COLOR.muted,
        confidence: "—",
        derived: false,
      },
      ceilings,
    };
  }

  // Phase 6 published no run-level verdict, so the report averages the domains
  // it did score and says that is what it did. An unweighted mean is the only
  // defensible guess: weighting would be this module inventing a policy.
  const mean = scored.reduce((sum, entry) => sum + entry.score, 0) / scored.length;
  return {
    present: true,
    domains: rows,
    overall: {
      score: String(Math.round(mean)),
      band: deriveBand(mean),
      color: bandColor(deriveBand(mean)),
      confidence: "—",
      derived: true,
    },
    ceilings,
  };
}

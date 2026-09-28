/**
 * The hard ceilings: the facts a domain cannot average its way past.
 *
 * Deductions are proportional, and proportional arithmetic has a failure mode.
 * A repository with one committed AWS key and otherwise tidy code loses 25
 * points and reports a `B` — a number that is arithmetically defensible and
 * substantively a lie, because the credential is either still live or someone
 * has to prove it is not. So three rules sit above the arithmetic and cap the
 * domain outright, and they are all in {@link SCORE_CEILINGS} below: one table,
 * in code, that a reader can check against the report.
 *
 * A fourth cap is fired by an *absence* rather than by a finding, and it lives
 * here for the same reason: {@link UNEXAMINED_EVIDENCE_CAP} is what stops a
 * domain whose units nobody audited from presenting the absence of deterministic
 * findings as health. Deterministic analysis can lower a score; it cannot certify
 * one.
 *
 * Each one records **why it applied** — the finding that fired it, by id and by
 * location — and that sentence is rendered next to the score. A cap without its
 * reason is indistinguishable from a bad mood.
 *
 * Two deliberate limits on when a ceiling fires:
 *
 * - **Low-confidence findings never fire one.** A cap is a claim Sentinel makes
 *   loudly; making it from a lead would be the same dishonesty in the other
 *   direction. A low-confidence finding still deducts (at half weight, see
 *   `deductions.ts`), it just cannot cap.
 * - **A ceiling fires on evidence Sentinel has, not on the remedy it cannot
 *   see.** Sentinel cannot tell whether a committed credential was rotated at
 *   the provider, or whether a destructive migration was preceded by a backfill
 *   in some other file. Where the plan says "unrotated" and "with no backfill",
 *   what is actually observable is the committed secret and the destructive
 *   statement; the ceiling applies on that, and its `reason` states the
 *   assumption in the same breath so the reader can discharge it.
 */

import type { Domain, Finding, Severity } from "../contracts/findings.ts";
import { SeveritySchema } from "../contracts/findings.ts";
import {
  type AppliedCeiling,
  AppliedCeilingSchema,
  type EvidenceSummary,
} from "../contracts/scorecard.ts";
import { PARTIAL_COVERAGE } from "./coverage-gate.ts";
import { describeUnits, describeUnitsExamined, domainEvidence, noEvidence } from "./evidence.ts";

/** Severity order, worst first, for the `at least this bad` guards below. */
const SEVERITY_RANK: ReadonlyMap<Severity, number> = new Map(
  SeveritySchema.options.map((severity, index) => [severity, index]),
);

/** True when `severity` is `floor` or worse. */
function atLeast(severity: Severity, floor: Severity): boolean {
  return (
    (SEVERITY_RANK.get(severity) ?? Number.MAX_SAFE_INTEGER) <= (SEVERITY_RANK.get(floor) ?? 0)
  );
}

/** One hard ceiling: what fires it, what it caps the domain at, and why. */
export interface ScoreCeiling {
  /** Stable id, rendered with the cap in the report. */
  readonly id: string;
  readonly domain: Domain;
  /** The highest score the domain may hold once this fires. */
  readonly cap: number;
  readonly title: string;
  /** Singular and plural noun for what fired it, for the reason sentence. */
  readonly noun: readonly [string, string];
  /** Why this caps the domain, including any assumption Sentinel cannot verify. */
  readonly rationale: string;
  /** Whether this finding fires the ceiling. Confidence is checked separately. */
  matches(finding: Finding): boolean;
}

/**
 * THE CEILING TABLE. Three entries, each from the plan, each with the rule it
 * keys off and the assumption it states out loud.
 *
 * `appsec.hardcoded-secret` is gitleaks', and gitleaks is the only source that
 * walks the commit graph — so it is the only rule that proves a credential
 * reached the repository rather than merely sitting in a working file. The
 * agent's `appsec.hardcoded-credential` and the SAST pack's
 * `appsec.auth.jwt-hardcoded-secret` deduct like any other finding and do not
 * cap, because neither proves the value was committed.
 */
export const SCORE_CEILINGS: readonly ScoreCeiling[] = [
  {
    id: "appsec.committed-secret",
    domain: "appsec",
    cap: 50,
    title: "A credential is in this repository's git history",
    noun: ["committed credential", "committed credentials"],
    rationale:
      "Every clone and every fork carries it, so deleting the line does not undo the exposure. " +
      "Sentinel cannot observe whether the value was rotated at the provider, so it is scored as " +
      "live: lift this cap by recording the rotation, not by removing the line.",
    matches: (finding) =>
      finding.domain === "appsec" &&
      finding.rule === "appsec.hardcoded-secret" &&
      atLeast(finding.severity, "high"),
  },
  {
    id: "dependencies.unpatched-critical-cve",
    domain: "dependencies",
    cap: 60,
    title: "A dependency ships a critical, unpatched vulnerability",
    noun: ["critical CVE", "critical CVEs"],
    rationale:
      "The advisory rates it critical and the installed version is the affected one, so the " +
      "exposure is present in what this repository resolves today. The rest of the dependency " +
      "tree being healthy does not reduce it.",
    matches: (finding) =>
      finding.domain === "dependencies" &&
      finding.rule === "dependencies.vulnerable-package" &&
      finding.severity === "critical",
  },
  {
    id: "data.destructive-migration",
    domain: "data",
    cap: 70,
    title: "A migration drops or rewrites data",
    noun: ["destructive migration", "destructive migrations"],
    rationale:
      "A statement that drops or rewrites a column is not reversible by re-running the migration, " +
      "and Sentinel can only see the migration file — whether a backfill exists elsewhere, and " +
      "whether it ran first, has to be shown rather than assumed.",
    matches: (finding) =>
      finding.domain === "data" &&
      finding.rule === "data.destructive-migration" &&
      atLeast(finding.severity, "medium"),
  },
];

/** Confidence a finding needs before it is allowed to cap a domain. */
export function canFireCeiling(finding: Finding): boolean {
  return finding.confidence !== "low";
}

/**
 * The highest score a domain may hold when nobody examined its evidence.
 *
 * It is the top of band `C`, and the boundary is the argument. Read the band
 * labels in `bands.ts`: `A` is "nothing material found in what was checked" and
 * `B` is "real issues, none of them urgent". Both are statements that the domain
 * is *healthy*, and health is precisely what a run that examined none of the
 * domain's units cannot have established. `C` — "several issues that need
 * scheduled work" — and everything below it are statements about problems found,
 * and problems found are exactly what deterministic analysis is entitled to
 * assert.
 *
 * So: deterministic findings may take a domain all the way to `F`, and the
 * absence of deterministic findings may not take it past `C`. The cap is
 * recorded as an {@link AppliedCeiling} like any other, with the units it names,
 * so it is printed rather than merely applied — and it lifts on its own the
 * moment the audit phase examines the units.
 */
export const UNEXAMINED_EVIDENCE_CAP = 74;

/**
 * Whether a domain's evidence is too thin to certify a score.
 *
 * Deliberately the same threshold the coverage gate refuses a number below: a
 * domain over half of whose units were examined has a real, if partial, number
 * and says so through its coverage; a domain under it has a bound, not a grade.
 */
export function capsScore(evidence: EvidenceSummary): boolean {
  return evidence.applies && evidence.ratio < PARTIAL_COVERAGE;
}

/** The sentence the evidence ceiling prints: what was not looked at, and why that caps. */
function evidenceReason(evidence: EvidenceSummary): string {
  const head = `Capped at ${UNEXAMINED_EVIDENCE_CAP}: only ${describeUnitsExamined(evidence)}`;
  const rationale =
    "Deterministic analysis can lower a score; it cannot certify one — a linter finding nothing is " +
    "evidence that a linter ran, not evidence that the code is correct. Bands A and B state that a " +
    "domain is healthy, and nothing in this run looked at the units that would show it. Run the " +
    "audit phase over these units to lift the cap; the findings below stand either way.";
  return `${head} (${describeUnits(evidence.kinds)}). ${rationale}`;
}

/**
 * The evidence ceiling for one domain, or null when its evidence was examined.
 *
 * Unlike the three in {@link SCORE_CEILINGS} this one is fired by an absence
 * rather than by a finding, so `triggeredBy` is empty: no finding caused it, and
 * pretending one did would send a reader looking for a citation that does not
 * exist. What it points at instead is in the reason, by unit kind and count.
 */
export function evidenceCeiling(
  domain: Domain,
  evidence: EvidenceSummary,
): Omit<AppliedCeiling, "binding"> | null {
  if (!capsScore(evidence)) return null;
  return {
    id: "evidence.unexamined-units",
    domain,
    cap: UNEXAMINED_EVIDENCE_CAP,
    title: "This domain's units were enumerated but never examined",
    reason: evidenceReason(evidence),
    triggeredBy: [],
  };
}

/** `file:line`, the way every other part of the dossier cites code. */
function citation(finding: Finding): string {
  return `${finding.location.file}:${finding.location.line}`;
}

/**
 * The sentence the report renders: what fired the cap, where, and why it caps.
 *
 * It does not name the domain. `AppliedCeiling.domain` already carries that as
 * data, every renderer has its own reader-facing label for it, and a sentence
 * that opened with the raw contract id (`data is capped at 70`) read like a log
 * line in the middle of a client document.
 */
function reasonFor(ceiling: ScoreCeiling, triggers: readonly Finding[]): string {
  const count = triggers.length;
  const noun = count === 1 ? ceiling.noun[0] : ceiling.noun[1];
  const first = triggers[0];
  const sample =
    first === undefined
      ? ""
      : ` — ${first.title} (${citation(first)})${count > 1 ? ", and others" : ""}`;
  return `Capped at ${ceiling.cap}: ${count} ${noun}${sample}. ${ceiling.rationale}`;
}

/**
 * Applies every ceiling for one domain to the score its deductions produced.
 *
 * A `null` score — a domain that was not assessed — stays `null`: there is no
 * number to cap. The ceilings it fired are still returned, marked `binding:
 * false`, so a report can say "not assessed, and here is the committed
 * credential we found anyway" instead of silently dropping it.
 *
 * The evidence ceiling goes last, so that a finding-driven cap is the one a
 * reader sees first when both bit: a committed credential is a more specific
 * explanation of a low number than "nobody looked".
 */
export function applyCeilings(
  domain: Domain,
  score: number | null,
  findings: readonly Finding[],
  evidence: EvidenceSummary = domainEvidence(domain, noEvidence()),
): { score: number | null; ceilings: AppliedCeiling[] } {
  const applied: AppliedCeiling[] = [];
  let current = score;

  for (const ceiling of SCORE_CEILINGS) {
    if (ceiling.domain !== domain) continue;
    const triggers = findings
      .filter((finding) => canFireCeiling(finding) && ceiling.matches(finding))
      .sort((left, right) => left.id.localeCompare(right.id));
    if (triggers.length === 0) continue;

    const binding = current !== null && current > ceiling.cap;
    if (binding) current = ceiling.cap;

    applied.push(
      AppliedCeilingSchema.parse({
        id: ceiling.id,
        domain: ceiling.domain,
        cap: ceiling.cap,
        title: ceiling.title,
        reason: reasonFor(ceiling, triggers),
        binding,
        triggeredBy: triggers.map((finding) => finding.id),
      }),
    );
  }

  const unexamined = evidenceCeiling(domain, evidence);
  if (unexamined !== null) {
    const binding = current !== null && current > unexamined.cap;
    if (binding) current = unexamined.cap;
    applied.push(AppliedCeilingSchema.parse({ ...unexamined, binding }));
  }

  return { score: current, ceilings: applied };
}

/**
 * What a domain's score is allowed to *rest* on: units somebody examined.
 *
 * The bug this file exists for is worth stating plainly, because it is the exact
 * failure mode the whole tool is built against. A repository whose data layer
 * holds hundreds of migrations and thousands of data-access call sites can score
 * **100 (A), "1 of 1 check ran (100%)"** on a run with no AI phase at all: one
 * shallow analyzer step is planned for that domain, it executes, it finds nothing
 * to say, and "nothing to say" is read as "nothing wrong".
 *
 * The coverage gate could not catch it because it measures *checks that ran over
 * checks planned*, and a domain that plans one check and runs it is, by that
 * measure, perfectly covered. So a second measure sits beside it:
 *
 * > **A linter finding nothing is not evidence of correctness. It is evidence
 * > that a linter ran.** Only an audited unit — a model verdict Sentinel
 * > verified, or a rule that actually examined that unit — is evidence about
 * > the unit.
 *
 * This module counts that second measure. For each domain it asks two numbers
 * of the run's artifacts: how many audit units of the domain's kinds phase 2
 * *enumerated*, and how many of them phase 4 came back with a *verdict* for. The
 * policy built on those numbers lives in `coverage-gate.ts` (what status they
 * permit) and `ceilings.ts` (the cap they impose); here there is only the model
 * and the sentence, because the sentence has to name the units — "500 migrations
 * and 4,000 data-access call sites exist; none were audited" is actionable and
 * "not assessed" is not.
 *
 * Nothing here suppresses anything. Every number it produces is written into
 * `scorecard.json`, the units it counts are listed one by one in
 * `inventory.json`, and the findings of a domain it refuses to score are still
 * reported in full — they are simply reported as problems found rather than as a
 * grade earned.
 */

import { DOMAIN_BY_UNIT_KIND, type KindCoverage } from "../audit/coverage.ts";
import { type Domain, DomainSchema } from "../contracts/findings.ts";
import {
  AUDIT_UNIT_KINDS,
  type AuditUnitKind,
  countUnits,
  groupThousands,
} from "../contracts/inventory.ts";
import {
  type EvidenceKind,
  type EvidenceSummary,
  EvidenceSummarySchema,
} from "../contracts/scorecard.ts";

/**
 * Which unit kinds are a domain's evidence.
 *
 * Inverted from `src/audit/coverage.ts`'s `DOMAIN_BY_UNIT_KIND` rather than
 * restated, so the domain a migration belongs to is decided in exactly one place
 * for both coverage and scoring. A domain absent from that map — `dependencies`,
 * `api`, `reliability`, `deadcode` — has an empty list, and an empty list means
 * "examined units are not this domain's measure", not "this domain has no
 * evidence": see {@link domainEvidence}.
 */
export const UNIT_KINDS_BY_DOMAIN: Readonly<Record<Domain, readonly AuditUnitKind[]>> = (() => {
  const table = {} as Record<Domain, readonly AuditUnitKind[]>;
  for (const domain of DomainSchema.options) {
    table[domain] = AUDIT_UNIT_KINDS.filter((kind) => DOMAIN_BY_UNIT_KIND[kind] === domain);
  }
  return table;
})();

/** One unit kind's two counters: units that exist, units a verdict examined. */
export interface UnitEvidence {
  readonly present: number;
  readonly verdicted: number;
}

/**
 * The counters the evidence model is built from, per unit kind.
 *
 * `auditRan` is carried separately because it changes the sentence and not the
 * arithmetic: `0 of 4,500 audited` because the audit phase never started reads
 * differently from `0 of 4,500 audited` because every batch failed, and a reader
 * deciding whether to re-run needs to know which.
 */
export interface EvidenceInput {
  readonly units: Readonly<Partial<Record<AuditUnitKind, UnitEvidence>>>;
  /** False when phase 4 did not run at all — a `--no-ai` or scan-only run. */
  readonly auditRan: boolean;
}

/** The slice of `inventory.json` the evidence model reads. */
export interface InventorySignalSource {
  readonly counts: Readonly<Partial<Record<AuditUnitKind, number>>>;
}

/** The slice of `audit.json` the evidence model reads. `AuditReport` satisfies it. */
export interface AuditUnitSource {
  readonly kinds: readonly KindCoverage[];
}

/** An input that claims nothing: no units enumerated, no audit phase. */
export function noEvidence(): EvidenceInput {
  return { units: {}, auditRan: false };
}

/**
 * Folds `inventory.json` and `audit.json` into the per-kind counters.
 *
 * The denominator comes from the **inventory**, not from the audit: that is the
 * whole repair. Phase 2 enumerates every unit whether or not phase 4 ever looks
 * at one, so a run with no audit still knows that 4,500 data-layer units exist
 * and that nothing examined them. Taking the larger of the two totals costs
 * nothing and means a unit that reached a batch without reaching the inventory
 * still counts against the domain rather than vanishing.
 *
 * With no inventory at all — a run whose phase 2 artifact is missing — the audit
 * is the only source, and with neither the result claims nothing and the score
 * phase behaves exactly as it did before this model existed.
 */
export function evidenceFrom(input: {
  readonly inventory?: InventorySignalSource | undefined;
  readonly audit?: AuditUnitSource | undefined;
}): EvidenceInput {
  const units: Partial<Record<AuditUnitKind, UnitEvidence>> = {};
  const audited = new Map<AuditUnitKind, KindCoverage>();
  for (const row of input.audit?.kinds ?? []) audited.set(row.kind, row);

  for (const kind of AUDIT_UNIT_KINDS) {
    const enumerated = input.inventory?.counts[kind] ?? 0;
    const row = audited.get(kind);
    const present = Math.max(enumerated, row?.unitsTotal ?? 0);
    if (present === 0) continue;
    units[kind] = { present, verdicted: Math.min(present, row?.unitsAudited ?? 0) };
  }

  return { units, auditRan: input.audit !== undefined };
}

/** Four decimals, the precision the coverage summary already diffs cleanly at. */
function ratio4(verdicted: number, present: number): number {
  if (present === 0) return 0;
  return Math.round(Math.min(1, verdicted / present) * 10_000) / 10_000;
}

/** `4,000 data-access call sites and 500 migrations`, biggest first. */
export function describeUnits(kinds: readonly EvidenceKind[]): string {
  const phrases = kinds.map((row) => countUnits(row.kind, row.present));
  if (phrases.length === 0) return "";
  if (phrases.length === 1) return phrases[0] ?? "";
  return `${phrases.slice(0, -1).join(", ")} and ${phrases[phrases.length - 1] ?? ""}`;
}

/** `0 of 4,500`, the fraction of a domain's units that a verdict examined. */
export function describeExamined(counts: {
  readonly unitsVerdicted: number;
  readonly unitsPresent: number;
}): string {
  return `${groupThousands(counts.unitsVerdicted)} of ${groupThousands(counts.unitsPresent)}`;
}

/** `90 of its 100 units were examined` — the clause a score is printed beside. */
export function describeUnitsExamined(counts: {
  readonly unitsVerdicted: number;
  readonly unitsPresent: number;
}): string {
  return `${groupThousands(counts.unitsVerdicted)} of its ${groupThousands(counts.unitsPresent)} ${
    counts.unitsPresent === 1 ? "unit" : "units"
  } ${counts.unitsVerdicted === 1 ? "was" : "were"} examined`;
}

/**
 * How many of a domain's units got a verdict, as the clause that follows the
 * units themselves: `…500 migrations exist and none of them were audited`.
 *
 * `none` is spelled out rather than printed as `0 of 500`, because the fraction
 * has already been said and `0 of 500 of them` is not a sentence.
 */
export function describeAudited(counts: {
  readonly unitsVerdicted: number;
  readonly unitsPresent: number;
}): string {
  if (counts.unitsVerdicted === 0) return "none of them were audited";
  if (counts.unitsVerdicted >= counts.unitsPresent) return "all of them were audited";
  return `only ${describeExamined(counts)} of them were audited`;
}

/**
 * Why a domain's units have no verdict, in the run's own terms.
 *
 * Only the two honest answers: the phase that produces verdicts did not run, or
 * it ran and did not reach these units. Sentinel does not know which flag the
 * operator passed, so it reports the phase rather than guessing at `--no-ai`.
 */
export function describeWhyUnaudited(auditRan: boolean): string {
  return auditRan
    ? "no audit batch returned a verdict for any of them"
    : "none of them were audited: the audit phase did not run in this run";
}

/** The sentence `scorecard.json` carries, and the report prints, about the evidence. */
function statementFor(
  core: Omit<EvidenceSummary, "statement">,
  auditRan: boolean,
  kindDetail: string,
): string {
  if (!core.applies) {
    return "no audit unit belongs to this domain, so what was examined is the analyzers that ran";
  }
  const head = describeUnitsExamined(core);
  if (core.unitsVerdicted >= core.unitsPresent) return `${head}: ${kindDetail}`;
  const cause = core.unitsVerdicted === 0 ? describeWhyUnaudited(auditRan) : describeAudited(core);
  return `${head}: ${kindDetail} exist and ${cause}`;
}

/**
 * Builds one domain's evidence summary.
 *
 * A domain with no unit kinds — `dependencies`, whose evidence is trivy over the
 * whole lockfile, or `deadcode`, whose candidates are a module graph rather than
 * an enumerated list — comes back with `applies: false`. That is not a pass: it
 * says examined units are not the right measure *for this domain*, so the
 * coverage gate keeps deciding it on the checks that ran, exactly as before.
 * A domain whose kinds exist but whose inventory found none of them also comes
 * back `applies: false`, because there is nothing to have examined.
 */
export function domainEvidence(domain: Domain, input: EvidenceInput): EvidenceSummary {
  const rows: EvidenceKind[] = [];
  for (const kind of UNIT_KINDS_BY_DOMAIN[domain]) {
    const counters = input.units[kind];
    if (counters === undefined || counters.present === 0) continue;
    rows.push({ kind, present: counters.present, verdicted: counters.verdicted });
  }

  // Biggest first, because the sentence leads with the number a reader will
  // argue about; ties fall back to the contract's kind order so two runs over
  // unchanged code still produce identical bytes.
  const order = new Map(AUDIT_UNIT_KINDS.map((kind, index) => [kind, index]));
  rows.sort(
    (left, right) =>
      right.present - left.present || (order.get(left.kind) ?? 0) - (order.get(right.kind) ?? 0),
  );

  const unitsPresent = rows.reduce((sum, row) => sum + row.present, 0);
  const unitsVerdicted = rows.reduce((sum, row) => sum + row.verdicted, 0);
  const core = {
    applies: unitsPresent > 0,
    unitsPresent,
    unitsVerdicted,
    ratio: ratio4(unitsVerdicted, unitsPresent),
    kinds: rows,
  };

  return EvidenceSummarySchema.parse({
    ...core,
    statement: statementFor(core, input.auditRan, describeUnits(rows)),
  });
}

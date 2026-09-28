/**
 * Phase 6: findings, assurances and coverage in; a defensible number per domain
 * out.
 *
 * The order of operations is the argument this phase makes, and it only reads
 * one way:
 *
 * 1. **Gate on coverage first** (`coverage-gate.ts`), where coverage means both
 *    the checks that ran and the units somebody actually examined
 *    (`evidence.ts`). A domain that did not earn a number never gets one, and no
 *    amount of clean findings can buy it — nor can a single shallow check that
 *    ran over a repository nobody audited.
 * 2. **Deduct from 100** (`deductions.ts`), weighted by severity, capped per
 *    tier so volume cannot outvote severity.
 * 3. **Apply the hard ceilings** (`ceilings.ts`), which can only lower, and
 *    each of which records why it applied.
 * 4. **Combine** (`overall.ts`) into a weighted mean over the domains that have
 *    a number, clamped to the worst of them plus 15.
 * 5. **State the confidence** (`confidence.ts`), derived from what the run did.
 *
 * Every function here is pure: no file is read, none is written, and two calls
 * with the same input produce byte-identical documents. The caller decides
 * whether the result is written to `scorecard.json`, rendered into the PDF, or
 * both.
 */

import type {
  Assurance,
  Coverage,
  Domain,
  Finding,
  FindingsDocument,
} from "../contracts/findings.ts";
import { DomainSchema, SCHEMA_VERSION } from "../contracts/findings.ts";
import {
  type DomainScore,
  DomainScoreSchema,
  type Scorecard,
  ScorecardSchema,
} from "../contracts/scorecard.ts";
import { bandFor, bandLabel } from "./bands.ts";
import { applyCeilings } from "./ceilings.ts";
import {
  type AuditSignalSource,
  type ConfidenceInput,
  type ScanSignalSource,
  buildConfidence,
  cleanConfidenceBasis,
  confidenceBasisFrom,
} from "./confidence.ts";
import { gateDomain } from "./coverage-gate.ts";
import { baseScoreFrom, computeDeductions, countBySeverity, totalDeduction } from "./deductions.ts";
import {
  type AuditUnitSource,
  type EvidenceInput,
  type InventorySignalSource,
  domainEvidence,
  evidenceFrom,
  noEvidence,
} from "./evidence.ts";
import { DOMAIN_WEIGHTS, buildOverall, effectiveWeight } from "./overall.ts";

/** Everything the score phase needs, and nothing it would have to read from disk. */
export interface ScorecardInput {
  readonly runId: string;
  /** Absolute path of the repository the findings are about. */
  readonly target: string;
  readonly findings: readonly Finding[];
  readonly assurances: readonly Assurance[];
  readonly coverage: readonly Coverage[];
  /**
   * The domains the run's scope turned on, from `scope-proposal.json`. Left
   * out, the domains with a coverage row are taken as the scope — which only
   * changes the sentence a `not-assessed` domain carries, never whether it is
   * one.
   */
  readonly scope?: readonly Domain[] | undefined;
  /** The counters confidence is derived from; a clean run when left out. */
  readonly confidence?: ConfidenceInput | undefined;
  /**
   * The units phase 2 enumerated and the verdicts phase 4 returned for them,
   * from {@link evidenceFrom}.
   *
   * Left out, no domain has examined evidence to weigh and every domain is
   * judged on its checks alone — which is the pre-`evidence.ts` behaviour and is
   * only correct for a caller that genuinely has no inventory. A caller holding
   * `inventory.json` must pass it: that document is what proves the migrations
   * exist for nobody to have audited.
   */
  readonly evidence?: EvidenceInput | undefined;
}

/** One domain's inputs, already narrowed to that domain. */
interface DomainInput {
  readonly domain: Domain;
  readonly findings: readonly Finding[];
  readonly assurances: readonly Assurance[];
  readonly coverage: Coverage | undefined;
  readonly inScope: boolean;
  /**
   * The units this run enumerated and verdicted. Left out, the domain is judged
   * on its checks alone — correct only for a caller that has no `inventory.json`.
   */
  readonly evidence?: EvidenceInput | undefined;
}

/**
 * What the report prints beside the number: the coverage caveat, the cap that
 * bit, and — for a domain with no number — the findings it holds anyway.
 *
 * That last clause is the one that stops `not-assessed` from reading as
 * "nothing here": a domain outside the run's scope can still collect findings
 * from a batch that looked at its units for another reason, and those findings
 * are in the dossier whether or not they could be scored.
 */
function domainStatement(input: {
  readonly gate: string;
  readonly cappedAt: number | null;
  readonly ceilingTitle: string;
  readonly assessed: boolean;
  readonly findingsTotal: number;
}): string {
  const capped =
    input.cappedAt === null
      ? input.gate
      : `${input.gate}; capped at ${input.cappedAt} — ${input.ceilingTitle.toLowerCase()}`;
  if (input.assessed || input.findingsTotal === 0) return capped;
  const plural = input.findingsTotal === 1 ? "finding" : "findings";
  return `${capped}; ${input.findingsTotal} ${plural} were reported for it anyway and are listed unscored`;
}

/**
 * Scores one domain: gate, deduct, cap.
 *
 * A `not-assessed` domain still carries its findings, its assurances and any
 * ceiling its findings fired — it simply has no number. That is the difference
 * this phase exists to preserve: "we did not look" and "we looked and it was
 * clean" are different sentences, and only one of them has a score.
 */
export function scoreDomain(input: DomainInput): DomainScore {
  const evidence = domainEvidence(input.domain, input.evidence ?? noEvidence());
  const gate = gateDomain(
    input.domain,
    input.coverage,
    input.inScope,
    evidence,
    input.findings.length,
  );
  const deductions = computeDeductions(input.findings);
  const assessed = gate.status !== "not-assessed";
  const baseScore = assessed ? baseScoreFrom(deductions) : null;
  const capped = applyCeilings(input.domain, baseScore, input.findings, evidence);
  const score = capped.score;
  const binding = capped.ceilings.find((ceiling) => ceiling.binding) ?? null;

  return DomainScoreSchema.parse({
    domain: input.domain,
    status: gate.status,
    score,
    band: score === null ? null : bandFor(score),
    bandLabel: score === null ? null : bandLabel(bandFor(score)),
    baseScore,
    coverage: gate.coverage,
    evidence,
    assessedRatio: gate.assessedRatio,
    deductions,
    deductionTotal: totalDeduction(deductions),
    ceilings: capped.ceilings,
    findingsTotal: input.findings.length,
    findingsBySeverity: countBySeverity(input.findings),
    assurances: input.assurances.length,
    assuranceUnits: input.assurances.reduce((sum, assurance) => sum + assurance.unitsChecked, 0),
    weight: DOMAIN_WEIGHTS[input.domain],
    effectiveWeight: score === null ? 0 : effectiveWeight(input.domain, gate.assessedRatio),
    statement: domainStatement({
      gate: gate.statement,
      cappedAt: binding === null ? null : binding.cap,
      ceilingTitle: binding === null ? "" : binding.title,
      assessed,
      findingsTotal: input.findings.length,
    }),
  });
}

/**
 * Builds the whole scorecard.
 *
 * Every domain in the contract gets a row, including the ones the run never
 * touched: a domain that is absent from the table is a domain a reader has to
 * notice is missing, and `not-assessed` is the whole point.
 */
export function buildScorecard(input: ScorecardInput): Scorecard {
  const coverageByDomain = new Map(input.coverage.map((row) => [row.domain, row]));
  const scope = new Set<Domain>(input.scope ?? input.coverage.map((row) => row.domain));
  const evidence = input.evidence ?? noEvidence();

  const domains = DomainSchema.options.map((domain) =>
    scoreDomain({
      domain,
      findings: input.findings.filter((finding) => finding.domain === domain),
      assurances: input.assurances.filter((assurance) => assurance.domain === domain),
      coverage: coverageByDomain.get(domain),
      inScope: scope.has(domain),
      evidence,
    }),
  );

  return ScorecardSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: input.runId,
    target: input.target,
    overall: buildOverall(domains),
    domains,
    confidence: buildConfidence(input.confidence ?? cleanConfidenceBasis()),
    findingsTotal: input.findings.length,
    findingsBySeverity: countBySeverity(input.findings),
    assurancesTotal: input.assurances.length,
  });
}

/**
 * The convenience the CLI wants: the three artifacts a finished run has on
 * disk, folded into a scorecard without this module touching the filesystem.
 *
 * `audit` and `scan` are optional because a run can legitimately have only one
 * of them — a scan-only run has no `audit.json`, an audit-only run no
 * `scan-report.json` — and what is missing contributes no confidence signal
 * rather than counting as a failure.
 *
 * `inventory` is what makes the evidence gate work, and a caller that has it
 * must pass it. `audit.json` alone cannot say how many units *exist*: a run that
 * audited nothing has no per-kind rows, so its evidence would read as "no units"
 * rather than as "thousands of units nobody looked at" — which is the difference between
 * this function and the bug it was written to close. `inventory.json` is written
 * by a deterministic phase and is present in every full run.
 */
export function buildScorecardFromArtifacts(input: {
  readonly document: FindingsDocument;
  readonly audit?: (AuditSignalSource & AuditUnitSource) | undefined;
  readonly scan?: ScanSignalSource | undefined;
  readonly inventory?: InventorySignalSource | undefined;
  readonly scope?: readonly Domain[] | undefined;
}): Scorecard {
  const { document } = input;
  return buildScorecard({
    runId: document.runId,
    target: document.target,
    findings: document.findings,
    assurances: document.assurances,
    coverage: document.coverage,
    ...(input.scope === undefined ? {} : { scope: input.scope }),
    evidence: evidenceFrom({
      ...(input.inventory === undefined ? {} : { inventory: input.inventory }),
      ...(input.audit === undefined ? {} : { audit: input.audit }),
    }),
    confidence: confidenceBasisFrom({
      ...(input.audit === undefined ? {} : { audit: input.audit }),
      ...(input.scan === undefined ? {} : { scan: input.scan }),
      findings: document.findings,
    }),
  });
}

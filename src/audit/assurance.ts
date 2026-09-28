/**
 * Assurances: the checks that ran and passed, with the evidence that proves it.
 *
 * A dossier that only lists what is broken is unreadable as a statement about a
 * codebase — the reader cannot tell the difference between "the handlers assert
 * ownership" and "nobody looked at the handlers". So the audit phase reports the
 * mirror image of a finding: *"ownership asserted before write: 23/23 mutation
 * handlers"*, with the `file:line` of each assertion, extracted from disk like
 * every other snippet Sentinel prints.
 *
 * Two rules shape everything here.
 *
 * **An assurance is an aggregate, not a per-unit echo.** Twenty-three units
 * asserting the same check produce one row, because the claim a client cares
 * about is the population, not the individual handler. The evidence is what
 * makes the aggregate checkable.
 *
 * **An assurance says what it does not cover.** If four handlers of the same
 * population were never audited — a failed batch, a model that declined — the
 * scope sentence states it. An unqualified "23/23" over a partial run is
 * exactly the overstatement this project exists not to make, and it is why the
 * un-audited count is an input to this module rather than an afterthought in
 * the renderer.
 */

import type { Assurance, CodeRef, Domain } from "../contracts/findings.ts";
import { DomainSchema } from "../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, type AuditUnitKind } from "../contracts/inventory.ts";
import { findingId } from "../scan/runners/_runner-support.ts";
import type { UnitOutcome } from "./coverage.ts";

/**
 * A check an agent asserted a unit passes, with its citations already proven.
 *
 * The refs arrive verified: the audit phase runs every one of them through
 * `src/verify/` and through the slice gate before it gets here, so this module
 * never has to wonder whether a snippet is real. It aggregates and it counts,
 * and that is all it does.
 */
export interface AssertedCheck {
  readonly unitId: string;
  readonly kind: AuditUnitKind;
  /** The domain whose checks the batch was running. */
  readonly domain: Domain;
  /** Dotted check id, e.g. `appsec.ownership-asserted-before-write`. */
  readonly checkId: string;
  /** One sentence in the report's voice: `ownership asserted before write`. */
  readonly statement: string;
  /** Plural noun for the population, e.g. `mutation handlers`. */
  readonly subject?: string | undefined;
  /** Verified citations showing the check is satisfied. */
  readonly evidence: readonly CodeRef[];
}

/** How many evidence refs one assurance carries before it starts sampling. */
export const MAX_ASSURANCE_EVIDENCE = 12;

/**
 * What a population of units is called in a report sentence.
 *
 * Sentinel's own words, not the model's: the model may call a population
 * anything, and `23/23 things` is not a sentence a client can act on. A check
 * that names its own `subject` overrides this, which is how "mutation
 * handlers" gets to be more specific than "route handlers".
 */
export const UNIT_KIND_NOUN: Readonly<Record<AuditUnitKind, string>> = {
  route: "route handlers",
  "data-access": "data-access call sites",
  "serverless-function": "serverless functions",
  "queue-consumer": "queue consumers",
  cron: "scheduled jobs",
  webhook: "webhook receivers",
  migration: "migrations",
  "role-gate": "role gates",
  sink: "unsafe-input sinks",
  "workflow-job": "CI workflow jobs",
  container: "container definitions",
};

/** Domain order in the assurance list: the declaration order of the contract's enum. */
const DOMAIN_RANK: ReadonlyMap<Domain, number> = new Map(
  DomainSchema.options.map((domain, index) => [domain, index]),
);

/** Unit-kind order in the assurance list: the declaration order of the contract's enum. */
const KIND_RANK: ReadonlyMap<AuditUnitKind, number> = new Map(
  AUDIT_UNIT_KINDS.map((kind, index) => [kind, index]),
);

/** Identity of a code pointer, so the same line cited twice is listed once. */
function refKey(ref: CodeRef): string {
  return `${ref.file}:${ref.line}:${ref.endLine ?? ""}`;
}

/** Stable across runs: an assurance is identified by its check and its population. */
export function assuranceId(domain: Domain, checkId: string, kind: AuditUnitKind): string {
  return findingId(domain, `assurance.${checkId}`, "", kind);
}

/**
 * Picks the sentence to print when units phrased the same check differently.
 *
 * The most frequent wins, ties broken lexicographically, because the artifact
 * has to be byte-identical between two runs over unchanged code and "whichever
 * unit answered first" is not.
 */
export function pickStatement(statements: readonly string[]): string {
  const counts = new Map<string, number>();
  for (const statement of statements) {
    const trimmed = statement.trim();
    if (trimmed === "") continue;
    counts.set(trimmed, (counts.get(trimmed) ?? 0) + 1);
  }
  const ranked = [...counts.entries()].sort(
    (left, right) => right[1] - left[1] || left[0].localeCompare(right[0]),
  );
  return ranked[0]?.[0] ?? "";
}

/** How a population of units fared, for the qualifier on a scope sentence. */
interface Population {
  readonly audited: number;
  readonly skipped: number;
}

/** Counts audited and un-audited units per `(domain, kind)`, over distinct ids. */
function populations(outcomes: readonly UnitOutcome[]): Map<string, Population> {
  const seen = new Map<string, Map<string, boolean>>();
  for (const outcome of outcomes) {
    const key = `${outcome.domain}/${outcome.kind}`;
    const units = seen.get(key) ?? new Map<string, boolean>();
    units.set(outcome.unitId, (units.get(outcome.unitId) ?? false) || outcome.audited);
    seen.set(key, units);
  }
  const out = new Map<string, Population>();
  for (const [key, units] of seen) {
    let audited = 0;
    for (const isAudited of units.values()) if (isAudited) audited += 1;
    out.set(key, { audited, skipped: units.size - audited });
  }
  return out;
}

/**
 * The scope sentence: the fraction, the population, and what is missing from it.
 *
 * The denominator is the number of units of this population that were
 * *audited*, never the number in the repository — a check is only claimed over
 * units an agent actually decided about. Units that were not audited are
 * disclosed after the fraction instead of being folded into it, because
 * "23/27" would read as four failing units when what happened is that four were
 * never looked at.
 */
export function buildScope(
  checked: number,
  noun: string,
  population: Population,
  evidenceShown: number,
): string {
  const considered = Math.max(checked, population.audited);
  const parts = [`${checked}/${considered} ${noun}`];
  if (population.skipped > 0) {
    // The noun is deliberately not repeated: the check's own subject may be
    // narrower than the population the un-audited units belong to, and `1
    // further mutation handlers` is not a sentence.
    parts.push(
      population.skipped === 1
        ? "1 more was not audited and is outside this assurance"
        : `${population.skipped} more were not audited and are outside this assurance`,
    );
  }
  if (evidenceShown < checked) {
    parts.push(`evidence lists ${evidenceShown} of ${checked}`);
  }
  return parts.join("; ");
}

/** One aggregation bucket: a check, over one population, in one domain. */
interface Bucket {
  readonly domain: Domain;
  readonly kind: AuditUnitKind;
  readonly checkId: string;
  readonly units: Set<string>;
  readonly statements: string[];
  readonly subjects: string[];
  readonly evidence: Map<string, CodeRef>;
}

/** Knobs for {@link buildAssurances}; both have a working default. */
export interface BuildAssurancesOptions {
  /** Evidence refs carried per assurance. Default {@link MAX_ASSURANCE_EVIDENCE}. */
  readonly maxEvidence?: number | undefined;
  /**
   * The run's scope. An assurance for a domain outside it is dropped rather
   * than reported, mirroring how coverage treats an out-of-scope domain.
   */
  readonly domains?: readonly Domain[] | undefined;
}

/**
 * Aggregates the checks the agents asserted into one `Assurance` per check and
 * population, with the evidence that proves each and a scope that admits what
 * it does not cover.
 *
 * Bucketed by `(domain, kind)` and not by check alone: the same check asserted
 * over route handlers and over data-access call sites is two claims with two
 * denominators, and merging them would produce a fraction that means nothing.
 */
export function buildAssurances(
  checks: readonly AssertedCheck[],
  outcomes: readonly UnitOutcome[] = [],
  options: BuildAssurancesOptions = {},
): Assurance[] {
  const limit = Math.max(1, Math.floor(options.maxEvidence ?? MAX_ASSURANCE_EVIDENCE));
  const counts = populations(outcomes);
  const buckets = new Map<string, Bucket>();

  for (const check of checks) {
    const checkId = check.checkId.trim();
    if (checkId === "") continue;
    if (options.domains !== undefined && !options.domains.includes(check.domain)) continue;
    const key = `${check.domain}${check.kind}${checkId}`;
    const bucket = buckets.get(key) ?? {
      domain: check.domain,
      kind: check.kind,
      checkId,
      units: new Set<string>(),
      statements: [],
      subjects: [],
      evidence: new Map<string, CodeRef>(),
    };
    bucket.units.add(check.unitId);
    bucket.statements.push(check.statement);
    if (check.subject !== undefined && check.subject.trim() !== "") {
      bucket.subjects.push(check.subject.trim());
    }
    for (const ref of check.evidence) {
      const refId = refKey(ref);
      if (!bucket.evidence.has(refId)) bucket.evidence.set(refId, ref);
    }
    buckets.set(key, bucket);
  }

  const assurances: Assurance[] = [];
  for (const bucket of buckets.values()) {
    const checked = bucket.units.size;
    if (checked === 0) continue;
    const noun = pickStatement(bucket.subjects) || UNIT_KIND_NOUN[bucket.kind];
    const population = counts.get(`${bucket.domain}/${bucket.kind}`) ?? {
      audited: checked,
      skipped: 0,
    };
    const evidence = [...bucket.evidence.values()]
      .sort((left, right) => left.file.localeCompare(right.file) || left.line - right.line)
      .slice(0, limit);

    assurances.push({
      id: assuranceId(bucket.domain, bucket.checkId, bucket.kind),
      domain: bucket.domain,
      check: pickStatement(bucket.statements) || bucket.checkId,
      scope: buildScope(checked, noun, population, evidence.length),
      unitsChecked: checked,
      evidence,
    });
  }

  return assurances.sort(
    (left, right) =>
      (DOMAIN_RANK.get(left.domain) ?? Number.MAX_SAFE_INTEGER) -
        (DOMAIN_RANK.get(right.domain) ?? Number.MAX_SAFE_INTEGER) ||
      left.check.localeCompare(right.check) ||
      left.id.localeCompare(right.id),
  );
}

/** Sorts assurances the way the artifacts store them; exported for the merge pass. */
export function compareAssurances(left: Assurance, right: Assurance): number {
  return (
    (DOMAIN_RANK.get(left.domain) ?? Number.MAX_SAFE_INTEGER) -
      (DOMAIN_RANK.get(right.domain) ?? Number.MAX_SAFE_INTEGER) ||
    left.check.localeCompare(right.check) ||
    left.id.localeCompare(right.id)
  );
}

/** Kind order helper, so a caller listing populations prints them in contract order. */
export function compareKinds(left: AuditUnitKind, right: AuditUnitKind): number {
  return (KIND_RANK.get(left) ?? 0) - (KIND_RANK.get(right) ?? 0);
}

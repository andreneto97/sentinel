/**
 * The prompt registry: one table saying which unit kinds phase 4 audits with a
 * model, **which domain each of those prompts answers for**, and the vocabulary —
 * check names, rule ids, severity ceilings — that the prompt and the decoder must
 * agree on.
 *
 * ## One table, three columns
 *
 * {@link PROMPT_REGISTRY} maps `(kind, domain) → prompt`. The domain column is
 * what was missing, and without it `api` and `reliability` can only report
 * `0 of 0`: a batch states the domain its verdicts are counted under
 * (`src/audit/coverage.ts`), so keying every batch by unit kind alone leaves no
 * unit reaching the D6 or D7 coverage tables even though `routes.ts` already asks
 * four `api.*` checks and `async.ts` three `reliability.*` ones. A
 * unit kind may now appear more than once, because a route really is an
 * access-control unit, an API contract and a reliability surface at the same
 * time.
 *
 * Registration is the honest boundary of the AI audit, in both directions:
 *
 * - A **kind** with no row that has a builder is not audited by a model, and
 *   `src/audit/batch.ts` reports its units as skipped with the reason from
 *   {@link unauditedReason} rather than quietly leaving them out of the coverage
 *   table. `container` is the only one: hadolint, `trivy config` and Sentinel's
 *   own D4 rules decide a Dockerfile in phase 1, so a model would only re-read it.
 *
 *   Note what that costs today, because the coverage table cannot say it: **no
 *   enumerator emits a `container` unit**, so `counts.container` is always 0 and
 *   the skip path above never fires for it. A repository with six Dockerfiles and
 *   three compose files still reports `container 0`, and its D4 findings arrive
 *   from phase 1 attached to no unit. The kind is therefore *declared* but not
 *   *enumerated*: `src/inventory/inventory.ts` registers route, data-access,
 *   migration, async and client-surface enumerators and nothing else. Until one
 *   exists, "audited deterministically in phase 1" is a claim the run cannot
 *   count, and D4 coverage speaks for its CI jobs alone.
 * - A **(kind, domain) pair** that is declared with no builder is a stated gap,
 *   not silence: {@link PROMPT_GAPS} carries the sentence, phase 3 puts it in the
 *   plan's notes, and the domain's score stays `not assessed`. No row is pending
 *   now — the D6 and D7 modules that were being written in parallel with this
 *   table are wired below — so a live run states no gap, and `prompts.test.ts`
 *   asserts that. The mechanism stays because the next domain will need it.
 *
 * ## Why the same unit is batched twice rather than asked twice in one batch
 *
 * A batch carries one domain, because `runAudit` files one outcome per unit per
 * batch and `buildAuditCoverage` groups those outcomes by domain — that is what
 * makes `audited + skipped === total` hold *per domain* by construction instead
 * of by arithmetic. Two domains therefore mean two batches over the same units,
 * and the second one pays for the same slices again. That is the price, and it is
 * why a row is only worth declaring when the domain asks something the other
 * rows do not: the registry deduplicates check ids across a kind's rows (first
 * row wins, see {@link checksFor}), so a second prompt that merely repeats the
 * first is reduced to nothing and reported as a gap rather than billed twice.
 *
 * ## What the lookups are for
 *
 * The lookups at the bottom are what keep the prompt and `src/audit/verdict.ts`
 * from drifting: the decoder asks this module which checks a kind demanded and
 * which rule ids it offered, so a rule the prompt never mentioned cannot arrive
 * as data and a check the prompt asked for cannot go unanswered unnoticed. They
 * answer over the *union* of a kind's rows when no domain is given, which is the
 * right answer for "is this allowed" — a route's reply may legitimately carry any
 * check any route prompt asks. A caller that holds the batch, and therefore knows
 * which half of that union was actually asked, should pass the batch's domain:
 * `checkIdsFor(kind, domain)` is the list that reply is obliged to answer.
 */

import type { Domain, Severity } from "../../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, type AuditUnitKind } from "../../contracts/inventory.ts";
import {
  type AuditCheck,
  type PromptBuilder,
  type PromptSpec,
  checkIdOf,
  createPromptBuilder,
} from "./_shared.ts";
import { apiPromptBuilder } from "./api.ts";
import {
  cronPromptBuilder,
  queueConsumerPromptBuilder,
  serverlessPromptBuilder,
  webhookPromptBuilder,
} from "./async.ts";
import { workflowJobPromptBuilder } from "./ci.ts";
import { roleGatePromptBuilder, sinkPromptBuilder } from "./client-surface.ts";
import { dataAccessPromptBuilder } from "./data-access.ts";
import { migrationPromptBuilder } from "./migrations.ts";
import {
  reliabilityCronPromptBuilder,
  reliabilityDataAccessPromptBuilder,
  reliabilityQueueConsumerPromptBuilder,
  reliabilityRoutePromptBuilder,
  reliabilityServerlessPromptBuilder,
} from "./reliability.ts";
import { routePromptBuilder } from "./routes.ts";

export type {
  AuditCheck,
  PromptBuilder,
  PromptContext,
  PromptParts,
  PromptSpec,
  PromptUnit,
  RelatedSlice,
  SharedSlice,
  StackFacts,
} from "./_shared.ts";
export {
  BLOCK_SEPARATOR,
  UNKNOWN_STACK,
  assemblePrompt,
  checkIdOf,
  createPromptBuilder,
  domainOfRule,
  promptChars,
  renderAttributes,
  renderChecks,
  renderShared,
  renderStack,
  renderUnit,
} from "./_shared.ts";

export { CRON_PROMPT, QUEUE_CONSUMER_PROMPT, SERVERLESS_PROMPT, WEBHOOK_PROMPT } from "./async.ts";
export { WORKFLOW_JOB_PROMPT } from "./ci.ts";
export { ROLE_GATE_PROMPT, SINK_PROMPT } from "./client-surface.ts";
export { DATA_ACCESS_PROMPT } from "./data-access.ts";
export { MIGRATION_PROMPT } from "./migrations.ts";
export { ROUTE_PROMPT } from "./routes.ts";

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/**
 * One row of the registry: a unit kind, the domain the verdicts are counted
 * under, and the prompt that asks that domain's questions.
 *
 * `builder` absent means the prompt does not exist yet. The row is still
 * declared, because a declared row produces a sentence in the plan and an
 * unwritten one produces nothing at all — and "nothing at all" is exactly how a
 * domain the plan intended comes to read as `0 of 0` with no explanation.
 */
export interface PromptRegistration {
  readonly kind: AuditUnitKind;
  /** The domain this prompt's verdicts are attributed to in the coverage table. */
  readonly domain: Domain;
  readonly builder?: PromptBuilder | undefined;
  /** Why there is no builder, naming the module that will export one. */
  readonly pending?: string | undefined;
}

/**
 * Every prompt phase 4 can send, and every one it is declared to be missing.
 *
 * Ordered by unit kind as `AUDIT_UNIT_KINDS` orders them, and within a kind with
 * its **primary** domain first. The primary domain must be the one
 * `DOMAIN_BY_UNIT_KIND` names in `src/audit/coverage.ts`, so that a unit no batch
 * reached lands in the same domain's table as a unit that was audited; the test
 * beside this file asserts it.
 */
export const PROMPT_REGISTRY: readonly PromptRegistration[] = [
  { kind: "route", domain: "appsec", builder: routePromptBuilder },
  { kind: "route", domain: "api", builder: apiPromptBuilder },
  { kind: "route", domain: "reliability", builder: reliabilityRoutePromptBuilder },
  { kind: "data-access", domain: "data", builder: dataAccessPromptBuilder },
  { kind: "data-access", domain: "reliability", builder: reliabilityDataAccessPromptBuilder },
  { kind: "serverless-function", domain: "serverless", builder: serverlessPromptBuilder },
  {
    kind: "serverless-function",
    domain: "reliability",
    builder: reliabilityServerlessPromptBuilder,
  },
  { kind: "queue-consumer", domain: "serverless", builder: queueConsumerPromptBuilder },
  { kind: "queue-consumer", domain: "reliability", builder: reliabilityQueueConsumerPromptBuilder },
  { kind: "cron", domain: "serverless", builder: cronPromptBuilder },
  { kind: "cron", domain: "reliability", builder: reliabilityCronPromptBuilder },
  { kind: "webhook", domain: "serverless", builder: webhookPromptBuilder },
  { kind: "migration", domain: "data", builder: migrationPromptBuilder },
  { kind: "role-gate", domain: "appsec", builder: roleGatePromptBuilder },
  { kind: "sink", domain: "appsec", builder: sinkPromptBuilder },
  { kind: "workflow-job", domain: "delivery", builder: workflowJobPromptBuilder },
];

/**
 * Why a kind has no prompt at all, stated once so the coverage table can quote it.
 *
 * `workflow-job` used to be here beside `container`, on the grounds that
 * actionlint and Sentinel's CI rules decide a workflow. They decide its syntax.
 * The worst thing a workflow does is build untrusted pull-request code with a
 * cloud role attached, and telling that apart from a job that merely checks the
 * same code out needs the steps read in order — so `./ci.ts` now audits the kind
 * and this map has one entry left.
 */
export const UNAUDITED_KIND_REASONS: Readonly<Partial<Record<AuditUnitKind, string>>> = {
  container:
    "audited deterministically in phase 1 by hadolint, trivy config and Sentinel's D4 rules",
};

// ---------------------------------------------------------------------------
// What the table resolves to
// ---------------------------------------------------------------------------

/** A prompt phase 4 will send: the kind, the domain it answers for, and the builder. */
export interface PromptPlanEntry {
  readonly kind: AuditUnitKind;
  readonly domain: Domain;
  readonly builder: PromptBuilder;
}

/** A declared `(kind, domain)` pair with no prompt behind it, and why. */
export interface PromptGap {
  readonly kind: AuditUnitKind;
  readonly domain: Domain;
  /** The sentence phase 3 prints; it names the module that would close the gap. */
  readonly reason: string;
}

/**
 * Resolves the table once: the prompts that will be sent, and the stated gaps.
 *
 * Two things happen here that a bare table cannot express. A prompt is
 * **projected** onto the checks no earlier row of the same kind already asks,
 * because a reply carries one answer per check id per unit — asking the same
 * question in two batches would buy two answers to one question, pay for the
 * slices twice, and double-count the check's population in the assurance table.
 * And a projection that empties a prompt becomes a gap, so a second module that
 * only repeats the first is reported instead of dispatched.
 */
export function resolveRegistry(rows: readonly PromptRegistration[]): {
  readonly entries: readonly PromptPlanEntry[];
  readonly gaps: readonly PromptGap[];
} {
  const entries: PromptPlanEntry[] = [];
  const gaps: PromptGap[] = [];
  for (const kind of AUDIT_UNIT_KINDS) {
    const claimed = new Map<string, Domain>();
    for (const row of rows.filter((candidate) => candidate.kind === kind)) {
      if (row.builder === undefined) {
        gaps.push({
          kind,
          domain: row.domain,
          reason: row.pending ?? "no prompt module claims this domain for this unit kind",
        });
        continue;
      }
      const spec = row.builder.spec;
      const kept = spec.checks.filter((check) => !claimed.has(checkIdOf(check)));
      if (kept.length === 0) {
        const first = spec.checks[0];
        const owner = first === undefined ? undefined : claimed.get(checkIdOf(first));
        gaps.push({
          kind,
          domain: row.domain,
          reason: `every check this prompt asks of a ${kind} is already asked by the ${owner ?? "primary"} prompt for that kind, so a second batch would buy the same answers twice`,
        });
        continue;
      }
      for (const check of kept) claimed.set(checkIdOf(check), row.domain);
      entries.push({
        kind,
        domain: row.domain,
        // Identity when nothing was projected away, so the prompt a kind's
        // primary batch sends is byte-for-byte the one its module declares.
        builder:
          kept.length === spec.checks.length
            ? row.builder
            : createPromptBuilder({ ...spec, checks: kept } satisfies PromptSpec),
      });
    }
  }
  return { entries, gaps };
}

const RESOLVED = resolveRegistry(PROMPT_REGISTRY);

/**
 * Every prompt phase 4 can send, in table order.
 *
 * This is the list `src/audit/batch.ts` iterates: one batch series per entry, so
 * a kind with two domains produces two series over the same units and each one
 * is counted under its own domain.
 */
export const AUDIT_PROMPTS: readonly PromptPlanEntry[] = RESOLVED.entries;

/** Every declared `(kind, domain)` pair that has no prompt, with the sentence to print. */
export const PROMPT_GAPS: readonly PromptGap[] = RESOLVED.gaps;

/** The kinds phase 4 sends to a model, in contract order. */
export const AUDITED_KINDS: readonly AuditUnitKind[] = AUDIT_UNIT_KINDS.filter((kind) =>
  AUDIT_PROMPTS.some((entry) => entry.kind === kind),
);

/** The prompts registered for one kind, primary domain first. */
export function promptsFor(kind: AuditUnitKind): readonly PromptPlanEntry[] {
  return AUDIT_PROMPTS.filter((entry) => entry.kind === kind);
}

/** The domains a kind's units are audited under, primary first. */
export function domainsFor(kind: AuditUnitKind): readonly Domain[] {
  return promptsFor(kind).map((entry) => entry.domain);
}

/** The declared gaps for one kind, or for every kind when none is named. */
export function gapsFor(kind?: AuditUnitKind): readonly PromptGap[] {
  return kind === undefined ? PROMPT_GAPS : PROMPT_GAPS.filter((gap) => gap.kind === kind);
}

/**
 * The prompt for a kind: the one that answers `domain`, or the primary one.
 *
 * `undefined` when no model audits that kind at all, or when it does but not for
 * the domain asked — which is the answer a caller iterating domains needs, and
 * the reason phase 3 never invents a batch for a gap.
 */
export function promptFor(kind: AuditUnitKind, domain?: Domain): PromptBuilder | undefined {
  const rows = promptsFor(kind);
  if (domain === undefined) return rows[0]?.builder;
  return rows.find((entry) => entry.domain === domain)?.builder;
}

/** The domain a kind's units are counted under when no batch says otherwise. */
export function primaryDomainOf(kind: AuditUnitKind): Domain | undefined {
  return promptsFor(kind)[0]?.domain;
}

/** True when phase 4 audits this kind with a model, under any domain. */
export function isAuditedKind(kind: AuditUnitKind): boolean {
  return promptsFor(kind).length > 0;
}

/**
 * Why this kind is not sent to a model, when it is not.
 *
 * A kind that is deterministic by design says so. A kind whose only rows are
 * pending says which module is missing, because "the prompt has not been written"
 * and "a model looked and found nothing" must never read the same way.
 */
export function unauditedReason(kind: AuditUnitKind): string {
  const declared = UNAUDITED_KIND_REASONS[kind];
  if (declared !== undefined) return declared;
  const pending = gapsFor(kind);
  if (pending.length > 0) {
    return `no prompt is built for this unit kind yet: ${pending.map((gap) => gap.reason).join("; ")}`;
  }
  return "no phase 4 prompt covers this unit kind";
}

// ---------------------------------------------------------------------------
// The check vocabulary
// ---------------------------------------------------------------------------

/**
 * The checks a kind's prompt demands, in the order it lists them.
 *
 * Without `domain`, every check any of the kind's prompts asks, deduplicated —
 * the set a reply for a unit of this kind may draw from. With `domain`, exactly
 * the checks that domain's batch asked, which is the set such a reply is
 * *obliged* to answer.
 */
export function checksFor(kind: AuditUnitKind, domain?: Domain): readonly AuditCheck[] {
  const rows =
    domain === undefined
      ? promptsFor(kind)
      : promptsFor(kind).filter((entry) => entry.domain === domain);
  return rows.flatMap((entry) => entry.builder.spec.checks);
}

/** The check ids a verdict for this kind (optionally, for this domain) must answer. */
export function checkIdsFor(kind: AuditUnitKind, domain?: Domain): readonly string[] {
  return checksFor(kind, domain).map((check) => checkIdOf(check));
}

/**
 * Every check any prompt asks, by its dotted id.
 *
 * Built once, across every kind, so a reply can be read without knowing which
 * kind produced it — which is what the audit phase's verdict adapter needs, and
 * what lets the same assertion made by a route and by a webhook be counted as
 * one population. Two kinds may share an id only when they mean the same thing:
 * `prompts.test.ts` fails if a shared id carries a different rule or statement.
 */
export const CHECK_INDEX: ReadonlyMap<string, AuditCheck> = (() => {
  const index = new Map<string, AuditCheck>();
  for (const kind of AUDITED_KINDS) {
    for (const check of checksFor(kind)) {
      const id = checkIdOf(check);
      if (!index.has(id)) index.set(id, check);
    }
  }
  return index;
})();

/** The check a dotted id names, whichever kind asked it. */
export function checkById(id: string): AuditCheck | undefined {
  return CHECK_INDEX.get(id);
}

/** The check a kind asks under this dotted id. */
export function checkOf(kind: AuditUnitKind, id: string): AuditCheck | undefined {
  return checksFor(kind).find((check) => checkIdOf(check) === id);
}

/** The rule ids a kind's prompt offered; anything else is not data. */
export function rulesFor(kind: AuditUnitKind, domain?: Domain): readonly string[] {
  return [...new Set(checksFor(kind, domain).map((check) => check.rule))];
}

/** Severities from weakest to strongest, for comparison against a ceiling. */
const SEVERITY_ORDER: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

/**
 * The highest severity each rule may carry, across every kind that offers it.
 *
 * Batch-independent on purpose: a reply can be clamped to the rubric by a caller
 * that has the rule and not the unit kind, which is what the audit phase's
 * verdict adapter has.
 */
export const RULE_CEILINGS: ReadonlyMap<string, Severity> = (() => {
  const index = new Map<string, Severity>();
  for (const kind of AUDITED_KINDS) {
    for (const check of checksFor(kind)) {
      const current = index.get(check.rule);
      if (
        current === undefined ||
        SEVERITY_ORDER.indexOf(check.ceiling) > SEVERITY_ORDER.indexOf(current)
      ) {
        index.set(check.rule, check.ceiling);
      }
    }
  }
  return index;
})();

/** The highest severity a rule may carry anywhere; `undefined` for an invented rule. */
export function ceilingOfRule(rule: string): Severity | undefined {
  return RULE_CEILINGS.get(rule);
}

/**
 * The highest severity a rule may carry for this kind.
 *
 * `undefined` for a rule the kind never offered, which is how the decoder tells
 * an invented rule from a real one. When two checks share a rule the looser
 * ceiling wins: the rule is the same claim whichever question raised it.
 */
export function ceilingFor(kind: AuditUnitKind, rule: string): Severity | undefined {
  let best: Severity | undefined;
  for (const check of checksFor(kind)) {
    if (check.rule !== rule) continue;
    if (
      best === undefined ||
      SEVERITY_ORDER.indexOf(check.ceiling) > SEVERITY_ORDER.indexOf(best)
    ) {
      best = check.ceiling;
    }
  }
  return best;
}

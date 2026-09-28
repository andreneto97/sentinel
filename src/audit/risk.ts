/**
 * Which units a bounded run should spend its model on first.
 *
 * Phase 2 enumerates every unit of audit. On a small application that is a couple
 * of hundred of them and phase 4 can afford all of it. On a large monorepo it is
 * thousands, which is several hundred batches and most of a day against a
 * throttled subscription — so phase 4 has to stop somewhere, and *where* it stops
 * is the whole question. A run that audits the first 800 units in
 * `AUDIT_UNIT_KINDS` order spends its entire budget on `data-access`, because
 * data-access call sites outnumber every other kind by an order of magnitude and
 * the enumeration order puts routes first only by accident of the enum. A run that
 * audits 800 units chosen by risk spends it on the route handlers that take an id
 * off the wire without an auth check, the webhook receivers that verify no
 * signature, and the queue consumers with no idempotency key — and *then* starts
 * on the queries.
 *
 * So this module answers one question about one unit: **how much would a
 * verdict about it be worth?** It answers in points, from facts phase 2 already
 * proved and wrote into `attributes` — never from the source, which this module
 * never reads, and never from a model, which has not been called yet.
 *
 * Three properties the rest of phase 3 and 4 depend on:
 *
 * - **It explains itself.** A score is useless in a dossier; `RiskScore.reasons`
 *   is the list of sentences that produced it, in descending weight, so the
 *   report can say *why* a unit was near the front instead of asking a reader to
 *   trust a number. "Bounding is not hiding" cuts both ways: the units that were
 *   left out are named, and the units that were chosen say what chose them.
 * - **It is deterministic.** Same inventory, same order, down to the tie-breaks,
 *   so a resumed run continues the list rather than reshuffling it.
 * - **It is conservative about the unknown.** An attribute phase 2 could not
 *   decide (`unknown`, `unresolved`, absent) never *lowers* a unit below one
 *   that was proved safe. A webhook whose signature check could not be found
 *   outranks one that demonstrably has it, because the first is a question and
 *   the second is an answer.
 *
 * The weights are judgement, and they are written as data rather than as `if`
 * statements so that the judgement can be read, argued with and tested in one
 * place. They encode the D2/D3/D5 priority order of `PLAN.md`: reachable from
 * the network beats internal; mutating beats reading; unauthenticated beats
 * guarded; a query that does not constrain by the principal beats one that does;
 * and a migration that already ran, on a schema the rest of the audit will
 * reconstruct anyway, comes last.
 */

import type { AuditUnit } from "../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, type AuditUnitKind } from "../contracts/inventory.ts";

/** The attributes of one unit, as phase 2 wrote them. */
type Attributes = Readonly<Record<string, string>>;

/** A unit's priority, and the sentences that produced it. */
export interface RiskScore {
  /** 0–100. Higher is audited earlier. */
  readonly score: number;
  /**
   * Why this unit was prioritised, heaviest signal first.
   *
   * This is what the dossier quotes. It is never empty: a unit with no risk
   * signal at all still says what kind of thing it is.
   */
  readonly reasons: readonly string[];
}

/** A unit with its score, as {@link rankUnits} returns it. */
export interface RankedUnit {
  readonly unit: AuditUnit;
  readonly risk: RiskScore;
}

/**
 * The one sentence that describes the ordering, for the report.
 *
 * Kept here, beside the weights it describes, so a change to the table that is
 * not reflected in the sentence is a diff a reviewer sees in one screen.
 */
export const RISK_ORDERING =
  "ordered by exposure and blast radius: entry points reachable from the network before internal " +
  "code, unauthenticated before guarded, mutating before reading, queries that do not constrain " +
  "by the authenticated principal before queries that do, and already-applied migrations last";

// ---------------------------------------------------------------------------
// The weights
// ---------------------------------------------------------------------------

/**
 * What a kind is worth before any of its own facts are read.
 *
 * This is blast radius, not likelihood: a route handler is the thing an attacker
 * can reach, a data-access call site is what the handler reaches, and a
 * migration has already run. `workflow-job` and `container` are scored for
 * totality only — no phase 4 prompt covers them, so they never reach a batch.
 */
export const KIND_BASE: Readonly<Record<AuditUnitKind, number>> = {
  route: 30,
  webhook: 30,
  cron: 30,
  "serverless-function": 26,
  sink: 24,
  "queue-consumer": 20,
  "role-gate": 16,
  "data-access": 10,
  migration: 6,
  "workflow-job": 4,
  container: 4,
};

/** One weighted fact about a unit. */
interface Signal {
  /** Points added when {@link Signal.when} holds. */
  readonly points: number;
  /** The sentence `RiskScore.reasons` carries when it fires. */
  readonly why: string;
  readonly when: (attributes: Attributes) => boolean;
}

/** True when phase 2 wrote a real value rather than a placeholder for "not known". */
function known(value: string | undefined): value is string {
  if (value === undefined) return false;
  const trimmed = value.trim().toLowerCase();
  return trimmed !== "" && trimmed !== "unknown" && trimmed !== "unresolved" && trimmed !== "n/a";
}

/** True unless phase 2 proved the answer is `yes`: an unproved guard is not a guard. */
function notProvenYes(value: string | undefined): boolean {
  return value?.trim().toLowerCase() !== "yes";
}

/** True when the value is one of `options`, case-insensitively. */
function isOneOf(value: string | undefined, ...options: readonly string[]): boolean {
  if (value === undefined) return false;
  const normalised = value.trim().toLowerCase();
  return options.includes(normalised);
}

/**
 * The words the codebase uses for "a read", across two vocabularies.
 *
 * `src/inventory/data-access.ts` writes `select`; `src/audit/prompts/` documents
 * the attribute as though it were `read`. Both are accepted rather than one
 * being declared correct, because a scorer that silently matched neither would
 * flatten every call site in a repository to the same score and nothing would
 * fail.
 */
const READ_OPERATIONS = ["select", "read", "find", "aggregate", "count"] as const;

/** The words it uses for "a write that can touch more than one row". */
const BROAD_WRITE_OPERATIONS = ["update", "delete", "upsert", "write"] as const;

/**
 * True when nothing constrains the query by the authenticated principal.
 *
 * Two spellings again: the enumerator emits `no` / `yes` / `scoped`, the prompt
 * documents `false` / `true`. `scoped` counts as constrained — it is the
 * enumerator saying it found the predicate on a column it recognised as a tenant
 * key — and an unknown counts as neither, because this is the single heaviest
 * signal in the data-access table and it must not fire on a shrug.
 */
function unscoped(value: string | undefined): boolean {
  return isOneOf(value, "no", "false");
}

/**
 * The per-kind signal tables.
 *
 * Read them as the audit questions themselves, weighted: every line here is a
 * precondition for a D2, D3 or D5 rule that phase 4's prompt for that kind will
 * ask about, so a unit that scores high is literally a unit where more of the
 * questions are already answered "maybe".
 */
const SIGNALS: Readonly<Partial<Record<AuditUnitKind, readonly Signal[]>>> = {
  route: [
    {
      points: 24,
      why: "reachable without authentication",
      when: (a) => isOneOf(a.authenticated, "no"),
    },
    {
      points: 10,
      why: "the handler performs no role or ownership check",
      when: (a) => isOneOf(a.authCheck, "none"),
    },
    { points: 12, why: "mutates state", when: (a) => isOneOf(a.mutates, "true") },
    {
      points: 6,
      why: "deletes, so a mistake is not reversible",
      when: (a) => isOneOf(a.method, "delete"),
    },
    {
      points: 3,
      why: "replaces a whole resource",
      when: (a) => isOneOf(a.method, "put", "patch"),
    },
    {
      points: 10,
      why: "takes an object id from the request, which is the precondition for IDOR",
      when: (a) => known(a.idParams),
    },
    {
      points: 8,
      why: "no schema validation at the request boundary",
      when: (a) => isOneOf(a.validation, "none"),
    },
    {
      points: 4,
      why: "reads the request body, so mass assignment is possible",
      when: (a) => isOneOf(a.readsBody, "true"),
    },
    {
      points: 2,
      why: "an unpaginated read, so the response size is unbounded",
      when: (a) => isOneOf(a.pagination, "none") && isOneOf(a.mutates, "false"),
    },
  ],
  webhook: [
    {
      points: 28,
      why: "no inbound signature verification was found",
      when: (a) => notProvenYes(a.signatureVerified),
    },
    {
      points: 10,
      why: "no replay or timestamp protection was found",
      when: (a) => notProvenYes(a.replayProtection),
    },
    {
      points: 6,
      why: "reads a parsed body where the raw body is what a signature covers",
      when: (a) => isOneOf(a.usesRawBody, "no"),
    },
  ],
  cron: [
    {
      points: 28,
      why: "the scheduled endpoint is reachable without a shared secret",
      when: (a) => isOneOf(a.authenticated, "no") || isOneOf(a.authCheck, "none"),
    },
    {
      points: 4,
      why: "the handler it invokes is known, so the schedule can be judged end to end",
      when: (a) => known(a.targetUnitId),
    },
  ],
  "serverless-function": [
    {
      points: 22,
      why: "invocable without authentication",
      when: (a) => isOneOf(a.authenticated, "no"),
    },
    { points: 6, why: "triggered over HTTP", when: (a) => isOneOf(a.trigger, "http") },
  ],
  "queue-consumer": [
    {
      points: 14,
      why: "no idempotency key, so a redelivery repeats the work",
      when: (a) => isOneOf(a.idempotencyKey, "none"),
    },
    {
      points: 10,
      why: "no dead-letter queue, so a poisoned message is lost or loops",
      when: (a) => isOneOf(a.dlq, "none"),
    },
    { points: 5, why: "no attempt cap", when: (a) => isOneOf(a.attempts, "unset") },
    { points: 5, why: "no backoff between attempts", when: (a) => isOneOf(a.backoff, "unset") },
    { points: 3, why: "the handler has no timeout", when: (a) => isOneOf(a.timeout, "unset") },
  ],
  "role-gate": [
    {
      points: 8,
      why: "the handler behind the gate is known, so the gate can be decided rather than guessed",
      when: (a) => known(a.targetUnitId),
    },
  ],
  sink: [
    {
      points: 20,
      why: "a SQL or command sink, where unsafe input becomes execution",
      when: (a) => isOneOf(a.sinkType, "sql", "nosql", "command", "eval"),
    },
    {
      points: 16,
      why: "an HTML sink, where unsafe input becomes script",
      when: (a) => isOneOf(a.sinkType, "xss", "html", "template"),
    },
    {
      points: 10,
      why: "the sink's argument is built at runtime rather than being a constant",
      when: (a) => isOneOf(a.dynamic, "yes"),
    },
  ],
  "data-access": [
    {
      points: 20,
      why: "no predicate constrains the query by the authenticated principal",
      when: (a) => unscoped(a.filtersByPrincipal),
    },
    { points: 10, why: "deletes rows", when: (a) => isOneOf(a.operation, "delete") },
    {
      points: 8,
      why: "writes rows",
      when: (a) => isOneOf(a.operation, "update", "upsert"),
    },
    {
      points: 6,
      why: "raw SQL, which the ORM does not parameterise for the caller",
      when: (a) => isOneOf(a.operation, "raw"),
    },
    { points: 4, why: "inserts rows", when: (a) => isOneOf(a.operation, "insert") },
    {
      points: 10,
      why: "a write with no WHERE clause, so it reaches every row",
      when: (a) => isOneOf(a.hasWhere, "false") && isOneOf(a.operation, ...BROAD_WRITE_OPERATIONS),
    },
    {
      points: 8,
      why: "the call sits inside a loop, which is the N+1 shape",
      when: (a) => known(a.insideLoop) && !isOneOf(a.insideLoop, "false"),
    },
    {
      points: 4,
      why: "an unbounded read with no LIMIT",
      when: (a) => isOneOf(a.hasLimit, "false") && isOneOf(a.operation, ...READ_OPERATIONS),
    },
    {
      points: 3,
      why: "runs inside a transaction, so it holds locks",
      when: (a) => isOneOf(a.insideTransaction, "true"),
    },
  ],
  migration: [
    {
      points: 16,
      why: "a destructive operation",
      when: (a) => isOneOf(a.destructive, "true"),
    },
    {
      points: 12,
      why: "a locking operation on a table that may already be large",
      when: (a) => known(a.lockRisk) && !isOneOf(a.lockRisk, "none"),
    },
    {
      points: 8,
      why: "no down migration, so there is no rollback path",
      when: (a) => isOneOf(a.hasDownMigration, "false"),
    },
    {
      points: 6,
      why: "mixes a data migration into a schema migration",
      when: (a) => isOneOf(a.mixesDataAndSchema, "true"),
    },
  ],
};

/** Highest score a unit can reach; the scale is capped so it reads as a percentage. */
const MAX_SCORE = 100;

/** How much of a migration's score recency is allowed to decide. */
const RECENCY_POINTS = 6;

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/**
 * The little the score needs to know about the *rest* of the inventory.
 *
 * Almost every signal is a fact about one unit, which is what keeps the function
 * testable. Recency is the exception and it is worth the exception: "an
 * unauthenticated cron endpoint outranks a migration from 2023" is only
 * decidable against the migrations that came after it. Built by
 * {@link riskContextOf} in one pass, and empty by default so `scoreUnit` remains
 * callable on a single unit.
 */
export interface RiskContext {
  /** The newest migration ordinal in the inventory, or 0 when there are none. */
  readonly newestMigration: number;
}

/** A context that knows nothing, which is what a single-unit score is judged under. */
export const EMPTY_RISK_CONTEXT: RiskContext = { newestMigration: 0 };

/** A migration's position in the history, from `ordinal` or the `version` stamp. */
function migrationOrdinal(attributes: Attributes): number {
  for (const key of ["ordinal", "version"]) {
    const raw = attributes[key];
    if (raw === undefined) continue;
    const digits = raw.replace(/\D/g, "");
    if (digits === "") continue;
    const value = Number(digits.slice(0, 15));
    if (Number.isFinite(value) && value > 0) return value;
  }
  return 0;
}

/** Reads the corpus-level facts the score needs, in one pass over the units. */
export function riskContextOf(units: readonly AuditUnit[]): RiskContext {
  let newest = 0;
  for (const unit of units) {
    if (unit.kind !== "migration") continue;
    newest = Math.max(newest, migrationOrdinal(unit.attributes));
  }
  return { newestMigration: newest };
}

// ---------------------------------------------------------------------------
// The score
// ---------------------------------------------------------------------------

/** `route handler` / `data-access call site`, for the reason a unit always carries. */
function kindReason(kind: AuditUnitKind): string {
  switch (kind) {
    case "route":
    case "webhook":
    case "cron":
    case "serverless-function":
      return "an entry point reachable from outside the process";
    case "queue-consumer":
      return "runs outside the request cycle, where retries and failures are invisible";
    case "sink":
      return "a sink where unsafe input leaves the program";
    case "role-gate":
      return "an authorization decision made in the client";
    case "data-access":
      return "a call site that reads or writes the database";
    case "migration":
      return "a migration that has already been applied";
    default:
      return "audited deterministically in phase 1";
  }
}

/**
 * Scores one unit from the facts phase 2 proved about it.
 *
 * Pure, total and independent of every other unit except for the migration
 * recency carried in `context` — so a unit's place in the queue can be explained
 * by pointing at the unit.
 */
export function scoreUnit(unit: AuditUnit, context: RiskContext = EMPTY_RISK_CONTEXT): RiskScore {
  const fired: Array<{ points: number; why: string }> = [];
  for (const signal of SIGNALS[unit.kind] ?? []) {
    if (signal.when(unit.attributes)) fired.push({ points: signal.points, why: signal.why });
  }

  if (unit.kind === "migration" && context.newestMigration > 0) {
    const ordinal = migrationOrdinal(unit.attributes);
    const share = ordinal <= 0 ? 0 : Math.min(1, ordinal / context.newestMigration);
    // Recency is a nudge inside the kind, never enough to lift a 2023 migration
    // past an unauthenticated endpoint: six points against a 30-point base.
    const points = Math.round(RECENCY_POINTS * share);
    if (points > 0) {
      fired.push({ points, why: "one of the most recent migrations, so least likely reviewed" });
    }
  }

  const raw = KIND_BASE[unit.kind] + fired.reduce((sum, signal) => sum + signal.points, 0);
  // Heaviest first, then alphabetically, so two units with the same signals
  // produce byte-identical explanations.
  fired.sort((left, right) => right.points - left.points || left.why.localeCompare(right.why));
  return {
    score: Math.max(0, Math.min(MAX_SCORE, raw)),
    reasons: [kindReason(unit.kind), ...fired.map((signal) => signal.why)],
  };
}

/** Kind order, for the tie-break: the contract's own declaration order. */
const KIND_RANK: ReadonlyMap<AuditUnitKind, number> = new Map(
  AUDIT_UNIT_KINDS.map((kind, index) => [kind, index]),
);

/**
 * Every unit with its score, highest risk first.
 *
 * The tie-break is the inventory's own sort — kind, file, line, id — so the
 * order is total and identical between two runs over unchanged code. That is
 * what makes a bounded run resumable: the second attempt continues the same
 * list instead of reshuffling it and re-auditing what the first one covered.
 */
export function rankUnits(
  units: readonly AuditUnit[],
  context: RiskContext = riskContextOf(units),
): RankedUnit[] {
  return units
    .map((unit) => ({ unit, risk: scoreUnit(unit, context) }))
    .sort(
      (left, right) =>
        right.risk.score - left.risk.score ||
        (KIND_RANK.get(left.unit.kind) ?? 0) - (KIND_RANK.get(right.unit.kind) ?? 0) ||
        left.unit.location.file.localeCompare(right.unit.location.file) ||
        left.unit.location.line - right.unit.location.line ||
        left.unit.id.localeCompare(right.unit.id),
    );
}

/**
 * The score a batch carries, for ordering batches against each other.
 *
 * The mean rather than the maximum, because a batch is dispatched whole: what it
 * is worth is what its twenty units are worth on average, and taking the maximum
 * would let one unauthenticated handler drag nineteen clean reads to the front
 * of the queue.
 */
export function meanRisk(scores: readonly RiskScore[]): number {
  if (scores.length === 0) return 0;
  const total = scores.reduce((sum, score) => sum + score.score, 0);
  // Two decimals: enough to order, few enough that the artifact diffs cleanly.
  return Math.round((total / scores.length) * 100) / 100;
}

/**
 * The distinct reasons a group of units was prioritised, most common first.
 *
 * What the dossier prints after "ordered by": the actual signals that put these
 * units at the front of this repository's queue, rather than the generic
 * sentence — on one repository that is "reachable without authentication", on
 * another it is "no idempotency key".
 */
export function topReasons(scores: readonly RiskScore[], limit = 3): string[] {
  const counts = new Map<string, { count: number; rank: number }>();
  for (const score of scores) {
    // The first reason is the kind itself, which every unit of the kind shares
    // and which therefore explains nothing about the ordering.
    score.reasons.slice(1).forEach((reason, index) => {
      const seen = counts.get(reason);
      // `reasons` is already heaviest-first, so the earliest position a reason
      // ever took is a stand-in for its weight. Ties on count then break on
      // weight rather than alphabetically, which is the difference between
      // "reachable without authentication" and "deletes, so a mistake is not
      // reversible" leading the sentence.
      counts.set(reason, {
        count: (seen?.count ?? 0) + 1,
        rank: Math.min(seen?.rank ?? index, index),
      });
    });
  }
  return [...counts.entries()]
    .sort(
      (left, right) =>
        right[1].count - left[1].count ||
        left[1].rank - right[1].rank ||
        left[0].localeCompare(right[0]),
    )
    .slice(0, Math.max(0, limit))
    .map(([reason]) => reason);
}

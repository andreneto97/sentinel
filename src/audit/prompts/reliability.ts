/**
 * The D7 prompts: reliability and observability, asked of units that already exist.
 *
 * Every other prompt module owns a unit *kind*. This one owns a *domain*, and
 * that is the whole difference: there is no `reliability` unit to enumerate. A
 * missing timeout lives in a route handler, a missing idempotency key lives in a
 * queue consumer, a tenant-blind cache key lives next to a query. So D7 is a
 * second lens over five kinds the inventory already produces — `route`,
 * `data-access`, `queue-consumer`, `cron` and `serverless-function` — registered
 * in `./index.ts` as `(kind, reliability)` rows, so the batches it plans carry
 * `domain: "reliability"`. That is what turns `no reliability check ran in this
 * run (0 of 0)` into a number a run actually earned.
 *
 * ## The rule that shapes the check sets
 *
 * **A kind is never asked the same question twice.** The D5 consumer prompt
 * already asks a BullMQ consumer about idempotency, retries, dead-lettering,
 * concurrency and swallowed failures; the D3 data-access prompt already asks a
 * call site whether its transaction holds network I/O. Asking again would put two
 * findings with two severities in two sections of the report for one defect, and
 * the reader could not tell they were the same — which is why the registry
 * projects a duplicated check id off the later row and, if that empties the
 * prompt, reports the row as a gap instead of dispatching it. So each kind here
 * is asked exactly the reliability questions no existing lens asks of *it*:
 *
 * | kind | what this lens adds |
 * |---|---|
 * | `route` | timeouts, backoff, idempotency, transaction boundary, swallowed failures, logging, cache scope, shutdown |
 * | `data-access` | timeouts, backoff, idempotency, swallowed failures, cache scope and expiry |
 * | `queue-consumer` | transaction boundary, logging, cache scope, shutdown — D5 owns the rest |
 * | `cron` | timeouts, backoff, idempotency, transaction boundary, swallowed failures, logging |
 * | `serverless-function` | the timeouts on the calls the function makes, not the function's own |
 *
 * `reliability.test.ts` fails if a check here collides with a check the same
 * kind is already asked, so the table above cannot rot.
 *
 * Where a question *is* shared, it is shared by identity rather than by
 * paraphrase: `transaction-boundary` carries D3's own rule, statement and
 * ceiling, so the same defect found from the handler and from the call site
 * collapses into one finding — phase 4 de-duplicates by `(domain, rule, file,
 * symbol)` — instead of into two that disagree.
 *
 * ## Two things this lens deliberately cannot do
 *
 * **Repository-level lifecycle.** "Does this service handle SIGTERM" is a
 * question about a process entry point, and an entry point is not an audit unit:
 * route units sit in routers and handlers, and a repository can hold hundreds of
 * them without one of them sitting in a `main.ts`. The `shutdown-readiness` check
 * therefore asks what a unit's own source can answer and, when it cannot, demands
 * a `not-applicable` whose note *names the entry point that was not shown*. That
 * is a disclosure in the run's own numbers — every unit asked, every one
 * unanswerable, and the file a reader should open — rather than a domain quietly
 * scoring well on a question nobody put. Closing it properly needs either a
 * `service-entrypoint` unit kind in the inventory or a deterministic phase 1
 * rule; neither is this module's to add.
 *
 * **Nothing about configuration it was not shown.** A timeout set on the client
 * a call goes through, a `statement_timeout` on the pool, a teardown in the
 * worker manager: each is a file this prompt may not carry. Every check that can
 * be defeated that way says so in its `notApplicable`, and the guidance names
 * the library defaults so a model that does judge a default states which one.
 */

import type { Domain } from "../../contracts/findings.ts";
import type { AuditUnitKind } from "../../contracts/inventory.ts";
import {
  type AuditCheck,
  type PromptBuilder,
  type PromptSpec,
  createPromptBuilder,
} from "./_shared.ts";

/** The domain every batch built from this module is attributed to. */
export const RELIABILITY_DOMAIN: Domain = "reliability";

// ---------------------------------------------------------------------------
// The check catalogue
// ---------------------------------------------------------------------------
//
// Defined once and shared between the kinds that ask them, because a check id is
// global vocabulary: `reliability.idempotency` has to mean the same thing, carry
// the same rule and publish the same assurance sentence whether a handler or a
// schedule was asked. Reusing the object makes that true by construction rather
// than by review.

/** Outbound calls: a call that can wait forever is a request that can hang forever. */
const OUTBOUND_TIMEOUT: AuditCheck = {
  name: "outbound-timeout",
  statement: "every outbound call sets a timeout",
  rule: "reliability.missing-timeout",
  question:
    "does every call that leaves this process — an HTTP request, a database query, a cloud SDK command, a cache read — carry a deadline it cannot exceed?",
  fails:
    "a call can wait indefinitely because no timeout, deadline or abort signal is set on it and none is set on the client it goes through, so one slow dependency holds this request, job or pooled connection open",
  ceiling: "medium",
  notApplicable:
    "the unit makes no call that leaves the process, or the client it calls through is configured in a file you were not shown — name that file",
};

/** Retries: the difference between recovering from a blip and finishing off a dependency. */
const RETRY_BACKOFF: AuditCheck = {
  name: "retry-backoff",
  statement: "retries are spaced by exponential backoff with jitter",
  rule: "reliability.retry-without-backoff",
  question:
    "where this code retries a failed call, is the number of attempts bounded and is each attempt spaced by a growing delay with a random component?",
  fails:
    "retries are immediate, spaced by a constant delay, or unbounded, so a dependency that is already failing is hit harder, and every instance retries in step with every other",
  ceiling: "medium",
  notApplicable: "nothing here retries, and no retry policy was declared for this unit",
};

/** Correctness under retry: the check the money depends on. */
const IDEMPOTENCY: AuditCheck = {
  name: "idempotency",
  statement: "an operation that runs twice has the effect of running once",
  subject: "state-changing operations",
  rule: "reliability.missing-idempotency-key",
  question:
    "if this operation ran a second time for the same input — a retried request, a redelivered message, an overlapping schedule — would it change anything the first run did not?",
  fails:
    "a second run can charge again, send again, insert a duplicate or apply a delta twice, and there is no idempotency key, unique constraint, conditional update, lock or state check standing in the way",
  ceiling: "high",
  notApplicable:
    "the operation only reads, or it writes a value that does not depend on the value already there",
};

/**
 * The same claim the data-layer lens makes, deliberately identical.
 *
 * Rule, statement and ceiling are D3's: this lens asks it of the code that
 * *opens* the transaction, D3 asks it of the query inside, and one defect found
 * from both sides has to arrive as one finding.
 */
const TRANSACTION_BOUNDARY: AuditCheck = {
  name: "transaction-boundary",
  statement: "transactions hold database work only",
  rule: "data.transaction-spans-io",
  question: "if this code opens a transaction, does everything inside it touch the database only?",
  fails:
    "an open transaction waits on an HTTP call, a queue publish, an email send, an upload or a long computation, holding its row locks and a pooled connection for as long as that takes",
  ceiling: "medium",
  notApplicable: "this code opens no transaction",
};

/** Error handling: the failure that is reported as a success is the expensive one. */
const ERROR_PROPAGATION: AuditCheck = {
  name: "error-propagation",
  statement: "a failed operation stops the work that depended on it",
  rule: "reliability.swallowed-error",
  question:
    "when a call in here fails, does the code stop, retry or compensate — or does it carry on as though the call had succeeded?",
  fails:
    "an empty catch, a catch that only logs, or a promise nobody awaits lets a failed write, publish or send be treated as done, so the caller, the queue or the schedule is told it worked",
  ceiling: "high",
  notApplicable:
    "the code continues deliberately and the fallback it takes is visible in the source shown",
};

/** Logging: what leaves the process in plain text and lands in a log index. */
const LOG_HYGIENE: AuditCheck = {
  name: "log-hygiene",
  statement: "logs carry identifiers rather than credentials or personal data",
  rule: "reliability.sensitive-data-in-log",
  question:
    "does everything this code writes to a log or an error reporter stay clear of credentials, tokens and personal data?",
  fails:
    "a whole request, body, job payload, entity or full URL is serialised into a log line, or a token, password, key, email address, phone number or payment detail is logged in the clear",
  ceiling: "medium",
  notApplicable: "the code shown writes nothing to a log or an error reporter",
};

/** Observability: a log nobody can join to an execution is a log nobody can use. */
const CORRELATION_ID: AuditCheck = {
  name: "correlation-id",
  statement: "log lines can be tied back to the request or job that caused them",
  rule: "reliability.missing-correlation-id",
  question:
    "can a log line this code writes be tied back to the request, job or message that caused it?",
  fails:
    "the lines carry no request id, job id, trace id or tenant, so two executions running at once cannot be told apart when one of them fails",
  ceiling: "low",
  notApplicable: "the code shown writes nothing to a log",
};

/** Caching: a key that omits the principal serves one caller's data to the next. */
const CACHE_KEY_SCOPE: AuditCheck = {
  name: "cache-key-scope",
  statement: "cache keys name the tenant or user whose data they hold",
  rule: "reliability.cache-key-missing-scope",
  question:
    "does every cache key built here include the principal whose data the entry holds — the user, the organisation, the tenant?",
  fails:
    "an entry holding per-principal data is keyed on something shared — a path, a resource id, a filter object — so the first caller's data is served to the next one",
  ceiling: "high",
  notApplicable:
    "nothing here reads or writes a cache, or the entry holds data that is the same for every caller",
};

/** Caching: an entry with no expiry outlives the fact it recorded. */
const CACHE_EXPIRY: AuditCheck = {
  name: "cache-expiry",
  statement: "cached entries expire",
  rule: "reliability.cache-without-ttl",
  question:
    "does every cache entry written here carry a time to live, and is it invalidated when the data behind it changes?",
  fails:
    "an entry is written with no expiry and no invalidation path, so stale data — a revoked permission, a deleted row — is served until somebody flushes the cache by hand",
  ceiling: "low",
  notApplicable: "nothing here writes to a cache",
};

/** Lifecycle: the question an orchestrator asks by sending SIGTERM. */
const SHUTDOWN_READINESS: AuditCheck = {
  name: "shutdown-readiness",
  statement: "long-lived processes expose a probe and shut down on signal",
  subject: "long-lived processes",
  rule: "reliability.no-graceful-shutdown",
  question:
    "if the code shown starts the server, worker or connection pool this unit runs in, does it also serve a liveness or readiness probe and close everything in order on SIGTERM?",
  fails:
    "the code starts a listener, a worker or a pool and nothing closes it on a signal, so an orchestrator's SIGTERM cuts off in-flight requests or jobs; or the process it starts serves no health or readiness probe",
  ceiling: "medium",
  notApplicable:
    "the code shown does not start or own the process — say so, and name the entry point you would have needed: the file that calls `listen`, constructs the worker, or opens the pool",
};

/** Every check this lens can ask, in report order; see the per-kind specs for who asks what. */
export const RELIABILITY_CHECKS: readonly AuditCheck[] = [
  OUTBOUND_TIMEOUT,
  RETRY_BACKOFF,
  IDEMPOTENCY,
  TRANSACTION_BOUNDARY,
  ERROR_PROPAGATION,
  LOG_HYGIENE,
  CORRELATION_ID,
  CACHE_KEY_SCOPE,
  CACHE_EXPIRY,
  SHUTDOWN_READINESS,
];

// ---------------------------------------------------------------------------
// Guidance
// ---------------------------------------------------------------------------

/**
 * What every kind is told, because every one of these mistakes is made with a
 * library whose default decides the answer.
 *
 * Named defaults rather than patterns: `timeout` absent from an `axios.create`
 * is a finding only because axios' default is "wait forever", and an
 * `@aws-sdk/client-*` built without a `requestHandler` is a finding for the
 * socket timeout and *not* for its retries, which already back off with jitter.
 * A model that has to name the default it is judging stops reporting the ones
 * that are safe.
 */
const SHARED_GUIDANCE: readonly string[] = [
  "Say what the defect costs in terms of this process: what holds a pooled connection, what holds a row lock, what a second run charges twice, what a caller sees while a dependency is slow. A reliability finding with no stated cost is an observation, not a finding.",
  "Name the default you are judging. `axios` without `timeout` waits forever. `fetch` has no deadline without an `AbortSignal`. An `@aws-sdk/client-*` built without a `requestHandler` has no socket timeout, while its own retry policy already defaults to three attempts with exponential backoff and jitter — so on an AWS client the timeout is the finding and the retries usually are not. A `pg`/TypeORM pool with no `statement_timeout` lets one query hold a connection indefinitely.",
  "`axios-retry` with no `retryDelay` retries immediately, and a `retryDelay` that ignores the retry-count argument it is handed is a constant delay, not a backoff. Both are the `retry-backoff` finding; a retry with no circuit breaker in front of it belongs in that finding's note, not in a second finding.",
  "Assume at-least-once delivery everywhere. A BullMQ job whose worker dies mid-run is recovered as *stalled* and handed to another worker whatever `attempts` says, and SQS redelivers when the visibility timeout expires — so idempotency is about what the code does, never about what the broker promises.",
  "Judge idempotency against the write, not the intention: an idempotency key, a unique constraint on the natural key, a conditional update (`UPDATE … WHERE status = 'pending'`), an advisory or row lock, or an insert that is a no-op on conflict. `balance = balance + x` and a plain `INSERT` are the two shapes that are never safe twice.",
  "A log line that happens to contain an id is not a correlation id. The id has to identify this execution and be on the lines that matter, not only on the first one.",
  "A timeout, a retry policy or a teardown that is not in the source you were shown may still exist in the client, the pool or the manager. That is a `not-applicable` whose note names the file, never a finding.",
];

/** Route handlers: the request path, where a hanging dependency is a user-visible outage. */
const ROUTE_GUIDANCE: readonly string[] = [
  "When the unit carries `handlerSource` for another file, that body is attached as the related slice above the registration. Audit the body; the registration line only declares the path and the middleware.",
  "Do not report a stack trace, a driver message or SQL reaching the caller here — that is the route lens's `api.error-leaks-internals`. This lens asks only whether the handler carried on after something failed.",
  "`mutates: true` with money, mail or an external side effect is where `idempotency` earns its ceiling: a retried POST that charges twice is a high finding, and a retried POST that writes the same row twice is the same rule with a smaller cost. Say which one it is.",
  "`shutdown-readiness` is asked here because a router or bootstrap file sometimes starts the server itself. When this one does not, answer `not-applicable` and name the entry point — that note is how the report discloses that the service's lifecycle was never assessed.",
];

/** Data-access call sites: the deadline is usually on the pool, not on the call. */
const DATA_ACCESS_GUIDANCE: readonly string[] = [
  "A query's deadline normally sits on the pool or the statement rather than the call site. Without the connection options in front of you, `outbound-timeout` is `not-applicable` and the note names the file that builds the data source.",
  "The transaction boundary is not asked again here: the data-layer lens already asks it of this call site. `insideTransaction` is stated so you can judge what else is happening inside that transaction, not so you can re-file it.",
  "A read-through cache usually wraps a query in the same function. The key is the thing to look at: `filtersByPrincipal` tells you the query is scoped, and a cache key that is not scoped the same way undoes it.",
  "An `update` or `delete` whose predicate is only an id, run from a retryable path, is the `idempotency` question. An `update` that writes an absolute value is safe twice; one that writes a delta is not.",
];

/** Queue consumers: D5 already asked most of this; say what it did not. */
const QUEUE_CONSUMER_GUIDANCE: readonly string[] = [
  "The D5 consumer lens already asks this consumer about idempotency, retries, dead-lettering, concurrency and swallowed failures. Do not answer those questions again. This lens asks what it does not: what the handler does inside a transaction, what reaches the log, and whether the worker stops cleanly.",
  "A consumer unit is anchored where the worker is *constructed*, which is why `symbol` is often `constructor`. The handler itself may be another method of the same class — `processJob`, `handleMessage` — and outside your slice. When a question needs that method, answer `not-applicable` and name it; never infer what a handler does from the queue's name.",
  "A worker's teardown is usually in the manager that constructs it — a `stopWorkers`, a `worker.close()`, a signal handler in the entry point. If the slice does not show it, `shutdown-readiness` is `not-applicable` and the note names the file.",
  "`concurrency` and `timeout` are recorded here as facts: a handler that logs a whole job payload at 50-way concurrency is a logging finding whose cost you can state exactly.",
  "A job id in a log line is the correlation id for a consumer. A handler that logs the payload but not the job id fails both logging checks for different reasons; keep them apart.",
];

/** Scheduled work: two runs, one row, and nobody watching. */
const CRON_GUIDANCE: readonly string[] = [
  "Whether two runs of the schedule can overlap at all is the D5 lens's lock question. This lens asks what happens to the *write* when they do: a dedupe key, a conditional update or a claim makes the overlap harmless, and nothing makes it a duplicate.",
  "A schedule that fans out over rows is the place an unbounded outbound call hurts most: one missing timeout multiplies by the batch size. Say what the batch size is, or where it comes from.",
  "A scheduled job has no caller to return an error to, so a swallowed failure here is invisible by construction. `failure-alerting` is D5's question about being told; this is the question about whether the run continued as if nothing happened.",
];

/** Serverless functions: their own limits are D5's; the calls they make are this lens's. */
const SERVERLESS_GUIDANCE: readonly string[] = [
  "The D5 lens judges the function's own timeout, memory and concurrency. This lens judges the timeouts on the calls the function *makes*: a 30-second function whose HTTP call has no deadline is killed by the platform mid-write, which is exactly the state the `idempotency` question is about.",
  "A platform retry is a redelivery. An asynchronously invoked function is retried by the platform whatever the code says, so a handler that writes without a dedupe key fails `idempotency` even with no retry logic of its own.",
  "A function whose code you were not shown can still be judged on its declaration: answer what the facts settle and mark the code-level checks `not-applicable`.",
];

// ---------------------------------------------------------------------------
// How to read each kind's facts
// ---------------------------------------------------------------------------

/** Route facts this lens leans on, as the route enumerator records them. */
const ROUTE_ATTRIBUTES: Readonly<Record<string, string>> = {
  method: "HTTP method, upper-case; `ANY` when the registration covers every method",
  path: "the resolved request path, or `unresolved` when Sentinel could not compose it",
  framework: "which framework registered it, as detected in phase 0",
  mutates: "`true` when the method or the body changes state — the idempotency question's trigger",
  middleware: "the middleware chain on the registration, when Sentinel could read it",
  pagination: "`limit`, `cursor` or `none`",
  handlerSymbol: "the exported function or method that is the handler",
  handlerSource:
    "`file:start-end` of that handler's body; when it is another file, that body is attached to this unit as related code",
};

/** Data-access facts this lens leans on, as the ORM extractor records them. */
const DATA_ACCESS_ATTRIBUTES: Readonly<Record<string, string>> = {
  orm: "which data layer the call belongs to, as detected in phase 0",
  operation: "what the call does: a read, a write, a delete, a raw statement",
  table: "the table or model the call resolves to",
  insideTransaction: "`true` when the call is inside a transaction block",
  insideLoop: "the kind of loop the call sits in, or absent when it sits in none",
  awaitedSequentially: "`true` when another independent query is awaited next to it",
  filtersByPrincipal:
    "`true` when the predicate names a principal (user id, org id, tenant) — compare a cache key against it",
  whereColumns: "the columns the predicate names",
  enclosingSymbol: "the function the call sits in",
};

/** Consumer facts this lens leans on, as the async enumerator records them. */
const QUEUE_CONSUMER_ATTRIBUTES: Readonly<Record<string, string>> = {
  library: "the queue library the consumer is built on",
  queue: "the queue, topic or event name it reads",
  concurrency: "declared concurrency, or `unset` for the library's default",
  attempts: "declared maximum attempts, or `unset`",
  backoff: "declared backoff, or `none`",
  idempotencyKey: "`none` when Sentinel found nothing to deduplicate on",
  dlq: "the dead-letter target, or `none`",
  timeout: "the declared job or visibility timeout, or `unset`",
  symbol: "the handler function",
};

/** Schedule facts this lens leans on, as the async enumerator records them. */
const CRON_ATTRIBUTES: Readonly<Record<string, string>> = {
  schedule: "the cron expression, exactly as written",
  library: "what schedules it: a platform, `node-cron`, a workflow",
  path: "the endpoint it calls, when it calls one",
  targetUnitId: "the id of the route unit it hits, when Sentinel could join them",
  trigger: "`schedule`",
};

/** Function facts this lens leans on, as the manifest reader recorded them. */
const SERVERLESS_ATTRIBUTES: Readonly<Record<string, string>> = {
  platform: "where it runs: `aws-lambda`, `vercel-edge`, `cloudflare-workers`…",
  trigger: "what invokes it: `http`, `queue`, `schedule`, `storage`, `stream`, `event`, `unknown`",
  timeout: "the function's own declared timeout — the ceiling every call it makes shares",
  memory: "declared memory",
  concurrency: "declared concurrency, or `unset`",
  dlq: "the dead-letter target, or `none`",
  handler: "the entry point, as declared",
  declaredBy: "the manifest or construct that declares it",
};

// ---------------------------------------------------------------------------
// The specs
// ---------------------------------------------------------------------------

/** The D7 questions asked of a route handler. */
export const RELIABILITY_ROUTE_PROMPT: PromptSpec = {
  kind: "route",
  noun: "route handler",
  mission:
    "You decide whether each request path survives a slow dependency, a retry and a failure: timeouts on what it calls, a safe second run, a transaction that holds only database work, and a failure that is neither swallowed nor logged in plain text.",
  checks: [
    OUTBOUND_TIMEOUT,
    RETRY_BACKOFF,
    IDEMPOTENCY,
    TRANSACTION_BOUNDARY,
    ERROR_PROPAGATION,
    LOG_HYGIENE,
    CORRELATION_ID,
    CACHE_KEY_SCOPE,
    SHUTDOWN_READINESS,
  ],
  attributes: ROUTE_ATTRIBUTES,
  guidance: [...SHARED_GUIDANCE, ...ROUTE_GUIDANCE],
};

/** The D7 questions asked of a data-access call site. */
export const RELIABILITY_DATA_ACCESS_PROMPT: PromptSpec = {
  kind: "data-access",
  noun: "data-access call site",
  mission:
    "You decide whether each call site is bounded in time, safe to repeat, and cached under a key that belongs to the caller it was read for.",
  checks: [
    OUTBOUND_TIMEOUT,
    RETRY_BACKOFF,
    IDEMPOTENCY,
    ERROR_PROPAGATION,
    CACHE_KEY_SCOPE,
    CACHE_EXPIRY,
  ],
  attributes: DATA_ACCESS_ATTRIBUTES,
  guidance: [...SHARED_GUIDANCE, ...DATA_ACCESS_GUIDANCE],
};

/** The D7 questions asked of a queue consumer, excluding the ones D5 already asks. */
export const RELIABILITY_QUEUE_CONSUMER_PROMPT: PromptSpec = {
  kind: "queue-consumer",
  noun: "queue consumer",
  mission:
    "You decide what each background handler holds open while it waits, what it writes to the log, and whether the worker it runs in can be stopped without losing the job in flight.",
  checks: [TRANSACTION_BOUNDARY, LOG_HYGIENE, CORRELATION_ID, CACHE_KEY_SCOPE, SHUTDOWN_READINESS],
  attributes: QUEUE_CONSUMER_ATTRIBUTES,
  guidance: [...SHARED_GUIDANCE, ...QUEUE_CONSUMER_GUIDANCE],
};

/** The D7 questions asked of scheduled work. */
export const RELIABILITY_CRON_PROMPT: PromptSpec = {
  kind: "cron",
  noun: "scheduled job",
  mission:
    "You decide whether a run that overlaps, retries or fails halfway leaves the data it touched in the state one clean run would have left it in.",
  checks: [
    OUTBOUND_TIMEOUT,
    RETRY_BACKOFF,
    IDEMPOTENCY,
    TRANSACTION_BOUNDARY,
    ERROR_PROPAGATION,
    LOG_HYGIENE,
  ],
  attributes: CRON_ATTRIBUTES,
  guidance: [...SHARED_GUIDANCE, ...CRON_GUIDANCE],
};

/** The D7 questions asked of a serverless function. */
export const RELIABILITY_SERVERLESS_PROMPT: PromptSpec = {
  kind: "serverless-function",
  noun: "serverless function",
  mission:
    "You decide whether each function's own calls are bounded in time, whether a platform retry is safe, and what the function leaves behind when it is killed at its timeout.",
  checks: [
    OUTBOUND_TIMEOUT,
    RETRY_BACKOFF,
    IDEMPOTENCY,
    TRANSACTION_BOUNDARY,
    ERROR_PROPAGATION,
    LOG_HYGIENE,
    CORRELATION_ID,
    CACHE_KEY_SCOPE,
  ],
  attributes: SERVERLESS_ATTRIBUTES,
  guidance: [...SHARED_GUIDANCE, ...SERVERLESS_GUIDANCE],
};

/** The D7 route-handler prompt builder. */
export const reliabilityRoutePromptBuilder = createPromptBuilder(RELIABILITY_ROUTE_PROMPT);

/** The D7 data-access prompt builder. */
export const reliabilityDataAccessPromptBuilder = createPromptBuilder(
  RELIABILITY_DATA_ACCESS_PROMPT,
);

/** The D7 queue-consumer prompt builder. */
export const reliabilityQueueConsumerPromptBuilder = createPromptBuilder(
  RELIABILITY_QUEUE_CONSUMER_PROMPT,
);

/** The D7 scheduled-work prompt builder. */
export const reliabilityCronPromptBuilder = createPromptBuilder(RELIABILITY_CRON_PROMPT);

/** The D7 serverless-function prompt builder. */
export const reliabilityServerlessPromptBuilder = createPromptBuilder(
  RELIABILITY_SERVERLESS_PROMPT,
);

// ---------------------------------------------------------------------------
// The lens registry
// ---------------------------------------------------------------------------

/**
 * The kinds this lens audits, mapped to their prompt.
 *
 * One row per entry is what `./index.ts` needs: `{ kind, domain:
 * RELIABILITY_DOMAIN, builder }`. Deliberately *not* a second lookup layer —
 * once a row is registered, `promptFor(kind, "reliability")`,
 * `checksFor(kind, "reliability")` and `rulesFor(kind, "reliability")` are the
 * answers, and a parallel set of accessors here would be a second source of
 * truth for the decoder to disagree with.
 *
 * Registration is additive, not a replacement: a `route` is audited by
 * `routePromptBuilder` under `appsec` *and* by `reliabilityRoutePromptBuilder`
 * under `reliability`, as two batch series over the same units.
 */
export const RELIABILITY_BUILDERS: Readonly<Partial<Record<AuditUnitKind, PromptBuilder>>> = {
  route: reliabilityRoutePromptBuilder,
  "data-access": reliabilityDataAccessPromptBuilder,
  "serverless-function": reliabilityServerlessPromptBuilder,
  "queue-consumer": reliabilityQueueConsumerPromptBuilder,
  cron: reliabilityCronPromptBuilder,
};

/** The kinds the D7 lens audits, in the contract's kind order. */
export const RELIABILITY_KINDS: readonly AuditUnitKind[] = [
  "route",
  "data-access",
  "serverless-function",
  "queue-consumer",
  "cron",
];

/** The D7 prompt for a kind, or `undefined` when this lens does not audit it. */
export function reliabilityPromptFor(kind: AuditUnitKind): PromptBuilder | undefined {
  return RELIABILITY_BUILDERS[kind];
}

/** The D7 checks a kind is asked, in the order its prompt lists them. */
export function reliabilityChecksFor(kind: AuditUnitKind): readonly AuditCheck[] {
  return RELIABILITY_BUILDERS[kind]?.spec.checks ?? [];
}

/**
 * Why the other six unit kinds have no D7 row, in this module's own words.
 *
 * The registry can only state a gap for a `(kind, domain)` pair somebody
 * declared, so a kind with no row at all would be an undocumented decision.
 * These are those decisions, written to be quoted verbatim in a `pending:` row
 * if a later run decides one of them was wrong.
 */
export const RELIABILITY_OUT_OF_SCOPE: Readonly<Partial<Record<AuditUnitKind, string>>> = {
  webhook:
    "the webhook prompt already asks a receiver D7's questions: response discipline, duplicate delivery, and the timeout on the work it does inline",
  migration:
    "a migration runs once, under supervision, outside any request path: its reliability questions are D3's locking, ordering and rollback checks",
  "role-gate":
    "a client-side role gate makes no outbound call, holds no transaction and writes no log a server can read",
  sink: "an unsafe-input sink is a single expression; the reliability of the code around it is judged on the route or call site that contains it",
  "workflow-job":
    "a CI workflow job runs no application code: its timeouts, concurrency and secret handling are the delivery lens's questions, not this one's",
  container:
    "a container definition declares a process rather than running one; its health check and stop signal are D4's, and phase 1 decides them deterministically",
};

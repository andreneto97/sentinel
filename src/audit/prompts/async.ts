/**
 * The D5 prompts: serverless functions, queue consumers, scheduled work and
 * webhook receivers.
 *
 * Everything that runs outside a request/response cycle, which is where a
 * backend audit usually stops looking. Four kinds, four builders, because the
 * questions really are different: a Lambda is asked about its IAM role and its
 * trigger, a consumer about idempotency and retries, a cron about the shared
 * secret on the endpoint it calls, a webhook about signature verification over
 * the raw body.
 *
 * What they share is where the facts come from. A serverless function's memory,
 * timeout, runtime and trigger were read out of a manifest, not guessed from
 * code, and the prompt says so — the model's job is to judge them, not to
 * re-derive them. A cron that calls an HTTP endpoint carries the id of the route
 * unit it hits, and `src/audit/batch.ts` attaches that handler's source, so
 * "reachable without a shared secret" is decided against the handler rather than
 * assumed from the path.
 */

import { type AuditCheck, type PromptSpec, createPromptBuilder } from "./_shared.ts";

// ---------------------------------------------------------------------------
// Serverless functions
// ---------------------------------------------------------------------------

/** The D5 questions asked of every serverless function. */
export const SERVERLESS_CHECKS: readonly AuditCheck[] = [
  {
    name: "trigger-authentication",
    statement: "every trigger authenticates its caller",
    rule: "serverless.unauthenticated-trigger",
    question: "can this function be invoked by anyone who knows its URL or its event source?",
    fails:
      "the function has a public URL, an open API-gateway route or an unauthenticated trigger, and neither its own code nor its declared configuration authenticates the caller",
    ceiling: "critical",
    notApplicable: "the function is only invoked by another service inside the same trust boundary",
  },
  {
    name: "least-privilege",
    statement: "function roles are scoped to the actions and resources they use",
    rule: "serverless.wildcard-iam",
    question: "is the function's role scoped to the actions and resources it actually uses?",
    fails:
      "the role grants a wildcard action or a wildcard resource, or one role is shared by functions with different jobs",
    ceiling: "high",
    notApplicable: "no role or permission information was provided for this function",
  },
  {
    name: "runtime-currency",
    statement: "functions run on a supported runtime version",
    rule: "serverless.eol-runtime",
    question: "is the declared runtime version still supported?",
    fails:
      "the runtime is past end of life, or is pinned to a version that no longer gets security fixes",
    ceiling: "high",
    notApplicable: "no runtime version was declared",
  },
  {
    name: "resource-limits",
    statement: "timeout, memory and concurrency are set deliberately",
    rule: "serverless.missing-limits",
    question:
      "are the timeout, the memory and the concurrency set to values that match what the function does?",
    fails:
      "the timeout is long enough to hold a request open on a failure, the concurrency is unbounded so the function can exhaust the database's connections, or a heavy function runs at the platform default",
    ceiling: "medium",
  },
  {
    name: "failure-handling",
    statement: "failed invocations are kept and surfaced",
    rule: "serverless.no-dlq",
    question: "when an invocation fails, is the event kept and is someone told?",
    fails: "an asynchronously invoked function has no dead-letter queue and no failure destination",
    ceiling: "medium",
    notApplicable: "the function is invoked synchronously and the caller handles the failure",
  },
  {
    name: "secret-handling",
    statement: "credentials are injected from configuration, never hardcoded",
    rule: "appsec.hardcoded-credential",
    question:
      "are the credentials this function uses injected from configuration or a secret store, rather than written in the code or the manifest?",
    fails:
      "a key, token or connection string is a literal in the code or in an `environment` block, or a default stands in for one",
    ceiling: "critical",
  },
  {
    name: "event-validation",
    statement: "event payloads are validated before they are used",
    rule: "api.missing-input-validation",
    question: "is the event payload validated before it is used?",
    fails:
      "a field of the event reaches a query, a path or a response without being parsed or narrowed",
    ceiling: "high",
    notApplicable: "the function reads nothing out of the event",
  },
];

/** How to read the facts the async enumerators attach to a serverless unit. */
const SERVERLESS_ATTRIBUTES: Readonly<Record<string, string>> = {
  platform:
    "where it runs: `aws-lambda`, `vercel-edge`, `cloudflare-workers`, `supabase-functions`…",
  declaredBy: "the manifest or construct that declares it",
  handler: "the entry point, as declared",
  trigger: "what invokes it: `http`, `queue`, `schedule`, `storage`, `stream`, `event`, `unknown`",
  authenticated: "`yes`/`no` when the declaration settles it; absent when it does not",
  publicUrl: "whether a public URL or route reaches it",
  memory: "declared memory",
  timeout: "declared timeout",
  runtimeVersion: "declared runtime",
  concurrency: "declared concurrency, or `unset`",
  dlq: "the dead-letter target, or `none`",
  iamRoleRef: "the role it assumes, or `generated-role` when the framework makes one",
};

/** The serverless-function prompt spec. */
export const SERVERLESS_PROMPT: PromptSpec = {
  kind: "serverless-function",
  noun: "serverless function",
  mission:
    "You decide who can invoke each function, what it is permitted to do once invoked, and what happens when it fails.",
  checks: SERVERLESS_CHECKS,
  attributes: SERVERLESS_ATTRIBUTES,
  guidance: [
    "The configuration facts were read out of the manifest by Sentinel. Judge them; do not re-derive them from the code.",
    "`trigger: unknown` means the declaration alone could not say what invokes the function — a CDK construct gets its event source from a separate call. Do not read it as `http`.",
    "An absent attribute means the platform's default applies. Name the default you are assuming before you report a finding about it.",
    "A function whose code you were not shown can still be audited on its declaration: answer the configuration checks and mark the code-level ones `not-applicable`.",
  ],
};

// ---------------------------------------------------------------------------
// Queue consumers
// ---------------------------------------------------------------------------

/** The D5/D7 questions asked of every queue consumer. */
export const QUEUE_CONSUMER_CHECKS: readonly AuditCheck[] = [
  {
    name: "idempotency",
    statement: "running a job twice changes nothing the first run did not",
    rule: "serverless.consumer-not-idempotent",
    question:
      "if this handler runs twice for the same message, does the second run change anything?",
    fails:
      "a retry can charge again, send again, insert a duplicate or apply a delta twice, and there is no idempotency key, no unique constraint and no state check standing in the way",
    ceiling: "critical",
    notApplicable: "the handler is a pure read, or it writes the same value whatever happens",
  },
  {
    name: "retry-policy",
    statement: "retries are bounded and backed off",
    rule: "serverless.no-retry-limit",
    question: "is the number of retries bounded, and is there a backoff between them?",
    fails:
      "the consumer retries without a maximum, or retries immediately, so a failing dependency turns into a hot loop against it",
    ceiling: "medium",
  },
  {
    name: "dead-letter",
    statement: "messages that cannot be processed are kept for inspection",
    rule: "serverless.no-dlq",
    question: "does a message that cannot be processed end up somewhere it can be inspected?",
    fails:
      "a permanently failing message is dropped, or blocks the queue, with no dead-letter target",
    ceiling: "medium",
  },
  {
    name: "concurrency-bound",
    statement: "the number of messages processed at once is bounded",
    rule: "serverless.unbounded-concurrency",
    question: "is the number of messages processed at once bounded?",
    fails:
      "concurrency is unset or unlimited while the handler holds a database connection, a lock or an external rate-limited resource",
    ceiling: "medium",
  },
  {
    name: "payload-trust",
    statement: "job payloads are validated and authorization is re-checked",
    rule: "appsec.unvalidated-queue-payload",
    question:
      "is the message payload validated, and is authorization re-checked rather than trusted from the producer?",
    fails:
      "the handler reads ids or amounts straight out of the message and acts on them, so a message a user can cause to be enqueued acts with the worker's privileges",
    ceiling: "high",
  },
  {
    name: "timeout-and-io",
    statement: "every outbound call in a handler has a timeout",
    rule: "reliability.missing-timeout",
    question: "does every outbound call in the handler have a timeout?",
    fails:
      "a fetch, a client call or a database call in the handler can hang indefinitely, holding the job and its lease",
    ceiling: "medium",
    notApplicable: "the handler makes no outbound call",
  },
  {
    name: "failure-visibility",
    statement: "handler failures reach the queue and the logs",
    rule: "reliability.swallowed-error",
    question: "when the handler fails, does the failure reach the queue and the logs?",
    fails:
      "the handler catches everything and returns success, so the message is acknowledged and the failure is invisible",
    ceiling: "high",
  },
];

/** How to read the facts the async enumerators attach to a consumer unit. */
const QUEUE_ATTRIBUTES: Readonly<Record<string, string>> = {
  library: "the queue library the consumer is built on",
  queue: "the queue, topic or event name it reads",
  trigger: "`queue` for a consumer",
  concurrency: "declared concurrency, or `unset`",
  attempts: "declared maximum attempts, or `unset`",
  backoff: "declared backoff, or `none`",
  idempotencyKey: "`none` when Sentinel found nothing to deduplicate on",
  dlq: "the dead-letter target, or `none`",
  symbol: "the handler function",
};

/** The queue-consumer prompt spec. */
export const QUEUE_CONSUMER_PROMPT: PromptSpec = {
  kind: "queue-consumer",
  noun: "queue consumer",
  mission:
    "You decide what happens when each background handler runs twice, fails, or is handed a message a user caused to be enqueued.",
  checks: QUEUE_CONSUMER_CHECKS,
  attributes: QUEUE_ATTRIBUTES,
  guidance: [
    "Assume at-least-once delivery. Every queue in use here can deliver the same message twice, so `idempotency` is about what the code does, never about what the broker promises.",
    "`idempotencyKey: none` means Sentinel found no deduplication key. A unique constraint in the schema excerpt, or a state check in the slice, is an equally good answer — look for both before failing the check.",
    "Money, email and external side effects are where a double run costs something. Say what runs twice and what it costs.",
    "An option Sentinel recorded as `unset` takes the library's default. Name the default you are judging.",
  ],
};

// ---------------------------------------------------------------------------
// Scheduled work
// ---------------------------------------------------------------------------

/** The D5 questions asked of every scheduled job. */
export const CRON_CHECKS: readonly AuditCheck[] = [
  {
    name: "trigger-secret",
    statement: "scheduled endpoints require a shared secret",
    rule: "serverless.open-cron-endpoint",
    question:
      "if this schedule invokes an HTTP endpoint, does that endpoint require a shared secret the scheduler holds?",
    fails:
      "the handler you were shown accepts the request without checking a secret header, a signature or a platform-provided credential, so anyone can trigger the job",
    ceiling: "critical",
    notApplicable:
      "the schedule invokes code directly rather than over HTTP, or no handler was provided",
  },
  {
    name: "overlap-protection",
    statement: "overlapping runs cannot process the same rows",
    rule: "serverless.cron-without-lock",
    question: "can two runs of this job overlap, and does it matter if they do?",
    fails:
      "a run can take longer than the interval and the job holds no lock, so two runs process the same rows",
    ceiling: "medium",
    notApplicable: "the work is idempotent and the job claims its rows atomically",
  },
  {
    name: "failure-alerting",
    statement: "a job that stops working raises an alert",
    rule: "serverless.cron-without-alerting",
    question: "if this job stops working, does anyone find out?",
    fails: "failures are swallowed or only logged, with no alert, no metric and no heartbeat",
    ceiling: "medium",
  },
  {
    name: "schedule-sanity",
    statement: "schedules express their intent in the right timezone",
    rule: "serverless.cron-schedule-drift",
    question: "does the schedule express what the job needs, in the timezone it needs it?",
    fails:
      "a daily job runs at a time that depends on the platform's timezone, a `*/5` schedule drives work that takes longer than five minutes, or the expression does not match the intent in the name",
    ceiling: "low",
  },
  {
    name: "work-bound",
    statement: "one run does a bounded amount of work",
    rule: "serverless.cron-unbounded-work",
    question: "is the work one run does bounded?",
    fails:
      "the job processes everything it finds with no batch size and no limit, so a backlog makes the run longer every time",
    ceiling: "medium",
  },
];

/** How to read the facts the async enumerators attach to a cron unit. */
const CRON_ATTRIBUTES: Readonly<Record<string, string>> = {
  schedule: "the cron expression, exactly as written",
  library: "what schedules it: a platform, `node-cron`, a workflow",
  path: "the endpoint it calls, when it calls one",
  targetUnitId: "the id of the route unit it hits, when Sentinel could join them",
  authenticated: "what Sentinel could prove about that endpoint's authentication",
  trigger: "`schedule`",
};

/** The scheduled-work prompt spec. */
export const CRON_PROMPT: PromptSpec = {
  kind: "cron",
  noun: "scheduled job",
  mission:
    "You decide whether each schedule can be triggered by someone other than the scheduler, whether two runs can collide, and whether a silent failure would be noticed.",
  checks: CRON_CHECKS,
  attributes: CRON_ATTRIBUTES,
  guidance: [
    "`GET /api/cron/*` left open is the classic finding in this kind. Decide it against the handler that was attached as related context, not against the path.",
    "A platform header a caller can send is not a secret. A header the platform sets and the handler compares against configuration is.",
    "When no handler was attached, the `trigger-secret` check is `not-applicable` and the note names the endpoint whose handler you would have needed.",
  ],
};

// ---------------------------------------------------------------------------
// Webhook receivers
// ---------------------------------------------------------------------------

/** The D5/D2 questions asked of every inbound webhook. */
export const WEBHOOK_CHECKS: readonly AuditCheck[] = [
  {
    name: "signature-verification",
    statement: "inbound webhooks verify their signature before acting",
    rule: "serverless.webhook-unverified",
    question: "is the request's signature verified against a secret before the payload is used?",
    fails:
      "the handler acts on the payload without verifying a signature, or verifies it after the side effect, or compares it with a non-constant-time equality",
    ceiling: "critical",
  },
  {
    name: "raw-body-integrity",
    statement: "signatures are verified over the exact bytes received",
    rule: "serverless.webhook-parsed-body",
    question: "is the signature computed over the exact bytes that were received?",
    fails:
      "the handler verifies against a re-serialised body, a parsed object or a framework-parsed JSON, so the signature no longer covers what arrived",
    ceiling: "high",
    notApplicable: "no signature is verified at all — that is the other check's finding",
  },
  {
    name: "replay-protection",
    statement: "a captured request cannot be accepted twice",
    rule: "serverless.webhook-replayable",
    question: "is a captured request prevented from being accepted twice?",
    fails:
      "there is no timestamp tolerance and no record of the event id, so a replayed request is processed again",
    ceiling: "high",
  },
  {
    name: "payload-validation",
    statement: "webhook payloads are validated before they are used",
    rule: "api.missing-input-validation",
    question: "is the payload parsed against a schema before its fields are used?",
    fails: "a field of the payload reaches a query, an amount or a path without being validated",
    ceiling: "high",
  },
  {
    name: "duplicate-delivery",
    statement: "a duplicate delivery changes nothing",
    rule: "serverless.webhook-not-idempotent",
    question:
      "if the provider delivers the same event twice, does the second delivery change state?",
    fails:
      "a duplicate delivery can duplicate a row, a charge or a notification, with no unique constraint and no event-id check",
    ceiling: "high",
  },
  {
    name: "response-discipline",
    statement: "webhooks answer promptly with an accurate status",
    rule: "reliability.webhook-response",
    question:
      "does the handler answer quickly with the right status, and do the slow parts happen out of band?",
    fails:
      "the handler does its work inline and can exceed the provider's timeout, or returns a success status for a request it did not process, or a failure status for one it did",
    ceiling: "medium",
  },
];

/** How to read the facts the async enumerators attach to a webhook unit. */
const WEBHOOK_ATTRIBUTES: Readonly<Record<string, string>> = {
  path: "the receiving path",
  method: "the HTTP method",
  provider: "the sender, when Sentinel could name it",
  library: "the SDK used to verify, when there is one",
  verification: "what Sentinel found of a signature check, or `none`",
  rawBody: "whether the handler reads the raw body",
  trigger: "`http`",
  symbol: "the handler function",
};

/** The webhook prompt spec. */
export const WEBHOOK_PROMPT: PromptSpec = {
  kind: "webhook",
  noun: "webhook receiver",
  mission:
    "You decide whether each inbound webhook proves who sent it, over the bytes that were actually sent, and whether a replay or a duplicate can move money or state.",
  checks: WEBHOOK_CHECKS,
  attributes: WEBHOOK_ATTRIBUTES,
  guidance: [
    "A webhook endpoint is public by definition. Every finding here is reachable by an unauthenticated caller, which is what the rubric's `critical` band is about — and also why the preconditions you state must be exact.",
    "Order matters: verifying the signature after the database write is not verification.",
    "In Next.js and Express, reading the raw body takes a deliberate step. If the slice shows a parsed body feeding the verifier, that is the `raw-body-integrity` finding.",
    "A shared secret compared with `===` is a timing oracle in theory and a finding in practice; name the constant-time comparison the SDK provides.",
  ],
};

/** The serverless-function prompt builder. */
export const serverlessPromptBuilder = createPromptBuilder(SERVERLESS_PROMPT);

/** The queue-consumer prompt builder. */
export const queueConsumerPromptBuilder = createPromptBuilder(QUEUE_CONSUMER_PROMPT);

/** The scheduled-work prompt builder. */
export const cronPromptBuilder = createPromptBuilder(CRON_PROMPT);

/** The webhook prompt builder. */
export const webhookPromptBuilder = createPromptBuilder(WEBHOOK_PROMPT);

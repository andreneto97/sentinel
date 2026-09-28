import { describe, expect, test } from "bun:test";
import type { AuditUnit } from "../../contracts/findings.ts";
import { DomainSchema, SeveritySchema } from "../../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, type AuditUnitKind } from "../../contracts/inventory.ts";
import type { AuditCheck, PromptContext, PromptUnit } from "./_shared.ts";
import { assemblePrompt, checkIdOf, promptChars } from "./_shared.ts";
import { CRON_PROMPT, QUEUE_CONSUMER_PROMPT, SERVERLESS_PROMPT, WEBHOOK_PROMPT } from "./async.ts";
import { DATA_ACCESS_PROMPT } from "./data-access.ts";
import { ceilingOfRule, checkById } from "./index.ts";
import { MIGRATION_PROMPT } from "./migrations.ts";
import {
  RELIABILITY_BUILDERS,
  RELIABILITY_CHECKS,
  RELIABILITY_DOMAIN,
  RELIABILITY_KINDS,
  RELIABILITY_OUT_OF_SCOPE,
  RELIABILITY_QUEUE_CONSUMER_PROMPT,
  RELIABILITY_ROUTE_PROMPT,
  reliabilityChecksFor,
  reliabilityPromptFor,
} from "./reliability.ts";
import { ROUTE_PROMPT } from "./routes.ts";

/** The check ids this lens asks of a kind, in prompt order. */
function reliabilityCheckIdsFor(kind: AuditUnitKind): string[] {
  return reliabilityChecksFor(kind).map((check) => checkIdOf(check));
}

/** The rule ids this lens offers a kind. */
function reliabilityRulesFor(kind: AuditUnitKind): string[] {
  return [...new Set(reliabilityChecksFor(kind).map((check) => check.rule))];
}

/** The highest severity this lens lets a rule carry for a kind. */
function reliabilityCeilingFor(kind: AuditUnitKind, rule: string): string | undefined {
  return reliabilityChecksFor(kind).find((check) => check.rule === rule)?.ceiling;
}

// ---------------------------------------------------------------------------
// The units this lens is exercised on
// ---------------------------------------------------------------------------
//
// An invented lending-library service, in the shape `inventory.json` takes:
// every id is `unitId(kind, file, symbol)` over the file and the symbol beside
// it, the attributes are the keys the enumerators attach, and each slice is
// rendered the way `src/inventory/slice.ts` renders one. The values are the ones
// this lens exists to read — `idempotencyKey: none`, `attempts: unset` and
// `timeout: unset` on the same consumer — because a prompt tested against facts
// no enumerator would ever produce proves nothing about the facts it will be
// handed.

/** `POST /:loanId/items/bulk-renew` — a mutating route, handler in another file. */
const RENEW_ITEMS_ROUTE: AuditUnit = {
  id: "4dba12691dd8e61a",
  kind: "route",
  label: "POST /:loanId/items/bulk-renew",
  location: { file: "apps/lending-api/src/http/v1/loans/items/router.ts", line: 9 },
  attributes: {
    authCheck: "none",
    authenticated: "no",
    framework: "express",
    handlerSource: "apps/lending-api/src/http/v1/loans/items/bulk-renew.ts:24-40",
    handlerSymbol: "bulkRenew",
    idParams: "loanId",
    method: "POST",
    mutates: "true",
    pagination: "none",
    path: "/:loanId/items/bulk-renew",
    readsBody: "false",
    trigger: "http",
    validation: "none",
  },
};

/** The registration line, as `src/inventory/slice.ts` renders it. */
const RENEW_ITEMS_SLICE = `// apps/lending-api/src/http/v1/loans/items/router.ts:9-9
9 | api.post('/bulk-renew', bulkRenew)`;

/** The handler body the batch planner attaches as related code. */
const RENEW_ITEMS_HANDLER_SLICE = `// apps/lending-api/src/http/v1/loans/items/bulk-renew.ts:24-40
24 | export default async (req: Request, res: Response, next: NextFunction) => {
25 |   try {
26 |     const service = container.resolve(LoanService)
27 |     const {
28 |       requestContext: { branchId },
29 |       body,
30 |       params: { loanId },
31 |       auth,
32 |     } = await validateRequest(bulkRenewSchema, req)
33 |
34 |     const data = await service.bulkRenewItems(loanId, branchId, body, req.requestContext, auth?.roles, req)
35 |
36 |     res.json(bulkOperationSerializer(data))
37 |   } catch (error) {
38 |     next(error)
39 |   }
40 | }`;

/** A BullMQ consumer with nothing declared: no attempts, no backoff, no DLQ, no dedupe key. */
const OVERDUE_NOTICE_CONSUMER: AuditUnit = {
  id: "8c1e2ba4506cf5dd",
  kind: "queue-consumer",
  label: "bullmq consumer this.queueName",
  location: { file: "apps/workers/src/workers/overdue-notices.worker.ts", line: 38 },
  attributes: {
    attempts: "unset",
    backoff: "unset",
    concurrency: "unset",
    dlq: "none",
    idempotencyKey: "none",
    library: "bullmq",
    queue: "this.queueName",
    symbol: "constructor",
    timeout: "unset",
  },
};

/** The worker's constructor, where the BullMQ `Worker` is built. */
const OVERDUE_NOTICE_SLICE = `// apps/workers/src/workers/overdue-notices.worker.ts:34-43
34 | constructor(noticeProcessor?: OverdueNoticeProcessor, feedClient?: CatalogFeedClient) {
35 |   super(QueueNames.OverdueNotices, config.OVERDUE_NOTICE_WORKER_CONCURRENCY, config.OVERDUE_NOTICE_WORKER_GLOBAL_CONCURRENCY)
36 |   this.metricsService = container.resolve(MetricsService)
37 |   this.processJob = this.processJob.bind(this)
38 |   this.worker = new Worker(this.queueName, this.processJob, this.workerOptions)
39 |   this.noticeProcessor =
40 |     noticeProcessor || new OverdueNoticeProcessor(new NoticeService(), new EmailNoticeDispatcher())
41 |   this.feedClient = feedClient || new CatalogFeedClient()
42 |   this.setupEventListeners()
43 | }`;

/** A second consumer in the same batch, so the footer has two ids to demand. */
const HOLD_EXPIRY_CONSUMER: AuditUnit = {
  ...OVERDUE_NOTICE_CONSUMER,
  id: "7fe98f834c667e3b",
  label: "bullmq consumer QueueNames.HoldExpiry",
  location: { file: "apps/workers/src/workers/hold-expiry.worker.ts", line: 31 },
  attributes: { ...OVERDUE_NOTICE_CONSUMER.attributes, queue: "QueueNames.HoldExpiry" },
};

/** Its constructor, where the queue name is a literal rather than a field. */
const HOLD_EXPIRY_SLICE = `// apps/workers/src/workers/hold-expiry.worker.ts:28-33
28 | constructor() {
29 |   super(QueueNames.HoldExpiry, config.HOLD_EXPIRY_WORKER_CONCURRENCY)
30 |   this.processJob = this.processJob.bind(this)
31 |   this.worker = new Worker(QueueNames.HoldExpiry, this.processJob, this.workerOptions)
32 |   this.setupEventListeners()
33 | }`;

/** A TypeORM `update` inside a progress-tracker flush, in a worker. */
const PROGRESS_FLUSH_QUERY: AuditUnit = {
  id: "1ccbbc8adb84a8f1",
  kind: "data-access",
  label: "typeorm update on unresolved",
  location: {
    file: "apps/workers/src/workers/async-jobs/handlers/catalog-export/build-progress-hooks.ts",
    line: 23,
  },
  attributes: {
    awaitedSequentially: "false",
    enclosingSymbol: "flush",
    filtersByPrincipal: "no",
    hasLimit: "n/a",
    hasProjection: "n/a",
    hasWhere: "false",
    insideLoop: "false",
    insideTransaction: "false",
    method: "update",
    operation: "update",
    orm: "typeorm",
    symbol: "flush",
    table: "unresolved",
    tableSource: "identifier",
  },
};

/** The tracker construction around that update. */
const PROGRESS_FLUSH_SLICE = `// apps/workers/src/workers/async-jobs/handlers/catalog-export/build-progress-hooks.ts:21-26
21 | const tracker = new JobProgressTracker({
22 |   jobId: context.jobId,
23 |   flush: (fields) => repository.update(context.jobId, fields),
24 |   intervalMs: config.JOB_PROGRESS_FLUSH_INTERVAL_MS,
25 |   onFlushError: (reason) => void metrics.counter('jobs.progress_flush_error', 1, { reason }),
26 | })`;

/**
 * A stack as phase 0 states one, matching the shapes above.
 *
 * Express, TypeORM over Postgres and BullMQ: the defaults this lens's guidance
 * names, so the prompt is exercised against a stack whose behaviour it claims to
 * know rather than against `UNKNOWN_STACK`.
 */
const STATED_STACK = {
  frameworks: ["express"],
  dataLayers: ["typeorm"],
  databases: ["postgresql"],
  authProviders: ["jsonwebtoken"],
  authHelpers: ["apps/lending-api/src/http/middlewares/require-session.ts"],
  hasFrontend: false,
  validatesConfig: true,
  notes: [],
} as const;

/** The context a batch of this lens is built with. */
const CONTEXT: PromptContext = {
  stack: STATED_STACK,
  shared: [],
  batchId: "reliability-route-0001",
};

/** One unit as the prompt renders it. */
function promptUnit(
  unit: AuditUnit,
  sliceText: string,
  related: readonly { label: string; unitId?: string; text: string }[] = [],
): PromptUnit {
  return { unit, sliceText, related };
}

/** Every check this lens asks, with the kind that asks it. */
function everyReliabilityCheck(): { kind: AuditUnitKind; check: AuditCheck }[] {
  return RELIABILITY_KINDS.flatMap((kind) =>
    reliabilityChecksFor(kind).map((check) => ({ kind, check })),
  );
}

describe("the D7 lens registry", () => {
  test("covers the five kinds that run code, and says why every other kind is out", () => {
    const expected: AuditUnitKind[] = [
      "cron",
      "data-access",
      "queue-consumer",
      "route",
      "serverless-function",
    ];
    expect([...RELIABILITY_KINDS].sort()).toEqual(expected.sort());
    for (const kind of AUDIT_UNIT_KINDS) {
      if (RELIABILITY_KINDS.includes(kind)) {
        expect(reliabilityPromptFor(kind)?.kind).toBe(kind);
        expect(RELIABILITY_OUT_OF_SCOPE[kind]).toBeUndefined();
        continue;
      }
      expect(reliabilityPromptFor(kind)).toBeUndefined();
      // A kind left out carries a written decision, not a silence.
      expect(RELIABILITY_OUT_OF_SCOPE[kind]?.length ?? 0).toBeGreaterThan(40);
    }
  });

  test("the registry key and the builder's own kind agree, so a batch cannot be mislabelled", () => {
    for (const [kind, builder] of Object.entries(RELIABILITY_BUILDERS)) {
      expect(builder.kind).toBe(kind as AuditUnitKind);
      expect(builder.spec.kind).toBe(kind as AuditUnitKind);
    }
  });

  test("every kind carries at least three checks and a mission", () => {
    for (const kind of RELIABILITY_KINDS) {
      const spec = reliabilityPromptFor(kind)?.spec;
      expect(spec?.checks.length ?? 0).toBeGreaterThanOrEqual(3);
      expect(spec?.mission.length ?? 0).toBeGreaterThan(40);
      expect(spec?.noun.length ?? 0).toBeGreaterThan(3);
    }
  });

  test("the domain every batch of this lens is attributed to is reliability", () => {
    expect(RELIABILITY_DOMAIN).toBe("reliability");
    expect(DomainSchema.safeParse(RELIABILITY_DOMAIN).success).toBe(true);
  });
});

describe("the check vocabulary", () => {
  test("every rule and check id names a real domain, and every ceiling a real severity", () => {
    for (const { check } of everyReliabilityCheck()) {
      const ruleDomain = check.rule.split(".")[0] ?? "";
      expect(DomainSchema.safeParse(ruleDomain).success).toBe(true);
      expect(checkIdOf(check)).toBe(`${ruleDomain}.${check.name}`);
      expect(SeveritySchema.safeParse(check.ceiling).success).toBe(true);
    }
  });

  test("check ids are unique inside a kind", () => {
    for (const kind of RELIABILITY_KINDS) {
      const ids = reliabilityCheckIdsFor(kind);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });

  test("a check asked by two kinds is the same object, so it cannot drift", () => {
    const byId = new Map<string, AuditCheck>();
    for (const { check } of everyReliabilityCheck()) {
      const id = checkIdOf(check);
      const first = byId.get(id);
      if (first === undefined) {
        byId.set(id, check);
        continue;
      }
      expect(check).toBe(first);
    }
    expect(byId.size).toBe(RELIABILITY_CHECKS.length);
  });

  test("every check has a question, a failure condition and a report-voice statement", () => {
    for (const { check } of everyReliabilityCheck()) {
      expect(check.question.length).toBeGreaterThan(20);
      expect(check.fails.length).toBeGreaterThan(20);
      expect(check.statement.length).toBeGreaterThan(15);
      // A statement is what a passing check publishes, so it reads positively.
      expect(check.statement.startsWith("no ") || !check.statement.includes("missing")).toBe(true);
    }
  });

  test("every rule a kind offers belongs to one of that kind's checks", () => {
    for (const kind of RELIABILITY_KINDS) {
      const rules = new Set(reliabilityRulesFor(kind));
      for (const check of reliabilityChecksFor(kind)) expect(rules.has(check.rule)).toBe(true);
      for (const rule of rules) {
        expect(reliabilityChecksFor(kind).some((check) => check.rule === rule)).toBe(true);
      }
    }
  });

  test("a rule carries the same ceiling everywhere this lens offers it", () => {
    for (const { kind, check } of everyReliabilityCheck()) {
      expect(reliabilityCeilingFor(kind, check.rule)).toBe(check.ceiling);
    }
    expect(reliabilityCeilingFor("route", "reliability.invented")).toBeUndefined();
    expect(reliabilityCeilingFor("migration", "reliability.missing-timeout")).toBeUndefined();
  });

  test("the rubric the report is scored on: idempotency high, timeout medium, correlation id low", () => {
    // Stated in the prompt rather than left to the model, and asserted here so a
    // future edit cannot quietly re-grade a domain.
    expect(reliabilityCeilingFor("route", "reliability.missing-idempotency-key")).toBe("high");
    expect(reliabilityCeilingFor("route", "reliability.missing-timeout")).toBe("medium");
    expect(reliabilityCeilingFor("route", "reliability.missing-correlation-id")).toBe("low");
    expect(reliabilityCeilingFor("route", "reliability.cache-key-missing-scope")).toBe("high");
    expect(reliabilityCeilingFor("route", "reliability.swallowed-error")).toBe("high");
  });

  test("a rule an existing lens already offers keeps that lens's ceiling", () => {
    // `ceilingOfRule` reads the registered lenses. A rule this lens shares with
    // one of them has to agree, or the global ceiling index would report two
    // caps for one rule. A rule that is new here is simply absent until
    // `./index.ts` registers the lens, which is why `undefined` passes.
    for (const { check } of everyReliabilityCheck()) {
      const registered = ceilingOfRule(check.rule);
      if (registered === undefined) continue;
      expect(registered).toBe(check.ceiling);
    }
    expect(ceilingOfRule("reliability.missing-timeout")).toBe("medium");
    expect(ceilingOfRule("reliability.swallowed-error")).toBe("high");
    expect(ceilingOfRule("data.transaction-spans-io")).toBe("medium");
  });

  test("the shared transaction check is D3's claim verbatim, not a paraphrase of it", () => {
    const mine = reliabilityChecksFor("route").find(
      (check) => check.name === "transaction-boundary",
    );
    const theirs = DATA_ACCESS_PROMPT.checks.find((check) => check.name === "transaction-boundary");
    expect(mine).toBeDefined();
    expect(theirs).toBeDefined();
    expect(mine?.rule).toBe(theirs?.rule);
    expect(mine?.statement).toBe(theirs?.statement);
    expect(mine?.ceiling).toBe(theirs?.ceiling);
    // Same id, so `CHECK_INDEX` holds one entry and the assurance is one population.
    expect(checkIdOf(mine as AuditCheck)).toBe(checkIdOf(theirs as AuditCheck));
    expect(checkById("data.transaction-boundary")?.rule).toBe("data.transaction-spans-io");
  });
});

describe("no kind is asked the same question twice", () => {
  /** The check ids the other lenses already ask of each kind. */
  const EXISTING: Readonly<Partial<Record<AuditUnitKind, readonly string[]>>> = {
    route: ROUTE_PROMPT.checks.map(checkIdOf),
    "data-access": DATA_ACCESS_PROMPT.checks.map(checkIdOf),
    "queue-consumer": QUEUE_CONSUMER_PROMPT.checks.map(checkIdOf),
    cron: CRON_PROMPT.checks.map(checkIdOf),
    "serverless-function": SERVERLESS_PROMPT.checks.map(checkIdOf),
    webhook: WEBHOOK_PROMPT.checks.map(checkIdOf),
    migration: MIGRATION_PROMPT.checks.map(checkIdOf),
  };

  test("a D7 check id never collides with one the same kind is already asked", () => {
    for (const kind of RELIABILITY_KINDS) {
      const existing = new Set(EXISTING[kind] ?? []);
      for (const id of reliabilityCheckIdsFor(kind)) {
        expect(existing.has(id)).toBe(false);
      }
    }
  });

  test("the consumer lens leaves D5's own questions to D5", () => {
    const ids = reliabilityCheckIdsFor("queue-consumer");
    // Idempotency, retries, dead-lettering, concurrency and swallowed failures
    // are the D5 consumer prompt's, and one defect must not be filed twice.
    expect(ids).not.toContain("serverless.idempotency");
    expect(ids).not.toContain("reliability.idempotency");
    expect(ids).not.toContain("reliability.timeout-and-io");
    expect(ids).not.toContain("reliability.outbound-timeout");
    expect(ids).not.toContain("reliability.failure-visibility");
    expect(ids).not.toContain("reliability.error-propagation");
    // What it does add.
    expect(ids).toContain("data.transaction-boundary");
    expect(ids).toContain("reliability.log-hygiene");
    expect(ids).toContain("reliability.correlation-id");
    expect(ids).toContain("reliability.shutdown-readiness");
  });

  test("the data-access lens does not re-ask the transaction boundary D3 owns there", () => {
    expect(reliabilityCheckIdsFor("data-access")).not.toContain("data.transaction-boundary");
    expect(reliabilityCheckIdsFor("data-access")).toContain("reliability.cache-expiry");
  });
});

describe("the system prompt", () => {
  test("states the closed world, the obligation, the rubric and the output contract", () => {
    for (const kind of RELIABILITY_KINDS) {
      const system = reliabilityPromptFor(kind)?.systemPrompt() ?? "";
      expect(system).toContain("no filesystem");
      expect(system).toContain("elided");
      expect(system).toContain("Return one verdict for EVERY unit id listed");
      for (const severity of SeveritySchema.options) expect(system).toContain(severity);
      expect(system).toContain("Reply with ONE JSON document");
      expect(system).toContain("not-applicable");
      expect(system).toContain("exploitability");
    }
  });

  test("offers only the rule ids its own checks use", () => {
    const system = reliabilityPromptFor("queue-consumer")?.systemPrompt() ?? "";
    for (const rule of reliabilityRulesFor("queue-consumer")) expect(system).toContain(rule);
    // A rule the consumer lens is not given cannot arrive as data.
    expect(system).not.toContain("reliability.missing-idempotency-key");
    expect(system).not.toContain("appsec.idor");
  });

  test("is constant for a kind, so the transport can cache it", () => {
    const builder = reliabilityPromptFor("route");
    expect(builder?.systemPrompt()).toBe(builder?.systemPrompt());
  });
});

describe("the user prompt, on enumerated units", () => {
  test("the header states the stack, the batch id and every check id", () => {
    const header =
      reliabilityPromptFor("route")?.header(CONTEXT, [
        promptUnit(RENEW_ITEMS_ROUTE, RENEW_ITEMS_SLICE),
      ]) ?? "";
    expect(header).toContain("BATCH reliability-route-0001");
    expect(header).toContain("framework: express");
    expect(header).toContain("data layer: typeorm");
    expect(header).toContain("SHARED CONTEXT: none was available");
    for (const id of reliabilityCheckIdsFor("route")) expect(header).toContain(`"${id}"`);
    expect(header).toContain("max severity: high");
    expect(header).toContain("axios-retry");
  });

  test("a route section carries the registration, its facts and the handler body", () => {
    const section =
      reliabilityPromptFor("route")?.section(
        promptUnit(RENEW_ITEMS_ROUTE, RENEW_ITEMS_SLICE, [
          {
            label: "the handler this route registers: bulkRenew",
            text: RENEW_ITEMS_HANDLER_SLICE,
          },
        ]),
      ) ?? "";
    expect(section).toContain("UNIT 4dba12691dd8e61a");
    expect(section).toContain("at: apps/lending-api/src/http/v1/loans/items/router.ts:9");
    expect(section).toContain("mutates: true");
    expect(section).toContain("handlerSource: apps/lending-api/src/http/v1/loans/items/bulk-renew");
    expect(section).toContain("related — the handler this route registers: bulkRenew:");
    expect(section).toContain("await service.bulkRenewItems(");
  });

  test("a consumer section carries the facts the idempotency question is read against", () => {
    const section =
      reliabilityPromptFor("queue-consumer")?.section(
        promptUnit(OVERDUE_NOTICE_CONSUMER, OVERDUE_NOTICE_SLICE),
      ) ?? "";
    expect(section).toContain("UNIT 8c1e2ba4506cf5dd");
    expect(section).toContain("idempotencyKey: none");
    expect(section).toContain("attempts: unset");
    expect(section).toContain("timeout: unset");
    expect(section).toContain("dlq: none");
    // The concurrency the constructor sets is in front of the model even though
    // the enumerator recorded `concurrency: unset` from the options object.
    expect(section).toContain("concurrency: unset");
    expect(section).toContain("config.OVERDUE_NOTICE_WORKER_CONCURRENCY");
    expect(section).toContain("new Worker(this.queueName, this.processJob, this.workerOptions)");
  });

  test("a data-access section carries the facts a cache key is compared against", () => {
    const section =
      reliabilityPromptFor("data-access")?.section(
        promptUnit(PROGRESS_FLUSH_QUERY, PROGRESS_FLUSH_SLICE),
      ) ?? "";
    expect(section).toContain("UNIT 1ccbbc8adb84a8f1");
    expect(section).toContain("filtersByPrincipal: no");
    expect(section).toContain("insideTransaction: false");
    expect(section).toContain("repository.update(context.jobId, fields)");
  });

  test("the footer demands a verdict for every unit id in the batch, by id", () => {
    const units = [
      promptUnit(OVERDUE_NOTICE_CONSUMER, OVERDUE_NOTICE_SLICE),
      promptUnit(HOLD_EXPIRY_CONSUMER, HOLD_EXPIRY_SLICE),
    ];
    const footer = reliabilityPromptFor("queue-consumer")?.footer(units) ?? "";
    expect(footer).toContain("A VERDICT IS REQUIRED FOR ALL 2 OF THESE UNIT IDS");
    expect(footer).toContain("8c1e2ba4506cf5dd");
    expect(footer).toContain("7fe98f834c667e3b");
    expect(footer).toContain(
      `${RELIABILITY_QUEUE_CONSUMER_PROMPT.checks.length} checks for every id`,
    );
  });

  test("the assembled prompt is exactly its parts, so a packed batch is measured not estimated", () => {
    const builder = reliabilityPromptFor("route");
    if (builder === undefined) throw new Error("the route lens must be registered");
    const units = [
      promptUnit(RENEW_ITEMS_ROUTE, RENEW_ITEMS_SLICE, [
        {
          label: "the handler this route registers: bulkRenew",
          text: RENEW_ITEMS_HANDLER_SLICE,
        },
      ]),
    ];
    const parts = {
      systemPrompt: builder.systemPrompt(),
      header: builder.header(CONTEXT, units),
      sections: units.map((entry) => builder.section(entry)),
      footer: builder.footer(units),
    };
    const assembled = assemblePrompt(parts);
    expect(assembled.startsWith(parts.header)).toBe(true);
    expect(assembled.endsWith(parts.footer)).toBe(true);
    for (const section of parts.sections) expect(assembled).toContain(section);
    expect(promptChars(parts)).toBe(parts.systemPrompt.length + assembled.length);
  });
});

describe("the guidance names the defaults it judges", () => {
  test("every kind is told what the libraries in this stack do when nothing is set", () => {
    for (const kind of RELIABILITY_KINDS) {
      const guidance = (reliabilityPromptFor(kind)?.spec.guidance ?? []).join("\n");
      expect(guidance).toContain("axios");
      expect(guidance).toContain("@aws-sdk/client-");
      expect(guidance).toContain("BullMQ");
      expect(guidance).toContain("statement_timeout");
    }
  });

  test("the route lens is told not to re-file the error-leak finding the D2 lens owns", () => {
    const guidance = RELIABILITY_ROUTE_PROMPT.guidance.join("\n");
    expect(guidance).toContain("api.error-leaks-internals");
    // And it is told what to do with the lifecycle question a handler cannot answer.
    expect(guidance).toContain("not-applicable");
    expect(guidance).toContain("entry point");
  });

  test("the lifecycle check demands the file it would have needed", () => {
    const check = reliabilityChecksFor("route").find(
      (candidate) => candidate.name === "shutdown-readiness",
    );
    expect(check?.rule).toBe("reliability.no-graceful-shutdown");
    expect(check?.notApplicable).toContain("name the entry point");
    expect(check?.fails).toContain("SIGTERM");
  });
});

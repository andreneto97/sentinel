import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import type { AuditUnit } from "../contracts/findings.ts";
import { entryOf, parseYaml } from "../scan/rules/_mini-yaml.ts";
import {
  astGrepPath,
  enumerationContext,
  fixtureRepo,
  match,
  realSearch,
  stubSearch,
} from "./__fixtures__/enumeration-harness.ts";
import type { DraftUnit } from "./_unit-support.ts";
import {
  ASYNC_UNIT_ENUMERATORS,
  cronAuthCheck,
  cronEnumerator,
  idempotencyOf,
  matchesGlob,
  nextRoutePath,
  queueConsumerEnumerator,
  renderPermissions,
  samePath,
  secretsUsed,
  serverlessFunctionEnumerator,
  webhookEnumerator,
  workflowJobEnumerator,
} from "./async-units.ts";

const TARGET = fixtureRepo("async-target");

/**
 * A workspace laid out as `apps/` plus `libs/`, holding one of every shape that
 * shares a webhook-shaped path without being a receiver: three authenticated CRUD
 * handlers and a router under `webhooks/`, three outbound senders (one that signs
 * and delegates, one HTTP client, one bare `fetch` to a stored URL), a `Map`-based
 * condition matcher, an OpenAPI document that describes the signature format in
 * prose, two actual receivers, and a BullMQ repeatable job. Kept apart from
 * `async-target` because that fixture's counts are asserted by the aggregator's
 * tests, and not in `FixtureName` because the harness's union is not this module's
 * to widen.
 */
const WORKSPACE_TARGET = join(import.meta.dir, "__fixtures__", "workspace-target");

/** Null when the pinned ast-grep is not installed; the rule tests then skip. */
const AST_GREP = await astGrepPath();

/** The one unit whose label matches, so a failing assertion names what it looked for. */
function unit(units: readonly DraftUnit[], label: string): DraftUnit {
  const found = units.find((candidate) => candidate.label === label);
  if (found === undefined) {
    throw new Error(`no unit labelled "${label}"; got ${units.map((u) => u.label).join(", ")}`);
  }
  return found;
}

/** A minimal audit unit, for driving the cron cross-reference without an aggregator. */
function auditUnit(partial: Partial<AuditUnit> & { id: string }): AuditUnit {
  return {
    id: partial.id,
    kind: partial.kind ?? "cron",
    label: partial.label ?? partial.id,
    location: partial.location ?? { file: "vercel.json", line: 1 },
    attributes: partial.attributes ?? {},
  };
}

describe("nextRoutePath", () => {
  test("reads both Next.js routers", () => {
    expect(nextRoutePath("app/api/cron/rotate/route.ts")).toBe("/api/cron/rotate");
    expect(nextRoutePath("src/app/api/users/[id]/route.tsx")).toBe("/api/users/[id]");
    expect(nextRoutePath("pages/api/legacy.ts")).toBe("/api/legacy");
    expect(nextRoutePath("pages/api/users/index.ts")).toBe("/api/users");
  });

  test("drops route groups and parallel routes", () => {
    expect(nextRoutePath("app/(admin)/dashboard/page.tsx")).toBe("/dashboard");
    expect(nextRoutePath("app/@modal/login/page.tsx")).toBe("/login");
  });

  test("a file that serves no route has no path", () => {
    expect(nextRoutePath("app/api/users/helpers.ts")).toBeUndefined();
    expect(nextRoutePath("src/lib/db.ts")).toBeUndefined();
  });
});

describe("samePath", () => {
  test("a dynamic segment matches a concrete one", () => {
    expect(samePath("/api/users/[id]", "/api/users/42")).toBe(true);
    expect(samePath("/api/users/:id", "/api/users/42")).toBe(true);
  });

  test("a different shape does not match", () => {
    expect(samePath("/api/users", "/api/users/42")).toBe(false);
    expect(samePath("/api/cron/rotate", "/api/cron/digest")).toBe(false);
    expect(samePath(undefined, "/api")).toBe(false);
  });
});

describe("matchesGlob", () => {
  test("matches the Vercel functions globs", () => {
    expect(matchesGlob("app/api/cron/digest/route.ts", "app/api/cron/digest/route.ts")).toBe(true);
    expect(matchesGlob("app/api/**/*.ts", "app/api/cron/digest/route.ts")).toBe(true);
    expect(matchesGlob("api/*.ts", "api/handler.ts")).toBe(true);
    expect(matchesGlob("api/*.ts", "api/nested/handler.ts")).toBe(false);
  });
});

describe("cronAuthCheck", () => {
  test("names the check a cron endpoint performs", () => {
    expect(cronAuthCheck("if (token !== process.env.CRON_SECRET) return;")).toBe("CRON_SECRET");
    expect(cronAuthCheck("const s = await getServerSession();")).toBe("session");
  });

  test("reports nothing when the endpoint checks nothing", () => {
    expect(cronAuthCheck("export async function GET() { return new Response('ok'); }")).toBeNull();
  });
});

describe("idempotencyOf", () => {
  test("names the token that deduplicates the work", () => {
    expect(idempotencyOf("queue.add('email', data, { jobId: key })")).toBe("jobId");
    expect(idempotencyOf("{ idempotencyKey: 'event.data.id' }")).toBe("idempotencyKey");
  });

  test("says so when nothing deduplicates", () => {
    expect(idempotencyOf("new Worker('email', handler, { concurrency: 5 })")).toBe("none");
  });
});

describe("workflow helpers", () => {
  test("renderPermissions reads both spellings", () => {
    const mapping = parseYaml("permissions:\n  contents: read\n  id-token: write\n").root;
    expect(renderPermissions(entryOf(mapping, "permissions")?.value ?? null)).toBe(
      "contents:read,id-token:write",
    );
    const scalar = parseYaml("permissions: write-all\n").root;
    expect(renderPermissions(entryOf(scalar, "permissions")?.value ?? null)).toBe("write-all");
    expect(renderPermissions(null)).toBeUndefined();
  });

  test("secretsUsed collects the names a range reads, sorted", () => {
    const lines = ["a: ${{ secrets.B_TOKEN }}", "b: ${{ secrets.A_TOKEN }}", "c: plain"];
    expect(secretsUsed(lines, 1, 3)).toEqual(["A_TOKEN", "B_TOKEN"]);
    expect(secretsUsed(lines, 3, 3)).toEqual([]);
  });
});

describe("serverlessFunctionEnumerator over the fixture manifests", () => {
  test("reads a Serverless Framework function with its provider defaults", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const outcome = await serverlessFunctionEnumerator.enumerate(ctx);
    expect(outcome.status).toBe("ok");

    const invoice = unit(outcome.units, "createInvoice (serverless.yml)");
    expect(invoice.attributes).toMatchObject({
      platform: "aws-lambda",
      trigger: "http",
      memory: "1024",
      timeout: "30",
      runtimeVersion: "nodejs18.x",
      concurrency: "5",
      authenticated: "yes",
      dlq: "arn:aws:sqs:eu-west-1:111122223333:invoice-dlq",
    });

    // The provider's memory, timeout, runtime and role apply where the
    // function declares none of its own.
    const payments = unit(outcome.units, "processPayments (serverless.yml)");
    expect(payments.attributes).toMatchObject({
      memory: "512",
      timeout: "10",
      runtimeVersion: "nodejs18.x",
      trigger: "queue,schedule",
      queue: "arn:aws:sqs:eu-west-1:111122223333:payments",
      dlq: "none",
      concurrency: "unset",
      iamRoleRef: "arn:aws:iam::111122223333:role/shared-lambda-role",
    });

    // An HTTP event with no authorizer is the finding this attribute exists for.
    expect(unit(outcome.units, "publicReport (serverless.yml)").attributes.authenticated).toBe(
      "no",
    );
  });

  test("reads a SAM template, including its globals and function URL", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const units = (await serverlessFunctionEnumerator.enumerate(ctx)).units;

    expect(unit(units, "ThumbnailFunction (template.yaml)").attributes).toMatchObject({
      declaredBy: "aws-sam",
      trigger: "storage",
      memory: "256",
      runtimeVersion: "nodejs16.x",
      publicUrl: "function-url",
      authenticated: "no",
    });
    expect(unit(units, "DigestFunction (template.yaml)").attributes).toMatchObject({
      trigger: "schedule",
      concurrency: "2",
      dlq: "arn:aws:sqs:eu-west-1:111122223333:digest-dlq",
    });
  });

  test("reads a Cloudflare worker and locates its entry module", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const worker = unit(
      (await serverlessFunctionEnumerator.enumerate(ctx)).units,
      "worker edge-gateway",
    );
    expect(worker.file).toBe("src/worker/index.ts");
    expect(worker.attributes).toMatchObject({
      platform: "cloudflare-workers",
      trigger: "http,schedule",
      runtimeVersion: "2024-05-02",
      schedule: "*/10 * * * *,0 6 * * 1",
    });
  });

  test("a Supabase function that opted out of JWT verification says so", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const checkout = unit(
      (await serverlessFunctionEnumerator.enumerate(ctx)).units,
      "supabase function checkout",
    );
    expect(checkout.attributes).toMatchObject({ authenticated: "no", verifyJwt: "false" });
  });

  test("a missing structural search degrades the outcome instead of hiding it", async () => {
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([], false, "ast-grep is not installed"),
    );
    const outcome = await serverlessFunctionEnumerator.enumerate(ctx);
    expect(outcome.status).toBe("degraded");
    expect(outcome.reason).toContain("ast-grep is not installed");
    // The manifests are still read: a missing tool costs code-declared units only.
    expect(outcome.units.length).toBeGreaterThan(0);
  });
});

describe("queueConsumerEnumerator", () => {
  test("reads a BullMQ worker's options and reports what it does not deduplicate", async () => {
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "bull-worker",
          file: "src/queue/email.worker.ts",
          line: 8,
          endLine: 14,
          text: 'new Worker("email", handler, { concurrency: 25, lockDuration: 30000 })',
          lists: { ARGS: ['"email"', "handler", "{ concurrency: 25, lockDuration: 30000 }"] },
        }),
      ]),
    );
    const outcome = await queueConsumerEnumerator.enumerate(ctx);
    const worker = unit(outcome.units, "bullmq consumer email");
    expect(worker.attributes).toMatchObject({
      library: "bullmq",
      queue: "email",
      concurrency: "25",
      timeout: "30000",
      idempotencyKey: "none",
      attempts: "unset",
      dlq: "none",
      symbol: "emailWorker",
    });
  });

  test("refuses a pattern in a file that does not import the library", async () => {
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "bull-worker",
          // A browser worker in a file that never imports bullmq.
          file: "src/worker/index.ts",
          line: 2,
          text: 'new Worker("/sw.js")',
          lists: { ARGS: ['"/sw.js"'] },
        }),
      ]),
    );
    expect((await queueConsumerEnumerator.enumerate(ctx)).units).toHaveLength(0);
  });
});

describe("cronEnumerator", () => {
  test("enumerates every scheduled declaration in the fixture", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const outcome = await cronEnumerator.enumerate(ctx);
    const labels = outcome.units.map((entry) => entry.label).sort();
    expect(labels).toEqual([
      "*/10 * * * * -> cloudflare worker",
      "*/15 * * * * -> /api/cron/digest",
      "0 0 * * 0 -> /api/cron/missing",
      "0 3 * * * -> /api/cron/rotate",
      "0 5 * * * -> ci.yml",
      "0 6 * * 1 -> cloudflare worker",
      "rate(5 minutes) -> processPayments",
    ]);
  });

  test("a BullMQ repeatable job is scheduled work, whatever no cron rule says", async () => {
    // A queue job with a `repeat` option, started on boot, is the one shape of
    // recurring work no cron source declares: a repository whose only schedule
    // looks like this reads as declaring none at all.
    const ctx = await enumerationContext(
      WORKSPACE_TARGET,
      stubSearch([
        match({
          ruleId: "repeatable-job",
          file: "libs/job-contracts/schedules/refresh-dock-status.job.ts",
          line: 19,
          endLine: 19,
          text: "repeat: { every: 5000, key: 'dock-status-refresh' }",
        }),
      ]),
    );
    const job = unit(
      (await cronEnumerator.enumerate(ctx)).units,
      "every 5000 -> scheduleDockStatusRefresh",
    );
    expect(job.file).toBe("libs/job-contracts/schedules/refresh-dock-status.job.ts");
    expect(job.line).toBe(19);
    expect(job.attributes).toMatchObject({
      library: "bullmq",
      schedule: "every 5000",
      repeatKey: "dock-status-refresh",
      timezone: "process default",
    });
  });

  test("a cron `pattern` is preferred over an `every` interval", async () => {
    const ctx = await enumerationContext(
      WORKSPACE_TARGET,
      stubSearch([
        match({
          ruleId: "job-scheduler",
          file: "libs/job-contracts/schedules/refresh-dock-status.job.ts",
          line: 13,
          text: "queue.upsertJobScheduler('nightly', { pattern: '0 3 * * *' })",
        }),
      ]),
    );
    const job = unit(
      (await cronEnumerator.enumerate(ctx)).units,
      "0 3 * * * -> scheduleDockStatusRefresh",
    );
    expect(job.attributes.schedule).toBe("0 3 * * *");
  });

  test("a `repeat` option outside queue code is not scheduled work", async () => {
    // The vocabulary guard: the same option name on a UI animation config.
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "repeatable-job",
          file: "src/jobs/cleanup.ts",
          line: 2,
          text: "repeat: { every: 200 }",
        }),
      ]),
    );
    const files = (await cronEnumerator.enumerate(ctx)).units.map((entry) => entry.file);
    expect(files).not.toContain("src/jobs/cleanup.ts");
  });

  test("a vercel cron carries the path it calls, for the cross-reference", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const rotate = unit(
      (await cronEnumerator.enumerate(ctx)).units,
      "0 3 * * * -> /api/cron/rotate",
    );
    expect(rotate.file).toBe("vercel.json");
    expect(rotate.attributes).toMatchObject({
      library: "vercel",
      schedule: "0 3 * * *",
      targetPath: "/api/cron/rotate",
      authenticated: "unknown",
    });
  });

  describe("cross-reference", () => {
    const crons = [
      auditUnit({
        id: "rotate",
        attributes: { targetPath: "/api/cron/rotate", authenticated: "unknown" },
      }),
      auditUnit({
        id: "digest",
        attributes: { targetPath: "/api/cron/digest", authenticated: "unknown" },
      }),
      auditUnit({
        id: "missing",
        attributes: { targetPath: "/api/cron/missing", authenticated: "unknown" },
      }),
    ];

    test("resolves the target through the file conventions when no route unit exists", async () => {
      const ctx = await enumerationContext(TARGET, stubSearch([]));
      const patches = await cronEnumerator.crossReference?.(crons, crons, ctx);

      expect(patches?.get("rotate")).toMatchObject({
        authenticated: "yes",
        authCheck: "CRON_SECRET",
        targetFile: "app/api/cron/rotate/route.ts",
      });
      // The classic finding: a cron endpoint anybody can call.
      expect(patches?.get("digest")).toMatchObject({ authenticated: "no", authCheck: "none" });
      // A path with no endpoint is "unknown", never "no" — the check did not run.
      expect(patches?.get("missing")).toMatchObject({ authenticated: "unknown" });
    });

    test("joins to a route unit when the route inventory has one", async () => {
      const ctx = await enumerationContext(TARGET, stubSearch([]));
      const route = auditUnit({
        id: "route-1",
        kind: "route",
        label: "GET /api/cron/rotate",
        location: { file: "app/api/cron/rotate/route.ts", line: 5 },
        attributes: { path: "/api/cron/rotate", method: "GET" },
      });
      const patches = await cronEnumerator.crossReference?.(crons, [...crons, route], ctx);
      expect(patches?.get("rotate")?.targetUnitId).toBe("route-1");
    });
  });
});

describe("webhookEnumerator", () => {
  test("reads what a receiver verifies, and what it does not", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const units = (await webhookEnumerator.enumerate(ctx)).units;

    expect(unit(units, "stripe webhook (/api/webhooks/stripe)").attributes).toMatchObject({
      provider: "stripe",
      signatureVerified: "yes",
      usesRawBody: "yes",
      replayProtection: "yes",
      method: "POST",
    });
    expect(unit(units, "custom webhook (/api/webhooks/legacy)").attributes).toMatchObject({
      provider: "custom",
      signatureVerified: "no",
      usesRawBody: "no",
      replayProtection: "no",
    });
  });

  test("a verification call outside a webhook-shaped path is still a receiver", async () => {
    // The path heuristic would never look at `src/jobs/cleanup.ts`; the
    // structural match for a provider's verify call is what puts it in scope.
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "stripe-webhook",
          file: "src/jobs/cleanup.ts",
          line: 5,
          text: "stripe.webhooks.constructEvent(payload, signature, secret)",
        }),
      ]),
    );
    const units = (await webhookEnumerator.enumerate(ctx)).units;
    const found = units.find((entry) => entry.file === "src/jobs/cleanup.ts");
    expect(found?.line).toBe(5);
  });

  test("`new Webhook(...)` is only believed in a file that imports svix or clerk", async () => {
    // The shape is Svix's and also every other class called `Webhook`, so the
    // import is what separates a receiver from a name collision.
    const ctx = await enumerationContext(
      TARGET,
      stubSearch([
        match({
          ruleId: "svix-webhook",
          file: "src/queue/billing.ts",
          line: 3,
          text: "new Webhook(secret)",
        }),
      ]),
    );
    const units = (await webhookEnumerator.enumerate(ctx)).units;
    expect(units.some((entry) => entry.file === "src/queue/billing.ts")).toBe(false);
  });
});

describe("webhookEnumerator over the workspace fixture's own shapes", () => {
  test("only the two receivers become units", async () => {
    const ctx = await enumerationContext(WORKSPACE_TARGET, stubSearch([]));
    const outcome = await webhookEnumerator.enumerate(ctx);
    expect(outcome.units.map((entry) => entry.file).sort()).toEqual([
      "app/api/hooks/dock-telemetry/route.ts",
      "apps/dock-api/src/http/v1/webhooks/inbound-events.ts",
    ]);

    // The CRUD handlers and the router that a path-only filter counts as
    // receivers are the route inventory's, not this enumerator's.
    const files = outcome.units.map((entry) => entry.file);
    expect(files).not.toContain("apps/dock-api/src/http/v1/webhooks/create-endpoint.ts");
    expect(files).not.toContain("apps/dock-api/src/http/v1/webhooks/routes.ts");
    expect(files).not.toContain("libs/fleet-notify/webhooks/outbound-sender.ts");
  });

  test("the run says how many were reclassified, into what, and where", async () => {
    const ctx = await enumerationContext(WORKSPACE_TARGET, stubSearch([]));
    const outcome = await webhookEnumerator.enumerate(ctx);
    const reason = outcome.reason ?? "";
    expect(reason).toContain("4 are webhook-subscription management endpoints");
    expect(reason).toContain("apps/dock-api/src/http/v1/webhooks/create-endpoint.ts:8");
    expect(reason).toContain("3 are outbound delivery code");
    expect(reason).toContain("libs/fleet-notify/webhooks/http-delivery-client.ts:14");
    expect(reason).toContain("2 are inbound receivers");
    // The OpenAPI document sits under `docs/`, so it is counted apart.
    expect(reason).toContain("1 further candidate is outside production code");
  });

  test("a receiver cites its proof and is identified by its handler", async () => {
    const ctx = await enumerationContext(WORKSPACE_TARGET, stubSearch([]));
    const units = (await webhookEnumerator.enumerate(ctx)).units;
    const stripe = unit(
      units,
      "stripe webhook (apps/dock-api/src/http/v1/webhooks/inbound-events.ts)",
    );
    expect(stripe.attributes).toMatchObject({
      provider: "stripe",
      trigger: "http",
      signatureVerified: "yes",
      verification: "constructEvent()",
      usesRawBody: "yes",
      replayProtection: "yes",
    });
    expect(stripe.note).toContain("classified as a receiver by");
    // Cited at the header read, identified by the handler above it: the symbol
    // must not be the `const event` the verification assigns to.
    expect(stripe.line).toBe(9);
    expect(stripe.symbol).toBe("webhook:stripe:inbound-events.ts");

    const partner = unit(units, "custom webhook (/api/hooks/dock-telemetry)");
    expect(partner.attributes).toMatchObject({
      method: "POST",
      path: "/api/hooks/dock-telemetry",
      signatureVerified: "no",
      verification: "none",
    });
  });

  test("a repository with no receiver says so as a fact, not as a zero", async () => {
    // `client-target` has no webhook-shaped path at all; the outcome has to be
    // `skipped` with a sentence, because `0 of 0` reads like a gap.
    const ctx = await enumerationContext(fixtureRepo("client-target"), stubSearch([]));
    const outcome = await webhookEnumerator.enumerate(ctx);
    expect(outcome.status).toBe("skipped");
    expect(outcome.units).toHaveLength(0);
    expect(outcome.reason).toContain("webhook-shaped path");
  });
});

describe("workflowJobEnumerator", () => {
  test("enumerates one unit per job, with the permissions that apply to it", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const outcome = await workflowJobEnumerator.enumerate(ctx);
    expect(outcome.units).toHaveLength(2);

    // The job declares none, so the workflow's permissions are what apply.
    expect(unit(outcome.units, "ci.yml#test").attributes).toMatchObject({
      permissions: "contents:read",
      runsOn: "ubuntu-latest",
      selfHosted: "no",
      usesSecrets: "none",
      triggers: "push,schedule",
    });
    expect(unit(outcome.units, "ci.yml#deploy").attributes).toMatchObject({
      permissions: "contents:write,id-token:write",
      runsOn: "self-hosted",
      selfHosted: "yes",
      usesSecrets: "AWS_DEPLOY_ROLE,NPM_TOKEN",
      environment: "production",
    });
  });

  test("a job's range ends where the next job starts, so the slice is the job", async () => {
    const ctx = await enumerationContext(TARGET, stubSearch([]));
    const test0 = unit((await workflowJobEnumerator.enumerate(ctx)).units, "ci.yml#test");
    expect(test0.line).toBe(13);
    expect(test0.endLine).toBe(18);
  });

  test("a repository with no workflows says so instead of reporting zero jobs", async () => {
    const ctx = await enumerationContext(fixtureRepo("client-target"), stubSearch([]));
    const outcome = await workflowJobEnumerator.enumerate(ctx);
    expect(outcome.status).toBe("skipped");
    expect(outcome.reason).toContain(".github/workflows");
  });
});

describe("the rules, against the real ast-grep", () => {
  test.skipIf(AST_GREP === null)(
    "finds the edge route, the worker and the firebase function",
    async () => {
      const ctx = await enumerationContext(TARGET, await realSearch(TARGET));
      const units = (await serverlessFunctionEnumerator.enumerate(ctx)).units;

      const edge = unit(units, "edge /api/cron/rotate");
      expect(edge.attributes).toMatchObject({ platform: "vercel-edge", runtimeVersion: "edge" });
      // `maxDuration` is read from the module, `memory` from vercel.json.
      expect(edge.attributes.timeout).toBe("60");
      expect(edge.endLine).toBeGreaterThan(edge.line);

      expect(unit(units, "notify (firebase http)").attributes).toMatchObject({
        platform: "firebase-functions",
        trigger: "http",
        memory: "1GB",
        timeout: "540",
      });
    },
  );

  test.skipIf(AST_GREP === null)("finds the queue consumers and the in-process cron", async () => {
    const ctx = await enumerationContext(TARGET, await realSearch(TARGET));
    const consumers = (await queueConsumerEnumerator.enumerate(ctx)).units;
    expect(consumers.map((entry) => entry.attributes.library).sort()).toEqual([
      "bullmq",
      "inngest",
    ]);
    expect(unit(consumers, "inngest consumer charge-customer").attributes).toMatchObject({
      attempts: "4",
      concurrency: "2",
      idempotencyKey: "idempotencyKey",
    });

    const crons = (await cronEnumerator.enumerate(ctx)).units;
    expect(unit(crons, "0 4 * * * -> scheduleCleanup").attributes).toMatchObject({
      library: "node-cron",
      schedule: "0 4 * * *",
    });
  });

  test.skipIf(AST_GREP === null)(
    "finds the recurring queue job and the two receivers in the workspace fixture",
    async () => {
      const ctx = await enumerationContext(WORKSPACE_TARGET, await realSearch(WORKSPACE_TARGET));

      // The kind-based rule is the only thing that finds a recurring queue job:
      // `repeat: { ... }` is an object property, and ast-grep's pattern syntax
      // parses a bare property as an expression and matches nothing.
      const crons = (await cronEnumerator.enumerate(ctx)).units;
      expect(crons.map((entry) => entry.label)).toEqual([
        "every 5000 -> scheduleDockStatusRefresh",
      ]);
      expect(unit(crons, "every 5000 -> scheduleDockStatusRefresh").attributes).toMatchObject({
        library: "bullmq",
        repeatKey: "dock-status-refresh",
      });

      // The provider rule promotes the receiver's citation to the verification
      // call, and the import guard keeps the ambiguous rules from firing.
      const webhooks = (await webhookEnumerator.enumerate(ctx)).units;
      const stripe = unit(
        webhooks,
        "stripe webhook (apps/dock-api/src/http/v1/webhooks/inbound-events.ts)",
      );
      expect(stripe.line).toBe(10);
      expect(stripe.attributes).toMatchObject({ library: "stripe", signatureVerified: "yes" });

      // The delivery service builds a request and signs it; nothing about it is
      // a receiver, and no rule in this enumerator claims it.
      expect(webhooks.map((entry) => entry.file)).not.toContain(
        "libs/fleet-notify/webhooks/outbound-sender.ts",
      );
    },
  );
});

describe("the enumerator registry", () => {
  test("covers every D5 kind exactly once", () => {
    const kinds = ASYNC_UNIT_ENUMERATORS.flatMap((enumerator) => [...enumerator.kinds]);
    expect(kinds.sort()).toEqual([
      "cron",
      "queue-consumer",
      "serverless-function",
      "webhook",
      "workflow-job",
    ]);
    expect(new Set(ASYNC_UNIT_ENUMERATORS.map((entry) => entry.name)).size).toBe(
      ASYNC_UNIT_ENUMERATORS.length,
    );
  });
});

import { describe, expect, test } from "bun:test";
import { isAuditedKind, unauditedReason } from "../audit/prompts/index.ts";
import type { AuditUnit } from "../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, InventoryDocumentSchema } from "../contracts/inventory.ts";
import {
  astGrepPath,
  enumerationContext,
  fixtureRepo,
  inventoryContext,
  realSearch,
  stubSearch,
} from "./__fixtures__/enumeration-harness.ts";
import type {
  AttributePatch,
  DraftUnit,
  EnumerationOutcome,
  InventoryEnumerator,
} from "./_unit-support.ts";
import { ASYNC_UNIT_ENUMERATORS } from "./async-units.ts";
import { CLIENT_SURFACE_ENUMERATORS } from "./client-surface.ts";
import {
  buildInventoryDocument,
  countByKind,
  defaultEnumerators,
  runEnumerator,
  runInventory,
  sortUnits,
} from "./inventory.ts";
import { MIGRATION_ENUMERATORS } from "./migrations.ts";

const ASYNC_TARGET = fixtureRepo("async-target");
const CLIENT_TARGET = fixtureRepo("client-target");

/** Null when the pinned ast-grep is not installed; the end-to-end tests then skip. */
const AST_GREP = await astGrepPath();

/** A draft pointing at a real line of a real fixture file. */
function draft(partial: Partial<DraftUnit> = {}): DraftUnit {
  return {
    kind: partial.kind ?? "cron",
    label: partial.label ?? "a cron",
    file: partial.file ?? "vercel.json",
    line: partial.line ?? 2,
    symbol: partial.symbol ?? "vercel-cron:/api/cron/rotate",
    attributes: partial.attributes ?? {},
    ...(partial.endLine === undefined ? {} : { endLine: partial.endLine }),
  };
}

/** An enumerator that returns exactly what a test hands it. */
function fake(
  name: string,
  outcome: EnumerationOutcome | (() => Promise<EnumerationOutcome>),
  extra: Partial<InventoryEnumerator> = {},
): InventoryEnumerator {
  return {
    name,
    kinds: extra.kinds ?? ["cron"],
    enumerate: typeof outcome === "function" ? outcome : async () => outcome,
    ...(extra.crossReference === undefined ? {} : { crossReference: extra.crossReference }),
  };
}

/** Runs the phase over a fixture with the given enumerators and nothing else. */
async function run(
  enumerators: readonly InventoryEnumerator[],
  targetDir = ASYNC_TARGET,
  options: { write?: boolean; timeoutMs?: number } = {},
) {
  const ctx = inventoryContext(targetDir, {
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  });
  const result = await runInventory(ctx, {
    enumerators,
    search: stubSearch([]),
    ...(options.write === undefined ? {} : { write: options.write }),
  });
  return { ...result, writes: ctx.fs.writes };
}

describe("runInventory", () => {
  test("validates and writes the document, and reports where", async () => {
    const { document, path, writes } = await run([
      fake("crons", { status: "ok", units: [draft()] }),
    ]);
    expect(() => InventoryDocumentSchema.parse(document)).not.toThrow();
    expect(path).toBe("/tmp/sentinel-inventory-test/inventory.json");
    expect(writes).toHaveLength(1);
    expect(JSON.parse(writes[0]?.content ?? "{}").units).toHaveLength(1);
    expect(writes[0]?.content.endsWith("\n")).toBe(true);
  });

  test("the reconstructed schema is written beside the inventory, for phase 3 to excerpt", async () => {
    const { schema, artifacts, writes } = await run(
      [...MIGRATION_ENUMERATORS],
      fixtureRepo("data-layer-target"),
    );
    // Phase 3 reads `schema-model.json` out of the run directory to build the
    // data-layer prompts' schema excerpt. Nothing else writes it, so this is
    // the assertion that keeps that excerpt from being silently always absent.
    expect(schema?.tables.length ?? 0).toBeGreaterThan(0);
    expect(artifacts.some((path) => path.endsWith("/schema-model.json"))).toBe(true);
    const written = writes.find((entry) => entry.path.endsWith("/schema-model.json"));
    expect(written).toBeDefined();
    expect(JSON.parse(written?.content ?? "{}").tables.length).toBeGreaterThan(0);
  });

  test("a run with no migration enumerator neither reconstructs nor writes a schema", async () => {
    const { schema, artifacts } = await run([fake("crons", { status: "ok", units: [draft()] })]);
    expect(schema).toBeNull();
    expect(artifacts).toEqual(["/tmp/sentinel-inventory-test/inventory.json"]);
  });

  test("writing can be turned off, which leaves no artifact behind", async () => {
    const { path, writes } = await run(
      [fake("crons", { status: "ok", units: [draft()] })],
      undefined,
      {
        write: false,
      },
    );
    expect(path).toBeNull();
    expect(writes).toHaveLength(0);
  });

  test("counts every kind, including the ones nobody enumerated", async () => {
    const { document } = await run([fake("crons", { status: "ok", units: [draft()] })]);
    expect(Object.keys(document.counts)).toEqual([...AUDIT_UNIT_KINDS]);
    expect(document.counts.cron).toBe(1);
    expect(document.counts.route).toBe(0);
  });

  test("an enumerator that found nothing still has a line, with its reason", async () => {
    const { document } = await run([
      fake("crons", { status: "skipped", units: [], reason: "no scheduled work" }),
    ]);
    expect(document.enumerators).toEqual([
      { name: "crons", status: "skipped", reason: "no scheduled work", kinds: ["cron"], units: 0 },
    ]);
  });

  test("a unit whose citation does not resolve is dropped and listed", async () => {
    const { document } = await run([
      fake("crons", {
        status: "ok",
        units: [
          draft({ file: "does-not-exist.json", symbol: "ghost" }),
          draft({ file: "vercel.json", line: 9_000, symbol: "past-the-end" }),
          draft({ file: "../../../etc/passwd", symbol: "escape" }),
        ],
      }),
    ]);
    expect(document.units).toHaveLength(0);
    expect(document.dropped.map((entry) => entry.reason.split(":")[0])).toEqual([
      "file-not-found",
      "line-out-of-range",
      "path-escape",
    ]);
    expect(document.enumerators[0]?.units).toBe(0);
  });

  test("the same unit found twice is kept once, and the duplicate says who lost", async () => {
    const { document } = await run([
      fake("first", { status: "ok", units: [draft()] }),
      fake("second", { status: "ok", units: [draft({ label: "the same cron, again" })] }),
    ]);
    expect(document.units).toHaveLength(1);
    expect(document.dropped).toHaveLength(1);
    expect(document.dropped[0]?.enumerator).toBe("second");
    expect(document.dropped[0]?.reason).toContain("already claimed");
  });

  test("an enumerator that throws costs one line, not the phase", async () => {
    const { document } = await run([
      fake("broken", async () => {
        throw new Error("the rule file is nonsense");
      }),
      fake("crons", { status: "ok", units: [draft()] }, { kinds: ["cron"] }),
    ]);
    expect(document.enumerators[0]).toMatchObject({
      status: "failed",
      reason: "the rule file is nonsense",
    });
    expect(document.units).toHaveLength(1);
  });

  test("an enumerator that hangs is given up on", async () => {
    const { document } = await run(
      [fake("slow", () => new Promise<EnumerationOutcome>(() => undefined))],
      undefined,
      { timeoutMs: 25 },
    );
    expect(document.enumerators[0]?.status).toBe("failed");
    expect(document.enumerators[0]?.reason).toContain("timed out");
  });

  test("units are stored without a snippet: phase 3 slices the real source", async () => {
    const { document } = await run([
      fake("crons", { status: "ok", units: [draft({ line: 2, endLine: 4 })] }),
    ]);
    const [unit] = document.units;
    expect(unit?.location.snippet).toBeUndefined();
    expect(unit?.location).toMatchObject({ file: "vercel.json", line: 2, endLine: 4 });
  });

  test("an id survives the unit moving down its file", async () => {
    const first = await run([fake("crons", { status: "ok", units: [draft({ line: 2 })] })]);
    const second = await run([fake("crons", { status: "ok", units: [draft({ line: 4 })] })]);
    expect(first.document.units[0]?.id).toBe(second.document.units[0]?.id ?? "");
  });

  test("attributes are key-sorted, whatever order an enumerator built them in", async () => {
    const { document } = await run([
      fake("crons", {
        status: "ok",
        units: [draft({ attributes: { schedule: "0 3 * * *", authenticated: "no", empty: "" } })],
      }),
    ]);
    expect(Object.keys(document.units[0]?.attributes ?? {})).toEqual(["authenticated", "schedule"]);
  });
});

describe("containment", () => {
  const WORKER = "src/queue/email.worker.ts";

  /** The consumer at lines 8-14 of the fixture, and the query on line 11 inside it. */
  function consumerAndQuery(): readonly InventoryEnumerator[] {
    return [
      fake(
        "queue-consumers",
        {
          status: "ok",
          units: [
            draft({
              kind: "queue-consumer",
              label: "bullmq worker email",
              file: WORKER,
              line: 8,
              endLine: 14,
              symbol: "emailWorker",
              attributes: { queue: "email" },
            }),
          ],
        },
        { kinds: ["queue-consumer"] },
      ),
      fake(
        "data-access",
        {
          status: "ok",
          units: [
            draft({
              kind: "data-access",
              label: "prisma update on outbox",
              file: WORKER,
              line: 11,
              symbol: "deliver:prisma.update:abc",
              attributes: { table: "outbox", operation: "update", orm: "prisma" },
            }),
            draft({
              kind: "data-access",
              label: "prisma select on users",
              file: WORKER,
              line: 18,
              endLine: 20,
              symbol: "deliver:prisma.select:def",
              attributes: { table: "users", operation: "select", orm: "prisma" },
            }),
          ],
        },
        { kinds: ["data-access"] },
      ),
    ];
  }

  test("a query inside a consumer leaves the document, and the one outside it does not", async () => {
    const { document } = await run(consumerAndQuery());

    expect(document.units).toHaveLength(2);
    expect(document.counts["data-access"]).toBe(1);
    expect(document.counts["queue-consumer"]).toBe(1);
    expect(document.units.find((unit) => unit.kind === "data-access")?.location.line).toBe(18);
  });

  test("the container carries what it absorbed, so the prompt still sees it", async () => {
    const { document } = await run(consumerAndQuery());
    const consumer = document.units.find((unit) => unit.kind === "queue-consumer");

    expect(consumer?.attributes.containedUnits).toBe("1");
    expect(consumer?.attributes.containedKinds).toBe("data-access:1");
    expect(consumer?.attributes.containedTables).toBe("outbox");
    expect(consumer?.attributes.containedOperations).toBe("update");
    // What the enumerator itself put there is untouched.
    expect(consumer?.attributes.queue).toBe("email");
  });

  test("both enumerators disclose their half of the accounting", async () => {
    const { document } = await run(consumerAndQuery());
    const byName = new Map(document.enumerators.map((entry) => [entry.name, entry]));

    expect(byName.get("data-access")?.reason).toContain(
      "2 data-access call sites, 1 of them inside a queue consumer that carries it",
    );
    expect(byName.get("queue-consumers")?.reason).toContain(
      "1 queue consumer carries 1 data-access call site as evidence rather than as a unit of its own",
    );
  });

  test("an enumerator's unit count is what reached the document, not what it produced", async () => {
    const { document } = await run(consumerAndQuery());
    const byName = new Map(document.enumerators.map((entry) => [entry.name, entry]));

    expect(byName.get("data-access")?.units).toBe(1);
    expect(byName.get("data-access")?.status).toBe("ok");
    expect(document.dropped).toEqual([]);
  });

  test("nothing is said about containment when nothing was contained", async () => {
    const { document } = await run([fake("crons", { status: "ok", units: [draft()] })]);
    expect(document.enumerators[0]?.reason).toBeUndefined();
  });
});

describe("cross-reference", () => {
  /** Returns a patch for every id it is given, including one it does not own. */
  function patcher(name: string, foreignId: string): InventoryEnumerator {
    return fake(
      name,
      { status: "ok", units: [draft()] },
      {
        async crossReference(own): Promise<AttributePatch> {
          const patches = new Map<string, Record<string, string | undefined>>();
          for (const unit of own) patches.set(unit.id, { authenticated: "yes" });
          patches.set(foreignId, { authenticated: "forged" });
          return patches;
        },
      },
    );
  }

  test("applies the patch to the enumerator's own units", async () => {
    const { document } = await run([patcher("crons", "not-a-real-id")]);
    expect(document.units[0]?.attributes.authenticated).toBe("yes");
  });

  test("ignores a patch for a unit the enumerator does not own", async () => {
    const other = fake("others", {
      status: "ok",
      units: [draft({ kind: "webhook", symbol: "webhook:stripe", file: "vercel.json" })],
    });
    const first = await run([other]);
    const foreignId = first.document.units[0]?.id ?? "";
    const { document } = await run([patcher("crons", foreignId), other]);
    const webhook = document.units.find((unit) => unit.kind === "webhook");
    expect(webhook?.attributes.authenticated).toBeUndefined();
  });

  test("a cross-reference that throws leaves the units as they were", async () => {
    const { document } = await run([
      fake(
        "crons",
        { status: "ok", units: [draft({ attributes: { authenticated: "unknown" } })] },
        {
          async crossReference(): Promise<AttributePatch> {
            throw new Error("the route inventory is not there");
          },
        },
      ),
    ]);
    expect(document.units[0]?.attributes.authenticated).toBe("unknown");
  });
});

describe("ordering", () => {
  test("units are sorted by kind, then file, then line", () => {
    const sorted = sortUnits([
      { id: "c", kind: "sink", label: "s", location: { file: "a.ts", line: 1 }, attributes: {} },
      { id: "b", kind: "cron", label: "b", location: { file: "b.json", line: 1 }, attributes: {} },
      { id: "a", kind: "cron", label: "a", location: { file: "a.json", line: 9 }, attributes: {} },
    ]);
    expect(sorted.map((unit) => unit.id)).toEqual(["a", "b", "c"]);
  });

  test("countByKind zeroes every kind it did not see", () => {
    const counts = countByKind([
      { id: "a", kind: "cron", label: "a", location: { file: "a", line: 1 }, attributes: {} },
    ]);
    expect(counts.cron).toBe(1);
    expect(counts.migration).toBe(0);
  });

  test("a document is built through its schema, so an invalid one cannot exist", () => {
    expect(() =>
      buildInventoryDocument({
        runId: "r",
        target: "/repo",
        units: [
          // The schema is the only thing standing between a typo and an artifact.
          {
            id: "a",
            kind: "not-a-kind",
            label: "x",
            location: { file: "a", line: 1 },
          } as unknown as AuditUnit,
        ],
        enumerators: [],
        dropped: [],
      }),
    ).toThrow();
  });
});

describe("runEnumerator", () => {
  test("a rejected enumerate becomes a failed outcome carrying the message", async () => {
    const ctx = await enumerationContext(CLIENT_TARGET, stubSearch([]));
    const outcome = await runEnumerator(
      fake("boom", async () => {
        throw new Error("nope");
      }),
      ctx,
      1_000,
    );
    expect(outcome).toEqual({ status: "failed", units: [], reason: "nope" });
  });
});

describe("the whole phase over a real repository", () => {
  test.skipIf(AST_GREP === null)("enumerates the async fixture end to end", async () => {
    const ctx = inventoryContext(ASYNC_TARGET);
    const { document } = await runInventory(ctx, {
      // Pinned to the async set: this test is about those enumerators, not
      // about whatever else the default registry has grown since.
      enumerators: ASYNC_UNIT_ENUMERATORS,
      search: await realSearch(ASYNC_TARGET),
    });

    expect(document.counts["serverless-function"]).toBe(9);
    expect(document.counts["queue-consumer"]).toBe(2);
    expect(document.counts.cron).toBe(8);
    expect(document.counts.webhook).toBe(2);
    expect(document.counts["workflow-job"]).toBe(2);
    expect(document.dropped).toHaveLength(0);
    expect(document.units).toHaveLength(23);

    // The cross-reference ran: the open cron endpoint is the one to find.
    const open = document.units.find((unit) => unit.label === "*/15 * * * * -> /api/cron/digest");
    expect(open?.attributes).toMatchObject({ authenticated: "no", authCheck: "none" });
  });

  test.skipIf(AST_GREP === null)(
    "two runs over unchanged code produce identical bytes",
    async () => {
      const first = inventoryContext(ASYNC_TARGET);
      const second = inventoryContext(ASYNC_TARGET);
      await runInventory(first, { search: await realSearch(ASYNC_TARGET) });
      await runInventory(second, { search: await realSearch(ASYNC_TARGET) });
      expect(first.fs.writes[0]?.content).toBe(second.fs.writes[0]?.content ?? "");
    },
  );

  test.skipIf(AST_GREP === null)("the client fixture reaches the same document", async () => {
    const ctx = inventoryContext(CLIENT_TARGET);
    const { document } = await runInventory(ctx, {
      enumerators: [...CLIENT_SURFACE_ENUMERATORS, ...ASYNC_UNIT_ENUMERATORS],
      search: await realSearch(CLIENT_TARGET),
    });
    expect(document.counts["role-gate"]).toBe(5);
    expect(document.counts.sink).toBe(6);
    // Nothing async lives here, and every enumerator says so in its own words.
    expect(
      document.enumerators.filter((report) => report.status === "skipped").map((r) => r.name),
    ).toEqual(["serverless-functions", "queue-consumers", "crons", "webhooks", "workflow-jobs"]);
  });
});

describe("which kinds an enumerator claims", () => {
  /**
   * `container` was the exception these two tests were written to pin: the
   * registry in `src/audit/prompts/index.ts` calls it "audited deterministically
   * in phase 1" and the coverage table is built to report an unaudited kind's
   * units as skipped with that sentence, but nothing enumerated the kind, so
   * `counts.container` was always 0, the skip path never fired, and phase 1's
   * Dockerfile findings arrived attached to no unit of audit.
   *
   * `src/inventory/containers.ts` closed it, so the exception is gone rather than
   * widened. Every kind the contract declares is now claimed, which is what makes
   * a count of 0 readable: it is a repository with none of that kind, never a kind
   * nobody looked for.
   */
  test("every unit kind is claimed by a default enumerator", () => {
    const claimed = new Set(defaultEnumerators().flatMap((enumerator) => enumerator.kinds));
    const unclaimed = AUDIT_UNIT_KINDS.filter((kind) => !claimed.has(kind));
    expect(unclaimed).toEqual([]);
  });

  test("a kind no model audits is still counted, and says why no model read it", () => {
    // The other half of the accounting. `container` is enumerated and *not* sent
    // to a model, which is a decision, not silence: its units reach the D4
    // coverage table as skipped, carrying the deterministic sentence — so the
    // number in the report is accounted for either way.
    const claimed = new Set(defaultEnumerators().flatMap((enumerator) => enumerator.kinds));
    const unit: AuditUnit = {
      id: "c1",
      kind: "container",
      label: "ops/Dockerfile",
      location: { file: "ops/Dockerfile", line: 1 },
      attributes: {},
    };
    expect(claimed.has("container")).toBe(true);
    expect(countByKind([unit]).container).toBe(1);
    expect(isAuditedKind("container")).toBe(false);
    expect(unauditedReason("container")).toContain("phase 1");
    // And no other kind may become the new silent one: a kind with no prompt has
    // to have a sentence of its own.
    for (const kind of AUDIT_UNIT_KINDS) {
      if (isAuditedKind(kind)) continue;
      expect(claimed.has(kind)).toBe(true);
      expect(unauditedReason(kind).trim()).not.toBe("");
    }
  });
});

import { describe, expect, test } from "bun:test";
import type { AuditUnit } from "../contracts/findings.ts";
import { AUDIT_UNIT_KINDS, type AuditUnitKind } from "../contracts/inventory.ts";
import {
  CONTAINED_UNIT_KINDS,
  CONTAINING_UNIT_KINDS,
  type DraftUnit,
  MAX_UNITS_PER_ENUMERATOR,
  PATH_INDEPENDENT_UNIT_KINDS,
  PRODUCTION_ONLY_UNIT_KINDS,
  attributesOf,
  brief,
  carriedNote,
  collapse,
  containUnits,
  containmentNote,
  contentSymbol,
  degraded,
  enclosingSymbol,
  enumerated,
  excludeNonProductionUnits,
  failed,
  finishOutcome,
  joinReasons,
  literalOf,
  notApplicable,
  optionOf,
  unitId,
} from "./_unit-support.ts";

describe("optionOf", () => {
  test("reads a scalar option out of an options object", () => {
    expect(optionOf("{ concurrency: 25, lockDuration: 30000 }", "concurrency")).toBe("25");
    expect(optionOf("{ concurrency: 25, lockDuration: 30000 }", "lockDuration")).toBe("30000");
  });

  test("keeps a nested object value whole", () => {
    const source = "{ attempts: 3, backoff: { type: 'exponential', delay: 1000 }, id: 'x' }";
    expect(optionOf(source, "backoff")).toBe("{ type: 'exponential', delay: 1000 }");
    expect(optionOf(source, "id")).toBe("'x'");
  });

  test("keeps an array value whole", () => {
    expect(optionOf("{ queues: ['a', 'b'], concurrency: 1 }", "queues")).toBe("['a', 'b']");
  });

  test("reads a quoted key", () => {
    expect(optionOf('{ "memory": "1GB" }', "memory")).toBe('"1GB"');
  });

  test("ignores the key when it only appears inside a string", () => {
    expect(optionOf("`SELECT timeout: 5 FROM t`", "timeout")).toBeUndefined();
  });

  test("returns undefined for an option nobody set", () => {
    expect(optionOf("{ concurrency: 1 }", "attempts")).toBeUndefined();
  });

  test("stops at the end of a multi-line declaration", () => {
    const source = "{\n  attempts: 5,\n  queue: 'email',\n}";
    expect(optionOf(source, "attempts")).toBe("5");
    expect(optionOf(source, "queue")).toBe("'email'");
  });
});

describe("literalOf", () => {
  test("unwraps every quote style", () => {
    expect(literalOf('"email"')).toBe("email");
    expect(literalOf("'email'")).toBe("email");
    expect(literalOf("`email`")).toBe("email");
  });

  test("refuses a template literal with a substitution", () => {
    expect(literalOf("`queue-${name}`")).toBeUndefined();
  });

  test("refuses an expression", () => {
    expect(literalOf("queueName")).toBeUndefined();
    expect(literalOf(undefined)).toBeUndefined();
  });
});

describe("enclosingSymbol", () => {
  const source = [
    "export function AdminPanel({ user }) {", // 1
    '  const isAdmin = user.role === "admin";', // 2
    "  return (", // 3
    "    <section>", // 4
    '      <RequireRole role="owner">', // 5
    "        <button />", // 6
    "      </RequireRole>", // 7
    "    </section>", // 8
    "  );", // 9
    "}", // 10
  ];

  test("names the declaration a cited line sits on", () => {
    expect(enclosingSymbol(source, 2)).toBe("isAdmin");
  });

  test("skips a finished statement and names the function that contains the line", () => {
    expect(enclosingSymbol(source, 5)).toBe("AdminPanel");
  });

  test("names a class", () => {
    const lines = ["export class AudioConsumer {", "  @Process()", "  async transcode() {}", "}"];
    expect(enclosingSymbol(lines, 2)).toBe("AudioConsumer");
  });

  test("names an anonymous default export", () => {
    const lines = ["export default function () {", "  el.innerHTML = body;", "}"];
    expect(enclosingSymbol(lines, 2)).toBe("default");
  });

  test("returns undefined when there is nothing to name", () => {
    expect(enclosingSymbol(["el.innerHTML = body;"], 1)).toBeUndefined();
    expect(enclosingSymbol([], 3)).toBeUndefined();
  });
});

describe("identity", () => {
  test("a unit id is stable across calls and machines", () => {
    expect(unitId("cron", "vercel.json", "vercel-cron:/api/cron/rotate")).toBe(
      unitId("cron", "vercel.json", "vercel-cron:/api/cron/rotate"),
    );
  });

  test("every component of the identity changes it", () => {
    const base = unitId("cron", "vercel.json", "a");
    expect(unitId("webhook", "vercel.json", "a")).not.toBe(base);
    expect(unitId("cron", "vercel.jsonc", "a")).not.toBe(base);
    expect(unitId("cron", "vercel.json", "b")).not.toBe(base);
  });

  test("the separator cannot be forged out of the parts", () => {
    expect(unitId("cron", "a", "b:c")).not.toBe(unitId("cron", "a:b", "c"));
  });

  test("a content symbol ignores whitespace, so reformatting keeps the id", () => {
    expect(contentSymbol("q", "new Worker(\n  'email',\n)")).toBe(
      contentSymbol("q", "new Worker( 'email', )"),
    );
  });
});

describe("attributesOf", () => {
  test("drops what could not be derived and sorts the rest", () => {
    const attributes = attributesOf({
      trigger: "http",
      memory: undefined,
      platform: "vercel-edge",
      dlq: "",
    });
    expect(Object.keys(attributes)).toEqual(["platform", "trigger"]);
  });

  test("two orders of the same facts serialise identically", () => {
    const left = attributesOf({ b: "2", a: "1" });
    const right = attributesOf({ a: "1", b: "2" });
    expect(JSON.stringify(left)).toBe(JSON.stringify(right));
  });

  test("collapses a multi-line value", () => {
    expect(attributesOf({ expression: "a\n  &&\n  b" }).expression).toBe("a && b");
  });
});

describe("text", () => {
  test("brief caps a long value", () => {
    expect(brief("x".repeat(400)).length).toBe(200);
  });

  test("collapse keeps a short value untouched", () => {
    expect(collapse("  new Worker('email')  ")).toBe("new Worker('email')");
  });
});

describe("outcomes", () => {
  test("carry the status the coverage table prints", () => {
    expect(enumerated([]).status).toBe("ok");
    expect(degraded([], "ast-grep is missing").status).toBe("degraded");
    expect(notApplicable("no workflows").status).toBe("skipped");
    expect(failed("threw").status).toBe("failed");
  });

  test("an outcome without a reason has no reason key at all", () => {
    expect("reason" in enumerated([])).toBe(false);
  });

  test("joinReasons drops the empty notes", () => {
    expect(joinReasons(["a", undefined, "", null, "b"])).toBe("a; b");
    expect(joinReasons([undefined, ""])).toBeUndefined();
  });
});

/** A draft shaped like the ones the enumerators return. */
function draft(kind: AuditUnitKind, file: string, line = 10): DraftUnit {
  return {
    kind,
    label: `${kind} in ${file}`,
    file,
    line,
    symbol: `s:${file}:${line}`,
    attributes: {},
  };
}

describe("the non-production unit policy", () => {
  test("a route or data-access unit in test code is excluded, and counted", () => {
    const units = [
      draft("route", "apps/dock-api/src/http/v1/reservations/create.test.ts"),
      draft("data-access", "apps/dock-api/src/http/v1/stations/list.test.ts"),
      draft("route", "apps/dock-api/src/http/v1/stations/list.ts"),
    ];
    const result = excludeNonProductionUnits(units);

    expect(result.kept.map((unit) => unit.file)).toEqual([
      "apps/dock-api/src/http/v1/stations/list.ts",
    ]);
    expect(result.excluded).toHaveLength(2);
    // The inventory's own vocabulary, so the coverage table does not argue with
    // itself about what a unit is called.
    expect(result.note).toContain("1 route handler and 1 data-access call site in test code");
    expect(result.note).toContain("were excluded from the audit");
  });

  test("only the three path-independent kinds are left alone wherever they live", () => {
    // A CI job, a Dockerfile and a migration are the real pipeline, the real
    // image and the real schema change whatever directory they sit in.
    expect([...PATH_INDEPENDENT_UNIT_KINDS].sort()).toEqual([
      "container",
      "migration",
      "workflow-job",
    ]);
    for (const kind of PATH_INDEPENDENT_UNIT_KINDS) {
      expect(PRODUCTION_ONLY_UNIT_KINDS).not.toContain(kind);
      const result = excludeNonProductionUnits([draft(kind, "src/api/create.test.ts")]);
      expect(result.excluded).toEqual([]);
      expect(result.note).toBeUndefined();
    }
  });

  test("every other kind is production-only, so no kind escapes the policy unnoticed", () => {
    for (const kind of AUDIT_UNIT_KINDS) {
      if (PATH_INDEPENDENT_UNIT_KINDS.includes(kind)) continue;
      expect(PRODUCTION_ONLY_UNIT_KINDS).toContain(kind);
      const result = excludeNonProductionUnits([draft(kind, "src/api/create.test.ts")]);
      expect(result.kept).toEqual([]);
      expect(result.excluded).toHaveLength(1);
      expect(result.note).toContain("in test code");
    }
  });

  test("a sink in test code is excluded before the cap, so the budget buys production code", () => {
    // Sinks are the one kind a test suite outnumbers production code in: an
    // integration suite asserts on rendered markup hundreds of times. Capping
    // before the policy runs spends the whole budget on assertions and pushes the
    // production candidates out of the inventory, so the policy runs first.
    const drafts = [
      ...Array.from({ length: 600 }, (_, index) =>
        draft("sink", "apps/dock-api/src/http/v1/receipts/list.test.ts", index + 1),
      ),
      ...Array.from({ length: 30 }, (_, index) =>
        draft("sink", "apps/dock-api/src/http/v1/receipts/handler.ts", index + 1),
      ),
    ];
    const outcome = finishOutcome(drafts, { emptyReason: "no sink was found" });

    expect(outcome.units).toHaveLength(30);
    expect(outcome.units.every((unit) => unit.file.endsWith("handler.ts"))).toBe(true);
    // Nothing was truncated, because the cap never saw the test code.
    expect(outcome.status).toBe("ok");
    expect(outcome.reason).not.toContain("stopped at");
    expect(outcome.reason).toContain("600 unsafe-input sinks in test code were excluded");
  });

  test("a production unit is never excluded, and nothing is said when nothing went", () => {
    const result = excludeNonProductionUnits([draft("route", "apps/api/src/routes/users.ts")]);
    expect(result.kept).toHaveLength(1);
    expect(result.excluded).toEqual([]);
    expect(result.note).toBeUndefined();
  });

  test("the count names every file kind it excluded, in a fixed order", () => {
    const result = excludeNonProductionUnits([
      draft("data-access", "src/db/__fixtures__/seed.ts"),
      draft("data-access", "src/db/queries.test.ts"),
      draft("data-access", "dist/db/queries.js"),
    ]);
    expect(result.excluded).toHaveLength(3);
    expect(result.note).toContain("3 data-access call sites in test, fixture and generated code");
  });

  test("the pluralisation and the thousands separator follow the count", () => {
    const many = Array.from({ length: 1842 }, (_, index) =>
      draft("data-access", `src/db/q${index}.test.ts`),
    );
    expect(excludeNonProductionUnits(many).note).toContain("1,842 data-access call sites");
    expect(excludeNonProductionUnits([draft("route", "a.test.ts")]).note).toContain(
      "1 route handler in test code was excluded",
    );
  });
});

describe("the policy is applied wherever units are returned", () => {
  const mixed = [draft("route", "src/api/users.ts"), draft("route", "src/api/users.test.ts")];

  test("enumerated() drops the test unit and discloses it in the reason", () => {
    const outcome = enumerated(mixed, "29 of 379 route(s) could not be resolved to a path");
    expect(outcome.status).toBe("ok");
    expect(outcome.units).toHaveLength(1);
    // The enumerator's own words come first; the exclusion is appended, not
    // substituted, so neither disclosure hides the other.
    expect(outcome.reason).toBe(
      "29 of 379 route(s) could not be resolved to a path; 1 route handler in test code was excluded" +
        " from the audit: nothing outside production code answers a real request, so a verdict on one" +
        " would be noise rather than coverage",
    );
    expect(outcome.excluded?.map((unit) => unit.file)).toEqual(["src/api/users.test.ts"]);
  });

  test("an exclusion never turns an ok enumerator into a degraded one", () => {
    // `degraded` means "coverage Sentinel cannot vouch for". A stated scope
    // decision is not that, and conflating them would make every repository with
    // tests look partially enumerated.
    expect(enumerated(mixed).status).toBe("ok");
    expect(degraded(mixed, "ast-grep output was truncated").status).toBe("degraded");
  });

  test("degraded() keeps its own reason and adds the count", () => {
    const outcome = degraded(mixed, "ast-grep output was truncated");
    expect(outcome.units).toHaveLength(1);
    expect(outcome.reason).toContain("ast-grep output was truncated");
    expect(outcome.reason).toContain("1 route handler in test code was excluded");
  });

  test("finishOutcome spends its unit budget on production code", () => {
    const limit = 3;
    const units = [
      draft("data-access", "src/db/a.test.ts"),
      draft("data-access", "src/db/b.test.ts"),
      ...Array.from({ length: 5 }, (_, index) => draft("data-access", `src/db/q${index}.ts`)),
    ];
    const outcome = finishOutcome(units, { emptyReason: "no data layer", limit });

    // Without the policy the two test units would have eaten two of the three
    // slots, and the report would have said "2 more were not kept" about five.
    expect(outcome.units).toHaveLength(limit);
    expect(outcome.units.every((unit) => !unit.file.endsWith(".test.ts"))).toBe(true);
    expect(outcome.status).toBe("degraded");
    expect(outcome.reason).toContain(`stopped at ${limit} units; 2 more were not kept`);
    expect(outcome.reason).toContain("2 data-access call sites in test code were excluded");
    expect(outcome.excluded).toHaveLength(2);
  });

  test("an enumerator whose every unit was excluded did not find nothing", () => {
    // `skipped` is the report's word for "there is none of this here", which
    // would be a lie: there are 2, and they are in test files.
    const outcome = finishOutcome(
      [draft("route", "src/api/a.test.ts"), draft("route", "src/api/b.test.ts")],
      { emptyReason: "the repository declares no route" },
    );
    expect(outcome.status).toBe("ok");
    expect(outcome.units).toEqual([]);
    expect(outcome.reason).toContain("2 route handlers in test code were excluded");
    expect(outcome.reason).not.toContain("the repository declares no route");
  });

  test("an enumerator that really found nothing still says so", () => {
    const outcome = finishOutcome([], { emptyReason: "the repository declares no route" });
    expect(outcome.status).toBe("skipped");
    expect(outcome.reason).toBe("the repository declares no route");
  });

  test("the count is not reported twice when finishOutcome hands units on", () => {
    const outcome = finishOutcome(mixed, { emptyReason: "none" });
    expect(outcome.reason?.match(/were excluded/g) ?? []).toHaveLength(0);
    expect(outcome.reason?.match(/was excluded/g)).toHaveLength(1);
    expect(MAX_UNITS_PER_ENUMERATOR).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

/** An audit unit as the aggregator has it: identified, verified, located. */
function unit(
  kind: AuditUnitKind,
  line: number,
  endLine?: number,
  extra: { id?: string; file?: string; attributes?: Record<string, string> } = {},
): AuditUnit {
  return {
    id: extra.id ?? `${kind}@${extra.file ?? "src/a.ts"}:${line}`,
    kind,
    label: `${kind} at ${line}`,
    location: {
      file: extra.file ?? "src/a.ts",
      line,
      ...(endLine === undefined ? {} : { endLine }),
    },
    attributes: extra.attributes ?? {},
  };
}

describe("containUnits", () => {
  test("the two kind sets do not overlap, so containment cannot cascade", () => {
    for (const kind of CONTAINING_UNIT_KINDS) {
      expect(CONTAINED_UNIT_KINDS).not.toContain(kind);
    }
    for (const kind of [...CONTAINING_UNIT_KINDS, ...CONTAINED_UNIT_KINDS]) {
      expect(AUDIT_UNIT_KINDS).toContain(kind);
    }
  });

  test("a query inside a migration is the migration's evidence, not a unit", () => {
    const migration = unit("migration", 1, 40);
    const query = unit("data-access", 12, 14);
    const result = containUnits([migration, query]);

    expect(result.units.map((one) => one.kind)).toEqual(["migration"]);
    expect(result.contained).toEqual([
      { containerId: migration.id, containerKind: "migration", unit: query },
    ]);
    expect(result.units[0]?.attributes.containedUnits).toBe("1");
    expect(result.units[0]?.attributes.containedKinds).toBe("data-access:1");
  });

  test("a query nothing encloses stays a unit, because something has to carry it", () => {
    const query = unit("data-access", 12, 14, { file: "src/service.ts" });
    const elsewhere = unit("migration", 1, 40, { file: "src/other.ts" });
    const result = containUnits([elsewhere, query]);

    expect(result.units.map((one) => one.id)).toEqual([elsewhere.id, query.id]);
    expect(result.contained).toEqual([]);
    expect(result.units[0]?.attributes.containedUnits).toBeUndefined();
  });

  test("a container is never absorbed by another container", () => {
    const route = unit("route", 1, 60);
    const webhook = unit("webhook", 10, 30);
    const result = containUnits([route, webhook]);

    expect(result.units.map((one) => one.kind).sort()).toEqual(["route", "webhook"]);
    expect(result.contained).toEqual([]);
  });

  test("the tightest container wins: a query in a webhook inside a route belongs to the webhook", () => {
    const route = unit("route", 1, 60);
    const webhook = unit("webhook", 10, 30);
    const query = unit("data-access", 15, 16);
    const result = containUnits([route, webhook, query]);

    expect(result.contained.map((one) => one.containerKind)).toEqual(["webhook"]);
    const carrier = result.units.find((one) => one.kind === "webhook");
    expect(carrier?.attributes.containedUnits).toBe("1");
    expect(result.units.find((one) => one.kind === "route")?.attributes.containedUnits).toBe(
      undefined,
    );
  });

  test("a container with no endLine carries only what sits on its own line", () => {
    const route = unit("route", 12);
    const sameLine = unit("data-access", 12, undefined, { id: "same" });
    const nextLine = unit("data-access", 13, undefined, { id: "next" });
    const result = containUnits([route, sameLine, nextLine]);

    expect(result.contained.map((one) => one.unit.id)).toEqual(["same"]);
    expect(result.units.map((one) => one.id)).toEqual([route.id, "next"]);
  });

  test("a unit that overruns the container's last line is not inside it", () => {
    const route = unit("route", 10, 20);
    const query = unit("data-access", 18, 25);
    expect(containUnits([route, query]).contained).toEqual([]);
  });

  test("the same file in another package is another file", () => {
    const migration = unit("migration", 1, 40, { file: "libs/a/m.ts" });
    const query = unit("data-access", 12, undefined, { file: "libs/b/m.ts" });
    expect(containUnits([migration, query]).contained).toEqual([]);
  });

  test("the container carries the tables, operations and sink types it absorbed", () => {
    const route = unit("route", 1, 50);
    const result = containUnits([
      route,
      unit("data-access", 10, undefined, {
        id: "q1",
        attributes: { table: "users", operation: "select", orm: "prisma" },
      }),
      unit("data-access", 20, undefined, {
        id: "q2",
        attributes: { table: "unresolved", operation: "update", orm: "prisma" },
      }),
      unit("sink", 30, undefined, { id: "s1", attributes: { sinkType: "sql" } }),
    ]);

    const carrier = result.units[0];
    expect(carrier?.attributes.containedUnits).toBe("3");
    expect(carrier?.attributes.containedKinds).toBe("data-access:2,sink:1");
    // `unresolved` is the enumerator's word for "no table name", not a table.
    expect(carrier?.attributes.containedTables).toBe("users");
    expect(carrier?.attributes.containedOperations).toBe("select,update");
    expect(carrier?.attributes.containedSinkTypes).toBe("sql");
  });

  test("the container's own attributes survive, and the keys stay sorted", () => {
    const route = unit("route", 1, 50, { attributes: { method: "GET", path: "/a" } });
    const [carrier] = containUnits([route, unit("data-access", 10)]).units;
    expect(Object.keys(carrier?.attributes ?? {})).toEqual([
      "containedKinds",
      "containedUnits",
      "method",
      "path",
    ]);
  });

  test("two orders of the same units contain the same way", () => {
    const units = [
      unit("route", 1, 60),
      unit("webhook", 10, 30),
      unit("data-access", 15),
      unit("sink", 40),
      unit("data-access", 99, undefined, { file: "src/loose.ts" }),
    ];
    const forward = containUnits(units);
    const backward = containUnits([...units].reverse());
    expect(new Set(backward.units.map((one) => one.id))).toEqual(
      new Set(forward.units.map((one) => one.id)),
    );
    expect(new Set(backward.contained.map((one) => `${one.containerId}<${one.unit.id}`))).toEqual(
      new Set(forward.contained.map((one) => `${one.containerId}<${one.unit.id}`)),
    );
  });

  test("a repository with no container leaves every unit alone", () => {
    const units = [unit("data-access", 1), unit("sink", 2), unit("workflow-job", 3)];
    const result = containUnits(units);
    expect(result.units).toEqual(units);
    expect(result.contained).toEqual([]);
  });
});

describe("the containment disclosure", () => {
  /** Most of a large repository's data-access sites sit inside a migration. */
  const workspace = {
    produced: Array.from({ length: 12 }, (_, index) => unit("data-access", index + 1)),
    absorbed: Array.from({ length: 9 }, (_, index) => ({
      containerId: "m1",
      containerKind: "migration" as AuditUnitKind,
      unit: unit("data-access", index + 1),
    })),
  };

  test("names the total, the share that was folded in, and what folded it", () => {
    const note = containmentNote(workspace.produced, workspace.absorbed);
    expect(note).toContain("12 data-access call sites, 9 of them inside a migration");
    expect(note).toContain("that carries them");
    expect(note).toContain("not a unit of its own");
  });

  test("lists every container kind when more than one absorbed something", () => {
    const note = containmentNote(workspace.produced, [
      ...workspace.absorbed,
      { containerId: "r1", containerKind: "route", unit: unit("data-access", 50) },
    ]);
    expect(note).toContain("inside a route handler or a migration that carries them");
  });

  test("groups thousands, because the report prints this sentence verbatim", () => {
    const produced = Array.from({ length: 4000 }, (_, index) => unit("data-access", index + 1));
    const absorbed = produced.slice(0, 3900).map((one) => ({
      containerId: "m1",
      containerKind: "migration" as AuditUnitKind,
      unit: one,
    }));
    expect(containmentNote(produced, absorbed)).toContain(
      "4,000 data-access call sites, 3,900 of them inside a migration",
    );
  });

  test("the container's side of the accounting counts containers and what they took", () => {
    const note = carriedNote([
      { containerId: "m1", containerKind: "migration", unit: unit("data-access", 1) },
      { containerId: "m1", containerKind: "migration", unit: unit("data-access", 2) },
      { containerId: "m2", containerKind: "migration", unit: unit("sink", 3) },
    ]);
    expect(note).toBe(
      "2 migrations carry 2 data-access call sites and 1 unsafe-input sink as evidence rather than as units of their own",
    );
  });

  test("neither sentence is invented when nothing was contained", () => {
    expect(containmentNote(workspace.produced, [])).toBeUndefined();
    expect(carriedNote([])).toBeUndefined();
  });
});

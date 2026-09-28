import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { createFileSystem } from "../ports/file-system.ts";
import { createProcessExecutor } from "../ports/process-executor.ts";
import { RepoSnapshot } from "../profile/repo-snapshot.ts";
import { readToolsLock } from "../tools/installer.ts";
import { createToolResolver } from "../tools/resolve.ts";
import { AST_GREP_TOOL } from "./_orms/_ast.ts";
import type { DraftUnit } from "./_unit-support.ts";
import {
  DATA_ACCESS_ENUMERATORS,
  type DataAccessContext,
  type DataAccessScan,
  declaredNames,
  hasDataDependency,
  scanDataAccess,
} from "./data-access.ts";

const TARGET = join(import.meta.dir, "__fixtures__/data-layer-target");

/** Builds the context over the real fixture; ast-grep is the pinned binary. */
async function fixtureContext(
  resolve: (name: string) => Promise<string | null>,
): Promise<DataAccessContext> {
  const fs = createFileSystem();
  return {
    exec: createProcessExecutor(),
    tools: { resolve },
    targetDir: TARGET,
    snapshot: await RepoSnapshot.create(fs, TARGET),
    timeoutMs: 60_000,
  };
}

const resolver = createToolResolver({ lock: await readToolsLock(), fs: createFileSystem() });
const binary = await resolver.resolve(AST_GREP_TOOL);
/**
 * The whole fixture, scanned once. Skipped rather than faked when the pinned
 * ast-grep is not installed: a stub cannot prove that a *rule* matches real
 * code, which is the only thing this file is here to test.
 */
const scan: DataAccessScan | null =
  binary === null ? null : await scanDataAccess(await fixtureContext(async () => binary));

/**
 * The units inside one function.
 *
 * Assertions name the function rather than a line number: the fixture is
 * formatted like the rest of the repository, and a reformat must not be able to
 * make a test pass for the wrong reason.
 */
function unitsIn(symbol: string): DraftUnit[] {
  return (scan?.outcome.units ?? []).filter((unit) => unit.attributes.enclosingSymbol === symbol);
}

/** The single unit inside one function. */
function only(symbol: string): DraftUnit | undefined {
  const found = unitsIn(symbol);
  return found.length === 1 ? found[0] : undefined;
}

describe("scanDataAccess over the fixture repository", () => {
  test.skipIf(scan === null)("enumerates every supported data layer", () => {
    if (scan === null) return;
    expect(scan.outcome.status).toBe("ok");
    const orms = new Set(scan.outcome.units.map((unit) => unit.attributes.orm));
    expect([...orms].sort()).toEqual([
      "drizzle",
      "knex",
      "mongoose",
      "pg",
      "prisma",
      "sequelize",
      "supabase",
      "typeorm",
    ]);
  });

  test.skipIf(scan === null)("every unit is a data-access unit with a real location", () => {
    if (scan === null) return;
    for (const unit of scan.outcome.units) {
      expect(unit.kind).toBe("data-access");
      expect(unit.line).toBeGreaterThan(0);
      // Identity is the enclosing symbol, the call and a digest of the query —
      // adding an import above a query must not give it a new id.
      expect(unit.symbol).toMatch(/^[\w.$]*:[a-z0-9]+\.[\w$]+:query:[0-9a-f]{12}(?:#\d+)?$/);
      expect(unit.symbol).toContain(unit.attributes.enclosingSymbol ?? "");
    }
  });

  test.skipIf(scan === null)("a Drizzle table is resolved through the schema file", () => {
    if (scan === null) return;
    const unit = only("listForOrganisation");
    expect(unit?.attributes.table).toBe("bookings");
    expect(unit?.attributes.tableSource).toBe("schema");
    expect(unit?.attributes.whereColumns).toBe("organizationId");
    expect(unit?.attributes.filtersByPrincipal).toBe("yes");
    expect(unit?.attributes.hasLimit).toBe("true");
    // `select()` with no argument reads every column.
    expect(unit?.attributes.hasProjection).toBe("false");
  });

  test.skipIf(scan === null)("an unconstrained read is recorded as one", () => {
    if (scan === null) return;
    const unit = only("listEverything");
    expect(unit?.attributes.hasWhere).toBe("false");
    expect(unit?.attributes.filtersByPrincipal).toBe("no");
    expect(unit?.attributes.hasLimit).toBe("false");
  });

  test.skipIf(scan === null)("a query inside a for loop carries the N+1 signal", () => {
    if (scan === null) return;
    const unit = only("withCreators");
    expect(unit?.attributes.insideLoop).toBe("for");
    expect(unit?.attributes.enclosingSymbol).toBe("withCreators");
  });

  test.skipIf(scan === null)("two independent awaits in one block are batchable", () => {
    if (scan === null) return;
    const pair = unitsIn("dashboard");
    expect(pair).toHaveLength(2);
    for (const unit of pair) expect(unit.attributes.awaitedSequentially).toBe("true");
    // A query that is the only one in its block is not a batching problem.
    expect(only("listForOrganisation")?.attributes.awaitedSequentially).toBe("false");
  });

  test.skipIf(scan === null)("a write inside a transaction callback says so", () => {
    if (scan === null) return;
    const unit = only("cancel");
    expect(unit?.attributes.operation).toBe("update");
    expect(unit?.attributes.insideTransaction).toBe("true");
    expect(unit?.attributes.whereColumns).toContain("creatorId");
    // A write projects nothing, which is not the same as reading every column.
    expect(unit?.attributes.hasProjection).toBe("n/a");
  });

  test.skipIf(scan === null)("a Prisma model is resolved through @@map", () => {
    if (scan === null) return;
    const unit = only("invoicesFor");
    expect(unit?.label).toBe("prisma select on invoices");
    expect(unit?.attributes.tableSource).toBe("schema");
    expect(unit?.attributes.hasProjection).toBe("true");
    expect(unit?.attributes.hasLimit).toBe("true");
  });

  test.skipIf(scan === null)("an upsert is not reported as an insert", () => {
    if (scan === null) return;
    expect(only("ensureCustomer")?.attributes.operation).toBe("upsert");
  });

  test.skipIf(scan === null)("raw SQL says the table is unresolved rather than guessing", () => {
    if (scan === null) return;
    const unit = only("totals");
    expect(unit?.attributes.operation).toBe("raw");
    expect(unit?.attributes.table).toBe("unresolved");
    expect(unit?.attributes.tableSource).toBe("none");
    expect(unit?.note).toContain("not parameterised");
  });

  test.skipIf(scan === null)("a Supabase chain is read through its PostgREST verbs", () => {
    if (scan === null) return;
    const unit = only("myBookings");
    expect(unit?.attributes.orm).toBe("supabase");
    expect(unit?.attributes.table).toBe("bookings");
    expect(unit?.attributes.whereColumns).toBe("user_id");
    expect(unit?.attributes.filtersByPrincipal).toBe("yes");
    expect(unit?.attributes.hasLimit).toBe("true");
    // `select("*")` is not a projection.
    expect(only("everyProfile")?.attributes.hasProjection).toBe("false");
  });

  test.skipIf(scan === null)("a Knex string table and object filter are both read", () => {
    if (scan === null) return;
    const unit = only("tenantAudit");
    expect(unit?.attributes.table).toBe("audit_log");
    expect(unit?.attributes.tableSource).toBe("literal");
    expect(unit?.attributes.whereColumns).toBe("tenant_id");
    expect(only("purge")?.attributes.operation).toBe("delete");
  });

  test.skipIf(scan === null)("a raw driver statement is parsed as SQL", () => {
    if (scan === null) return;
    const read = only("sessionFor");
    expect(read?.attributes.operation).toBe("select");
    expect(read?.attributes.table).toBe("sessions");
    expect(read?.attributes.tableSource).toBe("sql");
    expect(read?.attributes.hasProjection).toBe("false");
    const write = only("purgeExpired");
    expect(write?.attributes.operation).toBe("delete");
    expect(write?.note).toContain("interpolation");
  });

  test.skipIf(scan === null)("an ambiguous method goes to the ORM the file imports", () => {
    if (scan === null) return;
    // `find` belongs to Mongoose and to TypeORM; each file gets its own answer.
    expect(only("messagesIn")?.attributes.orm).toBe("mongoose");
    expect(only("ticketsFor")?.attributes.orm).toBe("typeorm");
    expect(only("accountsFor")?.attributes.orm).toBe("sequelize");
  });

  test.skipIf(scan === null)("the schema reads are handed back for the schema model", () => {
    if (scan === null) return;
    expect(scan.drizzleTables.map((table) => table.table).sort()).toEqual(["bookings", "users"]);
    expect(scan.prismaSchemas).toHaveLength(1);
    expect(scan.tables).toContain("invoices");
    // One raw statement names no table; nothing else is left unresolved.
    expect(scan.unresolvedTables).toBe(1);
  });

  test.skipIf(scan === null)("two queries in one function get different identities", () => {
    if (scan === null) return;
    const symbols = scan.outcome.units.map((unit) => `${unit.file}|${unit.symbol}`);
    expect(new Set(symbols).size).toBe(symbols.length);
  });
});

describe("scanDataAccess without the analyzer", () => {
  test("reports that it could not enumerate instead of returning nothing", async () => {
    const ctx = await fixtureContext(async () => null);
    const result = await scanDataAccess(ctx);
    expect(result.outcome.status).toBe("skipped");
    expect(result.outcome.reason).toContain("ast-grep");
    expect(result.outcome.units).toHaveLength(0);
  });
});

describe("the registered enumerator", () => {
  test("owns the data-access kind", () => {
    expect(DATA_ACCESS_ENUMERATORS).toHaveLength(1);
    expect(DATA_ACCESS_ENUMERATORS[0]?.name).toBe("data-access");
    expect(DATA_ACCESS_ENUMERATORS[0]?.kinds).toEqual(["data-access"]);
  });
});

describe("hasDataDependency", () => {
  test("a statement that uses the previous result is not batchable", () => {
    expect(
      hasDataDependency("const user = await db.select().from(users);", "await load(user.id);"),
    ).toBe(true);
  });

  test("two unrelated statements are", () => {
    expect(
      hasDataDependency(
        "const open = await db.select().from(bookings);",
        "const staff = await db.select().from(users);",
      ),
    ).toBe(false);
  });

  test("destructured bindings count too", () => {
    expect(declaredNames("const { rows, count } = await pool.query(sql);")).toEqual([
      "rows",
      "count",
    ]);
    expect(hasDataDependency("const { rows } = await pool.query(sql);", "await write(rows);")).toBe(
      true,
    );
  });
});

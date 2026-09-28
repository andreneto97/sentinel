import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { createFileSystem } from "../ports/file-system.ts";
import { createProcessExecutor } from "../ports/process-executor.ts";
import { RepoSnapshot } from "../profile/repo-snapshot.ts";
import { readToolsLock } from "../tools/installer.ts";
import { createToolResolver } from "../tools/resolve.ts";
import { AST_GREP_TOOL } from "./_orms/_ast.ts";
import {
  SCHEMA_MODEL_FILE,
  SchemaModelDocumentSchema,
  findTable,
  hasIndexOn,
} from "./_orms/schema-model.ts";
import type { DraftUnit } from "./_unit-support.ts";
import {
  MIGRATION_ENUMERATORS,
  type MigrationsContext,
  type MigrationsScan,
  classify,
  dialectOf,
  looksLikeMigration,
  scanMigrations,
  versionOf,
  writeSchemaModel,
} from "./migrations.ts";

const TARGET = join(import.meta.dir, "__fixtures__/data-layer-target");

/** Builds the context over the real fixture. */
async function fixtureContext(
  resolve: (name: string) => Promise<string | null>,
): Promise<MigrationsContext> {
  const fs = createFileSystem();
  return {
    exec: createProcessExecutor(),
    tools: { resolve },
    targetDir: TARGET,
    snapshot: await RepoSnapshot.create(fs, TARGET),
    runId: "test-run",
    timeoutMs: 60_000,
  };
}

const resolver = createToolResolver({ lock: await readToolsLock(), fs: createFileSystem() });
const binary = await resolver.resolve(AST_GREP_TOOL);
const scan: MigrationsScan | null =
  binary === null ? null : await scanMigrations(await fixtureContext(async () => binary));

/** The unit for one migration file. */
function unitFor(file: string): DraftUnit | undefined {
  return scan?.outcome.units.find((unit) => unit.file === file);
}

describe("scanMigrations over the fixture repository", () => {
  test.skipIf(scan === null)("finds every migration, whichever tool wrote it", () => {
    if (scan === null) return;
    expect(scan.outcome.status).toBe("ok");
    expect(scan.files.map((file) => `${file.tool}:${file.version}`).sort()).toEqual([
      "knex:20240401000000",
      "prisma:20240101120000",
      "prisma:20240210090000",
      "supabase:20240301000000",
    ]);
  });

  test.skipIf(scan === null)("the ordinal counts within one tool's own history", () => {
    if (scan === null) return;
    expect(unitFor("prisma/migrations/20240101120000_init/migration.sql")?.attributes.ordinal).toBe(
      "1",
    );
    expect(
      unitFor("prisma/migrations/20240210090000_secure_invoices/migration.sql")?.attributes.ordinal,
    ).toBe("2");
    // A different tool starts counting again.
    expect(unitFor("supabase/migrations/20240301000000_drop_legacy.sql")?.attributes.ordinal).toBe(
      "1",
    );
  });

  test.skipIf(scan === null)("an index build and a NOT NULL default are reported as locks", () => {
    if (scan === null) return;
    const unit = unitFor("prisma/migrations/20240210090000_secure_invoices/migration.sql");
    expect(unit?.attributes.operations).toBe("add-column,add-index,enable-rls,create-policy");
    expect(unit?.attributes.lockRisk).toBe("create-index-without-concurrently");
    expect(unit?.attributes.destructive).toBe("false");
    expect(unit?.note).toContain("CONCURRENTLY");
  });

  test.skipIf(scan === null)("a drop next to a backfill is destructive and mixed", () => {
    if (scan === null) return;
    const unit = unitFor("supabase/migrations/20240301000000_drop_legacy.sql");
    expect(unit?.attributes.destructive).toBe("true");
    expect(unit?.attributes.mixesDataAndSchema).toBe("true");
    expect(unit?.attributes.tables).toBe("customers");
  });

  test.skipIf(scan === null)("a SQL migration has no rollback path unless one is on disk", () => {
    if (scan === null) return;
    expect(
      unitFor("prisma/migrations/20240101120000_init/migration.sql")?.attributes.hasDownMigration,
    ).toBe("false");
  });

  test.skipIf(scan === null)("a script migration is read through its builder calls", () => {
    if (scan === null) return;
    const unit = unitFor("migrations/20240401000000_add_flag.ts");
    expect(unit?.attributes.tool).toBe("knex");
    expect(unit?.attributes.hasDownMigration).toBe("true");
    expect(unit?.attributes.lockRisk).toBe("add-not-null-with-default");
    expect(unit?.attributes.tables).toBe("audit_log");
    // The `down()` rollback drops a column; that is not a destructive migration.
    expect(unit?.attributes.destructive).toBe("false");
  });

  test.skipIf(scan === null)("every unit cites a statement rather than the file header", () => {
    if (scan === null) return;
    for (const unit of scan.outcome.units) {
      expect(unit.kind).toBe("migration");
      expect(unit.line).toBeGreaterThan(1);
      expect(unit.symbol).not.toContain("ordinal");
    }
  });

  test.skipIf(scan === null)(
    "a unit's extent is the whole script, not the cited statement",
    async () => {
      if (scan === null) return;
      // The checks ask whether a destructive statement has a guard and whether a
      // column drop is accompanied by a data migration; both are about statements
      // other than the cited one. Without an extent the slicer resolved only the
      // block around the citation, so phase 4 was asked about a migration it had
      // been shown one statement of.
      const fs = createFileSystem();
      for (const unit of scan.outcome.units) {
        const text = await fs.readFile(join(TARGET, unit.file));
        const lines = text.split("\n");
        const last = lines[lines.length - 1] === "" ? lines.length - 1 : lines.length;
        if (last <= unit.line) continue;
        expect(unit.endLine).toBe(last);
      }
    },
  );
});

describe("the schema model the migrations leave behind", () => {
  test.skipIf(scan === null)("is Zod-valid and names the engine", () => {
    if (scan === null) return;
    expect(() => SchemaModelDocumentSchema.parse(scan.schema)).not.toThrow();
    // No profile was passed, so the Prisma datasource is what proves the engine.
    expect(scan.schema.dialect).toBe("postgresql");
    expect(scan.schema.runId).toBe("test-run");
  });

  test.skipIf(scan === null)("merges the migrations with both ORM schema files", () => {
    if (scan === null) return;
    expect(scan.schema.tables.map((table) => table.name)).toEqual([
      "bookings",
      "customers",
      "invoices",
      "users",
    ]);
    expect(scan.schema.sources).toContain("src/db/schema.ts");
    expect(scan.schema.sources).toContain("prisma/schema.prisma");
  });

  test.skipIf(scan === null)("carries the column that a later migration added", () => {
    if (scan === null) return;
    const invoices = findTable(scan.schema, "invoices");
    expect(invoices?.columns.map((column) => column.name)).toContain("organization_id");
    // And not the one a later migration dropped.
    expect(findTable(scan.schema, "customers")?.columns.map((c) => c.name)).not.toContain(
      "legacy_name",
    );
  });

  test.skipIf(scan === null)("records row level security and the policies on it", () => {
    if (scan === null) return;
    const invoices = findTable(scan.schema, "invoices");
    expect(invoices?.rlsEnabled).toBe(true);
    expect(invoices?.policies.map((policy) => policy.command)).toEqual(["SELECT"]);
    // The tables nobody enabled it on say so, which is the finding.
    expect(findTable(scan.schema, "bookings")?.rlsEnabled).toBe(false);
  });

  test.skipIf(scan === null)("answers which columns are indexed, whatever declared them", () => {
    if (scan === null) return;
    const bookings = findTable(scan.schema, "bookings");
    const invoices = findTable(scan.schema, "invoices");
    expect(bookings && hasIndexOn(bookings, "organization_id")).toBe(true);
    // `creator_id` is a foreign key with no index: the query at bookings.ts:23
    // filters by it once per row.
    expect(bookings && hasIndexOn(bookings, "creator_id")).toBe(false);
    expect(bookings?.foreignKeys[0]?.referencesTable).toBe("users");
    expect(invoices && hasIndexOn(invoices, "customer_id")).toBe(true);
  });

  test.skipIf(scan === null)("every table points at a file a reader can open", () => {
    if (scan === null) return;
    for (const table of scan.schema.tables) {
      expect(table.evidence.length).toBeGreaterThan(0);
      expect(table.evidence[0]?.line).toBeGreaterThan(0);
    }
  });

  test.skipIf(scan === null)("is written as one artifact", async () => {
    if (scan === null) return;
    const writes: Array<{ path: string; content: string }> = [];
    const path = await writeSchemaModel(
      {
        async writeFile(target: string, data: string | Uint8Array): Promise<void> {
          writes.push({
            path: target,
            content: typeof data === "string" ? data : new TextDecoder().decode(data),
          });
        },
      },
      "/runs/2026-09-22",
      scan.schema,
    );
    expect(path).toBe(`/runs/2026-09-22/${SCHEMA_MODEL_FILE}`);
    expect(JSON.parse(writes[0]?.content ?? "{}").schemaVersion).toBe("1.0");
  });
});

describe("classification", () => {
  test("the path names the tool, and the file settles what it cannot", () => {
    expect(classify("prisma/migrations/2024_x/migration.sql", "")).toBe("prisma");
    expect(classify("supabase/migrations/2024_x.sql", "")).toBe("supabase");
    expect(classify("drizzle/0000_init.sql", "")).toBe("drizzle");
    expect(classify("db/migrations/0001.sql", "", ["db/migrations"])).toBe("drizzle");
    expect(classify("db/migrations/0001.sql", "")).toBe("raw-sql");
    expect(
      classify("src/migrations/1700.ts", "export class X implements MigrationInterface {}"),
    ).toBe("typeorm");
    expect(classify("migrations/1700.ts", "export async function up(knex) {}")).toBe("knex");
  });

  test("a version is read from the file, or from the directory Prisma names", () => {
    expect(versionOf("prisma/migrations/20240101120000_init/migration.sql")).toBe("20240101120000");
    expect(versionOf("migrations/20240401000000_add_flag.ts")).toBe("20240401000000");
    expect(versionOf("migrations/add_flag.ts")).toBe("");
  });

  test("only files in a migrations directory are migrations", () => {
    expect(looksLikeMigration("src/migrations/0001_init.sql")).toBe(true);
    expect(looksLikeMigration("drizzle/0000_init.sql")).toBe(true);
    expect(looksLikeMigration("src/db/seed.sql")).toBe(false);
    expect(looksLikeMigration("node_modules/pkg/migrations/1.sql")).toBe(false);
    expect(looksLikeMigration("migrations/index.ts")).toBe(false);
  });

  test("the engine comes from the profile when there is one", () => {
    expect(dialectOf(undefined)).toBe("unknown");
    expect(
      dialectOf({
        schemaVersion: "1.0",
        target: "/t",
        facts: [
          {
            kind: "database-engine",
            value: "mysql",
            confidence: "high",
            evidence: [{ file: "docker-compose.yml", line: 3 }],
          },
        ],
        absences: [],
        warnings: [],
        scan: { filesSeen: 1, filesRead: 1, truncated: false },
      }),
    ).toBe("mysql");
  });
});

describe("the registered enumerator", () => {
  test("owns the migration kind", () => {
    expect(MIGRATION_ENUMERATORS).toHaveLength(1);
    expect(MIGRATION_ENUMERATORS[0]?.name).toBe("migrations");
    expect(MIGRATION_ENUMERATORS[0]?.kinds).toEqual(["migration"]);
  });
});

// ---------------------------------------------------------------------------
// The extent of a script migration
// ---------------------------------------------------------------------------

const ORDER_TARGET = join(import.meta.dir, "__fixtures__/migration-order-target");
const ORDER_FILE = "migrations/20240501000000_down_first.ts";

/** Scans the fixture whose `down()` is declared above its `up()`. */
async function scanOrderTarget(): Promise<MigrationsScan | null> {
  if (binary === null) return null;
  const fs = createFileSystem();
  return scanMigrations({
    exec: createProcessExecutor(),
    tools: { resolve: async () => binary },
    targetDir: ORDER_TARGET,
    snapshot: await RepoSnapshot.create(fs, ORDER_TARGET),
    runId: "test-run",
    timeoutMs: 60_000,
  });
}

const ordered: MigrationsScan | null = await scanOrderTarget();

describe("the extent of a script migration", () => {
  test.skipIf(ordered === null)(
    "starts at the file's first statement, not at the first statement `up()` makes",
    () => {
      if (ordered === null) return;
      const unit = ordered.outcome.units.find((one) => one.file === ORDER_FILE);
      // `down()` runs its query on line 16 and `up()` on line 20. A unit citing
      // line 20 would leave line 16 outside its span, and phase 2 folds a query
      // into the unit around it *by span* — so that query would be enumerated a
      // second time as a `data-access` unit with no migration around it.
      expect(unit?.line).toBe(16);
      expect(unit?.endLine).toBe(22);
    },
  );

  test.skipIf(ordered === null)("still reads only the forward path for its verdicts", () => {
    if (ordered === null) return;
    const unit = ordered.outcome.units.find((one) => one.file === ORDER_FILE);
    // The `DROP TABLE` belongs to `down()`, so the migration is not destructive.
    expect(unit?.attributes.destructive).toBe("false");
    expect(unit?.attributes.hasDownMigration).toBe("true");
  });
});

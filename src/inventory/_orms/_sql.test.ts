import { describe, expect, test } from "bun:test";
import {
  analyseSql,
  analyseStatement,
  applyStatement,
  maskSql,
  parseColumnDefinition,
  selectsEverything,
  splitSqlStatements,
  sqlOperation,
  sqlTable,
  whereColumns,
  worseLockRisk,
} from "./_sql.ts";
import { SchemaBuilder, findTable, hasIndexOn } from "./schema-model.ts";

describe("maskSql", () => {
  test("blanks strings and comments but keeps the line count", () => {
    const sql = "-- drop it\nUPDATE t SET a = 'x; y';";
    const masked = maskSql(sql);
    expect(masked.split("\n")).toHaveLength(2);
    expect(masked).not.toContain("drop");
    expect(masked.indexOf(";")).toBe(masked.length - 1);
  });

  test("a dollar-quoted function body does not split the statement", () => {
    const sql = "CREATE FUNCTION f() RETURNS void AS $$ BEGIN; END; $$ LANGUAGE plpgsql;";
    expect(splitSqlStatements(sql)).toHaveLength(1);
  });
});

describe("splitSqlStatements", () => {
  test("reports the line each statement starts on", () => {
    const statements = splitSqlStatements(
      "-- header\n\nCREATE TABLE a (id uuid);\n\nALTER TABLE a ADD COLUMN b text;\n",
    );
    // Line 3 and line 5: a comment is not the statement that follows it.
    expect(statements.map((statement) => statement.line)).toEqual([3, 5]);
  });
});

describe("analyseStatement", () => {
  test("CREATE INDEX without CONCURRENTLY is a lock risk", () => {
    const analysis = analyseStatement('CREATE INDEX "i" ON "bookings" ("creator_id")');
    expect(analysis.operation).toBe("add-index");
    expect(analysis.table).toBe("bookings");
    expect(analysis.lockRisk).toBe("create-index-without-concurrently");
  });

  test("CONCURRENTLY clears it", () => {
    expect(analyseStatement("CREATE INDEX CONCURRENTLY i ON t (c)").lockRisk).toBe("none");
  });

  test("a NOT NULL column with a default rewrites the table", () => {
    const analysis = analyseStatement(
      'ALTER TABLE "invoices" ADD COLUMN "org" uuid NOT NULL DEFAULT \'0\'',
    );
    expect(analysis.operation).toBe("add-column");
    expect(analysis.lockRisk).toBe("add-not-null-with-default");
    expect(analysis.lockDetail).toContain("rewrites the table");
  });

  test("a type change is a rewrite", () => {
    expect(analyseStatement("ALTER TABLE t ALTER COLUMN c TYPE bigint").lockRisk).toBe(
      "type-rewrite",
    );
  });

  test("row level security and policies are read as their own operations", () => {
    expect(analyseStatement("ALTER TABLE t ENABLE ROW LEVEL SECURITY").operation).toBe(
      "enable-rls",
    );
    expect(analyseStatement("CREATE POLICY p ON t FOR SELECT USING (true)").operation).toBe(
      "create-policy",
    );
  });

  test("a comment is not mistaken for the statement it describes", () => {
    expect(analyseStatement("-- DROP TABLE users\nSELECT 1").operation).toBe("other");
  });
});

describe("analyseSql", () => {
  test("a backfill next to a schema change is both, and the worst lock wins", () => {
    const analysis = analyseSql(
      splitSqlStatements(
        [
          "UPDATE customers SET name = 'x' WHERE name IS NULL;",
          "ALTER TABLE customers DROP COLUMN legacy_name;",
          "CREATE INDEX i ON customers (email);",
        ].join("\n"),
      ),
    );
    expect(analysis.operations).toEqual(["backfill", "drop-column", "add-index"]);
    expect(analysis.destructive).toBe(true);
    expect(analysis.touchesData).toBe(true);
    expect(analysis.touchesSchema).toBe(true);
    expect(analysis.lockRisk).toBe("create-index-without-concurrently");
    expect(analysis.tables).toEqual(["customers"]);
  });

  test("worseLockRisk orders a rewrite above an index build", () => {
    expect(worseLockRisk("create-index-without-concurrently", "type-rewrite")).toBe("type-rewrite");
    expect(worseLockRisk("none", "add-not-null-with-default")).toBe("add-not-null-with-default");
  });
});

describe("parseColumnDefinition", () => {
  test("reads the type, the nullability and the reference", () => {
    const column = parseColumnDefinition(
      '"customer_id" uuid NOT NULL REFERENCES "customers" ("id") ON DELETE CASCADE',
    );
    expect(column?.name).toBe("customer_id");
    expect(column?.type).toBe("uuid");
    expect(column?.nullable).toBe(false);
    expect(column?.references).toEqual({ table: "customers", column: "id" });
  });

  test("a parameterised type survives the cut", () => {
    expect(parseColumnDefinition('"issued_at" timestamp with time zone DEFAULT now()')?.type).toBe(
      "timestamp with time zone",
    );
    expect(parseColumnDefinition('"total" numeric(10, 2) NOT NULL')?.type).toBe("numeric(10, 2)");
  });

  test("a primary key is not nullable", () => {
    const column = parseColumnDefinition('"id" uuid PRIMARY KEY');
    expect(column?.isPrimaryKey).toBe(true);
    expect(column?.nullable).toBe(false);
  });
});

describe("applyStatement", () => {
  test("replays a history into the schema it leaves behind", () => {
    const builder = new SchemaBuilder();
    const sql = [
      'CREATE TABLE "bookings" ("id" uuid PRIMARY KEY, "creator_id" uuid NOT NULL, "note" text);',
      'ALTER TABLE "bookings" ADD COLUMN "status" text NOT NULL DEFAULT \'open\';',
      'ALTER TABLE "bookings" DROP COLUMN "note";',
      'CREATE INDEX "bookings_creator_id_idx" ON "bookings" ("creator_id");',
      'ALTER TABLE "bookings" ENABLE ROW LEVEL SECURITY;',
      'CREATE POLICY "own_bookings" ON "bookings" FOR SELECT TO authenticated USING (true);',
    ].join("\n");
    for (const statement of splitSqlStatements(sql)) {
      applyStatement(builder, statement, { file: "migrations/1.sql", line: 1 });
    }
    const model = builder.build({ runId: "r", target: "/t", dialect: "postgresql" });
    const table = findTable(model, "bookings");

    expect(table?.columns.map((column) => column.name)).toEqual(["id", "creator_id", "status"]);
    expect(table?.primaryKey).toEqual(["id"]);
    expect(table?.rlsEnabled).toBe(true);
    expect(table?.policies[0]).toEqual({
      name: "own_bookings",
      command: "SELECT",
      roles: ["authenticated"],
    });
    expect(table !== undefined && hasIndexOn(table, "creator_id")).toBe(true);
    expect(table !== undefined && hasIndexOn(table, "status")).toBe(false);
    // Every table carries a citation a reader can open.
    expect(table?.evidence[0]?.file).toBe("migrations/1.sql");
  });

  test("a dropped table is not in the schema, whatever created it", () => {
    const builder = new SchemaBuilder();
    for (const statement of splitSqlStatements(
      "CREATE TABLE legacy (id uuid);\nDROP TABLE legacy;",
    )) {
      applyStatement(builder, statement, { file: "m.sql", line: 1 });
    }
    expect(builder.tables()).toHaveLength(0);
  });

  test("a table constraint becomes a foreign key on the column too", () => {
    const builder = new SchemaBuilder();
    for (const statement of splitSqlStatements(
      'CREATE TABLE "invoices" ("id" uuid, "customer_id" uuid, CONSTRAINT "fk" FOREIGN KEY ("customer_id") REFERENCES "customers" ("id") ON DELETE CASCADE);',
    )) {
      applyStatement(builder, statement, { file: "m.sql", line: 1 });
    }
    const [invoices] = builder.tables();
    expect(invoices?.foreignKeys[0]).toEqual({
      name: "fk",
      columns: ["customer_id"],
      referencesTable: "customers",
      referencesColumns: ["id"],
      onDelete: "CASCADE",
    });
    expect(
      invoices?.columns.find((column) => column.name === "customer_id")?.references?.table,
    ).toBe("customers");
  });
});

describe("statement reading for raw call sites", () => {
  test("names the operation, the table and the filtered columns", () => {
    const sql = "SELECT * FROM sessions WHERE user_id = $1 AND revoked_at IS NULL LIMIT 1";
    expect(sqlOperation(sql)).toBe("select");
    expect(sqlTable(sql)).toBe("sessions");
    expect(whereColumns(sql)).toEqual(["user_id", "revoked_at"]);
    expect(selectsEverything(sql)).toBe(true);
  });

  test("a projection is not a select-all", () => {
    expect(selectsEverything("SELECT id, name FROM t")).toBe(false);
  });

  test("the ORDER BY clause is not read as a filter", () => {
    expect(whereColumns("SELECT 1 FROM t WHERE a = 1 ORDER BY b DESC")).toEqual(["a"]);
  });
});

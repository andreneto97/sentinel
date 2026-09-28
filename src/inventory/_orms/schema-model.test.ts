import { describe, expect, test } from "bun:test";
import {
  SCHEMA_MODEL_FILE,
  SchemaBuilder,
  SchemaModelDocumentSchema,
  bareIdentifier,
  blankColumn,
  findTable,
  hasIndexOn,
} from "./schema-model.ts";

describe("bareIdentifier", () => {
  test("strips the quoting and the schema qualifier", () => {
    expect(bareIdentifier('public."Users"')).toBe("Users");
    expect(bareIdentifier("`bookings`")).toBe("bookings");
    expect(bareIdentifier("[dbo].[orders]")).toBe("orders");
  });
});

describe("SchemaBuilder", () => {
  test("an unquoted identifier folds to the same table", () => {
    const builder = new SchemaBuilder();
    builder.putColumn("Bookings", blankColumn("id", "uuid"));
    builder.putColumn("bookings", blankColumn("status", "text"));
    expect(builder.tables()).toHaveLength(1);
    expect(builder.tables()[0]?.columns.map((column) => column.name)).toEqual(["id", "status"]);
  });

  test("the last declaration of a column wins, because the history is replayed in order", () => {
    const builder = new SchemaBuilder();
    builder.putColumn("t", blankColumn("c", "text"));
    builder.patchColumn("t", "c", { type: "bigint", nullable: false });
    const [column] = builder.tables()[0]?.columns ?? [];
    expect(column?.type).toBe("bigint");
    expect(column?.nullable).toBe(false);
  });

  test("altering a column nobody declared creates it rather than losing the fact", () => {
    const builder = new SchemaBuilder();
    builder.patchColumn("t", "late", { type: "text" });
    expect(builder.tables()[0]?.columns[0]?.name).toBe("late");
  });

  test("the same index declared twice is one index", () => {
    const builder = new SchemaBuilder();
    builder.addIndex("t", { name: "", columns: ["email"], unique: true, concurrent: false });
    builder.addIndex("t", { name: "", columns: ["EMAIL"], unique: true, concurrent: false });
    expect(builder.tables()[0]?.indexes).toHaveLength(1);
  });

  test("a named index is replaced, not duplicated, when it is redefined", () => {
    const builder = new SchemaBuilder();
    builder.addIndex("t", { name: "i", columns: ["a"], unique: false, concurrent: false });
    builder.addIndex("t", { name: "i", columns: ["a", "b"], unique: false, concurrent: false });
    expect(builder.tables()[0]?.indexes).toEqual([
      { name: "i", columns: ["a", "b"], unique: false, concurrent: false },
    ]);
  });

  test("a single-column foreign key is mirrored onto the column", () => {
    const builder = new SchemaBuilder();
    builder.putColumn("bookings", blankColumn("creator_id", "uuid"));
    builder.addForeignKey("bookings", {
      name: "fk",
      columns: ["creator_id"],
      referencesTable: "users",
      referencesColumns: ["id"],
    });
    expect(builder.tables()[0]?.columns[0]?.references).toEqual({ table: "users", column: "id" });
  });

  test("dropping a column removes it from the primary key too", () => {
    const builder = new SchemaBuilder();
    builder.setPrimaryKey("t", ["a", "b"]);
    builder.putColumn("t", blankColumn("a", "uuid"));
    builder.dropColumn("t", "a");
    expect(builder.tables()[0]?.primaryKey).toEqual(["b"]);
  });

  test("evidence is deduplicated and bounded", () => {
    const builder = new SchemaBuilder();
    for (let line = 1; line <= 20; line += 1) {
      builder.addEvidence("t", { file: "m.sql", line });
      builder.addEvidence("t", { file: "m.sql", line });
    }
    const evidence = builder.tables()[0]?.evidence ?? [];
    expect(evidence.length).toBeLessThanOrEqual(8);
    expect(new Set(evidence.map((ref) => ref.line)).size).toBe(evidence.length);
  });

  test("a model with nothing in it says so rather than looking complete", () => {
    const builder = new SchemaBuilder();
    builder.warn("no tables could be reconstructed");
    const model = builder.build({ runId: "r", target: "/t", dialect: "unknown" });
    expect(model.tables).toHaveLength(0);
    expect(model.warnings).toEqual(["no tables could be reconstructed"]);
  });

  test("the built document satisfies its own schema", () => {
    const builder = new SchemaBuilder();
    builder.putColumn("t", blankColumn("id", "uuid"));
    builder.setRls("t", true);
    builder.addPolicy("t", { name: "p", command: "ALL", roles: [] });
    const model = builder.build({ runId: "r", target: "/t", dialect: "postgresql" });
    expect(() => SchemaModelDocumentSchema.parse(model)).not.toThrow();
    expect(SCHEMA_MODEL_FILE).toBe("schema-model.json");
  });

  test("tables come out name-sorted, so two runs produce the same bytes", () => {
    const builder = new SchemaBuilder();
    builder.table("zeta");
    builder.table("alpha");
    expect(builder.tables().map((table) => table.name)).toEqual(["alpha", "zeta"]);
  });
});

describe("hasIndexOn", () => {
  const builder = new SchemaBuilder();
  builder.putColumn("t", { ...blankColumn("id", "uuid"), isPrimaryKey: true, isUnique: true });
  builder.setPrimaryKey("t", ["id"]);
  builder.putColumn("t", { ...blankColumn("email", "text"), isUnique: true });
  builder.putColumn("t", blankColumn("org_id", "uuid"));
  builder.putColumn("t", blankColumn("created_at", "timestamp"));
  builder.addIndex("t", {
    name: "t_org_created_idx",
    columns: ["org_id", "created_at"],
    unique: false,
    concurrent: false,
  });
  const model = builder.build({ runId: "r", target: "/t", dialect: "postgresql" });
  const table = findTable(model, "t");

  test("a primary key and a unique column are both indexed", () => {
    expect(table && hasIndexOn(table, "id")).toBe(true);
    expect(table && hasIndexOn(table, "email")).toBe(true);
  });

  test("a composite index serves its leading column only", () => {
    expect(table && hasIndexOn(table, "org_id")).toBe(true);
    // Filtering by `created_at` alone cannot use `(org_id, created_at)`.
    expect(table && hasIndexOn(table, "created_at")).toBe(false);
  });
});

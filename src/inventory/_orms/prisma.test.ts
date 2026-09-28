import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { applyPrismaSchema, prismaDialect, prismaModelIndex } from "./prisma.ts";
import { SchemaBuilder, findTable, hasIndexOn } from "./schema-model.ts";

/** The real fixture schema, so the parser is tested against code that exists. */
const SCHEMA = await Bun.file(
  join(import.meta.dir, "../__fixtures__/data-layer-target/prisma/schema.prisma"),
).text();

describe("applyPrismaSchema", () => {
  const builder = new SchemaBuilder();
  const parsed = applyPrismaSchema(builder, SCHEMA, "prisma/schema.prisma");
  const model = builder.build({ runId: "r", target: "/t", dialect: parsed.dialect });

  test("a model maps to the table its @@map names", () => {
    expect(parsed.models.map((entry) => `${entry.name}->${entry.table}`)).toEqual([
      "Customer->customers",
      "Invoice->invoices",
    ]);
    expect(prismaModelIndex([parsed]).get("invoice")).toBe("invoices");
  });

  test("the datasource provider names the engine", () => {
    expect(parsed.dialect).toBe("postgresql");
    expect(prismaDialect(SCHEMA)).toBe("postgresql");
  });

  test("a scalar field becomes a column, under the name @map gives it", () => {
    const invoices = findTable(model, "invoices");
    expect(invoices?.columns.map((column) => column.name)).toEqual([
      "id",
      "customer_id",
      "total",
      "issued_at",
    ]);
  });

  test("optionality, defaults and the primary key are read off the attributes", () => {
    const customers = findTable(model, "customers");
    const name = customers?.columns.find((column) => column.name === "name");
    const id = customers?.columns.find((column) => column.name === "id");
    expect(name?.nullable).toBe(true);
    expect(id?.nullable).toBe(false);
    expect(id?.isPrimaryKey).toBe(true);
    expect(id?.hasDefault).toBe(true);
  });

  test("a relation field is a foreign key, not a column", () => {
    const invoices = findTable(model, "invoices");
    expect(invoices?.columns.some((column) => column.name === "customer")).toBe(false);
    expect(invoices?.foreignKeys[0]).toEqual({
      name: "",
      columns: ["customer_id"],
      referencesTable: "customers",
      referencesColumns: ["id"],
    });
  });

  test("@@index and @unique both answer the question the audit asks", () => {
    const invoices = findTable(model, "invoices");
    const customers = findTable(model, "customers");
    expect(invoices && hasIndexOn(invoices, "issued_at")).toBe(true);
    // `customer_id` carries the relation but no index: exactly the gap D3 looks for.
    expect(invoices && hasIndexOn(invoices, "customer_id")).toBe(false);
    expect(customers && hasIndexOn(customers, "email")).toBe(true);
  });

  test("every table carries the line it was declared on", () => {
    const invoices = findTable(model, "invoices");
    expect(invoices?.evidence[0]?.file).toBe("prisma/schema.prisma");
    expect(invoices?.evidence[0]?.line).toBeGreaterThan(1);
  });

  test("a schema with no datasource leaves the dialect unknown", () => {
    const empty = new SchemaBuilder();
    expect(applyPrismaSchema(empty, "model A {\n  id String @id\n}\n", "s.prisma").dialect).toBe(
      "unknown",
    );
  });
});

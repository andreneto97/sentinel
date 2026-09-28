/**
 * Prisma: `prisma.booking.findMany({ where: { userId } })`, plus the
 * `schema.prisma` reader that turns a model into a table.
 *
 * The client addresses models in camel case and the database sees whatever
 * `@@map` says, so a query's table name is only knowable through the schema —
 * which is also the only place Prisma declares its indexes, so it is the only
 * place the audit can learn that a column three queries filter by has none.
 */

import { objectEntries } from "./_chain.ts";
import { facts, filterObject, isPlainReceiver, receiverWord } from "./_claim.ts";
import {
  type SchemaBuilder,
  type SchemaDialect,
  bareIdentifier,
  blankColumn,
} from "./schema-model.ts";
import type { ClaimInput, DataAccessFacts, DataOperation, OrmExtractor } from "./types.ts";

/** Client methods, and what each one does to the store. */
const MODEL_OPERATIONS: Readonly<Record<string, DataOperation>> = {
  findMany: "select",
  findFirst: "select",
  findFirstOrThrow: "select",
  findUnique: "select",
  findUniqueOrThrow: "select",
  create: "insert",
  createMany: "insert",
  createManyAndReturn: "insert",
  update: "update",
  updateMany: "update",
  upsert: "upsert",
  delete: "delete",
  deleteMany: "delete",
  count: "aggregate",
  aggregate: "aggregate",
  groupBy: "aggregate",
};

/** Methods that read at most one row, so they are bounded by construction. */
const SINGLE_ROW = new Set([
  "findUnique",
  "findUniqueOrThrow",
  "findFirst",
  "findFirstOrThrow",
  "update",
  "delete",
  "upsert",
  "create",
]);

/** Receiver names that are plausibly a Prisma client. */
const CLIENT_NAMES = /^(prisma|prismaclient|db|client|tx|trx|_prisma|datasource|orm)$/;

/** Prisma's data-access call sites. */
export const prismaExtractor: OrmExtractor = {
  orm: "prisma",
  dataLayers: ["prisma"],
  imports: ["@prisma/client", ".prisma/client"],
  chainMethods: [
    "findMany",
    "findFirst",
    "findFirstOrThrow",
    "findUnique",
    "findUniqueOrThrow",
    "create",
    "createMany",
    "update",
    "updateMany",
    "upsert",
    "delete",
    "deleteMany",
    "count",
    "aggregate",
    "groupBy",
    "$queryRaw",
    "$queryRawUnsafe",
    "$executeRaw",
    "$executeRawUnsafe",
  ],
  priority: 60,
  patterns: [
    {
      id: "model",
      pattern: "$CLIENT.$MODEL.$OP($$$ARGS)",
      constraints: {
        MODEL: { regex: "^[a-z][A-Za-z0-9_]*$" },
        OP: {
          regex:
            "^(findMany|findFirst|findFirstOrThrow|findUnique|findUniqueOrThrow|create|createMany|createManyAndReturn|update|updateMany|upsert|delete|deleteMany|count|aggregate|groupBy)$",
        },
      },
    },
    {
      id: "raw",
      pattern: "$CLIENT.$OP($$$ARGS)",
      constraints: {
        OP: { regex: "^(\\$queryRaw|\\$queryRawUnsafe|\\$executeRaw|\\$executeRawUnsafe)$" },
      },
    },
  ],

  claim(input: ClaimInput): DataAccessFacts | null {
    const method = input.meta.OP ?? "";
    const client = input.meta.CLIENT ?? input.chain.base;
    if (!isPlainReceiver(client)) return null;

    if (input.patternId === "prisma.raw") {
      const unsafe = method.endsWith("Unsafe");
      return facts({
        orm: "prisma",
        operation: "raw",
        method,
        table: "unresolved",
        tableSource: "none",
        hasWhere: false,
        hasLimit: null,
        hasProjection: null,
        note: unsafe
          ? "raw SQL built as a string; the statement is not parameterised by Prisma"
          : "raw SQL through a tagged template; Prisma parameterises the interpolations",
      });
    }

    const operation = MODEL_OPERATIONS[method];
    if (operation === undefined) return null;
    // A model call has exactly one receiver segment, and the client is named
    // like one — `this.prisma.user.findMany`, not `res.locals.user.find`.
    if (!CLIENT_NAMES.test(receiverWord(client)) && !hasPrismaImport(input)) return null;

    const model = input.meta.MODEL ?? "";
    const mapped = input.tables.byModel(model);
    const options = input.chain.segments[0]?.args[0] ?? "";
    const entries = objectEntries(options);
    const where = entries.find((entry) => entry.key === "where");
    const filter = where === undefined ? { columns: [], values: [] } : filterObject(where.value);
    const reads = operation === "select" || operation === "aggregate";

    return facts({
      orm: "prisma",
      operation,
      method,
      table: mapped ?? (model === "" ? "unresolved" : model),
      tableSource: mapped !== undefined ? "schema" : model === "" ? "none" : "identifier",
      filter,
      hasWhere: where !== undefined,
      hasLimit: reads
        ? entries.some((entry) => entry.key === "take") || SINGLE_ROW.has(method)
        : null,
      hasProjection: reads
        ? entries.some((entry) => entry.key === "select" || entry.key === "_count")
        : null,
    });
  },
};

/** True when the file imports the Prisma client, which settles an ambiguous receiver. */
function hasPrismaImport(input: ClaimInput): boolean {
  for (const specifier of input.imports.specifiers) {
    if (specifier.includes("prisma")) return true;
  }
  return false;
}

/** One model of a `schema.prisma` file. */
export interface PrismaModel {
  /** The model name as the schema declares it, e.g. `Booking`. */
  readonly name: string;
  /** The table it maps to: `@@map("bookings")`, or the model name. */
  readonly table: string;
  readonly line: number;
}

/** What a `schema.prisma` file declares. */
export interface PrismaSchema {
  readonly models: readonly PrismaModel[];
  readonly dialect: SchemaDialect;
}

/** Prisma providers, and the engine each one names. */
const PROVIDERS: Readonly<Record<string, SchemaDialect>> = {
  postgresql: "postgresql",
  postgres: "postgresql",
  cockroachdb: "postgresql",
  mysql: "mysql",
  sqlite: "sqlite",
  sqlserver: "mssql",
  mongodb: "mongodb",
};

/** Scalar types Prisma maps straight onto a column. */
const SCALARS = new Set([
  "String",
  "Boolean",
  "Int",
  "BigInt",
  "Float",
  "Decimal",
  "DateTime",
  "Json",
  "Bytes",
  "Unsupported",
]);

/** Splits a `schema.prisma` into its top-level blocks, keeping each one's line. */
function blocks(text: string): Array<{ kind: string; name: string; body: string; line: number }> {
  const found: Array<{ kind: string; name: string; body: string; line: number }> = [];
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const header = /^\s*(model|enum|datasource|generator|type|view)\s+([A-Za-z_][\w]*)\s*\{/.exec(
      lines[index] ?? "",
    );
    if (header === null) continue;
    let depth = 1;
    const body: string[] = [];
    let cursor = index + 1;
    while (cursor < lines.length && depth > 0) {
      const line = lines[cursor] ?? "";
      depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
      if (depth > 0) body.push(line);
      cursor += 1;
    }
    found.push({
      kind: header[1] ?? "",
      name: header[2] ?? "",
      body: body.join("\n"),
      line: index + 1,
    });
    index = cursor - 1;
  }
  return found;
}

/** The names inside a `[a, b]` attribute argument. */
function attributeList(argument: string): string[] {
  const list = /\[([^\]]*)\]/.exec(argument)?.[1] ?? argument;
  return list
    .split(",")
    .map((name) => bareIdentifier(name.replace(/\(.*$/, "")))
    .filter((name) => name !== "");
}

/**
 * Reads a `schema.prisma` into the schema model and returns the model→table
 * mapping the data-access pass needs.
 */
export function applyPrismaSchema(
  builder: SchemaBuilder,
  text: string,
  file: string,
): PrismaSchema {
  const parsed = blocks(text);
  const modelNames = new Set(
    parsed.filter((block) => block.kind === "model" || block.kind === "view").map((b) => b.name),
  );
  const models: PrismaModel[] = [];
  let dialect: SchemaDialect = "unknown";

  for (const block of parsed) {
    if (block.kind === "datasource") {
      const provider = /provider\s*=\s*"([\w-]+)"/.exec(block.body)?.[1] ?? "";
      dialect = PROVIDERS[provider] ?? dialect;
    }
  }

  builder.addSource(file);
  for (const block of parsed) {
    if (block.kind !== "model" && block.kind !== "view") continue;
    const bodyLines = block.body.split(/\r?\n/);
    const mapped = /@@map\(\s*"([^"]+)"\s*\)/.exec(block.body)?.[1];
    const table = mapped ?? block.name;
    models.push({ name: block.name, table, line: block.line });
    builder.table(table);
    builder.addEvidence(table, {
      file,
      line: block.line,
      note: `prisma model ${block.name}`,
    });

    /** Prisma field name → column name, for the `@@index` and `@@unique` lists. */
    const columnOf = new Map<string, string>();
    const relations: Array<{ fields: string[]; references: string[]; target: string }> = [];

    for (let offset = 0; offset < bodyLines.length; offset += 1) {
      const raw = (bodyLines[offset] ?? "").replace(/\/\/.*$/, "").trim();
      if (raw === "" || raw.startsWith("@@")) continue;
      const field = /^([A-Za-z_][\w]*)\s+([A-Za-z_][\w]*)(\[\])?(\?)?\s*(.*)$/.exec(raw);
      if (field === null) continue;
      const name = field[1] ?? "";
      const type = field[2] ?? "";
      const list = field[3] !== undefined;
      const optional = field[4] !== undefined;
      const attributes = field[5] ?? "";

      if (modelNames.has(type)) {
        const relation = /@relation\(([^)]*)\)/.exec(attributes)?.[1];
        if (relation?.includes("fields") === true) {
          const fields = attributeList(/fields\s*:\s*(\[[^\]]*\])/.exec(relation)?.[1] ?? "");
          const references = attributeList(
            /references\s*:\s*(\[[^\]]*\])/.exec(relation)?.[1] ?? "",
          );
          relations.push({ fields, references, target: type });
        }
        continue;
      }
      // A non-scalar that is not a model is an enum or a composite type, which
      // still occupies a column; anything lower-cased is not a Prisma type.
      if (!SCALARS.has(type) && !/^[A-Z]/.test(type)) continue;
      const columnName = /@map\(\s*"([^"]+)"\s*\)/.exec(attributes)?.[1] ?? name;
      const column = blankColumn(columnName, list ? `${type}[]` : type);
      column.nullable = optional;
      column.hasDefault = /@default\(/.test(attributes) || /@updatedAt\b/.test(attributes);
      column.isPrimaryKey = /@id\b/.test(attributes);
      column.isUnique = column.isPrimaryKey || /@unique\b/.test(attributes);
      if (column.isPrimaryKey) column.nullable = false;
      columnOf.set(name, columnName);
      builder.putColumn(table, column);
    }

    for (const relation of relations) {
      const columns = relation.fields.map((field) => columnOf.get(field) ?? field);
      if (columns.length === 0) continue;
      const targetTable =
        parsed.find((b) => b.name === relation.target && (b.kind === "model" || b.kind === "view"))
          ?.body ?? "";
      const targetName = /@@map\(\s*"([^"]+)"\s*\)/.exec(targetTable)?.[1] ?? relation.target;
      builder.addForeignKey(table, {
        name: "",
        columns,
        referencesTable: targetName,
        referencesColumns: relation.references,
      });
    }

    const attributePattern = /@@(index|unique|id)\s*\(([^)]*)\)/g;
    for (;;) {
      const match = attributePattern.exec(block.body);
      if (match === null) break;
      const kind = match[1] ?? "";
      const columns = attributeList(match[2] ?? "").map((field) => columnOf.get(field) ?? field);
      if (columns.length === 0) continue;
      if (kind === "id") builder.setPrimaryKey(table, columns);
      else if (kind === "unique") {
        builder.addUnique(table, { name: "", columns });
        builder.addIndex(table, { name: "", columns, unique: true, concurrent: false });
      } else builder.addIndex(table, { name: "", columns, unique: false, concurrent: false });
    }

    // A single-field `@unique`/`@id` is an index too; the audit asks about both.
    for (const column of builder.table(table).columns) {
      if (!column.isUnique) continue;
      builder.addIndex(table, {
        name: "",
        columns: [column.name],
        unique: true,
        concurrent: false,
      });
    }
  }

  return { models, dialect };
}

/** Model name (however the client spells it) → table name. */
export function prismaModelIndex(schemas: readonly PrismaSchema[]): Map<string, string> {
  const index = new Map<string, string>();
  for (const schema of schemas) {
    for (const model of schema.models) index.set(model.name.toLowerCase(), model.table);
  }
  return index;
}

/** Reads a Prisma `datasource` provider out of a schema without building a model. */
export function prismaDialect(text: string): SchemaDialect {
  const provider = /datasource\s+\w+\s*\{[^}]*provider\s*=\s*"([\w-]+)"/s.exec(text)?.[1] ?? "";
  return PROVIDERS[provider] ?? "unknown";
}

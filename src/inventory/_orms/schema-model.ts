/**
 * The schema model: tables, columns, keys, indexes and row-level security,
 * assembled from the migration history and the ORM schema files.
 *
 * This is the artifact that lets the audit say something no linter can: "three
 * queries filter `bookings` by `creator_id` and no index covers it", or "`orders`
 * has RLS enabled and no policy, so every read returns nothing — or everything,
 * depending on the role". It is deliberately lightweight: enough structure to
 * answer questions about the columns the code actually touches, not a
 * replacement for the database's own catalogue.
 */

import { z } from "zod";
import { CodeRefSchema, SCHEMA_VERSION } from "../../contracts/findings.ts";

/** Where a column points when it is a foreign key. */
export const ColumnReferenceSchema = z.object({
  table: z.string(),
  column: z.string(),
});
/** A single-column foreign key target. */
export type ColumnReference = z.infer<typeof ColumnReferenceSchema>;

export const SchemaColumnSchema = z.object({
  name: z.string(),
  /** The declared type, as written: `text`, `uuid`, `timestamp without time zone`. */
  type: z.string(),
  nullable: z.boolean(),
  hasDefault: z.boolean(),
  isPrimaryKey: z.boolean(),
  isUnique: z.boolean(),
  references: ColumnReferenceSchema.optional(),
});
/** One column of one table. */
export type SchemaColumn = z.infer<typeof SchemaColumnSchema>;

export const SchemaIndexSchema = z.object({
  name: z.string(),
  columns: z.array(z.string()),
  unique: z.boolean(),
  /** Postgres only: created with `CONCURRENTLY`, so it did not lock writes. */
  concurrent: z.boolean(),
});
/** One index, however it was declared. */
export type SchemaIndex = z.infer<typeof SchemaIndexSchema>;

export const SchemaForeignKeySchema = z.object({
  name: z.string(),
  columns: z.array(z.string()),
  referencesTable: z.string(),
  referencesColumns: z.array(z.string()),
  onDelete: z.string().optional(),
});
/** A table-level foreign key, possibly composite. */
export type SchemaForeignKey = z.infer<typeof SchemaForeignKeySchema>;

export const SchemaUniqueSchema = z.object({
  name: z.string(),
  columns: z.array(z.string()),
});
/** A table-level unique constraint. */
export type SchemaUnique = z.infer<typeof SchemaUniqueSchema>;

export const SchemaPolicySchema = z.object({
  name: z.string(),
  /** `SELECT`, `INSERT`, `UPDATE`, `DELETE` or `ALL`, as declared. */
  command: z.string(),
  /** The roles the policy applies to, when the statement names them. */
  roles: z.array(z.string()).default([]),
});
/** One row-level security policy. */
export type SchemaPolicy = z.infer<typeof SchemaPolicySchema>;

export const SchemaTableSchema = z.object({
  name: z.string(),
  columns: z.array(SchemaColumnSchema).default([]),
  primaryKey: z.array(z.string()).default([]),
  foreignKeys: z.array(SchemaForeignKeySchema).default([]),
  indexes: z.array(SchemaIndexSchema).default([]),
  uniqueConstraints: z.array(SchemaUniqueSchema).default([]),
  /** Postgres/Supabase: `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` was seen. */
  rlsEnabled: z.boolean().default(false),
  policies: z.array(SchemaPolicySchema).default([]),
  /** Where the table was declared or last altered; every entry is a real file:line. */
  evidence: z.array(CodeRefSchema).default([]),
});
/** One table of the reconstructed schema. */
export type SchemaTable = z.infer<typeof SchemaTableSchema>;

export const SchemaDialectSchema = z.enum([
  "postgresql",
  "mysql",
  "sqlite",
  "mssql",
  "mongodb",
  "unknown",
]);
/** The engine the schema targets; decides whether RLS and `CONCURRENTLY` apply. */
export type SchemaDialect = z.infer<typeof SchemaDialectSchema>;

export const SchemaModelDocumentSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  runId: z.string(),
  target: z.string(),
  dialect: SchemaDialectSchema,
  tables: z.array(SchemaTableSchema).default([]),
  /** Files the model was reconstructed from, in the order they were applied. */
  sources: z.array(z.string()).default([]),
  /** What could not be reconstructed, so a thin model never reads as a complete one. */
  warnings: z.array(z.string()).default([]),
});
/** The phase 2 artifact written to `schema-model.json`. */
export type SchemaModelDocument = z.infer<typeof SchemaModelDocumentSchema>;

/** The name `schema-model.json` is written under, inside the run directory. */
export const SCHEMA_MODEL_FILE = "schema-model.json";

/** Strips quoting and a schema qualifier: `public."Users"` → `Users`. */
export function bareIdentifier(raw: string): string {
  const trimmed = raw.trim().replace(/[;,]$/, "");
  const parts = trimmed.split(".");
  const last = parts[parts.length - 1] ?? trimmed;
  return last.replace(/^["'`[]+/, "").replace(/["'`\]]+$/, "");
}

/**
 * Accumulates a schema while migrations are replayed in order.
 *
 * Tables are keyed case-insensitively because an unquoted Postgres identifier
 * folds to lower case, so `Bookings` and `bookings` are the same table.
 */
export class SchemaBuilder {
  readonly #tables = new Map<string, SchemaTable>();
  readonly #sources: string[] = [];
  readonly #warnings: string[] = [];

  /** The table, created empty when this is the first statement that mentions it. */
  table(name: string): SchemaTable {
    const bare = bareIdentifier(name);
    const key = bare.toLowerCase();
    const existing = this.#tables.get(key);
    if (existing !== undefined) return existing;
    const created: SchemaTable = {
      name: bare,
      columns: [],
      primaryKey: [],
      foreignKeys: [],
      indexes: [],
      uniqueConstraints: [],
      rlsEnabled: false,
      policies: [],
      evidence: [],
    };
    this.#tables.set(key, created);
    return created;
  }

  /** True when the table has already been seen. */
  has(name: string): boolean {
    return this.#tables.has(bareIdentifier(name).toLowerCase());
  }

  /** Removes a table; a `DROP TABLE` in the history means it is not in the schema. */
  dropTable(name: string): void {
    this.#tables.delete(bareIdentifier(name).toLowerCase());
  }

  /** Adds or replaces a column, keeping the last declaration to win. */
  putColumn(table: string, column: SchemaColumn): void {
    const target = this.table(table);
    const index = target.columns.findIndex(
      (existing) => existing.name.toLowerCase() === column.name.toLowerCase(),
    );
    if (index === -1) target.columns.push(column);
    else target.columns[index] = column;
    if (column.isPrimaryKey && !target.primaryKey.includes(column.name)) {
      target.primaryKey.push(column.name);
    }
  }

  /** Applies a partial change to an existing column, e.g. a type or nullability alter. */
  patchColumn(table: string, column: string, patch: Partial<SchemaColumn>): void {
    const target = this.table(table);
    const existing = target.columns.find(
      (candidate) => candidate.name.toLowerCase() === bareIdentifier(column).toLowerCase(),
    );
    if (existing === undefined) {
      this.putColumn(table, {
        name: bareIdentifier(column),
        type: patch.type ?? "unknown",
        nullable: patch.nullable ?? true,
        hasDefault: patch.hasDefault ?? false,
        isPrimaryKey: patch.isPrimaryKey ?? false,
        isUnique: patch.isUnique ?? false,
        ...(patch.references === undefined ? {} : { references: patch.references }),
      });
      return;
    }
    Object.assign(existing, patch);
  }

  /** Removes a column that a migration dropped. */
  dropColumn(table: string, column: string): void {
    const target = this.table(table);
    const bare = bareIdentifier(column).toLowerCase();
    const index = target.columns.findIndex((candidate) => candidate.name.toLowerCase() === bare);
    if (index !== -1) target.columns.splice(index, 1);
    target.primaryKey = target.primaryKey.filter((name) => name.toLowerCase() !== bare);
  }

  /**
   * Records an index, replacing an earlier one with the same name.
   *
   * An index covering the same columns with the same uniqueness is the same
   * index however it was declared, so a column that is `@unique` in the Prisma
   * schema and `UNIQUE` in the migration is not listed twice.
   */
  addIndex(table: string, index: SchemaIndex): void {
    const target = this.table(table);
    const named = target.indexes.findIndex(
      (candidate) => candidate.name !== "" && candidate.name === index.name,
    );
    if (named !== -1) {
      target.indexes[named] = index;
      return;
    }
    const sameColumns = target.indexes.some(
      (candidate) =>
        candidate.unique === index.unique &&
        candidate.columns.length === index.columns.length &&
        candidate.columns.every(
          (column, position) =>
            column.toLowerCase() === (index.columns[position] ?? "").toLowerCase(),
        ),
    );
    if (sameColumns) return;
    target.indexes.push(index);
    if (index.unique && index.columns.length > 0) {
      target.uniqueConstraints.push({ name: index.name, columns: [...index.columns] });
    }
  }

  /** Drops an index by name, wherever it lives. */
  dropIndex(name: string): void {
    const bare = bareIdentifier(name);
    for (const table of this.#tables.values()) {
      table.indexes = table.indexes.filter((index) => index.name !== bare);
    }
  }

  /** Records a foreign key, and mirrors a single-column one onto the column itself. */
  addForeignKey(table: string, key: SchemaForeignKey): void {
    const target = this.table(table);
    target.foreignKeys.push(key);
    const [only] = key.columns;
    const [referenced] = key.referencesColumns;
    if (key.columns.length === 1 && only !== undefined && referenced !== undefined) {
      this.patchColumn(table, only, {
        references: { table: bareIdentifier(key.referencesTable), column: referenced },
      });
    }
  }

  /** Records a table-level unique constraint. */
  addUnique(table: string, unique: SchemaUnique): void {
    this.table(table).uniqueConstraints.push(unique);
  }

  /** Sets the primary key columns of a table. */
  setPrimaryKey(table: string, columns: readonly string[]): void {
    const target = this.table(table);
    target.primaryKey = columns.map(bareIdentifier);
    for (const column of target.columns) {
      column.isPrimaryKey = target.primaryKey.some(
        (name) => name.toLowerCase() === column.name.toLowerCase(),
      );
    }
  }

  /** Marks row-level security as enabled or disabled on a table. */
  setRls(table: string, enabled: boolean): void {
    this.table(table).rlsEnabled = enabled;
  }

  /** Records a row-level security policy. */
  addPolicy(table: string, policy: SchemaPolicy): void {
    this.table(table).policies.push(policy);
  }

  /** Adds a citation for where a table was declared or altered. */
  addEvidence(table: string, ref: { file: string; line: number; note?: string }): void {
    const target = this.table(table);
    if (target.evidence.length >= 8) return;
    if (target.evidence.some((entry) => entry.file === ref.file && entry.line === ref.line)) return;
    target.evidence.push({
      file: ref.file,
      line: ref.line,
      ...(ref.note === undefined ? {} : { note: ref.note }),
    });
  }

  /** Records a file the model was built from. */
  addSource(file: string): void {
    if (!this.#sources.includes(file)) this.#sources.push(file);
  }

  /** Records something the model could not reconstruct. */
  warn(message: string): void {
    if (!this.#warnings.includes(message)) this.#warnings.push(message);
  }

  /** Tables seen so far, name-sorted. */
  tables(): SchemaTable[] {
    return [...this.#tables.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Freezes the accumulated schema into the artifact shape. */
  build(input: { runId: string; target: string; dialect: SchemaDialect }): SchemaModelDocument {
    return {
      schemaVersion: SCHEMA_VERSION,
      runId: input.runId,
      target: input.target,
      dialect: input.dialect,
      tables: this.tables(),
      sources: [...this.#sources],
      warnings: [...this.#warnings],
    };
  }
}

/** A column with every flag at its default, for the parsers to fill in. */
export function blankColumn(name: string, type: string): SchemaColumn {
  return {
    name: bareIdentifier(name),
    type,
    nullable: true,
    hasDefault: false,
    isPrimaryKey: false,
    isUnique: false,
  };
}

/** Looks a table up case-insensitively, the way an unquoted identifier resolves. */
export function findTable(model: SchemaModelDocument, name: string): SchemaTable | undefined {
  const bare = bareIdentifier(name).toLowerCase();
  return model.tables.find((table) => table.name.toLowerCase() === bare);
}

/**
 * True when some index on the table leads with `column`.
 *
 * Leading, not merely present: a composite index on `(org_id, created_at)`
 * cannot serve a filter on `created_at` alone, and saying it could would turn
 * a real missing-index finding into a false negative.
 */
export function hasIndexOn(table: SchemaTable, column: string): boolean {
  const bare = bareIdentifier(column).toLowerCase();
  if (table.primaryKey.some((name) => name.toLowerCase() === bare)) return true;
  if (table.columns.some((entry) => entry.name.toLowerCase() === bare && entry.isUnique)) {
    return true;
  }
  if (table.uniqueConstraints.some((unique) => (unique.columns[0] ?? "").toLowerCase() === bare)) {
    return true;
  }
  return table.indexes.some((index) => (index.columns[0] ?? "").toLowerCase() === bare);
}

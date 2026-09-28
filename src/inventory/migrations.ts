/**
 * Phase 2, domain D3: every migration in the repository, and the schema they
 * add up to.
 *
 * Two artifacts come out of one read of the migration history. The first is a
 * unit per migration file, carrying what it does and how it does it — whether
 * it drops something, whether it takes a lock a production table cannot
 * afford, whether it can be rolled back, whether it mixes a backfill into a
 * schema change. The second is `schema-model.json`: the tables, columns, keys,
 * indexes and row-level security the migrations leave behind, which is what
 * lets the audit say that a column three queries filter by has no index.
 *
 * Both come from replaying the history in order. A `DROP TABLE` in migration
 * 12 means the table is not in the schema, whatever migration 3 created — so
 * the model describes the database as it is now, not as the first migration
 * imagined it.
 */

import { join } from "node:path";
import type { AuditUnitKind } from "../contracts/inventory.ts";
import type { StackProfile } from "../contracts/profile.ts";
import {
  type AstGrepContext,
  type AstMatch,
  type AstRule,
  contains,
  runAstGrep,
} from "./_orms/_ast.ts";
import { stringLiteral } from "./_orms/_chain.ts";
import { CONTEXT_RULES, type FileContext, buildFileContexts } from "./_orms/_context.ts";
import {
  type LockRisk,
  type SqlOperation,
  type SqlStatement,
  analyseSql,
  applyStatement,
  splitSqlStatements,
  worseLockRisk,
} from "./_orms/_sql.ts";
import {
  DRIZZLE_SCHEMA_RULE,
  type DrizzleTableDeclaration,
  applyDrizzleTables,
  readDrizzleTables,
} from "./_orms/drizzle.ts";
import { applyPrismaSchema } from "./_orms/prisma.ts";
import {
  SCHEMA_MODEL_FILE,
  SchemaBuilder,
  type SchemaDialect,
  type SchemaModelDocument,
  SchemaModelDocumentSchema,
} from "./_orms/schema-model.ts";
import {
  type SchemaSnapshot,
  findPrismaSchemas,
  isIgnoredPath,
  readSources,
} from "./_orms/schema-sources.ts";
import {
  type DraftUnit,
  type EnumerationContext,
  type EnumerationOutcome,
  type InventoryEnumerator,
  degraded,
  enumerated,
  joinReasons,
  notApplicable,
} from "./_unit-support.ts";

/** The `AuditUnit.kind` every unit this module produces carries. */
export const MIGRATION_KIND: AuditUnitKind = "migration";

/** The migration tools phase 2 can read. */
export type MigrationTool = "prisma" | "drizzle" | "knex" | "typeorm" | "supabase" | "raw-sql";

/** One migration file, classified and ordered. */
export interface MigrationFile {
  /** Repo-relative POSIX path. */
  readonly file: string;
  readonly tool: MigrationTool;
  /** 1-based position in its tool's history. */
  readonly ordinal: number;
  /** The timestamp or sequence the file name carries, when it carries one. */
  readonly version: string;
  readonly text: string;
}

/** Everything the migration pass needs; `EnumerationContext` satisfies it. */
export interface MigrationsContext extends AstGrepContext {
  readonly snapshot: SchemaSnapshot;
  readonly profile?: StackProfile | undefined;
  /** Identifies the run inside `schema-model.json`. */
  readonly runId?: string | undefined;
}

/** Options for {@link scanMigrations}. */
export interface MigrationsOptions {
  /**
   * Drizzle schema objects the data-access pass already found. Passing them
   * avoids a second ast-grep pass over the repository.
   */
  readonly drizzleTables?: readonly DrizzleTableDeclaration[] | undefined;
  /** Overrides the dialect the profile proved. */
  readonly dialect?: SchemaDialect | undefined;
}

/** What the migration pass enumerated, and the schema it reconstructed. */
export interface MigrationsScan {
  readonly outcome: EnumerationOutcome;
  /** The `schema-model.json` payload; always Zod-valid. */
  readonly schema: SchemaModelDocument;
  readonly files: readonly MigrationFile[];
}

/** The enumerator phase 2 registers for domain D3's migrations. */
export const migrationEnumerator: InventoryEnumerator = {
  name: "migrations",
  kinds: [MIGRATION_KIND],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    return (await scanMigrations(ctx)).outcome;
  },
};

/** Registered by `defaultEnumerators()`; a list, for symmetry with the other groups. */
export const MIGRATION_ENUMERATORS: readonly InventoryEnumerator[] = [migrationEnumerator];

/**
 * Memo per context object.
 *
 * The enumerator wants the units and the phase wants `schema-model.json`, and
 * both come from the same replay. Keying on the context means the second
 * caller gets the first one's work instead of re-reading every migration.
 */
const scans = new WeakMap<object, Promise<MigrationsScan>>();

/** Enumerates the migrations and reconstructs the schema, once per context. */
export function scanMigrations(
  ctx: MigrationsContext,
  options: MigrationsOptions = {},
): Promise<MigrationsScan> {
  const cached = scans.get(ctx);
  if (cached !== undefined) return cached;
  const scan = runScan(ctx, options);
  scans.set(ctx, scan);
  return scan;
}

/** The schema model alone, for the phase that writes `schema-model.json`. */
export async function buildSchemaModel(
  ctx: MigrationsContext,
  options: MigrationsOptions = {},
): Promise<SchemaModelDocument> {
  return (await scanMigrations(ctx, options)).schema;
}

/** The filesystem operation writing the artifact needs. */
export interface SchemaModelWriter {
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
}

/**
 * The last line of a migration script, which is its extent.
 *
 * A trailing newline does not add a line: the range has to resolve against the
 * file on disk, and the citation verifier counts lines the same way.
 */
function lineCountOf(text: string): number {
  if (text === "") return 1;
  const lines = text.split("\n");
  const last = lines[lines.length - 1];
  return last === "" && lines.length > 1 ? lines.length - 1 : lines.length;
}

/** Writes `schema-model.json` into the run directory and returns its path. */
export async function writeSchemaModel(
  fs: SchemaModelWriter,
  runDir: string,
  model: SchemaModelDocument,
): Promise<string> {
  const path = join(runDir, SCHEMA_MODEL_FILE);
  await fs.writeFile(path, `${JSON.stringify(SchemaModelDocumentSchema.parse(model), null, 2)}\n`);
  return path;
}

/** Builder methods a JS/TS migration calls, and the operation each one is. */
const BUILDER_OPERATIONS: Readonly<Record<string, SqlOperation>> = {
  createTable: "create-table",
  createTableIfNotExists: "create-table",
  createTableLike: "create-table",
  dropTable: "drop-table",
  dropTableIfExists: "drop-table",
  renameTable: "rename",
  renameColumn: "rename",
  addColumn: "add-column",
  addColumns: "add-column",
  dropColumn: "drop-column",
  dropColumns: "drop-column",
  createIndex: "add-index",
  addIndex: "add-index",
  index: "add-index",
  dropIndex: "drop-index",
  unique: "add-constraint",
  addUniqueConstraint: "add-constraint",
  foreign: "add-constraint",
  addForeignKey: "add-constraint",
  createForeignKey: "add-constraint",
  createPrimaryKey: "add-constraint",
  dropUnique: "drop-constraint",
  dropForeign: "drop-constraint",
  dropConstraint: "drop-constraint",
  createCheckConstraint: "add-constraint",
  insert: "backfill",
  update: "backfill",
  del: "backfill",
  delete: "backfill",
  truncate: "truncate",
};

/** Column declarations inside a Knex table callback. */
const COLUMN_METHODS = new Set([
  "string",
  "text",
  "integer",
  "bigInteger",
  "boolean",
  "date",
  "dateTime",
  "datetime",
  "timestamp",
  "timestamps",
  "uuid",
  "jsonb",
  "json",
  "decimal",
  "float",
  "double",
  "binary",
  "enu",
  "enum",
  "specificType",
  "increments",
  "bigIncrements",
]);

/** Receiver names of a Knex table-builder callback, whose arguments are columns. */
const TABLE_BUILDER_RECEIVER = /^(table|t|tbl|builder|col|column)$/;

/** Methods that are read but are not operations of their own. */
const MODIFIERS = ["raw", "query", "alterTable", "table", "alter", "notNullable", "defaultTo"];

/** The rule that enumerates builder calls in a JS/TS migration. */
const BUILDER_RULE: AstRule = {
  id: "mig.call",
  rule: { pattern: "$RECEIVER.$METHOD($$$ARGS)" },
  constraints: {
    METHOD: {
      regex: `^(${[...Object.keys(BUILDER_OPERATIONS), ...COLUMN_METHODS, ...MODIFIERS].join("|")})$`,
    },
  },
};

/** The rule that spots `exports.down = ...` in a CommonJS migration. */
const EXPORT_RULE: AstRule = {
  id: "mig.export",
  rule: { pattern: "$OBJECT.$NAME = $VALUE" },
  constraints: { NAME: { regex: "^(up|down)$" } },
};

/** The uncached body of {@link scanMigrations}. */
async function runScan(
  ctx: MigrationsContext,
  options: MigrationsOptions,
): Promise<MigrationsScan> {
  const builder = new SchemaBuilder();
  const dialect = options.dialect ?? dialectOf(ctx.profile);
  const files = await discoverMigrations(ctx);

  const scripted = files.filter((file) => !file.file.endsWith(".sql"));
  const astRun =
    scripted.length === 0
      ? null
      : await runAstGrep(ctx, [BUILDER_RULE, EXPORT_RULE, ...CONTEXT_RULES], {
          paths: scripted.map((file) => file.file),
        });

  const builderCalls = new Map<string, AstMatch[]>();
  const exported = new Map<string, Set<string>>();
  for (const match of astRun?.matches ?? []) {
    if (match.ruleId === BUILDER_RULE.id) {
      const existing = builderCalls.get(match.file);
      if (existing === undefined) builderCalls.set(match.file, [match]);
      else existing.push(match);
      continue;
    }
    if (match.ruleId === EXPORT_RULE.id) {
      const name = match.meta.NAME ?? "";
      const existing = exported.get(match.file);
      if (existing === undefined) exported.set(match.file, new Set([name]));
      else existing.add(name);
    }
  }
  const contexts = buildFileContexts(astRun?.matches ?? []);
  const known = new Set(files.map((file) => file.file));

  const units: DraftUnit[] = [];
  for (const migration of files) {
    const calls = builderCalls.get(migration.file) ?? [];
    const analysis = migration.file.endsWith(".sql")
      ? analyseSqlMigration(builder, migration)
      : analyseScriptMigration(
          builder,
          migration,
          forwardCalls(calls, contexts.get(migration.file)),
        );

    const names = new Set([
      ...(contexts.get(migration.file)?.functions.map((fn) => fn.name) ?? []),
      ...(exported.get(migration.file) ?? []),
    ]);
    const hasDown = names.has("down") || hasDownSibling(migration, known);

    // A migration unit *is* the whole script. Its citation points at the most
    // interesting statement, but the extent has to cover the file: the checks
    // ask whether a destructive statement has a guard and whether a data
    // migration accompanies a column drop, and both are questions about
    // statements other than the cited one. Without this the slicer resolved the
    // block around the citation — the first `CREATE TABLE (...)` and nothing
    // else — so the model was asked about a migration it had not been shown,
    // and cited line 1 for a `DROP COLUMN` twelve lines further down.
    const lastLine = lineCountOf(migration.text);

    // …and the *start* of the extent has to cover the file's first statement,
    // not the first statement `up()` makes. `analysis.line` is deliberately the
    // first forward statement, which is the right thing to cite; but a file
    // that declares `down()` above `up()` puts real statements above it, and
    // phase 2 folds a query into the unit around it by span. A statement
    // outside the span is not folded, so it is enumerated a second time as a
    // `data-access` unit with no migration around it — the exact double count
    // containment exists to remove.
    const firstLine = calls.reduce((first, call) => Math.min(first, call.startLine), analysis.line);

    units.push({
      kind: MIGRATION_KIND,
      label: `${migration.tool} migration ${migration.version || String(migration.ordinal)}`,
      file: migration.file,
      line: firstLine,
      ...(lastLine > firstLine ? { endLine: lastLine } : {}),
      // A migration is identified by its tool and its version, never by its
      // ordinal: inserting a migration must not rename every later one.
      symbol: `${migration.tool}:${migration.version || basenameOf(migration.file)}`,
      ...(analysis.lockDetail === null ? {} : { note: analysis.lockDetail }),
      attributes: {
        tool: migration.tool,
        ordinal: String(migration.ordinal),
        version: migration.version === "" ? undefined : migration.version,
        operations: analysis.operations.join(","),
        destructive: String(analysis.destructive),
        lockRisk: analysis.lockRisk,
        hasDownMigration: String(hasDown),
        mixesDataAndSchema: String(analysis.touchesSchema && analysis.touchesData),
        tables: analysis.tables.join(","),
        statements: String(analysis.statementCount),
      },
    });
  }

  const applied = await applySchemaFiles(ctx, builder, options);
  const warnings = applied.warnings;
  const schema = SchemaModelDocumentSchema.parse(
    builder.build({
      runId: ctx.runId ?? "unknown",
      target: ctx.targetDir,
      // The Prisma datasource names the engine when phase 0 could not.
      dialect: dialect === "unknown" ? applied.dialect : dialect,
    }),
  );

  if (files.length === 0 && schema.tables.length === 0) {
    return {
      outcome: notApplicable("the repository has no migrations and no ORM schema file"),
      schema,
      files,
    };
  }

  const reason = joinReasons([astRun?.reason, ...warnings]);
  const outcome =
    astRun !== null && astRun.status !== "ok"
      ? degraded(units, reason ?? "the migration scripts could not be read structurally")
      : enumerated(units, reason);
  return { outcome, schema, files };
}

/**
 * The calls the migration makes on the way *up*.
 *
 * A `down()` that drops the column `up()` added is a rollback, not a
 * destructive migration, and counting it would mark every reversible migration
 * as data loss. When the file declares an `up`, only what it does counts.
 */
function forwardCalls(
  calls: readonly AstMatch[],
  context: FileContext | undefined,
): readonly AstMatch[] {
  const up = context?.functions.find((fn) => fn.name === "up");
  if (up === undefined) return calls;
  return calls.filter((call) => contains(up, call));
}

/** The base name of a path, used as the identity of an unversioned migration. */
function basenameOf(file: string): string {
  return file.split("/").pop() ?? file;
}

/** The engine the profile proved, mapped onto the dialects the model knows. */
export function dialectOf(profile: StackProfile | undefined): SchemaDialect {
  if (profile === undefined) return "unknown";
  const engines = profile.facts
    .filter((fact) => fact.kind === "database-engine")
    .map((fact) => fact.value);
  for (const engine of ["postgresql", "mysql", "sqlite", "mssql", "mongodb"] as const) {
    if (engines.includes(engine)) return engine;
  }
  return "unknown";
}

/** The version a migration file name carries: `20240117093000_add_index`. */
export function versionOf(file: string): string {
  const base = basenameOf(file);
  const directory = file.split("/").at(-2) ?? "";
  // Prisma names the directory, not the file: `20240117093000_add_index/migration.sql`.
  const source = base === "migration.sql" ? directory : base;
  return /^(\d{4,})/.exec(source)?.[1] ?? "";
}

/** True when a path looks like a migration this module can read. */
export function looksLikeMigration(path: string): boolean {
  if (isIgnoredPath(path)) return false;
  if (path.endsWith(".d.ts")) return false;
  if (/(^|\/)index\.(ts|js|cjs|mjs)$/.test(path)) return false;
  const segments = path.split("/");
  const inMigrationsDir = segments.slice(0, -1).includes("migrations");
  if (path.endsWith(".sql")) return inMigrationsDir || /(^|\/)drizzle\//.test(path);
  return inMigrationsDir && /\.(ts|js|cjs|mjs)$/.test(path);
}

/** Reads every migration file in the repository, ordered per tool. */
export async function discoverMigrations(ctx: MigrationsContext): Promise<MigrationFile[]> {
  const fromProfile = (ctx.profile?.facts ?? [])
    .filter((fact) => fact.kind === "migrations-dir")
    .map((fact) => `${fact.value}/`);
  const drizzleDirs = ctx.snapshot.files
    .filter((file) => file.endsWith("/meta/_journal.json"))
    .map((file) => file.replace(/\/meta\/_journal\.json$/, ""));

  const candidates = ctx.snapshot.files
    .filter(
      (file) =>
        looksLikeMigration(file) ||
        (fromProfile.some((dir) => file.startsWith(dir)) && /\.(sql|ts|js|cjs|mjs)$/.test(file)),
    )
    .filter((file) => !isIgnoredPath(file) && !file.endsWith(".d.ts"))
    .sort();

  const migrations: MigrationFile[] = [];
  for (const path of candidates) {
    const text = await ctx.snapshot.read(path);
    if (text === undefined) continue;
    migrations.push({
      file: path,
      tool: classify(path, text, drizzleDirs),
      ordinal: 0,
      version: versionOf(path),
      text,
    });
  }

  // The ordinal is the position in that tool's own history, which is what a
  // reader means by "the third migration".
  const counters = new Map<MigrationTool, number>();
  return migrations
    .sort((a, b) => a.version.localeCompare(b.version) || a.file.localeCompare(b.file))
    .map((migration) => {
      const next = (counters.get(migration.tool) ?? 0) + 1;
      counters.set(migration.tool, next);
      return { ...migration, ordinal: next };
    })
    .sort((a, b) => a.file.localeCompare(b.file));
}

/** Decides which tool wrote a migration, from where it lives and what it says. */
export function classify(
  path: string,
  text: string,
  drizzleDirs: readonly string[] = [],
): MigrationTool {
  if (/(^|\/)prisma\/migrations\//.test(path)) return "prisma";
  if (/(^|\/)supabase\/migrations\//.test(path)) return "supabase";
  if (drizzleDirs.some((dir) => path.startsWith(`${dir}/`))) return "drizzle";
  if (path.endsWith(".sql")) return /(^|\/)drizzle\//.test(path) ? "drizzle" : "raw-sql";
  if (/MigrationInterface|queryRunner/.test(text)) return "typeorm";
  return "knex";
}

/** What one migration file was found to do. */
interface MigrationAnalysis {
  readonly operations: readonly SqlOperation[];
  readonly destructive: boolean;
  readonly lockRisk: LockRisk;
  readonly lockDetail: string | null;
  readonly touchesSchema: boolean;
  readonly touchesData: boolean;
  readonly tables: readonly string[];
  readonly statementCount: number;
  /** The line the unit cites: the first statement that does something. */
  readonly line: number;
}

/** Operations that lose data. */
const DESTRUCTIVE = new Set<SqlOperation>([
  "drop-column",
  "drop-table",
  "truncate",
  "drop-constraint",
  "drop-policy",
  "disable-rls",
]);

/** Operations that change the shape of the schema. */
const SCHEMA_CHANGING = new Set<SqlOperation>([
  "create-table",
  "add-column",
  "drop-column",
  "drop-table",
  "alter-type",
  "alter-column",
  "rename",
  "add-index",
  "drop-index",
  "add-constraint",
  "drop-constraint",
]);

/** Reads a `.sql` migration: classify every statement and replay it onto the schema. */
function analyseSqlMigration(builder: SchemaBuilder, migration: MigrationFile): MigrationAnalysis {
  const statements = splitSqlStatements(migration.text);
  const analysis = analyseSql(statements);
  builder.addSource(migration.file);
  for (const statement of statements) {
    applyStatement(builder, statement, { file: migration.file, line: 1 });
  }
  return {
    operations: analysis.operations,
    destructive: analysis.destructive,
    lockRisk: analysis.lockRisk,
    lockDetail: analysis.lockDetail,
    touchesSchema: analysis.touchesSchema,
    touchesData: analysis.touchesData,
    tables: analysis.tables,
    statementCount: statements.length,
    line: firstStatementLine(statements),
  };
}

/** The line of the first statement, so the unit cites SQL rather than a comment header. */
function firstStatementLine(statements: readonly SqlStatement[]): number {
  return statements[0]?.line ?? 1;
}

/**
 * Reads a JS/TS migration.
 *
 * The builder calls come from ast-grep, and any SQL the migration hands to
 * `queryRunner.query` or `knex.raw` goes through the same SQL reader the
 * `.sql` migrations use — which is how a TypeORM migration still contributes
 * its tables and indexes to the schema model.
 */
function analyseScriptMigration(
  builder: SchemaBuilder,
  migration: MigrationFile,
  calls: readonly AstMatch[],
): MigrationAnalysis {
  const operations: SqlOperation[] = [];
  const tables: string[] = [];
  let lockRisk: LockRisk = "none";
  let lockDetail: string | null = null;
  let statementCount = 0;
  let line = 1;
  let inAlter = false;

  const record = (operation: SqlOperation): void => {
    if (!operations.includes(operation)) operations.push(operation);
  };
  const recordTable = (table: string | null): void => {
    if (table !== null && table !== "" && !tables.includes(table)) tables.push(table);
  };
  const worsen = (risk: LockRisk, detail: string): void => {
    const worse = worseLockRisk(lockRisk, risk);
    if (worse === lockRisk) return;
    lockRisk = worse;
    lockDetail = detail;
  };

  for (const call of calls) {
    const method = call.meta.METHOD ?? "";
    const [first] = call.metaList.ARGS ?? [];
    // Inside `alterTable("t", (table) => ...)` the receiver is the builder, and
    // its first argument is a *column* — recording it as a table would invent one.
    const onBuilder = TABLE_BUILDER_RECEIVER.test(call.meta.RECEIVER ?? "");
    if (line === 1 && call.startLine > 1) line = call.startLine;

    if (method === "raw" || method === "query") {
      const sql = first === undefined ? "" : (stringLiteral(first) ?? stripTemplate(first));
      if (sql.trim() === "") continue;
      const statements = splitSqlStatements(sql);
      statementCount += statements.length;
      const analysis = analyseSql(statements);
      for (const operation of analysis.operations) record(operation);
      for (const table of analysis.tables) recordTable(table);
      if (analysis.lockRisk !== "none") {
        worsen(analysis.lockRisk, analysis.lockDetail ?? "the statement takes a lock");
      }
      for (const statement of statements) {
        applyStatement(builder, statement, { file: migration.file, line: call.startLine });
      }
      continue;
    }

    if (method === "alterTable" || method === "table") {
      inAlter = true;
      recordTable(first === undefined ? null : stringLiteral(first));
      record("alter-column");
      continue;
    }
    if (method === "alter") {
      worsen("type-rewrite", "a column altered in place rewrites the table");
      record("alter-type");
      continue;
    }
    if (COLUMN_METHODS.has(method)) {
      if (inAlter) record("add-column");
      continue;
    }

    const operation = BUILDER_OPERATIONS[method];
    if (operation === undefined) continue;
    statementCount += 1;
    record(operation);
    const table = first === undefined || onBuilder ? null : stringLiteral(first);
    recordTable(table);
    if (operation === "create-table" && table !== null) {
      builder.table(table);
      builder.addSource(migration.file);
      builder.addEvidence(table, {
        file: migration.file,
        line: call.startLine,
        note: `created by a ${migration.tool} migration`,
      });
    }
    if (operation === "add-index" && table !== null) {
      builder.addIndex(table, { name: "", columns: [], unique: false, concurrent: false });
      worsen(
        "create-index-without-concurrently",
        "the query builder issues CREATE INDEX without CONCURRENTLY",
      );
    }
    if (operation === "drop-table" && table !== null) builder.dropTable(table);
  }

  // `.notNullable().defaultTo(...)` on a column added to an existing table is
  // the classic locking migration, whichever builder wrote it.
  const methods = new Set(calls.map((call) => call.meta.METHOD ?? ""));
  if (inAlter && methods.has("notNullable") && methods.has("defaultTo")) {
    worsen(
      "add-not-null-with-default",
      "a NOT NULL column with a default added to an existing table rewrites it",
    );
  }

  return {
    operations,
    destructive: operations.some((operation) => DESTRUCTIVE.has(operation)),
    lockRisk,
    lockDetail,
    touchesSchema: operations.some((operation) => SCHEMA_CHANGING.has(operation)),
    touchesData: operations.includes("backfill") || operations.includes("truncate"),
    tables,
    statementCount,
    line,
  };
}

/** Strips the backticks of a template literal, keeping the SQL between them. */
function stripTemplate(text: string): string {
  const trimmed = text.trim();
  if (!trimmed.startsWith("`")) return trimmed;
  return trimmed.slice(1, trimmed.endsWith("`") ? -1 : undefined);
}

/** True when a `.sql` migration ships a companion rollback file. */
function hasDownSibling(migration: MigrationFile, known: ReadonlySet<string>): boolean {
  if (!migration.file.endsWith(".sql")) return false;
  return [
    migration.file.replace(/\.sql$/, ".down.sql"),
    migration.file.replace(/\/migration\.sql$/, "/down.sql"),
    migration.file.replace(/(^|\/)up\.sql$/, "$1down.sql"),
  ].some((candidate) => candidate !== migration.file && known.has(candidate));
}

/** Folds the ORM schema files into the model, after the migrations have run. */
async function applySchemaFiles(
  ctx: MigrationsContext,
  builder: SchemaBuilder,
  options: MigrationsOptions,
): Promise<{ warnings: string[]; dialect: SchemaDialect }> {
  const warnings: string[] = [];
  let dialect: SchemaDialect = "unknown";

  const { sources, unreadable } = await readSources(ctx.snapshot, findPrismaSchemas(ctx.snapshot));
  for (const source of sources) {
    const parsed = applyPrismaSchema(builder, source.text, source.file);
    if (dialect === "unknown") dialect = parsed.dialect;
  }
  if (unreadable.length > 0) {
    warnings.push(`${unreadable.length} prisma schema file(s) could not be read`);
  }

  const drizzle = options.drizzleTables ?? (await collectDrizzleTables(ctx));
  if (drizzle.length > 0) applyDrizzleTables(builder, drizzle);

  if (builder.tables().length === 0) {
    builder.warn(
      "no tables could be reconstructed: the repository has no SQL migrations and no Drizzle or Prisma schema file",
    );
  }
  return { warnings, dialect };
}

/** Runs the Drizzle schema query alone, for a caller that has not run it already. */
async function collectDrizzleTables(
  ctx: MigrationsContext,
): Promise<readonly DrizzleTableDeclaration[]> {
  const run = await runAstGrep(ctx, [DRIZZLE_SCHEMA_RULE]);
  return run.status === "failed" || run.status === "skipped" ? [] : readDrizzleTables(run.matches);
}

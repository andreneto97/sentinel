/**
 * Drizzle: `db.select().from(bookings).where(eq(bookings.orgId, orgId))`.
 *
 * Drizzle names its tables with schema *objects*, not strings, so the table a
 * query reads is only knowable by resolving the variable against the schema
 * file — which is also where the columns, the foreign keys and the indexes
 * come from. Both jobs are done here, from the same ast-grep pass.
 */

import type { AstMatch, AstRule } from "./_ast.ts";
import { findSegment, objectEntries, parseChain, stringLiteral } from "./_chain.ts";
import { dedupe, expressionFilter, facts, firstStringArgument, isPlainReceiver } from "./_claim.ts";
import { type SchemaBuilder, bareIdentifier, blankColumn } from "./schema-model.ts";
import type { ClaimInput, DataAccessFacts, DataOperation, OrmExtractor } from "./types.ts";

/** Receivers that are plainly not a Drizzle database handle. */
const NOT_A_DB = /^(?:res|response|req|request|array|list|rows|items|Object|JSON|Math)$/;

/** The builder entry points, and the operation each one opens. */
const ENTRY_OPERATIONS: Readonly<Record<string, DataOperation>> = {
  select: "select",
  selectDistinct: "select",
  insert: "insert",
  update: "update",
  delete: "delete",
  execute: "raw",
  run: "raw",
  all: "raw",
  get: "raw",
};

/** Drizzle's relational query API: `db.query.users.findMany(...)`. */
const QUERY_OPERATIONS: Readonly<Record<string, DataOperation>> = {
  findMany: "select",
  findFirst: "select",
};

/** A `pgTable("name", { ... })` declaration found in a schema file. */
export interface DrizzleTableDeclaration {
  /** The variable the table is bound to, which is what queries name. */
  readonly variable: string;
  /** The SQL table name from the first argument. */
  readonly table: string;
  readonly file: string;
  readonly line: number;
  /** The declarator's source text, for the column and index parse. */
  readonly text: string;
}

/**
 * Matches `export const users = pgTable("users", {...})` in any schema file.
 *
 * The pattern needs a `context` and a `selector`: `$VAR = $FACTORY(...)` on its
 * own parses as an assignment, and a table declaration is a variable
 * declarator, so the bare pattern matches nothing at all.
 */
export const DRIZZLE_SCHEMA_RULE: AstRule = {
  id: "schema.drizzle.table",
  rule: {
    pattern: {
      context: "const $VAR = $FACTORY($NAME, $$$REST)",
      selector: "variable_declarator",
    },
  },
  constraints: {
    FACTORY: { regex: "^(pgTable|mysqlTable|sqliteTable|pgView|table)$" },
    NAME: { kind: "string" },
  },
};

/** Reads the table declarations out of one ast-grep pass. */
export function readDrizzleTables(matches: readonly AstMatch[]): DrizzleTableDeclaration[] {
  const declarations: DrizzleTableDeclaration[] = [];
  for (const match of matches) {
    if (match.ruleId !== DRIZZLE_SCHEMA_RULE.id) continue;
    const variable = match.meta.VAR ?? "";
    const name = stringLiteral(match.meta.NAME ?? "");
    if (variable === "" || name === null) continue;
    declarations.push({
      variable,
      table: name,
      file: match.file,
      line: match.startLine,
      text: match.text,
    });
  }
  return declarations;
}

/** Column helpers whose presence means the column has a server-side default. */
const DEFAULT_SEGMENTS = new Set([
  "default",
  "defaultNow",
  "defaultRandom",
  "$defaultFn",
  "generatedAlwaysAs",
]);

/** The SQL name and flags of one `columnName: uuid("column_name").notNull()` entry. */
function readColumn(property: string, definition: string) {
  const chain = parseChain(definition);
  const [first] = chain.segments;
  const sqlName = firstStringArgument(first) ?? property;
  const column = blankColumn(sqlName, chain.base === "" ? "unknown" : chain.base);
  for (const segment of chain.segments) {
    if (segment.name === "notNull") column.nullable = false;
    if (segment.name === "primaryKey") {
      column.isPrimaryKey = true;
      column.nullable = false;
      column.isUnique = true;
    }
    if (segment.name === "unique") column.isUnique = true;
    if (DEFAULT_SEGMENTS.has(segment.name)) column.hasDefault = true;
    if (segment.name === "references") {
      // `references(() => users.id)` — the arrow's body names table and column.
      const target = /([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)/.exec(segment.argsText);
      if (target !== null) {
        column.references = { table: target[1] ?? "", column: target[2] ?? "id" };
      }
    }
  }
  return { property, column };
}

/**
 * Replays the Drizzle schema files onto the schema model: columns, primary
 * keys, foreign keys and the indexes declared in the table's extra config.
 */
export function applyDrizzleTables(
  builder: SchemaBuilder,
  declarations: readonly DrizzleTableDeclaration[],
): void {
  /** Variable → SQL table, so a `references(() => users.id)` resolves. */
  const byVariable = new Map<string, string>();
  for (const declaration of declarations) byVariable.set(declaration.variable, declaration.table);

  for (const declaration of declarations) {
    builder.table(declaration.table);
    builder.addSource(declaration.file);
    builder.addEvidence(declaration.table, {
      file: declaration.file,
      line: declaration.line,
      note: "drizzle table definition",
    });
    const chain = parseChain(declaration.text.replace(/^[^=]*=\s*/, ""));
    const [call] = chain.segments;
    if (call === undefined) continue;
    const [, columnsArg, extrasArg] = call.args;
    if (columnsArg === undefined) continue;

    /** Property name → SQL column name, for the index declarations below. */
    const columnNames = new Map<string, string>();
    for (const entry of objectEntries(columnsArg)) {
      if (entry.key === "..." || entry.key === "[]") continue;
      const { column } = readColumn(entry.key, entry.value);
      columnNames.set(entry.key, column.name);
      if (column.references !== undefined) {
        const target = byVariable.get(column.references.table) ?? column.references.table;
        column.references = { table: target, column: column.references.column };
        builder.putColumn(declaration.table, column);
        builder.addForeignKey(declaration.table, {
          name: "",
          columns: [column.name],
          referencesTable: target,
          referencesColumns: [column.references.column],
        });
        continue;
      }
      builder.putColumn(declaration.table, column);
    }
    // A unique column is an index; the audit asks "is this column indexed?"
    // and must get the same answer whichever way the schema declared it.
    for (const column of builder.table(declaration.table).columns) {
      if (!column.isUnique) continue;
      builder.addIndex(declaration.table, {
        name: "",
        columns: [column.name],
        unique: true,
        concurrent: false,
      });
    }

    if (extrasArg === undefined) continue;

    const resolve = (reference: string): string => {
      const property = /\.\s*([A-Za-z_$][\w$]*)/.exec(reference)?.[1] ?? bareIdentifier(reference);
      return columnNames.get(property) ?? property;
    };
    for (const entry of objectEntries(
      extrasArg.replace(/^[^=]*=>\s*/, "").replace(/^\(|\)$/g, ""),
    )) {
      const value = parseChain(entry.value);
      const unique = value.base === "uniqueIndex" || value.base === "unique";
      if (value.base === "index" || unique) {
        const on = findSegment(value, "on", "using");
        builder.addIndex(declaration.table, {
          name: firstStringArgument(value.segments[0]) ?? entry.key,
          columns: (on?.args ?? []).map(resolve),
          unique,
          concurrent: false,
        });
        continue;
      }
      if (value.base === "primaryKey") {
        const columns = [...(value.segments[0]?.args ?? [])];
        const listed = columns.flatMap((argument) => {
          const inner = objectEntries(argument).find((item) => item.key === "columns");
          return inner === undefined ? [argument] : inner.value.replace(/^\[|\]$/g, "").split(",");
        });
        builder.setPrimaryKey(declaration.table, dedupe(listed.map(resolve)));
      }
    }
  }
}

/** Drizzle's data-access call sites. */
export const drizzleExtractor: OrmExtractor = {
  orm: "drizzle",
  dataLayers: ["drizzle"],
  imports: ["drizzle-orm"],
  chainMethods: [
    "select",
    "selectDistinct",
    "insert",
    "update",
    "delete",
    "execute",
    "from",
    "where",
    "values",
    "returning",
    "findMany",
    "findFirst",
  ],
  priority: 50,
  patterns: [
    {
      id: "builder",
      pattern: "$DB.$ENTRY($$$ARGS)",
      constraints: {
        DB: { regex: "^(?:[A-Za-z_$][\\w$]*)(?:\\.[A-Za-z_$][\\w$]*)*$" },
        ENTRY: { regex: "^(select|selectDistinct|insert|update|delete|execute)$" },
      },
    },
    { id: "query", pattern: "$DB.query.$TABLE.$OP($$$ARGS)" },
  ],

  claim(input: ClaimInput): DataAccessFacts | null {
    const { chain } = input;
    if (input.patternId === "drizzle.query") return claimQueryApi(input);

    const [entry] = chain.segments;
    if (entry === undefined) return null;
    const operation = ENTRY_OPERATIONS[entry.name];
    if (operation === undefined) return null;
    if (!isPlainReceiver(chain.base) || NOT_A_DB.test(chain.base)) return null;
    // `knex.select("id")` and `pool.query("...")` reach this pattern too; Drizzle
    // never names a column or a table with a string here.
    if (entry.args.some((argument) => stringLiteral(argument) !== null)) return null;

    const from = findSegment(chain, "from");
    const target =
      operation === "select" || operation === "raw" ? (from?.args[0] ?? "") : (entry.args[0] ?? "");
    const resolved = resolveTable(input, target);
    const where = findSegment(chain, "where");
    const having = findSegment(chain, "having");
    const filter = expressionFilter([
      ...(where === undefined ? [] : [where.argsText]),
      ...(having === undefined ? [] : [having.argsText]),
    ]);
    const isRead = operation === "select" || operation === "raw";
    const projected = entry.args.length > 0 || findSegment(chain, "returning") !== undefined;

    return facts({
      orm: "drizzle",
      operation: aggregateOf(entry, operation),
      method: entry.name,
      table: resolved.table,
      tableSource: resolved.source,
      filter,
      hasWhere: where !== undefined,
      hasLimit: isRead ? findSegment(chain, "limit") !== undefined : null,
      hasProjection: isRead ? projected : null,
      ...(operation === "raw"
        ? { note: "raw SQL executed through the Drizzle driver; the statement decides the table" }
        : {}),
    });
  },
};

/** `db.select({ total: count() })` reads an aggregate, not rows. */
function aggregateOf(
  entry: { readonly argsText: string },
  operation: DataOperation,
): DataOperation {
  if (operation !== "select") return operation;
  return /\b(count|sum|avg|min|max)\s*\(/.test(entry.argsText) ? "aggregate" : operation;
}

/** Resolves a table expression through the schema index, or says it could not. */
function resolveTable(input: ClaimInput, expression: string) {
  const identifier = bareIdentifier(expression.trim());
  if (identifier === "" || !/^[A-Za-z_$][\w$]*$/.test(identifier)) {
    return { table: "unresolved" as const, source: "none" as const };
  }
  const resolved = input.tables.byVariable(input.file, identifier);
  if (resolved !== undefined) return { table: resolved, source: "schema" as const };
  return { table: identifier, source: "identifier" as const };
}

/** `db.query.bookings.findMany({ where, limit, columns })`. */
function claimQueryApi(input: ClaimInput): DataAccessFacts | null {
  const method = input.meta.OP ?? "";
  const operation = QUERY_OPERATIONS[method];
  if (operation === undefined) return null;
  const variable = input.meta.TABLE ?? "";
  const resolved = resolveTable(input, variable);
  const options = input.chain.segments[0]?.args[0] ?? "";
  const entries = objectEntries(options);
  const where = entries.find((entry) => entry.key === "where");
  const filter = where === undefined ? undefined : expressionFilter([where.value]);
  return facts({
    orm: "drizzle",
    operation,
    method,
    table: resolved.table,
    tableSource: resolved.source,
    ...(filter === undefined ? {} : { filter }),
    hasWhere: where !== undefined,
    hasLimit: entries.some((entry) => entry.key === "limit") || method === "findFirst",
    hasProjection: entries.some((entry) => entry.key === "columns"),
  });
}

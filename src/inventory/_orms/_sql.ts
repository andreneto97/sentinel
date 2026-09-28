/**
 * SQL reading for the migration inventory.
 *
 * Migrations are the one place the inventory cannot use ast-grep: there is no
 * SQL grammar in the pinned tool, and a `.sql` file is not a JavaScript
 * expression. So this module does the splitting and classification itself —
 * conservatively, statement by statement, on text that has had its literals,
 * comments and dollar-quoted bodies blanked out first.
 *
 * It answers two questions: what does this migration *do* (the operations, and
 * whether any of them is destructive or takes a lock), and what does the
 * schema look like once it has run.
 */

import {
  type SchemaBuilder,
  type SchemaColumn,
  bareIdentifier,
  blankColumn,
} from "./schema-model.ts";

/** What one SQL statement does, in the vocabulary the migration unit reports. */
export type SqlOperation =
  | "create-table"
  | "add-column"
  | "drop-column"
  | "drop-table"
  | "alter-type"
  | "alter-column"
  | "rename"
  | "add-index"
  | "drop-index"
  | "add-constraint"
  | "drop-constraint"
  | "enable-rls"
  | "disable-rls"
  | "create-policy"
  | "drop-policy"
  | "create-enum"
  | "create-view"
  | "create-function"
  | "create-trigger"
  | "create-extension"
  | "grant"
  | "backfill"
  | "truncate"
  | "other";

/** Operations that change the shape of the schema rather than its contents. */
const SCHEMA_OPERATIONS: ReadonlySet<SqlOperation> = new Set<SqlOperation>([
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
  "create-enum",
  "create-view",
  "create-function",
  "create-trigger",
]);

/** Operations that lose data if the migration is applied to a populated table. */
const DESTRUCTIVE_OPERATIONS: ReadonlySet<SqlOperation> = new Set<SqlOperation>([
  "drop-column",
  "drop-table",
  "truncate",
  "drop-constraint",
  "drop-policy",
  "disable-rls",
]);

/** How a migration can block writes while it runs. */
export type LockRisk =
  | "add-not-null-with-default"
  | "create-index-without-concurrently"
  | "type-rewrite"
  | "none";

/** Worst first: a migration reports the highest risk any of its statements carries. */
const LOCK_RISK_ORDER: readonly LockRisk[] = [
  "type-rewrite",
  "create-index-without-concurrently",
  "add-not-null-with-default",
  "none",
];

/** One statement of a migration file, with the line it starts on. */
export interface SqlStatement {
  /** The statement's source text, terminator excluded. */
  readonly text: string;
  /** 1-based line the statement starts on, for a citation. */
  readonly line: number;
}

/** Blanks out literals, comments and dollar-quoted bodies, preserving length. */
export function maskSql(sql: string): string {
  const out = sql.split("");
  const blank = (from: number, to: number): void => {
    for (let i = from; i < to && i < out.length; i += 1) {
      // Newlines stay so line numbers survive the mask.
      if (out[i] !== "\n") out[i] = " ";
    }
  };
  let index = 0;
  while (index < sql.length) {
    const char = sql[index] ?? "";
    const next = sql[index + 1] ?? "";
    if (char === "-" && next === "-") {
      const end = sql.indexOf("\n", index);
      const stop = end === -1 ? sql.length : end;
      blank(index, stop);
      index = stop;
      continue;
    }
    if (char === "/" && next === "*") {
      const end = sql.indexOf("*/", index + 2);
      const stop = end === -1 ? sql.length : end + 2;
      blank(index, stop);
      index = stop;
      continue;
    }
    if (char === "$") {
      // Postgres dollar quoting: $$ ... $$ or $tag$ ... $tag$.
      const tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(index));
      if (tag !== null) {
        const marker = tag[0];
        const end = sql.indexOf(marker, index + marker.length);
        const stop = end === -1 ? sql.length : end + marker.length;
        blank(index, stop);
        index = stop;
        continue;
      }
    }
    if (char === "'" || char === '"' || char === "`") {
      let cursor = index + 1;
      while (cursor < sql.length) {
        const current = sql[cursor];
        if (current === "\\") {
          cursor += 2;
          continue;
        }
        // '' inside a string is an escaped quote, not the end of it.
        if (current === char && sql[cursor + 1] === char) {
          cursor += 2;
          continue;
        }
        if (current === char) break;
        cursor += 1;
      }
      const stop = Math.min(cursor + 1, sql.length);
      // Identifier quoting carries meaning, so only string bodies are blanked.
      if (char === "'") blank(index, stop);
      index = stop;
      continue;
    }
    index += 1;
  }
  return out.join("");
}

/** Splits a migration file into statements, keeping each one's starting line. */
export function splitSqlStatements(sql: string): SqlStatement[] {
  const mask = maskSql(sql);
  const statements: SqlStatement[] = [];
  let start = 0;
  let line = 1;
  let statementLine = 1;
  let seenContent = false;
  const push = (from: number, to: number): void => {
    const text = sql.slice(from, to).trim();
    if (text !== "" && /[A-Za-z]/.test(maskSql(text))) {
      statements.push({ text, line: statementLine });
    }
  };
  for (let i = 0; i < mask.length; i += 1) {
    const char = mask[i];
    if (char === "\n") {
      line += 1;
      if (!seenContent) statementLine = line;
      continue;
    }
    if (!seenContent && char !== undefined && char.trim() !== "") {
      seenContent = true;
      statementLine = line;
    }
    if (char === ";") {
      push(start, i);
      start = i + 1;
      seenContent = false;
      statementLine = line;
    }
  }
  push(start, sql.length);
  return statements;
}

/** Collapses whitespace and upper-cases, for matching keywords. */
function normalise(statement: string): string {
  return maskSql(statement).replace(/\s+/g, " ").trim().toUpperCase();
}

/** Splits a parenthesised list at top-level commas. */
function splitList(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  const mask = maskSql(body);
  for (let i = 0; i < mask.length; i += 1) {
    const char = mask[i];
    if (char === "(") depth += 1;
    else if (char === ")") depth -= 1;
    else if (char === "," && depth === 0) {
      parts.push(body.slice(start, i).trim());
      start = i + 1;
    }
  }
  parts.push(body.slice(start).trim());
  return parts.filter((part) => part !== "");
}

/** The text inside the outermost parentheses of a statement, or null. */
function parenBody(statement: string): string | null {
  const mask = maskSql(statement);
  const open = mask.indexOf("(");
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < mask.length; i += 1) {
    const char = mask[i];
    if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return statement.slice(open + 1, i);
    }
  }
  return null;
}

/** Column names listed inside a parenthesised list, ignoring `ASC`/`DESC` and expressions. */
function columnList(body: string): string[] {
  return splitList(body)
    .map((part) => part.replace(/\s+(ASC|DESC|NULLS\s+(FIRST|LAST))\b/gi, "").trim())
    .map(bareIdentifier)
    .filter((name) => name !== "");
}

/** What one statement was classified as, and what it touches. */
export interface StatementAnalysis {
  readonly operation: SqlOperation;
  readonly table: string | null;
  readonly lockRisk: LockRisk;
  /** Why the lock risk applies, in words, for the unit's `lockDetail`. */
  readonly lockDetail: string | null;
}

const TABLE_PATTERNS: ReadonlyArray<{ readonly re: RegExp; readonly group: number }> = [
  { re: /^(?:CREATE|ALTER|DROP)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([^\s(]+)/i, group: 1 },
  { re: /^INSERT\s+INTO\s+([^\s(]+)/i, group: 1 },
  { re: /^UPDATE\s+(?:ONLY\s+)?([^\s(]+)/i, group: 1 },
  { re: /^DELETE\s+FROM\s+([^\s(]+)/i, group: 1 },
  { re: /^TRUNCATE\s+(?:TABLE\s+)?([^\s(;]+)/i, group: 1 },
  { re: /\bON\s+([^\s(]+)\s*(?:USING\b|\()/i, group: 1 },
];

/** The table a statement addresses, when it names one. */
export function statementTable(statement: string): string | null {
  const text = maskSql(statement).trim();
  for (const candidate of TABLE_PATTERNS) {
    const match = candidate.re.exec(text);
    const found = match?.[candidate.group];
    if (found !== undefined && found !== "") return bareIdentifier(found);
  }
  return null;
}

/** Classifies one statement: what it does, to what, and what it locks. */
export function analyseStatement(statement: string): StatementAnalysis {
  const upper = normalise(statement);
  const table = statementTable(statement);
  const base = (operation: SqlOperation): StatementAnalysis => ({
    operation,
    table,
    lockRisk: "none",
    lockDetail: null,
  });

  if (/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\b/.test(upper)) {
    return base("create-view");
  }
  if (/^CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b/.test(upper)) return base("create-function");
  if (/^CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\b/.test(upper)) return base("create-trigger");
  if (/^CREATE\s+EXTENSION\b/.test(upper)) return base("create-extension");
  if (/^CREATE\s+TYPE\b/.test(upper)) return base("create-enum");
  if (/^CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\b/.test(upper)) return base("create-table");
  if (/^CREATE\s+(?:UNIQUE\s+)?INDEX\b/.test(upper)) {
    const concurrent = /\bCONCURRENTLY\b/.test(upper);
    return {
      operation: "add-index",
      table,
      lockRisk: concurrent ? "none" : "create-index-without-concurrently",
      lockDetail: concurrent
        ? null
        : "CREATE INDEX without CONCURRENTLY blocks writes on the table for the whole build",
    };
  }
  if (/^DROP\s+INDEX\b/.test(upper)) return base("drop-index");
  if (/^DROP\s+TABLE\b/.test(upper)) return base("drop-table");
  if (/^DROP\s+POLICY\b/.test(upper)) return base("drop-policy");
  if (/^CREATE\s+POLICY\b/.test(upper)) return base("create-policy");
  if (/^TRUNCATE\b/.test(upper)) return base("truncate");
  if (/^(GRANT|REVOKE)\b/.test(upper)) return base("grant");
  if (/^(INSERT|UPDATE|DELETE)\b/.test(upper)) return base("backfill");

  if (/^ALTER\s+TABLE\b/.test(upper)) {
    if (/\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b/.test(upper)) return base("enable-rls");
    if (/\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/.test(upper)) return base("disable-rls");
    if (/\bDROP\s+CONSTRAINT\b/.test(upper)) return base("drop-constraint");
    if (/\bDROP\s+COLUMN\b/.test(upper)) return base("drop-column");
    if (/\bRENAME\b/.test(upper)) return base("rename");
    if (/\bADD\s+(?:COLUMN\b|IF\s+NOT\s+EXISTS\b)/.test(upper)) {
      const notNullDefault = /\bNOT\s+NULL\b/.test(upper) && /\bDEFAULT\b/.test(upper);
      return {
        operation: "add-column",
        table,
        lockRisk: notNullDefault ? "add-not-null-with-default" : "none",
        lockDetail: notNullDefault
          ? "adding a NOT NULL column with a DEFAULT rewrites the table on PostgreSQL before 11 and on MySQL"
          : null,
      };
    }
    if (
      /\bADD\s+CONSTRAINT\b/.test(upper) ||
      /\bADD\s+(PRIMARY\s+KEY|UNIQUE|FOREIGN\s+KEY|CHECK)\b/.test(upper)
    ) {
      return base("add-constraint");
    }
    if (
      /\bALTER\s+(?:COLUMN\s+)?[^\s]+\s+TYPE\b/.test(upper) ||
      /\bSET\s+DATA\s+TYPE\b/.test(upper)
    ) {
      return {
        operation: "alter-type",
        table,
        lockRisk: "type-rewrite",
        lockDetail: "changing a column type rewrites the table and holds an exclusive lock",
      };
    }
    if (/\bSET\s+NOT\s+NULL\b/.test(upper)) {
      return {
        operation: "alter-column",
        table,
        lockRisk: "add-not-null-with-default",
        lockDetail: "SET NOT NULL scans the whole table under an exclusive lock",
      };
    }
    return base("alter-column");
  }
  return base("other");
}

/** Everything the migration unit reports about a file's statements. */
export interface SqlAnalysis {
  readonly operations: readonly SqlOperation[];
  readonly destructive: boolean;
  readonly lockRisk: LockRisk;
  readonly lockDetail: string | null;
  readonly touchesSchema: boolean;
  readonly touchesData: boolean;
  readonly tables: readonly string[];
}

/** The worse of two lock risks. */
export function worseLockRisk(a: LockRisk, b: LockRisk): LockRisk {
  return LOCK_RISK_ORDER.indexOf(a) <= LOCK_RISK_ORDER.indexOf(b) ? a : b;
}

/** Folds every statement of a migration into one verdict. */
export function analyseSql(statements: readonly SqlStatement[]): SqlAnalysis {
  const operations: SqlOperation[] = [];
  const tables: string[] = [];
  let destructive = false;
  let lockRisk: LockRisk = "none";
  let lockDetail: string | null = null;
  let touchesSchema = false;
  let touchesData = false;

  for (const statement of statements) {
    const analysis = analyseStatement(statement.text);
    if (analysis.operation !== "other" && !operations.includes(analysis.operation)) {
      operations.push(analysis.operation);
    }
    if (analysis.table !== null && !tables.includes(analysis.table)) tables.push(analysis.table);
    if (DESTRUCTIVE_OPERATIONS.has(analysis.operation)) destructive = true;
    if (SCHEMA_OPERATIONS.has(analysis.operation)) touchesSchema = true;
    if (analysis.operation === "backfill" || analysis.operation === "truncate") touchesData = true;
    const worse = worseLockRisk(lockRisk, analysis.lockRisk);
    if (worse !== lockRisk) {
      lockRisk = worse;
      lockDetail = analysis.lockDetail;
    }
  }
  return {
    operations,
    destructive,
    lockRisk,
    lockDetail,
    touchesSchema,
    touchesData,
    tables,
  };
}

/** Reads one column definition of a `CREATE TABLE` body. */
export function parseColumnDefinition(definition: string): SchemaColumn | null {
  const text = definition.trim();
  const match = /^((?:"[^"]+")|(?:`[^`]+`)|(?:\[[^\]]+\])|(?:[A-Za-z_][\w$]*))\s+(.*)$/s.exec(text);
  if (match === null) return null;
  const name = bareIdentifier(match[1] ?? "");
  const rest = (match[2] ?? "").trim();
  if (name === "" || rest === "") return null;
  const upper = rest.toUpperCase();
  // The type runs until the first constraint keyword; `timestamp(3) with time
  // zone` and `numeric(10,2)` both have to survive that cut.
  const typeMatch =
    /^((?:[A-Za-z_][\w]*)(?:\s*\([^)]*\))?(?:\s+(?:WITH|WITHOUT)\s+TIME\s+ZONE)?(?:\s*\[\s*\])*)/i.exec(
      rest,
    );
  const type = (typeMatch?.[1] ?? rest.split(/\s+/)[0] ?? "unknown").trim();
  const column = blankColumn(name, type);
  column.nullable = !/\bNOT\s+NULL\b/.test(upper);
  column.hasDefault = /\bDEFAULT\b/.test(upper) || /\bGENERATED\b/.test(upper);
  column.isPrimaryKey = /\bPRIMARY\s+KEY\b/.test(upper);
  column.isUnique = column.isPrimaryKey || /\bUNIQUE\b/.test(upper);
  if (column.isPrimaryKey) column.nullable = false;
  const reference = /\bREFERENCES\s+([^\s(]+)\s*(?:\(\s*([^)]+)\s*\))?/i.exec(rest);
  if (reference !== null) {
    column.references = {
      table: bareIdentifier(reference[1] ?? ""),
      column: bareIdentifier(reference[2] ?? "id"),
    };
  }
  return column;
}

/** True when a `CREATE TABLE` body entry is a table constraint rather than a column. */
function isTableConstraint(definition: string): boolean {
  return /^\s*(CONSTRAINT|PRIMARY\s+KEY|UNIQUE|FOREIGN\s+KEY|CHECK|EXCLUDE)\b/i.test(definition);
}

/** Applies a table constraint from a `CREATE TABLE` body or an `ADD CONSTRAINT`. */
function applyConstraint(builder: SchemaBuilder, table: string, definition: string): void {
  const named = /^\s*CONSTRAINT\s+("[^"]+"|`[^`]+`|[\w$]+)\s+(.*)$/is.exec(definition);
  const name = named === null ? "" : bareIdentifier(named[1] ?? "");
  const body = (named === null ? definition : (named[2] ?? "")).trim();
  const upper = body.toUpperCase();

  if (upper.startsWith("PRIMARY KEY")) {
    const list = parenBody(body);
    if (list !== null) builder.setPrimaryKey(table, columnList(list));
    return;
  }
  if (upper.startsWith("UNIQUE")) {
    const list = parenBody(body);
    if (list !== null) builder.addUnique(table, { name, columns: columnList(list) });
    return;
  }
  if (upper.startsWith("FOREIGN KEY")) {
    const columns = parenBody(body);
    const target = /REFERENCES\s+([^\s(]+)\s*(?:\(\s*([^)]+)\s*\))?/i.exec(body);
    if (columns === null || target === null) return;
    const onDelete = /ON\s+DELETE\s+([A-Z ]+?)(?:\s+ON\s+|\s*$)/i.exec(body)?.[1]?.trim();
    builder.addForeignKey(table, {
      name,
      columns: columnList(columns),
      referencesTable: bareIdentifier(target[1] ?? ""),
      referencesColumns: columnList(target[2] ?? "id"),
      ...(onDelete === undefined ? {} : { onDelete }),
    });
  }
}

/** Where a statement came from, so the table keeps a citation. */
export interface SqlOrigin {
  readonly file: string;
  readonly line: number;
}

/**
 * Replays one statement onto the accumulating schema.
 *
 * Only what the statement proves is applied: an unrecognised statement leaves
 * the model untouched rather than inventing a table.
 */
export function applyStatement(
  builder: SchemaBuilder,
  statement: SqlStatement,
  origin: SqlOrigin,
): void {
  const text = statement.text;
  const upper = normalise(text);
  const line = origin.line + statement.line - 1;
  const cite = (table: string, note: string): void => {
    builder.addEvidence(table, { file: origin.file, line, note });
  };

  const createTable =
    /^CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)/i.exec(
      maskSql(text).trim(),
    );
  if (createTable !== null) {
    const table = bareIdentifier(createTable[1] ?? "");
    builder.table(table);
    cite(table, "created here");
    const body = parenBody(text);
    if (body === null) return;
    for (const definition of splitList(body)) {
      if (isTableConstraint(definition)) {
        applyConstraint(builder, table, definition);
        continue;
      }
      const column = parseColumnDefinition(definition);
      if (column !== null) builder.putColumn(table, column);
    }
    return;
  }

  if (/^DROP\s+TABLE\b/.test(upper)) {
    const table = statementTable(text);
    if (table !== null) builder.dropTable(table);
    return;
  }

  if (/^CREATE\s+(?:UNIQUE\s+)?INDEX\b/.test(upper)) {
    const head =
      /^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]*)\s*ON\s+([^\s(]+)/i.exec(
        maskSql(text).trim(),
      );
    if (head === null) return;
    const table = bareIdentifier(head[3] ?? "");
    const body = parenBody(text);
    builder.addIndex(table, {
      name: bareIdentifier(head[2] ?? ""),
      columns: body === null ? [] : columnList(body),
      unique: head[1] !== undefined,
      concurrent: /\bCONCURRENTLY\b/.test(upper),
    });
    cite(table, "index created here");
    return;
  }

  if (/^DROP\s+INDEX\b/.test(upper)) {
    const name = /^DROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?([^\s;]+)/i.exec(
      maskSql(text).trim(),
    )?.[1];
    if (name !== undefined) builder.dropIndex(name);
    return;
  }

  if (/^CREATE\s+POLICY\b/.test(upper)) {
    const head = /^CREATE\s+POLICY\s+("[^"]+"|`[^`]+`|[^\s]+)\s+ON\s+([^\s]+)/i.exec(
      maskSql(text).trim(),
    );
    if (head === null) return;
    const table = bareIdentifier(head[2] ?? "");
    const command = /\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b/i.exec(upper)?.[1] ?? "ALL";
    const roles = /\bTO\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)/i.exec(text)?.[1];
    builder.addPolicy(table, {
      name: bareIdentifier(head[1] ?? ""),
      command: command.toUpperCase(),
      roles: roles === undefined ? [] : roles.split(",").map((role) => role.trim()),
    });
    cite(table, "policy created here");
    return;
  }

  if (/^ALTER\s+TABLE\b/.test(upper)) {
    const table = statementTable(text);
    if (table === null) return;
    if (/\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b/.test(upper)) {
      builder.setRls(table, true);
      cite(table, "row level security enabled here");
      return;
    }
    if (/\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/.test(upper)) {
      builder.setRls(table, false);
      return;
    }
    const addColumn = /\bADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(.*)$/is.exec(text);
    if (addColumn !== null) {
      const column = parseColumnDefinition(addColumn[1] ?? "");
      if (column !== null) {
        builder.putColumn(table, column);
        cite(table, `column ${column.name} added here`);
      }
      return;
    }
    const dropColumn = /\bDROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?([^\s,;]+)/i.exec(maskSql(text));
    if (dropColumn !== null) {
      builder.dropColumn(table, dropColumn[1] ?? "");
      return;
    }
    const alterType =
      /\bALTER\s+(?:COLUMN\s+)?([^\s]+)\s+(?:SET\s+DATA\s+)?TYPE\s+([^\s,;]+)/i.exec(maskSql(text));
    if (alterType !== null) {
      builder.patchColumn(table, alterType[1] ?? "", { type: alterType[2] ?? "unknown" });
      return;
    }
    const setNotNull = /\bALTER\s+(?:COLUMN\s+)?([^\s]+)\s+SET\s+NOT\s+NULL/i.exec(maskSql(text));
    if (setNotNull !== null) {
      builder.patchColumn(table, setNotNull[1] ?? "", { nullable: false });
      return;
    }
    const dropNotNull = /\bALTER\s+(?:COLUMN\s+)?([^\s]+)\s+DROP\s+NOT\s+NULL/i.exec(maskSql(text));
    if (dropNotNull !== null) {
      builder.patchColumn(table, dropNotNull[1] ?? "", { nullable: true });
      return;
    }
    const addConstraint =
      /\bADD\s+(CONSTRAINT\s+.*|PRIMARY\s+KEY\s*\(.*|UNIQUE\s*\(.*|FOREIGN\s+KEY\s*\(.*)$/is.exec(
        text,
      );
    if (addConstraint !== null) {
      applyConstraint(builder, table, addConstraint[1] ?? "");
      cite(table, "constraint added here");
    }
  }
}

/** Replays a whole migration file onto the schema. */
export function applySqlFile(
  builder: SchemaBuilder,
  sql: string,
  origin: { readonly file: string },
): SqlStatement[] {
  const statements = splitSqlStatements(sql);
  builder.addSource(origin.file);
  for (const statement of statements) {
    applyStatement(builder, statement, { file: origin.file, line: 1 });
  }
  return statements;
}

/** The columns a `WHERE` clause names, for the raw-SQL data-access extractor. */
export function whereColumns(sql: string): string[] {
  const mask = maskSql(sql);
  const where = /\bWHERE\b/i.exec(mask);
  if (where === null) return [];
  const clause = sql.slice(where.index + where[0].length);
  const stop = /\b(GROUP\s+BY|ORDER\s+BY|LIMIT|OFFSET|RETURNING|FETCH|HAVING|WINDOW)\b/i.exec(
    maskSql(clause),
  );
  const body = stop === null ? clause : clause.slice(0, stop.index);
  const columns: string[] = [];
  const pattern =
    /("[^"]+"|`[^`]+`|[A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?)\s*(?:=|<>|!=|>=|<=|>|<|\bIN\b|\bLIKE\b|\bILIKE\b|\bIS\b|\bBETWEEN\b|\bANY\b)/gi;
  for (;;) {
    const match = pattern.exec(body);
    if (match === null) break;
    const name = bareIdentifier(match[1] ?? "");
    if (name === "" || /^(AND|OR|NOT|WHERE|TRUE|FALSE|NULL)$/i.test(name)) continue;
    if (!columns.includes(name)) columns.push(name);
  }
  return columns;
}

/** The leading verb of a SQL statement, mapped to a data-access operation. */
export function sqlOperation(sql: string): "select" | "insert" | "update" | "delete" | "raw" {
  const upper = normalise(sql);
  if (/^(WITH\b.*\bSELECT\b|SELECT\b)/.test(upper)) return "select";
  if (/^INSERT\b/.test(upper)) return "insert";
  if (/^UPDATE\b/.test(upper)) return "update";
  if (/^DELETE\b/.test(upper)) return "delete";
  return "raw";
}

/** True when a `SELECT` reads every column rather than a projection. */
export function selectsEverything(sql: string): boolean {
  return /\bSELECT\s+(?:DISTINCT\s+)?(?:[A-Za-z_][\w$]*\s*\.\s*)?\*/i.test(maskSql(sql));
}

/** The table a `SELECT`/`INSERT`/`UPDATE`/`DELETE` addresses, when it names one. */
export function sqlTable(sql: string): string | null {
  const mask = maskSql(sql);
  const from = /\bFROM\s+((?:"[^"]+"|`[^`]+`|[A-Za-z_][\w$.]*))/i.exec(mask);
  if (from !== null) return bareIdentifier(from[1] ?? "");
  return statementTable(sql);
}

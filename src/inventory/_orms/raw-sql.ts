/**
 * Raw drivers: `pg`, `mysql2` and the `postgres`/`sql` tagged template.
 *
 * There is no builder to read here, only a SQL string — so the statement
 * itself is parsed: what it does, which table it addresses, which columns it
 * filters by, and whether it reads every column. Whether the parameters are
 * bound or interpolated is left to the audit, but the inventory records the
 * shape it saw so the question can be asked of a concrete statement.
 */

import { stringLiteral } from "./_chain.ts";
import { dedupe, facts, isPlainReceiver } from "./_claim.ts";
import { selectsEverything, sqlOperation, sqlTable, whereColumns } from "./_sql.ts";
import type { ClaimInput, DataAccessFacts, OrmExtractor, OrmName } from "./types.ts";

/** Receivers a connection or pool is plausibly bound to. */
const CONNECTION =
  "^(?:this\\.)?(pool|client|conn|connection|db|database|pg|pgClient|dbClient|mysql|sql)$";

/** Tag functions that build SQL: `postgres`'s `sql`, Drizzle's `sql`, Slonik's. */
const SQL_TAGS = "^(sql|postgres|db|SQL)$";

/** Keywords a whole SQL statement can open with; anything else is a fragment. */
const STATEMENT_START =
  /^\s*(with|select|insert|update|delete|merge|truncate|call|create|alter|drop)\b/i;

/** Unwraps a template literal whose interpolations keep it from being a plain literal. */
function stripBackticks(text: string): string {
  const trimmed = text.trim();
  if (!trimmed.startsWith("`")) return trimmed;
  return trimmed.slice(1, trimmed.endsWith("`") ? -1 : undefined);
}

/** True when the statement interpolates something that is not a bound parameter. */
function looksInterpolated(argsText: string, tagged: boolean): boolean {
  if (tagged) return false;
  return /\$\{/.test(argsText) || /["'`]\s*\+/.test(argsText);
}

/**
 * The raw-driver extractor.
 *
 * `pg` and `mysql2` produce the same call shapes, so one extractor covers
 * both and the caller says which name the repository's profile proved.
 */
export function createRawSqlExtractor(orm: OrmName = "pg"): OrmExtractor {
  return {
    orm,
    dataLayers: ["pg", "mysql2", "postgres-js"],
    imports: ["pg", "mysql2", "postgres", "pg-promise", "slonik"],
    chainMethods: ["query", "execute", "rows", "raw"],
    priority: 30,
    patterns: [
      {
        id: "query",
        pattern: "$CONN.query($$$ARGS)",
        constraints: { CONN: { regex: CONNECTION } },
      },
      {
        id: "execute",
        pattern: "$CONN.execute($$$ARGS)",
        constraints: { CONN: { regex: CONNECTION } },
      },
      {
        id: "tagged",
        rule: {
          all: [
            { kind: "call_expression" },
            { has: { field: "function", regex: SQL_TAGS } },
            { has: { field: "arguments", kind: "template_string" } },
          ],
        },
      },
    ],

    claim(input: ClaimInput): DataAccessFacts | null {
      const { chain } = input;
      const [call] = chain.segments;
      if (call === undefined) return null;
      if (input.patternId !== `${orm}.tagged` && !isPlainReceiver(chain.base)) return null;

      const tagged = call.tagged;
      const raw = tagged ? call.argsText : (call.args[0] ?? "");
      const sql = tagged ? raw : (stringLiteral(raw) ?? stripBackticks(raw));
      if (sql.trim() === "") return null;
      // A `sql` tag is also how Drizzle and Kysely write a *fragment*:
      // `sql`count(*)`` inside a projection is part of another query, not a
      // call site of its own, so only a whole statement is claimed here.
      if (tagged && !STATEMENT_START.test(sql)) return null;
      // A query built entirely out of a variable is still a call site; the
      // statement is just not visible here, and the audit is told so.
      const visible = /\b(select|insert|update|delete|with|call|merge)\b/i.test(sql);

      const operation = sqlOperation(sql);
      const table = sqlTable(sql);
      const reads = operation === "select" || operation === "raw";
      const columns = whereColumns(sql);

      return facts({
        orm,
        operation,
        method: tagged ? "sql" : call.name === "" ? "query" : call.name,
        table: table ?? "unresolved",
        tableSource: table === null ? "none" : "sql",
        filter: { columns: dedupe(columns), values: [] },
        hasWhere: /\bWHERE\b/i.test(sql),
        hasLimit: reads ? /\b(LIMIT|FETCH\s+FIRST|TOP)\b/i.test(sql) : null,
        hasProjection: reads ? !selectsEverything(sql) : null,
        note: !visible
          ? "the statement is not a literal here; the SQL is assembled elsewhere"
          : looksInterpolated(raw, tagged)
            ? "the statement is assembled by string interpolation rather than bound parameters"
            : tagged
              ? "tagged template; the driver binds the interpolations as parameters"
              : "parameters are passed separately to the driver",
      });
    },
  };
}

/** The default raw-driver extractor, for repositories that proved `pg`. */
export const rawSqlExtractor: OrmExtractor = createRawSqlExtractor("pg");

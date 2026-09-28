/**
 * Knex: `knex("users").where({ tenant_id }).select("id").limit(20)`.
 *
 * Knex names tables and columns with strings, which is what tells it apart
 * from Drizzle's identifiers and Supabase's PostgREST verbs. Everything the
 * audit needs is in the chain; nothing has to be resolved against a schema.
 */

import { stringLiteral } from "./_chain.ts";
import { dedupe, facts, filterObject, isPlainReceiver, mergeFilters } from "./_claim.ts";
import { sqlOperation, whereColumns } from "./_sql.ts";
import type { ClaimInput, DataAccessFacts, DataOperation, OrmExtractor } from "./types.ts";

/** Terminal methods, and what each one does. */
const OPERATIONS: Readonly<Record<string, DataOperation>> = {
  insert: "insert",
  update: "update",
  del: "delete",
  delete: "delete",
  truncate: "delete",
  count: "aggregate",
  countDistinct: "aggregate",
  sum: "aggregate",
  avg: "aggregate",
  min: "aggregate",
  max: "aggregate",
};

/** Links that add a predicate. */
const WHERE_METHODS = [
  "where",
  "andWhere",
  "orWhere",
  "whereNot",
  "whereIn",
  "whereNotIn",
  "whereNull",
  "whereNotNull",
  "whereBetween",
  "whereLike",
  "whereILike",
  "whereExists",
  "having",
  "havingIn",
];

/** Receivers a Knex instance is plausibly bound to. */
const KNEX_RECEIVER = "^(?:this\\.)?(knex|db|database|sql|conn|connection|pg|client|trx|tx)$";

/** Knex's data-access call sites. */
export const knexExtractor: OrmExtractor = {
  orm: "knex",
  dataLayers: ["knex"],
  imports: ["knex", "objection"],
  chainMethods: [
    "where",
    "andWhere",
    "whereIn",
    "whereRaw",
    "select",
    "insert",
    "update",
    "del",
    "delete",
    "first",
    "limit",
    "into",
    "table",
    "from",
    "raw",
    "count",
    "onConflict",
  ],
  priority: 70,
  patterns: [
    {
      id: "table",
      pattern: "$KNEX($TABLE)",
      constraints: { KNEX: { regex: KNEX_RECEIVER }, TABLE: { kind: "string" } },
    },
    {
      id: "from",
      pattern: "$KNEX.from($TABLE)",
      constraints: { TABLE: { kind: "string" } },
    },
    {
      id: "into",
      pattern: "$KNEX.into($TABLE)",
      constraints: { TABLE: { kind: "string" } },
    },
    {
      id: "tableName",
      pattern: "$KNEX.table($TABLE)",
      constraints: { TABLE: { kind: "string" } },
    },
    {
      id: "raw",
      pattern: "$KNEX.raw($$$ARGS)",
      constraints: { KNEX: { regex: KNEX_RECEIVER } },
    },
  ],

  claim(input: ClaimInput): DataAccessFacts | null {
    const { chain } = input;
    if (!isPlainReceiver(chain.base)) return null;

    if (input.patternId === "knex.raw") {
      const [first] = chain.segments[0]?.args ?? [];
      const sql = first === undefined ? "" : (stringLiteral(first) ?? first);
      return facts({
        orm: "knex",
        operation: sqlOperation(sql),
        method: "raw",
        table: "unresolved",
        tableSource: "none",
        filter: { columns: whereColumns(sql), values: [] },
        hasWhere: /\bWHERE\b/i.test(sql),
        hasLimit: /\bLIMIT\b/i.test(sql),
        hasProjection: null,
        note: "raw SQL through knex.raw; bindings decide whether it is parameterised",
      });
    }

    const table = stringLiteral(input.meta.TABLE ?? "");
    if (table === null) return null;

    const writer = chain.segments.find((segment) => OPERATIONS[segment.name] !== undefined);
    const upsert =
      chain.segments.some((segment) => segment.name === "onConflict") &&
      chain.segments.some((segment) => segment.name === "merge" || segment.name === "ignore");
    const operation: DataOperation = upsert
      ? "upsert"
      : (OPERATIONS[writer?.name ?? ""] ?? "select");

    const wheres = chain.segments.filter((segment) => WHERE_METHODS.includes(segment.name));
    const columns: string[] = [];
    const values: string[] = [];
    let objectFilter = { columns: [] as string[], values: [] as string[] };
    for (const where of wheres) {
      const [first, second] = where.args;
      if (first === undefined) continue;
      const literal = stringLiteral(first);
      if (literal !== null) {
        columns.push(literal.split(".").pop() ?? literal);
        if (second !== undefined) values.push(second);
        continue;
      }
      if (first.trim().startsWith("{")) {
        objectFilter = mergeFilters(objectFilter, filterObject(first));
      }
    }
    const raws = chain.segments.filter((segment) => segment.name === "whereRaw");
    for (const raw of raws) {
      const [first] = raw.args;
      const sql = first === undefined ? "" : (stringLiteral(first) ?? first);
      columns.push(...whereColumns(`WHERE ${sql}`));
    }

    const filter = mergeFilters({ columns: dedupe(columns), values: dedupe(values) }, objectFilter);
    const select = chain.segments.find(
      (segment) => segment.name === "select" || segment.name === "pluck",
    );
    const projected =
      select !== undefined &&
      select.args.length > 0 &&
      !select.args.every((argument) => stringLiteral(argument) === "*");
    const reads = operation === "select" || operation === "aggregate";

    return facts({
      orm: "knex",
      operation,
      method: writer?.name ?? select?.name ?? "select",
      table,
      tableSource: "literal",
      filter,
      hasWhere: wheres.length > 0 || raws.length > 0,
      hasLimit: reads
        ? chain.segments.some((segment) => segment.name === "limit" || segment.name === "first")
        : null,
      hasProjection: reads ? projected : null,
    });
  },
};

/**
 * The Supabase client: `supabase.from("bookings").select("*").eq("user_id", uid)`.
 *
 * Supabase is the one data layer where the absence of a filter is not
 * necessarily a hole — row-level security may be doing the work — and where
 * its presence is not necessarily enough, because the anon key reaches the
 * table directly. So the call site is recorded with both halves, and the
 * schema model says whether RLS is on and whether any policy exists.
 */

import { findSegment, stringLiteral } from "./_chain.ts";
import {
  dedupe,
  facts,
  filterObject,
  firstStringArgument,
  isPlainReceiver,
  mergeFilters,
} from "./_claim.ts";
import type { ClaimInput, DataAccessFacts, DataOperation, OrmExtractor } from "./types.ts";

/** PostgREST verbs, and what each one does. */
const VERBS: Readonly<Record<string, DataOperation>> = {
  select: "select",
  insert: "insert",
  update: "update",
  delete: "delete",
  upsert: "upsert",
};

/** Filter links; each takes the column as its first argument. */
const COLUMN_FILTERS = [
  "eq",
  "neq",
  "gt",
  "gte",
  "lt",
  "lte",
  "like",
  "ilike",
  "is",
  "in",
  "contains",
  "containedBy",
  "rangeGt",
  "rangeGte",
  "rangeLt",
  "rangeLte",
  "overlaps",
  "textSearch",
  "filter",
  "not",
  "order",
];

/** Links that bound the number of rows returned. */
const LIMITS = ["limit", "range", "single", "maybeSingle"];

/** The Supabase client's data-access call sites. */
export const supabaseExtractor: OrmExtractor = {
  orm: "supabase",
  dataLayers: ["supabase"],
  imports: ["@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs"],
  chainMethods: ["from", "select", "insert", "update", "delete", "upsert", "rpc", "eq", "limit"],
  priority: 80,
  patterns: [
    {
      id: "from",
      pattern: "$CLIENT.from($TABLE)",
      constraints: { TABLE: { kind: "string" } },
    },
    { id: "rpc", pattern: "$CLIENT.rpc($$$ARGS)" },
  ],

  claim(input: ClaimInput): DataAccessFacts | null {
    const { chain } = input;
    if (!isPlainReceiver(chain.base)) return null;

    if (input.patternId === "supabase.rpc") {
      const name = firstStringArgument(chain.segments[0]);
      return facts({
        orm: "supabase",
        operation: "raw",
        method: "rpc",
        table: name ?? "unresolved",
        tableSource: name === null ? "none" : "literal",
        hasWhere: false,
        hasLimit: null,
        hasProjection: null,
        note: "PostgREST function call; the function body decides what it reads",
      });
    }

    const verb = chain.segments.find((segment) => VERBS[segment.name] !== undefined);
    // `db.select().from(users)` (Drizzle) and `knex.select("id").from("t")` reach
    // this pattern as well; only a Supabase chain puts the verb *after* `from`.
    if (verb === undefined) return null;
    const table = stringLiteral(input.meta.TABLE ?? "");
    if (table === null) return null;
    const operation = VERBS[verb.name] ?? "select";

    const filters = chain.segments.filter((segment) => COLUMN_FILTERS.includes(segment.name));
    const columns: string[] = [];
    const values: string[] = [];
    for (const filter of filters) {
      const column = firstStringArgument(filter);
      if (column !== null) columns.push(column.split(".")[0] ?? column);
      const [, second] = filter.args;
      if (second !== undefined) values.push(second);
    }
    const match = findSegment(chain, "match");
    const matched =
      match === undefined ? { columns: [], values: [] } : filterObject(match.argsText);
    const or = findSegment(chain, "or");
    if (or !== undefined) {
      // `or("owner_id.eq.1,status.eq.open")` names its columns inside the string.
      const expression = firstStringArgument(or) ?? "";
      for (const clause of expression.split(",")) {
        const column = clause.split(".")[0];
        if (column !== undefined && column !== "") columns.push(column);
      }
    }
    const filter = mergeFilters({ columns: dedupe(columns), values: dedupe(values) }, matched);
    const projection = firstStringArgument(verb);
    const reads = operation === "select";

    return facts({
      orm: "supabase",
      operation,
      method: verb.name,
      table,
      tableSource: "literal",
      filter,
      hasWhere: filter.columns.length > 0 || matched.columns.length > 0,
      hasLimit: reads ? chain.segments.some((s) => LIMITS.includes(s.name)) : null,
      hasProjection:
        reads && projection !== null && projection.trim() !== "" && projection.trim() !== "*",
      note: "reached through PostgREST; row-level security is the only server-side gate",
    });
  },
};

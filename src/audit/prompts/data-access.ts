/**
 * The data-access prompt (D3, with the D2 injection and tenant checks).
 *
 * A data-access unit is one call site — a `prisma.booking.findMany`, a
 * `db.select().from(...)`, a `client.from("orders").select()` — with the facts
 * the ORM extractor proved about it: which table, which columns it filters on,
 * whether it sits inside a loop, whether it is one of several sequential
 * awaits. Those facts are what make the questions answerable from a slice: "is
 * this an N+1" is a guess from a grep and a decision from `insideLoop: for-of`
 * plus the enclosing function.
 *
 * The schema excerpt in the shared context is what lets this prompt ask the
 * question no linter can: a filter on a column the reconstructed schema has no
 * leading index for is a real missing-index finding, and one where the schema
 * was not reconstructed is `not-applicable` — never a guess.
 */

import { type AuditCheck, type PromptSpec, createPromptBuilder } from "./_shared.ts";

/** The D3/D2 questions asked of every data-access call site. */
export const DATA_ACCESS_CHECKS: readonly AuditCheck[] = [
  {
    name: "principal-scope",
    statement:
      "queries are scoped to the authenticated principal or to a row-level security policy",
    rule: "data.unscoped-query",
    question:
      "is this query constrained by the authenticated principal — a user id, an organisation, a tenant — or by a row-level security policy that is proven to exist?",
    fails:
      "the query reads or writes rows that belong to someone, and nothing in the predicate ties them to the caller",
    ceiling: "critical",
    notApplicable:
      "the table holds no per-principal data (a lookup table, a feature flag, a public catalogue)",
  },
  {
    name: "injection",
    statement: "dynamic values reach the database as bound parameters",
    rule: "appsec.sql-injection",
    question:
      "if this call builds SQL, a filter object or a command, is every dynamic part a bound parameter rather than interpolated text?",
    fails:
      "a value that can come from a request is concatenated or interpolated into SQL, into a `$where`, or into an identifier",
    ceiling: "critical",
    notApplicable: "the call is a typed ORM method with no raw fragment",
  },
  {
    name: "n-plus-one",
    statement: "queries run once per request, not once per row",
    rule: "data.n-plus-one",
    question:
      "does this call run once per row of another query — inside a loop, a `map`, or a `Promise.all` over rows?",
    fails:
      "the call sits inside an iteration over data that came from another query, where a join, an `in` predicate or an ORM include would do it in one round trip",
    ceiling: "medium",
    notApplicable: "the call runs once per request",
  },
  {
    name: "unbounded-result",
    statement: "list queries are bounded by a limit or a narrowing predicate",
    rule: "data.unbounded-query",
    question: "is the number of rows this query can return bounded?",
    fails:
      "a list query over a table that grows with usage has no limit, no pagination and no narrowing predicate",
    ceiling: "medium",
    notApplicable: "the query returns at most one row, or the table is bounded by construction",
  },
  {
    name: "projection",
    statement: "queries select the columns they use",
    rule: "data.select-star",
    question: "does the query select the columns it needs rather than every column?",
    fails:
      "a wide table is read whole where the code uses a few columns, or a read of a table holding credentials or tokens has no projection",
    ceiling: "medium",
    notApplicable: "the query is a write, or the entity is small and fully used",
  },
  {
    name: "index-support",
    statement: "filtered and ordered columns are covered by an index",
    rule: "data.missing-index-on-filter",
    question:
      "do the columns this query filters, joins or orders by have a supporting index in the schema excerpt?",
    fails:
      "the schema excerpt shows the table and no index leads with the column this query filters or orders by",
    ceiling: "medium",
    notApplicable:
      "no schema excerpt was provided for this table, or the filter is on the primary key",
  },
  {
    name: "transaction-boundary",
    statement: "transactions hold database work only",
    rule: "data.transaction-spans-io",
    question:
      "if this call is inside a transaction, does that transaction hold only database work?",
    fails:
      "a transaction that contains this call also performs network I/O, a queue publish, an email send or a long computation, holding the row locks while it waits",
    ceiling: "medium",
    notApplicable: "the call is not inside a transaction",
  },
  {
    name: "sequential-awaits",
    statement: "independent queries are issued together",
    rule: "data.sequential-awaits",
    question:
      "if this call is one of several independent queries awaited in a row, could they have been issued together?",
    fails:
      "two or more awaited queries in the same function do not depend on each other's results and are still issued one at a time",
    ceiling: "low",
    notApplicable: "the call depends on the result of the query before it",
  },
  {
    name: "error-and-null-handling",
    statement: "query results are checked before they are used",
    rule: "data.unchecked-result",
    question:
      "is the result of this call checked before it is used — a missing row, an empty list, a failed write?",
    fails:
      "a nullable result is dereferenced, an update's affected-row count is ignored where it decides authorization, or a failed call is swallowed",
    ceiling: "medium",
  },
];

/** How to read the facts the data-access enumerator attaches to a unit. */
const DATA_ACCESS_ATTRIBUTES: Readonly<Record<string, string>> = {
  orm: "which data layer the call belongs to, as detected in phase 0",
  operation: "what the call does: a read, a write, a delete, a raw statement",
  table: "the table or model the call resolves to",
  tableSource: "how Sentinel resolved that table name",
  hasWhere: "`true` when the call carries a predicate at all",
  whereColumns: "the columns the predicate names",
  filtersByPrincipal:
    "`true` when one of those columns looks like a principal (user id, org id, tenant)",
  hasLimit: "`true`, `false`, or `n/a` when a limit cannot apply to this operation",
  hasProjection: "`true`, `false`, or `n/a` when a projection cannot apply",
  insideLoop: "the kind of loop the call sits in, or absent when it sits in none",
  insideTransaction: "`true` when the call is inside a transaction block",
  awaitedSequentially: "`true` when another independent query is awaited next to it",
  enclosingSymbol: "the function the call sits in",
};

/** The data-access prompt spec. */
export const DATA_ACCESS_PROMPT: PromptSpec = {
  kind: "data-access",
  noun: "data-access call site",
  mission:
    "You decide whether each query is scoped to the caller, safe from injection, and shaped so it will not fall over at production volume.",
  checks: DATA_ACCESS_CHECKS,
  attributes: DATA_ACCESS_ATTRIBUTES,
  guidance: [
    "`filtersByPrincipal: false` is a reason to read the slice, not a finding. The predicate may be applied by the caller, by a helper, or by a row-level security policy — the slice and the schema excerpt are the evidence.",
    "On Supabase and Postgres, a table with `rlsEnabled: true` and at least one policy in the schema excerpt is scoped by the database. A table with RLS enabled and no policy is the opposite: it is a hard denial, and a service-role key that bypasses it is the finding.",
    "A service-role, admin or superuser client bypasses row-level security. A query on such a client is unscoped unless its own predicate scopes it.",
    "`insideLoop` is proven by containment, not by a pattern. If it is set, the N+1 question is about whether the loop iterates over rows, which the slice shows.",
    "Answer `index-support` only from the schema excerpt in the shared context. No excerpt means `not-applicable`, never a guess.",
    "A missing index on a table of a few hundred rows is not a medium finding. Say what makes the table grow, or lower the severity.",
  ],
};

/** The data-access prompt builder. */
export const dataAccessPromptBuilder = createPromptBuilder(DATA_ACCESS_PROMPT);

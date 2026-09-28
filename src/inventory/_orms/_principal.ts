/**
 * The tenant-isolation signal.
 *
 * A query that constrains by the authenticated principal is the difference
 * between "lists this user's bookings" and "lists everybody's bookings". No
 * linter can see that, so the inventory records it as a fact about the call —
 * which column the filter names, and whether the value it compares against
 * comes from the session — and leaves the verdict to the audit.
 *
 * Both halves are heuristics, and they are deliberately generous: a false
 * "filters by principal" would hide a real hole, so a column only counts when
 * it names a principal-ish entity, and a value only counts when it is read off
 * a session, a request user or an auth helper.
 */

/** Splits `organizationId`, `organization_id` and `ORGANIZATION-ID` into words. */
export function splitWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((word) => word !== "")
    .map((word) => word.toLowerCase());
}

/**
 * Entities that identify who the row belongs to. Singular and plural both
 * appear as column prefixes, and the short forms (`uid`, `sub`) are what JWT
 * claims are usually stored as.
 */
const PRINCIPAL_WORDS: ReadonlySet<string> = new Set([
  "account",
  "accounts",
  "author",
  "buyer",
  "client",
  "company",
  "creator",
  "customer",
  "member",
  "org",
  "orgs",
  "organisation",
  "organization",
  "owner",
  "principal",
  "profile",
  "seller",
  "sub",
  "team",
  "tenant",
  "uid",
  "user",
  "users",
  "workspace",
]);

/** Column names that name the principal on their own, with no qualifying word. */
const PRINCIPAL_EXACT: ReadonlySet<string> = new Set([
  "created_by",
  "createdby",
  "updated_by",
  "updatedby",
  "owned_by",
  "ownedby",
  "belongs_to",
  "auth_id",
  "authid",
]);

/**
 * True when a column name identifies the row's principal.
 *
 * `userId`, `organization_id`, `tenantId`, `created_by` and `ownerId` all
 * qualify; `username`, `user_agent` and `account_type` do not — they name a
 * property *of* the principal, not the principal the row belongs to.
 */
export function isPrincipalColumn(column: string): boolean {
  const bare = column.trim().replace(/^["'`\[]+|["'`\]]+$/g, "");
  if (bare === "") return false;
  const normalised = bare.toLowerCase();
  if (PRINCIPAL_EXACT.has(normalised)) return true;
  const words = splitWords(bare);
  if (words.length === 0) return false;
  const [first] = words;
  if (first === undefined || !PRINCIPAL_WORDS.has(first)) return false;
  // `user` alone is the principal; `user_id` and `userUuid` are its key.
  if (words.length === 1) return true;
  const rest = words.slice(1).join("");
  return ["id", "ids", "uuid", "key", "sub", "email", "identifier", "slug", "ref"].includes(rest);
}

/**
 * Expressions that carry the authenticated principal. These are the shapes a
 * request handler actually uses; a bare `userId` variable is included because
 * it is the near-universal name for the value pulled off the session one line
 * earlier.
 */
const PRINCIPAL_EXPRESSIONS: readonly RegExp[] = [
  /\bsession\s*[.?]/i,
  /\bauth\s*\(\s*\)/,
  /\bauth\s*[.?]\s*uid\s*\(/i,
  /\bgetServerSession\b/,
  /\bgetSession\b/,
  /\bcurrentUser\b/i,
  /\b(?:req|request|ctx|context|locals|event|res)\s*[.?]\s*(?:locals\s*[.?]\s*)?user\b/i,
  /\b(?:req|request|ctx|context)\s*[.?]\s*auth\b/i,
  /\bthis\s*[.?]\s*(?:user|currentUser|principal)\b/i,
  /\buser\s*[.?]\s*id\b/i,
  /\b(?:user|owner|tenant|org|organisation|organization|account|workspace|team|member|customer|creator|author)(?:_?[Ii]d|Id|ID)\b/,
  /\bclaims\s*[.?]/i,
  /\bjwt\s*[.?]/i,
  /\btoken\s*[.?]\s*sub\b/i,
];

/** True when an expression reads the authenticated principal rather than user input. */
export function isPrincipalExpression(expression: string): boolean {
  const text = expression.trim();
  if (text === "") return false;
  return PRINCIPAL_EXPRESSIONS.some((pattern) => pattern.test(text));
}

/**
 * The tenant-isolation verdict for one call: true when any filtered column
 * names the principal, or any filter value is read off the session.
 */
export function filtersByPrincipal(
  columns: readonly string[],
  valueExpressions: readonly string[],
): boolean {
  if (columns.some(isPrincipalColumn)) return true;
  return valueExpressions.some(isPrincipalExpression);
}

/**
 * A foreign-key-shaped column: `businessId`, `project_id`, `tenantId`. A bare
 * `id` is excluded on purpose — filtering only by the row's own primary key is
 * the IDOR shape, not a scoping shape.
 */
function isEntityIdColumn(name: string): boolean {
  const words = splitWords(name);
  const last = words[words.length - 1];
  if (last !== "id" && last !== "uuid") return false;
  return words.length > 1;
}

/**
 * How well a call is scoped, as three states rather than a boolean.
 *
 * `"scoped"` is the honest answer for `where(eq(opportunities.businessId, businessId))`
 * in a codebase whose tenant happens to be a business: the call *is* narrowed
 * by an owning entity, but nothing here proves that entity is the caller's.
 * Collapsing that into `false` told the audit a query was unscoped when it was
 * merely scoped by a column this module does not recognise — which is how a
 * false positive reaches a client report.
 */
export type PrincipalScope = "yes" | "scoped" | "no";

/** The tri-state tenant-isolation signal, with the columns that produced it. */
export function principalScope(
  columns: readonly string[],
  valueExpressions: readonly string[],
): { scope: PrincipalScope; scopeColumns: string[] } {
  if (filtersByPrincipal(columns, valueExpressions)) {
    return { scope: "yes", scopeColumns: columns.filter(isPrincipalColumn) };
  }
  const entityColumns = columns.filter(isEntityIdColumn);
  if (entityColumns.length > 0) return { scope: "scoped", scopeColumns: entityColumns };
  return { scope: "no", scopeColumns: [] };
}

/** Receivers that are not column owners: a filter value, not a table alias. */
const NON_TABLE_RECEIVERS: ReadonlySet<string> = new Set([
  "auth",
  "body",
  "console",
  "ctx",
  "context",
  "data",
  "env",
  "event",
  "input",
  "JSON",
  "locals",
  "Math",
  "Number",
  "Object",
  "options",
  "params",
  "payload",
  "process",
  "props",
  "query",
  "req",
  "request",
  "res",
  "response",
  "search",
  "searchParams",
  "session",
  "String",
  "this",
  "url",
  "user",
  "args",
]);

/**
 * Column names read out of a comparison expression such as
 * `eq(bookings.organizationId, orgId)`.
 *
 * Drizzle, Kysely and TypeORM's query builder all address a column as
 * `<table>.<column>`, so the property of a member expression is the column —
 * unless the receiver is plainly a request or session object, in which case the
 * member expression is the *value* being compared against.
 */
export function memberColumns(expression: string): string[] {
  const columns: string[] = [];
  const pattern = /\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\b/g;
  for (;;) {
    const match = pattern.exec(expression);
    if (match === null) break;
    const receiver = match[1] ?? "";
    const column = match[2] ?? "";
    if (NON_TABLE_RECEIVERS.has(receiver)) continue;
    if (column === "") continue;
    columns.push(column);
  }
  return columns;
}

/** Value expressions in a comparison, i.e. everything that is not a column reference. */
export function comparisonValues(expression: string): string[] {
  const values: string[] = [];
  const pattern = /\b((?:[A-Za-z_$][\w$]*)(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)\b/g;
  for (;;) {
    const match = pattern.exec(expression);
    if (match === null) break;
    const path = (match[1] ?? "").replace(/\s+/g, "");
    if (path === "") continue;
    const receiver = path.split(".")[0] ?? "";
    if (NON_TABLE_RECEIVERS.has(receiver) || !path.includes(".")) values.push(path);
  }
  return values;
}

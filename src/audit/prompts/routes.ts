/**
 * The route-handler prompt (D2, with the D6 boundary checks).
 *
 * This is the prompt the whole dossier leans on. The five access-control
 * categories of D2 — tenant isolation, server-side authorization, IDOR, secrets
 * and injection — are all decided inside a request handler, and a linter cannot
 * decide any of them: there is no pattern for "this query should have been
 * scoped by the session's organisation". What there is, is the handler's source,
 * the auth helper it should have called, and the facts the inventory proved
 * about it (`authCheck: none`, `idParams: id`, `validation: none`). The prompt
 * hands over all three and asks the questions in that order.
 *
 * The checks deliberately include the ones whose answer is usually *pass*.
 * "All 23 mutation handlers assert ownership before writing" is an output of
 * this phase, and it only exists because every handler was asked.
 */

import { type AuditCheck, type PromptSpec, createPromptBuilder } from "./_shared.ts";

/** The D2/D6 questions asked of every route handler, in report order. */
export const ROUTE_CHECKS: readonly AuditCheck[] = [
  {
    name: "tenant-isolation",
    statement: "every read is constrained by the authenticated principal",
    rule: "appsec.missing-tenant-scope",
    question:
      "does every read or list this handler performs constrain the rows by the authenticated principal — the session's user id, organisation or tenant?",
    fails:
      "a query returns rows that belong to anyone, filtered only by an id or a status the caller supplies, or by nothing at all",
    ceiling: "critical",
    notApplicable:
      "the handler reads nothing, or the data it reads is deliberately public (a health check, a public listing)",
  },
  {
    name: "server-side-authorization",
    statement: "authorization is enforced by the handler itself",
    rule: "appsec.missing-authorization-check",
    question:
      "for a privileged action, does the handler itself check the caller's role or ownership before acting?",
    fails:
      "the handler performs a privileged or destructive action and the only check is authentication, a client-supplied role field, or nothing",
    ceiling: "critical",
    notApplicable: "the action is available to every authenticated user by design",
  },
  {
    name: "idor",
    statement: "objects are loaded with an ownership predicate",
    rule: "appsec.idor",
    question:
      "for every object id read from the path, query or body, is the object loaded with an ownership predicate rather than by id alone?",
    fails:
      "an id from the request selects a row and no part of the query or a following check ties that row to the caller",
    ceiling: "critical",
    notApplicable: "the handler reads no object id from the request",
  },
  {
    name: "input-validation",
    statement: "request input is validated against a schema before it is used",
    rule: "api.missing-input-validation",
    question:
      "is the request body, query and path validated against a schema before any value is used?",
    fails:
      "a request value reaches a query, a filesystem path, a template or a response without having been parsed by a schema or explicitly narrowed",
    ceiling: "high",
    notApplicable: "the handler reads nothing from the request",
  },
  {
    name: "mass-assignment",
    statement: "written fields are an explicit list, not a spread of the request body",
    subject: "mutation handlers",
    rule: "api.mass-assignment",
    question:
      "are the fields written to the database an explicit list, rather than a spread of the request body?",
    fails:
      "the body, or an object derived from it without a whitelist, is spread into a create or update",
    ceiling: "high",
    notApplicable: "the handler writes nothing",
  },
  {
    name: "output-serialisation",
    statement: "responses carry projected fields, not raw database rows",
    subject: "data-returning handlers",
    rule: "api.response-leaks-fields",
    question:
      "does the response carry only the fields the caller is entitled to, rather than a row straight out of the database?",
    fails:
      "a database row, or an object containing one, is returned without a projection, so a credential hash, an internal id, a soft-deleted row or another tenant's field can leave",
    ceiling: "high",
    notApplicable: "the handler returns no data",
  },
  {
    name: "error-handling",
    statement: "errors return a generic message with a correct status",
    rule: "api.error-leaks-internals",
    question:
      "do the error paths return a generic message with a correct status, and is every failure actually handled?",
    fails:
      "an error response carries a stack trace, a driver message or SQL; a caught error is swallowed; or a failure returns 200",
    ceiling: "medium",
  },
  {
    name: "secrets-and-config",
    statement: "credentials come from configuration, never from source",
    rule: "appsec.hardcoded-credential",
    question:
      "is every credential, token or signing key this handler uses read from configuration rather than written in the source?",
    fails:
      "a key, token, password or connection string is a literal in the code, or a fallback default stands in for one",
    ceiling: "critical",
    notApplicable: "the handler uses no credential",
  },
  {
    name: "rate-limit",
    statement: "callable endpoints are rate limited or otherwise cost-bounded",
    rule: "appsec.missing-rate-limit",
    question:
      "is this handler protected against being called in a loop — a limiter, a lock, or a cost bound on the work it does?",
    fails:
      "an expensive or credential-checking handler has no limiter anywhere in the code you were shown AND the facts do not record one",
    ceiling: "medium",
    notApplicable:
      "a limiter would be registered in middleware you were not shown: say so rather than guessing",
  },
];

/** How to read the facts the route enumerator attaches to a unit. */
const ROUTE_ATTRIBUTES: Readonly<Record<string, string>> = {
  method: "HTTP method, upper-case; `ANY` when the registration covers every method",
  path: "the resolved request path, or `unresolved` when Sentinel could not compose it",
  framework: "which framework registered it, as detected in phase 0",
  authenticated:
    "`yes` when Sentinel found an authentication check in the body, `no` when it did not",
  authCheck: "the guard call that was found, or `none`",
  authSource: "`file:line` of that guard",
  validation: "the schema applied to the input, or `none`",
  idParams: "object-id parameters the handler reads from the request",
  readsBody: "`true` when the handler reads the request body",
  mutates: "`true` when the method or the body changes state",
  pagination: "`limit`, `cursor` or `none`",
  handlerSymbol: "the exported function or method that is the handler",
  handlerSource:
    "`file:start-end` of that handler's body; when it is another file, that body is attached to this unit as related code",
};

/** The route-handler prompt spec. */
export const ROUTE_PROMPT: PromptSpec = {
  kind: "route",
  noun: "route handler",
  mission:
    "You decide whether each HTTP entry point enforces access control on the server, validates what it is given, and returns only what the caller is entitled to.",
  checks: ROUTE_CHECKS,
  attributes: ROUTE_ATTRIBUTES,
  guidance: [
    "`authenticated: no` means Sentinel's own pattern matching found no check in the body — it is a reason to look, not a finding on its own. The slice is the evidence.",
    "When a unit carries `handlerSource` for another file, the handler's body is the related slice above the registration: audit that body. The registration line is only where the path and the middleware are declared.",
    "Authentication is not authorization. A handler that resolves a session and then acts on an id the caller chose is still an IDOR.",
    "When the shared context contains the project's auth helper, read what it actually returns: a helper that resolves a session without asserting a role cannot be the authorization check for a privileged route.",
    "A guard applied by middleware or by a decorator may not be inside the slice. If the facts record `authCheck` with an `authSource` you were not shown, treat authentication as present and say so in the note.",
    "`path: unresolved` means Sentinel could not compose the path. Audit the handler anyway; do not report the unresolved path as a finding.",
    "A server action or a tRPC procedure is a route: it is reachable by anyone who can reach the application, and the argument it takes is as untrusted as a request body.",
  ],
};

/** The route-handler prompt builder. */
export const routePromptBuilder = createPromptBuilder(ROUTE_PROMPT);

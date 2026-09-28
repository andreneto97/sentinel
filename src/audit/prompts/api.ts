/**
 * The D6 prompt: API surface and contracts.
 *
 * `PLAN.md` specifies this domain and nothing implemented it, so a full run over a
 * repository full of routes would report `api — not assessed: no api check ran in
 * this run (0 of 0)` while `api.*` findings sat in `findings.json`, arriving as a
 * by-product of the route auditor's boundary checks. A domain that
 * produces findings and claims no coverage is the exact failure this project
 * exists to prevent: the score phase cannot tell whether `api` is clean or
 * unexamined, so it refuses to say either.
 *
 * This prompt asks the D6 questions of the unit the batch already carries — the
 * route handler — and it is the *second* pass over that unit, not a replacement
 * for the first. `routes.ts` asks whether the handler enforces access control;
 * this one asks what the endpoint promises its callers and whether it keeps the
 * promise. `src/audit/coverage.ts` was written for exactly this: "the same
 * handler is an `appsec` unit in the authorization batch and an `api` unit in the
 * contract batch", counted once per domain in the domain table and once overall
 * in the per-kind table.
 *
 * Five of the checks are deliberately *identical* to five of `routes.ts`'s —
 * same name, rule, statement and ceiling — because `_shared.ts` makes a check id
 * shared vocabulary: "two kinds may share an id only when they mean the same
 * thing", and an assurance published by both passes is one population, not two.
 * They are restated here rather than imported, so that a rename in `routes.ts`
 * breaks {@link SHARED_WITH_ROUTE_CHECKS} in `api.test.ts` — the place a
 * vocabulary change should be noticed — instead of silently forking it.
 *
 * Declaring them is not the same as billing for them. `./index.ts` projects a
 * prompt onto the checks no earlier row of the same kind already asks, so with
 * the route prompt registered first for `appsec` this spec is dispatched carrying
 * only its five *new* checks: the access-control pass answers input validation,
 * mass assignment, output serialisation, error handling and the rate limit, and
 * this pass answers what that pass cannot. Two consequences the guidance below
 * has to survive. The prompt must never instruct the model to answer under a key
 * `CHECKS` does not list, because the decoder would reject it as an
 * `unknown-check`; and two of `endpoint-matrix.md`'s four columns are filled from
 * the other pass's verdicts, which is why `_api-support.ts` joins a column to a
 * check *id* rather than to this spec.
 *
 * Five checks are new, and they are the ones a single pass could not carry:
 *
 * - **the matrix columns** `api.auth-requirement` and `api.pagination`, which
 *   exist so `endpoint-matrix.md` has an answer in every cell rather than a
 *   blank. `_api-support.ts` joins column to check id in one place.
 * - **`api.serializer-too-broad`**, the question `api.response-leaks-fields`
 *   cannot ask. The first asks whether a projection exists at all; this one asks
 *   whether the projection is *narrower than the entity behind it*. Where a
 *   codebase gives its serialisers files of their own, the field list is often
 *   derived from the contract schema's own keys rather than written out, so the
 *   answer turns on a schema the batch may not carry, and the check says so
 *   rather than guessing.
 * - **`api.misleading-status-code`**, where a status code is a disclosure: a
 *   failure answered `200`, or an authorization failure answered in a way that
 *   tells the caller the object exists.
 * - **`api.contract-drift`**, which is `not-applicable` unless a committed
 *   OpenAPI or GraphQL schema was quoted. A project that generates its OpenAPI
 *   document at build time and never commits it leaves this check nothing to
 *   compare against, so the honest answer is `not-applicable` naming the
 *   generator — which is the answer this check is built to give.
 *
 * Every check states the evidence it needs, and the rubric in
 * {@link API_GUIDANCE} fixes severity for this domain's own questions so the
 * model cannot invent a scale: another tenant's data leaving is `high`, a missing
 * bound on an unauthenticated endpoint is `medium`, the same gap behind
 * authentication is `low`.
 */

import type { Domain } from "../../contracts/findings.ts";
import { type AuditCheck, type PromptSpec, createPromptBuilder } from "./_shared.ts";

/**
 * The domain a batch built from this prompt attributes its coverage to.
 *
 * Not derivable from the unit kind: the kind is `route`, and
 * `DOMAIN_BY_UNIT_KIND` maps that to `appsec` — correctly, for the batch that
 * asks the access-control questions. `./index.ts` carries the authoritative
 * `(kind, domain)` row; this constant is what `api.test.ts` checks that row
 * against, so a builder wired onto a row for some other domain fails a test
 * instead of quietly leaving D6 at `0 of 0`.
 */
export const API_DOMAIN: Domain = "api";

/**
 * The checks this prompt shares verbatim with `routes.ts`, by name.
 *
 * The list is the contract `api.test.ts` enforces field by field. Sharing the id
 * is what lets one assurance population span both passes; sharing everything
 * *but* the id would make the report contradict itself.
 */
export const SHARED_WITH_ROUTE_CHECKS: readonly string[] = [
  "input-validation",
  "rate-limit",
  "mass-assignment",
  "output-serialisation",
  "error-handling",
];

/**
 * The D6 questions asked of every endpoint, in report order.
 *
 * The first four are the endpoint matrix's columns, in the order
 * `endpoint-matrix.md` prints them, so a reply read top to bottom fills the table
 * left to right. The rest are the contract questions.
 */
export const API_CHECKS: readonly AuditCheck[] = [
  {
    name: "auth-requirement",
    statement: "every endpoint states the auth it requires",
    rule: "api.undeclared-auth",
    question:
      "what does reaching this handler require — nothing, a session, a particular role, a machine credential — and is that requirement visible in the code, the facts or the shared context you were given?",
    fails:
      "nothing you were shown states any authentication or authorization requirement for this endpoint and the endpoint is not public by design, so the endpoint matrix would have to record its auth as unknown",
    ceiling: "low",
    notApplicable:
      "the endpoint is public by design — a health check, a documentation redirect, a webhook that authenticates by signature instead: name the line that shows it",
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
    name: "pagination",
    statement: "collection responses are bounded by a pagination contract",
    subject: "collection endpoints",
    rule: "api.unbounded-collection",
    question:
      "when this handler returns a collection, is the number of rows bounded by a pagination contract the caller can page through — a limit, a page or a cursor the handler actually applies?",
    fails:
      "a collection response has no limit, page or cursor that this handler applies, so the size of the response is decided by how much data exists rather than by the request",
    ceiling: "medium",
    notApplicable: "the handler returns a single object, a count, or no body at all",
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
    name: "serializer-breadth",
    statement: "serialisers expose a narrower field list than the entity behind them",
    subject: "serialised responses",
    rule: "api.serializer-too-broad",
    question:
      "when a serialiser, DTO or projection shapes this response, is its field list narrower than the entity it is handed, and does it leave out the fields no caller should see?",
    fails:
      "the projection's field list is the entity's own key list, or it names a password or token hash, an internal or provider id, a soft-delete column, or a foreign key to another tenant, without gating that field behind an explicit opt-in",
    ceiling: "high",
    notApplicable:
      "no serialiser, DTO or projection was quoted for this response, or its field list is computed from a schema you were not given: name the file you would have needed",
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
    name: "status-codes",
    statement: "status codes match what happened and disclose nothing further",
    rule: "api.misleading-status-code",
    question:
      "does every status this handler can return match what actually happened, and does it avoid telling the caller something the caller is not entitled to know?",
    fails:
      "a failure path answers 2xx; a caught error is answered with the success status; or an authorization failure on an object the caller may not see is answered in a way that distinguishes `exists but forbidden` from `does not exist`",
    ceiling: "medium",
    notApplicable:
      "the handler sets no status of its own and every failure is delegated to an error middleware you were not shown",
  },
  {
    name: "contract-drift",
    statement: "the committed API schema describes the endpoint as it is implemented",
    subject: "documented endpoints",
    rule: "api.contract-drift",
    question:
      "when a committed OpenAPI or GraphQL schema for this endpoint was quoted, does the implementation match it — the same path and method, the same required fields and types, the same success status, the same response shape?",
    fails:
      "the quoted schema and the handler disagree about a path, a method, a required field, a type, a success status or a response shape, or the schema omits an endpoint it claims to describe",
    ceiling: "medium",
    notApplicable:
      "no committed OpenAPI or GraphQL schema was quoted in this batch: say so and name the file you would have needed",
  },
];

/**
 * How to read the facts the route enumerator attaches to a unit.
 *
 * Wider than `routes.ts`'s table by three keys — `middleware`, `trigger` and
 * `symbol` — because the route enumerator attaches each of them whenever the
 * registration shows it, and `middleware` is the one fact that can settle the
 * rate-limit and auth columns without a slice. The descriptions of `validation`
 * and `pagination` are deliberately weaker than `routes.ts`'s: both come from
 * pattern matching that a codebase's own validation or pagination helper defeats
 * on every route at once, and a prompt that presents a pattern match as a fact
 * turns one enumerator's blind spot into one finding per endpoint.
 */
const API_ATTRIBUTES: Readonly<Record<string, string>> = {
  method: "HTTP method, upper-case; `ANY` when the registration covers every method",
  path: "the resolved request path, or `unresolved` when Sentinel could not compose it",
  framework: "which framework registered it, as detected in phase 0",
  trigger: "what invokes it; `http` for every route",
  authenticated:
    "`yes` when Sentinel's pattern matching found an authentication check in the body, `no` when it did not — not proof either way",
  authCheck: "the guard call that was found, or `none`",
  authSource: "`file:line` of that guard",
  middleware: "middleware named on the registration line, which is where a limiter usually sits",
  validation:
    "the schema call Sentinel matched, or `none` — which also means it matched nothing it recognises",
  pagination:
    "`limit`, `cursor` or `none`, from pagination *words* appearing in the handler rather than from a bound being applied",
  idParams: "object-id parameters the handler reads from the request",
  readsBody: "`true` when the handler reads the request body",
  mutates: "`true` when the method or the body changes state",
  symbol: "the enclosing function, component or class the unit sits in",
  handlerSymbol: "the exported function or method that is the handler",
  handlerSource:
    "`file:start-end` of that handler's body; when it is another file, that body is attached to this unit as related code",
};

/**
 * The reading rules and the severity rubric for this domain.
 *
 * The rubric is here rather than in a check's `fails` because it is one scale
 * across ten checks, and `_shared.ts` renders `guidance` into the prompt header —
 * so the model is given the scale before it is given a unit, and the per-rule
 * ceilings clamp anything it still gets wrong.
 */
export const API_GUIDANCE: readonly string[] = [
  "SEVERITY FOR THIS DOMAIN, which you may not replace with a scale of your own: a response, an error or a status code that lets a caller read another tenant's or another user's data — or learn that it exists — is `high`. A credential, token or password hash that can leave in a response is `high`. A missing rate limit or a missing pagination bound on an endpoint reachable WITHOUT authentication is `medium`; the same gap BEHIND authentication is `low`. A contract drift, a status-code mismatch or an undeclared auth requirement with no disclosure in it is `low`, and `info` when the endpoint is reachable only from inside the trust boundary. Each check also states a ceiling, and a finding above its ceiling is lowered to it.",
  "`endpoint-matrix.md` is published from four answers about every endpoint: the auth it requires, whether its input is validated, whether it paginates, and whether it is rate limited. Answer EVERY key CHECKS lists below and no others — a key CHECKS does not list is asked of this same handler by Sentinel's access-control pass, and an answer under it is discarded. When a check fills one of those four columns, put the column's *value* in its note: `requires: a session and the org-admin role`, `paginationSchema, perPage and page, applied at line 41`, `none`. A column left unanswered is printed in the published table as `not audited`, which is a hole in it.",
  "`validation: none` and `authenticated: no` are the results of Sentinel's own pattern matching, which looks for a `.parse(`-shaped call and a small set of guard names. A project that validates through a helper of its own — `parseRequest(schema, req)` — or that populates `req.auth` in middleware shows `none` on every route. Read the slice: a schema parsed through a project helper *is* validation, and a handler that reads `req.auth.user.id` is behind an authentication middleware. Treat every fact as a reason to look, never as an answer, and record in the note what the code actually does.",
  "For the serialiser check, decide on the field list you were shown. A serialiser that enumerates the entity's own keys — `attributes: entitySchema.keyof().options` — is not narrower than the entity, but whether that leaks depends on the schema; when the schema was not quoted, answer `not-applicable` and name it. A serialiser carrying an explicit deny list for its credentials, requiring an opt-in to expose them, passes: quote the line that does it.",
  "Do not report a query without a `LIMIT` here. That is the data layer's `data.unbounded-query`, asked of data-access units. This check is about the endpoint's contract: whether the caller can page through the collection at all. A handler that reads `perPage` and then ignores it fails this check even though the facts record `pagination: limit`.",
  "The control that guards an endpoint is usually registered as middleware, in a router mount or an application bootstrap that is not in your slice: the authentication, the rate limiter, the security headers. When the facts record `middleware` or `authSource`, or the shared context quotes the control, treat it as present and name it in the note. When nothing you were shown records it, answer the check that asked about it `not-applicable` and say where the control would have been — never report a control missing because you could not see where it is installed.",
  "A handler ending in `catch (error) { next(error) }` delegates its status and its error body to an error middleware. That is a status decided elsewhere, not a missing one: when the middleware was not quoted, answer the status question `not-applicable` and name it in the note. When it was quoted, judge the statuses it produces — whether a failure can reach the caller as a 2xx, and whether the status it chooses tells the caller more than it should.",
  "A server action, a tRPC procedure and a GraphQL resolver are endpoints here: the argument they take is as untrusted as a request body, and the contract questions apply to them unchanged.",
  "`path: unresolved` means Sentinel could not compose the path. Audit the endpoint anyway, and do not report the unresolved path as a finding.",
  "Sentinel audits this same handler a second time, for access control, and some of the questions this domain owns are asked there instead. Answer exactly the keys CHECKS lists, judge only what is in front of you, and file each finding once: what the other pass concluded is not your concern and is not something to guess at.",
];

/** The D6 endpoint prompt spec. */
export const API_PROMPT: PromptSpec = {
  kind: "route",
  noun: "API endpoint",
  mission:
    "You decide what each HTTP endpoint promises its callers and whether it keeps the promise: whether it validates what it is given, bounds what it returns, states the auth it requires, and answers with only the fields, the status and the error the caller is entitled to.",
  checks: API_CHECKS,
  attributes: API_ATTRIBUTES,
  guidance: API_GUIDANCE,
};

/**
 * The D6 prompt builder.
 *
 * Same `PromptBuilder` shape as every other module here, and `kind` is `route`
 * because a route unit is what it audits. Registering it therefore needs the
 * planner to allow a second builder over one kind, and to take the batch's domain
 * from {@link API_DOMAIN} rather than from `DOMAIN_BY_UNIT_KIND`.
 */
export const apiPromptBuilder = createPromptBuilder(API_PROMPT);

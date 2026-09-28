import { describe, expect, test } from "bun:test";
import { type AuditUnit, DomainSchema, SeveritySchema } from "../../contracts/findings.ts";
import {
  type EndpointMatrixRow,
  MATRIX_CHECK_IDS,
  MATRIX_COLUMNS,
  MATRIX_STATES,
  type MatrixVerdict,
  buildEndpointMatrix,
  formatColumnSummary,
  renderEndpointMatrix,
  summariseEndpointMatrix,
} from "./_api-support.ts";
import { type AuditCheck, type PromptContext, UNKNOWN_STACK, checkIdOf } from "./_shared.ts";
import {
  API_CHECKS,
  API_DOMAIN,
  API_GUIDANCE,
  SHARED_WITH_ROUTE_CHECKS,
  apiPromptBuilder,
} from "./api.ts";
import { PROMPT_REGISTRY } from "./index.ts";
import { ROUTE_CHECKS } from "./routes.ts";

/**
 * Four route units shaped as `inventory.json` carries them, over an invented
 * lending-library service: the service is invented, and the shape it is written
 * in is the one `src/inventory/` produces.
 *
 * Every id below is `unitId(kind, file, symbol)` — the construction
 * `src/inventory/inventory.ts` assigns, over these files and these route
 * symbols — and every attribute is a key the route enumerator attaches, carrying
 * a value its pattern matching can produce. That is the shape under test: a
 * service that validates through its own `validateRequest` helper and
 * authenticates in middleware enumerates as `validation: none` and
 * `authenticated: no` on every route, and a prompt that read those two as facts
 * would report one finding per endpoint that is not there.
 */
const LIST_BORROWER_CARDS: AuditUnit = {
  id: "1de5cad2b568764e",
  kind: "route",
  label: "GET /",
  location: { file: "apps/lending-api/src/http/v1/borrower-cards/router.ts", line: 11 },
  attributes: {
    authCheck: "none",
    authenticated: "no",
    framework: "express",
    handlerSource: "apps/lending-api/src/http/v1/borrower-cards/list.ts:27-71",
    handlerSymbol: "list",
    method: "GET",
    mutates: "false",
    pagination: "limit",
    path: "/",
    readsBody: "false",
    trigger: "http",
    validation: "none",
  },
};

const CREATE_BORROWER_CARD: AuditUnit = {
  id: "d0e89473a3899e19",
  kind: "route",
  label: "POST /",
  location: { file: "apps/lending-api/src/http/v1/borrower-cards/router.ts", line: 13 },
  attributes: {
    authCheck: "none",
    authenticated: "no",
    framework: "express",
    handlerSource: "apps/lending-api/src/http/v1/borrower-cards/create.ts:20-60",
    handlerSymbol: "create",
    method: "POST",
    mutates: "true",
    pagination: "none",
    path: "/",
    readsBody: "false",
    trigger: "http",
    validation: "none",
  },
};

const COVER_UPLOAD_URL: AuditUnit = {
  id: "ee0873316aa4fa57",
  kind: "route",
  label: "POST /cover-upload-url",
  location: { file: "apps/lending-api/src/http/v1/catalog-covers/router.ts", line: 9 },
  attributes: {
    authCheck: "none",
    authenticated: "no",
    framework: "express",
    handlerSource: "apps/lending-api/src/http/v1/catalog-covers/create-signed-url.ts:15-25",
    handlerSymbol: "createSignedUrl",
    method: "POST",
    middleware: "legacyCoverMiddleware",
    mutates: "true",
    pagination: "none",
    path: "/cover-upload-url",
    readsBody: "false",
    trigger: "http",
    validation: "none",
  },
};

const API_REFERENCE_REDIRECT: AuditUnit = {
  id: "983e9d9dfae5170e",
  kind: "route",
  label: "GET /api-reference",
  location: { file: "apps/lending-api/src/http/v1/index.ts", line: 12, endLine: 14 },
  attributes: {
    authCheck: "none",
    authenticated: "no",
    framework: "express",
    method: "GET",
    mutates: "false",
    pagination: "none",
    path: "/api-reference",
    readsBody: "false",
    trigger: "http",
    validation: "none",
  },
};

/** A route whose path argument is not a literal, so the enumerator resolved none. */
const REMOVE_MEMBER: AuditUnit = {
  id: "7272026d6a824e64",
  kind: "route",
  label: "DELETE unresolved",
  location: {
    file: "apps/lending-api/src/http/v1/members/remove.ts",
    line: 22,
    note: "the path argument is not a literal, so the route could not be resolved",
  },
  attributes: {
    authCheck: "none",
    authenticated: "no",
    framework: "express",
    idParams: "id",
    method: "DELETE",
    middleware: "branchId",
    mutates: "true",
    pagination: "none",
    path: "unresolved",
    readsBody: "false",
    symbol: "data",
    trigger: "http",
    validation: "none",
  },
};

/** The source slice of `list.ts`, as `src/inventory/slice.ts` renders one. */
const LIST_SLICE = [
  "// apps/lending-api/src/http/v1/borrower-cards/list.ts:27-33",
  "27 | export default async (req: Request, res: Response, next: NextFunction) => {",
  "28 |   try {",
  "29 |     const service = container.resolve(BorrowerCardService)",
  "30 |",
  "31 |     const parsed = await validateRequest(listCardsSchema, req)",
  "32 |     const librarianId = req.auth?.user?.id",
  "33 |     const { query } = parsed",
].join("\n");

/**
 * The create handler, which spreads the request body into the write.
 *
 * The facts say `readsBody: false` and the code says otherwise, which is the
 * pair the mass-assignment question has to be read against.
 */
const CREATE_SLICE = [
  "// apps/lending-api/src/http/v1/borrower-cards/create.ts:20-30",
  "20 | export default async (req: Request, res: Response, next: NextFunction) => {",
  "21 |   try {",
  "22 |     const service = container.resolve(BorrowerCardService)",
  "23 |     const { body, params } = await validateRequest(createCardSchema, req)",
  "24 |",
  "25 |     const card = await service.create({ ...body, branchId: params.branchId })",
  "26 |",
  "27 |     res.status(201).json(borrowerCardSerializer(card))",
  "28 |   } catch (error) {",
  "29 |     next(error)",
  "30 |   }",
].join("\n");

/** A check of `API_CHECKS`, by the name the prompt lists it under. */
function apiCheck(name: string): AuditCheck | undefined {
  return API_CHECKS.find((check) => check.name === name);
}

/** A check of `ROUTE_CHECKS`, by name. */
function routeCheck(name: string): AuditCheck | undefined {
  return ROUTE_CHECKS.find((check) => check.name === name);
}

describe("the D6 check vocabulary", () => {
  test("every rule names a real domain and every check id is derived from it", () => {
    for (const check of API_CHECKS) {
      const domain = check.rule.split(".")[0] ?? "";
      expect(DomainSchema.safeParse(domain).success).toBe(true);
      expect(checkIdOf(check)).toBe(`${domain}.${check.name}`);
      expect(SeveritySchema.safeParse(check.ceiling).success).toBe(true);
    }
  });

  test("check ids and check names are unique inside the prompt", () => {
    const ids = API_CHECKS.map((check) => checkIdOf(check));
    expect(new Set(ids).size).toBe(ids.length);
    const names = API_CHECKS.map((check) => check.name);
    expect(new Set(names).size).toBe(names.length);
  });

  test("every check carries a question, a failure condition and a report-voice statement", () => {
    for (const check of API_CHECKS) {
      expect(check.question.length).toBeGreaterThan(20);
      expect(check.fails.length).toBeGreaterThan(20);
      expect(check.statement.length).toBeGreaterThan(15);
      // Mirrors the invariant `prompts.test.ts` applies to every registered kind,
      // so this prompt satisfies it before the integrator registers it.
      expect(check.statement.startsWith("no ") || !check.statement.includes("missing")).toBe(true);
    }
  });

  test("the checks shared with the route prompt are identical in every field", () => {
    for (const name of SHARED_WITH_ROUTE_CHECKS) {
      const mine = apiCheck(name);
      const theirs = routeCheck(name);
      expect(mine).toBeDefined();
      expect(theirs).toBeDefined();
      // `_shared.ts`: a check id shared by two prompts must mean the same thing,
      // or one assurance population becomes two that contradict each other.
      expect(mine).toEqual(theirs);
    }
  });

  test("SHARED_WITH_ROUTE_CHECKS names the whole overlap and nothing else", () => {
    const routeNames = new Set(ROUTE_CHECKS.map((check) => check.name));
    const overlap = API_CHECKS.filter((check) => routeNames.has(check.name)).map(
      (check) => check.name,
    );
    expect([...overlap].sort()).toEqual([...SHARED_WITH_ROUTE_CHECKS].sort());
  });

  test("the questions the route prompt cannot ask carry rules of their own", () => {
    const routeRules = new Set(ROUTE_CHECKS.map((check) => check.rule));
    const added = API_CHECKS.filter((check) => !routeRules.has(check.rule)).map(
      (check) => check.rule,
    );
    expect([...added].sort()).toEqual([
      "api.contract-drift",
      "api.misleading-status-code",
      "api.serializer-too-broad",
      "api.unbounded-collection",
      "api.undeclared-auth",
    ]);
  });

  test("every endpoint-matrix column is answered by one of these checks", () => {
    const ids = new Set(API_CHECKS.map((check) => checkIdOf(check)));
    for (const id of MATRIX_CHECK_IDS) expect(ids.has(id)).toBe(true);
    expect(MATRIX_CHECK_IDS.length).toBe(MATRIX_COLUMNS.length);
  });

  test("the matrix columns are the first four checks, in the order the table prints them", () => {
    expect(API_CHECKS.slice(0, MATRIX_CHECK_IDS.length).map((check) => checkIdOf(check))).toEqual([
      ...MATRIX_CHECK_IDS,
    ]);
  });

  test("every attribute a matrix column falls back to is one the route enumerator attaches", () => {
    for (const column of MATRIX_COLUMNS) {
      if (column.attribute === undefined) continue;
      expect(Object.keys(LIST_BORROWER_CARDS.attributes)).toContain(column.attribute);
    }
  });

  test("the batch domain is api, not the unit kind's appsec", () => {
    expect(API_DOMAIN).toBe("api");
    expect(apiPromptBuilder.kind).toBe("route");
  });

  test("the registry declares a route row for this domain, so D6 coverage has somewhere to land", () => {
    const row = PROMPT_REGISTRY.find(
      (entry) => entry.kind === "route" && entry.domain === API_DOMAIN,
    );
    // Declared but still `pending` until the integrator sets `builder:`; either
    // way the row must exist, because a domain with no row reads `0 of 0` with
    // no sentence beside it — the failure this prompt was written to close.
    expect(row).toBeDefined();
    expect(row?.builder ?? apiPromptBuilder).toBe(apiPromptBuilder);
  });

  test("the checks the access-control pass already asks are the ones the registry projects away", () => {
    // `./index.ts` keeps, for a kind's second row, only the checks no earlier row
    // claims. With the route prompt registered first for `appsec`, that leaves
    // exactly the five questions it cannot ask — so the second batch is paid for
    // only once and never buys an answer twice.
    const claimed = new Set(ROUTE_CHECKS.map((check) => checkIdOf(check)));
    const projected = API_CHECKS.filter((check) => !claimed.has(checkIdOf(check)));
    expect(projected.map((check) => check.name)).toEqual([
      "auth-requirement",
      "pagination",
      "serializer-breadth",
      "status-codes",
      "contract-drift",
    ]);
  });

  test("the matrix columns the projection removes are answered by the pass that keeps them", () => {
    const routeIds = new Set(ROUTE_CHECKS.map((check) => checkIdOf(check)));
    const mine = new Set(API_CHECKS.map((check) => checkIdOf(check)));
    for (const id of MATRIX_CHECK_IDS) expect(routeIds.has(id) || mine.has(id)).toBe(true);
    // Two columns come from each pass; neither pass alone fills the table.
    expect(MATRIX_CHECK_IDS.filter((id) => routeIds.has(id))).toEqual([
      "api.input-validation",
      "appsec.rate-limit",
    ]);
  });
});

describe("the D6 prompt", () => {
  const context: PromptContext = { stack: UNKNOWN_STACK, shared: [], batchId: "api-1" };

  test("the system prompt offers only the rules its own checks use", () => {
    const system = apiPromptBuilder.systemPrompt();
    for (const check of API_CHECKS) expect(system).toContain(check.rule);
    expect(system).not.toContain("appsec.idor");
    expect(system).not.toContain("data.unbounded-query");
    expect(system).toContain("no filesystem");
    expect(system).toContain("Reply with ONE JSON document");
  });

  test("the header states the severity rubric for this domain before any unit", () => {
    const header = apiPromptBuilder.header(context, [
      { unit: LIST_BORROWER_CARDS, sliceText: LIST_SLICE, related: [] },
    ]);
    expect(header).toContain("SEVERITY FOR THIS DOMAIN");
    expect(header).toContain("WITHOUT authentication is `medium`");
    expect(header).toContain("BEHIND authentication is `low`");
    for (const check of API_CHECKS) expect(header).toContain(`"${checkIdOf(check)}"`);
    expect(header).toContain("BATCH api-1");
  });

  test("the header refuses to present the enumerator's pattern match as a fact", () => {
    const header = apiPromptBuilder.header(context, [
      { unit: LIST_BORROWER_CARDS, sliceText: LIST_SLICE, related: [] },
    ]);
    expect(header).toContain("not proof either way");
    expect(header).toContain("pagination *words*");
    // Every reading rule reaches the header, so the caveat that tells the model
    // to read the slice rather than the fact cannot be dropped from the spec
    // without this failing — whatever words it is written in.
    expect(API_GUIDANCE.length).toBeGreaterThan(5);
    for (const line of API_GUIDANCE) expect(header).toContain(line);
  });

  test("a unit section carries the enumerated facts and the source slice", () => {
    const section = apiPromptBuilder.section({
      unit: LIST_BORROWER_CARDS,
      sliceText: LIST_SLICE,
      related: [],
    });
    expect(section).toContain("UNIT 1de5cad2b568764e");
    expect(section).toContain("at: apps/lending-api/src/http/v1/borrower-cards/router.ts:11");
    expect(section).toContain("pagination: limit");
    expect(section).toContain(
      "handlerSource: apps/lending-api/src/http/v1/borrower-cards/list.ts:27-71",
    );
    expect(section).toContain(
      "31 |     const parsed = await validateRequest(listCardsSchema, req)",
    );
  });

  test("a mutating section carries the body spread the mass-assignment check is read against", () => {
    const section = apiPromptBuilder.section({
      unit: CREATE_BORROWER_CARD,
      sliceText: CREATE_SLICE,
      related: [],
    });
    expect(section).toContain("UNIT d0e89473a3899e19");
    expect(section).toContain("mutates: true");
    // The fact says the body is not read; the line says it is spread into the
    // write. Both are in front of the model, which is what the check needs.
    expect(section).toContain("readsBody: false");
    expect(section).toContain("service.create({ ...body, branchId: params.branchId })");
  });

  test("an unresolved path is still audited, and its reason travels with it", () => {
    const section = apiPromptBuilder.section({
      unit: REMOVE_MEMBER,
      sliceText: "// apps/lending-api/src/http/v1/members/remove.ts:22-22\n22 | const data = await",
      related: [],
    });
    expect(section).toContain("path: unresolved");
    expect(section).toContain("note: the path argument is not a literal");
  });

  test("the footer demands every check for every unit id", () => {
    const footer = apiPromptBuilder.footer([
      { unit: LIST_BORROWER_CARDS, sliceText: LIST_SLICE, related: [] },
      { unit: CREATE_BORROWER_CARD, sliceText: CREATE_SLICE, related: [] },
    ]);
    expect(footer).toContain("A VERDICT IS REQUIRED FOR ALL 2 OF THESE UNIT IDS");
    expect(footer).toContain("1de5cad2b568764e");
    expect(footer).toContain("d0e89473a3899e19");
    expect(footer).toContain(`${API_CHECKS.length} checks`);
  });
});

describe("the endpoint matrix", () => {
  /** The verdict the D6 pass would return for the borrower-card list endpoint. */
  const listVerdict: MatrixVerdict = {
    unitId: LIST_BORROWER_CARDS.id,
    checks: [
      {
        checkId: "api.auth-requirement",
        result: "pass",
        note: "requires: a session; the handler reads req.auth.user.id at line 32",
      },
      {
        checkId: "api.input-validation",
        result: "pass",
        note: "listCardsSchema, parsed by validateRequest at line 31",
      },
      { checkId: "api.pagination", result: "pass", note: "cardPageSchema, perPage and page" },
      {
        checkId: "appsec.rate-limit",
        result: "not-applicable",
        note: "a limiter would be registered in the application bootstrap, which was not quoted",
      },
    ],
  };

  test("a route with no verdict reads not audited, never no", () => {
    const rows = buildEndpointMatrix([CREATE_BORROWER_CARD], []);
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row?.validation.state).toBe("not-audited");
    expect(row?.auth.state).toBe("not-audited");
    expect(row?.pagination.state).toBe("not-audited");
    expect(row?.rateLimit.state).toBe("not-audited");
  });

  test("the enumerator's fact fills the detail of an unanswered cell, labelled as such", () => {
    const rows = buildEndpointMatrix([LIST_BORROWER_CARDS], []);
    expect(rows[0]?.validation.detail).toBe("enumerated: none");
    expect(rows[0]?.pagination.detail).toBe("enumerated: limit");
    // Nothing in the inventory records a limiter, so there is nothing to quote.
    expect(rows[0]?.rateLimit.detail).toBe("");
  });

  test("a verdict decides the cell, and its note is what the column prints", () => {
    const rows = buildEndpointMatrix([LIST_BORROWER_CARDS], [listVerdict]);
    const row = rows[0];
    expect(row?.validation.state).toBe("yes");
    expect(row?.validation.detail).toBe("listCardsSchema, parsed by validateRequest at line 31");
    expect(row?.auth.state).toBe("yes");
    expect(row?.pagination.state).toBe("yes");
    expect(row?.rateLimit.state).toBe("not-applicable");
    expect(row?.rateLimit.detail).toContain("application bootstrap");
  });

  test("a failed check is the finding the table shows as a gap", () => {
    const rows = buildEndpointMatrix(
      [COVER_UPLOAD_URL],
      [
        {
          unitId: COVER_UPLOAD_URL.id,
          checks: [
            {
              checkId: "api.input-validation",
              result: "fail",
              note: "req.body reaches the signer",
            },
            { checkId: "api.auth-requirement", result: "fail" },
          ],
        },
      ],
    );
    expect(rows[0]?.validation.state).toBe("no");
    expect(rows[0]?.validation.detail).toBe("req.body reaches the signer");
    // No note: the state alone is the answer, and the enumerated fact backs it.
    expect(rows[0]?.auth.state).toBe("no");
    expect(rows[0]?.auth.detail).toBe("enumerated: none");
  });

  test("a public-by-design endpoint reads n/a rather than a failure", () => {
    const rows = buildEndpointMatrix(
      [API_REFERENCE_REDIRECT],
      [
        {
          unitId: API_REFERENCE_REDIRECT.id,
          checks: [
            {
              checkId: "api.auth-requirement",
              result: "not-applicable",
              note: "a documentation redirect, public by design (line 12)",
            },
          ],
        },
      ],
    );
    expect(rows[0]?.auth.state).toBe("not-applicable");
    expect(renderEndpointMatrix(rows)).toContain("n/a — a documentation redirect");
  });

  test("only route units get a row", () => {
    const query: AuditUnit = {
      id: "q1",
      kind: "data-access",
      label: "find borrowerCards",
      location: { file: "libs/lending/src/application/base.service.ts", line: 40 },
      attributes: {},
    };
    expect(buildEndpointMatrix([LIST_BORROWER_CARDS, query], []).map((row) => row.unitId)).toEqual([
      LIST_BORROWER_CARDS.id,
    ]);
  });

  test("rows are sorted by path, then method, then location, so two runs agree", () => {
    const forward = buildEndpointMatrix(
      [COVER_UPLOAD_URL, API_REFERENCE_REDIRECT, CREATE_BORROWER_CARD, LIST_BORROWER_CARDS],
      [],
    );
    const reversed = buildEndpointMatrix(
      [LIST_BORROWER_CARDS, CREATE_BORROWER_CARD, API_REFERENCE_REDIRECT, COVER_UPLOAD_URL],
      [],
    );
    expect(forward.map((row) => `${row.method} ${row.path}`)).toEqual([
      "GET /",
      "POST /",
      "GET /api-reference",
      "POST /cover-upload-url",
    ]);
    expect(renderEndpointMatrix(forward)).toBe(renderEndpointMatrix(reversed));
  });

  test("a note containing a pipe cannot break the rendered table", () => {
    const rows = buildEndpointMatrix(
      [LIST_BORROWER_CARDS],
      [
        {
          unitId: LIST_BORROWER_CARDS.id,
          checks: [
            {
              checkId: "api.input-validation",
              result: "pass",
              note: "listCardsSchema\n  | filters | pagination",
            },
          ],
        },
      ],
    );
    expect(rows[0]?.validation.detail).toBe("listCardsSchema \\| filters \\| pagination");
    const table = renderEndpointMatrix(rows)
      .split("\n")
      .filter((line) => line.startsWith("| GET"));
    expect(table).toHaveLength(1);
    expect(table[0]?.split(" | ")).toHaveLength(7);
  });

  test("the rendered document discloses what an unanswered cell means", () => {
    const markdown = renderEndpointMatrix(buildEndpointMatrix([LIST_BORROWER_CARDS], []));
    expect(markdown).toContain("# Endpoint matrix");
    expect(markdown).toContain("1 route handler enumerated by Sentinel.");
    expect(markdown).toContain("never rendered as `no`, because nobody asked");
    expect(markdown).toContain(
      "| Method | Path | Auth | Validated | Paginated | Rate limited | Declared at |",
    );
    expect(markdown).toContain(
      "| GET | `/` | not audited — enumerated: none | not audited — enumerated: none | not audited — enumerated: limit | not audited | apps/lending-api/src/http/v1/borrower-cards/router.ts:11 |",
    );
    expect(markdown.endsWith("\n")).toBe(true);
  });

  test("the summary counts every state of every column, and omits none that occurred", () => {
    const rows = buildEndpointMatrix([LIST_BORROWER_CARDS, CREATE_BORROWER_CARD], [listVerdict]);
    const summary = summariseEndpointMatrix(rows);
    expect(summary.map((column) => column.key)).toEqual([
      "auth",
      "validation",
      "pagination",
      "rateLimit",
    ]);
    const validation = summary.find((column) => column.key === "validation");
    expect(validation?.counts).toEqual({ yes: 1, no: 0, "not-applicable": 0, "not-audited": 1 });
    // biome-ignore lint/style/noNonNullAssertion: asserted defined on the line above
    expect(formatColumnSummary(validation!)).toBe("Validated: 1 yes, 1 not audited");
    const rateLimit = summary.find((column) => column.key === "rateLimit");
    expect(rateLimit).toBeDefined();
    // biome-ignore lint/style/noNonNullAssertion: asserted defined on the line above
    expect(formatColumnSummary(rateLimit!)).toBe("Rate limited: 1 n/a, 1 not audited");
  });

  test("every state a row can hold is one the summary knows about", () => {
    const rows: EndpointMatrixRow[] = buildEndpointMatrix([LIST_BORROWER_CARDS], [listVerdict]);
    for (const row of rows) {
      for (const column of MATRIX_COLUMNS) {
        expect(MATRIX_STATES).toContain(row[column.key].state);
      }
    }
  });
});

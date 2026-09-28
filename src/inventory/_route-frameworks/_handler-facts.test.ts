import { describe, expect, test } from "bun:test";
import {
  type HandlerInput,
  authenticationCheck,
  balancedArgument,
  changesState,
  guardLabel,
  inputValidation,
  looksLikeGuardName,
  looksLikeObjectId,
  objectIdParameters,
  paginationStyle,
  readHandler,
  readsRequestBody,
  receiverBefore,
} from "./_handler-facts.ts";

/** A handler whose body is `source`, starting at line 10 of `src/api.ts`. */
function handler(source: string, extra: Partial<HandlerInput> = {}): HandlerInput {
  return { file: "src/api.ts", regions: [{ text: source, startLine: 10 }], ...extra };
}

describe("looksLikeObjectId", () => {
  test("id words and camel or snake boundaries are ids", () => {
    for (const name of ["id", "uuid", "slug", "userId", "post_id", "orgID", "tenantUuid"]) {
      expect(looksLikeObjectId(name)).toBe(true);
    }
  });

  test("words that merely end in the letters are not", () => {
    for (const name of ["valid", "grid", "paid", "void", "apiKey", "email"]) {
      expect(looksLikeObjectId(name)).toBe(false);
    }
  });

  test("a route path is not a parameter name, however it ends", () => {
    expect(looksLikeObjectId("/:userId")).toBe(false);
    expect(looksLikeObjectId("/teams/:teamId")).toBe(false);
  });
});

describe("objectIdParameters", () => {
  test("ids are collected from the path and from every way the body reads them", () => {
    const input = handler(
      `const { orgId, name } = req.query;
       const post = await db.post.findUnique({ where: { id: req.params.postId } });
       const tenant = searchParams.get("tenantId");
       const other = body.email;`,
      { path: "/orgs/:orgId/posts/:postId" },
    );
    expect(objectIdParameters(input)).toEqual(["orgId", "postId", "tenantId"]);
  });

  test("Nest parameter decorators name the ids they bind", () => {
    // The committed Nest fixture cannot carry parameter decorators: they need
    // `experimentalDecorators`, which this repository does not enable. The
    // detector is exercised here instead, against the source Nest generates.
    const input = handler(
      'async findOne(@Param("userId") userId: string, @Query("cursor") cursor: string) {}',
    );
    expect(objectIdParameters(input)).toEqual(["userId"]);
  });

  test("a handler that reads no identifier reports none", () => {
    expect(objectIdParameters(handler("return NextResponse.json({ ok: true });"))).toEqual([]);
  });
});

describe("readsRequestBody", () => {
  test("every way of reading the request body counts", () => {
    for (const source of [
      "const body = await request.json();",
      "const data = req.body;",
      "const form = await request.formData();",
      "async create(@Body() dto: CreateUserDto) {}",
      "const parsed = await c.req.json();",
    ]) {
      expect(readsRequestBody(handler(source))).toBe(true);
    }
  });

  test("writing the response body in Koa is not reading the request", () => {
    expect(readsRequestBody(handler("context.body = await db.post.findMany();"))).toBe(false);
    expect(readsRequestBody(handler("ctx.body = rows;"))).toBe(false);
  });

  test("a comparison against the body is still a read", () => {
    expect(readsRequestBody(handler("if (req.body === undefined) return;"))).toBe(true);
  });
});

describe("authenticationCheck", () => {
  test("a named guard is found, with the line it runs on", () => {
    const found = authenticationCheck(handler("const x = 1;\nconst user = await requireUser();"));
    expect(found?.line).toBe(11);
    expect(guardLabel(found?.text ?? "")).toBe("requireUser()");
  });

  test("a session helper only counts when it is called with nothing", () => {
    expect(authenticationCheck(handler("const s = await getSession();"))).toBeDefined();
    expect(authenticationCheck(handler("const u = getUser(params.id);"))).toBeUndefined();
  });

  test("library checks are recognised by shape", () => {
    for (const source of [
      "const { data } = await supabase.auth.getUser();",
      "const payload = jwt.verify(token, secret);",
      "@UseGuards(AuthGuard)",
      "const claims = await jwtVerify(token, key);",
    ]) {
      expect(authenticationCheck(handler(source))).toBeDefined();
    }
  });

  test("a hand-rolled guard is recognised by its shape, not by a list", () => {
    expect(authenticationCheck(handler("assertTenantAccess(user, org);"))).toBeDefined();
    expect(authenticationCheck(handler("validateInputShape(body);"))).toBeUndefined();
  });

  test("a project's own guard is recognised when phase 0 proved where it lives", () => {
    const input = handler("const viewer = await ownGuard();", { guards: new Set(["ownGuard"]) });
    expect(authenticationCheck(input)).toBeDefined();
    expect(authenticationCheck(handler("const viewer = await ownGuard();"))).toBeUndefined();
  });

  test("a handler with no check at all says none", () => {
    expect(authenticationCheck(handler("return db.user.findMany();"))).toBeUndefined();
  });
});

describe("looksLikeGuardName", () => {
  test("middleware that guards is told apart from middleware that does not", () => {
    for (const name of ["requireUser", "isAuthenticated", "authMiddleware", "ensureSession"]) {
      expect(looksLikeGuardName(name)).toBe(true);
    }
    for (const name of ["cors", "json", "logger", "compression", "rateLimit"]) {
      expect(looksLikeGuardName(name)).toBe(false);
    }
  });
});

describe("inputValidation", () => {
  test("the schema is named, not just the library", () => {
    expect(inputValidation(handler("const body = UpdateUser.parse(await req.json());"))?.text).toBe(
      "UpdateUser",
    );
  });

  test("an inline schema comes back whole", () => {
    const found = inputValidation(handler("const x = z.object({ id: z.string() }).parse(input);"));
    expect(found?.text).toBe("z.object({ id: z.string() })");
  });

  test("a declared input schema is read to its closing parenthesis", () => {
    const found = inputValidation(
      handler("publicProcedure.input(z.object({ postId: z.string() })).query(fn)"),
    );
    expect(found?.text).toBe("z.object({ postId: z.string() })");
  });

  test("parsing JSON is not validating input", () => {
    expect(inputValidation(handler("const data = JSON.parse(raw);"))).toBeUndefined();
    expect(inputValidation(handler("const n = Number.parseInt(value, 10);"))).toBeUndefined();
  });

  test("valibot's functional form names its schema too", () => {
    expect(inputValidation(handler("const data = parse(CreateUser, body);"))?.text).toBe(
      "CreateUser",
    );
  });
});

describe("receiverBefore and balancedArgument", () => {
  test("the receiver of a call is read back through its own parentheses", () => {
    const text = "z.object({ a: 1 }).parse(x)";
    expect(receiverBefore(text, text.indexOf(".parse"))).toBe("z.object({ a: 1 })");
    expect(receiverBefore("Schema.parse(x)", "Schema".length)).toBe("Schema");
  });

  test("an argument list is read to the parenthesis that closes it", () => {
    const text = "input(z.object({ a: fn(1, 2) }))";
    expect(balancedArgument(text, text.indexOf("("))).toBe("z.object({ a: fn(1, 2) })");
    expect(balancedArgument("input(unclosed", 5)).toBeUndefined();
  });
});

describe("paginationStyle and changesState", () => {
  test("keyset pagination outranks offset pagination", () => {
    expect(paginationStyle(handler("db.post.findMany({ cursor, take: 20 })"))).toBe("cursor");
    expect(paginationStyle(handler("db.post.findMany({ take: 20 })"))).toBe("limit");
    expect(paginationStyle(handler("db.post.findMany()"))).toBe("none");
  });

  test("a mutating method mutates, and so does a write in a read handler", () => {
    expect(changesState(handler("return rows;", { method: "DELETE" }))).toBe(true);
    expect(changesState(handler("await db.user.update({ where });", { method: "GET" }))).toBe(true);
    expect(changesState(handler('await db.query("INSERT INTO audit VALUES (1)");'))).toBe(true);
    expect(changesState(handler("return db.user.findMany();", { method: "GET" }))).toBe(false);
  });
});

describe("readHandler", () => {
  test("an unguarded handler that loads an object by id reports exactly that", () => {
    const facts = readHandler(
      handler("const post = await db.post.findUnique({ where: { id: params.postId } });", {
        method: "GET",
        path: "/posts/:postId",
      }),
    );
    expect(facts).toEqual({
      idParams: "postId",
      readsBody: "false",
      authCheck: "none",
      authenticated: "no",
      validation: "none",
      pagination: "none",
      mutates: "false",
    });
  });

  test("a guarded, validated, paginated handler reports every one of them", () => {
    const facts = readHandler(
      handler(
        `const user = await requireUser();
         const body = UpdateUser.parse(await request.json());
         return db.post.updateMany({ where: { authorId: user.id }, take: 10 });`,
        { method: "PATCH", path: "/posts" },
      ),
    );
    expect(facts.authCheck).toBe("requireUser()");
    expect(facts.authSource).toBe("src/api.ts:10");
    expect(facts.authenticated).toBe("yes");
    expect(facts.validation).toBe("UpdateUser");
    expect(facts.readsBody).toBe("true");
    expect(facts.pagination).toBe("limit");
    expect(facts.mutates).toBe("true");
  });

  test("a forced body read is honoured, for a shape the body cannot show", () => {
    expect(readHandler(handler("return 1;", { readsBody: true })).readsBody).toBe("true");
  });
});

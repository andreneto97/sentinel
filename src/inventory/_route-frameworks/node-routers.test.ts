import { describe, expect, test } from "bun:test";
import { astGrepBinary, enumerateFixture, unitLabelled } from "./_test-support.ts";
import {
  chainPath,
  constructionPrefix,
  frameworkOfFactory,
  methodList,
  parseFactory,
} from "./node-routers.ts";

const AST_GREP = await astGrepBinary();

describe("parseFactory", () => {
  test("the declarator's own text names the variable and the factory", () => {
    expect(parseFactory("app = express()")).toEqual({ name: "app", callee: "express" });
    expect(parseFactory("router = express.Router()")).toEqual({
      name: "router",
      callee: "express.Router",
    });
  });

  test("a type annotation or a type argument does not hide either of them", () => {
    expect(parseFactory("app: Express = express()")).toEqual({ name: "app", callee: "express" });
    expect(parseFactory("api = new Hono<{ Bindings: Env }>()")).toEqual({
      name: "api",
      callee: "Hono",
    });
  });
});

describe("frameworkOfFactory", () => {
  test("a bare `Router` is Express, unless the file imports Koa's", () => {
    expect(frameworkOfFactory("Router", new Set(["express"]))).toBe("express");
    expect(frameworkOfFactory("Router", new Set(["@koa/router"]))).toBe("koa");
  });

  test("each factory names its own framework", () => {
    expect(frameworkOfFactory("Fastify", new Set())).toBe("fastify");
    expect(frameworkOfFactory("Hono", new Set())).toBe("hono");
    expect(frameworkOfFactory("Koa", new Set())).toBe("koa");
    expect(frameworkOfFactory("Map", new Set())).toBeUndefined();
  });
});

describe("constructionPrefix", () => {
  test("Koa's option and Hono's basePath are both prefixes", () => {
    expect(constructionPrefix('router = new Router({ prefix: "/api/koa" })')).toBe("/api/koa");
    expect(constructionPrefix('api = new Hono().basePath("/api/v2")')).toBe("/api/v2");
  });

  test("a router built with no prefix has none", () => {
    expect(constructionPrefix("app = express()")).toBeUndefined();
    expect(constructionPrefix("r = new Router({ prefix: base })")).toBeUndefined();
  });
});

describe("chainPath and methodList", () => {
  test("an Express chain carries its path on the `.route()` call", () => {
    expect(chainPath('admin.route("/reports").get(handler)')).toBe("/reports");
    expect(chainPath("admin.get(handler)")).toBeUndefined();
  });

  test("a method option can name one method or several", () => {
    expect(methodList('"PUT"')).toEqual(["PUT"]);
    expect(methodList('["GET", "POST"]')).toEqual(["GET", "POST"]);
    expect(methodList(undefined)).toEqual(["ANY"]);
    expect(methodList("allowedMethods")).toEqual(["ANY"]);
  });
});

describe.skipIf(AST_GREP === null)("router registrations in the fixture", () => {
  test("a route mounted under a prefix reports the full path", async () => {
    const outcome = await enumerateFixture();
    const read = unitLabelled(outcome, "GET /api/users/:userId");
    expect(read?.attributes).toMatchObject({
      framework: "express",
      method: "GET",
      path: "/api/users/:userId",
      idParams: "userId",
      middleware: "requireUser",
      authCheck: "requireUser",
      authenticated: "yes",
    });
  });

  test("a handler imported one-per-file is resolved, so its facts come from its own body", async () => {
    const outcome = await enumerateFixture();
    const remove = unitLabelled(outcome, "DELETE /api/orders/:orderId");
    expect(remove?.file).toBe("src/server/orders-router.ts");
    // The registration is one line; everything a verdict needs is in the other file.
    expect(remove?.attributes.handlerSource).toBe("src/server/orders/remove.ts:11-15");
    expect(remove?.attributes.handlerSymbol).toBe("removeOrder");
    expect(remove?.attributes.authCheck).toBe("getSession()");
    expect(remove?.attributes.authenticated).toBe("yes");
    // The guard is cited where it actually runs, not where the route was registered.
    expect(remove?.attributes.authSource).toBe("src/server/orders/remove.ts:12");
    expect(remove?.attributes.idParams).toBe("orderId");
    expect(remove?.attributes.mutates).toBe("true");
  });

  test("`export default listOrders` is followed to the function it names", async () => {
    const outcome = await enumerateFixture();
    const list = unitLabelled(outcome, "GET /api/orders");
    expect(list?.attributes.handlerSource).toBe("src/server/orders/list.ts:6-8");
    expect(list?.attributes.handlerSymbol).toBe("listOrders");
    expect(list?.attributes.pagination).toBe("limit");
  });

  test("an imported middleware is never mistaken for the handler", async () => {
    const outcome = await enumerateFixture();
    // `requireUser` is imported and passed before an inline handler: following
    // the import would read the guard's body and cite it as the handler's.
    const read = unitLabelled(outcome, "GET /api/users/:userId");
    expect(read?.attributes.handlerSource).toBeUndefined();
    expect(read?.attributes.authCheck).toBe("requireUser");
  });

  test("a chained `.route().get().post()` is two routes, not one", async () => {
    const outcome = await enumerateFixture();
    expect(unitLabelled(outcome, "GET /api/admin/reports")?.attributes.mutates).toBe("false");
    const write = unitLabelled(outcome, "POST /api/admin/reports");
    expect(write?.attributes.middleware).toBe("requireUser");
    // The guard on the POST must not be read as the GET's.
    expect(unitLabelled(outcome, "GET /api/admin/reports")?.attributes.authCheck).toBe("none");
    expect(write?.attributes.authCheck).toBe("requireUser");
  });

  test("a path built from a variable is a unit with an honest `unresolved`", async () => {
    const outcome = await enumerateFixture();
    const dynamic = unitLabelled(outcome, "GET unresolved");
    expect(dynamic?.file).toBe("src/server/express-app.ts");
    expect(dynamic?.attributes.path).toBe("unresolved");
    expect(dynamic?.note).toContain("not a literal");
  });

  test("a Fastify route object is read for its method, url and schema", async () => {
    const outcome = await enumerateFixture();
    const put = unitLabelled(outcome, "PUT /things/:thingId");
    expect(put?.attributes).toMatchObject({
      framework: "fastify",
      method: "PUT",
      idParams: "thingId",
    });
    expect(put?.attributes.validation).toContain("schema:");
    expect(put?.attributes.authCheck).toBe("server.authenticate");
  });

  test("a plugin's prefix reaches the routes registered inside it", async () => {
    const outcome = await enumerateFixture();
    const charge = unitLabelled(outcome, "POST /api/billing/charge");
    expect(charge?.attributes.path).toBe("/api/billing/charge");
    expect(charge?.attributes.symbol).toBe("billingRoutes");
  });

  test("Hono's basePath and chained registrations compose", async () => {
    const outcome = await enumerateFixture();
    expect(unitLabelled(outcome, "GET /api/v2/posts")?.attributes.pagination).toBe("limit");
    expect(unitLabelled(outcome, "POST /api/v2/posts")?.attributes.readsBody).toBe("true");
    expect(unitLabelled(outcome, "DELETE /api/v2/posts/:postId")?.attributes.idParams).toBe(
      "postId",
    );
  });

  test("a Koa router's constructor prefix and its `del` alias are both honoured", async () => {
    const outcome = await enumerateFixture();
    const read = unitLabelled(outcome, "GET /api/koa/teams/:teamId");
    expect(read?.attributes).toMatchObject({
      framework: "koa",
      authCheck: "getSession()",
      idParams: "teamId",
    });
    // `router.del(...)` is Koa's spelling of DELETE.
    expect(unitLabelled(outcome, "DELETE /api/koa/teams/:teamId")?.attributes.method).toBe(
      "DELETE",
    );
    // Writing `ctx.body` is a response, not a body read.
    expect(read?.attributes.readsBody).toBe("false");
  });
});

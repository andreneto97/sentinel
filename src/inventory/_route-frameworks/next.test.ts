import { describe, expect, test } from "bun:test";
import { astGrepBinary, enumerateFixture, unitLabelled } from "./_test-support.ts";
import {
  appRoutePath,
  exportedNames,
  isAppRouteFile,
  isDirectiveLine,
  isPagesApiFile,
  methodsBranchedOn,
  pagesApiPath,
} from "./next.ts";

const AST_GREP = await astGrepBinary();

describe("route module detection", () => {
  test("an app-router handler module is recognised wherever `app/` lives", () => {
    expect(isAppRouteFile("app/api/users/route.ts")).toBe(true);
    expect(isAppRouteFile("src/app/route.js")).toBe(true);
    expect(isAppRouteFile("app/api/users/page.tsx")).toBe(false);
    expect(isAppRouteFile("lib/app/route.ts")).toBe(false);
  });

  test("a pages API module is recognised, and a page is not", () => {
    expect(isPagesApiFile("pages/api/users/[id].ts")).toBe(true);
    expect(isPagesApiFile("src/pages/api/legacy.js")).toBe(true);
    expect(isPagesApiFile("pages/about.tsx")).toBe(false);
  });
});

describe("appRoutePath", () => {
  test("the URL is the directory the handler sits in", () => {
    expect(appRoutePath("app/api/users/[id]/route.ts")).toBe("/api/users/[id]");
    expect(appRoutePath("src/app/api/health/route.ts")).toBe("/api/health");
    expect(appRoutePath("app/route.ts")).toBe("/");
  });

  test("route groups and named slots are not part of the URL", () => {
    expect(appRoutePath("app/(marketing)/api/leads/route.ts")).toBe("/api/leads");
    expect(appRoutePath("app/@modal/api/x/route.ts")).toBe("/api/x");
  });
});

describe("pagesApiPath", () => {
  test("the URL is the file path without its extension", () => {
    expect(pagesApiPath("pages/api/legacy.ts")).toBe("/api/legacy");
    expect(pagesApiPath("src/pages/api/users/[id].ts")).toBe("/api/users/[id]");
    expect(pagesApiPath("pages/api/index.ts")).toBe("/api");
  });
});

describe("exportedNames", () => {
  test("an aliased re-export exports the alias", () => {
    expect(exportedNames(["handler as GET", "other as HEAD"])).toEqual([
      { local: "handler", exported: "GET" },
      { local: "other", exported: "HEAD" },
    ]);
  });

  test("a plain re-export exports its own name, and separators are ignored", () => {
    expect(exportedNames(["GET", ",", " "])).toEqual([{ local: "GET", exported: "GET" }]);
  });
});

describe("isDirectiveLine", () => {
  test("only a line that is the directive and nothing else counts", () => {
    expect(isDirectiveLine('"use server";')).toBe(true);
    expect(isDirectiveLine("'use server'")).toBe(true);
    expect(isDirectiveLine('const mode = "use server";')).toBe(false);
    expect(isDirectiveLine('log("use server")')).toBe(false);
  });
});

describe("methodsBranchedOn", () => {
  test("the methods a pages handler tests for are the methods it serves", () => {
    expect(methodsBranchedOn('if (req.method === "POST") {}')).toEqual(["POST"]);
    expect(
      methodsBranchedOn('switch (req.method) { case "GET": break; case "PUT": break; }'),
    ).toEqual(["GET", "PUT"]);
    expect(methodsBranchedOn("return res.json([]);")).toEqual([]);
  });
});

describe.skipIf(AST_GREP === null)("Next entry points in the fixture", () => {
  test("one unit per exported method, with the path the folder names", async () => {
    const outcome = await enumerateFixture();
    const methods = outcome.units
      .filter((unit) => unit.file === "app/api/users/[id]/route.ts")
      .map((unit) => unit.attributes.method);
    expect(methods).toEqual(["GET", "PATCH", "DELETE"]);
  });

  test("a handler re-exported under a method name is still that method's unit", async () => {
    const outcome = await enumerateFixture();
    const options = unitLabelled(outcome, "OPTIONS /api/health");
    expect(options?.note).toContain("exported as OPTIONS from `optionsHandler`");
    expect(options?.line).toBe(12);
  });

  test("a route segment's runtime travels with every handler in the file", async () => {
    const outcome = await enumerateFixture();
    expect(unitLabelled(outcome, "GET /api/health")?.attributes.runtime).toBe("edge");
  });

  test("every export of a `use server` module is an entry point", async () => {
    const outcome = await enumerateFixture();
    const created = unitLabelled(outcome, "server action createPost");
    const deleted = unitLabelled(outcome, "server action deletePost");
    expect(created?.attributes).toMatchObject({
      method: "POST",
      framework: "next-server-action",
      actionKind: "module",
      authCheck: "requireUser()",
      validation: "CreatePost",
      mutates: "true",
    });
    expect(deleted?.attributes).toMatchObject({
      authCheck: "none",
      authenticated: "no",
      validation: "none",
      actionKind: "module",
    });
    // The path is not derivable from the definition site, and is not invented.
    expect(created?.attributes.path).toBe("unresolved");
    expect(created?.note).toContain("generated action id");
  });

  test("an inline `use server` function is an entry point too, with its own body", async () => {
    const outcome = await enumerateFixture();
    const inline = unitLabelled(outcome, "server action reload");
    expect(inline?.file).toBe("app/dashboard-actions.tsx");
    expect(inline?.attributes.actionKind).toBe("inline");
    expect(inline?.attributes.handlerSymbol).toBe("reload");
    expect(inline?.line).toBe(5);
    expect(inline?.endLine).toBe(8);
  });

  test("a pages API route is one unit that names the methods it branches on", async () => {
    const outcome = await enumerateFixture();
    const legacy = unitLabelled(outcome, "ANY /api/legacy");
    expect(legacy?.attributes).toMatchObject({
      method: "ANY",
      methodsHandled: "POST",
      framework: "next-pages-router",
      handlerSymbol: "handler",
      idParams: "orgId",
      readsBody: "true",
      authCheck: "none",
    });
  });
});

import { describe, expect, test } from "bun:test";
import { createFileSystem } from "../../ports/file-system.ts";
import { RepoSnapshot } from "../../profile/repo-snapshot.ts";
import { fixtureRepo } from "../__fixtures__/enumeration-harness.ts";
import type { StructuralMatch } from "../_ast-grep.ts";
import { scanSource } from "../slice.ts";
import {
  baseIdentifier,
  declarationIndex,
  importedGuards,
  importedModules,
  importsAny,
  indexMatches,
  joinPaths,
  normalisePath,
  parseExport,
  pathLiteral,
  pathParameters,
  readPathAliases,
  resolveImport,
  resolveRelativeImport,
  textOf,
  trimReceiver,
} from "./_shared.ts";
import { routeTarget } from "./_test-support.ts";

const snapshot = await RepoSnapshot.create(createFileSystem(), routeTarget());

/** A repository that imports its own guard through a tsconfig alias. */
const aliasSnapshot = await RepoSnapshot.create(createFileSystem(), fixtureRepo("alias-target"));

/** One file of the alias fixture, as lines. */
async function aliasLines(file: string): Promise<readonly string[]> {
  return (await aliasSnapshot.lines(file)) ?? [];
}

/** A match with just the fields the index cares about. */
function match(ruleId: string, file: string, line: number): StructuralMatch {
  return { ruleId, file, line, endLine: line, text: "", vars: {}, lists: {} };
}

describe("normalisePath and joinPaths", () => {
  test("a path always has one leading slash and no trailing one", () => {
    expect(normalisePath("api/users")).toBe("/api/users");
    expect(normalisePath("/api/users/")).toBe("/api/users");
    expect(normalisePath("//api//users")).toBe("/api/users");
    expect(normalisePath("")).toBe("/");
  });

  test("a mount prefix and a route path compose into one path", () => {
    expect(joinPaths("/api", "/users", "/:id")).toBe("/api/users/:id");
    expect(joinPaths(undefined, "/users")).toBe("/users");
    expect(joinPaths("/api", "/")).toBe("/api");
    expect(joinPaths()).toBe("/");
  });

  test("an unresolved segment poisons the whole path instead of half-resolving it", () => {
    expect(joinPaths("unresolved", "/users")).toBe("unresolved");
    expect(joinPaths("/api", "unresolved")).toBe("unresolved");
  });
});

describe("pathLiteral and pathParameters", () => {
  test("only a literal is a path", () => {
    expect(pathLiteral('"/users"')).toBe("/users");
    expect(pathLiteral("'/users'")).toBe("/users");
    expect(pathLiteral("`/users`")).toBe("/users");
    expect(pathLiteral("`/users/${id}`")).toBeUndefined();
    expect(pathLiteral("ROUTES.users")).toBeUndefined();
    expect(pathLiteral(undefined)).toBeUndefined();
  });

  test("every spelling of a dynamic segment is a parameter", () => {
    expect(pathParameters("/users/:userId/posts/:postId")).toEqual(["userId", "postId"]);
    expect(pathParameters("/users/[id]/posts/[...slug]")).toEqual(["id", "slug"]);
    expect(pathParameters("/users/{orgId}")).toEqual(["orgId"]);
    expect(pathParameters("unresolved")).toEqual([]);
  });
});

describe("parseExport", () => {
  test("a return type annotation does not hide the handler", () => {
    expect(parseExport("export async function GET(req: Request): Promise<Response> {}")).toEqual({
      name: "GET",
      value: undefined,
      isDefault: false,
    });
  });

  test("a type annotation on the constant does not hide it either", () => {
    expect(parseExport("export const POST: RouteHandler = async () => {}")).toEqual({
      name: "POST",
      value: "async () => {}",
      isDefault: false,
    });
  });

  test("default exports are named `default`, with or without a function name", () => {
    expect(parseExport("export default async function handler() {}")?.name).toBe("handler");
    expect(parseExport("export default handler;")).toEqual({
      name: "default",
      value: "handler",
      isDefault: true,
    });
  });

  test("a class export is recognised, and anything else is not an export of a value", () => {
    expect(parseExport("export class UsersController {}")?.name).toBe("UsersController");
    expect(parseExport("import { x } from './y'")).toBeUndefined();
  });
});

describe("trimReceiver", () => {
  test("the chained sibling call is dropped, and the line moves with it", () => {
    const text = 'app\n  .get("/a", one)\n  .post("/b", two)';
    const receiver = 'app\n  .get("/a", one)';
    expect(trimReceiver(text, receiver, 10)).toEqual({
      text: '\n  .post("/b", two)',
      startLine: 11,
    });
  });

  test("a receiver that does not prefix the text leaves it alone", () => {
    expect(trimReceiver("app.get(x)", "other", 3)).toEqual({ text: "app.get(x)", startLine: 3 });
  });
});

describe("baseIdentifier and textOf", () => {
  test("the base identifier of a chain is the object it started from", () => {
    expect(baseIdentifier('router.route("/x").get(h)')).toBe("router");
    expect(baseIdentifier("  api ")).toBe("api");
    expect(baseIdentifier("42")).toBeUndefined();
  });

  test("a line range is extracted inclusively and 1-based", () => {
    expect(textOf(["a", "b", "c", "d"], 2, 3)).toBe("b\nc");
    expect(textOf(["a"], 1, 99)).toBe("a");
  });
});

describe("indexMatches", () => {
  test("matches are addressable by rule and by file", () => {
    const index = indexMatches([
      match("node-call-get", "a.ts", 1),
      match("node-call-get", "b.ts", 2),
      match("node-call-post", "a.ts", 3),
    ]);
    expect(index.of("node-call-get")).toHaveLength(2);
    expect(index.in("node-call-get", "a.ts")).toHaveLength(1);
    expect(index.in("node-call-get", "c.ts")).toHaveLength(0);
    expect(index.files(["node-call-get", "node-call-post"])).toEqual(["a.ts", "b.ts"]);
  });
});

describe("imports", () => {
  test("every form of module specifier is collected", () => {
    const found = importedModules([
      'import express from "express";',
      "import { Hono } from 'hono';",
      'const koa = require("koa");',
      'const mod = await import("./local.ts");',
      'import "./side-effect.ts";',
    ]);
    expect([...found].sort()).toEqual(["./local.ts", "./side-effect.ts", "express", "hono", "koa"]);
  });

  test("a subpath import still proves the package", () => {
    const found = new Set(["hono/tiny", "next/server"]);
    expect(importsAny(found, ["hono"])).toBe(true);
    expect(importsAny(found, ["koa"])).toBe(false);
  });

  test("a relative import resolves to the file it names, extension or not", () => {
    expect(resolveRelativeImport("src/server/express-app.ts", "../lib/auth.ts", snapshot)).toBe(
      "src/lib/auth.ts",
    );
    expect(resolveRelativeImport("src/server/express-app.ts", "../lib/auth", snapshot)).toBe(
      "src/lib/auth.ts",
    );
    expect(resolveRelativeImport("src/server/express-app.ts", "express", snapshot)).toBeUndefined();
    expect(
      resolveRelativeImport("src/server/express-app.ts", "../lib/none", snapshot),
    ).toBeUndefined();
  });
});

describe("declarationIndex", () => {
  test("every named declaration is found with the block it owns", () => {
    const lines = [
      "const before = 1;",
      "export async function handler(req: Req): Promise<void> {",
      "  return;",
      "}",
      "const arrow = async () => {",
      "  return 1;",
      "};",
      "class Controller {}",
    ];
    const index = declarationIndex(lines, scanSource(lines));
    expect(index.get("handler")).toEqual({ startLine: 2, endLine: 4 });
    expect(index.get("arrow")).toEqual({ startLine: 5, endLine: 7 });
    expect(index.get("Controller")).toEqual({ startLine: 8, endLine: 8 });
  });

  test("an anonymous default export is indexed under `default`, which is the name an import resolves to", () => {
    const lines = [
      'import { db } from "./db.ts";',
      "",
      "export default async (req: Req): Promise<void> => {",
      "  await db.post.delete({ where: { id: req.params.id } });",
      "};",
    ];
    const index = declarationIndex(lines, scanSource(lines));
    expect(index.get("default")).toEqual({ startLine: 3, endLine: 5 });
  });

  test("`export default listOrders` resolves to the declaration it names, wherever that sits", () => {
    const lines = [
      "async function listOrders(): Promise<void> {",
      "  return;",
      "}",
      "",
      "export default listOrders;",
    ];
    const index = declarationIndex(lines, scanSource(lines));
    expect(index.get("default")).toEqual({ startLine: 1, endLine: 3 });
    expect(index.get("listOrders")).toEqual({ startLine: 1, endLine: 3 });
  });

  test("a default export that is a named function keeps both keys", () => {
    const lines = ["export default async function remove(): Promise<void> {", "  return;", "}"];
    const index = declarationIndex(lines, scanSource(lines));
    expect(index.get("default")).toEqual({ startLine: 1, endLine: 3 });
    expect(index.get("remove")).toEqual({ startLine: 1, endLine: 3 });
  });

  test("a file with no default export has no `default` entry to mislead a lookup", () => {
    const lines = ["export const schema = 1;"];
    expect(declarationIndex(lines, scanSource(lines)).has("default")).toBe(false);
  });
});

describe("readPathAliases", () => {
  test("reads compilerOptions.paths through comments and trailing commas", async () => {
    const aliases = await readPathAliases(aliasSnapshot);
    expect(aliases).toEqual([{ prefix: "@/", targets: ["src/"] }]);
  });

  test("a repository with no tsconfig paths has no aliases, which is not an error", async () => {
    expect(await readPathAliases(snapshot)).toEqual([]);
  });
});

describe("resolveImport", () => {
  test("an alias resolves to the file it names", async () => {
    const aliases = await readPathAliases(aliasSnapshot);
    expect(
      resolveImport(
        "src/app/business/opportunities/actions.ts",
        "@/lib/opportunities",
        aliasSnapshot,
        aliases,
      ),
    ).toBe("src/lib/opportunities.ts");
  });

  test("a bare package specifier resolves to nothing: a dependency is not ours", async () => {
    const aliases = await readPathAliases(aliasSnapshot);
    expect(resolveImport("src/lib/auth.ts", "next/server", aliasSnapshot, aliases)).toBeUndefined();
  });

  test("an alias that points at no file resolves to nothing rather than to a guess", async () => {
    const aliases = await readPathAliases(aliasSnapshot);
    expect(resolveImport("src/lib/auth.ts", "@/lib/nope", aliasSnapshot, aliases)).toBeUndefined();
  });
});

describe("importedGuards", () => {
  test("a guard imported from a file phase 0 proved holds a check is recognised by name", async () => {
    const lines = [
      'import { requireUser, getSession } from "../lib/auth.ts";',
      'import { db } from "../lib/db.ts";',
    ];
    const guards = await importedGuards(
      lines,
      "src/server/express-app.ts",
      new Set(["src/lib/auth.ts"]),
      snapshot,
    );
    expect([...guards].sort()).toEqual(["getSession", "requireUser"]);
  });

  test("a symbol from a module that does not authenticate is not a guard", async () => {
    const lines = ['import { db } from "../lib/db.ts";'];
    const guards = await importedGuards(
      lines,
      "src/server/express-app.ts",
      new Set(["src/lib/auth.ts"]),
      snapshot,
    );
    expect(guards.size).toBe(0);
  });

  test("a domain guard is recognised through an alias, one hop from the auth helper", async () => {
    // The `requireBusiness()` shape: a name no pattern matches, in a file phase 0
    // did not prove, reached through a tsconfig alias. Before this it was not a
    // guard, and the handler that calls it on its first line was reported as
    // `authCheck: none` — a claim the audit prompt then states as proven.
    const aliases = await readPathAliases(aliasSnapshot);
    const guards = await importedGuards(
      await aliasLines("src/app/business/opportunities/actions.ts"),
      "src/app/business/opportunities/actions.ts",
      new Set(["src/lib/auth.ts"]),
      aliasSnapshot,
      aliases,
    );
    // Only `requireBusiness` authenticates. `parseOpportunityForm` sits in the
    // same module and guards nothing, and accepting it would let `authCheck`
    // name it on a handler nobody checked.
    expect([...guards].sort()).toEqual(["requireBusiness"]);
  });

  test("a guard in a multi-line import clause is found", async () => {
    // Every formatter in this ecosystem breaks a clause of more than a few
    // symbols across lines, so a per-line scan missed the common case entirely.
    const lines = [
      "import {",
      "  parseOpportunityForm,",
      "  type Unused,",
      "  requireBusiness,",
      '} from "@/lib/opportunities";',
    ];
    const guards = await importedGuards(
      lines,
      "src/app/business/opportunities/actions.ts",
      new Set(["src/lib/auth.ts"]),
      aliasSnapshot,
      await readPathAliases(aliasSnapshot),
    );
    expect([...guards]).toEqual(["requireBusiness"]);
  });

  test("guard resolution is one hop, not transitive", async () => {
    // `actions.ts` itself contains no check — it only calls one. A module that
    // imports from `actions.ts` therefore gains no guard from it.
    const lines = ['import { createOpportunity } from "@/app/business/opportunities/actions";'];
    const guards = await importedGuards(
      lines,
      "src/app/page.tsx",
      new Set(["src/lib/auth.ts"]),
      aliasSnapshot,
      await readPathAliases(aliasSnapshot),
    );
    expect(guards.size).toBe(0);
  });
});

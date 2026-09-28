import { describe, expect, test } from "bun:test";
import { astGrepBinary, enumerateFixture, unitLabelled, unitsIn } from "./_test-support.ts";
import { decoratorPath, methodName, parseDecorator } from "./nest.ts";

const AST_GREP = await astGrepBinary();

describe("parseDecorator", () => {
  test("a decorator splits into its name and its arguments", () => {
    expect(parseDecorator('@Get(":userId")')).toEqual({ name: "Get", args: '":userId"' });
    expect(parseDecorator("@UseGuards(AuthGuard, RolesGuard)")).toEqual({
      name: "UseGuards",
      args: "AuthGuard, RolesGuard",
    });
  });

  test("a decorator with no arguments has none, not an empty match", () => {
    expect(parseDecorator("@Public")).toEqual({ name: "Public", args: "" });
    expect(parseDecorator("@Post()")).toEqual({ name: "Post", args: "" });
    expect(parseDecorator("not a decorator")).toBeUndefined();
  });
});

describe("methodName", () => {
  test("modifiers and generics do not hide the method's name", () => {
    expect(methodName("async findOne(id: string) {}")).toBe("findOne");
    expect(methodName("private static helper() {}")).toBe("helper");
    expect(methodName("list<T>(): Promise<T[]> {}")).toBe("list");
  });
});

describe("decoratorPath", () => {
  test("an empty argument list is the controller's own path", () => {
    expect(decoratorPath("")).toBe("");
    expect(decoratorPath('"users"')).toBe("users");
    expect(decoratorPath('":userId"')).toBe(":userId");
  });

  test("an options object still names a path", () => {
    expect(decoratorPath('{ path: "users", version: "2" }')).toBe("users");
  });

  test("a path built from a value is not a path", () => {
    expect(decoratorPath("ROUTES.users")).toBeUndefined();
  });
});

describe.skipIf(AST_GREP === null)("Nest controllers in the fixture", () => {
  test("the controller prefix composes with each method decorator", async () => {
    const outcome = await enumerateFixture();
    const labels = unitsIn(outcome, "src/nest/users.controller.ts").map((unit) => unit.label);
    expect(labels).toEqual([
      "GET /users/:userId",
      "GET /users",
      "POST /users",
      "DELETE /users/:userId",
      "GET /health",
    ]);
  });

  test("a second controller in the same file keeps its own prefix", async () => {
    const outcome = await enumerateFixture();
    expect(unitLabelled(outcome, "GET /health")?.attributes.controller).toBe("HealthController");
  });

  test("a guard decorator is the authentication check, with the line it sits on", async () => {
    const outcome = await enumerateFixture();
    const guarded = unitLabelled(outcome, "GET /users/:userId");
    expect(guarded?.attributes).toMatchObject({
      framework: "nestjs",
      authCheck: "@UseGuards(AuthGuard)",
      authenticated: "yes",
      middleware: "@UseGuards(AuthGuard)",
      handlerSymbol: "UsersController.findOne",
      idParams: "userId",
    });
    expect(guarded?.attributes.authSource).toBe("src/nest/users.controller.ts:10");
  });

  test("a method without a guard says so", async () => {
    const outcome = await enumerateFixture();
    expect(unitLabelled(outcome, "POST /users")?.attributes.authCheck).toBe("none");
    expect(unitLabelled(outcome, "POST /users")?.attributes.mutates).toBe("true");
  });

  test("the unit spans its decorators, so the slice shows what guards it", async () => {
    const outcome = await enumerateFixture();
    const guarded = unitLabelled(outcome, "GET /users/:userId");
    expect(guarded?.line).toBe(9);
    expect(guarded?.endLine).toBe(13);
  });

  test("a guard on the class guards every method in it", async () => {
    const outcome = await enumerateFixture();
    const health = unitLabelled(outcome, "GET /health");
    expect(health?.attributes.authCheck).toBe("@UseGuards(AuthGuard)");
    expect(health?.attributes.authenticated).toBe("yes");
    // The class decorator is not part of the method's own unit range.
    expect(health?.line).toBe(41);
  });

  test("a method with no routing decorator is not a route", async () => {
    const outcome = await enumerateFixture();
    expect(unitsIn(outcome, "src/nest/users.controller.ts")).toHaveLength(5);
  });
});

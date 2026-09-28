import { describe, expect, test } from "bun:test";
import type { StructuralMatch } from "../_ast-grep.ts";
import { astGrepBinary, enumerateFixture, unitLabelled } from "./_test-support.ts";
import { isProtectedBuilder, pairKey, procedureBuilder, procedureType } from "./trpc.ts";

const AST_GREP = await astGrepBinary();

/** A match carrying only the meta variables the type check reads. */
function match(lists: Record<string, readonly string[]>): StructuralMatch {
  return { ruleId: "trpc-procedure", file: "r.ts", line: 1, endLine: 1, text: "", vars: {}, lists };
}

describe("pairKey", () => {
  test("the property name is the procedure name, quoted or not", () => {
    expect(pairKey("byId: publicProcedure.query(fn)")).toBe("byId");
    expect(pairKey('"by-id": publicProcedure.query(fn)')).toBe("by-id");
    expect(pairKey("publicProcedure.query(fn)")).toBeUndefined();
  });
});

describe("procedureType", () => {
  test("the meta variable that bound says which kind of procedure it is", () => {
    expect(procedureType(match({ QUERY: [] }))).toBe("query");
    expect(procedureType(match({ MUTATION: [] }))).toBe("mutation");
    expect(procedureType(match({ SUBSCRIPTION: [] }))).toBe("subscription");
  });
});

describe("procedureBuilder", () => {
  test("the builder is found through the chain that configures it", () => {
    expect(procedureBuilder("publicProcedure.input(z.object({}))")).toBe("publicProcedure");
    expect(procedureBuilder("protectedProcedure")).toBe("protectedProcedure");
    expect(procedureBuilder("db.query")).toBe("db");
  });

  test("a builder whose name says authenticated is treated as authenticated", () => {
    expect(isProtectedBuilder("protectedProcedure")).toBe(true);
    expect(isProtectedBuilder("adminProcedure")).toBe(true);
    expect(isProtectedBuilder("publicProcedure")).toBe(false);
    expect(isProtectedBuilder(undefined)).toBe(false);
  });
});

describe.skipIf(AST_GREP === null)("tRPC procedures in the fixture", () => {
  test("a nested router composes the dotted procedure path", async () => {
    const outcome = await enumerateFixture();
    const byId = unitLabelled(outcome, "GET /api/trpc/post.byId");
    expect(byId?.attributes).toMatchObject({
      framework: "trpc",
      method: "GET",
      procedureType: "query",
      procedureBuilder: "publicProcedure",
      handlerSymbol: "post.byId",
      idParams: "postId",
    });
  });

  test("the adapter's endpoint is where the procedures are actually served", async () => {
    const outcome = await enumerateFixture();
    expect(unitLabelled(outcome, "GET /api/trpc/health")?.attributes.path).toBe("/api/trpc/health");
  });

  test("a mutation is a POST that reads a body, and its builder is its guard", async () => {
    const outcome = await enumerateFixture();
    const update = unitLabelled(outcome, "POST /api/trpc/post.update");
    expect(update?.attributes).toMatchObject({
      method: "POST",
      procedureType: "mutation",
      readsBody: "true",
      mutates: "true",
      authCheck: "protectedProcedure",
      authenticated: "yes",
      validation: "UpdatePost",
    });
  });

  test("the input schema is reported whole, never cut in half", async () => {
    const outcome = await enumerateFixture();
    expect(unitLabelled(outcome, "GET /api/trpc/post.byId")?.attributes.validation).toBe(
      "z.object({ postId: z.string() })",
    );
  });

  test("only the innermost pair is a procedure; the router that holds it is not", async () => {
    const outcome = await enumerateFixture();
    const trpcUnits = outcome.units.filter((unit) => unit.attributes.framework === "trpc");
    expect(trpcUnits.map((unit) => unit.symbol)).toEqual([
      "procedure post.byId",
      "procedure post.update",
      "procedure health",
    ]);
  });
});

import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { SCHEMA_VERSION } from "../contracts/findings.ts";
import type { StackProfile } from "../contracts/profile.ts";
import { createFileSystem } from "../ports/file-system.ts";
import { createProcessExecutor } from "../ports/process-executor.ts";
import { RepoSnapshot } from "../profile/repo-snapshot.ts";
import type { StructuralSearch, StructuralSearchResult } from "./_ast-grep.ts";
import {
  astGrepBinary,
  enumerateFixture,
  labelsOf,
  routeTarget,
  unitLabelled,
} from "./_route-frameworks/_test-support.ts";
import type { EnumerationContext } from "./_unit-support.ts";
import { ROUTE_RULES, enumerateRoutes, sortDrafts } from "./routes.ts";
import { createSourceCache, sliceCode } from "./slice.ts";

const AST_GREP = await astGrepBinary();

/** A context whose structural search is scripted, for the paths that never spawn anything. */
async function contextWith(
  search: StructuralSearch,
  target = routeTarget(),
): Promise<EnumerationContext> {
  const fs = createFileSystem();
  return {
    fs,
    exec: createProcessExecutor(),
    tools: { resolve: async () => null },
    targetDir: target,
    runDir: join(target, "out"),
    runId: "test",
    snapshot: await RepoSnapshot.create(fs, target),
    search,
  };
}

/** A profile that proves one file holds an authentication check, and nothing else. */
function profileWithAuthHelper(file: string): StackProfile {
  return {
    schemaVersion: SCHEMA_VERSION,
    target: routeTarget(),
    facts: [
      {
        kind: "auth-helper",
        value: file,
        confidence: "high",
        evidence: [{ file, line: 1 }],
      },
    ],
    absences: [],
    warnings: [],
    scan: { filesSeen: 0, filesRead: 0, truncated: false },
  };
}

/** A profile that claims a backend framework the fixture does not use. */
function profileWithFramework(framework: string): StackProfile {
  return {
    schemaVersion: SCHEMA_VERSION,
    target: routeTarget(),
    facts: [
      {
        kind: "backend-framework",
        value: framework,
        confidence: "high",
        evidence: [{ file: "package.json", line: 1 }],
      },
    ],
    absences: [],
    warnings: [],
    scan: { filesSeen: 0, filesRead: 0, truncated: false },
  };
}

/** A search that always answers the same thing. */
function fixedSearch(result: StructuralSearchResult): StructuralSearch {
  return { search: async () => result };
}

describe("ROUTE_RULES", () => {
  test("every rule id is unique, so a collector cannot read another's matches", () => {
    const ids = ROUTE_RULES.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("no rule id contains the separator the driver uses for languages", () => {
    for (const rule of ROUTE_RULES) expect(rule.id).toMatch(/^[a-z0-9-]+$/);
  });
});

describe("enumerateRoutes without a structural search", () => {
  test("a repository with no JS/TS is skipped, not reported as having no routes", async () => {
    const empty = join(import.meta.dir, "__fixtures__", "slice-target");
    const ctx = await contextWith(fixedSearch({ ok: true, matches: [] }), empty);
    const outcome = await enumerateRoutes({
      ...ctx,
      snapshot: { ...ctx.snapshot, sourceFiles: () => [] } as unknown as RepoSnapshot,
    });
    expect(outcome.status).toBe("skipped");
    expect(outcome.units).toHaveLength(0);
  });

  test("a missing ast-grep degrades with the tool's own reason, never silently", async () => {
    const ctx = await contextWith(
      fixedSearch({ ok: false, matches: [], reason: "ast-grep is not installed" }),
    );
    const outcome = await enumerateRoutes(ctx);
    expect(outcome.status).toBe("degraded");
    expect(outcome.units).toHaveLength(0);
    expect(outcome.reason).toBe("ast-grep is not installed");
  });

  test("a route a file name proves survives a search that matched nothing", async () => {
    const ctx = await contextWith(fixedSearch({ ok: true, matches: [] }));
    const outcome = await enumerateRoutes(ctx);
    expect(outcome.status).toBe("ok");
    // `pages/api/legacy.ts` is an endpoint because of where it sits, whatever
    // the parser managed to make of its default export.
    expect(outcome.units.map((unit) => unit.label)).toEqual(["ANY /api/legacy"]);
    expect(outcome.reason).toContain("no default export");
  });

  test("a search that throws is reported as a degraded enumeration, not a crash", async () => {
    const ctx = await contextWith({
      search: async () => {
        throw new Error("boom");
      },
    });
    const outcome = await enumerateRoutes(ctx);
    expect(outcome.status).toBe("degraded");
    expect(outcome.reason).toContain("boom");
  });
});

describe("sortDrafts", () => {
  test("orders by file, then line, then symbol, so two runs agree", () => {
    const draft = (file: string, line: number, symbol: string) => ({
      kind: "route" as const,
      label: symbol,
      file,
      line,
      symbol,
      attributes: {},
    });
    const sorted = sortDrafts([
      draft("b.ts", 1, "GET /b"),
      draft("a.ts", 9, "POST /a"),
      draft("a.ts", 9, "GET /a"),
      draft("a.ts", 2, "GET /root"),
    ]);
    expect(sorted.map((unit) => `${unit.file}:${unit.line} ${unit.symbol}`)).toEqual([
      "a.ts:2 GET /root",
      "a.ts:9 GET /a",
      "a.ts:9 POST /a",
      "b.ts:1 GET /b",
    ]);
  });
});

describe.skipIf(AST_GREP === null)("enumerateRoutes over the fixture repository", () => {
  test("every entry point in the target is listed, and nothing else is", async () => {
    const outcome = await enumerateFixture();
    expect(outcome.status).toBe("ok");
    expect(labelsOf(outcome)).toEqual([
      "ANY /api/legacy",
      "DELETE /api/koa/teams/:teamId",
      "DELETE /api/orders/:orderId",
      "DELETE /api/users/[id]",
      "DELETE /api/v2/posts/:postId",
      "DELETE /users/:userId",
      "GET /api/admin/reports",
      "GET /api/health",
      "GET /api/koa/teams/:teamId",
      "GET /api/orders",
      "GET /api/trpc/[trpc]",
      "GET /api/trpc/health",
      "GET /api/trpc/post.byId",
      "GET /api/users/:userId",
      "GET /api/users/[id]",
      "GET /api/v2/posts",
      "GET /health",
      "GET /things",
      "GET /users",
      "GET /users/:userId",
      "GET unresolved",
      "OPTIONS /api/health",
      "PATCH /api/users/:userId",
      "PATCH /api/users/[id]",
      "POST /api/admin/reports",
      "POST /api/billing/charge",
      "POST /api/trpc/[trpc]",
      "POST /api/trpc/post.update",
      "POST /api/users",
      "POST /api/v2/posts",
      "POST /users",
      "PUT /things/:thingId",
      "server action createPost",
      "server action deletePost",
      "server action reload",
    ]);
  });

  test("a private controller method is not a route", async () => {
    const outcome = await enumerateFixture();
    expect(outcome.units.some((unit) => unit.symbol.endsWith(".helper"))).toBe(false);
  });

  test("every unit carries a line range a slice can be taken from", async () => {
    const outcome = await enumerateFixture();
    for (const unit of outcome.units) {
      expect(unit.line).toBeGreaterThan(0);
      expect(unit.endLine ?? unit.line).toBeGreaterThanOrEqual(unit.line);
      expect(unit.kind).toBe("route");
      expect(unit.attributes.trigger).toBe("http");
    }
  });

  test("the outcome says how many routes it could not resolve", async () => {
    const outcome = await enumerateFixture();
    const unresolved = outcome.units.filter((unit) => unit.attributes.path === "unresolved");
    expect(unresolved).toHaveLength(4);
    expect(outcome.reason).toContain("4 of 35 route(s) could not be resolved");
    for (const unit of unresolved) expect(unit.note).toBeDefined();
  });

  test("two enumerations of unchanged code produce the same units", async () => {
    const first = await enumerateFixture();
    const target = routeTarget();
    const fs = createFileSystem();
    const exec = createProcessExecutor();
    const second = await enumerateRoutes({
      fs,
      exec,
      tools: { resolve: async () => AST_GREP },
      targetDir: target,
      runDir: join(target, "out"),
      runId: "second",
      snapshot: await RepoSnapshot.create(fs, target),
      search: (await import("./_ast-grep.ts")).createAstGrepSearch({
        exec,
        tools: { resolve: async () => AST_GREP },
        targetDir: target,
      }),
    });
    expect(JSON.stringify(second.units)).toBe(JSON.stringify(first.units));
  });

  test("a handler with no guard says so, which is what the audit is looking for", async () => {
    const outcome = await enumerateFixture();
    const remove = unitLabelled(outcome, "DELETE /api/users/[id]");
    expect(remove?.attributes).toMatchObject({
      method: "DELETE",
      path: "/api/users/[id]",
      framework: "next-app-router",
      handlerSymbol: "DELETE",
      idParams: "id",
      authCheck: "none",
      authenticated: "no",
      validation: "none",
      mutates: "true",
      readsBody: "false",
      pagination: "none",
    });
  });

  test("every unit slices into real, budgeted source for the audit prompt", async () => {
    const outcome = await enumerateFixture();
    const ctx = {
      fs: createFileSystem(),
      targetDir: routeTarget(),
      budget: { maxLines: 40, maxBytes: 3_000 },
      cache: createSourceCache(),
    };
    for (const unit of outcome.units) {
      const sliced = await sliceCode(
        {
          file: unit.file,
          line: unit.line,
          ...(unit.endLine === undefined ? {} : { endLine: unit.endLine }),
        },
        ctx,
      );
      expect(sliced.ok).toBe(true);
      if (!sliced.ok) continue;
      expect(sliced.slice.text.split("\n").length).toBeLessThanOrEqual(40);
      expect(sliced.slice.bytes).toBeLessThanOrEqual(3_000);
      expect(sliced.slice.text.startsWith(`// ${unit.file}:`)).toBe(true);
      // The model is only ever shown lines it can cite back.
      expect(sliced.slice.text).toMatch(/\n\s*\d+ \| /);
    }
  });

  test("phase 0's auth helper turns a nameless guard into a detected check", async () => {
    // `gate()` is named after nothing and its body checks nothing it can be read
    // off: only phase 0's `auth-helper` fact can prove what it is. That fact
    // vouches for the whole file, which is why every symbol imported from it
    // counts; a module phase 0 did *not* prove has each imported symbol judged on
    // its own body instead (see `importedGuards`).
    const blind = await enumerateFixture();
    expect(unitLabelled(blind, "PATCH /api/users/:userId")?.attributes.authCheck).toBe("none");

    const informed = await enumerateFixture(profileWithAuthHelper("src/lib/auth.ts"));
    const guarded = unitLabelled(informed, "PATCH /api/users/:userId");
    expect(guarded?.attributes.authCheck).toBe("gate");
    expect(guarded?.attributes.authenticated).toBe("yes");
  });

  test("a framework phase 0 proved but nobody enumerated is reported, not hidden", async () => {
    const outcome = await enumerateFixture(profileWithFramework("remix"));
    expect(outcome.reason).toContain("phase 0 detected remix");
  });

  test("a guarded handler names its guard and cites the line it runs on", async () => {
    const outcome = await enumerateFixture();
    const read = unitLabelled(outcome, "GET /api/users/[id]");
    expect(read?.attributes.authCheck).toBe("requireUser()");
    expect(read?.attributes.authSource).toBe("app/api/users/[id]/route.ts:13");
    expect(read?.attributes.pagination).toBe("limit");
  });
});

/**
 * tRPC procedures: every `publicProcedure.query(…)` and
 * `protectedProcedure.mutation(…)` is an HTTP endpoint, even though nothing in
 * the file looks like a route.
 *
 * Two things have to be composed. The procedure's *name* is the key of the
 * object property it is assigned to, and its namespace is the key of every
 * router that nests it — `user.byId`, not `byId`. Its *URL* comes from
 * somewhere else entirely: the adapter that mounts the router, which is
 * usually a Next route handler at `app/api/trpc/[trpc]/route.ts`. When that
 * adapter cannot be found the procedure path is still reported, with a note
 * saying the mount point was not resolved — the procedure exists either way.
 */

import type { StructuralMatch, StructuralRule } from "../_ast-grep.ts";
import { literalOf, optionOf } from "../_unit-support.ts";
import { readHandler } from "./_handler-facts.ts";
import {
  FRAMEWORKS,
  type RouteContext,
  type RouteDraft,
  baseIdentifier,
  joinPaths,
  normalisePath,
} from "./_shared.ts";
import { appRoutePath, isAppRouteFile } from "./next.ts";

/** The queries this collector contributes to the search. */
export const TRPC_RULES: readonly StructuralRule[] = [
  {
    id: "trpc-procedure",
    // A pair whose value contains a procedure definition. The relational form
    // keeps every other object property in the repository out of the results.
    rule: {
      kind: "pair",
      has: {
        any: [
          { pattern: "$PROC.query($$$QUERY)" },
          { pattern: "$PROC.mutation($$$MUTATION)" },
          { pattern: "$PROC.subscription($$$SUBSCRIPTION)" },
        ],
        stopBy: "end",
      },
    },
  },
  {
    id: "trpc-adapter",
    rule: {
      any: [
        { pattern: "fetchRequestHandler($ARG)" },
        { pattern: "createNextApiHandler($ARG)" },
        { pattern: "createHTTPHandler($ARG)" },
        { pattern: "createExpressMiddleware($ARG)" },
        { pattern: "createOpenApiFetchHandler($ARG)" },
      ],
    },
  },
];

/** Procedure builders whose name says the caller must be authenticated. */
const PROTECTED_PREFIXES: readonly string[] = [
  "protected",
  "private",
  "auth",
  "authed",
  "authenticated",
  "admin",
  "member",
  "signedIn",
  "user",
];

/** The kind of procedure a match describes, from the meta variable that bound. */
export function procedureType(match: StructuralMatch): "query" | "mutation" | "subscription" {
  if (match.lists.MUTATION !== undefined) return "mutation";
  if (match.lists.SUBSCRIPTION !== undefined) return "subscription";
  return "query";
}

/** The key an object pair declares: `byId` in `byId: publicProcedure…`. */
export function pairKey(text: string): string | undefined {
  const match = /^\s*(?:(['"])([^'"]+)\1|([A-Za-z_$][\w$]*))\s*:/.exec(text);
  return match?.[2] ?? match?.[3];
}

/** True when `outer` strictly contains `inner`. */
function contains(outer: StructuralMatch, inner: StructuralMatch): boolean {
  if (outer === inner) return false;
  if (outer.line > inner.line || outer.endLine < inner.endLine) return false;
  return outer.text.length > inner.text.length;
}

/** The builder a procedure chain starts from: `protectedProcedure.input(…)`. */
export function procedureBuilder(expression: string | undefined): string | undefined {
  if (expression === undefined) return undefined;
  const match = /\b([A-Za-z_$][\w$]*[Pp]rocedure)\b/.exec(expression);
  return match?.[1] ?? baseIdentifier(expression);
}

/** True when the builder's own name says the procedure is authenticated. */
export function isProtectedBuilder(builder: string | undefined): boolean {
  if (builder === undefined) return false;
  const lower = builder.toLowerCase();
  return PROTECTED_PREFIXES.some((prefix) => lower.startsWith(prefix.toLowerCase()));
}

/**
 * Where the router is mounted over HTTP.
 *
 * The adapter's `endpoint` option wins; failing that, an adapter living in an
 * app-router route handler serves at that handler's own path, minus the
 * catch-all segment tRPC uses to receive the procedure name.
 */
export function mountPoint(ctx: RouteContext): string | undefined {
  for (const match of ctx.matches.of("trpc-adapter")) {
    const endpoint = optionOf(match.vars.ARG ?? "", "endpoint");
    const literal = endpoint === undefined ? undefined : literalOf(endpoint);
    if (literal !== undefined) return normalisePath(literal);
    if (isAppRouteFile(match.file)) {
      const path = appRoutePath(match.file);
      const segments = path.split("/").filter((segment) => segment !== "");
      const last = segments[segments.length - 1];
      if (last?.startsWith("[") === true) segments.pop();
      return normalisePath(segments.join("/"));
    }
  }
  return undefined;
}

/** Enumerates every tRPC procedure as the endpoint it is. */
export async function collectTrpcRoutes(ctx: RouteContext): Promise<RouteDraft[]> {
  const drafts: RouteDraft[] = [];
  const mount = mountPoint(ctx);
  const files = ctx.matches.files(["trpc-procedure"]);

  for (const file of files) {
    const pairs = ctx.matches.in("trpc-procedure", file);
    const innermost = pairs.filter((pair) => !pairs.some((other) => contains(pair, other)));
    for (const pair of innermost) {
      const builder = procedureBuilder(pair.vars.PROC);
      // `.query(` is not tRPC's alone; the builder's name is what proves it.
      if (builder === undefined || !/[Pp]rocedure$/.test(builder)) continue;
      const key = pairKey(pair.text);
      if (key === undefined) continue;

      const namespaces = pairs
        .filter((other) => contains(other, pair))
        .sort((left, right) => right.text.length - left.text.length)
        .map((other) => pairKey(other.text))
        .filter((name): name is string => name !== undefined);
      const procedure = [...namespaces, key].join(".");
      const type = procedureType(pair);
      const method = type === "mutation" ? "POST" : "GET";
      const path = mount === undefined ? procedure : joinPaths(mount, procedure);

      const facts = readHandler({
        file,
        regions: [{ text: pair.text, startLine: pair.line }],
        method,
        guards: await ctx.guards(file),
        readsBody: type === "mutation",
      });
      const protectedBuilder = isProtectedBuilder(builder);
      drafts.push({
        kind: "route",
        label: `${method} ${path}`,
        file,
        line: pair.line,
        endLine: pair.endLine,
        symbol: `procedure ${procedure}`,
        ...(mount === undefined
          ? { note: "no tRPC adapter was found, so the path is the procedure name only" }
          : {}),
        attributes: {
          trigger: "http",
          method,
          path,
          framework: FRAMEWORKS.trpc,
          handlerSymbol: procedure,
          symbol: procedure,
          procedureType: type,
          procedureBuilder: builder,
          ...facts,
          ...(protectedBuilder
            ? { authCheck: builder, authSource: `${file}:${pair.line}`, authenticated: "yes" }
            : {}),
        },
      });
    }
  }
  return drafts;
}

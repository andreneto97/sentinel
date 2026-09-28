/**
 * Next.js entry points: app-router route handlers, pages-router API routes and
 * **server actions**.
 *
 * Server actions are here because they are the entry points most audits miss.
 * A `"use server"` function is a POST endpoint that Next generates an id for
 * and exposes to the internet; nothing authenticates it by default, and it is
 * reachable whether or not the component that imports it ever renders. An
 * inventory that lists `app/api/**` and stops has under-counted the attack
 * surface, so both flavours are enumerated: a file whose prologue is
 * `"use server"` (every export is an action) and a function whose own first
 * statement is the directive.
 */

import type { StructuralRule } from "../_ast-grep.ts";
import { enclosingSymbol } from "../_unit-support.ts";
import { resolveBlock } from "../slice.ts";
import { readHandler } from "./_handler-facts.ts";
import {
  FRAMEWORKS,
  type RouteContext,
  type RouteDraft,
  UNRESOLVED_PATH,
  joinPaths,
  normalisePath,
  parseExport,
  pathLiteral,
  textOf,
} from "./_shared.ts";

/** Rule ids this collector reads; also the queries it contributes to the search. */
export const NEXT_RULES: readonly StructuralRule[] = [
  {
    // Every exported declaration. Matched by *kind* rather than by pattern:
    // `export async function GET(req: Request): Promise<Response>` carries a
    // return type, and a pattern written without one drops the handler.
    id: "next-export",
    rule: {
      all: [
        { kind: "export_statement" },
        {
          has: {
            any: [
              { kind: "function_declaration" },
              { kind: "generator_function_declaration" },
              { kind: "lexical_declaration" },
              { kind: "variable_declaration" },
              { kind: "class_declaration" },
            ],
            stopBy: "neighbor",
          },
        },
        {
          any: [
            { regex: "^export\\s+(default\\s+)?(async\\s+)?function\\b" },
            { regex: "^export\\s+(default\\s+)?(abstract\\s+)?class\\b" },
            // An exported function value: a handler, or an action in a "use server" module.
            {
              regex:
                "^export\\s+(const|let|var)\\s+[A-Za-z_$][\\w$]*\\s*(:[^=]+)?=\\s*(async\\s*)?(\\(|function\\b)",
            },
            // A route-segment export, which is configuration rather than a handler.
            {
              regex:
                "^export\\s+(const|let|var)\\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|runtime|dynamic|revalidate|maxDuration|preferredRegion)\\b",
            },
          ],
        },
      ],
    },
  },
  {
    id: "next-export-default",
    rule: { all: [{ kind: "export_statement" }, { regex: "^export\\s+default\\b" }] },
  },
  { id: "next-export-specifier", rule: { pattern: "export { $$$SPECS }" } },
  {
    id: "next-use-server",
    rule: { any: [{ pattern: "'use server'" }, { pattern: '"use server"' }] },
  },
];

/**
 * Why a server action's path is `unresolved`: Next posts it to whatever page
 * imported it, addressed by a generated action id, so the definition site does
 * not name a URL. The endpoint is real; the path is not derivable from here.
 */
export const ACTION_NOTE =
  "a server action is POSTed to the page that imports it, addressed by a generated action id";

/** The HTTP methods a Next app-router `route.ts` may export, in export order. */
export const ROUTE_EXPORTS: readonly string[] = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
];

/** True when the file is an app-router route handler module. */
export function isAppRouteFile(file: string): boolean {
  return /^(?:src\/)?app\/(?:.*\/)?route\.(?:m|c)?[jt]sx?$/.test(file);
}

/** True when the file is a pages-router API route module. */
export function isPagesApiFile(file: string): boolean {
  return /^(?:src\/)?pages\/api\/.+\.(?:m|c)?[jt]sx?$/.test(file);
}

/**
 * The URL path an app-router handler serves.
 *
 * Route groups (`(marketing)`) and named slots (`@modal`) exist for the file
 * tree, not for the URL, so they are dropped; dynamic segments keep Next's own
 * `[id]` spelling, because that is what a reader will grep for.
 */
export function appRoutePath(file: string): string {
  const withoutSource = file.replace(/^src\//, "");
  const segments = withoutSource.split("/").slice(1, -1);
  const kept = segments.filter(
    (segment) => !(segment.startsWith("(") && segment.endsWith(")")) && !segment.startsWith("@"),
  );
  return normalisePath(kept.join("/"));
}

/** The URL path a pages-router API route serves. */
export function pagesApiPath(file: string): string {
  const withoutSource = file.replace(/^src\//, "");
  const withoutExtension = withoutSource.replace(/\.(?:m|c)?[jt]sx?$/, "");
  const segments = withoutExtension.split("/").slice(1);
  const last = segments[segments.length - 1];
  if (last === "index") segments.pop();
  return normalisePath(segments.join("/"));
}

/** True when a line is nothing but a `"use server"` directive. */
export function isDirectiveLine(line: string | undefined): boolean {
  return line !== undefined && /^["']use server["']\s*;?\s*$/.test(line);
}

/** The exported names a specifier list binds: `handler as GET` exports `GET`. */
export function exportedNames(
  specifiers: readonly string[],
): Array<{ local: string; exported: string }> {
  const names: Array<{ local: string; exported: string }> = [];
  for (const specifier of specifiers) {
    const trimmed = specifier.trim();
    if (trimmed === "" || trimmed === ",") continue;
    const aliased = /^([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/.exec(trimmed);
    if (aliased?.[1] !== undefined && aliased[2] !== undefined) {
      names.push({ local: aliased[1], exported: aliased[2] });
      continue;
    }
    if (/^[A-Za-z_$][\w$]*$/.test(trimmed)) names.push({ local: trimmed, exported: trimmed });
  }
  return names;
}

/** Where an exported symbol is defined in its own file, when it is defined there. */
interface Definition {
  readonly line: number;
  readonly endLine: number;
}

/** Where every name of one file is defined: its exports first, then its locals. */
async function definitionsOf(ctx: RouteContext, file: string): Promise<Map<string, Definition>> {
  const definitions = new Map<string, Definition>();
  for (const match of ctx.matches.in("next-export", file)) {
    const parsed = parseExport(match.text);
    if (parsed === undefined || definitions.has(parsed.name)) continue;
    definitions.set(parsed.name, { line: match.line, endLine: match.endLine });
  }
  // A local declaration exported further down the file: `export { handler as GET }`.
  for (const [name, range] of await ctx.declarations(file)) {
    if (definitions.has(name)) continue;
    definitions.set(name, { line: range.startLine, endLine: range.endLine });
  }
  return definitions;
}

/** Builds one route draft, reading every attribute out of the handler's own source. */
async function draftFor(
  ctx: RouteContext,
  input: {
    file: string;
    line: number;
    endLine: number;
    method: string;
    path: string;
    framework: string;
    symbol: string;
    handlerSymbol: string;
    label: string;
    note?: string | undefined;
    extra?: Readonly<Record<string, string | undefined>> | undefined;
  },
): Promise<RouteDraft> {
  const lines = await ctx.lines(input.file);
  const facts = readHandler({
    file: input.file,
    regions: [{ text: textOf(lines, input.line, input.endLine), startLine: input.line }],
    method: input.method,
    path: input.path,
    guards: await ctx.guards(input.file),
  });
  return {
    kind: "route",
    label: input.label,
    file: input.file,
    line: input.line,
    endLine: input.endLine,
    symbol: input.symbol,
    ...(input.note === undefined ? {} : { note: input.note }),
    attributes: {
      trigger: "http",
      method: input.method,
      path: input.path,
      framework: input.framework,
      handlerSymbol: input.handlerSymbol,
      symbol: input.handlerSymbol,
      ...facts,
      ...input.extra,
    },
  };
}

/** App-router handlers: one unit per exported HTTP method in every `route.ts`. */
async function collectAppRouter(ctx: RouteContext): Promise<RouteDraft[]> {
  const drafts: RouteDraft[] = [];
  const files = ctx.snapshot.files.filter(isAppRouteFile);
  for (const file of files) {
    const path = appRoutePath(file);
    const definitions = await definitionsOf(ctx, file);
    const exports = ctx.matches
      .in("next-export", file)
      .map((match) => ({ match, parsed: parseExport(match.text) }));
    const runtime = exports.find((entry) => entry.parsed?.name === "runtime")?.parsed?.value;
    const extra = runtime === undefined ? undefined : { runtime: pathLiteral(runtime) ?? runtime };

    const exported = new Map<string, { line: number; endLine: number; note?: string }>();
    for (const { match, parsed } of exports) {
      if (parsed === undefined || !ROUTE_EXPORTS.includes(parsed.name)) continue;
      exported.set(parsed.name, { line: match.line, endLine: match.endLine });
    }
    for (const match of ctx.matches.in("next-export-specifier", file)) {
      for (const { local, exported: name } of exportedNames(match.lists.SPECS ?? [])) {
        if (!ROUTE_EXPORTS.includes(name) || exported.has(name)) continue;
        const definition = definitions.get(local);
        if (definition === undefined) {
          exported.set(name, {
            line: match.line,
            endLine: match.endLine,
            note: `handler \`${local}\` is defined outside this file`,
          });
          continue;
        }
        exported.set(name, {
          line: definition.line,
          endLine: definition.endLine,
          note: `exported as ${name} from \`${local}\``,
        });
      }
    }

    if (exported.size === 0) {
      ctx.warn(`${file} is an app-router route module but exports no HTTP method`);
    }
    for (const method of ROUTE_EXPORTS) {
      const found = exported.get(method);
      if (found === undefined) continue;
      drafts.push(
        await draftFor(ctx, {
          file,
          line: found.line,
          endLine: found.endLine,
          method,
          path,
          framework: FRAMEWORKS.nextApp,
          symbol: `${method} ${path}`,
          handlerSymbol: method,
          label: `${method} ${path}`,
          ...(found.note === undefined ? {} : { note: found.note }),
          ...(extra === undefined ? {} : { extra }),
        }),
      );
    }
  }
  return drafts;
}

/** The methods a pages-router handler branches on, which is the only honest method list. */
export function methodsBranchedOn(source: string): string[] {
  const found = new Set<string>();
  const pattern = /\b(?:req|request|event)\s*\.\s*method\s*(?:===?|!==?)\s*['"]([A-Za-z]+)['"]/g;
  let match = pattern.exec(source);
  while (match !== null) {
    const method = match[1];
    if (method !== undefined) found.add(method.toUpperCase());
    match = pattern.exec(source);
  }
  const switched = /\bswitch\s*\(\s*(?:req|request)\s*\.\s*method\s*\)/.test(source);
  if (switched) {
    const cases = /case\s+['"]([A-Za-z]+)['"]/g;
    let hit = cases.exec(source);
    while (hit !== null) {
      const method = hit[1];
      if (method !== undefined) found.add(method.toUpperCase());
      hit = cases.exec(source);
    }
  }
  return [...found].sort();
}

/** Pages-router API routes: one unit per file, because one file is one endpoint. */
async function collectPagesRouter(ctx: RouteContext): Promise<RouteDraft[]> {
  const drafts: RouteDraft[] = [];
  for (const file of ctx.snapshot.files.filter(isPagesApiFile)) {
    const defaultExport = ctx.matches.in("next-export-default", file)[0];
    const lines = await ctx.lines(file);
    if (lines.length === 0) continue;
    const path = pagesApiPath(file);
    const line = defaultExport?.line ?? 1;
    const endLine = defaultExport?.endLine ?? lines.length;
    const methods = methodsBranchedOn(textOf(lines, 1, lines.length));
    const declared =
      defaultExport === undefined ? undefined : parseExport(defaultExport.text)?.value;
    const handler =
      (declared !== undefined && /^[A-Za-z_$][\w$]*$/.test(declared) ? declared : undefined) ??
      enclosingSymbol(lines, line) ??
      "default";
    if (defaultExport === undefined) {
      ctx.warn(`${file} is a pages API route with no default export; the whole file is the unit`);
    }
    drafts.push(
      await draftFor(ctx, {
        file,
        line,
        endLine,
        // A pages handler answers every method it does not reject itself.
        method: "ANY",
        path,
        framework: FRAMEWORKS.nextPages,
        symbol: `ANY ${path}`,
        handlerSymbol: handler,
        label: `ANY ${path}`,
        ...(methods.length === 0 ? {} : { extra: { methodsHandled: methods.join(",") } }),
      }),
    );
  }
  return drafts;
}

/** Every exported function of a file, for a module whose prologue is `"use server"`. */
async function exportedFunctions(
  ctx: RouteContext,
  file: string,
): Promise<Array<{ name: string; line: number; endLine: number }>> {
  const found = new Map<string, { name: string; line: number; endLine: number }>();
  for (const ruleId of ["next-export", "next-export-default"]) {
    for (const match of ctx.matches.in(ruleId, file)) {
      const parsed = parseExport(match.text);
      if (parsed === undefined || found.has(parsed.name)) continue;
      found.set(parsed.name, { name: parsed.name, line: match.line, endLine: match.endLine });
    }
  }
  return [...found.values()].sort((left, right) => left.line - right.line);
}

/**
 * Server actions, of both kinds: a module whose prologue is `"use server"`
 * (every export is an action) and a function whose own first statement is the
 * directive.
 */
async function collectServerActions(ctx: RouteContext): Promise<RouteDraft[]> {
  const drafts: RouteDraft[] = [];
  const byFile = new Map<string, number[]>();
  for (const match of ctx.matches.of("next-use-server")) {
    const lines = byFile.get(match.file);
    if (lines === undefined) byFile.set(match.file, [match.line]);
    else lines.push(match.line);
  }

  for (const [file, directiveLines] of [...byFile.entries()].sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    const lines = await ctx.lines(file);
    const structure = await ctx.structure(file);
    const moduleLevel: number[] = [];
    const inline: number[] = [];
    for (const line of [...new Set(directiveLines)].sort((a, b) => a - b)) {
      if (!isDirectiveLine(lines[line - 1]?.trim())) continue;
      const depth = structure.braceDepth[line - 1] ?? 0;
      if (depth === 0) moduleLevel.push(line);
      else inline.push(line);
    }

    if (moduleLevel.length > 0) {
      for (const action of await exportedFunctions(ctx, file)) {
        drafts.push(
          await draftFor(ctx, {
            file,
            line: action.line,
            endLine: action.endLine,
            method: "POST",
            path: UNRESOLVED_PATH,
            framework: FRAMEWORKS.serverAction,
            symbol: `action ${action.name}`,
            handlerSymbol: action.name,
            label: `server action ${action.name}`,
            note: ACTION_NOTE,
            extra: { actionKind: "module" },
          }),
        );
      }
    }
    for (const line of inline) {
      const block = resolveBlock(lines, structure, line);
      const name = enclosingSymbol(lines, block.startLine) ?? "anonymous";
      drafts.push(
        await draftFor(ctx, {
          file,
          line: block.startLine,
          endLine: block.endLine,
          method: "POST",
          path: UNRESOLVED_PATH,
          framework: FRAMEWORKS.serverAction,
          symbol: `action ${name}`,
          handlerSymbol: name,
          label: `server action ${name}`,
          note: `inline "use server" directive; ${ACTION_NOTE}`,
          extra: { actionKind: "inline" },
        }),
      );
    }
  }
  return drafts;
}

/** Enumerates every Next.js entry point: handlers, API routes and server actions. */
export async function collectNextRoutes(ctx: RouteContext): Promise<RouteDraft[]> {
  return [
    ...(await collectAppRouter(ctx)),
    ...(await collectPagesRouter(ctx)),
    ...(await collectServerActions(ctx)),
  ];
}

/** Exposed for the tRPC collector, which mounts its procedures under a route path. */
export function routePathOf(file: string): string | undefined {
  if (!isAppRouteFile(file)) return undefined;
  return joinPaths(appRoutePath(file));
}

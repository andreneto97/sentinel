/**
 * Express, Fastify, Koa and Hono: the four frameworks that register a route by
 * calling a method on a router object.
 *
 * The hard part is never finding `app.get("/x", …)`; it is saying what the
 * path *is*. A router is built in one file, mounted under a prefix in another,
 * and mounted again under the router that mounts it. So this module builds a
 * small graph first — every router instance, where it was created, what prefix
 * it carries and what mounted it, across files — and only then turns each
 * registration into a unit with the full path.
 *
 * Where a link in that chain is not a literal, the path is `unresolved` and the
 * unit says why. That is the honest outcome: a route listed at the wrong path
 * is worse than one listed as unresolved, and a route left out entirely is a
 * coverage lie.
 */

import type { StructuralRule } from "../_ast-grep.ts";
import { brief, enclosingSymbol, literalOf, optionOf } from "../_unit-support.ts";
import type { LineRange } from "../slice.ts";
import { type SourceRegion, looksLikeGuardName, readHandler } from "./_handler-facts.ts";
import {
  FRAMEWORKS,
  FRAMEWORK_PACKAGES,
  METHOD_NAMES,
  ROUTER_METHODS,
  type RouteContext,
  type RouteDraft,
  UNRESOLVED_PATH,
  baseIdentifier,
  importsAny,
  joinPaths,
  parseExport,
  pathLiteral,
  resolveRelativeImport,
  textOf,
  trimReceiver,
} from "./_shared.ts";

/** Receivers that answer to `.get` and never route anything. */
const NOT_ROUTERS: ReadonlySet<string> = new Set([
  "map",
  "cache",
  "store",
  "session",
  "headers",
  "cookies",
  "searchParams",
  "params",
  "query",
  "formData",
  "localStorage",
  "sessionStorage",
  "env",
  "process",
  "registry",
  "context",
  "ctx",
  "res",
  "response",
  "url",
  "JSON",
  "Object",
  "Reflect",
]);

/** Factories that produce a router, and the framework each one belongs to. */
const FACTORY_FRAMEWORKS: ReadonlyArray<{ pattern: RegExp; framework: string }> = [
  { pattern: /^express(\.Router)?$/, framework: FRAMEWORKS.express },
  { pattern: /^(Fastify|fastify)$/, framework: FRAMEWORKS.fastify },
  { pattern: /^(Hono|OpenAPIHono)$/, framework: FRAMEWORKS.hono },
  { pattern: /^Koa$/, framework: FRAMEWORKS.koa },
];

/** The queries this collector contributes to the search. */
export const NODE_ROUTER_RULES: readonly StructuralRule[] = [
  ...ROUTER_METHODS.map((method) => ({
    id: `node-call-${method}`,
    rule: { pattern: `$OBJ.${method}($PATH, $$$HANDLERS)` },
  })),
  ...ROUTER_METHODS.map((method) => ({
    id: `node-chain-${method}`,
    // `router.route("/x").get(handler)` takes a single argument, so the
    // two-argument shape above cannot see it; the regex keeps the
    // single-argument shape from matching every `.get(key)` in the repository.
    rule: {
      all: [{ pattern: `$OBJ.${method}($HANDLER)` }, { regex: "\\.route\\s*\\(" }],
    },
  })),
  {
    id: "node-use",
    rule: {
      any: [{ pattern: "$OBJ.use($PATH, $$$MIDDLEWARE)" }, { pattern: "$OBJ.use($MOUNTED)" }],
    },
  },
  { id: "node-route-object", rule: { pattern: "$OBJ.route($ARG)" } },
  { id: "node-route-mount", rule: { pattern: "$OBJ.route($PATH, $SUB)" } },
  { id: "node-register", rule: { pattern: "$OBJ.register($PLUGIN, $$$OPTIONS)" } },
  { id: "node-basepath", rule: { pattern: "$OBJ.basePath($PATH)" } },
  { id: "node-on", rule: { pattern: "$OBJ.on($METHOD, $PATH, $$$HANDLERS)" } },
  {
    id: "node-factory",
    rule: {
      kind: "variable_declarator",
      has: {
        all: [
          { any: [{ kind: "call_expression" }, { kind: "new_expression" }] },
          {
            regex:
              "^(new\\s+)?(express(\\.Router)?|Router|Fastify|fastify|Hono|OpenAPIHono|Koa)\\s*[(<]",
          },
        ],
        stopBy: "neighbor",
      },
    },
  },
];

/** A router instance: where it was built, what it carries, and what mounted it. */
interface RouterRecord {
  readonly key: string;
  readonly file: string;
  readonly name: string;
  framework: string | undefined;
  /** A prefix the router was constructed with: Koa's `{ prefix }`, Hono's `basePath`. */
  ownPrefix: string | undefined;
  /** The router this one is mounted on, and under which prefix. */
  mount: { parent: string; prefix: string | undefined } | undefined;
}

/** A fastify plugin mounted under a prefix; every route inside it inherits the prefix. */
interface PluginMount {
  readonly file: string;
  /** Line range of the plugin function, or the whole file when it is another module. */
  readonly from: number;
  readonly to: number;
  readonly prefix: string | undefined;
}

/** The router graph of the whole repository, built once per enumeration. */
interface RouterGraph {
  readonly routers: Map<string, RouterRecord>;
  readonly plugins: PluginMount[];
}

/** The key a router is known by across files. */
function routerKey(file: string, name: string): string {
  return `${file}#${name}`;
}

/** The framework a factory expression belongs to, given what the file imports. */
export function frameworkOfFactory(
  callee: string,
  specifiers: ReadonlySet<string>,
): string | undefined {
  if (callee === "Router" || callee === "express.Router") {
    if (importsAny(specifiers, FRAMEWORK_PACKAGES[FRAMEWORKS.koa] ?? [])) return FRAMEWORKS.koa;
    return FRAMEWORKS.express;
  }
  return FACTORY_FRAMEWORKS.find((entry) => entry.pattern.test(callee))?.framework;
}

/** The framework a file belongs to, when exactly one is imported. */
async function frameworkOfFile(ctx: RouteContext, file: string): Promise<string | undefined> {
  const specifiers = await ctx.imports(file);
  const found = Object.entries(FRAMEWORK_PACKAGES).filter(([, packages]) =>
    importsAny(specifiers, packages),
  );
  return found.length === 1 ? found[0]?.[0] : undefined;
}

/** `name` and `callee` out of a variable declarator's own source text. */
export function parseFactory(text: string): { name: string; callee: string } | undefined {
  const match = /^\s*([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*(?:new\s+)?([A-Za-z_$][\w$.]*)/.exec(text);
  const name = match?.[1];
  const callee = match?.[2];
  return name === undefined || callee === undefined ? undefined : { name, callee };
}

/** The prefix a router was constructed with, from Koa's options or Hono's `basePath`. */
export function constructionPrefix(text: string): string | undefined {
  const basePath = /\.basePath\s*\(\s*(['"`])([^'"`]*)\1\s*\)/.exec(text);
  if (basePath?.[2] !== undefined) return basePath[2];
  const option = optionOf(text, "prefix");
  return option === undefined ? undefined : literalOf(option);
}

/** What a file binds by importing other modules: local name to the module and export it names. */
function importedBindings(
  lines: readonly string[],
  file: string,
  ctx: RouteContext,
): Map<string, { file: string; name: string }> {
  const bindings = new Map<string, { file: string; name: string }>();
  const statement = /import\s+([^;'"]+?)\s+from\s*['"]([^'"]+)['"]/g;
  for (const line of lines) {
    statement.lastIndex = 0;
    let match = statement.exec(line);
    while (match !== null) {
      const specifier = match[2];
      const target =
        specifier === undefined ? undefined : resolveRelativeImport(file, specifier, ctx.snapshot);
      const clause = match[1]?.trim() ?? "";
      match = statement.exec(line);
      if (target === undefined) continue;
      const defaultBinding = /^([A-Za-z_$][\w$]*)\s*(?:,|$)/.exec(clause);
      if (defaultBinding?.[1] !== undefined) {
        bindings.set(defaultBinding[1], { file: target, name: "default" });
      }
      const named = /\{([^}]*)\}/.exec(clause);
      for (const part of (named?.[1] ?? "").split(",")) {
        const aliased = /^\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*$/.exec(part);
        const exported = aliased?.[1];
        if (exported === undefined) continue;
        bindings.set(aliased?.[2] ?? exported, { file: target, name: exported });
      }
    }
  }
  return bindings;
}

/** What a file exports under each name, so an import can be followed to a declaration. */
function exportAliases(ctx: RouteContext, file: string): Map<string, string> {
  const aliases = new Map<string, string>();
  for (const match of ctx.matches.in("next-export-specifier", file)) {
    for (const specifier of match.lists.SPECS ?? []) {
      const aliased = /^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/.exec(specifier.trim());
      if (aliased?.[1] !== undefined) aliases.set(aliased[2] ?? aliased[1], aliased[1]);
    }
  }
  for (const match of ctx.matches.in("next-export-default", file)) {
    const parsed = parseExport(match.text);
    const value = parsed?.value ?? parsed?.name;
    if (value !== undefined && /^[A-Za-z_$][\w$]*$/.test(value)) aliases.set("default", value);
  }
  return aliases;
}

/** Everything one file needs resolved before its registrations can be read. */
interface FileScope {
  readonly file: string;
  readonly bindings: Map<string, { file: string; name: string }>;
  readonly locals: Set<string>;
  readonly framework: string | undefined;
  readonly routing: boolean;
}

/**
 * Resolves a receiver expression to the router it refers to, following an
 * import into the file that declared it — which is where the prefix a route
 * actually serves under usually lives.
 */
function resolveRouter(
  ctx: RouteContext,
  graph: RouterGraph,
  scopes: Map<string, FileScope>,
  file: string,
  expression: string | undefined,
): RouterRecord | undefined {
  const name = baseIdentifier(expression);
  if (name === undefined) return undefined;
  const scope = scopes.get(file);
  if (scope?.locals.has(name) === true) return graph.routers.get(routerKey(file, name));
  const binding = scope?.bindings.get(name);
  if (binding === undefined) return graph.routers.get(routerKey(file, name));
  const local = exportAliases(ctx, binding.file).get(binding.name) ?? binding.name;
  return graph.routers.get(routerKey(binding.file, local));
}

/** The full prefix a router serves under, following its mounts up to the root. */
export function fullPrefix(graph: RouterGraph, key: string, depth = 0): string | undefined {
  const record = graph.routers.get(key);
  if (record === undefined || depth > 8) return undefined;
  const mount = record.mount;
  if (mount === undefined) return joinPaths(record.ownPrefix);
  const parent = fullPrefix(graph, mount.parent, depth + 1);
  if (mount.prefix === undefined && record.ownPrefix === undefined) return parent;
  return joinPaths(parent, mount.prefix, record.ownPrefix);
}

/** Builds the repository-wide router graph. */
async function buildGraph(ctx: RouteContext, scopes: Map<string, FileScope>): Promise<RouterGraph> {
  const graph: RouterGraph = { routers: new Map(), plugins: [] };

  for (const match of ctx.matches.of("node-factory")) {
    const parsed = parseFactory(match.text);
    if (parsed === undefined) continue;
    const specifiers = await ctx.imports(match.file);
    const key = routerKey(match.file, parsed.name);
    graph.routers.set(key, {
      key,
      file: match.file,
      name: parsed.name,
      framework: frameworkOfFactory(parsed.callee, specifiers),
      ownPrefix: constructionPrefix(match.text),
      mount: undefined,
    });
  }

  // A Hono base path can also be set after construction: `app.basePath("/api")`.
  for (const match of ctx.matches.of("node-basepath")) {
    const record = resolveRouter(ctx, graph, scopes, match.file, match.vars.OBJ);
    const prefix = pathLiteral(match.vars.PATH);
    if (record !== undefined && prefix !== undefined && record.ownPrefix === undefined) {
      record.ownPrefix = prefix;
    }
  }

  for (const match of [...ctx.matches.of("node-use"), ...ctx.matches.of("node-route-mount")]) {
    const parent = resolveRouter(ctx, graph, scopes, match.file, match.vars.OBJ);
    if (parent === undefined) continue;
    const mountedArgs =
      match.vars.MOUNTED !== undefined
        ? [match.vars.MOUNTED]
        : [
            ...(match.lists.MIDDLEWARE ?? []),
            ...(match.vars.SUB === undefined ? [] : [match.vars.SUB]),
          ];
    const prefix = pathLiteral(match.vars.PATH);
    const dynamic = match.vars.PATH !== undefined && prefix === undefined;
    for (const argument of mountedArgs) {
      const child = resolveRouter(ctx, graph, scopes, match.file, argument);
      if (child === undefined || child.key === parent.key || child.mount !== undefined) continue;
      child.mount = {
        parent: parent.key,
        ...(dynamic ? { prefix: UNRESOLVED_PATH } : { prefix }),
      };
    }
  }

  for (const match of ctx.matches.of("node-register")) {
    const options = (match.lists.OPTIONS ?? []).join(" ");
    const declared = optionOf(options, "prefix");
    const prefix = declared === undefined ? undefined : literalOf(declared);
    const plugin = baseIdentifier(match.vars.PLUGIN);
    if (plugin === undefined) continue;
    const scope = scopes.get(match.file);
    const local = (await ctx.declarations(match.file)).get(plugin);
    if (local !== undefined) {
      graph.plugins.push({
        file: match.file,
        from: local.startLine,
        to: local.endLine,
        ...(declared !== undefined && prefix === undefined
          ? { prefix: UNRESOLVED_PATH }
          : { prefix }),
      });
      continue;
    }
    const binding = scope?.bindings.get(plugin);
    if (binding === undefined) continue;
    graph.plugins.push({
      file: binding.file,
      from: 1,
      to: Number.MAX_SAFE_INTEGER,
      ...(declared !== undefined && prefix === undefined
        ? { prefix: UNRESOLVED_PATH }
        : { prefix }),
    });
  }

  return graph;
}

/** The prefix a fastify plugin mount imposes on a registration inside it. */
function pluginPrefix(graph: RouterGraph, file: string, line: number): string | undefined {
  for (const plugin of graph.plugins) {
    if (plugin.file === file && line >= plugin.from && line <= plugin.to) return plugin.prefix;
  }
  return undefined;
}

/**
 * How a middleware argument is named in the report: as written when it is an
 * identifier or a member expression, and by its receiver otherwise, so an
 * inline arrow does not paste a function body into an attribute.
 */
export function middlewareLabel(expression: string): string {
  const trimmed = expression.trim();
  if (trimmed === "") return "";
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(trimmed)) return trimmed;
  return baseIdentifier(trimmed) ?? brief(trimmed);
}

/** The path a chained `router.route("/x").get(…)` registration carries. */
export function chainPath(expression: string | undefined): string | undefined {
  if (expression === undefined) return undefined;
  const match = /\.route\s*\(\s*(['"`])([^'"`]*)\1\s*\)/.exec(expression);
  return match?.[2];
}

/** One registration found in the source, before it becomes a unit. */
interface Registration {
  readonly file: string;
  readonly line: number;
  readonly endLine: number;
  readonly text: string;
  readonly method: string;
  readonly receiver: string | undefined;
  readonly path: string | undefined;
  readonly dynamicPath: boolean;
  readonly handlers: readonly string[];
  /** A `schema` option, for the Fastify route-object form. */
  readonly options?: string | undefined;
}

/** Every registration in the repository, in file and line order. */
function registrations(ctx: RouteContext): Registration[] {
  const found: Registration[] = [];
  for (const method of ROUTER_METHODS) {
    for (const match of ctx.matches.of(`node-call-${method}`)) {
      // In `router.route("/x").get(guard, handler)` the first argument is a
      // handler, not a path: the path came from the `.route()` before it.
      const chained = chainPath(match.vars.OBJ);
      const literal = pathLiteral(match.vars.PATH);
      const handlers = match.lists.HANDLERS ?? [];
      found.push({
        file: match.file,
        line: match.line,
        endLine: match.endLine,
        text: match.text,
        method: METHOD_NAMES[method] ?? method.toUpperCase(),
        receiver: match.vars.OBJ,
        path: chained ?? literal,
        dynamicPath: chained === undefined && literal === undefined,
        handlers:
          chained === undefined
            ? handlers
            : [...(match.vars.PATH === undefined ? [] : [match.vars.PATH]), ...handlers],
      });
    }
    for (const match of ctx.matches.of(`node-chain-${method}`)) {
      const path = chainPath(match.vars.OBJ);
      found.push({
        file: match.file,
        line: match.line,
        endLine: match.endLine,
        text: match.text,
        method: METHOD_NAMES[method] ?? method.toUpperCase(),
        receiver: match.vars.OBJ,
        path,
        dynamicPath: path === undefined,
        handlers: match.vars.HANDLER === undefined ? [] : [match.vars.HANDLER],
      });
    }
  }
  for (const match of ctx.matches.of("node-on")) {
    const path = pathLiteral(match.vars.PATH);
    for (const method of methodList(match.vars.METHOD)) {
      found.push({
        file: match.file,
        line: match.line,
        endLine: match.endLine,
        text: match.text,
        method,
        receiver: match.vars.OBJ,
        path,
        dynamicPath: path === undefined,
        handlers: match.lists.HANDLERS ?? [],
      });
    }
  }
  for (const match of ctx.matches.of("node-route-object")) {
    const argument = match.vars.ARG ?? "";
    // `app.route("/x")` is the head of an Express chain; the methods come from
    // the chained calls, which `node-chain-*` reports separately.
    if (!argument.trimStart().startsWith("{")) continue;
    const url = optionOf(argument, "url") ?? optionOf(argument, "path");
    const path = url === undefined ? undefined : literalOf(url);
    for (const method of methodList(optionOf(argument, "method"))) {
      found.push({
        file: match.file,
        line: match.line,
        endLine: match.endLine,
        text: match.text,
        method,
        receiver: match.vars.OBJ,
        path,
        dynamicPath: path === undefined,
        handlers: [],
        options: argument,
      });
    }
  }
  return found.sort(
    (left, right) =>
      left.file.localeCompare(right.file) ||
      left.line - right.line ||
      left.method.localeCompare(right.method),
  );
}

/** The methods a `method:` option or an `on()` argument names. */
export function methodList(text: string | undefined): string[] {
  if (text === undefined) return ["ANY"];
  const found = [...text.matchAll(/['"`]([A-Za-z]+)['"`]/g)]
    .map((match) => (match[1] ?? "").toUpperCase())
    .filter((method) => method !== "");
  return found.length === 0 ? ["ANY"] : [...new Set(found)].sort();
}

/** Builds the scope of every file that might register a route. */
async function buildScopes(ctx: RouteContext): Promise<Map<string, FileScope>> {
  const ruleIds = [
    ...ROUTER_METHODS.flatMap((method) => [`node-call-${method}`, `node-chain-${method}`]),
    "node-use",
    "node-route-object",
    "node-route-mount",
    "node-register",
    "node-basepath",
    "node-on",
    "node-factory",
  ];
  const scopes = new Map<string, FileScope>();
  for (const file of ctx.matches.files(ruleIds)) {
    const lines = await ctx.lines(file);
    const locals = new Set<string>();
    for (const match of ctx.matches.in("node-factory", file)) {
      const parsed = parseFactory(match.text);
      if (parsed !== undefined) locals.add(parsed.name);
    }
    const specifiers = await ctx.imports(file);
    const framework = await frameworkOfFile(ctx, file);
    const routing =
      locals.size > 0 ||
      framework !== undefined ||
      ctx.inRouteDir(file) ||
      Object.values(FRAMEWORK_PACKAGES).some((packages) => importsAny(specifiers, packages));
    scopes.set(file, {
      file,
      bindings: importedBindings(lines, file, ctx),
      locals,
      framework,
      routing,
    });
  }
  return scopes;
}

/** A handler argument that is a bare name, and so can be followed to its import. */
const PLAIN_IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

/** A handler's body, wherever it turned out to be declared. */
interface ResolvedHandler {
  /** The identifier the registration named. */
  readonly name: string;
  /** Repo-relative file the declaration lives in. */
  readonly file: string;
  /** The declaration's extent in that file. */
  readonly range: LineRange;
  /** The same extent as a region the fact detectors can read. */
  readonly region: SourceRegion;
}

/**
 * The body of the handler a registration points at — in the router's own file,
 * or in the file the router imported it from.
 *
 * A router that declares its handler inline is the easy half. The dominant
 * Express layout in a large codebase is one file per handler, default-exported
 * and imported by the router, and for those the registration line contains no
 * code at all: `api.delete("/:type/:id", removeByTypeAndId)`. Read only that,
 * and every fact comes back negative — `authCheck: none`, `validation: none` —
 * not because the handler checks nothing but because nobody opened it. Those
 * are the facts the audit prompt presents as ground truth, so an unresolved
 * import does not merely lose coverage, it states the opposite of the truth.
 *
 * The router's own declarations win, so a locally declared handler resolves
 * exactly as it did before imports were followed at all.
 */
async function resolveHandler(
  ctx: RouteContext,
  scope: FileScope | undefined,
  file: string,
  declarations: ReadonlyMap<string, LineRange>,
  names: { readonly local: readonly string[]; readonly imported: string | undefined },
): Promise<ResolvedHandler | undefined> {
  for (const name of names.local) {
    const range = declarations.get(name);
    if (range === undefined) continue;
    const lines = await ctx.lines(file);
    return {
      name,
      file,
      range,
      region: { text: textOf(lines, range.startLine, range.endLine), startLine: range.startLine },
    };
  }
  const name = names.imported;
  const binding = name === undefined ? undefined : scope?.bindings.get(name);
  if (name === undefined || binding === undefined || binding.file === file) return undefined;
  const range = (await ctx.declarations(binding.file)).get(binding.name);
  if (range === undefined) return undefined;
  const lines = await ctx.lines(binding.file);
  return {
    name,
    file: binding.file,
    range,
    region: {
      text: textOf(lines, range.startLine, range.endLine),
      startLine: range.startLine,
      // Named, because a guard or a schema found here is cited in this file.
      file: binding.file,
    },
  };
}

/** Enumerates every Express, Fastify, Koa and Hono route registration. */
export async function collectNodeRoutes(ctx: RouteContext): Promise<RouteDraft[]> {
  const scopes = await buildScopes(ctx);
  const graph = await buildGraph(ctx, scopes);
  const drafts: RouteDraft[] = [];
  const seen = new Map<string, number>();

  for (const registration of registrations(ctx)) {
    const scope = scopes.get(registration.file);
    const receiverName = baseIdentifier(registration.receiver) ?? "";
    if (NOT_ROUTERS.has(receiverName)) continue;
    const record = resolveRouter(ctx, graph, scopes, registration.file, registration.receiver);
    const literalPath = registration.path?.startsWith("/") === true;
    // A path-shaped literal is proof enough on its own; anything else has to
    // come from a file that is demonstrably routing, or it is someone's `.get`.
    if (!literalPath && record === undefined && scope?.routing !== true) continue;
    if (registration.method === "ANY" && registration.path === undefined) continue;

    const mounted = record === undefined ? undefined : fullPrefix(graph, record.key);
    const plugin = pluginPrefix(graph, registration.file, registration.line);
    const path = registration.dynamicPath
      ? UNRESOLVED_PATH
      : joinPaths(mounted, plugin, registration.path);
    const framework =
      record?.framework ?? scope?.framework ?? (await frameworkOfFile(ctx, registration.file));

    const lines = await ctx.lines(registration.file);
    const declarations = await ctx.declarations(registration.file);
    const guards = await ctx.guards(registration.file);
    // The handler is the last argument; everything before it is middleware.
    const candidates = [...registration.handlers]
      .reverse()
      .map((handler) => baseIdentifier(handler))
      .filter((name): name is string => name !== undefined);
    // Only the last argument is the handler. A locally declared middleware has
    // always been an accepted fallback, but following an *import* to one would
    // read `requireUser`'s body as the handler's and attribute its guard to a
    // route that never runs it.
    const last = registration.handlers[registration.handlers.length - 1]?.trim() ?? "";
    const resolved = await resolveHandler(ctx, scope, registration.file, declarations, {
      local: candidates,
      imported: PLAIN_IDENTIFIER.test(last) ? last : undefined,
    });
    const named = resolved?.name;
    const regions = [
      trimReceiver(registration.text, registration.receiver, registration.line),
      ...(resolved === undefined ? [] : [resolved.region]),
    ];
    const facts = readHandler({
      file: registration.file,
      regions,
      method: registration.method,
      // The composed path, so a parameter declared on the mount prefix counts.
      path,
      // A handler in another file imports its own guard: the router's import
      // list cannot vouch for a check that is not written in the router.
      guards:
        resolved === undefined || resolved.file === registration.file
          ? guards
          : new Set([...guards, ...(await ctx.guards(resolved.file))]),
    });

    const preHandlers =
      registration.options === undefined
        ? []
        : ["preHandler", "onRequest", "preValidation"].flatMap((option) =>
            (optionOf(registration.options ?? "", option) ?? "")
              .split(/[[\],]/)
              .map((entry) => middlewareLabel(entry))
              .filter((entry) => entry !== ""),
          );
    const middleware = [
      ...registration.handlers
        .slice(0, Math.max(0, registration.handlers.length - 1))
        .map((entry) => middlewareLabel(entry)),
      ...preHandlers,
    ].filter((entry) => entry !== "");
    // A guard passed as middleware is a reference, not a call, so the body
    // scan cannot see it; the argument list is where it is named.
    const guardMiddleware = middleware.find((entry) =>
      entry.split(".").some((segment) => looksLikeGuardName(segment) || guards.has(segment)),
    );
    const enclosing = enclosingSymbol(lines, registration.line);
    const base = `${registration.method} ${path}`;
    const count = (seen.get(`${registration.file}${base}`) ?? 0) + 1;
    seen.set(`${registration.file}${base}`, count);

    const notes = [
      registration.dynamicPath
        ? "the path argument is not a literal, so the route could not be resolved"
        : undefined,
      mounted === UNRESOLVED_PATH || plugin === UNRESOLVED_PATH
        ? "the mount prefix is not a literal"
        : undefined,
      record === undefined && !registration.dynamicPath && plugin === undefined
        ? "no router declaration was found for this receiver, so any mount prefix is missing"
        : undefined,
    ].filter((note): note is string => note !== undefined);

    drafts.push({
      kind: "route",
      label: `${registration.method} ${path}`,
      file: registration.file,
      line: registration.line,
      endLine: registration.endLine,
      symbol: count === 1 ? base : `${base} #${count}`,
      ...(notes.length === 0 ? {} : { note: notes.join("; ") }),
      attributes: {
        trigger: "http",
        method: registration.method,
        path,
        ...(framework === undefined ? {} : { framework }),
        ...(named === undefined ? {} : { handlerSymbol: named }),
        ...(enclosing === undefined ? {} : { symbol: enclosing }),
        ...(resolved === undefined
          ? {}
          : {
              handlerSource: `${resolved.file}:${resolved.range.startLine}-${resolved.range.endLine}`,
            }),
        ...(middleware.length === 0 ? {} : { middleware: middleware.join(",") }),
        ...facts,
        ...(facts.authCheck === "none" && guardMiddleware !== undefined
          ? {
              authCheck: guardMiddleware,
              authSource: `${registration.file}:${registration.line}`,
              authenticated: "yes",
            }
          : {}),
        ...(registration.options !== undefined &&
        optionOf(registration.options, "schema") !== undefined
          ? { validation: brief(`schema: ${optionOf(registration.options, "schema") ?? ""}`) }
          : {}),
      },
    });
  }
  return drafts;
}

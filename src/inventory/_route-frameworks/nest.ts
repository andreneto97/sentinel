/**
 * NestJS controllers: a route is a method decorator, and its path is composed
 * from three places at once — the global prefix set in `main.ts`, the
 * `@Controller()` prefix, and the method decorator's own argument.
 *
 * Decorators are enumerated as nodes and composed here by line range rather
 * than through relational rules, because a method carries several of them
 * (`@Get`, `@UseGuards`, `@HttpCode`) and the guard decorators are exactly
 * what the audit needs to see. Matching "the decorator immediately before the
 * method" would have thrown them away.
 */

import type { StructuralRule } from "../_ast-grep.ts";
import { brief, collapse } from "../_unit-support.ts";
import { readHandler } from "./_handler-facts.ts";
import {
  FRAMEWORKS,
  METHOD_NAMES,
  type RouteContext,
  type RouteDraft,
  UNRESOLVED_PATH,
  joinPaths,
  pathLiteral,
  textOf,
} from "./_shared.ts";

/** Decorators worth enumerating: routing, guards and parameter binding. */
const DECORATOR_NAMES =
  "Controller|Get|Post|Put|Patch|Delete|Head|Options|All|Search|UseGuards|UseInterceptors|SetMetadata|Public|Roles|HttpCode|Redirect|Sse|Body|Param|Query|Headers|Req|Request|UploadedFile|UploadedFiles|Version";

/** The queries this collector contributes to the search. */
export const NEST_RULES: readonly StructuralRule[] = [
  {
    id: "nest-decorator",
    rule: {
      all: [{ kind: "decorator" }, { regex: `^@\\s*(${DECORATOR_NAMES})\\b` }],
    },
  },
  {
    id: "nest-method",
    // Only methods that sit in a decorated class body; an undecorated class is
    // not a controller, and this keeps every method in the repository out.
    rule: {
      all: [{ kind: "method_definition" }, { follows: { kind: "decorator", stopBy: "end" } }],
    },
  },
  {
    id: "nest-global-prefix",
    rule: {
      any: [
        { pattern: "$APP.setGlobalPrefix($PREFIX)" },
        { pattern: "$APP.setGlobalPrefix($PREFIX, $$$REST)" },
      ],
    },
  },
];

/** The HTTP method each Nest routing decorator maps to. */
const DECORATOR_METHODS: Readonly<Record<string, string>> = {
  Get: "GET",
  Post: "POST",
  Put: "PUT",
  Patch: "PATCH",
  Delete: "DELETE",
  Head: "HEAD",
  Options: "OPTIONS",
  All: "ANY",
  Search: "SEARCH",
  Sse: "GET",
};

/** Decorators that gate a route; their presence is the authorization check. */
const GUARD_DECORATORS: ReadonlySet<string> = new Set(["UseGuards", "Roles"]);

/**
 * The decorator that takes a guard away.
 *
 * `@Public()` is the convention for opting a route out of a globally applied
 * guard, so a route carrying it is unauthenticated however many guards the
 * application registered — which is exactly the case the audit must see.
 */
const PUBLIC_DECORATOR = "Public";

/** One decorator, parsed from its own source text. */
export interface ParsedDecorator {
  readonly name: string;
  /** The argument list as written, without the parentheses. */
  readonly args: string;
  readonly line: number;
  readonly endLine: number;
  readonly text: string;
}

/** Splits `@Get(":id")` into its name and its arguments. */
export function parseDecorator(text: string): { name: string; args: string } | undefined {
  const match = /^@\s*([A-Za-z_$][\w$.]*)\s*(?:\(([\s\S]*)\))?\s*$/.exec(text.trim());
  const name = match?.[1];
  if (name === undefined) return undefined;
  return { name, args: match?.[2] ?? "" };
}

/** The name a method definition declares. */
export function methodName(text: string): string | undefined {
  const match =
    /^\s*(?:(?:public|private|protected|static|readonly|async|override)\s+)*\*?\s*([A-Za-z_$][\w$]*)\s*[(<]/.exec(
      text,
    );
  return match?.[1];
}

/** The path a `@Controller()` or `@Get()` argument declares, if it is a literal. */
export function decoratorPath(args: string): string | undefined {
  const trimmed = args.trim();
  if (trimmed === "") return "";
  const literal = pathLiteral(trimmed.split(",")[0]?.trim());
  if (literal !== undefined) return literal;
  const option = /path\s*:\s*(['"`])([^'"`]*)\1/.exec(trimmed);
  return option?.[2];
}

/** The class a decorator is attached to, and the line that declares it. */
function classBelow(
  lines: readonly string[],
  line: number,
): { name: string; line: number } | undefined {
  for (let index = line; index < Math.min(lines.length, line + 12); index += 1) {
    const match = /\bclass\s+([A-Za-z_$][\w$]*)/.exec(lines[index] ?? "");
    if (match?.[1] !== undefined) return { name: match[1], line: index + 1 };
  }
  return undefined;
}

/** A controller and the prefix every route inside it inherits. */
interface Controller {
  /** Line of the `@Controller()` decorator. */
  readonly line: number;
  /** Line of the `class` keyword; decorators above it are the class's, below it a method's. */
  readonly classLine: number;
  readonly name: string;
  readonly prefix: string | undefined;
}

/** The global prefix the application sets, when exactly one is set. */
function globalPrefix(ctx: RouteContext): string | undefined {
  const values = new Set<string>();
  for (const match of ctx.matches.of("nest-global-prefix")) {
    const prefix = pathLiteral(match.vars.PREFIX);
    if (prefix !== undefined) values.add(prefix);
  }
  if (values.size > 1) {
    ctx.warn(
      `setGlobalPrefix is called with ${values.size} different prefixes; controller paths are reported without it`,
    );
    return undefined;
  }
  return [...values][0];
}

/** Enumerates every NestJS controller route. */
export async function collectNestRoutes(ctx: RouteContext): Promise<RouteDraft[]> {
  const drafts: RouteDraft[] = [];
  const prefix = globalPrefix(ctx);
  const files = ctx.matches.files(["nest-decorator"]);

  for (const file of files) {
    const lines = await ctx.lines(file);
    const decorators: ParsedDecorator[] = [];
    for (const match of ctx.matches.in("nest-decorator", file)) {
      const parsed = parseDecorator(match.text);
      if (parsed === undefined) continue;
      decorators.push({
        name: parsed.name,
        args: parsed.args,
        line: match.line,
        endLine: match.endLine,
        text: match.text,
      });
    }
    if (decorators.length === 0) continue;
    decorators.sort((left, right) => left.line - right.line);

    const controllers: Controller[] = decorators
      .filter((decorator) => decorator.name === "Controller")
      .map((decorator) => {
        const declared = classBelow(lines, decorator.line);
        return {
          line: decorator.line,
          classLine: declared?.line ?? decorator.line,
          name: declared?.name ?? "Controller",
          prefix: decoratorPath(decorator.args),
        };
      });
    if (controllers.length === 0) continue;

    const methods = [...ctx.matches.in("nest-method", file)].sort(
      (left, right) => left.line - right.line,
    );
    let previousEnd = 0;
    for (const method of methods) {
      const controller = [...controllers]
        .reverse()
        .find((candidate) => candidate.line < method.line);
      if (controller === undefined) continue;
      // A decorator above the `class` keyword belongs to the class, not to the
      // first method under it — and a class-level `@UseGuards` is what
      // authenticates most Nest applications.
      const boundary = Math.max(previousEnd, controller.classLine);
      const attached = decorators.filter(
        (decorator) => decorator.endLine < method.line && decorator.line > boundary,
      );
      previousEnd = method.endLine;
      const routing = attached.filter(
        (decorator) => DECORATOR_METHODS[decorator.name] !== undefined,
      );
      if (routing.length === 0) continue;

      const classLevel = decorators.filter(
        (decorator) =>
          decorator.line >= controller.line &&
          decorator.line < controller.classLine &&
          GUARD_DECORATORS.has(decorator.name),
      );
      const name = methodName(method.text) ?? "handler";
      const guards = [
        ...classLevel,
        ...attached.filter((decorator) => GUARD_DECORATORS.has(decorator.name)),
      ];
      const isPublic = attached.some((decorator) => decorator.name === PUBLIC_DECORATOR);
      for (const decorator of routing) {
        const httpMethod =
          DECORATOR_METHODS[decorator.name] ?? METHOD_NAMES[decorator.name.toLowerCase()] ?? "ANY";
        const own = decoratorPath(decorator.args);
        const path =
          controller.prefix === undefined || own === undefined
            ? undefined
            : joinPaths(prefix, controller.prefix, own);
        const regions = [
          ...attached.map((entry) => ({ text: entry.text, startLine: entry.line })),
          { text: textOf(lines, method.line, method.endLine), startLine: method.line },
        ];
        const facts = readHandler({
          file,
          regions,
          method: httpMethod,
          ...(path === undefined ? {} : { path }),
          guards: await ctx.guards(file),
        });
        const label = `${httpMethod} ${path ?? UNRESOLVED_PATH}`;
        drafts.push({
          kind: "route",
          label,
          file,
          line: attached[0]?.line ?? method.line,
          endLine: method.endLine,
          symbol: `${controller.name}.${name}`,
          ...(path === undefined ? { note: "the controller or method path is not a literal" } : {}),
          attributes: {
            trigger: "http",
            method: httpMethod,
            path: path ?? UNRESOLVED_PATH,
            framework: FRAMEWORKS.nest,
            handlerSymbol: `${controller.name}.${name}`,
            symbol: `${controller.name}.${name}`,
            controller: controller.name,
            ...(guards.length === 0
              ? {}
              : { middleware: guards.map((guard) => collapse(guard.text)).join(",") }),
            ...facts,
            ...(guards.length === 0 || isPublic
              ? {}
              : {
                  authCheck: brief(guards.map((guard) => collapse(guard.text)).join(" ")),
                  authSource: `${file}:${guards[0]?.line ?? method.line}`,
                  authenticated: "yes",
                }),
            ...(isPublic
              ? { authCheck: "none", authenticated: "no", publicDecorator: "true" }
              : {}),
          },
        });
      }
    }
  }
  return drafts;
}

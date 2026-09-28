/**
 * What every route collector shares: the vocabulary of HTTP methods, the index
 * that hands a collector its own matches, path composition, and the small
 * amount of import resolution that decides whether a file belongs to a
 * framework at all.
 *
 * The enumerators express *shapes* as ast-grep rules and do the composing here,
 * in TypeScript, rather than in ever-cleverer relational rules. A mounted
 * router, a controller prefix and a nested tRPC namespace are all the same
 * problem — "which node encloses which" — and range arithmetic over matched
 * nodes is both easier to test and easier to read than a rule that tries to
 * express it.
 */

import { posix } from "node:path";
import { z } from "zod";
import type { StackProfile } from "../../contracts/profile.ts";
import { authHelperFiles, routeDirs } from "../../profile/accessors.ts";
import type { RepoSnapshot } from "../../profile/repo-snapshot.ts";
import type { StructuralMatch } from "../_ast-grep.ts";
import type { DraftUnit } from "../_unit-support.ts";
import { type LineRange, type SourceStructure, resolveBlock, scanSource } from "../slice.ts";
import { containsAuthCheck } from "./_auth-patterns.ts";

/** A route unit as the collectors build it; the aggregator gives it its id. */
export type RouteDraft = DraftUnit & { readonly kind: "route" };

/** The HTTP methods a route unit can carry, plus the aliases frameworks accept. */
export const METHOD_NAMES: Readonly<Record<string, string>> = {
  get: "GET",
  post: "POST",
  put: "PUT",
  patch: "PATCH",
  delete: "DELETE",
  del: "DELETE",
  head: "HEAD",
  options: "OPTIONS",
  all: "ANY",
  use: "ANY",
};

/** The method names a router registers a handler under, in a fixed order. */
export const ROUTER_METHODS: readonly string[] = [
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "del",
  "head",
  "options",
  "all",
];

/** Methods that change state by definition; a `GET` that writes is the audit's problem. */
const MUTATING_METHODS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** True when the method itself implies a state change. */
export function isMutatingMethod(method: string | undefined): boolean {
  return method !== undefined && MUTATING_METHODS.has(method.toUpperCase());
}

/** The value a `path` attribute carries when the registration cannot be resolved. */
export const UNRESOLVED_PATH = "unresolved";

/** Sentinel's own name for each supported framework, used as the `framework` attribute. */
export const FRAMEWORKS = {
  nextApp: "next-app-router",
  nextPages: "next-pages-router",
  serverAction: "next-server-action",
  express: "express",
  fastify: "fastify",
  koa: "koa",
  hono: "hono",
  nest: "nestjs",
  trpc: "trpc",
} as const;

/** One of Sentinel's framework names; see {@link FRAMEWORKS}. */
export type FrameworkName = (typeof FRAMEWORKS)[keyof typeof FRAMEWORKS];

/** The package each framework is proven by, for the per-file import check. */
export const FRAMEWORK_PACKAGES: Readonly<Record<string, readonly string[]>> = {
  [FRAMEWORKS.express]: ["express"],
  [FRAMEWORKS.fastify]: ["fastify"],
  [FRAMEWORKS.koa]: ["koa", "@koa/router", "koa-router"],
  [FRAMEWORKS.hono]: ["hono", "hono/tiny", "@hono/zod-openapi"],
};

// ---------------------------------------------------------------------------
// The match index
// ---------------------------------------------------------------------------

/** Every match of a search, addressable by rule and by file. */
export interface MatchIndex {
  /** Every match of one rule, in file and line order. */
  of(ruleId: string): readonly StructuralMatch[];
  /** Every match of one rule inside one file. */
  in(ruleId: string, file: string): readonly StructuralMatch[];
  /** Files with at least one match of any of the given rules, sorted. */
  files(ruleIds: readonly string[]): readonly string[];
}

/** Groups a flat match list by rule and by file, once per run. */
export function indexMatches(matches: readonly StructuralMatch[]): MatchIndex {
  const byRule = new Map<string, StructuralMatch[]>();
  const byRuleFile = new Map<string, StructuralMatch[]>();
  for (const match of matches) {
    const rule = byRule.get(match.ruleId);
    if (rule === undefined) byRule.set(match.ruleId, [match]);
    else rule.push(match);
    const key = `${match.ruleId}${match.file}`;
    const scoped = byRuleFile.get(key);
    if (scoped === undefined) byRuleFile.set(key, [match]);
    else scoped.push(match);
  }
  return {
    of: (ruleId) => byRule.get(ruleId) ?? [],
    in: (ruleId, file) => byRuleFile.get(`${ruleId}${file}`) ?? [],
    files(ruleIds) {
      const seen = new Set<string>();
      for (const ruleId of ruleIds) {
        for (const match of byRule.get(ruleId) ?? []) seen.add(match.file);
      }
      return [...seen].sort();
    },
  };
}

// ---------------------------------------------------------------------------
// The collector context
// ---------------------------------------------------------------------------

/** Everything a framework collector is handed. */
export interface RouteContext {
  /** The repository listing, with cached reads. */
  readonly snapshot: RepoSnapshot;
  /** Phase 0 output, when the phase ran. */
  readonly profile?: StackProfile | undefined;
  readonly matches: MatchIndex;
  /** A file's lines, cached; empty when it could not be read. */
  lines(file: string): Promise<readonly string[]>;
  /** A file's lexical structure, cached, for resolving a handler body. */
  structure(file: string): Promise<SourceStructure>;
  /** The module specifiers a file imports, cached. */
  imports(file: string): Promise<ReadonlySet<string>>;
  /** Where each top-level name of a file is defined, cached. */
  declarations(file: string): Promise<ReadonlyMap<string, LineRange>>;
  /** Names a file imports from a file phase 0 proved holds an auth check, cached. */
  guards(file: string): Promise<ReadonlySet<string>>;
  /** Repo-relative files phase 0 proved contain an authentication check. */
  readonly authHelperFiles: ReadonlySet<string>;
  /** True when phase 0 proved this file sits in a directory that registers routes. */
  inRouteDir(file: string): boolean;
  /** Records something the collector could not resolve; surfaced on the outcome. */
  warn(message: string): void;
}

/** Builds the collector context over a snapshot and one search result. */
export function createRouteContext(input: {
  snapshot: RepoSnapshot;
  matches: readonly StructuralMatch[];
  profile?: StackProfile | undefined;
  warnings: string[];
}): RouteContext {
  const lineCache = new Map<string, readonly string[]>();
  const structureCache = new Map<string, SourceStructure>();
  const importCache = new Map<string, ReadonlySet<string>>();
  const declarationCache = new Map<string, ReadonlyMap<string, LineRange>>();
  const guardCache = new Map<string, ReadonlySet<string>>();
  let aliases: Promise<PathAlias[]> | undefined;
  // Phase 0 proved these directories register routes; a file in one is routing
  // even when it imports its router from somewhere else.
  const directories = input.profile === undefined ? [] : routeDirs(input.profile);
  return {
    snapshot: input.snapshot,
    ...(input.profile === undefined ? {} : { profile: input.profile }),
    matches: indexMatches(input.matches),
    authHelperFiles: new Set(input.profile === undefined ? [] : authHelperFiles(input.profile)),
    inRouteDir(file: string): boolean {
      return directories.some(
        (directory) => file === directory || file.startsWith(`${directory}/`),
      );
    },
    async lines(file: string): Promise<readonly string[]> {
      const cached = lineCache.get(file);
      if (cached !== undefined) return cached;
      const read = (await input.snapshot.lines(file)) ?? [];
      lineCache.set(file, read);
      return read;
    },
    async structure(file: string): Promise<SourceStructure> {
      const cached = structureCache.get(file);
      if (cached !== undefined) return cached;
      const scanned = scanSource(await this.lines(file));
      structureCache.set(file, scanned);
      return scanned;
    },
    async imports(file: string): Promise<ReadonlySet<string>> {
      const cached = importCache.get(file);
      if (cached !== undefined) return cached;
      const found = importedModules(await this.lines(file));
      importCache.set(file, found);
      return found;
    },
    async declarations(file: string): Promise<ReadonlyMap<string, LineRange>> {
      const cached = declarationCache.get(file);
      if (cached !== undefined) return cached;
      const found = declarationIndex(await this.lines(file), await this.structure(file));
      declarationCache.set(file, found);
      return found;
    },
    async guards(file: string): Promise<ReadonlySet<string>> {
      const cached = guardCache.get(file);
      if (cached !== undefined) return cached;
      // The alias map is read once per context: every handler in the repository
      // resolves its imports against the same tsconfig.
      aliases ??= readPathAliases(input.snapshot);
      const found = await importedGuards(
        await this.lines(file),
        file,
        this.authHelperFiles,
        input.snapshot,
        await aliases,
      );
      guardCache.set(file, found);
      return found;
    },
    warn(message: string): void {
      if (!input.warnings.includes(message)) input.warnings.push(message);
    },
  };
}

/** Every module specifier a file imports or requires. */
export function importedModules(lines: readonly string[]): ReadonlySet<string> {
  const found = new Set<string>();
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
  ];
  for (const line of lines) {
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match = pattern.exec(line);
      while (match !== null) {
        const specifier = match[1];
        if (specifier !== undefined && specifier !== "") found.add(specifier);
        match = pattern.exec(line);
      }
    }
  }
  return found;
}

/** What an `export` statement declares, read from its own source text. */
export interface ParsedExport {
  /** The exported name; `default` for a default export with no name of its own. */
  readonly name: string;
  /** The initialiser, for `export const x = …`; absent for a function or class. */
  readonly value: string | undefined;
  readonly isDefault: boolean;
}

/**
 * Parses an export statement.
 *
 * Done on the node's text rather than with a pattern per shape, because
 * `export async function GET(req: Request): Promise<Response>` and
 * `export const GET: RouteHandler = async () => {}` are the same export with
 * type annotations in the way — and a pattern that does not allow for the
 * annotation silently drops the handler, which is the worst failure this
 * phase has.
 */
export function parseExport(text: string): ParsedExport | undefined {
  const trimmed = text.trim();
  const isDefault = /^export\s+default\b/.test(trimmed);
  const fn = /^export\s+(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)?/.exec(
    trimmed,
  );
  if (fn !== null) {
    return { name: fn[1] ?? "default", value: undefined, isDefault };
  }
  const klass = /^export\s+(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)?/.exec(
    trimmed,
  );
  if (klass !== null) {
    return { name: klass[1] ?? "default", value: undefined, isDefault };
  }
  const declared =
    /^export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*([\s\S]*)$/.exec(trimmed);
  if (declared?.[1] !== undefined) {
    return { name: declared[1], value: declared[2]?.replace(/;\s*$/, ""), isDefault: false };
  }
  if (isDefault) {
    const value = trimmed.replace(/^export\s+default\s+/, "").replace(/;\s*$/, "");
    return { name: "default", value, isDefault: true };
  }
  return undefined;
}

/** Top-level declarations a route collector has to be able to look up by name. */
const DECLARATION_PATTERNS: readonly RegExp[] = [
  /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/,
  /^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=/,
];

/**
 * `export default …` — anything but the `export default from` that is not JS.
 *
 * Indexed under the key {@link DEFAULT_EXPORT_KEY} because that is the name an
 * imported default binding resolves under, and because `default` is a reserved
 * word, so it can never collide with a declaration of the file's own.
 */
const DEFAULT_EXPORT = /^\s*export\s+default\s+\S/;

/** `export default listUsers;` — the default is a declaration made elsewhere in the file. */
const DEFAULT_EXPORT_ALIAS = /^\s*export\s+default\s+([A-Za-z_$][\w$]*)\s*;?\s*$/;

/**
 * The key a module's default export is indexed under.
 *
 * `importedBindings` records a default import as `{ file, name: "default" }`,
 * and this is the other half of that agreement.
 */
export const DEFAULT_EXPORT_KEY = "default";

/**
 * Where each named declaration of a file lives.
 *
 * Needed whenever a route points at a handler by name — `router.get("/x",
 * listUsers)`, `export { handler as GET }`, `server.register(billingRoutes)` —
 * because the unit's slice has to contain the code that runs, not the line
 * that mentions it.
 *
 * The default export is indexed too, under {@link DEFAULT_EXPORT_KEY}. A router
 * that imports a handler per file (`import remove from "./remove"`) is the
 * dominant Express layout, and an anonymous `export default async (req, res) =>
 * …` has no name for any other pattern here to find — so without this entry the
 * handler's whole body is invisible and the route reads as if it validated
 * nothing and checked nobody.
 */
export function declarationIndex(
  lines: readonly string[],
  structure: SourceStructure,
): Map<string, LineRange> {
  const found = new Map<string, LineRange>();
  let defaultAlias: string | undefined;
  for (let index = 0; index < lines.length; index += 1) {
    const text = lines[index] ?? "";
    if (!found.has(DEFAULT_EXPORT_KEY) && DEFAULT_EXPORT.test(text)) {
      const alias = DEFAULT_EXPORT_ALIAS.exec(text)?.[1];
      if (alias === undefined)
        found.set(DEFAULT_EXPORT_KEY, resolveBlock(lines, structure, index + 1));
      else defaultAlias ??= alias;
    }
    for (const pattern of DECLARATION_PATTERNS) {
      const match = pattern.exec(text);
      const name = match?.[1];
      if (name === undefined || found.has(name)) continue;
      found.set(name, resolveBlock(lines, structure, index + 1));
      break;
    }
  }
  // `export default handler` can precede or follow the declaration it names, so
  // the alias is resolved once the whole file has been indexed.
  const aliased = defaultAlias === undefined ? undefined : found.get(defaultAlias);
  if (aliased !== undefined && !found.has(DEFAULT_EXPORT_KEY)) {
    found.set(DEFAULT_EXPORT_KEY, aliased);
  }
  return found;
}

/**
 * The `{ a, b as c }` names of one import clause, in source order.
 *
 * A `type X` specifier is dropped by the identifier test, because the space
 * survives the trim — which is the wanted answer either way: a type-only import
 * is never the guard that runs.
 */
function importedNames(clause: string): string[] {
  const names: string[] = [];
  for (const part of clause.split(",")) {
    const name = part
      .split(/\s+as\s+/)
      .pop()
      ?.trim();
    if (name !== undefined && /^[A-Za-z_$][\w$]*$/.test(name)) names.push(name);
  }
  return names;
}

/**
 * The exports of one module that are themselves authentication checks.
 *
 * Each candidate is judged on *its own* body, not on the module's. A domain
 * module holds a guard next to a dozen functions that are not one —
 * `src/lib/marketplace.ts` exports `requireBusiness` beside
 * `deletePendingDeliveries` — and treating every export of it as a guard is how
 * `authCheck` ends up naming the first unrelated helper the handler happens to
 * call. That reads as "authenticated" on a handler nobody checked, which is the
 * one error worse than missing a guard.
 */
async function authenticatingExports(
  module: string,
  names: readonly string[],
  snapshot: RepoSnapshot,
): Promise<string[]> {
  const lines = await snapshot.lines(module);
  if (lines === undefined) return [];
  const structure = scanSource(lines);
  const declarations = declarationIndex(lines, structure);
  return names.filter((name) => {
    const range = declarations.get(name);
    if (range === undefined) return false;
    // For `function f() {` the declaration is the signature line, because the
    // block it opens starts on the next one; resolving from there is what gets
    // the body rather than just the return type.
    const body = resolveBlock(lines, structure, Math.min(range.startLine + 1, lines.length));
    const from = Math.min(range.startLine, body.startLine);
    const to = Math.max(range.endLine, body.endLine);
    return containsAuthCheck(lines.slice(from - 1, to).join("\n"));
  });
}

/**
 * The symbols a file imports that are authentication checks, so a project's own
 * guard is recognised by name even though Sentinel has never seen it before.
 *
 * Two things make a symbol count, and they are deliberately asymmetric.
 *
 * Phase 0's `auth-helper` list is the first: a file it proved holds the
 * project's check is a file whose *whole purpose* is authenticating, so every
 * symbol imported from it is taken as a guard. That is how a guard named after
 * nothing — `gate()` — is recognised at all.
 *
 * The second is why this is not enough. `requireBusiness()` is a guard whose
 * name is about a domain role rather than about identity, living in a domain
 * module beside functions that guard nothing, and reached through a tsconfig
 * alias. No name pattern matches it and its file is not the auth helper, so the
 * handler that calls it on its first line was reported as `authCheck: none` —
 * a fact the audit prompt then states as proven, two lines above source that
 * plainly contradicts it. For a module like that the *symbol* is judged, by
 * reading the body of the function it names.
 *
 * One hop, both ways: a function that merely calls a guard is not itself one.
 * That leaves handlers whose guard is two hops away reported as unchecked, which
 * is the conservative direction and the one the audit prompt can still recover
 * from by reading the source it was given.
 */
export async function importedGuards(
  lines: readonly string[],
  file: string,
  authHelpers: ReadonlySet<string>,
  snapshot: RepoSnapshot,
  aliases: readonly PathAlias[] = [],
): Promise<ReadonlySet<string>> {
  const guards = new Set<string>();
  // Matched over the whole source, not line by line: a named-import clause of
  // more than two or three symbols is formatted across lines by every formatter
  // in this ecosystem, and scanning one line at a time silently missed every one
  // of them — including the `requireBusiness` this function exists to catch.
  const source = lines.join("\n");
  const pattern = /import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g;
  let match = pattern.exec(source);
  while (match !== null) {
    const specifier = match[2];
    const clause = match[1] ?? "";
    match = pattern.exec(source);
    const resolved =
      specifier === undefined ? undefined : resolveImport(file, specifier, snapshot, aliases);
    if (resolved === undefined || resolved === file) continue;
    const names = importedNames(clause);
    if (names.length === 0) continue;
    const accepted = authHelpers.has(resolved)
      ? names
      : await authenticatingExports(resolved, names, snapshot);
    for (const name of accepted) guards.add(name);
  }
  return guards;
}

/** True when a file imports any of the packages, including their subpaths. */
export function importsAny(specifiers: ReadonlySet<string>, packages: readonly string[]): boolean {
  for (const specifier of specifiers) {
    for (const name of packages) {
      if (specifier === name || specifier.startsWith(`${name}/`)) return true;
    }
  }
  return false;
}

/** Extensions an import may resolve to, in the order a bundler tries them. */
const SOURCE_EXTENSIONS: readonly string[] = ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];

/** The repo-relative file a module path resolves to, trying each extension. */
function resolveModulePath(base: string, snapshot: RepoSnapshot): string | undefined {
  const withoutExtension = base.replace(/\.(m|c)?(j|t)sx?$/, "");
  const candidates = [
    base,
    ...SOURCE_EXTENSIONS.flatMap((extension) => [
      `${withoutExtension}.${extension}`,
      `${withoutExtension}/index.${extension}`,
    ]),
  ];
  return candidates.find((candidate) => snapshot.has(candidate));
}

/**
 * Resolves a relative import to a repo-relative file, so a handler can be told
 * that the guard it calls comes from a file phase 0 proved is an auth helper.
 */
export function resolveRelativeImport(
  fromFile: string,
  specifier: string,
  snapshot: RepoSnapshot,
): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  return resolveModulePath(
    posix.normalize(posix.join(posix.dirname(fromFile), specifier)),
    snapshot,
  );
}

/**
 * One `compilerOptions.paths` entry: the literal part before the `*`, and the
 * directories the `*` expands against.
 */
export interface PathAlias {
  /** `@/` for the mapping `"@/*": ["./src/*"]`. */
  readonly prefix: string;
  /** `src/`, repo-relative and slash-terminated. */
  readonly targets: readonly string[];
}

/** The part of a tsconfig this module reads; everything else in it is ignored. */
const TsconfigPathsSchema = z.object({
  compilerOptions: z
    .object({
      baseUrl: z.string().optional(),
      paths: z.record(z.string(), z.array(z.string())).optional(),
    })
    .optional(),
});

/** Strips comments and trailing commas, which `tsconfig.json` is allowed to carry. */
function stripJsonc(text: string): string {
  return text
    .replace(/"(?:[^"\\]|\\.)*"|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (match) =>
      match.startsWith('"') ? match : "",
    )
    .replace(/,(\s*[}\]])/g, "$1");
}

/**
 * The path aliases a tsconfig declares, as repo-relative prefixes.
 *
 * Without this the whole imported-guard mechanism is dead on any project that
 * imports through an alias — which is most Next.js codebases, where
 * `@/lib/auth` is the idiom and a relative path to it is the exception. A
 * malformed or absent tsconfig yields no aliases, which is exactly the previous
 * behaviour.
 *
 * Only the root-most tsconfigs are read, and only `paths`: resolving the full
 * TypeScript algorithm (`extends`, project references, `baseUrl` interactions)
 * is not worth it when every candidate is checked against the snapshot anyway,
 * so a wrong guess resolves to nothing rather than to the wrong file.
 */
export async function readPathAliases(snapshot: RepoSnapshot): Promise<PathAlias[]> {
  const configs = snapshot
    .filesMatching(/(^|\/)tsconfig(\.\w+)?\.json$/)
    .sort((left, right) => left.split("/").length - right.split("/").length)
    .slice(0, 4);
  const aliases: PathAlias[] = [];
  for (const config of configs) {
    const raw = await snapshot.read(config);
    if (raw === undefined) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(stripJsonc(raw));
    } catch {
      continue;
    }
    const result = TsconfigPathsSchema.safeParse(parsed);
    if (!result.success) continue;
    const paths = result.data.compilerOptions?.paths;
    if (paths === undefined) continue;
    // `baseUrl` is relative to the tsconfig, and so are the path targets; both
    // are folded into one repo-relative prefix here.
    const root = posix.dirname(config) === "." ? "" : `${posix.dirname(config)}/`;
    const base = result.data.compilerOptions?.baseUrl ?? ".";
    for (const [pattern, targets] of Object.entries(paths)) {
      const star = pattern.indexOf("*");
      if (star < 0) continue;
      const expanded = targets
        .filter((target) => target.includes("*"))
        .map((target) => {
          const literal = target.slice(0, target.indexOf("*"));
          return `${posix.normalize(`${root}${base}/${literal}`).replace(/^\.\//, "")}/`.replace(
            /\/+/g,
            "/",
          );
        });
      if (expanded.length > 0) {
        aliases.push({ prefix: pattern.slice(0, star), targets: expanded });
      }
    }
  }
  return aliases;
}

/**
 * Resolves any import — relative or through a tsconfig alias — to a
 * repo-relative file, or `undefined` when it leaves the repository.
 *
 * A bare specifier (`express`, `next/server`) resolves to nothing on purpose:
 * this exists to find the project's own modules, and a dependency's source is
 * not something the inventory reasons about.
 */
export function resolveImport(
  fromFile: string,
  specifier: string,
  snapshot: RepoSnapshot,
  aliases: readonly PathAlias[] = [],
): string | undefined {
  const relative = resolveRelativeImport(fromFile, specifier, snapshot);
  if (relative !== undefined) return relative;
  if (specifier.startsWith(".")) return undefined;
  for (const alias of aliases) {
    if (!specifier.startsWith(alias.prefix)) continue;
    const rest = specifier.slice(alias.prefix.length);
    for (const target of alias.targets) {
      const resolved = resolveModulePath(posix.normalize(`${target}${rest}`), snapshot);
      if (resolved !== undefined) return resolved;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** Normalises one path segment: a leading slash, no trailing slash, no doubles. */
export function normalisePath(value: string): string {
  const collapsed = `/${value.trim()}`.replace(/\/{2,}/g, "/");
  const trimmed = collapsed.length > 1 ? collapsed.replace(/\/+$/, "") : collapsed;
  return trimmed === "" ? "/" : trimmed;
}

/**
 * Joins a mount prefix to a route path.
 *
 * An unresolved segment poisons the whole path: half a path is worse than
 * saying the path is not known, because a reader would take it for the real
 * endpoint.
 */
export function joinPaths(...segments: ReadonlyArray<string | undefined>): string {
  const parts: string[] = [];
  for (const segment of segments) {
    if (segment === undefined) continue;
    if (segment === UNRESOLVED_PATH) return UNRESOLVED_PATH;
    const trimmed = segment.trim();
    if (trimmed === "" || trimmed === "/") continue;
    parts.push(trimmed.replace(/^\/+/, "").replace(/\/+$/, ""));
  }
  return parts.length === 0 ? "/" : normalisePath(parts.join("/"));
}

/** The literal path a registration argument carries, or `undefined` when it is dynamic. */
export function pathLiteral(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  const trimmed = text.trim();
  const quoted = /^(['"`])([\s\S]*)\1$/.exec(trimmed);
  if (quoted === null) return undefined;
  const body = quoted[2] ?? "";
  if (quoted[1] === "`" && body.includes("${")) return undefined;
  return body;
}

/** Parameter names a path template declares: `:id`, `[id]`, `[...slug]`, `{id}`. */
export function pathParameters(path: string | undefined): string[] {
  if (path === undefined || path === UNRESOLVED_PATH) return [];
  const names: string[] = [];
  const patterns = [
    /:([A-Za-z_$][\w$]*)/g,
    /\[\.{0,3}([A-Za-z_$][\w$]*)\]/g,
    /\{([A-Za-z_$][\w$]*)\}/g,
  ];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    let match = pattern.exec(path);
    while (match !== null) {
      const name = match[1];
      if (name !== undefined) names.push(name);
      match = pattern.exec(path);
    }
  }
  return names;
}

// ---------------------------------------------------------------------------
// Source helpers
// ---------------------------------------------------------------------------

/** The source text of a 1-based, inclusive line range. */
export function textOf(lines: readonly string[], from: number, to: number): string {
  return lines.slice(Math.max(0, from - 1), Math.min(lines.length, to)).join("\n");
}

/**
 * A matched call with its receiver removed, and the line the remainder starts on.
 *
 * `app.get("/a", one).post("/b", two)` matches twice, and the outer match's
 * text contains the inner one. Trimming the receiver is what stops the `POST`
 * unit from reading the `GET` handler's guard as its own.
 */
export function trimReceiver(
  text: string,
  receiver: string | undefined,
  line: number,
): { text: string; startLine: number } {
  if (receiver === undefined || receiver === "" || !text.startsWith(receiver)) {
    return { text, startLine: line };
  }
  const newlines = receiver.split("\n").length - 1;
  return { text: text.slice(receiver.length), startLine: line + newlines };
}

/** The base identifier of an expression: `router` in `router.route("/x")`. */
export function baseIdentifier(expression: string | undefined): string | undefined {
  if (expression === undefined) return undefined;
  const match = /^\s*([A-Za-z_$][\w$]*)/.exec(expression);
  return match?.[1];
}

/** A `file:line` citation, the shape the `authSource` attribute carries. */
export function citation(file: string, line: number): string {
  return `${file}:${line}`;
}

/** The 1-based line a substring falls on inside a range that starts at `startLine`. */
export function lineOfOffset(text: string, offset: number, startLine: number): number {
  let line = startLine;
  for (let index = 0; index < offset && index < text.length; index += 1) {
    if (text[index] === "\n") line += 1;
  }
  return line;
}

/**
 * What a handler's own source says about it: which object ids it reads, whether
 * it touches the request body, which guard (if any) runs before it, what
 * validates its input, whether it paginates, and whether it writes.
 *
 * These are *facts for the prompt*, not verdicts. Phase 4 decides whether a
 * missing ownership check is a finding; this module's job is to hand the model
 * — and the endpoint matrix — an honest summary of what is in the code, and to
 * say nothing at all when it cannot tell. `authCheck: "none"` is a claim
 * Sentinel is willing to make, because the handler's whole body was read;
 * `idParams` absent means no identifier looked like an object id, not that
 * nobody looked.
 *
 * The detectors are regular expressions over source *that has already been
 * located structurally*: ast-grep decided where the handler starts and ends,
 * so a match here is inside a body that really is a route handler, which is
 * what makes patterns this simple safe to use.
 */

import { brief, collapse } from "../_unit-support.ts";
import {
  AUTH_CALLS,
  AUTH_LIBRARY,
  AUTH_NULLARY,
  AUTH_SHAPED,
  AUTH_SUBJECTS,
} from "./_auth-patterns.ts";
import { citation, isMutatingMethod, pathParameters } from "./_shared.ts";

/** A stretch of source to inspect, with the line its first character sits on. */
export interface SourceRegion {
  readonly text: string;
  /** 1-based line of the region's first character. */
  readonly startLine: number;
  /**
   * Repo-relative file this region was read from, when it is not the file the
   * route was registered in.
   *
   * An Express router that points at an imported handler has its guard and its
   * schema in the *handler's* file, so a citation that assumed the registration
   * file would name the wrong one.
   */
  readonly file?: string | undefined;
}

/** Everything the detectors need about one handler. */
export interface HandlerInput {
  /** Repo-relative POSIX path, for the `authSource` citation. */
  readonly file: string;
  /** The handler body, plus anything that guards it from outside: middleware, decorators. */
  readonly regions: readonly SourceRegion[];
  /** Upper-case HTTP method, when the registration named one. */
  readonly method?: string | undefined;
  /** The route path template, which is where most id parameters are declared. */
  readonly path?: string | undefined;
  /** Symbols imported from a file phase 0 proved contains an authentication check. */
  readonly guards?: ReadonlySet<string> | undefined;
  /** Forces `readsBody`, for a shape the body itself does not show (a tRPC mutation input). */
  readonly readsBody?: boolean | undefined;
}

/** What the handler's source proves about it. */
export interface HandlerFacts {
  /** Comma-separated object-id parameters, or absent when there are none. */
  readonly idParams?: string | undefined;
  readonly readsBody: string;
  /** The guard call that was found, or `"none"` when the body contains no check. */
  readonly authCheck: string;
  /** `file:line` of the guard, absent when there is none. */
  readonly authSource?: string | undefined;
  /** The cross-enumerator form of the same fact: `yes` or `no`. */
  readonly authenticated: string;
  /** The schema applied to the input, or `"none"`. */
  readonly validation: string;
  /** `limit`, `cursor` or `none`. */
  readonly pagination: string;
  /** `true` when the method or the body changes state. */
  readonly mutates: string;
}

/** One detector hit: what matched, the line it matched on, and the file it came from. */
interface Hit {
  readonly text: string;
  readonly line: number;
  /** The region's file, when the region named one. */
  readonly file?: string | undefined;
}

/** The 1-based line an offset inside a region falls on. */
function lineAt(region: SourceRegion, offset: number): number {
  let line = region.startLine;
  const limit = Math.min(offset, region.text.length);
  for (let index = 0; index < limit; index += 1) {
    if (region.text[index] === "\n") line += 1;
  }
  return line;
}

/** The first match of a pattern across the regions, in the order they were given. */
function firstHit(
  regions: readonly SourceRegion[],
  pattern: RegExp,
  accept: (match: RegExpExecArray) => string | undefined = (match) => match[0],
): Hit | undefined {
  for (const region of regions) {
    pattern.lastIndex = 0;
    let match = pattern.exec(region.text);
    while (match !== null) {
      const text = accept(match);
      if (text !== undefined) {
        return {
          text: collapse(text),
          line: lineAt(region, match.index),
          ...(region.file === undefined ? {} : { file: region.file }),
        };
      }
      if (!pattern.global) break;
      match = pattern.exec(region.text);
    }
  }
  return undefined;
}

/** Every capture of a global pattern across the regions. */
function allCaptures(regions: readonly SourceRegion[], pattern: RegExp, group = 1): string[] {
  const found: string[] = [];
  for (const region of regions) {
    pattern.lastIndex = 0;
    let match = pattern.exec(region.text);
    while (match !== null) {
      const value = match[group];
      if (value !== undefined) found.push(value);
      match = pattern.exec(region.text);
    }
  }
  return found;
}

// ---------------------------------------------------------------------------
// Object ids
// ---------------------------------------------------------------------------

/** Names that are an object identifier on their own. */
const BARE_ID_NAMES: ReadonlySet<string> = new Set(["id", "uuid", "guid", "slug"]);

/** `userId`, `postIds`, `orgID`, `tenantUuid` — an id behind a camel-case boundary. */
const CAMEL_ID = /[a-z0-9](?:Id|Ids|ID|IDs|Uuid|UUID|Guid|GUID|Slug)$/;

/** `user_id`, `post_uuid` — an id behind a snake-case boundary. */
const SNAKE_ID = /_(?:id|ids|uuid|guid|slug)$/i;

/**
 * True when a parameter name identifies an object.
 *
 * Deliberately conservative about boundaries: `valid` and `grid` end in "id"
 * and identify nothing, so a bare suffix is never enough — the name is either
 * an id word on its own, or the suffix sits behind a case or underscore break.
 */
export function looksLikeObjectId(name: string): boolean {
  const trimmed = name.trim();
  // A route path read out of a registration argument is not a parameter name.
  if (!/^[A-Za-z_$][\w$]*$/.test(trimmed)) return false;
  if (BARE_ID_NAMES.has(trimmed.toLowerCase())) return true;
  return CAMEL_ID.test(trimmed) || SNAKE_ID.test(trimmed);
}

/** Reads of a named member off a request container: `params.userId`, `body.orgId`. */
const MEMBER_READ = /\b(?:params|query|body|input|dto|payload|searchParams)\.([A-Za-z_$][\w$]*)/g;

/** Keyed reads: `searchParams.get("orgId")`, `c.req.param("postId")`. */
const KEYED_READ = /\.(?:get|param|query|getAll)\s*\(\s*['"]([^'"]+)['"]/g;

/** Destructuring a request container: `const { id, orgId } = req.params`. */
const DESTRUCTURED =
  /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?[\w$.]*\b(?:params|query|body|input|dto|payload|searchParams)\b/g;

/** Nest parameter decorators, which name the parameter they bind. */
const PARAM_DECORATOR = /@(?:Param|Query)\s*\(\s*(?:['"]([^'"]+)['"])?\s*\)\s*([A-Za-z_$][\w$]*)?/g;

/** The object-id parameters a handler reads, from its path and from its body. */
export function objectIdParameters(input: HandlerInput): string[] {
  const names = new Set<string>(pathParameters(input.path));
  for (const name of allCaptures(input.regions, MEMBER_READ)) names.add(name);
  for (const name of allCaptures(input.regions, KEYED_READ)) names.add(name);
  for (const group of allCaptures(input.regions, DESTRUCTURED)) {
    for (const part of group.split(",")) {
      // `const { id: userId }` binds `userId` but reads `id`; both are the same id.
      const name = part.split(":")[0]?.replace(/\.{3}/, "").trim();
      if (name !== undefined && name !== "") names.add(name);
    }
  }
  for (const region of [...input.regions]) {
    PARAM_DECORATOR.lastIndex = 0;
    let match = PARAM_DECORATOR.exec(region.text);
    while (match !== null) {
      const named = match[1] ?? match[2];
      if (named !== undefined) names.add(named);
      match = PARAM_DECORATOR.exec(region.text);
    }
  }
  return [...names].filter(looksLikeObjectId).sort();
}

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

/** Ways a handler reaches the request body. */
const BODY_READS: readonly RegExp[] = [
  // `ctx.body = …` is Koa writing the *response*; only a read counts.
  /\b(?:req|request|ctx|context|c|event)\s*\.\s*body\b(?!\s*=[^=])/,
  /\b(?:req|request|c\.req|ctx\.request|context\.req)\s*\.\s*(?:json|text|formData|arrayBuffer|blob)\s*\(\s*\)/,
  /\bawait\s+(?:request|req)\s*\.\s*(?:json|text|formData)\s*\(/,
  /@Body\s*\(/,
  /\bgetRequestBody\s*\(/,
  /\breadBody\s*\(/,
];

/** True when the handler reads the request body at all. */
export function readsRequestBody(input: HandlerInput): boolean {
  if (input.readsBody === true) return true;
  return BODY_READS.some((pattern) => firstHit(input.regions, pattern) !== undefined);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/** Renders a detected guard as a call, so `requireUser(` never reaches a report. */
export function guardLabel(text: string): string {
  const trimmed = collapse(text);
  return trimmed.endsWith("(") ? `${trimmed.slice(0, -1).trim()}()` : trimmed;
}

/** The guard that runs for this handler, if any, and where it is. */
export function authenticationCheck(input: HandlerInput): Hit | undefined {
  for (const pattern of AUTH_LIBRARY) {
    const hit = firstHit(input.regions, pattern);
    if (hit !== undefined) return hit;
  }
  const explicit = firstHit(input.regions, AUTH_CALLS);
  if (explicit !== undefined) return explicit;
  const nullary = firstHit(input.regions, AUTH_NULLARY);
  if (nullary !== undefined) return nullary;
  const shaped = firstHit(input.regions, AUTH_SHAPED, (match) =>
    match[1] !== undefined && AUTH_SUBJECTS.test(match[1]) ? match[0] : undefined,
  );
  if (shaped !== undefined) return shaped;
  const guards = input.guards;
  if (guards !== undefined && guards.size > 0) {
    const names = [...guards].sort();
    const pattern = new RegExp(`\\b(${names.map(escapeForPattern).join("|")})\\b`);
    const imported = firstHit(input.regions, pattern);
    if (imported !== undefined) return imported;
  }
  return undefined;
}

/** Escapes a symbol name for inclusion in a generated pattern. */
function escapeForPattern(name: string): string {
  return name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Receivers whose `.parse` has nothing to do with validating a request. */
const NOT_SCHEMAS: ReadonlySet<string> = new Set([
  "JSON",
  "JSON5",
  "Number",
  "Date",
  "Math",
  "URL",
  "qs",
  "querystring",
  "path",
  "yaml",
  "YAML",
  "toml",
  "semver",
  "url",
]);

/** Schema methods that validate a value and hand it back. */
const SCHEMA_CALL =
  /\.\s*(?:safeParseAsync|safeParse|parseAsync|parse|validateSync|validateAsync|validate|assert|check)\s*\(/g;

/** valibot's functional form: `parse(Schema, input)`. */
const FUNCTIONAL_SCHEMA = /\b(?:v\.)?(?:safeParse|parse)\s*\(\s*([A-Za-z_$][\w$.]*)\s*,/;

/** tRPC and Nest declare their validation as part of the route definition. */
const DECLARED_SCHEMA = /\.\s*(?:input|output)\s*\(/g;

/** The expression a `.parse(` call is made on: `UpdateUser`, `z.object({ … })`. */
export function receiverBefore(text: string, dotIndex: number): string | undefined {
  let end = dotIndex;
  while (end > 0 && /\s/.test(text[end - 1] ?? "")) end -= 1;
  let start = end;
  if (text[end - 1] === ")") {
    let depth = 0;
    let index = end - 1;
    for (; index >= 0; index -= 1) {
      const char = text[index];
      if (char === ")") depth += 1;
      else if (char === "(") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    start = Math.max(0, index);
    while (start > 0 && /[\w$.[\]]/.test(text[start - 1] ?? "")) start -= 1;
  } else {
    while (start > 0 && /[\w$.[\]'"]/.test(text[start - 1] ?? "")) start -= 1;
  }
  const receiver = text.slice(start, end).trim();
  return receiver === "" ? undefined : receiver;
}

/** The schema applied to this handler's input, or `undefined` when there is none. */
export function inputValidation(input: HandlerInput): Hit | undefined {
  for (const region of input.regions) {
    SCHEMA_CALL.lastIndex = 0;
    let match = SCHEMA_CALL.exec(region.text);
    while (match !== null) {
      const receiver = receiverBefore(region.text, match.index);
      const base = receiver?.split(/[.(]/)[0] ?? "";
      if (receiver !== undefined && !NOT_SCHEMAS.has(base)) {
        return { text: brief(receiver), line: lineAt(region, match.index) };
      }
      match = SCHEMA_CALL.exec(region.text);
    }
  }
  const functional = firstHit(input.regions, FUNCTIONAL_SCHEMA, (match) => match[1]);
  if (functional !== undefined) return functional;
  for (const region of input.regions) {
    DECLARED_SCHEMA.lastIndex = 0;
    const declared = DECLARED_SCHEMA.exec(region.text);
    if (declared === null) continue;
    const argument = balancedArgument(region.text, declared.index + declared[0].length - 1);
    if (argument !== undefined) {
      return { text: brief(argument), line: lineAt(region, declared.index) };
    }
  }
  return undefined;
}

/**
 * The argument list of a call, read from its opening parenthesis to the one
 * that closes it, so a schema is never reported cut in half.
 */
export function balancedArgument(text: string, openIndex: number): string | undefined {
  if (text[openIndex] !== "(") return undefined;
  let depth = 0;
  let quote: string | null = null;
  for (let index = openIndex; index < text.length; index += 1) {
    const char = text[index] ?? "";
    if (quote !== null) {
      if (char === "\\") index += 1;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      quote = char;
      continue;
    }
    if (char === "(" || char === "[" || char === "{") depth += 1;
    else if (char === ")" || char === "]" || char === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(openIndex + 1, index).trim();
    }
  }
  return undefined;
}

/**
 * True when a name passed as middleware is a guard.
 *
 * Middleware is a *reference*, not a call, so the body scan cannot see it:
 * `router.get("/x", requireUser, handler)` is the whole check.
 */
export function looksLikeGuardName(name: string): boolean {
  if (name === "") return false;
  if (/auth/i.test(name)) return true;
  return (
    AUTH_SUBJECTS.test(name) &&
    /^(require|ensure|assert|check|verify|validate|guard|is|has|with|protect|only)/i.test(name)
  );
}

// ---------------------------------------------------------------------------
// Pagination and writes
// ---------------------------------------------------------------------------

/** Keyset pagination, which is the one that survives a large table. */
const CURSOR_PAGINATION =
  /\b(?:cursor|after|before|startAfter|startingAfter|pageToken|nextToken|continuationToken)\b/;

/** Offset or limit pagination, including every ORM's spelling of it. */
const LIMIT_PAGINATION =
  /\b(?:limit|take|first|last|perPage|per_page|pageSize|page_size|offset|skip|page)\b/;

/** How the handler bounds the rows it returns. */
export function paginationStyle(input: HandlerInput): string {
  if (firstHit(input.regions, CURSOR_PAGINATION) !== undefined) return "cursor";
  if (firstHit(input.regions, LIMIT_PAGINATION) !== undefined) return "limit";
  return "none";
}

/** Calls that change stored state, across the ORMs and drivers v1 supports. */
const WRITE_CALLS =
  /\.\s*(?:create|createMany|createManyAndReturn|update|updateMany|updateOne|upsert|delete|deleteMany|deleteOne|destroy|save|insert|insertInto|insertMany|findOneAndUpdate|findOneAndDelete|replaceOne|bulkWrite|increment|decrement)\s*\(/;

/** Raw SQL that writes. */
const WRITE_SQL = /\b(?:INSERT\s+INTO|UPDATE\s+[\w."`]+\s+SET|DELETE\s+FROM|TRUNCATE\s+TABLE)\b/i;

/** True when the method or the body changes stored state. */
export function changesState(input: HandlerInput): boolean {
  if (isMutatingMethod(input.method)) return true;
  if (firstHit(input.regions, WRITE_CALLS) !== undefined) return true;
  return firstHit(input.regions, WRITE_SQL) !== undefined;
}

// ---------------------------------------------------------------------------
// The whole picture
// ---------------------------------------------------------------------------

/** Reads every fact the audit prompt and the endpoint matrix need from a handler. */
export function readHandler(input: HandlerInput): HandlerFacts {
  const ids = objectIdParameters(input);
  const auth = authenticationCheck(input);
  const validation = inputValidation(input);
  return {
    ...(ids.length === 0 ? {} : { idParams: ids.join(",") }),
    readsBody: readsRequestBody(input) ? "true" : "false",
    authCheck: auth === undefined ? "none" : brief(guardLabel(auth.text)),
    ...(auth === undefined ? {} : { authSource: citation(auth.file ?? input.file, auth.line) }),
    authenticated: auth === undefined ? "no" : "yes",
    validation: validation === undefined ? "none" : validation.text,
    pagination: paginationStyle(input),
    mutates: changesState(input) ? "true" : "false",
  };
}

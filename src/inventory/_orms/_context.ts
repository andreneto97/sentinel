/**
 * The context a data-access call sits in: which function encloses it, whether
 * a loop repeats it, whether a transaction wraps it, and which of its siblings
 * it waits for.
 *
 * Every one of these is an ast-grep query over node kinds plus a containment
 * test on byte ranges — no regular expression decides where a block begins.
 * The names (a function's, a class's) are read out of the matched node's own
 * header, which is the one place a pattern is cheaper than a second query.
 */

import type { AstMatch, AstRule } from "./_ast.ts";
import { contains, width } from "./_ast.ts";

/** Rule ids the context pass emits; the extractors never see these. */
export const CONTEXT_RULE_IDS = {
  functionDeclaration: "ctx.fn.declaration",
  functionMethod: "ctx.fn.method",
  functionVariable: "ctx.fn.variable",
  functionProperty: "ctx.fn.property",
  class: "ctx.class",
  loopFor: "ctx.loop.for",
  loopWhile: "ctx.loop.while",
  loopMap: "ctx.loop.map",
  loopForEach: "ctx.loop.forEach",
  transaction: "ctx.transaction",
  block: "ctx.block",
  statement: "ctx.statement",
  await: "ctx.await",
  import: "ctx.import",
} as const;

/** Methods whose callback body runs once per row — the N+1 shape. */
const ITERATOR_METHODS = "^(map|flatMap)$";
const FOREACH_METHODS = "^(forEach)$";

/**
 * Methods that open a transaction and run the work inside their callback.
 * `$transaction` is Prisma's, `withTransaction` MongoDB's session helper,
 * `transaction` is shared by Knex, Sequelize, Drizzle and TypeORM.
 */
const TRANSACTION_METHODS =
  "^(transaction|\\$transaction|withTransaction|runTransaction|inTransaction|transactional)$";

/** Matches the argument list of a call whose method name matches `property`. */
function argumentsOfCall(property: string): Record<string, unknown> {
  return {
    kind: "arguments",
    inside: {
      kind: "call_expression",
      has: {
        field: "function",
        kind: "member_expression",
        has: { field: "property", regex: property },
      },
    },
  };
}

/**
 * The context queries, run once alongside the data-access anchors.
 *
 * The loop and transaction rules match the *argument list*, not the whole
 * call: in `(await db.select()).map(row => ...)` the receiver is evaluated
 * once, so only what sits inside the callback is repeated.
 */
export const CONTEXT_RULES: readonly AstRule[] = [
  {
    id: CONTEXT_RULE_IDS.functionDeclaration,
    rule: {
      any: [
        { kind: "function_declaration" },
        { kind: "generator_function_declaration" },
        { kind: "function_expression" },
      ],
    },
  },
  { id: CONTEXT_RULE_IDS.functionMethod, rule: { kind: "method_definition" } },
  {
    id: CONTEXT_RULE_IDS.functionVariable,
    rule: {
      kind: "variable_declarator",
      has: {
        field: "value",
        any: [{ kind: "arrow_function" }, { kind: "function_expression" }],
      },
    },
  },
  {
    id: CONTEXT_RULE_IDS.functionProperty,
    rule: {
      kind: "pair",
      has: {
        field: "value",
        any: [{ kind: "arrow_function" }, { kind: "function_expression" }],
      },
    },
  },
  {
    id: CONTEXT_RULE_IDS.class,
    rule: { any: [{ kind: "class_declaration" }, { kind: "class" }] },
  },
  {
    id: CONTEXT_RULE_IDS.loopFor,
    rule: { any: [{ kind: "for_statement" }, { kind: "for_in_statement" }] },
  },
  {
    id: CONTEXT_RULE_IDS.loopWhile,
    rule: { any: [{ kind: "while_statement" }, { kind: "do_statement" }] },
  },
  { id: CONTEXT_RULE_IDS.loopMap, rule: argumentsOfCall(ITERATOR_METHODS) },
  { id: CONTEXT_RULE_IDS.loopForEach, rule: argumentsOfCall(FOREACH_METHODS) },
  { id: CONTEXT_RULE_IDS.transaction, rule: argumentsOfCall(TRANSACTION_METHODS) },
  { id: CONTEXT_RULE_IDS.block, rule: { kind: "statement_block" } },
  {
    id: CONTEXT_RULE_IDS.statement,
    rule: {
      any: [
        { kind: "expression_statement" },
        { kind: "lexical_declaration" },
        { kind: "variable_declaration" },
        { kind: "return_statement" },
      ],
    },
  },
  { id: CONTEXT_RULE_IDS.await, rule: { kind: "await_expression" } },
  {
    id: CONTEXT_RULE_IDS.import,
    rule: { any: [{ kind: "import_statement" }, { pattern: "require($SOURCE)" }] },
  },
];

/** The module specifier an import or a `require` names. */
export function importSpecifier(text: string): string {
  return (
    /(?:^|\s)from\s*["'`]([^"'`]+)["'`]/.exec(text)?.[1] ??
    /^\s*import\s*["'`]([^"'`]+)["'`]/.exec(text)?.[1] ??
    /require\(\s*["'`]([^"'`]+)["'`]\s*\)/.exec(text)?.[1] ??
    ""
  );
}

/** Every module specifier each file imports, so an ambiguous call can be attributed. */
export function buildFileImports(matches: readonly AstMatch[]): Map<string, Set<string>> {
  const imports = new Map<string, Set<string>>();
  for (const match of matches) {
    if (match.ruleId !== CONTEXT_RULE_IDS.import) continue;
    const specifier = match.meta.SOURCE ?? importSpecifier(match.text);
    const cleaned = specifier.replace(/^["'`]|["'`]$/g, "");
    if (cleaned === "") continue;
    const existing = imports.get(match.file);
    if (existing === undefined) imports.set(match.file, new Set([cleaned]));
    else existing.add(cleaned);
  }
  return imports;
}

/** What repeats a call site; `false` is spelled out because it reaches the report. */
export type LoopKind = "for" | "while" | "map" | "forEach" | "false";

/** A byte range in one file, as ast-grep reported it. */
export interface Range {
  readonly startByte: number;
  readonly endByte: number;
  readonly startLine: number;
  readonly endLine: number;
}

/** A range that carries the name of what it declares. */
export interface NamedRange extends Range {
  readonly name: string;
}

/** Everything the attribute builders need to know about one file's structure. */
export interface FileContext {
  readonly functions: readonly NamedRange[];
  readonly classes: readonly NamedRange[];
  readonly loops: ReadonlyArray<Range & { readonly kind: LoopKind }>;
  readonly transactions: readonly Range[];
  readonly blocks: readonly Range[];
  readonly statements: readonly Range[];
  readonly awaits: readonly Range[];
}

/** An empty context, for a file in which nothing structural matched. */
export function emptyFileContext(): FileContext {
  return {
    functions: [],
    classes: [],
    loops: [],
    transactions: [],
    blocks: [],
    statements: [],
    awaits: [],
  };
}

function toRange(match: AstMatch): Range {
  return {
    startByte: match.startByte,
    endByte: match.endByte,
    startLine: match.startLine,
    endLine: match.endLine,
  };
}

/** The name a `function`/`function*` header declares. */
export function declarationName(text: string): string {
  return /function\s*\*?\s*([A-Za-z_$][\w$]*)/.exec(text)?.[1] ?? "";
}

/** The name a class or object method declares, past its modifiers. */
export function methodName(text: string): string {
  const match =
    /^(?:(?:public|private|protected|static|async|get|set|override|abstract|readonly)\s+)*\*?\s*(?:(["'])([^"']+)\1|([A-Za-z_$#][\w$]*))\s*[(<]/.exec(
      text.trim(),
    );
  return match?.[2] ?? match?.[3] ?? "";
}

/** The name a `const x = () => {}` declarator binds. */
export function declaratorName(text: string): string {
  return /^([A-Za-z_$][\w$]*)/.exec(text.trim())?.[1] ?? "";
}

/** The key an object property binds a function to. */
export function propertyName(text: string): string {
  return /^(["']?)([A-Za-z_$][\w$]*)\1\s*:/.exec(text.trim())?.[2] ?? "";
}

/** The name a class declaration introduces. */
export function className(text: string): string {
  return /class\s+([A-Za-z_$][\w$]*)/.exec(text.trim())?.[1] ?? "";
}

/** Groups the context matches of one ast-grep pass into a per-file index. */
export function buildFileContexts(matches: readonly AstMatch[]): Map<string, FileContext> {
  const contexts = new Map<
    string,
    {
      functions: NamedRange[];
      classes: NamedRange[];
      loops: Array<Range & { kind: LoopKind }>;
      transactions: Range[];
      blocks: Range[];
      statements: Range[];
      awaits: Range[];
    }
  >();
  const of = (file: string) => {
    const existing = contexts.get(file);
    if (existing !== undefined) return existing;
    const created = {
      functions: [] as NamedRange[],
      classes: [] as NamedRange[],
      loops: [] as Array<Range & { kind: LoopKind }>,
      transactions: [] as Range[],
      blocks: [] as Range[],
      statements: [] as Range[],
      awaits: [] as Range[],
    };
    contexts.set(file, created);
    return created;
  };

  for (const match of matches) {
    const range = toRange(match);
    switch (match.ruleId) {
      case CONTEXT_RULE_IDS.functionDeclaration:
        of(match.file).functions.push({ ...range, name: declarationName(match.text) });
        break;
      case CONTEXT_RULE_IDS.functionMethod:
        of(match.file).functions.push({ ...range, name: methodName(match.text) });
        break;
      case CONTEXT_RULE_IDS.functionVariable:
        of(match.file).functions.push({ ...range, name: declaratorName(match.text) });
        break;
      case CONTEXT_RULE_IDS.functionProperty:
        of(match.file).functions.push({ ...range, name: propertyName(match.text) });
        break;
      case CONTEXT_RULE_IDS.class:
        of(match.file).classes.push({ ...range, name: className(match.text) });
        break;
      case CONTEXT_RULE_IDS.loopFor:
        of(match.file).loops.push({ ...range, kind: "for" });
        break;
      case CONTEXT_RULE_IDS.loopWhile:
        of(match.file).loops.push({ ...range, kind: "while" });
        break;
      case CONTEXT_RULE_IDS.loopMap:
        of(match.file).loops.push({ ...range, kind: "map" });
        break;
      case CONTEXT_RULE_IDS.loopForEach:
        of(match.file).loops.push({ ...range, kind: "forEach" });
        break;
      case CONTEXT_RULE_IDS.transaction:
        of(match.file).transactions.push(range);
        break;
      case CONTEXT_RULE_IDS.block:
        of(match.file).blocks.push(range);
        break;
      case CONTEXT_RULE_IDS.statement:
        of(match.file).statements.push(range);
        break;
      case CONTEXT_RULE_IDS.await:
        of(match.file).awaits.push(range);
        break;
      default:
        break;
    }
  }

  const result = new Map<string, FileContext>();
  for (const [file, groups] of contexts) result.set(file, groups);
  return result;
}

/** The narrowest range in `candidates` that contains `inner`, if any. */
export function innermostContaining<T extends Range>(
  candidates: readonly T[],
  inner: Range,
): T | undefined {
  let best: T | undefined;
  for (const candidate of candidates) {
    if (!contains(candidate, inner)) continue;
    if (best === undefined || width(candidate) < width(best)) best = candidate;
  }
  return best;
}

/** The widest range in `candidates` that contains `inner`, if any. */
export function widestContaining<T extends Range>(
  candidates: readonly T[],
  inner: Range,
): T | undefined {
  let best: T | undefined;
  for (const candidate of candidates) {
    if (!contains(candidate, inner)) continue;
    if (best === undefined || width(candidate) > width(best)) best = candidate;
  }
  return best;
}

/** Fallback symbol for a call that sits at the top level of a module. */
export const MODULE_SCOPE = "module";

/**
 * The function a call site belongs to, qualified by its class when it is a
 * method: `UsersService.findAll`. Anonymous callbacks inherit the nearest
 * named function, which is what a reader needs to locate the code.
 */
export function enclosingSymbol(context: FileContext, range: Range): string {
  const named = context.functions.filter((candidate) => candidate.name !== "");
  const fn = innermostContaining(named, range);
  if (fn === undefined) {
    const owner = innermostContaining(context.classes, range);
    return owner === undefined || owner.name === "" ? MODULE_SCOPE : owner.name;
  }
  const owner = innermostContaining(context.classes, fn);
  return owner === undefined || owner.name === "" ? fn.name : `${owner.name}.${fn.name}`;
}

/** The innermost loop repeating a call site, or `"false"` when nothing does. */
export function loopKind(context: FileContext, range: Range): LoopKind {
  return innermostContaining(context.loops, range)?.kind ?? "false";
}

/** True when the call site runs inside a transaction callback. */
export function insideTransaction(context: FileContext, range: Range): boolean {
  return innermostContaining(context.transactions, range) !== undefined;
}

/** The block a call site executes in; `undefined` at module top level. */
export function enclosingBlock(context: FileContext, range: Range): Range | undefined {
  return innermostContaining(context.blocks, range);
}

/** The whole statement a call site belongs to, within its block. */
export function enclosingStatement(context: FileContext, range: Range): Range | undefined {
  const block = enclosingBlock(context, range);
  const candidates =
    block === undefined
      ? context.statements
      : context.statements.filter((statement) => contains(block, statement));
  return widestContaining(candidates, range);
}

/** Tolerance in bytes between a chain's end and its `await`'s, for `!` or a cast. */
const AWAIT_SLACK = 2;

/**
 * True when `await` applies to this call and nothing else.
 *
 * The distinction matters: the calls inside `await Promise.all([a, b])` are
 * concurrent, and reporting them as sequential awaits would invent a batching
 * problem that does not exist.
 */
export function isDirectlyAwaited(context: FileContext, range: Range): boolean {
  return context.awaits.some(
    (await_) =>
      contains(await_, range) &&
      await_.endByte >= range.endByte &&
      await_.endByte - range.endByte <= AWAIT_SLACK,
  );
}

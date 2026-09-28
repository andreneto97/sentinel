/**
 * **Provenance of the expressions a pattern rule found inside a statement.**
 *
 * A pattern can see that a template was interpolated into a query. It cannot
 * see the difference between
 *
 * ```ts
 * `SELECT id FROM "${table}"`        // table: 'users' | 'purchases' | ...
 * `SELECT id FROM "${req.query.t}"`  // whatever the caller sent
 * ```
 *
 * and shipping both as `critical` is what makes a reader stop trusting the
 * report. This module answers, for one matched call, where each interpolated
 * expression comes from, and what that means for the finding's severity and
 * confidence.
 *
 * It reads **one file** — the file the match is in — parsed with the TypeScript
 * compiler API with no type checker, no `Program` and no module resolution. So
 * every answer is cheap, deterministic, and explainable in one sentence that
 * names the declaration it resolved to. What it cannot see it says it cannot
 * see: a value that arrives from another module is `unresolved`, never assumed
 * safe.
 *
 * The four verdicts, and what each one does to a finding:
 *
 * | class | what it means | severity | confidence | id |
 * |---|---|---|---|---|
 * | `closed` | every interpolated expression resolves to a value the code fixes | `info` | high | P1 |
 * | `config` | the only open parts are deploy-time configuration | capped at `low` | low | P2 |
 * | `unresolved` | at least one part is not resolvable in this file | capped at `medium` | low | P3 |
 * | `reachable` | a part is read from the request object | untouched | high | P4 |
 *
 * And one context rule on top:
 *
 * - **P5** — a statement in a class implementing TypeORM's `MigrationInterface`
 *   is capped at `low`, and at `info` inside `down()`. Migrations run from a
 *   migration command by whoever holds the deployment credentials; there is no
 *   HTTP, queue or CLI-argument path into them, and `down()` runs only on an
 *   explicit manual revert. P5 never applies to a `reachable` verdict — if a
 *   request value really does reach a migration, that is the finding.
 *
 * Nothing here deletes a finding. The most a `closed` verdict does is restate
 * it as `info` with the provenance spelled out, so a future edit that makes the
 * value dynamic shows up as a change rather than as a new alarm.
 */

import * as ts from "typescript";
import type { Confidence, Severity } from "../contracts/findings.ts";
import { severityRank } from "./severity.ts";

/** How many resolution steps Sentinel follows before it reports "unresolved". */
export const MAX_DEPTH = 8;

/** Parts named in the rendered sentence before it switches to a count. */
const MAX_PARTS_NAMED = 4;

/** Expression text longer than this is clipped in the sentence. */
const MAX_TEXT = 80;

/** A file larger than this is not parsed: it is a bundle, not hand-written code. */
export const MAX_FILE_BYTES = 2_000_000;

// ---------------------------------------------------------------------------
// What a part can be
// ---------------------------------------------------------------------------

/** What an interpolated expression turned out to be. */
export type ProvenanceKind =
  /** A literal written at the interpolation site. */
  | "literal"
  /** A `const` bound to a literal, never reassigned. */
  | "constant"
  /** A declared type that is a closed set of literals (union, `as const`, `z.enum`). */
  | "closed-union"
  /** A member of a TypeScript `enum`. */
  | "enum-member"
  /** The binding of a `for...of` over an array literal of literals. */
  | "loop-literal"
  /** A numeric coercion, or a `number`-typed binding. */
  | "numeric"
  /** `.map(...).join(...)` over a frozen tuple of literals. */
  | "frozen-tuple"
  /** A field of a module imported for configuration, or `process.env.*`. */
  | "config"
  /** A function parameter this file does not constrain. */
  | "parameter"
  /** Anything this file cannot resolve. */
  | "unresolved"
  /** Read from the request object. */
  | "request-input";

/** The verdict a part carries. Ordered from safest to worst. */
export type ProvenanceClass = "closed" | "config" | "unresolved" | "reachable";

const CLASS_ORDER: readonly ProvenanceClass[] = ["closed", "config", "unresolved", "reachable"];

/** The worse of two verdicts; the verdict of a whole statement is the worst of its parts. */
export function worseClass(left: ProvenanceClass, right: ProvenanceClass): ProvenanceClass {
  return CLASS_ORDER.indexOf(left) >= CLASS_ORDER.indexOf(right) ? left : right;
}

/** Which verdict each kind carries on its own. */
const KIND_CLASS: Readonly<Record<ProvenanceKind, ProvenanceClass>> = {
  literal: "closed",
  constant: "closed",
  "closed-union": "closed",
  "enum-member": "closed",
  "loop-literal": "closed",
  numeric: "closed",
  "frozen-tuple": "closed",
  config: "config",
  parameter: "unresolved",
  unresolved: "unresolved",
  "request-input": "reachable",
};

/** What one expression resolved to, and the path that got there. */
export interface Provenance {
  readonly kind: ProvenanceKind;
  readonly klass: ProvenanceClass;
  /** A noun phrase naming what the expression resolves to. */
  readonly why: string;
  /** The declarations crossed on the way, outermost first. */
  readonly via?: readonly string[] | undefined;
}

/** One interpolated expression of the matched statement. */
export interface InterpolatedPart extends Provenance {
  /** The expression's source text, whitespace collapsed and clipped. */
  readonly text: string;
  /** 1-based line the expression sits on. */
  readonly line: number;
}

// ---------------------------------------------------------------------------
// Execution context
// ---------------------------------------------------------------------------

/** What runs the code the match sits in. */
export type ExecutionContextKind =
  | "migration-up"
  | "migration-down"
  | "request-handler"
  | "unknown";

/** The context, with the sentence that argues for it. */
export interface ExecutionContext {
  readonly kind: ExecutionContextKind;
  /** The enclosing function or method name; part of the dedup key. */
  readonly symbol: string | null;
  /** A noun phrase naming what executes this line; `""` when nothing is known. */
  readonly detail: string;
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/** A match Sentinel resolved. */
export interface ProvenanceVerdict {
  readonly analysed: true;
  readonly klass: ProvenanceClass;
  /** Every distinct interpolated expression of the statement. */
  readonly parts: readonly InterpolatedPart[];
  readonly context: ExecutionContext;
  /**
   * Identity of the interpolation: the enclosing function plus the set of
   * interpolated expressions. Two sinks in one loop fed by one variable share
   * it, which is what lets the runner report them once.
   */
  readonly signature: string;
}

/** A match Sentinel left exactly as the rule reported it, and why. */
export interface ProvenanceSkipped {
  readonly analysed: false;
  readonly reason: string;
}

export type ProvenanceResult = ProvenanceVerdict | ProvenanceSkipped;

// ---------------------------------------------------------------------------
// Which rules are gated, and on what
// ---------------------------------------------------------------------------

/**
 * Which arguments of the matched call carry the statement.
 *
 * - `statement` — only the first argument. Everything after it is the driver's
 *   bound-value array, and treating a bound value as evidence of danger is the
 *   mistake that makes a parameterised query look like an injection.
 * - `arguments` — every argument, for a call whose danger is the composed path
 *   rather than one statement string (`path.join(root, name)`).
 */
export type ArgumentScope = "statement" | "arguments";

/** A rule this module grades, with what it builds and where the build inputs are. */
export interface GatedRule {
  readonly scope: ArgumentScope;
  /** What the call builds, for the rendered sentence ("SQL statement", "shell command"). */
  readonly subject: string;
}

/**
 * The rules whose severity provenance decides.
 *
 * Every one of them is a *pattern* rule whose match proves only that a value
 * was interpolated; none of them proves the value is attacker-controlled. Rules
 * whose match is already specific — `nosql-where-operator` matches an operator,
 * not a value — are not listed and are reported exactly as they fire.
 */
export const PROVENANCE_GATED_RULES: Readonly<Record<string, GatedRule>> = {
  "appsec.injection.sql-built-from-variables": { scope: "statement", subject: "SQL statement" },
  "appsec.injection.raw-query-unsafe": { scope: "statement", subject: "SQL statement" },
  "appsec.injection.command-interpolation": { scope: "statement", subject: "shell command" },
  "appsec.injection.path-from-request-input": { scope: "arguments", subject: "filesystem path" },
};

/** The gating configuration for a rule id, or null when the rule is not gated. */
export function gatedRule(ruleId: string): GatedRule | null {
  return PROVENANCE_GATED_RULES[ruleId] ?? null;
}

/** The extensions whose contents this module can parse. */
const SCRIPT_KINDS: Readonly<Record<string, ts.ScriptKind>> = {
  ts: ts.ScriptKind.TS,
  mts: ts.ScriptKind.TS,
  cts: ts.ScriptKind.TS,
  tsx: ts.ScriptKind.TSX,
  js: ts.ScriptKind.JS,
  mjs: ts.ScriptKind.JS,
  cjs: ts.ScriptKind.JS,
  jsx: ts.ScriptKind.JSX,
};

/** The script kind for a path, or null when it is not JavaScript or TypeScript. */
export function scriptKindOf(path: string): ts.ScriptKind | null {
  const extension = path.split(".").at(-1)?.toLowerCase() ?? "";
  return SCRIPT_KINDS[extension] ?? null;
}

/** True when this module can parse the file at `path`. */
export function isAnalysableFile(path: string): boolean {
  return scriptKindOf(path) !== null;
}

// ---------------------------------------------------------------------------
// The match span
// ---------------------------------------------------------------------------

/** Where the rule matched, as SARIF reports it: 1-based, columns optional. */
export interface MatchSpan {
  readonly startLine: number;
  readonly startColumn: number | null;
  readonly endLine: number | null;
  readonly endColumn: number | null;
}

/** A file offset for a 1-based line/column, clamped to the line and to the file. */
function positionOf(sf: ts.SourceFile, line: number, column: number | null): number {
  const starts = sf.getLineStarts();
  const index = Math.min(Math.max(line - 1, 0), starts.length - 1);
  const lineStart = starts[index] ?? 0;
  const next = starts[index + 1];
  const lineEnd = next === undefined ? sf.text.length : next;
  const offset = column === null ? 0 : Math.max(column - 1, 0);
  return Math.min(lineStart + offset, lineEnd);
}

/**
 * The call the rule matched: the one whose own range is closest to the span.
 *
 * A rule's span is normally the whole call, but SARIF makes columns optional, a
 * pattern can point inside a call, and a method chain gives every call in it the
 * *same* start offset — `appClient.get(...).query(...).set(...)` is three calls
 * all beginning at `appClient`. Picking the innermost or the outermost is wrong
 * in one of those cases each, so the match is scored: how far its start is from
 * the span's start plus how far its end is from the span's end. A span that is
 * exactly a call scores zero on it and on nothing else.
 */
function matchedCall(sf: ts.SourceFile, start: number, end: number): ts.CallExpression | null {
  let best: ts.CallExpression | null = null;
  let bestScore = Number.POSITIVE_INFINITY;
  let bestWidth = Number.POSITIVE_INFINITY;
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const from = node.getStart(sf);
      const to = node.getEnd();
      // Overlap is the only requirement; the score decides between the rest.
      if (to > start && from <= end) {
        const score = Math.abs(from - start) + Math.abs(to - end);
        const width = to - from;
        if (score < bestScore || (score === bestScore && width < bestWidth)) {
          best = node;
          bestScore = score;
          bestWidth = width;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);
  return best;
}

// ---------------------------------------------------------------------------
// File facts, gathered once
// ---------------------------------------------------------------------------

/** Where a locally bound name came from. */
interface ImportedFrom {
  readonly specifier: string;
  /** 1-based line of the import statement, so the sentence can cite it. */
  readonly line: number;
}

/** The whole-file facts the resolver needs, collected in one pass. */
interface Resolver {
  readonly sf: ts.SourceFile;
  /** Names assigned to anywhere in the file (`x = `, `x++`, `this.x = `). */
  readonly reassigned: ReadonlySet<string>;
  /** Names a mutating array method is called on (`x.push(...)`). */
  readonly mutated: ReadonlySet<string>;
  readonly types: ReadonlyMap<string, ts.TypeAliasDeclaration>;
  readonly enums: ReadonlyMap<string, ts.EnumDeclaration>;
  /** Locally bound name to the module it was imported from, and the line it sits on. */
  readonly imports: ReadonlyMap<string, ImportedFrom>;
}

/** Array methods that change the receiver, so its contents are not frozen. */
const MUTATING_METHODS: ReadonlySet<string> = new Set([
  "push",
  "pop",
  "shift",
  "unshift",
  "splice",
  "sort",
  "reverse",
  "fill",
  "copyWithin",
]);

/**
 * `=` and every compound assignment (`+=`, `??=`, ...). The contiguous
 * `FirstAssignment..LastAssignment` range is the public form of the check the
 * compiler makes internally.
 */
function isAssignment(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

/** Collects the whole-file facts: assignments, mutations, types, enums, imports. */
function buildResolver(sf: ts.SourceFile): Resolver {
  const reassigned = new Set<string>();
  const mutated = new Set<string>();
  const types = new Map<string, ts.TypeAliasDeclaration>();
  const enums = new Map<string, ts.EnumDeclaration>();
  const imports = new Map<string, ImportedFrom>();

  const noteTarget = (target: ts.Node): void => {
    if (ts.isIdentifier(target)) reassigned.add(target.text);
    else if (
      ts.isPropertyAccessExpression(target) &&
      target.expression.kind === ts.SyntaxKind.ThisKeyword
    ) {
      reassigned.add(`this.${target.name.text}`);
    }
  };

  const walk = (node: ts.Node): void => {
    if (ts.isBinaryExpression(node) && isAssignment(node.operatorToken.kind)) {
      noteTarget(node.left);
    } else if (ts.isPostfixUnaryExpression(node) || ts.isPrefixUnaryExpression(node)) {
      const operator = node.operator;
      if (operator === ts.SyntaxKind.PlusPlusToken || operator === ts.SyntaxKind.MinusMinusToken) {
        noteTarget(node.operand);
      }
    } else if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      MUTATING_METHODS.has(node.expression.name.text) &&
      ts.isIdentifier(node.expression.expression)
    ) {
      mutated.add(node.expression.expression.text);
    }
    ts.forEachChild(node, walk);
  };
  walk(sf);

  // Not named `declare`: a statement that starts with that word is parsed as an
  // ambient declaration and erased, so the call would silently never run.
  const collect = (statements: readonly ts.Statement[]): void => {
    for (const statement of statements) {
      if (ts.isTypeAliasDeclaration(statement)) types.set(statement.name.text, statement);
      else if (ts.isEnumDeclaration(statement)) enums.set(statement.name.text, statement);
      else if (ts.isModuleDeclaration(statement) && statement.body !== undefined) {
        if (ts.isModuleBlock(statement.body)) collect(statement.body.statements);
      } else if (ts.isImportDeclaration(statement)) {
        const specifier = ts.isStringLiteral(statement.moduleSpecifier)
          ? statement.moduleSpecifier.text
          : "";
        const clause = statement.importClause;
        if (clause === undefined) continue;
        const from: ImportedFrom = {
          specifier,
          line: sf.getLineAndCharacterOfPosition(statement.getStart(sf)).line + 1,
        };
        if (clause.name !== undefined) imports.set(clause.name.text, from);
        const bindings = clause.namedBindings;
        if (bindings === undefined) continue;
        if (ts.isNamespaceImport(bindings)) imports.set(bindings.name.text, from);
        else for (const element of bindings.elements) imports.set(element.name.text, from);
      }
    }
  };
  collect(sf.statements);

  return { sf, reassigned, mutated, types, enums, imports };
}

// ---------------------------------------------------------------------------
// Name resolution, by walking the scopes the expression sits in
// ---------------------------------------------------------------------------

/** What a name turned out to be bound to in the enclosing scopes. */
type Binding =
  | { readonly kind: "variable"; readonly decl: ts.VariableDeclaration; readonly frozen: boolean }
  | {
      readonly kind: "loop";
      readonly decl: ts.VariableDeclaration;
      readonly source: ts.Expression;
    }
  | {
      readonly kind: "parameter";
      readonly decl: ts.ParameterDeclaration;
      readonly owner: string | null;
    }
  | { readonly kind: "function"; readonly decl: ts.FunctionDeclaration }
  | { readonly kind: "enum"; readonly decl: ts.EnumDeclaration }
  | { readonly kind: "import"; readonly from: ImportedFrom }
  /** Declared, but in a shape this module does not follow (destructured, caught). */
  | { readonly kind: "opaque"; readonly what: string };

/** True when a binding name binds `name`; a destructuring pattern counts. */
function bindsName(binding: ts.BindingName, name: string): "exact" | "pattern" | null {
  if (ts.isIdentifier(binding)) return binding.text === name ? "exact" : null;
  for (const element of binding.elements) {
    if (ts.isOmittedExpression(element)) continue;
    if (bindsName(element.name, name) !== null) return "pattern";
  }
  return null;
}

/** `const` (or a `let` nothing ever assigns to) counts as frozen. */
function isFrozenDeclaration(
  decl: ts.VariableDeclaration,
  name: string,
  reassigned: ReadonlySet<string>,
): boolean {
  const list = decl.parent;
  const isConst = ts.isVariableDeclarationList(list)
    ? (list.flags & ts.NodeFlags.Const) !== 0
    : false;
  return isConst || !reassigned.has(name);
}

/** Looks for `name` among a scope's own statements. */
function findInStatements(
  resolver: Resolver,
  statements: readonly ts.Statement[],
  name: string,
): Binding | null {
  for (const statement of statements) {
    if (ts.isVariableStatement(statement)) {
      for (const decl of statement.declarationList.declarations) {
        const match = bindsName(decl.name, name);
        if (match === null) continue;
        if (match === "pattern") {
          return { kind: "opaque", what: `the destructured binding \`${name}\`` };
        }
        return {
          kind: "variable",
          decl,
          frozen: isFrozenDeclaration(decl, name, resolver.reassigned),
        };
      }
    } else if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
      return { kind: "function", decl: statement };
    } else if (ts.isEnumDeclaration(statement) && statement.name.text === name) {
      return { kind: "enum", decl: statement };
    } else if (ts.isClassDeclaration(statement) && statement.name?.text === name) {
      return { kind: "opaque", what: `the class \`${name}\`` };
    }
  }
  const from = resolver.imports.get(name);
  return from === undefined ? null : { kind: "import", from };
}

/** The name of a function-like node, for the sentence and for the dedup key. */
function functionName(node: ts.Node): string | null {
  if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) {
    const name = node.name;
    return name === undefined ? null : name.getText(node.getSourceFile());
  }
  if (ts.isConstructorDeclaration(node)) return "constructor";
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
    const parent = node.parent;
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
    if (ts.isPropertyDeclaration(parent) || ts.isPropertyAssignment(parent)) {
      return parent.name.getText(node.getSourceFile());
    }
  }
  return null;
}

/** Resolves `name` as seen from `from`, innermost scope first. */
function resolveName(resolver: Resolver, name: string, from: ts.Node): Binding | null {
  let cursor: ts.Node | undefined = from.parent;
  while (cursor !== undefined) {
    if (ts.isSourceFile(cursor) || ts.isBlock(cursor) || ts.isModuleBlock(cursor)) {
      const found = findInStatements(resolver, cursor.statements, name);
      if (found !== null) return found;
    }
    if (ts.isCaseClause(cursor) || ts.isDefaultClause(cursor)) {
      const found = findInStatements(resolver, cursor.statements, name);
      if (found !== null) return found;
    }
    if (ts.isForStatement(cursor) || ts.isForOfStatement(cursor) || ts.isForInStatement(cursor)) {
      const initializer = cursor.initializer;
      if (initializer !== undefined && ts.isVariableDeclarationList(initializer)) {
        for (const decl of initializer.declarations) {
          const match = bindsName(decl.name, name);
          if (match === null) continue;
          if (match === "pattern") {
            return { kind: "opaque", what: `the destructured loop binding \`${name}\`` };
          }
          return ts.isForOfStatement(cursor)
            ? { kind: "loop", decl, source: cursor.expression }
            : { kind: "variable", decl, frozen: true };
        }
      }
    }
    if (ts.isFunctionLike(cursor)) {
      for (const parameter of cursor.parameters) {
        const match = bindsName(parameter.name, name);
        if (match === null) continue;
        if (match === "pattern") {
          return { kind: "opaque", what: `the destructured parameter \`${name}\`` };
        }
        return { kind: "parameter", decl: parameter, owner: functionName(cursor) };
      }
    }
    if (ts.isCatchClause(cursor)) {
      const variable = cursor.variableDeclaration;
      if (variable !== undefined && bindsName(variable.name, name) !== null) {
        return { kind: "opaque", what: `the caught error \`${name}\`` };
      }
    }
    cursor = cursor.parent;
  }
  return null;
}

// ---------------------------------------------------------------------------
// The classifier
// ---------------------------------------------------------------------------

/** Names bound by a callback whose receiver is a frozen literal source. */
type Env = ReadonlyMap<string, Provenance>;

const EMPTY_ENV: Env = new Map<string, Provenance>();

/** Builds a provenance record, deriving the verdict from the kind. */
function provenance(kind: ProvenanceKind, why: string, via?: readonly string[]): Provenance {
  const record = { kind, klass: KIND_CLASS[kind], why };
  return via === undefined || via.length === 0 ? record : { ...record, via };
}

/** Re-wraps a resolved provenance, recording the declaration crossed to reach it. */
function through(step: string, inner: Provenance): Provenance {
  return provenance(inner.kind, inner.why, [step, ...(inner.via ?? [])]);
}

/** The worse of two provenances; ties keep the left one, so order is stable. */
function worse(left: Provenance, right: Provenance): Provenance {
  return CLASS_ORDER.indexOf(right.klass) > CLASS_ORDER.indexOf(left.klass) ? right : left;
}

/** Collapses whitespace and clips, so a 40-line template does not enter a sentence. */
export function clip(text: string, limit = MAX_TEXT): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length <= limit ? collapsed : `${collapsed.slice(0, limit - 3)}...`;
}

/** Source text of a node, collapsed and clipped. */
function textOf(resolver: Resolver, node: ts.Node, limit = MAX_TEXT): string {
  return clip(node.getText(resolver.sf), limit);
}

/**
 * The 1-based line a node sits on. Every sentence this module writes names one,
 * because a claim about a declaration the reader cannot find is not checkable.
 */
function lineOf(resolver: Resolver, node: ts.Node): number {
  return resolver.sf.getLineAndCharacterOfPosition(node.getStart(resolver.sf)).line + 1;
}

/** Strips the wrappers that do not change a value: parens, `as`, `!`, `satisfies`. */
function unwrap(node: ts.Expression): ts.Expression {
  let cursor = node;
  for (;;) {
    if (ts.isParenthesizedExpression(cursor) || ts.isNonNullExpression(cursor)) {
      cursor = cursor.expression;
    } else if (ts.isAsExpression(cursor) || ts.isSatisfiesExpression(cursor)) {
      cursor = cursor.expression;
    } else if (ts.isTypeAssertionExpression(cursor)) {
      cursor = cursor.expression;
    } else {
      return cursor;
    }
  }
}

/** True for an expression that is already its own value. */
function isLiteralish(node: ts.Expression): boolean {
  return (
    ts.isStringLiteral(node) ||
    ts.isNoSubstitutionTemplateLiteral(node) ||
    ts.isNumericLiteral(node) ||
    ts.isBigIntLiteral(node) ||
    node.kind === ts.SyntaxKind.TrueKeyword ||
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword ||
    (ts.isIdentifier(node) && node.text === "undefined")
  );
}

/**
 * The dynamic pieces of a string-building expression: template substitutions
 * and the non-literal operands of a `+` chain. A literal contributes nothing,
 * and anything that is not a template or a concatenation is itself one piece.
 */
export function dynamicParts(expression: ts.Expression): ts.Expression[] {
  const node = unwrap(expression);
  if (isLiteralish(node)) return [];
  if (ts.isTemplateExpression(node)) {
    return node.templateSpans.flatMap((span) => dynamicParts(span.expression));
  }
  if (ts.isTaggedTemplateExpression(node)) return [];
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return [...dynamicParts(node.left), ...dynamicParts(node.right)];
  }
  return [node];
}

/** Calls that can only produce digits, `.`, `-`, `e`, `Infinity` or `NaN`. */
const NUMERIC_COERCERS: ReadonlySet<string> = new Set([
  "Number",
  "parseInt",
  "parseFloat",
  "BigInt",
]);

/** Array methods whose result is still drawn from the receiver's elements. */
const CHAIN_METHODS: ReadonlySet<string> = new Set([
  "map",
  "filter",
  "join",
  "flatMap",
  "flat",
  "slice",
  "sort",
  "reverse",
  "concat",
  "entries",
]);

/** Parameter names that hold a request when they are a handler's parameter. */
const REQUEST_NAMES: ReadonlySet<string> = new Set([
  "req",
  "request",
  "ctx",
  "context",
  "event",
  "httpRequest",
]);

/** The fields of a request object that carry caller-controlled data. */
const REQUEST_FIELDS: ReadonlySet<string> = new Set([
  "query",
  "params",
  "body",
  "headers",
  "cookies",
  "url",
  "rawBody",
  "searchParams",
  "nextUrl",
  "queryStringParameters",
  "pathParameters",
  "multiValueQueryStringParameters",
]);

/** Parameter types that are a request whatever the parameter is called. */
const REQUEST_TYPES: ReadonlySet<string> = new Set([
  "Request",
  "IncomingMessage",
  "FastifyRequest",
  "NextRequest",
  "NextApiRequest",
  "ExpressRequest",
  "APIGatewayProxyEvent",
  "APIGatewayProxyEventV2",
  "APIGatewayEvent",
  "HttpRequest",
]);

/** Module specifiers a configuration object is imported from. */
const CONFIG_SPECIFIER =
  /(^|[/@.])(env|envs|config|configs|configuration|settings)(\.[cm]?[jt]s)?$/i;

/** The leftmost expression of a property or element access chain. */
function rootOf(node: ts.Expression): ts.Expression {
  let cursor = unwrap(node);
  for (;;) {
    if (ts.isPropertyAccessExpression(cursor) || ts.isElementAccessExpression(cursor)) {
      cursor = unwrap(cursor.expression);
    } else if (ts.isCallExpression(cursor)) {
      cursor = unwrap(cursor.expression);
    } else {
      return cursor;
    }
  }
}

/**
 * The first property name read off the root of an access chain, so
 * `req.query.sort` and `req.query["sort"]` both answer `query`.
 */
function firstField(node: ts.Expression): string | null {
  const names: string[] = [];
  let cursor = unwrap(node);
  for (;;) {
    if (ts.isPropertyAccessExpression(cursor)) {
      names.unshift(cursor.name.text);
      cursor = unwrap(cursor.expression);
    } else if (ts.isElementAccessExpression(cursor)) {
      const argument = unwrap(cursor.argumentExpression);
      if (ts.isStringLiteral(argument)) names.unshift(argument.text);
      cursor = unwrap(cursor.expression);
    } else {
      return names[0] ?? null;
    }
  }
}

/** A frozen source of literals: an array literal, or a name bound to one. */
interface FrozenSource {
  /** A noun phrase for the sentence. */
  readonly label: string;
  readonly elements: readonly ts.Expression[];
}

/** True when every element is a literal, or an array/object of literals. */
function allLiteralElements(elements: readonly ts.Expression[]): boolean {
  return elements.every((element) => {
    const node = unwrap(element);
    if (isLiteralish(node)) return true;
    if (ts.isArrayLiteralExpression(node)) return allLiteralElements(node.elements);
    if (ts.isObjectLiteralExpression(node)) {
      return node.properties.every(
        (property) =>
          ts.isPropertyAssignment(property) && allLiteralElements([property.initializer]),
      );
    }
    return false;
  });
}

/** True when the expression is `<something> as const`. */
function isAsConst(expression: ts.Expression): boolean {
  return (
    ts.isAsExpression(expression) &&
    ts.isTypeReferenceNode(expression.type) &&
    expression.type.typeName.getText(expression.getSourceFile()) === "const"
  );
}

/** Resolves an expression to a frozen tuple of literals, or null. */
function frozenSource(resolver: Resolver, expression: ts.Expression): FrozenSource | null {
  const asConst = isAsConst(expression);
  const node = unwrap(expression);
  if (ts.isArrayLiteralExpression(node)) {
    if (!allLiteralElements(node.elements)) return null;
    return {
      label: `the ${asConst ? "`as const` " : ""}array literal \`${textOf(resolver, node, 60)}\``,
      elements: node.elements,
    };
  }
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "freeze"
  ) {
    const first = node.arguments[0];
    return first === undefined ? null : frozenSource(resolver, first);
  }
  if (!ts.isIdentifier(node)) return null;
  const binding = resolveName(resolver, node.text, node);
  if (binding === null || binding.kind !== "variable") return null;
  if (!binding.frozen || resolver.mutated.has(node.text)) return null;
  const initializer = binding.decl.initializer;
  if (initializer === undefined) return null;
  const inner = frozenSource(resolver, initializer);
  if (inner === null) return null;
  const scope = ts.isSourceFile(binding.decl.parent.parent.parent) ? "module" : "local";
  const frozenWord = isAsConst(initializer) ? "`as const` tuple" : "array literal";
  return {
    label: `the ${scope} ${frozenWord} \`${node.text} = ${textOf(resolver, unwrap(initializer), 60)}\` on line ${lineOf(resolver, binding.decl)}`,
    elements: inner.elements,
  };
}

/** Every `return` expression of a function body, not descending into nested ones. */
function returnExpressions(fn: ts.SignatureDeclaration): ts.Expression[] {
  const body = "body" in fn ? fn.body : undefined;
  if (body === undefined) return [];
  if (!ts.isBlock(body)) return [body];
  const found: ts.Expression[] = [];
  const walk = (node: ts.Node): void => {
    if (ts.isFunctionLike(node)) return;
    if (ts.isReturnStatement(node) && node.expression !== undefined) found.push(node.expression);
    ts.forEachChild(node, walk);
  };
  ts.forEachChild(body, walk);
  return found;
}

/** Binds a callback's parameters to the frozen elements its receiver holds. */
function bindCallbackParams(fn: ts.SignatureDeclaration, source: FrozenSource, env: Env): Env {
  const bound = new Map(env);
  const element = provenance("frozen-tuple", `an element of ${source.label}`);
  const index = provenance("numeric", "the iteration index, which is a number");
  fn.parameters.forEach((parameter, position) => {
    const value = position === 0 ? element : index;
    const names: string[] = [];
    const collect = (binding: ts.BindingName): void => {
      if (ts.isIdentifier(binding)) {
        names.push(binding.text);
        return;
      }
      for (const entry of binding.elements) {
        if (ts.isOmittedExpression(entry)) continue;
        collect(entry.name);
      }
    };
    collect(parameter.name);
    for (const name of names) bound.set(name, value);
  });
  return bound;
}

/** A closed type, or null when the annotation does not close the value. */
function classifyType(resolver: Resolver, type: ts.TypeNode, depth: number): Provenance | null {
  if (depth > MAX_DEPTH) return null;
  if (ts.isParenthesizedTypeNode(type)) return classifyType(resolver, type.type, depth + 1);
  if (ts.isLiteralTypeNode(type)) {
    const literal = type.literal;
    if (ts.isStringLiteral(literal) || ts.isNumericLiteral(literal)) {
      return provenance("closed-union", `the literal type \`${textOf(resolver, type, 40)}\``);
    }
    return null;
  }
  if (ts.isUnionTypeNode(type)) {
    const members = type.types.map((member) => classifyType(resolver, member, depth + 1));
    if (members.some((member) => member === null)) return null;
    return provenance(
      "closed-union",
      `the closed literal union \`${textOf(resolver, type, 60)}\` (${type.types.length} members)`,
    );
  }
  if (type.kind === ts.SyntaxKind.NumberKeyword) {
    return provenance(
      "numeric",
      "a `number`-typed binding, which cannot carry a quote, a semicolon or a comment",
    );
  }
  if (type.kind === ts.SyntaxKind.BooleanKeyword) {
    return provenance("closed-union", "a `boolean`-typed binding");
  }
  if (ts.isTypeOperatorNode(type)) return classifyType(resolver, type.type, depth + 1);
  if (ts.isArrayTypeNode(type)) return classifyType(resolver, type.elementType, depth + 1);
  if (ts.isIndexedAccessTypeNode(type)) {
    // `(typeof X)[number]` -- the element type of an `as const` array.
    const object = ts.isParenthesizedTypeNode(type.objectType)
      ? type.objectType.type
      : type.objectType;
    if (type.indexType.kind !== ts.SyntaxKind.NumberKeyword) return null;
    if (!ts.isTypeQueryNode(object)) return null;
    const name = object.exprName.getText(resolver.sf);
    const statements = resolver.sf.statements;
    const binding = findInStatements(resolver, statements, name);
    if (binding === null || binding.kind !== "variable") return null;
    const initializer = binding.decl.initializer;
    if (initializer === undefined || !isAsConst(initializer)) return null;
    const frozen = frozenSource(resolver, initializer);
    if (frozen === null) return null;
    return provenance(
      "closed-union",
      `the ${frozen.elements.length} literals of the \`as const\` array \`${name}\` on line ${lineOf(resolver, binding.decl)}, so the value can only ever be one of them`,
    );
  }
  if (ts.isTypeReferenceNode(type)) {
    const name = type.typeName.getText(resolver.sf);
    const enumDeclaration = resolver.enums.get(name);
    if (enumDeclaration !== undefined) {
      return provenance(
        "enum-member",
        `a member of the \`enum ${name}\` declared in this file (${enumDeclaration.members.length} members)`,
      );
    }
    const alias = resolver.types.get(name);
    if (alias !== undefined) {
      const inner = classifyType(resolver, alias.type, depth + 1);
      return inner === null ? null : through(`the type alias \`${name}\``, inner);
    }
    return null;
  }
  return null;
}

/** True when a parameter holds a request object. */
function isRequestParameter(resolver: Resolver, parameter: ts.ParameterDeclaration): boolean {
  const type = parameter.type;
  if (type !== undefined) {
    const text = type.getText(resolver.sf);
    for (const name of REQUEST_TYPES) {
      if (new RegExp(`\\b${name}\\b`).test(text)) return true;
    }
  }
  return false;
}

/** The provenance of a function parameter, once its type failed to close it. */
function parameterProvenance(
  resolver: Resolver,
  parameter: ts.ParameterDeclaration,
  owner: string | null,
): Provenance {
  const name = textOf(resolver, parameter.name, 40);
  const type =
    parameter.type === undefined ? "" : `, typed \`${textOf(resolver, parameter.type, 40)}\``;
  const where = owner === null ? "" : ` of \`${owner}\``;
  return provenance(
    "parameter",
    `the parameter \`${name}\`${where} on line ${lineOf(resolver, parameter)}${type}, whose callers this file does not show`,
  );
}

/** Config provenance for a member of an imported binding. */
function configProvenance(text: string, from: ImportedFrom): Provenance {
  return provenance(
    "config",
    `\`${text}\`, read from \`${from.specifier}\` (imported on line ${from.line}) -- deploy-time configuration set by whoever operates the service, not a value a caller supplies`,
  );
}

/** Call sites of `name` in this file, as a plain call or as `this.name(...)`. */
function callSites(resolver: Resolver, name: string, limit: number): ts.CallExpression[] {
  const found: ts.CallExpression[] = [];
  const walk = (node: ts.Node): void => {
    if (found.length >= limit) return;
    if (ts.isCallExpression(node)) {
      const callee = unwrap(node.expression);
      const matches = ts.isIdentifier(callee)
        ? callee.text === name
        : ts.isPropertyAccessExpression(callee) && callee.name.text === name;
      if (matches) found.push(node);
    }
    ts.forEachChild(node, walk);
  };
  walk(resolver.sf);
  return found;
}

/** True when the declaration is exported, so this file cannot see all its callers. */
function isExported(node: ts.Node): boolean {
  const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  if (modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true) {
    return true;
  }
  // `export const handler = (...) => {}` carries the modifier on the statement.
  let cursor: ts.Node | undefined = node.parent;
  while (cursor !== undefined && !ts.isSourceFile(cursor)) {
    if (ts.isVariableStatement(cursor) || ts.isClassDeclaration(cursor)) {
      const outer = ts.getModifiers(cursor);
      if (outer?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true) {
        return true;
      }
    }
    cursor = cursor.parent;
  }
  return false;
}

/** How many call sites of one function this module reads before it stops. */
const MAX_CALL_SITES = 8;

/** Methods that hand a receiver's own elements to a callback. */
const ITERATION_METHODS: ReadonlySet<string> = new Set([
  "map",
  "forEach",
  "filter",
  "flatMap",
  "find",
  "some",
  "every",
]);

/**
 * A callback parameter whose receiver is a frozen tuple of literals, as in
 * `TABLES.forEach((table) => queryRunner.query(...))`. The same closed set as
 * the `for...of` form, reached the other way round.
 */
function classifyCallbackParameter(
  resolver: Resolver,
  parameter: ts.ParameterDeclaration,
): Provenance | null {
  const fn = parameter.parent;
  if (!ts.isArrowFunction(fn) && !ts.isFunctionExpression(fn)) return null;
  const call = fn.parent;
  if (!ts.isCallExpression(call)) return null;
  const callee = unwrap(call.expression);
  if (!ts.isPropertyAccessExpression(callee)) return null;
  if (!ITERATION_METHODS.has(callee.name.text)) return null;
  const source = frozenSource(resolver, callee.expression);
  if (source === null) return null;
  const index = fn.parameters.indexOf(parameter);
  return index === 0
    ? provenance(
        "loop-literal",
        `an element of ${source.label}, handed to a \`.${callee.name.text}()\` callback`,
      )
    : provenance("numeric", "the iteration index, which is a number");
}

/**
 * What the callers in *this file* pass for a parameter.
 *
 * This is the one hop that turns the commonest true positive back into a
 * critical: a handler reading `req.query.x` and passing it to a helper two
 * functions down. It is also where the module refuses to over-claim — for an
 * **exported** function the file cannot see every caller, so an in-file call
 * site can only make the verdict worse (a request value found here is proof),
 * never better (a literal found here proves nothing about the other callers).
 */
function classifyParameterFlow(
  resolver: Resolver,
  parameter: ts.ParameterDeclaration,
  owner: string | null,
  depth: number,
): Provenance | null {
  const fn = parameter.parent;
  if (!ts.isFunctionLike(fn) || owner === null) return null;
  const index = fn.parameters.indexOf(parameter);
  if (index < 0) return null;
  const sites = callSites(resolver, owner, MAX_CALL_SITES);
  if (sites.length === 0) return null;

  let worstSite: Provenance | null = null;
  for (const site of sites) {
    const argument = site.arguments[index];
    if (argument === undefined) continue;
    const resolved = classify(resolver, argument, EMPTY_ENV, depth + 1);
    worstSite = worstSite === null ? resolved : worse(worstSite, resolved);
  }
  if (worstSite === null) return null;

  const plural = sites.length === 1 ? "the one call site" : `all ${sites.length} call sites`;
  const step = `the parameter \`${textOf(resolver, parameter.name, 30)}\` of \`${owner}\`, fed by ${plural} in this file`;
  if (worstSite.klass === "reachable") return through(step, worstSite);
  // An exported function is called from files this module did not read, so a
  // clean local call site is not an answer about the value.
  if (isExported(fn)) return null;
  return through(step, worstSite);
}

/** Resolves one expression to a provenance. The only entry point that recurses. */
function classify(
  resolver: Resolver,
  expression: ts.Expression,
  env: Env,
  depth: number,
): Provenance {
  if (depth > MAX_DEPTH) {
    return provenance(
      "unresolved",
      `an expression Sentinel stopped resolving after ${MAX_DEPTH} steps`,
    );
  }
  const node = unwrap(expression);

  if (isLiteralish(node)) {
    return provenance("literal", `the literal \`${textOf(resolver, node, 40)}\``);
  }
  if (ts.isTemplateExpression(node)) {
    const parts = node.templateSpans.map((span) =>
      classify(resolver, span.expression, env, depth + 1),
    );
    const worst = parts.reduce(
      (left, right) => worse(left, right),
      provenance("literal", "a template of literals"),
    );
    return worst.klass === "closed"
      ? provenance("literal", `a template whose ${parts.length} interpolations are all closed`)
      : worst;
  }
  if (ts.isBinaryExpression(node)) {
    const operator = node.operatorToken.kind;
    if (
      operator === ts.SyntaxKind.PlusToken ||
      operator === ts.SyntaxKind.QuestionQuestionToken ||
      operator === ts.SyntaxKind.BarBarToken ||
      operator === ts.SyntaxKind.AmpersandAmpersandToken
    ) {
      return worse(
        classify(resolver, node.left, env, depth + 1),
        classify(resolver, node.right, env, depth + 1),
      );
    }
  }
  if (ts.isConditionalExpression(node)) {
    // A test on input choosing between two branches is control flow; only the
    // branches reach the string.
    return worse(
      classify(resolver, node.whenTrue, env, depth + 1),
      classify(resolver, node.whenFalse, env, depth + 1),
    );
  }
  if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.PlusToken) {
    return provenance("numeric", "a unary `+` coercion, which can only produce a number");
  }
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.length === 0
      ? provenance("literal", "an empty array literal")
      : node.elements
          .map((element) => classify(resolver, element, env, depth + 1))
          .reduce((left, right) => worse(left, right));
  }
  if (ts.isObjectLiteralExpression(node)) {
    const values = node.properties
      .filter(ts.isPropertyAssignment)
      .map((property) => classify(resolver, property.initializer, env, depth + 1));
    return values.length === 0
      ? provenance("literal", "an object literal with no values")
      : values.reduce((left, right) => worse(left, right));
  }
  if (ts.isIdentifier(node)) return classifyIdentifier(resolver, node, env, depth);
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return classifyAccess(resolver, node, env, depth);
  }
  if (ts.isCallExpression(node)) return classifyCall(resolver, node, env, depth);
  if (node.kind === ts.SyntaxKind.ThisKeyword) {
    return provenance("unresolved", "`this`, which this module does not follow on its own");
  }
  return provenance(
    "unresolved",
    `the expression \`${textOf(resolver, node, 40)}\`, which this file does not resolve`,
  );
}

/** An identifier: the env first, then the scopes it sits in. */
function classifyIdentifier(
  resolver: Resolver,
  node: ts.Identifier,
  env: Env,
  depth: number,
): Provenance {
  const bound = env.get(node.text);
  if (bound !== undefined) return bound;

  const binding = resolveName(resolver, node.text, node);
  if (binding === null) {
    return provenance(
      "unresolved",
      `\`${node.text}\`, which is not declared in this file (an ambient or global value)`,
    );
  }
  switch (binding.kind) {
    case "import":
      return CONFIG_SPECIFIER.test(binding.from.specifier)
        ? configProvenance(node.text, binding.from)
        : provenance(
            "unresolved",
            `\`${node.text}\`, imported from \`${binding.from.specifier}\` on line ${binding.from.line}, which Sentinel does not follow across files`,
          );
    case "enum":
      return provenance(
        "enum-member",
        `the \`enum ${node.text}\` declared in this file (${binding.decl.members.length} members)`,
      );
    case "parameter": {
      // The declared type is a *bound* on the value, whatever the callers pass,
      // so it is consulted before any call site.
      const type = binding.decl.type;
      const closed = type === undefined ? null : classifyType(resolver, type, depth + 1);
      if (closed !== null) {
        return through(`the parameter \`${node.text}\``, closed);
      }
      if (isRequestParameter(resolver, binding.decl)) {
        return provenance(
          "request-input",
          `the request object \`${node.text}\`, which the caller controls`,
        );
      }
      const iterated = classifyCallbackParameter(resolver, binding.decl);
      if (iterated !== null) return iterated;
      const flowed = classifyParameterFlow(resolver, binding.decl, binding.owner, depth);
      if (flowed !== null) return flowed;
      return parameterProvenance(resolver, binding.decl, binding.owner);
    }
    case "loop": {
      const frozen = frozenSource(resolver, binding.source);
      if (frozen !== null) {
        return provenance(
          "loop-literal",
          `the \`for...of\` binding \`${node.text}\` over ${frozen.label}, so it can only ever be one of those literals`,
        );
      }
      return through(
        `the \`for...of\` binding \`${node.text}\` over \`${textOf(resolver, binding.source, 40)}\``,
        classify(resolver, binding.source, env, depth + 1),
      );
    }
    case "variable": {
      if (!binding.frozen) {
        return provenance(
          "unresolved",
          `\`${node.text}\`, a binding this file assigns to more than once`,
        );
      }
      const initializer = binding.decl.initializer;
      if (initializer === undefined) {
        return provenance("unresolved", `\`${node.text}\`, declared without a value`);
      }
      const scope = ts.isSourceFile(binding.decl.parent.parent.parent) ? "module" : "local";
      const where = `declared on line ${lineOf(resolver, binding.decl)}`;
      const inner = classify(resolver, initializer, env, depth + 1);
      if (inner.kind === "literal") {
        return provenance(
          "constant",
          `the ${scope} constant \`${node.text} = ${textOf(resolver, initializer, 48)}\`, ${where} and never reassigned in this file`,
        );
      }
      return through(`the ${scope} constant \`${node.text}\` (${where})`, inner);
    }
    case "function":
      return provenance(
        "unresolved",
        `the function \`${node.text}\` used as a value, which this module does not follow`,
      );
    case "opaque":
      return provenance("unresolved", `${binding.what}, which this module does not follow`);
    default:
      return provenance("unresolved", "an expression this file does not resolve");
  }
}

/** A property or element access: judged by its root, then by its object. */
function classifyAccess(
  resolver: Resolver,
  node: ts.PropertyAccessExpression | ts.ElementAccessExpression,
  env: Env,
  depth: number,
): Provenance {
  const whole = textOf(resolver, node, 60);
  const root = rootOf(node);

  if (ts.isIdentifier(root)) {
    if (root.text === "process" && firstField(node) === "env") {
      return provenance(
        "config",
        `\`${whole}\`, an environment variable read at run time -- set by whoever operates the service`,
      );
    }
    const bound = env.get(root.text);
    if (bound !== undefined) return through(`the access \`${whole}\``, bound);

    const binding = resolveName(resolver, root.text, root);
    if (binding !== null) {
      if (binding.kind === "import") {
        return CONFIG_SPECIFIER.test(binding.from.specifier)
          ? configProvenance(whole, binding.from)
          : provenance(
              "unresolved",
              `\`${whole}\`, reached through \`${root.text}\` imported from \`${binding.from.specifier}\` on line ${binding.from.line}, which Sentinel does not follow across files`,
            );
      }
      if (binding.kind === "parameter") {
        const field = firstField(node);
        const looksLikeRequest =
          isRequestParameter(resolver, binding.decl) ||
          (REQUEST_NAMES.has(root.text) && field !== null && REQUEST_FIELDS.has(field));
        if (looksLikeRequest) {
          return provenance(
            "request-input",
            `\`${whole}\`, read from the request object \`${root.text}\`, which the caller controls`,
          );
        }
      }
      if (binding.kind === "enum") {
        return provenance(
          "enum-member",
          `a member of the \`enum ${root.text}\` declared in this file (${binding.decl.members.length} members)`,
        );
      }
    }
  }

  if (root.kind === ts.SyntaxKind.ThisKeyword && ts.isPropertyAccessExpression(node)) {
    const member = classifyThisMember(resolver, node, env, depth);
    if (member !== null) return member;
  }

  // Not special: the value is whatever the object holds.
  const object = node.expression;
  if (object === root && ts.isIdentifier(root)) {
    return through(`the access \`${whole}\``, classifyIdentifier(resolver, root, env, depth + 1));
  }
  return through(`the access \`${whole}\``, classify(resolver, object, env, depth + 1));
}

/** `this.x` where `x` is a class property this file initialises and never assigns. */
function classifyThisMember(
  resolver: Resolver,
  node: ts.PropertyAccessExpression,
  env: Env,
  depth: number,
): Provenance | null {
  let cursor: ts.Node | undefined = node;
  while (cursor !== undefined && !ts.isClassLike(cursor)) cursor = cursor.parent;
  if (cursor === undefined) return null;
  const name = node.name.text;
  if (resolver.reassigned.has(`this.${name}`)) return null;
  for (const member of cursor.members) {
    if (!ts.isPropertyDeclaration(member)) continue;
    if (member.name.getText(resolver.sf) !== name) continue;
    const initializer = member.initializer;
    if (initializer === undefined) return null;
    return through(
      `the class property \`this.${name}\``,
      classify(resolver, initializer, env, depth + 1),
    );
  }
  return null;
}

/** A call: numeric coercion, a frozen-tuple chain, a local helper, or unresolved. */
function classifyCall(
  resolver: Resolver,
  node: ts.CallExpression,
  env: Env,
  depth: number,
): Provenance {
  const callee = unwrap(node.expression);

  if (ts.isIdentifier(callee)) {
    if (NUMERIC_COERCERS.has(callee.text)) {
      return provenance(
        "numeric",
        `\`${callee.text}(...)\`, which can only produce digits, \`.\`, \`-\`, \`e\`, \`Infinity\` or \`NaN\``,
      );
    }
    if (callee.text === "String") {
      const first = node.arguments[0];
      return first === undefined
        ? provenance("literal", "`String()` with no argument")
        : through("the `String(...)` coercion", classify(resolver, first, env, depth + 1));
    }
  }

  if (ts.isPropertyAccessExpression(callee)) {
    const method = callee.name.text;
    if (method === "toString" || method === "toFixed" || method === "trim") {
      return through(
        `the \`.${method}()\` call`,
        classify(resolver, callee.expression, env, depth + 1),
      );
    }
  }

  const chain = classifyFrozenChain(resolver, node, env, depth);
  if (chain !== null) return chain;

  const helper = classifyHelperCall(resolver, node, env, depth);
  if (helper !== null) return helper;

  return provenance(
    "unresolved",
    `the result of \`${textOf(resolver, node, 48)}\`, which this file does not resolve`,
  );
}

/** `<frozen>.map(cb).join(sep)` and friends: closed when every callback is closed. */
function classifyFrozenChain(
  resolver: Resolver,
  node: ts.CallExpression,
  env: Env,
  depth: number,
): Provenance | null {
  const steps: { method: string; args: readonly ts.Expression[] }[] = [];
  let cursor: ts.Expression = node;
  while (ts.isCallExpression(cursor)) {
    const callee = unwrap(cursor.expression);
    if (!ts.isPropertyAccessExpression(callee)) return null;
    const method = callee.name.text;
    if (!CHAIN_METHODS.has(method)) return null;
    steps.unshift({ method, args: [...cursor.arguments] });
    cursor = unwrap(callee.expression);
  }
  if (steps.length === 0) return null;

  const source = frozenSource(resolver, cursor);
  if (source === null) return null;

  let worstChild = provenance("literal", "a literal");
  for (const step of steps) {
    for (const argument of step.args) {
      const callback = unwrap(argument);
      if (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) {
        const inner = bindCallbackParams(callback, source, env);
        const returns = returnExpressions(callback);
        if (returns.length === 0) {
          worstChild = worse(
            worstChild,
            provenance(
              "unresolved",
              `the callback of \`.${step.method}()\`, which returns nothing`,
            ),
          );
        }
        for (const returned of returns) {
          worstChild = worse(worstChild, classify(resolver, returned, inner, depth + 1));
        }
      } else {
        worstChild = worse(worstChild, classify(resolver, argument, env, depth + 1));
      }
    }
  }

  const chain = steps.map((step) => `.${step.method}(...)`).join("");
  if (worstChild.klass === "closed") {
    return provenance(
      "frozen-tuple",
      `\`${chain}\` over ${source.label}, so the fragment belongs to a fixed compile-time set`,
    );
  }
  return through(`\`${chain}\` over ${source.label}`, worstChild);
}

/** A call of a function declared in this file: classify what it returns. */
function classifyHelperCall(
  resolver: Resolver,
  node: ts.CallExpression,
  env: Env,
  depth: number,
): Provenance | null {
  const callee = unwrap(node.expression);
  let fn: ts.SignatureDeclaration | null = null;
  let label = "";

  if (ts.isIdentifier(callee)) {
    const binding = resolveName(resolver, callee.text, callee);
    if (binding === null) return null;
    if (binding.kind === "function") {
      fn = binding.decl;
      label = `the local helper \`${callee.text}()\``;
    } else if (binding.kind === "variable" && binding.frozen) {
      const initializer = binding.decl.initializer;
      if (
        initializer !== undefined &&
        (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer))
      ) {
        fn = initializer;
        label = `the local helper \`${callee.text}()\``;
      }
    }
  } else if (
    ts.isPropertyAccessExpression(callee) &&
    callee.expression.kind === ts.SyntaxKind.ThisKeyword
  ) {
    let cursor: ts.Node | undefined = node;
    while (cursor !== undefined && !ts.isClassLike(cursor)) cursor = cursor.parent;
    if (cursor === undefined) return null;
    const name = callee.name.text;
    for (const member of cursor.members) {
      if (ts.isMethodDeclaration(member) && member.name.getText(resolver.sf) === name) {
        fn = member;
        label = `the method \`this.${name}()\``;
        break;
      }
    }
  }

  if (fn === null) return null;
  const returns = returnExpressions(fn);
  if (returns.length === 0) {
    return provenance("unresolved", `${label}, whose return value this file does not show`);
  }
  const worstReturn = returns
    .map((returned) => classify(resolver, returned, env, depth + 1))
    .reduce((left, right) => worse(left, right));
  return through(label, worstReturn);
}

// ---------------------------------------------------------------------------
// Execution context
// ---------------------------------------------------------------------------

/** True when the class declares `implements MigrationInterface`. */
function implementsMigrationInterface(node: ts.ClassLikeDeclaration): boolean {
  for (const clause of node.heritageClauses ?? []) {
    if (clause.token !== ts.SyntaxKind.ImplementsKeyword) continue;
    for (const type of clause.types) {
      if (type.expression.getText(node.getSourceFile()) === "MigrationInterface") return true;
    }
  }
  return false;
}

/** The nearest enclosing function-like node. */
function enclosingFunction(node: ts.Node): ts.SignatureDeclaration | null {
  let cursor: ts.Node | undefined = node;
  while (cursor !== undefined) {
    if (ts.isFunctionLike(cursor)) return cursor;
    cursor = cursor.parent;
  }
  return null;
}

/** What runs the matched line, which is what decides who can reach it. */
function executionContext(resolver: Resolver, node: ts.Node): ExecutionContext {
  const fn = enclosingFunction(node);
  const symbol = fn === null ? null : functionName(fn);

  let cursor: ts.Node | undefined = node;
  while (cursor !== undefined && !ts.isClassLike(cursor)) cursor = cursor.parent;
  if (cursor !== undefined && implementsMigrationInterface(cursor)) {
    const method = symbol ?? "up";
    if (method === "down") {
      return {
        kind: "migration-down",
        symbol,
        detail:
          "the `down()` rollback method of a class implementing TypeORM's `MigrationInterface`, which runs only on an explicit manual revert",
      };
    }
    return {
      kind: "migration-up",
      symbol,
      detail: `the \`${method}()\` method of a class implementing TypeORM's \`MigrationInterface\`, which runs from a migration command and has no HTTP, queue or CLI-argument path into it`,
    };
  }

  if (fn !== null) {
    for (const parameter of fn.parameters) {
      const name = ts.isIdentifier(parameter.name) ? parameter.name.text : "";
      if (isRequestParameter(resolver, parameter) || REQUEST_NAMES.has(name)) {
        return {
          kind: "request-handler",
          symbol,
          detail: `\`${symbol ?? "this function"}\`, which receives the request object \`${name || "request"}\``,
        };
      }
    }
  }
  return { kind: "unknown", symbol, detail: "" };
}

// ---------------------------------------------------------------------------
// The entry points
// ---------------------------------------------------------------------------

/** The file a match sits in. */
export interface ProvenanceSource {
  /** Repository-relative path; only its extension is read. */
  readonly file: string;
  readonly text: string;
}

/** A parsed file, reusable across every match in it. */
interface ParsedFile {
  readonly resolver: Resolver;
}

/** Parses a file, or explains why it was not parsed. */
function parse(source: ProvenanceSource): ParsedFile | ProvenanceSkipped {
  const kind = scriptKindOf(source.file);
  if (kind === null) {
    return { analysed: false, reason: "the file is not JavaScript or TypeScript" };
  }
  if (source.text.length > MAX_FILE_BYTES) {
    return { analysed: false, reason: "the file is too large to parse as hand-written code" };
  }
  const sf = ts.createSourceFile(source.file, source.text, ts.ScriptTarget.Latest, true, kind);
  return { resolver: buildResolver(sf) };
}

/** Grades one match inside an already-parsed file. */
function analyse(parsed: ParsedFile, span: MatchSpan, scope: ArgumentScope): ProvenanceResult {
  const { resolver } = parsed;
  const sf = resolver.sf;
  const start = positionOf(sf, span.startLine, span.startColumn);
  const endLine = span.endLine ?? span.startLine;
  // An absent end column means "to the end of that line", which is the start of
  // the next one -- clamped to the file, so the last line works too.
  const end =
    span.endColumn === null
      ? positionOf(sf, endLine + 1, 1)
      : positionOf(sf, endLine, span.endColumn);
  const call = matchedCall(sf, start, Math.max(start, end));
  if (call === null) {
    return {
      analysed: false,
      reason:
        "the match does not sit on a call, so Sentinel could not separate the statement from the bound values",
    };
  }

  const args = scope === "statement" ? call.arguments.slice(0, 1) : [...call.arguments];
  const parts: InterpolatedPart[] = [];
  const seen = new Set<string>();
  for (const argument of args) {
    for (const expression of dynamicParts(argument)) {
      const text = textOf(resolver, expression);
      const resolved = classify(resolver, expression, EMPTY_ENV, 0);
      const key = `${text}\u0000${resolved.kind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      parts.push({
        ...resolved,
        text,
        line: sf.getLineAndCharacterOfPosition(expression.getStart(sf)).line + 1,
      });
    }
  }
  if (parts.length === 0) {
    return {
      analysed: false,
      reason:
        scope === "statement"
          ? "the statement the call executes is built from literals only, so there was nothing to resolve"
          : "the matched call takes no dynamic argument",
    };
  }

  const klass = parts.reduce<ProvenanceClass>(
    (worstSoFar, part) => worseClass(worstSoFar, part.klass),
    "closed",
  );
  const context = executionContext(resolver, call);
  const signature = [context.symbol ?? "", ...parts.map((part) => part.text).sort()].join("\u0000");
  return { analysed: true, klass, parts, context, signature };
}

/** Grades one match, parsing the file it sits in. */
export function analyseInterpolation(
  source: ProvenanceSource,
  span: MatchSpan,
  scope: ArgumentScope = "statement",
): ProvenanceResult {
  const parsed = parse(source);
  if ("analysed" in parsed) return parsed;
  return analyse(parsed, span, scope);
}

/** Grades many matches, parsing each file once. */
export interface ProvenanceReader {
  analyse(source: ProvenanceSource, span: MatchSpan, scope: ArgumentScope): ProvenanceResult;
}

/** A reader that keeps each file's parse, for a run with many matches per file. */
export function createProvenanceReader(): ProvenanceReader {
  const cache = new Map<string, ParsedFile | ProvenanceSkipped>();
  return {
    analyse(source, span, scope) {
      let parsed = cache.get(source.file);
      if (parsed === undefined) {
        parsed = parse(source);
        cache.set(source.file, parsed);
      }
      if ("analysed" in parsed) return parsed;
      return analyse(parsed, span, scope);
    },
  };
}

// ---------------------------------------------------------------------------
// The severity policy
// ---------------------------------------------------------------------------

/** The policy ids, quoted in the sentence the report prints. */
export const PROVENANCE_RULE_IDS = {
  closed: "P1",
  config: "P2",
  unresolved: "P3",
  reachable: "P4",
  executionContext: "P5",
} as const;

/** Lowers `severity` to `ceiling` when it sits above it; never raises. */
export function capAt(severity: Severity, ceiling: Severity): Severity {
  return severityRank(severity) < severityRank(ceiling) ? ceiling : severity;
}

/** What each verdict does to a finding. One row per class; nothing else moves severity. */
const CLASS_POLICY: Readonly<
  Record<ProvenanceClass, { readonly cap: Severity | null; readonly confidence: Confidence }>
> = {
  closed: { cap: "info", confidence: "high" },
  config: { cap: "low", confidence: "low" },
  unresolved: { cap: "medium", confidence: "low" },
  reachable: { cap: null, confidence: "high" },
};

/** The ceiling each execution context puts on a finding that is not `reachable`. */
const CONTEXT_CAP: Readonly<Record<ExecutionContextKind, Severity | null>> = {
  "migration-up": "low",
  "migration-down": "info",
  "request-handler": null,
  unknown: null,
};

/** What the policy decided for one finding, and the words to say about it. */
export interface ProvenanceDecision {
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly klass: ProvenanceClass;
  /** True when the finding no longer claims a vulnerability. */
  readonly suppressed: boolean;
  /** Prefixed to the title; `""` when the finding stands as the rule wrote it. */
  readonly titlePrefix: string;
  /** One or two sentences naming the policy that moved it; appended to the description. */
  readonly rationale: string;
  /** Replaces the rule's (absent) preconditions with what provenance proved. */
  readonly exploitability: string;
  /** Replaces the rule's acceptance criteria; null keeps them. */
  readonly acceptanceCriteria: readonly string[] | null;
  /**
   * Replaces the rule's impact; null keeps it. A `closed` verdict has to
   * replace it, because the rule's impact sentence ("a crafted value changes
   * the statement") is the claim the verdict just withdrew.
   */
  readonly impact: string | null;
  /** Replaces the rule's recommendation; null keeps it. */
  readonly recommendation: string | null;
}

/** Renders the parts into the clause the rationale and the exploitability share. */
export function renderParts(parts: readonly InterpolatedPart[]): string {
  const named = parts.slice(0, MAX_PARTS_NAMED).map((part) => {
    const via = part.via === undefined ? "" : `, through ${part.via.join(", then ")},`;
    return `\`${part.text}\` (line ${part.line}) resolves${via} to ${part.why}`;
  });
  const rest = parts.length - named.length;
  return rest <= 0
    ? named.join("; ")
    : `${named.join("; ")}; and ${rest} further interpolated ${rest === 1 ? "expression" : "expressions"}`;
}

/** The open parts, which is what a reader has to check. */
function openParts(parts: readonly InterpolatedPart[]): readonly InterpolatedPart[] {
  return parts.filter((part) => part.klass !== "closed");
}

/** Applies the provenance policy to a finding's base severity and confidence. */
export function decideProvenance(
  base: { readonly severity: Severity; readonly confidence: Confidence },
  verdict: ProvenanceVerdict,
  subject = "statement",
): ProvenanceDecision {
  const policy = CLASS_POLICY[verdict.klass];
  let severity = policy.cap === null ? base.severity : capAt(base.severity, policy.cap);
  const open = openParts(verdict.parts);
  const sentences: string[] = [];
  let titlePrefix = "";
  let exploitability: string;
  let acceptanceCriteria: readonly string[] | null = null;
  let impact: string | null = null;
  let recommendation: string | null = null;

  switch (verdict.klass) {
    case "closed": {
      titlePrefix = "Not injectable: ";
      sentences.push(
        `Sentinel resolved every expression interpolated into this ${subject} to a value the code ` +
          `fixes, so it is recorded as information rather than as a vulnerability (${PROVENANCE_RULE_IDS.closed}): ` +
          `${renderParts(verdict.parts)}. Nothing a caller supplies reaches the ${subject}.`,
      );
      exploitability = `No caller-controlled value reaches this ${subject}: ${renderParts(verdict.parts)}. Provenance was resolved inside this file only, which is where every one of these declarations sits.`;
      impact = `None as written: every expression interpolated into this ${subject} is fixed by the code, so no caller-controlled value reaches it. The finding is kept as a marker, so an edit that makes one of these values dynamic shows up as a change rather than as a new alarm.`;
      recommendation = `No change is required. If this ${subject} later has to carry a value from a caller, bind it as a parameter instead of interpolating it, and the finding stays closed.`;
      acceptanceCriteria = [
        `No change is required while the interpolated ${verdict.parts.length === 1 ? "expression stays" : "expressions stay"} closed: ${verdict.parts
          .map((part) => `\`${part.text}\``)
          .join(", ")}.`,
        `If any of them becomes dynamic -- a parameter without a literal type, a request field, or a value from another module -- this returns as a vulnerability, so bind it with a placeholder now if the ${subject} is likely to grow.`,
      ];
      break;
    }
    case "config": {
      sentences.push(
        `Sentinel resolved the interpolated expressions and the only open ${open.length === 1 ? "one is" : "ones are"} deploy-time configuration (${PROVENANCE_RULE_IDS.config}): ${renderParts(open)}. The actor who can change that value is the operator who already holds the deployment credentials, so this is configuration hygiene rather than an injection an outside caller can reach; Sentinel did not read the configuration module, so the value's format is unverified.`,
      );
      exploitability = `Not reachable from a request: ${renderParts(open)}. Exploiting it requires setting the configuration value itself, which is the deployer's own privilege.`;
      acceptanceCriteria = [
        `The configuration value is bound as a parameter, or escaped for the target dialect (\`quote_literal\` / \`format('%L')\` in PostgreSQL), instead of being pasted into the ${subject}.`,
        "The value is validated at startup with a format check, so a stray quote fails the boot rather than the statement.",
      ];
      break;
    }
    case "unresolved": {
      sentences.push(
        `Sentinel could not resolve ${open.length === 1 ? "one interpolated expression" : `${open.length} interpolated expressions`} inside this file (${PROVENANCE_RULE_IDS.unresolved}): ${renderParts(open)}. Reachability is therefore not established: this is a lead to check, not a proven injection, which is why it is reported at ${severity} with low confidence rather than as a critical.`,
      );
      exploitability = `Reachability was not established: ${renderParts(open)}. Sentinel resolves provenance within one file, so a value that arrives from a caller or from another module is reported without proof that a request can reach it. Confirm where the value comes from before scheduling the fix.`;
      break;
    }
    case "reachable": {
      sentences.push(
        `Sentinel traced an interpolated expression to request input (${PROVENANCE_RULE_IDS.reachable}): ` +
          `${renderParts(open)}. The ${subject} is built from a value the caller controls, so the rule's severity stands.`,
      );
      exploitability = `A caller controls the interpolated value: ${renderParts(open)}. No configuration, flag or privilege is needed beyond reaching this code path.`;
      break;
    }
  }

  const contextCap = verdict.klass === "reachable" ? null : CONTEXT_CAP[verdict.context.kind];
  if (contextCap !== null) {
    const capped = capAt(severity, contextCap);
    if (capped !== severity) {
      sentences.push(
        `Sentinel then capped it at ${capped} (${PROVENANCE_RULE_IDS.executionContext}): the ${subject} is executed by ` +
          `${verdict.context.detail}.`,
      );
      severity = capped;
    }
  }

  return {
    severity,
    confidence: policy.confidence,
    klass: verdict.klass,
    suppressed: verdict.klass === "closed",
    titlePrefix,
    rationale: sentences.join(" "),
    exploitability,
    acceptanceCriteria,
    impact,
    recommendation,
  };
}

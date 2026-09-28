/**
 * The contract every ORM extractor implements.
 *
 * An extractor declares the structural queries that find its call sites, and
 * then reads one matched expression into facts. It never sees a file, never
 * spawns anything and never guesses: when the shape it was handed is not
 * really one of its calls — `knex.select("id")` looks exactly like a Drizzle
 * select until you notice the string argument — it returns `null` and another
 * extractor gets the call.
 */

import type { AstRule } from "./_ast.ts";
import type { ParsedChain } from "./_chain.ts";

/** One of the supported data layers; matches the profile's `data-layer` values. */
export type OrmName =
  | "drizzle"
  | "prisma"
  | "typeorm"
  | "sequelize"
  | "knex"
  | "mongoose"
  | "supabase"
  | "pg"
  | "mysql2";

/** What a call site does to the store. */
export type DataOperation =
  | "select"
  | "insert"
  | "update"
  | "delete"
  | "upsert"
  | "raw"
  | "aggregate";

/** How confidently the table name was established. */
export type TableSource =
  | "schema" // resolved through a Drizzle/Prisma schema object
  | "literal" // the call names the table in a string
  | "identifier" // the variable that holds the table, no schema to confirm it
  | "sql" // parsed out of a SQL statement
  | "none"; // nothing in the call names a table

/** What an extractor proved about one call site. */
export interface DataAccessFacts {
  readonly orm: OrmName;
  readonly operation: DataOperation;
  /** Resolved table, model or collection, or `"unresolved"`. */
  readonly table: string;
  readonly tableSource: TableSource;
  readonly hasWhere: boolean;
  /** Columns the filter names, in source order, deduplicated by the caller. */
  readonly whereColumns: readonly string[];
  /** Filter values, so the principal test can look at what is compared, not only to what. */
  readonly filterValues: readonly string[];
  /** Null when the operation cannot take a limit (an insert, a single-row upsert). */
  readonly hasLimit: boolean | null;
  /** Null when nothing is projected (a write); false when it reads every column. */
  readonly hasProjection: boolean | null;
  /** The method that identifies the call, for the unit label: `findMany`, `select`. */
  readonly method: string;
  /** Anything the audit should know that the attributes cannot carry. */
  readonly note?: string | undefined;
}

/** Resolves a Drizzle table variable or a Prisma model to its SQL table name. */
export interface TableResolver {
  /** The SQL table a Drizzle schema variable declares, or undefined. */
  byVariable(file: string, variable: string): string | undefined;
  /** The SQL table a Prisma model maps to, or undefined. */
  byModel(model: string): string | undefined;
}

/** What one file's imports prove about which data layer its calls belong to. */
export interface FileImports {
  /** Module specifiers the file imports or requires. */
  readonly specifiers: ReadonlySet<string>;
}

/** Everything an extractor is given to decide one call site. */
export interface ClaimInput {
  /** Repo-relative path of the file the call lives in. */
  readonly file: string;
  /** The id of the pattern that matched, without its `a:` prefix. */
  readonly patternId: string;
  /** Single metavariables of the anchor match, by name. */
  readonly meta: Readonly<Record<string, string>>;
  /** The whole call chain the anchor opens, already parsed. */
  readonly chain: ParsedChain;
  readonly tables: TableResolver;
  readonly imports: FileImports;
}

/** A structural query an extractor owns, from which the anchor and chain rules are built. */
export interface OrmPattern {
  /** Unique within the extractor; the id the claim sees is `<orm>.<id>`. */
  readonly id: string;
  /** An ast-grep pattern, the common case. */
  readonly pattern?: string | undefined;
  /** A full rule body, when the query needs more than a pattern. */
  readonly rule?: Readonly<Record<string, unknown>> | undefined;
  readonly constraints?: Readonly<Record<string, unknown>> | undefined;
}

/** One data layer's enumeration of its own call sites. */
export interface OrmExtractor {
  readonly orm: OrmName;
  /**
   * The profile `data-layer` values that switch this extractor on. A repo
   * without a profile runs all of them.
   */
  readonly dataLayers: readonly string[];
  /** Module specifiers whose presence in a file confirms this extractor owns its calls. */
  readonly imports: readonly string[];
  /**
   * Method names that identify one of this extractor's chains.
   *
   * They are what the single chain-root query is built from: a call chain
   * containing `.select(`, `.findMany(` or `.where(` is a candidate chain, and
   * one that contains none of them cannot hold this extractor's anchor.
   */
  readonly chainMethods: readonly string[];
  /**
   * Tie-break when two extractors claim the same expression; higher wins.
   * Specific shapes (a Supabase `from("t")`, a Knex string table) outrank the
   * generic ones so the ambiguity resolves toward the narrower query.
   */
  readonly priority: number;
  readonly patterns: readonly OrmPattern[];
  /** Reads one matched expression into facts, or declines it. */
  claim(input: ClaimInput): DataAccessFacts | null;
}

/** Builds the rule body an extractor's pattern stands for. */
function patternRule(pattern: OrmPattern): Readonly<Record<string, unknown>> {
  if (pattern.rule !== undefined) return pattern.rule;
  return { pattern: pattern.pattern ?? "" };
}

/** The anchor rules one extractor contributes, one per pattern. */
export function extractorRules(extractor: OrmExtractor): AstRule[] {
  return extractor.patterns.map((pattern) => ({
    id: `${ANCHOR_PREFIX}${extractor.orm}.${pattern.id}`,
    rule: patternRule(pattern),
    ...(pattern.constraints === undefined ? {} : { constraints: pattern.constraints }),
  }));
}

/** Rule-id prefix of an anchor: the call that identifies the data access. */
export const ANCHOR_PREFIX = "a:";

/** Rule id of the chain-root query; there is exactly one for the whole pass. */
export const CHAIN_RULE_ID = "c:chain";

/**
 * The query that finds chain roots: the outermost call of a chain.
 *
 * `db.select()` is what identifies a Drizzle read, but
 * `db.select().from(t).where(p).limit(10)` is the expression the audit needs,
 * and the two start at the same byte — which is how an anchor is joined to its
 * chain. The rule matches a call that is not itself a link of a longer chain
 * and that contains one of the method names the enabled extractors care about.
 *
 * The selectivity comes from a `regex` on the property node rather than a
 * metavariable constraint: ast-grep evaluates a constraint against the
 * bindings of the outermost alternative, so a constraint on a pattern reached
 * through `has` silently matches nothing.
 */
export function chainRootRule(extractors: readonly OrmExtractor[]): AstRule {
  const methods = [...new Set(extractors.flatMap((extractor) => extractor.chainMethods))].sort();
  return {
    id: CHAIN_RULE_ID,
    rule: {
      kind: "call_expression",
      not: { inside: { kind: "member_expression" } },
      has: {
        stopBy: "end",
        kind: "member_expression",
        has: { field: "property", regex: `^(${methods.map(escapeRegex).join("|")})$` },
      },
    },
  };
}

/** Escapes a method name for the alternation the chain rule is built from. */
function escapeRegex(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

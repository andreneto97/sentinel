/**
 * Helpers shared by the ORM extractors.
 *
 * The ORMs differ in syntax and agree on substance: every one of them filters
 * by something, projects something, and bounds (or fails to bound) the number
 * of rows it reads. These functions read those three things out of the two
 * shapes the libraries actually use — an options object, and a chain of
 * filter calls.
 */

import type { ChainSegment } from "./_chain.ts";
import { objectEntries, stringLiteral } from "./_chain.ts";
import { comparisonValues, memberColumns } from "./_principal.ts";
import type { DataAccessFacts, OrmName, TableSource } from "./types.ts";

/** Keys of a filter object that are operators, not columns. */
const FILTER_OPERATORS: ReadonlySet<string> = new Set([
  // Prisma
  "equals",
  "not",
  "in",
  "notIn",
  "lt",
  "lte",
  "gt",
  "gte",
  "contains",
  "startsWith",
  "endsWith",
  "search",
  "mode",
  "some",
  "every",
  "none",
  "is",
  "isNot",
  "AND",
  "OR",
  "NOT",
  // Mongo
  "$and",
  "$or",
  "$nor",
  "$not",
  "$eq",
  "$ne",
  "$gt",
  "$gte",
  "$lt",
  "$lte",
  "$in",
  "$nin",
  "$exists",
  "$regex",
  "$elemMatch",
  "$expr",
  // Sequelize
  "[Op.and]",
  "[Op.or]",
  "[]",
  "...",
]);

/** The columns and the compared values a filter object names, nested operators included. */
export interface FilterFacts {
  readonly columns: string[];
  readonly values: string[];
}

const MAX_FILTER_DEPTH = 4;

/**
 * Reads a filter object — Prisma's `where`, Mongoose's query document,
 * Sequelize's `where` — into the columns it constrains and the expressions it
 * compares them against. Operator keys are stepped through, not reported.
 */
export function filterObject(text: string, depth = 0): FilterFacts {
  const columns: string[] = [];
  const values: string[] = [];
  if (depth > MAX_FILTER_DEPTH) return { columns, values };
  for (const entry of objectEntries(text)) {
    const isOperator = FILTER_OPERATORS.has(entry.key) || entry.key.startsWith("$");
    if (!isOperator && entry.key !== "") columns.push(entry.key);
    const value = entry.value.trim();
    if (value.startsWith("{") || value.startsWith("[")) {
      const nested = filterObject(value.replace(/^\[|\]$/g, ""), depth + 1);
      columns.push(...nested.columns);
      values.push(...nested.values);
      continue;
    }
    if (value !== "") values.push(value);
  }
  return { columns: dedupe(columns), values: dedupe(values) };
}

/** Keeps the first occurrence of each value, dropping the empty ones. */
export function dedupe(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (trimmed === "" || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

/** The first argument of a segment read as a string literal, or null. */
export function firstStringArgument(segment: ChainSegment | undefined): string | null {
  if (segment === undefined) return null;
  const [first] = segment.args;
  return first === undefined ? null : stringLiteral(first);
}

/** Columns and values named by a chain of comparison calls such as Drizzle's `where`. */
export function expressionFilter(expressions: readonly string[]): FilterFacts {
  const columns: string[] = [];
  const values: string[] = [];
  for (const expression of expressions) {
    columns.push(...memberColumns(expression));
    values.push(...comparisonValues(expression));
  }
  return { columns: dedupe(columns), values: dedupe(values) };
}

/** Merges several filter readings into one. */
export function mergeFilters(...parts: readonly FilterFacts[]): FilterFacts {
  return {
    columns: dedupe(parts.flatMap((part) => part.columns)),
    values: dedupe(parts.flatMap((part) => part.values)),
  };
}

/** Everything but the identity of the call; the extractors fill the rest in. */
export interface FactsInput {
  readonly orm: OrmName;
  readonly operation: DataAccessFacts["operation"];
  readonly method: string;
  readonly table: string;
  readonly tableSource: TableSource;
  readonly filter?: FilterFacts | undefined;
  readonly hasWhere?: boolean | undefined;
  readonly hasLimit?: boolean | null | undefined;
  readonly hasProjection?: boolean | null | undefined;
  readonly note?: string | undefined;
}

/** Assembles the facts record, defaulting what the extractor did not observe. */
export function facts(input: FactsInput): DataAccessFacts {
  const filter = input.filter ?? { columns: [], values: [] };
  const hasWhere = input.hasWhere ?? (filter.columns.length > 0 || filter.values.length > 0);
  return {
    orm: input.orm,
    operation: input.operation,
    table: input.table,
    tableSource: input.tableSource,
    hasWhere,
    whereColumns: filter.columns,
    filterValues: filter.values,
    hasLimit: input.hasLimit ?? null,
    hasProjection: input.hasProjection ?? null,
    method: input.method,
    ...(input.note === undefined ? {} : { note: input.note }),
  };
}

/** True when a receiver path is a plain identifier chain, with no call in it. */
export function isPlainReceiver(path: string): boolean {
  return /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(path.trim());
}

/** The last segment of a dotted path, lower-cased, for receiver-name tests. */
export function receiverWord(path: string): string {
  const parts = path.trim().split(".");
  return (parts[parts.length - 1] ?? "").toLowerCase();
}

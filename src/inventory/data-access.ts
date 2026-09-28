/**
 * Phase 2, domain D3: every data-access call site in the repository.
 *
 * One ast-grep pass finds the calls and the structure around them; the ORM
 * extractors read each matched expression into facts. The aggregator proves
 * every citation and slices the source into the audit prompt, so the model
 * that audits these units never opens a file — which is the whole point of
 * enumerating them here.
 *
 * What a unit records is chosen to answer questions a linter cannot: does this
 * query constrain by the authenticated principal, does it run once per row of
 * another query, is it one of several awaits that could have been one round
 * trip, and which table is it actually reading.
 *
 * This enumerator drives ast-grep itself instead of going through
 * `EnumerationContext.search`, for two reasons the D3 attributes depend on:
 * metavariable **constraints**, without which `$CLIENT.$MODEL.$OP(...)` would
 * match every two-level call in the repository, and **byte offsets**, without
 * which a call cannot be told from another one on the same line and
 * `insideLoop` / `insideTransaction` cannot be decided by containment.
 */

import { ATTRIBUTE, type AuditUnitKind } from "../contracts/inventory.ts";
import { dataLayers } from "../profile/accessors.ts";
import { type AstGrepContext, type AstMatch, type AstRule, runAstGrep } from "./_orms/_ast.ts";
import { parseChain } from "./_orms/_chain.ts";
import { receiverWord } from "./_orms/_claim.ts";
import {
  CONTEXT_RULES,
  type Range,
  buildFileContexts,
  buildFileImports,
  emptyFileContext,
  enclosingBlock,
  enclosingStatement,
  enclosingSymbol,
  insideTransaction,
  isDirectlyAwaited,
  loopKind,
} from "./_orms/_context.ts";
import { principalScope } from "./_orms/_principal.ts";
import {
  DRIZZLE_SCHEMA_RULE,
  type DrizzleTableDeclaration,
  readDrizzleTables,
} from "./_orms/drizzle.ts";
import { extractorsFor } from "./_orms/index.ts";
import { type PrismaSchema, applyPrismaSchema, prismaModelIndex } from "./_orms/prisma.ts";
import { SchemaBuilder } from "./_orms/schema-model.ts";
import {
  type SchemaSnapshot,
  createTableResolver,
  findPrismaSchemas,
  readSources,
} from "./_orms/schema-sources.ts";
import type { DataAccessFacts, OrmExtractor } from "./_orms/types.ts";
import { ANCHOR_PREFIX, CHAIN_RULE_ID, chainRootRule, extractorRules } from "./_orms/types.ts";
import {
  type DraftUnit,
  type EnumerationContext,
  type EnumerationOutcome,
  type InventoryEnumerator,
  contentSymbol,
  degraded,
  enumerated,
  failed,
  joinReasons,
  notApplicable,
} from "./_unit-support.ts";

/** The `AuditUnit.kind` every unit this module produces carries. */
export const DATA_ACCESS_KIND: AuditUnitKind = "data-access";

/** A repository with more call sites than this is reported as capped, not silently cut. */
export const DEFAULT_MAX_UNITS = 5_000;

/** Receivers that name a transaction handle rather than the database itself. */
const TRANSACTION_RECEIVER = /^(tx|trx|transaction)$/;

/** What the pass found, kept so the migration enumerator can reuse the schema reads. */
export interface DataAccessScan {
  readonly outcome: EnumerationOutcome;
  /** Drizzle schema objects found on the way, for the schema model to reuse. */
  readonly drizzleTables: readonly DrizzleTableDeclaration[];
  /** Prisma schemas parsed on the way. */
  readonly prismaSchemas: readonly PrismaSchema[];
  /** Tables the call sites name, deduplicated and sorted. */
  readonly tables: readonly string[];
  /** How many call sites could not be tied to a table name. */
  readonly unresolvedTables: number;
}

/** A claimed call site, before it becomes a draft unit. */
interface Candidate {
  readonly file: string;
  readonly facts: DataAccessFacts;
  readonly extractor: OrmExtractor;
  readonly range: Range;
  readonly text: string;
  readonly symbol: string;
  readonly loop: string;
  readonly inTransaction: boolean;
  readonly awaited: boolean;
  readonly blockKey: string;
  readonly statement: Range | undefined;
}

/** The enumerator phase 2 registers for domain D3's call sites. */
export const dataAccessEnumerator: InventoryEnumerator = {
  name: "data-access",
  kinds: [DATA_ACCESS_KIND],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    return (await scanDataAccess(ctx)).outcome;
  },
};

/** Registered by `defaultEnumerators()`; a list, for symmetry with the other groups. */
export const DATA_ACCESS_ENUMERATORS: readonly InventoryEnumerator[] = [dataAccessEnumerator];

/** Options for {@link scanDataAccess}. */
export interface DataAccessOptions {
  /** Cap on the number of units produced; defaults to {@link DEFAULT_MAX_UNITS}. */
  readonly maxUnits?: number | undefined;
}

/** Everything the data-access pass needs; `EnumerationContext` satisfies it. */
export interface DataAccessContext extends AstGrepContext {
  readonly snapshot: SchemaSnapshot;
  readonly profile?: EnumerationContext["profile"];
}

/**
 * Enumerates every data-access call site in the target repository.
 *
 * Exposed separately from the enumerator so the migration pass can reuse the
 * Drizzle and Prisma schema reads instead of repeating them.
 */
export async function scanDataAccess(
  ctx: DataAccessContext,
  options: DataAccessOptions = {},
): Promise<DataAccessScan> {
  const layers = ctx.profile === undefined ? [] : dataLayers(ctx.profile);
  const extractors = extractorsFor(layers);
  if (extractors.length === 0) {
    return empty(notApplicable("no supported data layer was detected"));
  }

  const rules: AstRule[] = [
    ...extractors.flatMap((extractor) => extractorRules(extractor)),
    chainRootRule(extractors),
    ...CONTEXT_RULES,
  ];
  if (extractors.some((extractor) => extractor.orm === "drizzle")) rules.push(DRIZZLE_SCHEMA_RULE);

  const run = await runAstGrep(ctx, rules);
  if (run.status === "skipped") {
    return empty(notApplicable(run.reason ?? "structural enumeration could not run"));
  }
  if (run.status === "failed") return empty(failed(run.reason ?? "ast-grep failed"));

  const drizzleTables = readDrizzleTables(run.matches);
  const { prismaSchemas, warnings } = await readPrismaSchemas(ctx.snapshot);
  const tables = createTableResolver({
    drizzle: drizzleTables,
    prismaModels: prismaModelIndex(prismaSchemas),
  });
  const contexts = buildFileContexts(run.matches);
  const imports = buildFileImports(run.matches);
  const chains = indexChains(run.matches);
  const byExtractor = new Map<string, OrmExtractor>(
    extractors.map((extractor) => [extractor.orm, extractor]),
  );

  const candidates = new Map<string, Candidate>();
  for (const anchor of run.matches) {
    if (!anchor.ruleId.startsWith(ANCHOR_PREFIX)) continue;
    const patternId = anchor.ruleId.slice(ANCHOR_PREFIX.length);
    const extractor = byExtractor.get(patternId.split(".")[0] ?? "");
    if (extractor === undefined) continue;

    const chainMatch = chains.get(positionKey(anchor.file, anchor.startByte)) ?? anchor;
    const chain = parseChain(chainMatch.text);
    const claimed = extractor.claim({
      file: anchor.file,
      patternId,
      meta: anchor.meta,
      chain,
      tables,
      imports: { specifiers: imports.get(anchor.file) ?? new Set<string>() },
    });
    if (claimed === null) continue;

    const context = contexts.get(anchor.file) ?? emptyFileContext();
    const range: Range = {
      startByte: chainMatch.startByte,
      endByte: chainMatch.endByte,
      startLine: chainMatch.startLine,
      endLine: chainMatch.endLine,
    };
    const block = enclosingBlock(context, range);
    const candidate: Candidate = {
      file: anchor.file,
      facts: claimed,
      extractor,
      range,
      text: chainMatch.text,
      symbol: enclosingSymbol(context, range),
      loop: loopKind(context, range),
      inTransaction:
        insideTransaction(context, range) || TRANSACTION_RECEIVER.test(receiverWord(chain.base)),
      awaited: isDirectlyAwaited(context, range),
      blockKey:
        block === undefined ? `${anchor.file}:program` : `${anchor.file}:${block.startByte}`,
      statement: enclosingStatement(context, range),
    };

    const key = positionKey(anchor.file, range.startByte);
    const existing = candidates.get(key);
    if (existing === undefined || prefer(candidate, existing, imports)) {
      candidates.set(key, candidate);
    }
  }

  const ordered = withoutNested(
    [...candidates.values()].sort(
      (a, b) => a.file.localeCompare(b.file) || a.range.startByte - b.range.startByte,
    ),
  );
  const maxUnits = options.maxUnits ?? DEFAULT_MAX_UNITS;
  const capped = ordered.length > maxUnits;
  const kept = capped ? ordered.slice(0, maxUnits) : ordered;
  const sequential = await sequentialAwaits(ctx.snapshot, kept);

  const units: DraftUnit[] = [];
  const tableNames = new Set<string>();
  let unresolved = 0;
  for (const candidate of kept) {
    if (candidate.facts.table === "unresolved") unresolved += 1;
    else tableNames.add(candidate.facts.table);
    units.push(draftOf(candidate, sequential.has(candidate)));
  }

  const reason = joinReasons([
    run.reason,
    ...warnings,
    capped ? `more than ${maxUnits} data-access call sites; the inventory was capped` : null,
  ]);
  const outcome =
    capped || run.status === "degraded"
      ? degraded(units, reason ?? "the enumeration is partial")
      : enumerated(units, reason);

  return {
    outcome,
    drizzleTables,
    prismaSchemas,
    tables: [...tableNames].sort(),
    unresolvedTables: unresolved,
  };
}

/** Turns one claimed call site into the draft the aggregator identifies and verifies. */
function draftOf(candidate: Candidate, awaitedSequentially: boolean): DraftUnit {
  const { facts } = candidate;
  return {
    kind: DATA_ACCESS_KIND,
    label: `${facts.orm} ${facts.operation} on ${facts.table}`,
    file: candidate.file,
    line: candidate.range.startLine,
    ...(candidate.range.endLine > candidate.range.startLine
      ? { endLine: candidate.range.endLine }
      : {}),
    // Identity is the enclosing symbol plus a digest of the query itself, so
    // two different queries in one function are two units, and editing the line
    // above either of them renames neither.
    symbol: `${candidate.symbol}:${facts.orm}.${facts.method}:${contentSymbol("query", candidate.text)}`,
    ...(facts.note === undefined ? {} : { note: facts.note }),
    attributes: {
      orm: facts.orm,
      operation: facts.operation,
      table: facts.table,
      tableSource: facts.tableSource,
      hasWhere: String(facts.hasWhere),
      whereColumns: facts.whereColumns.join(","),
      ...principalScopeAttributes(facts.whereColumns, facts.filterValues),
      hasLimit: applicable(facts.hasLimit),
      hasProjection: applicable(facts.hasProjection),
      insideLoop: candidate.loop,
      insideTransaction: String(candidate.inTransaction),
      enclosingSymbol: candidate.symbol,
      awaitedSequentially: String(awaitedSequentially),
      method: facts.method,
      // The shared key every enumerator spells the same way, so a route unit
      // and the queries inside it can be joined without guessing.
      [ATTRIBUTE.symbol]: candidate.symbol,
    },
  };
}

/** `"n/a"` when a flag cannot apply — an insert has no projection to be missing. */
/**
 * The tenant-isolation signal as the prompt sees it: `yes` when a principal
 * column or a session-derived value narrows the call, `scoped` when some other
 * owning-entity id does (the audit decides whether that id is the tenant), and
 * `no` when nothing narrows it.
 */
function principalScopeAttributes(
  columns: readonly string[],
  values: readonly string[],
): Record<string, string> {
  const { scope, scopeColumns } = principalScope(columns, values);
  return {
    filtersByPrincipal: scope,
    ...(scopeColumns.length > 0 ? { scopeColumns: scopeColumns.join(",") } : {}),
  };
}

function applicable(value: boolean | null): string {
  return value === null ? "n/a" : String(value);
}

/** An empty scan carrying the reason it is empty. */
function empty(outcome: EnumerationOutcome): DataAccessScan {
  return { outcome, drizzleTables: [], prismaSchemas: [], tables: [], unresolvedTables: 0 };
}

/**
 * Drops a call site that sits inside another one.
 *
 * `db.execute(sql`SELECT ...`)` is one round trip, matched twice: once as the
 * Drizzle escape hatch and once as the raw statement inside it. The outer
 * expression is the call site; the inner one is part of it.
 */
function withoutNested(sorted: readonly Candidate[]): Candidate[] {
  const kept: Candidate[] = [];
  for (const candidate of sorted) {
    const container = kept[kept.length - 1];
    const nested =
      container !== undefined &&
      container.file === candidate.file &&
      container.range.startByte <= candidate.range.startByte &&
      container.range.endByte >= candidate.range.endByte;
    if (!nested) kept.push(candidate);
  }
  return kept;
}

/** Identifies a call site by where it starts, which anchor and chain agree on. */
function positionKey(file: string, startByte: number): string {
  return `${file}${String.fromCharCode(31)}${startByte}`;
}

/** The widest chain root at each anchor position; a chain starts where its anchor does. */
function indexChains(matches: readonly AstMatch[]): Map<string, AstMatch> {
  const chains = new Map<string, AstMatch>();
  for (const match of matches) {
    if (match.ruleId !== CHAIN_RULE_ID) continue;
    const key = positionKey(match.file, match.startByte);
    const existing = chains.get(key);
    if (existing === undefined || match.endByte > existing.endByte) chains.set(key, match);
  }
  return chains;
}

/**
 * Which of two extractors owns an expression both matched.
 *
 * What the file imports settles it first — a file that imports `mongoose` is
 * not making Sequelize calls — and the declared priority only breaks a tie
 * nothing else could.
 */
function prefer(
  candidate: Candidate,
  incumbent: Candidate,
  imports: ReadonlyMap<string, Set<string>>,
): boolean {
  const specifiers = imports.get(candidate.file) ?? new Set<string>();
  const imported = (extractor: OrmExtractor): boolean =>
    extractor.imports.some((specifier) =>
      [...specifiers].some((actual) => actual === specifier || actual.startsWith(`${specifier}/`)),
    );
  const candidateImported = imported(candidate.extractor);
  const incumbentImported = imported(incumbent.extractor);
  if (candidateImported !== incumbentImported) return candidateImported;
  return candidate.extractor.priority > incumbent.extractor.priority;
}

/** Reads and parses every `schema.prisma`, so a model can be named as its table. */
async function readPrismaSchemas(
  snapshot: SchemaSnapshot,
): Promise<{ prismaSchemas: PrismaSchema[]; warnings: string[] }> {
  const files = findPrismaSchemas(snapshot);
  if (files.length === 0) return { prismaSchemas: [], warnings: [] };
  const { sources, unreadable } = await readSources(snapshot, files);
  // The builder is discarded: here the schema is read only for the model→table
  // mapping. `migrations.ts` builds the model that reaches the artifact.
  const builder = new SchemaBuilder();
  const prismaSchemas = sources.map((source) =>
    applyPrismaSchema(builder, source.text, source.file),
  );
  const warnings =
    unreadable.length === 0 ? [] : [`could not read ${unreadable.length} prisma schema file(s)`];
  return { prismaSchemas, warnings };
}

/** The names a statement binds, so the next statement can be tested against them. */
export function declaredNames(statement: string): string[] {
  const names: string[] = [];
  const pattern = /\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)/g;
  for (;;) {
    const match = pattern.exec(statement);
    if (match === null) break;
    const bound = match[1] ?? "";
    if (bound.startsWith("{") || bound.startsWith("[")) {
      for (const part of bound.slice(1, -1).split(",")) {
        const name = /([A-Za-z_$][\w$]*)\s*$/.exec(part.split(":").pop() ?? "")?.[1];
        if (name !== undefined) names.push(name);
      }
      continue;
    }
    names.push(bound);
  }
  return names;
}

/** True when the later statement uses something the earlier one bound. */
export function hasDataDependency(earlier: string, later: string): boolean {
  const names = declaredNames(earlier);
  if (names.length === 0) return false;
  return names.some((name) => new RegExp(`\\b${name}\\b`).test(later));
}

/**
 * Marks the call sites that are one of several sequential awaits in the same
 * block with no data dependency between them — the shape that should have been
 * one round trip, or a `Promise.all`.
 */
async function sequentialAwaits(
  snapshot: SchemaSnapshot,
  candidates: readonly Candidate[],
): Promise<Set<Candidate>> {
  const sequential = new Set<Candidate>();
  const blocks = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    // A query inside a loop is an N+1, which is a different finding; and a
    // query nobody waits for cannot be one of several sequential awaits.
    if (!candidate.awaited || candidate.loop !== "false") continue;
    const group = blocks.get(candidate.blockKey);
    if (group === undefined) blocks.set(candidate.blockKey, [candidate]);
    else group.push(candidate);
  }

  const statementText = async (candidate: Candidate): Promise<string> => {
    const range = candidate.statement;
    if (range === undefined) return candidate.text;
    const source = await snapshot.lines(candidate.file);
    if (source === undefined) return candidate.text;
    return source.slice(range.startLine - 1, range.endLine).join("\n");
  };

  for (const group of blocks.values()) {
    if (group.length < 2) continue;
    group.sort((a, b) => a.range.startByte - b.range.startByte);
    const texts = await Promise.all(group.map(statementText));
    for (let index = 0; index + 1 < group.length; index += 1) {
      const earlier = group[index];
      const later = group[index + 1];
      if (earlier === undefined || later === undefined) continue;
      // Two awaits in the same block are only a batching problem when the
      // second does not need the first one's result.
      if (hasDataDependency(texts[index] ?? "", texts[index + 1] ?? "")) continue;
      sequential.add(earlier);
      sequential.add(later);
    }
  }
  return sequential;
}

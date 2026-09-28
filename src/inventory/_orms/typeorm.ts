/**
 * TypeORM: repository calls, the query builder, and `queryRunner.query`.
 *
 * TypeORM reaches the database three different ways and the audit cares about
 * all three: the repository API (an options object), the query builder (a
 * chain with string predicates), and raw SQL through the runner or the entity
 * manager. `save` is recorded as an upsert, because that is what it does.
 */

import { objectKeys, objectValue, stringLiteral } from "./_chain.ts";
import {
  dedupe,
  facts,
  filterObject,
  firstStringArgument,
  isPlainReceiver,
  mergeFilters,
  receiverWord,
} from "./_claim.ts";
import { sqlOperation, whereColumns } from "./_sql.ts";
import type { ClaimInput, DataAccessFacts, DataOperation, OrmExtractor } from "./types.ts";

/** Repository methods, and what each one does. */
const OPERATIONS: Readonly<Record<string, DataOperation>> = {
  find: "select",
  findBy: "select",
  findOne: "select",
  findOneBy: "select",
  findOneOrFail: "select",
  findOneByOrFail: "select",
  findAndCount: "select",
  findAndCountBy: "select",
  count: "aggregate",
  countBy: "aggregate",
  sum: "aggregate",
  average: "aggregate",
  maximum: "aggregate",
  minimum: "aggregate",
  save: "upsert",
  upsert: "upsert",
  insert: "insert",
  update: "update",
  increment: "update",
  decrement: "update",
  delete: "delete",
  remove: "delete",
  softDelete: "delete",
  softRemove: "delete",
  restore: "update",
};

/** Query-builder terminals, and what each one does. */
const BUILDER_TERMINALS: Readonly<Record<string, DataOperation>> = {
  getMany: "select",
  getOne: "select",
  getManyAndCount: "select",
  getRawMany: "select",
  getRawOne: "select",
  getCount: "aggregate",
  stream: "select",
  execute: "raw",
};

/** Methods that address exactly one row by construction. */
const SINGLE_ROW = new Set(["findOne", "findOneBy", "findOneOrFail", "findOneByOrFail"]);

/** Receivers that name a repository, a manager or a connection. */
const REPOSITORY_WORD = /(repo|repository|manager|datasource|connection|entitymanager|orm)$/;

/** TypeORM's data-access call sites. */
export const typeormExtractor: OrmExtractor = {
  orm: "typeorm",
  dataLayers: ["typeorm"],
  imports: ["typeorm", "@nestjs/typeorm", "typeorm/repository/Repository"],
  chainMethods: [
    "find",
    "findBy",
    "findOne",
    "findOneBy",
    "findAndCount",
    "save",
    "insert",
    "update",
    "delete",
    "remove",
    "softDelete",
    "count",
    "createQueryBuilder",
    "getMany",
    "getOne",
    "getRawMany",
    "andWhere",
    "query",
  ],
  priority: 55,
  patterns: [
    {
      id: "repository",
      pattern: "$REPO.$OP($$$ARGS)",
      constraints: {
        OP: {
          regex:
            "^(find|findBy|findOne|findOneBy|findOneOrFail|findOneByOrFail|findAndCount|findAndCountBy|count|countBy|sum|average|maximum|minimum|save|upsert|insert|update|increment|decrement|delete|remove|softDelete|softRemove|restore)$",
        },
      },
    },
    { id: "builder", pattern: "$REPO.createQueryBuilder($$$ARGS)" },
    {
      id: "raw",
      pattern: "$RUNNER.query($$$ARGS)",
      constraints: {
        RUNNER: {
          regex: "^(?:this\\.)?(queryRunner|manager|entityManager|dataSource|connection)$",
        },
      },
    },
  ],

  claim(input: ClaimInput): DataAccessFacts | null {
    const { chain } = input;

    if (input.patternId === "typeorm.raw") {
      const [first] = chain.segments[0]?.args ?? [];
      const sql = first === undefined ? "" : (stringLiteral(first) ?? first);
      return facts({
        orm: "typeorm",
        operation: sqlOperation(sql),
        method: "query",
        table: "unresolved",
        tableSource: "none",
        filter: { columns: whereColumns(sql), values: [] },
        hasWhere: /\bWHERE\b/i.test(sql),
        hasLimit: /\bLIMIT\b/i.test(sql),
        hasProjection: null,
        note: "raw SQL through the TypeORM runner",
      });
    }

    if (input.patternId === "typeorm.builder") return claimBuilder(input);

    const method = input.meta.OP ?? "";
    const operation = OPERATIONS[method];
    if (operation === undefined) return null;
    const repo = input.meta.REPO ?? chain.base;
    if (!isPlainReceiver(repo)) return null;
    if (!REPOSITORY_WORD.test(receiverWord(repo)) && !/^[A-Z]/.test(repo.split(".").pop() ?? "")) {
      return null;
    }

    const args = chain.segments[0]?.args ?? [];
    // `update(criteria, values)` and `find(options)` put the filter in
    // different places; `findOneBy(where)` passes it bare.
    const optionsText = args[0] ?? "";
    const criteriaFirst = ["update", "delete", "softDelete", "increment", "decrement"].includes(
      method,
    );
    const nested = objectValue(optionsText, "where");
    const where = criteriaFirst
      ? optionsText
      : (nested ?? (method.endsWith("By") ? optionsText : ""));
    const filter = where === "" ? { columns: [], values: [] } : filterObject(where);
    const keys = objectKeys(optionsText);
    const reads = operation === "select" || operation === "aggregate";

    return facts({
      orm: "typeorm",
      operation,
      method,
      table: entityOf(repo, input),
      tableSource: "identifier",
      filter,
      hasWhere: filter.columns.length > 0,
      hasLimit: reads ? keys.includes("take") || SINGLE_ROW.has(method) : null,
      hasProjection: reads ? keys.includes("select") : null,
      ...(method === "save"
        ? { note: "save() inserts when the entity has no primary key and updates when it has one" }
        : {}),
    });
  },
};

/** The entity a repository is typed with, when the call or the receiver names it. */
function entityOf(repo: string, input: ClaimInput): string {
  const explicit = input.meta.ENTITY ?? "";
  if (explicit !== "") return explicit;
  const word = repo.split(".").pop() ?? repo;
  const stripped = word.replace(/(Repository|Repo)$/i, "");
  if (stripped === "" || stripped === word.toLowerCase()) return "unresolved";
  return stripped;
}

/** `repo.createQueryBuilder("u").where("u.ownerId = :id").take(10).getMany()`. */
function claimBuilder(input: ClaimInput): DataAccessFacts | null {
  const { chain } = input;
  const terminal = chain.segments.find((segment) => BUILDER_TERMINALS[segment.name] !== undefined);
  const writer = chain.segments.find((segment) =>
    ["insert", "update", "delete", "softDelete"].includes(segment.name),
  );
  const operation: DataOperation =
    writer !== undefined
      ? writer.name === "insert"
        ? "insert"
        : writer.name === "update"
          ? "update"
          : "delete"
      : (BUILDER_TERMINALS[terminal?.name ?? ""] ?? "select");

  const predicates = chain.segments.filter((segment) =>
    ["where", "andWhere", "orWhere", "having"].includes(segment.name),
  );
  let filter = { columns: [] as string[], values: [] as string[] };
  for (const predicate of predicates) {
    const literal = firstStringArgument(predicate);
    if (literal !== null) {
      filter = mergeFilters(filter, {
        columns: whereColumns(`WHERE ${literal}`),
        values: [literal],
      });
      continue;
    }
    const [first] = predicate.args;
    if (first !== undefined) filter = mergeFilters(filter, filterObject(first));
  }
  const parameters = chain.segments.filter((segment) => segment.name === "setParameter");
  for (const parameter of parameters) {
    const [, value] = parameter.args;
    if (value !== undefined) filter = mergeFilters(filter, { columns: [], values: [value] });
  }
  // `.where("u.ownerId = :id", { id: user.id })` carries the value in a second argument.
  for (const predicate of predicates) {
    const [, bindings] = predicate.args;
    if (bindings !== undefined) filter = mergeFilters(filter, filterObject(bindings));
  }

  const alias = firstStringArgument(chain.segments[0]);
  const reads = operation === "select" || operation === "aggregate";
  return facts({
    orm: "typeorm",
    operation,
    method: terminal?.name ?? "createQueryBuilder",
    table: entityOf(chain.base, input),
    tableSource: "identifier",
    filter: { columns: dedupe(filter.columns), values: dedupe(filter.values) },
    hasWhere: predicates.length > 0,
    hasLimit: reads
      ? chain.segments.some((segment) => ["take", "limit", "getOne"].includes(segment.name))
      : null,
    hasProjection: reads ? chain.segments.some((segment) => segment.name === "select") : null,
    ...(alias === null ? {} : { note: `query builder aliased as "${alias}"` }),
  });
}

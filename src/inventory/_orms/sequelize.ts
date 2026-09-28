/**
 * Sequelize: `User.findAll({ where: { tenantId }, limit: 20 })`.
 *
 * Everything a Sequelize query does lives in one options object, so the
 * attributes come out of its keys: `where` is the filter, `attributes` is the
 * projection, `limit` is the bound. `sequelize.query` is the escape hatch and
 * is recorded as raw SQL.
 */

import { objectKeys, objectValue, stringLiteral } from "./_chain.ts";
import { dedupe, facts, filterObject, isPlainReceiver, receiverWord } from "./_claim.ts";
import { sqlOperation, whereColumns } from "./_sql.ts";
import type { ClaimInput, DataAccessFacts, DataOperation, OrmExtractor } from "./types.ts";

/** Model methods, and what each one does. */
const OPERATIONS: Readonly<Record<string, DataOperation>> = {
  findAll: "select",
  findOne: "select",
  findByPk: "select",
  findAndCountAll: "select",
  scope: "select",
  findOrCreate: "upsert",
  upsert: "upsert",
  create: "insert",
  bulkCreate: "insert",
  update: "update",
  increment: "update",
  decrement: "update",
  destroy: "delete",
  restore: "update",
  count: "aggregate",
  sum: "aggregate",
  max: "aggregate",
  min: "aggregate",
};

/** Methods that read at most one row. */
const SINGLE_ROW = new Set(["findOne", "findByPk", "findOrCreate", "upsert"]);

/** Sequelize's data-access call sites. */
export const sequelizeExtractor: OrmExtractor = {
  orm: "sequelize",
  dataLayers: ["sequelize"],
  imports: ["sequelize", "sequelize-typescript", "@sequelize/core"],
  chainMethods: [
    "findAll",
    "findOne",
    "findByPk",
    "findAndCountAll",
    "findOrCreate",
    "create",
    "bulkCreate",
    "update",
    "destroy",
    "upsert",
    "count",
    "query",
  ],
  priority: 45,
  patterns: [
    {
      id: "model",
      pattern: "$MODEL.$OP($$$ARGS)",
      constraints: {
        OP: {
          regex:
            "^(findAll|findOne|findByPk|findAndCountAll|findOrCreate|create|bulkCreate|update|destroy|upsert|increment|decrement|count|sum|max|min|restore)$",
        },
      },
    },
    {
      id: "raw",
      pattern: "$CONN.query($$$ARGS)",
      constraints: { CONN: { regex: "^(?:this\\.)?(sequelize|db|connection|conn)$" } },
    },
  ],

  claim(input: ClaimInput): DataAccessFacts | null {
    const { chain } = input;

    if (input.patternId === "sequelize.raw") {
      const [first] = chain.segments[0]?.args ?? [];
      const sql = first === undefined ? "" : (stringLiteral(first) ?? first);
      return facts({
        orm: "sequelize",
        operation: sqlOperation(sql),
        method: "query",
        table: "unresolved",
        tableSource: "none",
        filter: { columns: whereColumns(sql), values: [] },
        hasWhere: /\bWHERE\b/i.test(sql),
        hasLimit: /\bLIMIT\b/i.test(sql),
        hasProjection: null,
        note: "raw SQL through sequelize.query; replacements decide whether it is parameterised",
      });
    }

    const method = input.meta.OP ?? "";
    const operation = OPERATIONS[method];
    if (operation === undefined) return null;
    const model = input.meta.MODEL ?? chain.base;
    if (!isPlainReceiver(model)) return null;
    const bare = model.split(".").pop() ?? model;
    const word = receiverWord(model);
    if (!/^[A-Z]/.test(bare) && !word.endsWith("model") && !word.endsWith("repository")) {
      return null;
    }

    // `Model.update(values, options)` puts the filter in the second argument.
    const args = chain.segments[0]?.args ?? [];
    const optionsText =
      method === "update" || method === "increment" || method === "decrement"
        ? (args[1] ?? "")
        : (args[0] ?? "");
    const optionKeys = objectKeys(optionsText);
    const where = objectValue(optionsText, "where");
    const filter = where === undefined ? { columns: [], values: [] } : filterObject(where);
    const reads = operation === "select" || operation === "aggregate";

    return facts({
      orm: "sequelize",
      operation,
      method,
      table: bare.replace(/Model$/, ""),
      tableSource: "identifier",
      filter: { columns: dedupe(filter.columns), values: dedupe(filter.values) },
      hasWhere: where !== undefined || method === "findByPk",
      hasLimit: reads ? optionKeys.includes("limit") || SINGLE_ROW.has(method) : null,
      hasProjection: reads ? optionKeys.includes("attributes") : null,
    });
  },
};

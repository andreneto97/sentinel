/**
 * Mongoose: `User.find({ tenantId }).limit(20)`, `this.userModel.findById(id)`.
 *
 * Mongoose and Sequelize both hang their queries off a capitalised model, and
 * several method names (`create`, `findOne`, `update`, `count`) belong to
 * both. Which extractor gets such a call is settled by the profile and, when
 * both libraries are present, by what the file imports — never by guessing.
 */

import { dedupe, facts, filterObject, isPlainReceiver, receiverWord } from "./_claim.ts";
import type { ClaimInput, DataAccessFacts, DataOperation, OrmExtractor } from "./types.ts";

/** Model methods, and what each one does to the collection. */
const OPERATIONS: Readonly<Record<string, DataOperation>> = {
  find: "select",
  findOne: "select",
  findById: "select",
  distinct: "aggregate",
  countDocuments: "aggregate",
  estimatedDocumentCount: "aggregate",
  aggregate: "aggregate",
  exists: "select",
  create: "insert",
  insertMany: "insert",
  updateOne: "update",
  updateMany: "update",
  replaceOne: "update",
  findOneAndUpdate: "update",
  findByIdAndUpdate: "update",
  findOneAndReplace: "update",
  deleteOne: "delete",
  deleteMany: "delete",
  findOneAndDelete: "delete",
  findByIdAndDelete: "delete",
  findByIdAndRemove: "delete",
  bulkWrite: "raw",
};

/** Methods whose first argument is the filter document. */
const FILTER_FIRST = new Set([
  "find",
  "findOne",
  "updateOne",
  "updateMany",
  "replaceOne",
  "findOneAndUpdate",
  "findOneAndReplace",
  "deleteOne",
  "deleteMany",
  "findOneAndDelete",
  "countDocuments",
  "distinct",
  "exists",
]);

/** Methods that address exactly one document by its `_id`. */
const BY_ID = new Set(["findById", "findByIdAndUpdate", "findByIdAndDelete", "findByIdAndRemove"]);

/** Mongoose's data-access call sites. */
export const mongooseExtractor: OrmExtractor = {
  orm: "mongoose",
  dataLayers: ["mongoose", "mongodb"],
  imports: ["mongoose", "@nestjs/mongoose", "mongodb"],
  chainMethods: [
    "find",
    "findOne",
    "findById",
    "findOneAndUpdate",
    "updateOne",
    "updateMany",
    "deleteOne",
    "deleteMany",
    "insertMany",
    "countDocuments",
    "aggregate",
    "limit",
    "lean",
    "exec",
  ],
  priority: 40,
  patterns: [
    {
      id: "model",
      pattern: "$MODEL.$OP($$$ARGS)",
      constraints: {
        OP: {
          regex:
            "^(find|findOne|findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|replaceOne|deleteOne|deleteMany|insertMany|countDocuments|estimatedDocumentCount|distinct|aggregate|exists|bulkWrite|create)$",
        },
      },
    },
  ],

  claim(input: ClaimInput): DataAccessFacts | null {
    const { chain } = input;
    const method = input.meta.OP ?? chain.segments[0]?.name ?? "";
    const operation = OPERATIONS[method];
    if (operation === undefined) return null;
    const model = input.meta.MODEL ?? chain.base;
    if (!isPlainReceiver(model)) return null;

    // A Mongoose query hangs off a model: `User`, `this.userModel`, `db.User`.
    const word = receiverWord(model);
    const looksLikeModel =
      /^[A-Z]/.test(model.split(".").pop() ?? "") ||
      word.endsWith("model") ||
      word.endsWith("collection");
    if (!looksLikeModel) return null;

    const [first] = chain.segments[0]?.args ?? [];
    const filter = BY_ID.has(method)
      ? { columns: ["_id"], values: first === undefined ? [] : [first] }
      : FILTER_FIRST.has(method) && first !== undefined
        ? filterObject(first)
        : { columns: [], values: [] };

    const projection = chain.segments.find(
      (segment) => segment.name === "select" || segment.name === "projection",
    );
    const reads = operation === "select" || operation === "aggregate";
    const single = BY_ID.has(method) || method === "findOne" || method.startsWith("findOneAnd");

    return facts({
      orm: "mongoose",
      operation,
      method,
      table: collectionOf(model),
      tableSource: "identifier",
      filter: { columns: dedupe(filter.columns), values: dedupe(filter.values) },
      hasWhere: filter.columns.length > 0 || chain.segments.some((s) => s.name === "where"),
      hasLimit: reads
        ? single || chain.segments.some((s) => s.name === "limit" || s.name === "findOne")
        : null,
      hasProjection: reads
        ? projection !== undefined ||
          (method === "find" && (chain.segments[0]?.args.length ?? 0) > 1)
        : null,
    });
  },
};

/** The collection a model variable stands for; Mongoose derives it from the model name. */
function collectionOf(model: string): string {
  const name = model.split(".").pop() ?? model;
  const bare = name.replace(/Model$/, "").replace(/Collection$/, "");
  return bare === "" ? "unresolved" : bare;
}

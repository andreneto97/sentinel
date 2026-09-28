/**
 * The ORM extractor registry.
 *
 * Which extractors run is decided by the profile: a repository that proved
 * only Drizzle is not searched for Sequelize models, which is both faster and
 * the only way the ambiguous shapes (`find`, `create`, `update` — every ORM
 * has them) resolve to one answer. A repository with no profile runs all of
 * them and lets the claim rules and the priorities sort it out.
 */

import { drizzleExtractor } from "./drizzle.ts";
import { knexExtractor } from "./knex.ts";
import { mongooseExtractor } from "./mongoose.ts";
import { prismaExtractor } from "./prisma.ts";
import { createRawSqlExtractor } from "./raw-sql.ts";
import { sequelizeExtractor } from "./sequelize.ts";
import { supabaseExtractor } from "./supabase.ts";
import { typeormExtractor } from "./typeorm.ts";
import type { OrmExtractor } from "./types.ts";

export { drizzleExtractor } from "./drizzle.ts";
export { knexExtractor } from "./knex.ts";
export { mongooseExtractor } from "./mongoose.ts";
export { prismaExtractor } from "./prisma.ts";
export { createRawSqlExtractor, rawSqlExtractor } from "./raw-sql.ts";
export { sequelizeExtractor } from "./sequelize.ts";
export { supabaseExtractor } from "./supabase.ts";
export { typeormExtractor } from "./typeorm.ts";

/** Every extractor that does not depend on which raw driver is in use. */
const BUILDER_EXTRACTORS: readonly OrmExtractor[] = [
  supabaseExtractor,
  knexExtractor,
  prismaExtractor,
  typeormExtractor,
  drizzleExtractor,
  sequelizeExtractor,
  mongooseExtractor,
];

/**
 * The extractors to run for a repository, highest priority first.
 *
 * `dataLayers` are the profile's `data-layer` values. An empty list means the
 * profile could not tell, so everything runs.
 */
export function extractorsFor(dataLayers: readonly string[]): OrmExtractor[] {
  const layers = new Set(dataLayers);
  const selected =
    layers.size === 0
      ? [...BUILDER_EXTRACTORS]
      : BUILDER_EXTRACTORS.filter((extractor) =>
          extractor.dataLayers.some((layer) => layers.has(layer)),
        );

  const wantsRaw =
    layers.size === 0 || ["pg", "mysql2", "postgres-js"].some((layer) => layers.has(layer));
  if (wantsRaw) {
    // One extractor covers both drivers; the profile decides which name the
    // findings carry, and `mysql2` only wins when `pg` is not also present.
    const orm = layers.has("mysql2") && !layers.has("pg") ? "mysql2" : "pg";
    selected.push(createRawSqlExtractor(orm));
  }
  return selected.sort((a, b) => b.priority - a.priority);
}

export type {
  ClaimInput,
  DataAccessFacts,
  DataOperation,
  FileImports,
  OrmExtractor,
  OrmName,
  OrmPattern,
  TableResolver,
  TableSource,
} from "./types.ts";
export { extractorRules } from "./types.ts";

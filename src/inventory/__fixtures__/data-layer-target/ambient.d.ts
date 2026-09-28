// The data-layer fixture exists to be *enumerated*, not compiled against real
// ORMs: phase 2 reads it as text and queries it with ast-grep. These shorthand
// declarations keep `tsc --noEmit` green without adding dependencies Sentinel
// does not use.
//
// Packages already declared by `src/profile/__fixtures__/fixtures.d.ts` or by
// `src/inventory/__fixtures__/fixtures-ambient.d.ts` are not repeated here.

declare module "drizzle-orm";
declare module "drizzle-orm/pg-core";
declare module "drizzle-orm/node-postgres";
declare module "@prisma/client";
declare module "@supabase/supabase-js";
declare module "knex";
declare module "typeorm";
declare module "sequelize";
declare module "mongoose";
declare module "pg";

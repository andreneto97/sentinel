// Fixture sources exist to be *detected*, not to be compiled against real
// packages: phase 0 reads them as text. These shorthand ambient declarations
// keep `tsc --noEmit` green without adding dependencies Sentinel does not use.
// Only packages that appear exclusively inside `__fixtures__` are listed here.

declare module "@prisma/client";
declare module "next-auth";
declare module "next/server";
declare module "fastify";
declare module "pg";
declare module "@nestjs/common";
declare module "typeorm";
declare module "bullmq";

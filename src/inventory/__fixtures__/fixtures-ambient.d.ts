// Fixture sources exist to be *enumerated*, not to be compiled against real
// packages: the inventory phase reads them as text and parses them with
// ast-grep. These shorthand ambient declarations keep `tsc --noEmit` green
// without adding dependencies Sentinel does not use.
//
// Only packages that appear exclusively under `src/inventory/__fixtures__` are
// listed here; anything already declared by `src/profile/__fixtures__` must not
// be repeated.

declare module "express";
declare module "hono";
declare module "koa";
declare module "@koa/router";
declare module "@trpc/server";
declare module "@nestjs/core";
declare module "next";
declare module "next/headers";

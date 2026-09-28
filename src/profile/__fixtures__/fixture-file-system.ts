import { createFileSystem } from "../../ports/file-system.ts";
import type { ProfileFileSystem } from "../file-system-port.ts";

/**
 * The real filesystem port, narrowed to what phase 0 uses.
 *
 * The return type is the point: it fails to compile the day `FileSystem` stops
 * satisfying `ProfileFileSystem`, which is the only thing keeping the profile
 * package's structural port honest.
 */
export function createFixtureFileSystem(): ProfileFileSystem {
  return createFileSystem();
}

/** The fixture repositories: a Next.js app, a legacy Express API, a pure API and a monorepo. */
export type FixtureName = "next-prisma" | "express-knex" | "pure-api" | "monorepo";

/** Absolute path of one of the fixture repositories in this directory. */
export function fixturePath(name: FixtureName): string {
  return `${import.meta.dir}/${name}`;
}

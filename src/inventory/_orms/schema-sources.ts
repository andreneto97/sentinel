/**
 * Finding and reading the files that declare the schema.
 *
 * Both halves of D3 need them: the data-access pass, to turn `from(bookings)`
 * into the table `bookings`, and the schema model, to know what columns and
 * indexes that table has. Everything goes through the shared repository
 * snapshot, so the walk happens once and a schema file read by the data-access
 * enumerator is not read again by the migration one.
 */

import type { DrizzleTableDeclaration } from "./drizzle.ts";
import type { TableResolver } from "./types.ts";

/**
 * The slice of `RepoSnapshot` the D3 inventory uses. Declared structurally so
 * a test can stand in a handful of files without building a snapshot.
 */
export interface SchemaSnapshot {
  /** Every non-ignored file in the repository, as repo-relative POSIX paths. */
  readonly files: readonly string[];
  /** Reads a file through the port, cached; undefined when missing or oversized. */
  read(relativePath: string): Promise<string | undefined>;
  /** Reads a file and splits it into lines, cached. */
  lines(relativePath: string): Promise<readonly string[] | undefined>;
}

/** Directories a repository walk may list but nothing first-party lives in. */
const IGNORED = ["node_modules/", "dist/", "build/", ".next/", "coverage/", ".git/"];

/** True when a repo-relative path is inside a directory nothing first-party lives in. */
export function isIgnoredPath(path: string): boolean {
  return IGNORED.some((prefix) => path.startsWith(prefix) || path.includes(`/${prefix}`));
}

/** Every `schema.prisma` in the repository. */
export function findPrismaSchemas(snapshot: SchemaSnapshot): string[] {
  return snapshot.files.filter((file) => file.endsWith(".prisma") && !isIgnoredPath(file)).sort();
}

/** One schema file read off disk, with the repo-relative path it was read from. */
export interface SchemaSource {
  readonly file: string;
  readonly text: string;
}

/** Reads schema files, listing the ones that could not be read rather than failing. */
export async function readSources(
  snapshot: SchemaSnapshot,
  files: readonly string[],
): Promise<{ sources: SchemaSource[]; unreadable: string[] }> {
  const sources: SchemaSource[] = [];
  const unreadable: string[] = [];
  for (const file of files) {
    const text = await snapshot.read(file);
    if (text === undefined) unreadable.push(file);
    else sources.push({ file, text });
  }
  return { sources, unreadable };
}

/** Builds the table resolver the extractors use to name a table. */
export function createTableResolver(input: {
  /** Drizzle schema objects, keyed by the variable a query names them with. */
  readonly drizzle: readonly DrizzleTableDeclaration[];
  /** Prisma models, keyed by the lower-cased model name the client uses. */
  readonly prismaModels: ReadonlyMap<string, string>;
}): TableResolver {
  /** Variable → table, with the names that mean two things left out entirely. */
  const byName = new Map<string, string>();
  const ambiguous = new Set<string>();
  for (const declaration of input.drizzle) {
    const existing = byName.get(declaration.variable);
    if (existing !== undefined && existing !== declaration.table) {
      ambiguous.add(declaration.variable);
      continue;
    }
    byName.set(declaration.variable, declaration.table);
  }
  /** The same, scoped to the file the declaration is in, which always wins. */
  const byFile = new Map<string, string>();
  for (const declaration of input.drizzle) {
    byFile.set(scopedKey(declaration.file, declaration.variable), declaration.table);
  }

  return {
    byVariable(file: string, variable: string): string | undefined {
      const local = byFile.get(scopedKey(file, variable));
      if (local !== undefined) return local;
      // Two schema files declaring the same variable name differently is not a
      // resolution; it is a reason to say "unresolved".
      if (ambiguous.has(variable)) return undefined;
      return byName.get(variable);
    },
    byModel(model: string): string | undefined {
      return input.prismaModels.get(model.toLowerCase());
    },
  };
}

/** Keys a declaration by the file it lives in; `` cannot occur in either part. */
function scopedKey(file: string, variable: string): string {
  return `${file}${String.fromCharCode(31)}${variable}`;
}

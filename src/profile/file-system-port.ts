/**
 * The filesystem surface phase 0 needs, declared structurally.
 *
 * Deliberately a *subset* of `FileSystem` in `src/ports/file-system.ts`: the
 * real port is assignable to it without knowing it exists, a test double only
 * has to implement three methods, and the profile package still imports nothing
 * from `node:fs`.
 */
export interface ProfileFileSystem {
  /** Reads a file as UTF-8; rejects when it does not exist or is not readable. */
  readFile(path: string): Promise<string>;
  /** True when the path exists. */
  exists(path: string): Promise<boolean>;
  /** Lists one directory. Symlinked directories report `isDirectory: false` and are not followed. */
  readDir(path: string): Promise<readonly ProfileDirEntry[]>;
}

/** One entry of a directory listing, typed so the walk needs no second call per entry. */
export interface ProfileDirEntry {
  readonly name: string;
  readonly isFile: boolean;
  readonly isDirectory: boolean;
}

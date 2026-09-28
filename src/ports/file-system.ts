/**
 * Filesystem seam.
 *
 * This is the only module allowed to import `node:fs` / `node:fs/promises` or
 * to reach for `Bun.file`. Everything else takes a `FileSystem` as an argument,
 * which is what makes the rest of the pipeline testable without a disk.
 */

import { constants } from "node:fs";
import * as fsp from "node:fs/promises";
import { basename, dirname, join } from "node:path";

/** Metadata about an existing path; `stat` follows symlinks, so a link reports its target. */
export interface FileStat {
  /** Size in bytes. */
  readonly size: number;
  /** Last modification time, epoch milliseconds. */
  readonly mtimeMs: number;
  readonly isFile: boolean;
  readonly isDirectory: boolean;
}

/** One entry of a directory listing, typed without a second `stat` call. */
export interface DirEntry {
  readonly name: string;
  readonly isFile: boolean;
  readonly isDirectory: boolean;
  readonly isSymbolicLink: boolean;
}

/** Options for {@link FileSystem.glob}; defaults match `Bun.Glob` except that files-only is on. */
export interface GlobOptions {
  readonly cwd?: string;
  readonly absolute?: boolean;
  readonly onlyFiles?: boolean;
  readonly dot?: boolean;
  readonly followSymlinks?: boolean;
}

/** Options for {@link FileSystem.writeFile}. */
export interface WriteFileOptions {
  /** Permission bits for the created file. Default 0o666 (umask applies). */
  readonly mode?: number;
  /** Create the parent directory when missing. Default true. */
  readonly ensureDir?: boolean;
}

/** Options for {@link FileSystem.remove}. */
export interface RemoveOptions {
  /** Delete directories and their contents. Default true. */
  readonly recursive?: boolean;
}

/** The filesystem operations Sentinel needs; implement it to fake a disk in tests. */
export interface FileSystem {
  /** Reads a whole file as UTF-8 text. */
  readFile(path: string): Promise<string>;
  /** Reads a whole file as bytes (binaries, hashing, archives). */
  readFileBytes(path: string): Promise<Uint8Array>;
  /**
   * Writes a file atomically: temp file in the same directory, fsync, rename.
   * A reader either sees the previous content or the new one, never a partial file.
   */
  writeFile(path: string, data: string | Uint8Array, options?: WriteFileOptions): Promise<void>;
  /** Creates a directory and every missing parent; succeeds when it already exists. */
  mkdirp(path: string): Promise<void>;
  /** True when the path resolves to something that exists (follows symlinks). */
  exists(path: string): Promise<boolean>;
  /** Metadata for a path, or null when it does not exist. Other errors throw. */
  stat(path: string): Promise<FileStat | null>;
  /** Lists a directory, sorted by name so runs are reproducible. */
  readDir(path: string): Promise<DirEntry[]>;
  /** Expands one or more glob patterns into a sorted, de-duplicated list of paths. */
  glob(patterns: string | readonly string[], options?: GlobOptions): Promise<string[]>;
  /** Deletes a path; a missing path is not an error. */
  remove(path: string, options?: RemoveOptions): Promise<void>;
  /** Resolves symlinks and `..` to a canonical absolute path. */
  realpath(path: string): Promise<string>;
  /** True when the current process may execute the path (used by the tool installer). */
  isExecutable(path: string): Promise<boolean>;
  /** Sets permission bits, e.g. 0o755 on a downloaded tool binary. */
  chmod(path: string, mode: number): Promise<void>;
  /**
   * Reads lines `from`..`to`, 1-indexed and inclusive, without loading the whole
   * file: the stream is abandoned once `to` is passed. `to` may be Infinity to
   * read to EOF. A trailing CR is stripped so CRLF files yield clean snippets.
   * Out-of-range requests return fewer lines rather than throwing.
   */
  readLines(path: string, from: number, to: number): Promise<string[]>;
}

/** Suffix that marks an in-flight atomic write, so a crash leaves obvious debris. */
const TEMP_SUFFIX = ".sentinel-tmp";

/** Monotonic within a process; combined with pid and time it makes temp names unique. */
let tempCounter = 0;

/** Builds the sibling temp path an atomic write renames from. */
function tempPathFor(target: string): string {
  tempCounter += 1;
  const unique = `${process.pid.toString(36)}-${Date.now().toString(36)}-${tempCounter.toString(36)}`;
  return join(dirname(target), `.${basename(target)}.${unique}${TEMP_SUFFIX}`);
}

/** Node error codes that mean "this path is simply not there". */
function isMissing(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/**
 * fsync the directory so the rename itself is durable, not just the file bytes.
 * Not supported on every platform (Windows), and a best-effort flush is never
 * worth failing a write over.
 */
async function syncDirectory(dir: string): Promise<void> {
  let handle: fsp.FileHandle | undefined;
  try {
    handle = await fsp.open(dir, "r");
    await handle.sync();
  } catch {
    // Directory fsync is advisory; the rename already happened.
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Strips a single trailing CR left by CRLF line endings. */
function stripCarriageReturn(line: string): string {
  return line.endsWith("\r") ? line.slice(0, -1) : line;
}

/** Creates the real, disk-backed filesystem port. */
export function createFileSystem(): FileSystem {
  return {
    async readFile(path: string): Promise<string> {
      return await Bun.file(path).text();
    },

    async readFileBytes(path: string): Promise<Uint8Array> {
      return await Bun.file(path).bytes();
    },

    async writeFile(
      path: string,
      data: string | Uint8Array,
      options?: WriteFileOptions,
    ): Promise<void> {
      const dir = dirname(path);
      if (options?.ensureDir !== false) {
        await fsp.mkdir(dir, { recursive: true });
      }
      const temp = tempPathFor(path);
      try {
        // "wx" refuses to clobber: if the unique name somehow exists, fail loudly.
        const handle = await fsp.open(temp, "wx", options?.mode ?? 0o666);
        try {
          await handle.writeFile(data);
          await handle.sync();
        } finally {
          await handle.close();
        }
        await fsp.rename(temp, path);
      } catch (error) {
        await fsp.rm(temp, { force: true }).catch(() => undefined);
        throw error;
      }
      await syncDirectory(dir);
    },

    async mkdirp(path: string): Promise<void> {
      await fsp.mkdir(path, { recursive: true });
    },

    async exists(path: string): Promise<boolean> {
      try {
        await fsp.access(path, constants.F_OK);
        return true;
      } catch {
        return false;
      }
    },

    async stat(path: string): Promise<FileStat | null> {
      try {
        const stats = await fsp.stat(path);
        return {
          size: stats.size,
          mtimeMs: stats.mtimeMs,
          isFile: stats.isFile(),
          isDirectory: stats.isDirectory(),
        };
      } catch (error) {
        if (isMissing(error)) return null;
        throw error;
      }
    },

    async readDir(path: string): Promise<DirEntry[]> {
      const entries = await fsp.readdir(path, { withFileTypes: true });
      return entries
        .map((entry) => ({
          name: entry.name,
          isFile: entry.isFile(),
          isDirectory: entry.isDirectory(),
          isSymbolicLink: entry.isSymbolicLink(),
        }))
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    },

    async glob(patterns: string | readonly string[], options?: GlobOptions): Promise<string[]> {
      const list = typeof patterns === "string" ? [patterns] : patterns;
      const scanOptions = {
        cwd: options?.cwd ?? process.cwd(),
        absolute: options?.absolute ?? false,
        onlyFiles: options?.onlyFiles ?? true,
        dot: options?.dot ?? false,
        followSymlinks: options?.followSymlinks ?? false,
      };
      const seen = new Set<string>();
      for (const pattern of list) {
        for await (const match of new Bun.Glob(pattern).scan(scanOptions)) {
          seen.add(match);
        }
      }
      return [...seen].sort();
    },

    async remove(path: string, options?: RemoveOptions): Promise<void> {
      await fsp.rm(path, { recursive: options?.recursive ?? true, force: true });
    },

    async realpath(path: string): Promise<string> {
      return await fsp.realpath(path);
    },

    async isExecutable(path: string): Promise<boolean> {
      try {
        await fsp.access(path, constants.X_OK);
        return true;
      } catch {
        return false;
      }
    },

    async chmod(path: string, mode: number): Promise<void> {
      await fsp.chmod(path, mode);
    },

    async readLines(path: string, from: number, to: number): Promise<string[]> {
      if (!Number.isInteger(from) || from < 1) {
        throw new RangeError(`readLines: "from" must be a 1-indexed integer, got ${from}`);
      }
      if (!(Number.isInteger(to) || to === Number.POSITIVE_INFINITY) || to < from) {
        throw new RangeError(`readLines: "to" must be an integer >= from (${from}), got ${to}`);
      }

      const lines: string[] = [];
      const reader = Bun.file(path).stream().getReader();
      const decoder = new TextDecoder();
      let lineNumber = 1;
      let pending = "";

      try {
        while (lineNumber <= to) {
          const { done, value } = await reader.read();
          if (done) {
            pending += decoder.decode();
            break;
          }
          pending += decoder.decode(value, { stream: true });

          // Index-based scan: slicing per line would be quadratic on big chunks.
          let start = 0;
          while (lineNumber <= to) {
            const newline = pending.indexOf("\n", start);
            if (newline === -1) break;
            if (lineNumber >= from) {
              lines.push(stripCarriageReturn(pending.slice(start, newline)));
            }
            start = newline + 1;
            lineNumber += 1;
          }
          pending = pending.slice(start);
        }

        // A last line with no trailing newline is still a line.
        if (lineNumber <= to && lineNumber >= from && pending.length > 0) {
          lines.push(stripCarriageReturn(pending));
        }
      } finally {
        await reader.cancel().catch(() => undefined);
      }

      return lines;
    },
  };
}

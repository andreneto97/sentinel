import path from "node:path";
import type { ScanStats } from "../contracts/profile.ts";
import { scopeMatcher } from "../contracts/scope.ts";
import type { ProfileDirEntry, ProfileFileSystem } from "./file-system-port.ts";
import { toLines } from "./text.ts";

/**
 * Directories that never contain first-party source, and whose contents would
 * otherwise dominate both the walk and every content scan.
 */
export const DEFAULT_IGNORED_DIRECTORIES: readonly string[] = [
  ".cache",
  ".expo",
  ".git",
  ".next",
  ".nuxt",
  ".output",
  ".serverless",
  ".svelte-kit",
  ".turbo",
  ".venv",
  ".vercel",
  "__pycache__",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "Pods",
  "vendor",
];

/** File extensions treated as first-party JS/TS source by the content scans. */
export const SOURCE_EXTENSIONS: readonly string[] = [
  ".cjs",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".mts",
  ".ts",
  ".tsx",
];

/** Caps that keep a scan of a large repository bounded; every one is reported in `ScanStats`. */
export interface SnapshotLimits {
  /** Maximum number of source files a content scan will read. */
  readonly maxSourceFiles: number;
  /** Files larger than this are not read (minified bundles, vendored blobs). */
  readonly maxFileBytes: number;
  /** Maximum number of paths the directory walk will collect. */
  readonly maxFiles: number;
  /** Maximum directory nesting the walk descends into. */
  readonly maxDepth: number;
}

/** Default scan caps: generous enough for real backends, small enough to stay fast. */
export const DEFAULT_LIMITS: SnapshotLimits = {
  maxSourceFiles: 4000,
  maxFileBytes: 512_000,
  maxFiles: 200_000,
  maxDepth: 24,
};

/** Options accepted by `RepoSnapshot.create`. */
export interface SnapshotOptions {
  readonly ignoreDirectories?: readonly string[];
  readonly limits?: Partial<SnapshotLimits>;
  /**
   * `--path`: repo-relative subtrees or globs this snapshot *lists*.
   *
   * The walk still descends the whole repository and every file stays readable
   * through {@link RepoSnapshot.read} and {@link RepoSnapshot.has} — a scoped
   * run still has to be able to answer "does this repository have a lockfile",
   * and in a workspace layout the manifest that proves the stack sits above the
   * analysed subtree. What the scope narrows is enumeration: `files`,
   * `sourceFiles`, `filesNamed`, `filesMatching` and `grep` see the subtree
   * only, so a caller that walks the listing cannot accidentally produce a unit
   * outside the scope. Empty means the whole repository.
   */
  readonly scope?: readonly string[] | undefined;
}

/** One line of one file matched by `RepoSnapshot.grep`. */
export interface GrepHit {
  readonly file: string;
  /** 1-based, so it can go straight into a `CodeRef`. */
  readonly line: number;
  readonly text: string;
}

/** Options for `RepoSnapshot.grep`. */
export interface GrepOptions {
  /** Files to search; defaults to every JS/TS source file. */
  readonly files?: readonly string[];
  /** Maximum number of hits to return. */
  readonly limit?: number;
}

function isIgnored(relativePath: string, ignored: ReadonlySet<string>): boolean {
  const segments = relativePath.split("/");
  // The last segment is the file name; only directory segments are matched.
  for (let i = 0; i < segments.length - 1; i += 1) {
    const segment = segments[i];
    if (segment !== undefined && ignored.has(segment)) return true;
  }
  return false;
}

/**
 * One filtered listing of a repository, plus cached, capped file reads.
 *
 * Every detector shares a snapshot so the repository is walked once and each
 * file is read at most once, whatever number of detectors happen to want it.
 */
export class RepoSnapshot {
  readonly #fs: ProfileFileSystem;
  readonly #limits: SnapshotLimits;
  readonly #fileSet: ReadonlySet<string>;
  readonly #contents = new Map<string, string | undefined>();
  readonly #lines = new Map<string, readonly string[] | undefined>();
  #truncated = false;

  private constructor(
    fileSystem: ProfileFileSystem,
    readonly root: string,
    /**
     * Every non-ignored file the walk found, sorted, `/`-separated and relative
     * to `root` — the whole repository, whatever the scope says.
     */
    readonly allFiles: readonly string[],
    /** The scope's view of {@link allFiles}; the same list when unscoped. */
    readonly files: readonly string[],
    /** Repo-relative subtrees and globs this snapshot lists; empty is everything. */
    readonly scope: readonly string[],
    limits: SnapshotLimits,
  ) {
    this.#fs = fileSystem;
    this.#limits = limits;
    // Existence is a question about the repository, not about the scope: a
    // detector asking whether `prisma/schema.prisma` exists deserves the truth
    // even when the analysis covers `apps/api` alone.
    this.#fileSet = new Set(allFiles);
  }

  /** Walks `root` once through the filesystem port and returns the filtered listing. */
  static async create(
    fileSystem: ProfileFileSystem,
    root: string,
    options: SnapshotOptions = {},
  ): Promise<RepoSnapshot> {
    const ignored = new Set(options.ignoreDirectories ?? DEFAULT_IGNORED_DIRECTORIES);
    const limits: SnapshotLimits = { ...DEFAULT_LIMITS, ...options.limits };
    const files: string[] = [];
    // Breadth-first and iterative: ignored directories are skipped before they
    // are opened, which is the difference between reading a repository and
    // reading its `node_modules`.
    const queue: Array<{ relative: string; depth: number }> = [{ relative: "", depth: 0 }];
    let truncated = false;
    while (queue.length > 0) {
      const next = queue.shift();
      if (next === undefined) break;
      if (next.depth > limits.maxDepth) {
        truncated = true;
        continue;
      }
      let entries: readonly ProfileDirEntry[];
      try {
        entries = await fileSystem.readDir(
          next.relative === "" ? root : path.join(root, next.relative),
        );
      } catch {
        continue;
      }
      for (const entry of entries) {
        if (entry.isDirectory) {
          if (ignored.has(entry.name)) continue;
          queue.push({
            relative: next.relative === "" ? entry.name : `${next.relative}/${entry.name}`,
            depth: next.depth + 1,
          });
          continue;
        }
        if (!entry.isFile) continue;
        if (files.length >= limits.maxFiles) {
          truncated = true;
          break;
        }
        files.push(next.relative === "" ? entry.name : `${next.relative}/${entry.name}`);
      }
    }
    const kept = [...new Set(files.filter((file) => !isIgnored(file, ignored)))].sort();
    const scope = (options.scope ?? []).filter((entry) => entry.trim() !== "");
    const snapshot = new RepoSnapshot(
      fileSystem,
      root,
      kept,
      scope.length === 0 ? kept : kept.filter(scopeMatcher(scope)),
      scope,
      limits,
    );
    if (truncated) snapshot.markTruncated();
    return snapshot;
  }

  /** Records that a cap stopped the walk or a read; surfaced through `stats()`. */
  markTruncated(): void {
    this.#truncated = true;
  }

  /** Absolute path of a repo-relative path, for handing back to the filesystem port. */
  absolute(relativePath: string): string {
    return path.join(this.root, relativePath);
  }

  /** True when the repo contains exactly this path. */
  has(relativePath: string): boolean {
    return this.#fileSet.has(relativePath);
  }

  /** The first of `candidates` that exists, or `undefined`. */
  firstExisting(candidates: readonly string[]): string | undefined {
    return candidates.find((candidate) => this.#fileSet.has(candidate));
  }

  /** Every file whose base name equals `name`, at any depth. */
  filesNamed(name: string): string[] {
    return this.files.filter((file) => path.posix.basename(file) === name);
  }

  /** Every file whose repo-relative path matches `pattern`. */
  filesMatching(pattern: RegExp): string[] {
    return this.files.filter((file) => {
      pattern.lastIndex = 0;
      return pattern.test(file);
    });
  }

  /** The files of `paths` this snapshot walked; every file when `paths` is empty. */
  filesWithin(paths: readonly string[]): string[] {
    const entries = paths.filter((entry) => entry.trim() !== "");
    if (entries.length === 0) return [...this.allFiles];
    return this.allFiles.filter(scopeMatcher(entries));
  }

  /** Every JS/TS source file, in path order. */
  sourceFiles(): string[] {
    return this.files.filter((file) =>
      SOURCE_EXTENSIONS.includes(path.posix.extname(file).toLowerCase()),
    );
  }

  /** Reads a file through the port, cached; `undefined` when missing, unreadable or oversized. */
  async read(relativePath: string): Promise<string | undefined> {
    const cached = this.#contents.get(relativePath);
    if (cached !== undefined || this.#contents.has(relativePath)) return cached;
    let content: string | undefined;
    try {
      const raw = await this.#fs.readFile(this.absolute(relativePath));
      content = raw.length > this.#limits.maxFileBytes ? undefined : raw;
      if (content === undefined) this.#truncated = true;
    } catch {
      content = undefined;
    }
    this.#contents.set(relativePath, content);
    return content;
  }

  /** Reads a file and splits it into lines, cached. */
  async lines(relativePath: string): Promise<readonly string[] | undefined> {
    const cached = this.#lines.get(relativePath);
    if (cached !== undefined || this.#lines.has(relativePath)) return cached;
    const content = await this.read(relativePath);
    const split = content === undefined ? undefined : toLines(content);
    this.#lines.set(relativePath, split);
    return split;
  }

  /**
   * Line-oriented search over the repository.
   *
   * Line-oriented rather than whole-file, because every hit has to become a
   * `CodeRef` with a real line number — a match Sentinel cannot point at is of
   * no use to the phases that quote it.
   */
  async grep(pattern: RegExp, options: GrepOptions = {}): Promise<GrepHit[]> {
    const limit = options.limit ?? 200;
    const candidates = options.files ?? this.sourceFiles();
    const budget = Math.min(candidates.length, this.#limits.maxSourceFiles);
    if (candidates.length > budget) this.#truncated = true;
    const hits: GrepHit[] = [];
    for (let f = 0; f < budget; f += 1) {
      const file = candidates[f];
      if (file === undefined) continue;
      const lines = await this.lines(file);
      if (lines === undefined) continue;
      for (let i = 0; i < lines.length; i += 1) {
        const text = lines[i];
        if (text === undefined) continue;
        pattern.lastIndex = 0;
        if (!pattern.test(text)) continue;
        hits.push({ file, line: i + 1, text });
        if (hits.length >= limit) return hits;
      }
    }
    return hits;
  }

  /**
   * Accounting for the run: how much was seen, how much was actually read.
   *
   * `filesSeen` is this snapshot's *listing*, so a scoped snapshot reports the
   * subtree it lists rather than the repository it walked. The whole-repository
   * count is {@link allFiles}, and the scope that separates the two is
   * {@link scope} — a caller that reports one of these numbers has both.
   */
  stats(): ScanStats {
    let filesRead = 0;
    for (const content of this.#contents.values()) if (content !== undefined) filesRead += 1;
    return { filesSeen: this.files.length, filesRead, truncated: this.#truncated };
  }
}

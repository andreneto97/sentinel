/**
 * Shared types for the citation verifier: the narrow filesystem seam it
 * needs, the knobs that shape an extracted snippet, and the reasons a
 * citation can be rejected.
 */

/**
 * The narrow filesystem seam the verifier depends on. The real
 * `FileSystemPort` satisfies it structurally, so nothing here imports
 * `node:fs` (see the port discipline rule).
 */
export interface VerifyFileSystem {
  /** Raw bytes of a file; rejects when the path is missing or not readable as a file. */
  readBytes(path: string): Promise<Uint8Array>;
  /** Absolute path with every symlink resolved; rejects when the path does not exist. */
  realpath(path: string): Promise<string>;
}

/** Why a citation was refused. These are the only reasons the report can show. */
export type DropReason = "file-not-found" | "line-out-of-range" | "path-escape" | "binary-file";

/** Every drop reason, for building zeroed counters. */
export const DROP_REASONS: readonly DropReason[] = [
  "file-not-found",
  "line-out-of-range",
  "path-escape",
  "binary-file",
];

/** Everything the verifier needs to resolve a citation against the target repo. */
export interface VerifyContext {
  /** The filesystem seam; injected so verification is testable without disk. */
  readonly fs: VerifyFileSystem;
  /** Absolute path of the analysed repository. Nothing outside it may be cited. */
  readonly targetDir: string;
  /** Lines of context kept on each side of the cited line (default 3). */
  readonly contextLines?: number | undefined;
  /** Characters kept per snippet line before truncation (default 200). */
  readonly maxLineWidth?: number | undefined;
  /** Hard cap on snippet height, so a wide `endLine` cannot paste a file (default 24). */
  readonly maxSnippetLines?: number | undefined;
  /** Half-width of the window `fuzzyRelocate` searches (default 50). */
  readonly relocateWindow?: number | undefined;
  /** Columns a tab expands to when normalising a snippet (default 2). */
  readonly tabWidth?: number | undefined;
}

/** Defaults applied to every optional knob in `VerifyContext`. */
export const VERIFY_DEFAULTS = {
  contextLines: 3,
  maxLineWidth: 200,
  maxSnippetLines: 24,
  relocateWindow: 50,
  tabWidth: 2,
} as const;

/** The resolved settings of a context, with defaults filled in. */
export interface VerifySettings {
  contextLines: number;
  maxLineWidth: number;
  maxSnippetLines: number;
  relocateWindow: number;
  tabWidth: number;
}

/** Fills a context's optional knobs with their defaults. */
export function settingsOf(ctx: VerifyContext): VerifySettings {
  return {
    contextLines: ctx.contextLines ?? VERIFY_DEFAULTS.contextLines,
    maxLineWidth: ctx.maxLineWidth ?? VERIFY_DEFAULTS.maxLineWidth,
    maxSnippetLines: ctx.maxSnippetLines ?? VERIFY_DEFAULTS.maxSnippetLines,
    relocateWindow: ctx.relocateWindow ?? VERIFY_DEFAULTS.relocateWindow,
    tabWidth: ctx.tabWidth ?? VERIFY_DEFAULTS.tabWidth,
  };
}

/** Extra anchors a caller can give the relocation step (the audited unit's symbol). */
export interface RefHints {
  /** A symbol name the agent claimed the citation points at. */
  readonly symbol?: string | undefined;
}

import type { CodeRef } from "../contracts/findings.ts";
import { type DropReason, type RefHints, type VerifyContext, settingsOf } from "./context.ts";
import { type RepoPath, isInside, resolveRepoPath } from "./paths.ts";
import { buildNeedles, fuzzyRelocate, lineMatchesAnyNeedle } from "./relocate.ts";
import { extractSnippet } from "./snippet.ts";
import { decodeUtf8, looksBinary, splitLines } from "./text.ts";

/** A citation that resolved, with the snippet Sentinel read from disk. */
export interface VerifiedRef {
  readonly ok: true;
  /** A new ref: repo-relative path, proven line, snippet extracted here. */
  readonly ref: CodeRef;
  /** True when the line number had to be corrected to match the cited code. */
  readonly relocated: boolean;
}

/** A citation that did not resolve, and why. */
export interface UnverifiedRef {
  readonly ok: false;
  readonly reason: DropReason;
  readonly detail: string;
}

/** The outcome of verifying one citation. */
export type CodeRefVerification = VerifiedRef | UnverifiedRef;

/** A file read once and reused across every citation that points at it. */
export type LoadedFile = { readonly ok: true; readonly lines: string[] } | UnverifiedRef;

/** Per-run memo of file reads, so a batch of findings touches each file once. */
export interface VerifyCache {
  readonly files: Map<string, LoadedFile>;
  /** The target directory with symlinks resolved; filled on first use. */
  root: string | null;
}

/** Creates an empty cache to share across a batch of verifications. */
export function createVerifyCache(): VerifyCache {
  return { files: new Map<string, LoadedFile>(), root: null };
}

/** Resolves the target directory once, following symlinks. */
async function resolveRoot(ctx: VerifyContext, cache: VerifyCache): Promise<string | null> {
  if (cache.root !== null) return cache.root;
  try {
    cache.root = await ctx.fs.realpath(ctx.targetDir);
  } catch {
    return null;
  }
  return cache.root;
}

/** Reads a file through the port, rejecting links out of the repo and binaries. */
async function readFile(
  ctx: VerifyContext,
  cache: VerifyCache,
  repo: RepoPath,
): Promise<LoadedFile> {
  const root = await resolveRoot(ctx, cache);
  if (root === null) {
    return { ok: false, reason: "file-not-found", detail: "target directory does not resolve" };
  }

  let real: string;
  try {
    real = await ctx.fs.realpath(repo.absolute);
  } catch {
    return { ok: false, reason: "file-not-found", detail: `${repo.relative} does not exist` };
  }
  // A symlink inside the repo can still point out of it; the link target is what
  // would be read, so containment is re-checked after resolution.
  if (!isInside(root, real)) {
    return {
      ok: false,
      reason: "path-escape",
      detail: `${repo.relative} links outside the target directory`,
    };
  }

  let bytes: Uint8Array;
  try {
    bytes = await ctx.fs.readBytes(repo.absolute);
  } catch {
    return { ok: false, reason: "file-not-found", detail: `${repo.relative} is not readable` };
  }
  if (looksBinary(bytes)) {
    return { ok: false, reason: "binary-file", detail: `${repo.relative} is binary` };
  }
  return { ok: true, lines: splitLines(decodeUtf8(bytes)) };
}

/** Reads a file at most once per cache. */
async function loadFile(
  ctx: VerifyContext,
  cache: VerifyCache,
  repo: RepoPath,
): Promise<LoadedFile> {
  const cached = cache.files.get(repo.relative);
  if (cached !== undefined) return cached;
  const loaded = await readFile(ctx, cache, repo);
  cache.files.set(repo.relative, loaded);
  return loaded;
}

/** Joins the caller's note with Sentinel's own, so neither is lost. */
function mergeNote(existing: string | undefined, added: string | null): string | undefined {
  const parts = [existing?.trim(), added].filter(
    (part): part is string => part !== undefined && part !== null && part !== "",
  );
  return parts.length === 0 ? undefined : parts.join(" · ");
}

/**
 * Proves a citation points at real code and returns a new ref whose snippet was
 * read from disk. Any snippet supplied by the caller is used only as a
 * relocation anchor and is always overwritten.
 */
export async function verifyCodeRef(
  ref: CodeRef,
  ctx: VerifyContext,
  hints: RefHints = {},
  cache: VerifyCache = createVerifyCache(),
): Promise<CodeRefVerification> {
  const resolved = resolveRepoPath(ref.file, ctx.targetDir);
  if (!resolved.ok) return { ok: false, reason: resolved.reason, detail: resolved.detail };

  const loaded = await loadFile(ctx, cache, resolved.value);
  if (!loaded.ok) return loaded;

  const settings = settingsOf(ctx);
  const lines = loaded.lines;
  if (lines.length === 0) {
    return {
      ok: false,
      reason: "line-out-of-range",
      detail: `${resolved.value.relative} is empty`,
    };
  }

  const needles = buildNeedles({ snippet: ref.snippet, symbol: hints.symbol }, settings.tabWidth);
  const inRange = ref.line >= 1 && ref.line <= lines.length;
  const anchored =
    inRange &&
    (needles.length === 0 ||
      lineMatchesAnyNeedle(lines[ref.line - 1] ?? "", needles, settings.tabWidth));

  let line = ref.line;
  let relocated = false;
  if (!anchored) {
    const moved = fuzzyRelocate({
      lines,
      line: ref.line,
      needles,
      window: settings.relocateWindow,
      tabWidth: settings.tabWidth,
    });
    if (moved !== null) {
      line = moved.line;
      relocated = true;
    } else if (!inRange) {
      return {
        ok: false,
        reason: "line-out-of-range",
        detail: `${resolved.value.relative} has ${lines.length} lines, citation is line ${ref.line}`,
      };
    }
    // Line exists but nothing anchors it: keep it. An unmatched snippet is not
    // proof the line is wrong — the model may have paraphrased what it read.
  }

  const shifted = ref.endLine === undefined ? undefined : ref.endLine + (line - ref.line);
  const endLine =
    shifted === undefined || shifted <= line ? undefined : Math.min(shifted, lines.length);
  const note = mergeNote(ref.note, relocated ? `relocated from line ${ref.line}` : null);

  const verified: CodeRef = {
    file: resolved.value.relative,
    line,
    snippet: extractSnippet({
      lines,
      line,
      endLine,
      contextLines: settings.contextLines,
      maxLineWidth: settings.maxLineWidth,
      maxSnippetLines: settings.maxSnippetLines,
      tabWidth: settings.tabWidth,
    }),
    ...(endLine !== undefined && endLine > line ? { endLine } : {}),
    ...(note !== undefined ? { note } : {}),
  };
  return { ok: true, ref: verified, relocated };
}

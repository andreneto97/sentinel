/**
 * Source slicing — the primitive every audit prompt is built from.
 *
 * Sentinel feeds the code to the model; the model never reads files. A slice is
 * the enclosing function or block of a citation, taken from disk, with its real
 * line numbers preserved so the model can only cite lines it was shown. Two
 * properties matter more than anything else here:
 *
 * - **It never exceeds its budget.** A prompt is assembled from dozens of
 *   slices, so a single pathological file cannot be allowed to eat the context
 *   window.
 * - **Truncation is explicit.** Every cut is marked with an elision line that
 *   states how many lines were removed, so a model cannot mistake a cut for the
 *   end of a function and conclude that the missing ownership check is absent.
 *
 * Block resolution is lexical, not syntactic: a small scanner tracks strings,
 * template interpolations, comments and regular expressions so that braces in
 * text never move a block boundary. That is enough to find `{ … }` extents and
 * costs no subprocess, which matters when every unit in a repository is sliced.
 */

import type { CodeRef } from "../contracts/findings.ts";
import { type DropReason, isInside, resolveRepoPath } from "../verify/index.ts";
import {
  decodeUtf8,
  expandTabs,
  leadingSpaces,
  looksBinary,
  splitLines,
  truncate,
} from "../verify/text.ts";

/** The filesystem operations a slice needs; the real port satisfies it structurally. */
export interface SliceFileSystem {
  /** Raw bytes of a file; rejects when the path is missing or not readable. */
  readFileBytes(path: string): Promise<Uint8Array>;
  /** Absolute path with every symlink resolved; rejects when the path does not exist. */
  realpath(path: string): Promise<string>;
}

/** Hard limits on one rendered slice. Every one of them is enforced, never approximated. */
export interface SliceBudget {
  /** Maximum rendered lines, counting the header and every elision marker. */
  readonly maxLines: number;
  /** Maximum rendered size in UTF-8 bytes, counting the header. */
  readonly maxBytes: number;
  /** Characters kept per source line before it is truncated. */
  readonly maxLineWidth: number;
  /** Columns a tab expands to. */
  readonly tabWidth: number;
}

/**
 * The default budget: enough for a long route handler, small enough that a
 * batch of forty units still fits in one prompt.
 */
export const SLICE_BUDGET: SliceBudget = {
  maxLines: 120,
  maxBytes: 12_000,
  maxLineWidth: 200,
  tabWidth: 2,
};

/** Everything `sliceCode` needs to resolve and read a citation. */
export interface SliceContext {
  /** The filesystem seam; injected so slicing is testable without a disk. */
  readonly fs: SliceFileSystem;
  /** Absolute path of the analysed repository. Nothing outside it can be sliced. */
  readonly targetDir: string;
  /** Overrides for any budget knob; anything omitted keeps its {@link SLICE_BUDGET} value. */
  readonly budget?: Partial<SliceBudget> | undefined;
  /** Shared across a batch so a file with twenty handlers is read once. */
  readonly cache?: SourceCache | undefined;
}

/** A file read once, with the lexical structure every slice of it reuses. */
export interface LoadedSource {
  /** Repo-relative POSIX path. */
  readonly file: string;
  /** Line terminators already stripped; index 0 is line 1. */
  readonly lines: readonly string[];
  readonly structure: SourceStructure;
}

/** Why a file could not be sliced; the same vocabulary the citation verifier uses. */
export interface SliceFailure {
  readonly ok: false;
  readonly reason: DropReason;
  readonly detail: string;
}

/** A file load that succeeded. */
export interface LoadedSourceResult {
  readonly ok: true;
  readonly source: LoadedSource;
}

/** The outcome of reading a file for slicing. */
export type SourceLoad = LoadedSourceResult | SliceFailure;

/** Per-run memo of file reads, so a batch of units touches each file once. */
export interface SourceCache {
  readonly files: Map<string, SourceLoad>;
  /** The target directory with symlinks resolved; filled on first use. */
  root: string | null;
}

/** Creates an empty cache to share across every slice of one batch. */
export function createSourceCache(): SourceCache {
  return { files: new Map<string, SourceLoad>(), root: null };
}

/** One `{ … }` extent found by the lexical scanner, 1-based and inclusive. */
export interface SourceBlock {
  readonly startLine: number;
  readonly endLine: number;
  /** Nesting level of the opening brace; 0 for a top-level block. */
  readonly depth: number;
}

/** What the lexical scanner proved about a file, reused by every slice of it. */
export interface SourceStructure {
  /** Brace nesting at the start of each line; index 0 is line 1. */
  readonly braceDepth: readonly number[];
  /** Parenthesis and bracket nesting at the start of each line; index 0 is line 1. */
  readonly parenDepth: readonly number[];
  /** Every balanced brace block, ordered by closing line. */
  readonly blocks: readonly SourceBlock[];
}

/** A 1-based, inclusive line range. */
export interface LineRange {
  readonly startLine: number;
  readonly endLine: number;
}

/** A slice of a file, ready to be pasted into a prompt. */
export interface CodeSlice {
  /** Repo-relative POSIX path. */
  readonly file: string;
  /** First line of the resolved block, whether or not it survived the budget. */
  readonly startLine: number;
  /** Last line of the resolved block, whether or not it survived the budget. */
  readonly endLine: number;
  /** The line the citation pointed at. */
  readonly focusLine: number;
  /** Header comment, gutter-numbered source, and any elision markers. */
  readonly text: string;
  /** True when at least one line was elided. */
  readonly truncated: boolean;
  /** How many lines of the block are not in `text`. */
  readonly elidedLines: number;
  /** Size of `text` in UTF-8 bytes; never above the budget. */
  readonly bytes: number;
}

/** A slice that was produced. */
export interface SlicedResult {
  readonly ok: true;
  readonly slice: CodeSlice;
}

/** The outcome of slicing one citation. */
export type SliceResult = SlicedResult | SliceFailure;

/** How far above a block the slicer will climb to pick up a signature or decorators. */
const MAX_HEADROOM_LINES = 24;

/** Share of the leftover budget spent on the head of a block before its tail. */
const HEAD_SHARE = 0.6;

/** Lines kept below a citation that has no enclosing block and no continuation. */
const ORPHAN_TRAILING_LINES = 8;

/** Fills a partial budget with the defaults, clamping every knob to something renderable. */
export function budgetOf(overrides: Partial<SliceBudget> | undefined): SliceBudget {
  const merged = { ...SLICE_BUDGET, ...overrides };
  return {
    maxLines: Math.max(1, Math.floor(merged.maxLines)),
    maxBytes: Math.max(1, Math.floor(merged.maxBytes)),
    maxLineWidth: Math.max(1, Math.floor(merged.maxLineWidth)),
    tabWidth: Math.max(1, Math.floor(merged.tabWidth)),
  };
}

/** The elision line that marks a cut, so a model cannot read one as the end of a function. */
export function elisionMarker(lines: number): string {
  return `// … ${lines} line${lines === 1 ? "" : "s"} elided …`;
}

/** The header comment naming the file and the line range the slice came from. */
export function sliceHeader(file: string, range: LineRange): string {
  return `// ${file}:${range.startLine}-${range.endLine}`;
}

/** Characters after which a `/` opens a regular expression rather than dividing. */
const REGEX_PRECEDERS = new Set([
  "(",
  ",",
  "=",
  ":",
  "[",
  "!",
  "&",
  "|",
  "?",
  "{",
  "}",
  ";",
  "+",
  "-",
  "*",
  "%",
  "~",
  "^",
  "<",
  ">",
  "/",
]);

/** Keywords after which a `/` opens a regular expression rather than dividing. */
const REGEX_KEYWORDS = new Set([
  "return",
  "typeof",
  "instanceof",
  "in",
  "of",
  "new",
  "delete",
  "void",
  "case",
  "do",
  "else",
  "yield",
  "await",
]);

/** Lexer states; `code` also covers the inside of a `${ … }` interpolation. */
type ScanMode =
  | "code"
  | "line-comment"
  | "block-comment"
  | "single"
  | "double"
  | "template"
  | "regex";

/**
 * Tracks brace and parenthesis nesting per line, ignoring anything inside a
 * string, comment, template literal or regular expression.
 *
 * This is what stops `db.query("SELECT … {")` or a `/\{/` pattern from moving a
 * block boundary, which would make a slice start or end in the wrong place —
 * the one failure mode that would silently feed the model the wrong function.
 */
export function scanSource(lines: readonly string[]): SourceStructure {
  const braceDepth: number[] = [];
  const parenDepth: number[] = [];
  const blocks: SourceBlock[] = [];
  const openBraces: Array<{ line: number; depth: number }> = [];
  /** Brace depth each open `${` must fall back to before the template resumes. */
  const interpolations: number[] = [];

  let mode: ScanMode = "code";
  let brace = 0;
  let paren = 0;
  let previous = "";
  let word = "";
  /** True while the regex scanner sits inside a `[ … ]` character class. */
  let inCharClass = false;

  for (let index = 0; index < lines.length; index += 1) {
    braceDepth.push(brace);
    parenDepth.push(paren);
    const text = lines[index] ?? "";
    const lineNumber = index + 1;
    if (mode === "line-comment") mode = "code";

    for (let column = 0; column < text.length; column += 1) {
      const char = text[column] ?? "";
      const next = text[column + 1] ?? "";

      if (mode === "block-comment") {
        if (char === "*" && next === "/") {
          mode = "code";
          column += 1;
        }
        continue;
      }
      if (mode === "single" || mode === "double") {
        if (char === "\\") column += 1;
        else if ((mode === "single" && char === "'") || (mode === "double" && char === '"')) {
          mode = "code";
        }
        continue;
      }
      if (mode === "template") {
        if (char === "\\") column += 1;
        else if (char === "`") mode = "code";
        else if (char === "$" && next === "{") {
          interpolations.push(brace);
          brace += 1;
          mode = "code";
          column += 1;
        }
        continue;
      }
      if (mode === "regex") {
        if (char === "\\") column += 1;
        else if (inCharClass) {
          if (char === "]") inCharClass = false;
        } else if (char === "[") inCharClass = true;
        else if (char === "/") mode = "code";
        continue;
      }

      // Plain code from here down.
      if (char === "/" && next === "/") {
        mode = "line-comment";
        break;
      }
      if (char === "/" && next === "*") {
        mode = "block-comment";
        column += 1;
        continue;
      }
      if (char === "/") {
        if (previous === "" || REGEX_PRECEDERS.has(previous) || REGEX_KEYWORDS.has(word)) {
          mode = "regex";
          inCharClass = false;
          previous = "/";
          word = "";
          continue;
        }
      } else if (char === '"') {
        mode = "double";
      } else if (char === "'") {
        mode = "single";
      } else if (char === "`") {
        mode = "template";
      } else if (char === "{") {
        openBraces.push({ line: lineNumber, depth: brace });
        brace += 1;
      } else if (char === "}") {
        const interpolation = interpolations[interpolations.length - 1];
        if (interpolation !== undefined && brace === interpolation + 1) {
          interpolations.pop();
          brace = interpolation;
          mode = "template";
        } else {
          brace = Math.max(0, brace - 1);
          const open = openBraces.pop();
          if (open !== undefined) {
            blocks.push({ startLine: open.line, endLine: lineNumber, depth: open.depth });
          }
        }
      } else if (char === "(" || char === "[") {
        paren += 1;
      } else if (char === ")" || char === "]") {
        paren = Math.max(0, paren - 1);
      }

      if (!/\s/.test(char)) previous = char;
      word = /[A-Za-z_$]/.test(char) ? `${word}${char}` : "";
    }
  }

  // A file that ends inside an unclosed block still has to be sliceable.
  for (const open of openBraces) {
    blocks.push({ startLine: open.line, endLine: lines.length, depth: open.depth });
  }
  blocks.sort((a, b) => a.startLine - b.startLine || a.endLine - b.endLine || a.depth - b.depth);
  return { braceDepth, parenDepth, blocks };
}

/** Nesting depth at the start of a 1-based line, saturating outside the file. */
function depthAt(depths: readonly number[], line: number): number {
  if (line <= 0) return depths[0] ?? 0;
  if (line > depths.length) return depths[depths.length - 1] ?? 0;
  return depths[line - 1] ?? 0;
}

/**
 * Climbs above a range to pick up what belongs to it: an unfinished signature
 * (`export async function GET(\n  req,\n) {`) and any decorators sitting
 * directly on top of it, which for NestJS carry the route and its guards.
 */
function extendUpwards(
  lines: readonly string[],
  structure: SourceStructure,
  startLine: number,
): number {
  let start = startLine;
  const floor = Math.max(1, startLine - MAX_HEADROOM_LINES);
  while (start > floor && depthAt(structure.parenDepth, start) > 0) start -= 1;
  while (start > floor) {
    const above = (lines[start - 2] ?? "").trim();
    if (!above.startsWith("@")) break;
    start -= 1;
  }
  return start;
}

/**
 * The extent of the statement starting on `line`, following its open parentheses
 * and braces down. Used when a citation has no enclosing block at all, so a
 * top-level `router.get("/x", …)` still slices as one statement instead of
 * dragging in its neighbours.
 */
function statementExtent(structure: SourceStructure, line: number, lineCount: number): number {
  const baseParen = depthAt(structure.parenDepth, line);
  const baseBrace = depthAt(structure.braceDepth, line);
  let end = line;
  while (
    end < lineCount &&
    (depthAt(structure.parenDepth, end + 1) > baseParen ||
      depthAt(structure.braceDepth, end + 1) > baseBrace)
  ) {
    end += 1;
  }
  return end;
}

/**
 * Resolves the block a citation belongs to.
 *
 * An explicit `endLine` is taken as given — it came from a structural query, so
 * it already bounds the construct — and only grows upwards over a signature or
 * decorators. A bare line resolves to its innermost enclosing `{ … }`, and a
 * line with no enclosing block resolves to its own statement.
 */
export function resolveBlock(
  lines: readonly string[],
  structure: SourceStructure,
  line: number,
  endLine?: number | undefined,
): LineRange {
  const lineCount = lines.length;
  const focus = Math.min(Math.max(1, line), Math.max(1, lineCount));
  if (endLine !== undefined && endLine > focus) {
    const end = Math.min(endLine, lineCount);
    return { startLine: extendUpwards(lines, structure, focus), endLine: end };
  }

  let innermost: SourceBlock | undefined;
  for (const block of structure.blocks) {
    if (block.startLine > focus) break;
    if (block.endLine < focus) continue;
    if (innermost === undefined || block.depth >= innermost.depth) innermost = block;
  }
  if (innermost !== undefined) {
    return {
      startLine: extendUpwards(lines, structure, innermost.startLine),
      endLine: Math.min(innermost.endLine, lineCount),
    };
  }

  const start = extendUpwards(lines, structure, focus);
  const extent = statementExtent(structure, focus, lineCount);
  const end = extent > focus ? extent : Math.min(lineCount, focus + ORPHAN_TRAILING_LINES);
  return { startLine: start, endLine: end };
}

/** Merges ranges that overlap or touch, so two kept windows never print a zero-line elision. */
function mergeRanges(ranges: readonly LineRange[]): LineRange[] {
  const sorted = [...ranges].sort((a, b) => a.startLine - b.startLine);
  const merged: LineRange[] = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (last !== undefined && range.startLine <= last.endLine + 1) {
      merged[merged.length - 1] = {
        startLine: last.startLine,
        endLine: Math.max(last.endLine, range.endLine),
      };
      continue;
    }
    merged.push(range);
  }
  return merged;
}

/**
 * Chooses which lines of a block survive a line budget: the citation always,
 * then the head of the block (its signature and guard clauses), then its tail
 * (the closing lines), then whatever is left grows the window around the
 * citation. Deterministic for a given block and budget.
 */
export function planSegments(
  block: LineRange,
  focus: LineRange,
  contentBudget: number,
): LineRange[] {
  const total = block.endLine - block.startLine + 1;
  if (contentBudget <= 0) return [];
  if (total <= contentBudget) return [block];

  const focusStart = Math.min(Math.max(focus.startLine, block.startLine), block.endLine);
  const focusEnd = Math.min(Math.max(focus.endLine, focusStart), block.endLine);
  const window: LineRange = {
    startLine: focusStart,
    endLine: Math.min(focusEnd, focusStart + contentBudget - 1),
  };

  const remaining = contentBudget - (window.endLine - window.startLine + 1);
  const above = window.startLine - block.startLine;
  const below = block.endLine - window.endLine;
  let head = Math.max(0, Math.min(Math.ceil(remaining * HEAD_SHARE), above));
  let tail = Math.max(0, Math.min(remaining - head, below));
  // Whatever one side cannot use is spent on the other, never left unspent.
  head = Math.min(above, head + Math.max(0, remaining - head - tail));
  tail = Math.min(below, tail + Math.max(0, remaining - head - tail));

  const kept: LineRange[] = [window];
  if (head > 0) kept.push({ startLine: block.startLine, endLine: block.startLine + head - 1 });
  if (tail > 0) kept.push({ startLine: block.endLine - tail + 1, endLine: block.endLine });
  return mergeRanges(kept);
}

/** UTF-8 size of a string, which is what the byte budget is measured in. */
function byteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

/** Last resort: cuts a rendered slice at a line boundary so the byte budget holds. */
function hardTruncate(text: string, maxBytes: number): string {
  if (byteLength(text) <= maxBytes) return text;
  const lines = text.split("\n");
  let kept = "";
  for (const line of lines) {
    const candidate = kept === "" ? line : `${kept}\n${line}`;
    if (byteLength(candidate) > maxBytes) break;
    kept = candidate;
  }
  if (kept !== "") return kept;
  // Even the first line is too wide: cut it on a character boundary.
  let cut = text;
  while (cut.length > 0 && byteLength(cut) > maxBytes) cut = cut.slice(0, -1);
  return cut;
}

/** Renders the kept segments as a header plus gutter-numbered lines and elision markers. */
function render(
  file: string,
  lines: readonly string[],
  block: LineRange,
  segments: readonly LineRange[],
  budget: SliceBudget,
): { text: string; shown: number } {
  const header = sliceHeader(file, block);
  if (segments.length === 0) return { text: header, shown: 0 };

  const body: string[] = [];
  for (const segment of segments) {
    for (let n = segment.startLine; n <= segment.endLine; n += 1) {
      body.push(expandTabs(lines[n - 1] ?? "", budget.tabWidth));
    }
  }
  const indents = body.map(leadingSpaces).filter((value): value is number => value !== null);
  const dedent = indents.length === 0 ? 0 : Math.min(...indents);
  const gutter = String(block.endLine).length;

  const out: string[] = [header];
  let shown = 0;
  let cursor = 0;
  segments.forEach((segment, index) => {
    const previous = segments[index - 1];
    if (previous !== undefined) {
      out.push(elisionMarker(segment.startLine - previous.endLine - 1));
    }
    for (let n = segment.startLine; n <= segment.endLine; n += 1) {
      const content = body[cursor] ?? "";
      cursor += 1;
      shown += 1;
      out.push(
        `${String(n).padStart(gutter)} | ${truncate(content.slice(dedent), budget.maxLineWidth)}`.trimEnd(),
      );
    }
  });
  const first = segments[0];
  const last = segments[segments.length - 1];
  if (first !== undefined && first.startLine > block.startLine) {
    out.splice(1, 0, elisionMarker(first.startLine - block.startLine));
  }
  if (last !== undefined && last.endLine < block.endLine) {
    out.push(elisionMarker(block.endLine - last.endLine));
  }
  return { text: out.join("\n"), shown };
}

/**
 * Renders a block under a budget, cutting lines out of the middle rather than
 * off the end and marking every cut. Pure, so the whole truncation contract is
 * testable without a filesystem.
 */
export function renderSlice(
  file: string,
  lines: readonly string[],
  block: LineRange,
  focus: LineRange,
  budget: SliceBudget,
): CodeSlice {
  const total = block.endLine - block.startLine + 1;
  let plan = planSegments(block, focus, Math.max(0, budget.maxLines - 1));
  let markers = countMarkers(block, plan);
  // The markers are rendered lines too, so the plan is redone once they are known.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const next = planSegments(block, focus, Math.max(0, budget.maxLines - 1 - markers));
    const nextMarkers = countMarkers(block, next);
    plan = next;
    if (nextMarkers === markers) break;
    markers = nextMarkers;
  }

  let drawn = render(file, lines, block, plan, budget);
  let content = Math.max(0, budget.maxLines - 1 - markers);
  while (byteLength(drawn.text) > budget.maxBytes && content > 1) {
    content = Math.max(1, content - Math.max(1, Math.floor(content / 4)));
    plan = planSegments(block, focus, content);
    drawn = render(file, lines, block, plan, budget);
  }
  const text = hardTruncate(drawn.text, budget.maxBytes);
  const shown = text === drawn.text ? drawn.shown : countRenderedLines(text);
  return {
    file,
    startLine: block.startLine,
    endLine: block.endLine,
    focusLine: focus.startLine,
    text,
    truncated: shown < total,
    elidedLines: Math.max(0, total - shown),
    bytes: byteLength(text),
  };
}

/** How many elision markers a plan needs: one per gap, plus the ends it does not reach. */
function countMarkers(block: LineRange, segments: readonly LineRange[]): number {
  if (segments.length === 0) return 0;
  let markers = segments.length - 1;
  const first = segments[0];
  const last = segments[segments.length - 1];
  if (first !== undefined && first.startLine > block.startLine) markers += 1;
  if (last !== undefined && last.endLine < block.endLine) markers += 1;
  return markers;
}

/** Counts the source lines left in a rendered slice after a hard byte cut. */
function countRenderedLines(text: string): number {
  let count = 0;
  for (const line of text.split("\n")) {
    if (/^\s*\d+ \|/.test(line)) count += 1;
  }
  return count;
}

/** Resolves the target directory once per cache, following symlinks. */
async function resolveRoot(ctx: SliceContext, cache: SourceCache): Promise<string | null> {
  if (cache.root !== null) return cache.root;
  try {
    cache.root = await ctx.fs.realpath(ctx.targetDir);
  } catch {
    return null;
  }
  return cache.root;
}

/** Reads a file through the port, refusing links out of the repository and binaries. */
async function readSource(
  ctx: SliceContext,
  cache: SourceCache,
  relative: string,
  absolute: string,
): Promise<SourceLoad> {
  const root = await resolveRoot(ctx, cache);
  if (root === null) {
    return { ok: false, reason: "file-not-found", detail: "target directory does not resolve" };
  }
  let real: string;
  try {
    real = await ctx.fs.realpath(absolute);
  } catch {
    return { ok: false, reason: "file-not-found", detail: `${relative} does not exist` };
  }
  if (!isInside(root, real)) {
    return { ok: false, reason: "path-escape", detail: `${relative} links outside the target` };
  }
  let bytes: Uint8Array;
  try {
    bytes = await ctx.fs.readFileBytes(absolute);
  } catch {
    return { ok: false, reason: "file-not-found", detail: `${relative} is not readable` };
  }
  if (looksBinary(bytes)) {
    return { ok: false, reason: "binary-file", detail: `${relative} is binary` };
  }
  const lines = splitLines(decodeUtf8(bytes));
  return { ok: true, source: { file: relative, lines, structure: scanSource(lines) } };
}

/**
 * Reads a repository file once and keeps its lexical structure, so every unit
 * in the same file is sliced from a single read.
 */
export async function loadSource(file: string, ctx: SliceContext): Promise<SourceLoad> {
  const resolved = resolveRepoPath(file, ctx.targetDir);
  if (!resolved.ok) return { ok: false, reason: resolved.reason, detail: resolved.detail };
  const cache = ctx.cache ?? createSourceCache();
  const cached = cache.files.get(resolved.value.relative);
  if (cached !== undefined) return cached;
  const loaded = await readSource(ctx, cache, resolved.value.relative, resolved.value.absolute);
  cache.files.set(resolved.value.relative, loaded);
  return loaded;
}

/**
 * Extracts the enclosing function or block of a citation from disk, numbered,
 * budgeted, and with every cut marked. This is the only way code reaches an
 * audit prompt.
 */
export async function sliceCode(ref: CodeRef, ctx: SliceContext): Promise<SliceResult> {
  const loaded = await loadSource(ref.file, ctx);
  if (!loaded.ok) return loaded;
  const { source } = loaded;
  if (source.lines.length === 0) {
    return { ok: false, reason: "line-out-of-range", detail: `${source.file} is empty` };
  }
  if (ref.line < 1 || ref.line > source.lines.length) {
    return {
      ok: false,
      reason: "line-out-of-range",
      detail: `${source.file} has ${source.lines.length} lines, citation is line ${ref.line}`,
    };
  }
  const budget = budgetOf(ctx.budget);
  const block = resolveBlock(source.lines, source.structure, ref.line, ref.endLine);
  const focus: LineRange = {
    startLine: ref.line,
    endLine: Math.min(Math.max(ref.endLine ?? ref.line, ref.line), source.lines.length),
  };
  return { ok: true, slice: renderSlice(source.file, source.lines, block, focus, budget) };
}

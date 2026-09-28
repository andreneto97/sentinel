/**
 * Text the PDF can actually print.
 *
 * Two jobs live here. The first is the snippet: `src/verify/snippet.ts` already
 * renders a gutter (`> 26 | const x = ...`), and the report must show those
 * numbers as a gutter rather than as part of the code, so this module parses
 * that format back apart. The second is safety — the base-14 fonts encode
 * WinAnsi and nothing else, and a character outside it would be dropped
 * silently, turning "não" into "no" inside a quoted line of evidence. Every
 * string the report draws goes through {@link toWinAnsi} first, where an
 * unrepresentable character becomes a visible `?`.
 */

import { MONO_ADVANCE } from "./theme.ts";

/**
 * Characters WinAnsi encodes above Latin-1 — the typographic block at 0x80-0x9F.
 *
 * Everything at or below U+00FF is in the encoding already (except the control
 * range, which is replaced), so this set is the whole exception list.
 */
const WIN_ANSI_EXTRA = new Set([
  "€", // euro
  "‚",
  "ƒ",
  "„",
  "…", // ellipsis
  "†",
  "‡",
  "ˆ",
  "‰",
  "Š",
  "‹",
  "Œ",
  "Ž",
  "‘",
  "’", // curly quotes
  "“",
  "”",
  "•", // bullet
  "–", // en dash
  "—", // em dash
  "˜",
  "™", // trademark
  "š",
  "›",
  "œ",
  "ž",
  "Ÿ",
]);

/** What an unrepresentable character becomes: visible, so nothing is lost silently. */
const REPLACEMENT = "?";

/**
 * Makes a string safe for the base-14 fonts.
 *
 * Tabs become spaces (a PDF has no tab stops), other control characters are
 * dropped, newlines are kept because pdfkit honours them, and anything the
 * encoding cannot represent — CJK, emoji, box drawing — becomes `?`. Surrogate
 * pairs are replaced as one character rather than two.
 */
export function toWinAnsi(value: string, tabWidth = 2): string {
  let out = "";
  for (const char of value) {
    if (char === "\n") {
      out += char;
      continue;
    }
    if (char === "\t") {
      out += " ".repeat(tabWidth);
      continue;
    }
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) continue;
    if (code <= 0xff || WIN_ANSI_EXTRA.has(char)) {
      out += char;
      continue;
    }
    out += REPLACEMENT;
  }
  return out;
}

/** One line of a snippet, split into what the gutter shows and what the code says. */
export interface SnippetLine {
  /** The line number as the snippet states it, or an empty string on a wrap. */
  readonly gutter: string;
  readonly code: string;
  /** True on the line the finding cites — the one the `>` marker points at. */
  readonly cited: boolean;
  /** True when this row continues the previous one because it was too wide. */
  readonly wrapped: boolean;
}

/** The gutter format `src/verify/snippet.ts` writes, and this module reads back. */
const GUTTER = /^([>\s])\s*(\d+)\s\|(?:\s(.*))?$/;

/**
 * Parses a verified snippet into gutter-and-code rows, wrapping over-wide code.
 *
 * A snippet that does not carry the expected gutter — a hand-written fixture, a
 * future extractor — is still rendered: its lines are numbered from
 * `firstLine`, and nothing is dropped. Wrapping, rather than truncating, is
 * deliberate: the snippet is the evidence, and a cut-off line is evidence the
 * reader cannot check.
 */
export function parseSnippet(
  snippet: string,
  options: { readonly maxChars: number; readonly firstLine?: number; readonly maxLines?: number },
): SnippetLine[] {
  const source = toWinAnsi(snippet).replace(/\n+$/, "");
  if (source === "") return [];

  const raw = source.split("\n");
  const rows: SnippetLine[] = [];
  let fallbackNumber = options.firstLine ?? 1;

  for (const line of raw) {
    const match = GUTTER.exec(line);
    const cited = match?.[1] === ">";
    const gutter = match?.[2] ?? String(fallbackNumber);
    const code = match === null ? line : (match[3] ?? "");
    if (match === null) fallbackNumber += 1;

    const pieces = wrapMonospace(code, options.maxChars);
    pieces.forEach((piece, index) => {
      rows.push({
        gutter: index === 0 ? gutter : "",
        code: piece,
        cited,
        wrapped: index > 0,
      });
    });
  }

  const limit = options.maxLines;
  if (limit !== undefined && rows.length > limit) {
    const kept = rows.slice(0, limit);
    kept.push({
      gutter: "",
      code: `... ${rows.length - limit} more line(s) in the file`,
      cited: false,
      wrapped: true,
    });
    return kept;
  }
  return rows;
}

/**
 * Breaks a line of code at a character budget, preferring a space.
 *
 * Code has no words, so a greedy word wrap would leave half a line empty on a
 * long URL or a long SQL statement; the break only respects a space when one
 * falls in the last quarter of the budget.
 */
export function wrapMonospace(line: string, maxChars: number): string[] {
  const budget = Math.max(8, Math.floor(maxChars));
  if (line.length <= budget) return [line];

  const pieces: string[] = [];
  let rest = line;
  while (rest.length > budget) {
    const window = rest.slice(0, budget);
    const space = window.lastIndexOf(" ");
    const cut = space > budget * 0.75 ? space + 1 : budget;
    pieces.push(rest.slice(0, cut).trimEnd());
    rest = rest.slice(cut);
  }
  if (rest.length > 0) pieces.push(rest);
  return pieces;
}

/** How many Courier characters fit in `width` points at `size`. */
export function monoColumns(width: number, size: number): number {
  return Math.max(8, Math.floor(width / (size * MONO_ADVANCE)));
}

/** Width in points of `count` Courier characters at `size`. */
export function monoWidth(count: number, size: number): number {
  return count * size * MONO_ADVANCE;
}

/**
 * Shortens a string to fit a width, with a leading ellipsis for paths.
 *
 * A truncated path is useless from the front (`src/api/admin/...`) and useful
 * from the back (`.../(auth)/actions.ts`), so file cells lose their head, not
 * their tail.
 */
export function truncateStart(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `...${value.slice(value.length - (maxChars - 3))}`;
}

/** Shortens a string to fit, keeping the front, which is where a title says what it is. */
export function truncateEnd(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, Math.max(1, maxChars - 1)).trimEnd()}…`;
}

/** `file:line`, the citation format used everywhere in the report. */
export function citation(file: string, line: number, endLine?: number | undefined): string {
  return endLine !== undefined && endLine > line ? `${file}:${line}-${endLine}` : `${file}:${line}`;
}

/** The repository's own name, for the cover, from the absolute path that was analysed. */
export function repositoryName(target: string): string {
  const parts = target.replace(/[/\\]+$/, "").split(/[/\\]/);
  return parts.at(-1) ?? target;
}

/** A long path with its middle elided, for the cover's scope line. */
export function shortenPath(target: string, maxChars = 72): string {
  if (target.length <= maxChars) return target;
  const parts = target.split("/");
  const tail = parts.slice(-3).join("/");
  return `${parts[0] ?? ""}/${parts[1] ?? ""}/.../${tail}`;
}

/** `2026-03-04 09:30 UTC` — a timestamp a reader can compare with a commit. */
export function formatTimestamp(at: Date): string {
  const iso = at.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

/** `4 March 2026` — the date on the cover. */
export function formatDate(at: Date): string {
  const months = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
  ];
  return `${at.getUTCDate()} ${months[at.getUTCMonth()] ?? ""} ${at.getUTCFullYear()}`;
}

/** `10m 45s` — a duration a reader can weigh against the cost of the run. */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "unknown";
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${String(seconds % 60).padStart(2, "0")}s`;
}

/** `1,234` — thousands separated, so a token count is readable at a glance. */
export function formatCount(value: number): string {
  return Math.round(value).toLocaleString("en-US");
}

/**
 * Singular or plural, chosen by the count that precedes it.
 *
 * A noun ending in a sibilant takes `-es`, because the bare `-s` default printed
 * "20 of 100 batchs" on the appendix page of every dossier. An irregular plural
 * still has to be passed (`plural(n, "retry", "retries")`); this only removes the
 * trap a caller falls into by spelling its noun correctly.
 */
export function plural(count: number, singular: string, pluralForm?: string): string {
  if (count === 1) return singular;
  if (pluralForm !== undefined) return pluralForm;
  return `${singular}${/(?:s|x|z|ch|sh)$/.test(singular) ? "es" : "s"}`;
}

/** Sentence case for an identifier: `not-assessed` reads as `Not assessed`. */
export function humanise(value: string): string {
  const spaced = value.replace(/[-_]+/g, " ").trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/** Upper-cases the first character and leaves the rest of the sentence alone. */
export function capitalise(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

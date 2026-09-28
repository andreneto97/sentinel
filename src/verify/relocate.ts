import type { RefHints } from "./context.ts";
import { expandTabs } from "./text.ts";

/** A gutter (`> 42 | code`) that a previous Sentinel snippet may have added. */
const GUTTER = /^\s*>?\s*\d+\s*\|\s?/;
/** A needle must be long enough, and identifier-ish enough, to anchor anything. */
const MIN_NEEDLE_LENGTH = 4;
const IDENTIFIER_PAIR = /[A-Za-z_$][A-Za-z0-9_$]/;
const SYMBOL = /^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$/;
const MAX_NEEDLES = 8;

/** Where a relocation landed, and the text that anchored it. */
export interface Relocation {
  /** 1-based corrected line. */
  readonly line: number;
  /** The anchor text that matched exactly once. */
  readonly needle: string;
}

/** Inputs for a relocation attempt. */
export interface RelocateRequest {
  /** The file's lines, from disk. */
  readonly lines: readonly string[];
  /** The line the model cited; the search is centred on it. */
  readonly line: number;
  /** Anchor texts, most distinctive first. */
  readonly needles: readonly string[];
  /** Half-width of the searched window. */
  readonly window: number;
  /** Columns a tab expands to, so anchors match tab-indented code. */
  readonly tabWidth: number;
}

/** True when a line still contains one of the anchors — the citation is not off. */
export function lineMatchesAnyNeedle(
  line: string,
  needles: readonly string[],
  tabWidth: number,
): boolean {
  const haystack = expandTabs(line, tabWidth);
  return needles.some((needle) => haystack.includes(needle));
}

/**
 * Turns a model-supplied snippet and symbol into anchor texts, longest first.
 * The snippet's *text* is used as evidence of what the model looked at — it is
 * never trusted as the snippet that reaches the report.
 */
export function buildNeedles(
  input: { readonly snippet?: string | undefined } & RefHints,
  tabWidth: number,
): string[] {
  const candidates: string[] = [];
  for (const raw of (input.snippet ?? "").split(/\r\n|\n|\r/)) {
    const cleaned = expandTabs(raw.replace(GUTTER, ""), tabWidth).trim();
    if (cleaned.length >= MIN_NEEDLE_LENGTH && IDENTIFIER_PAIR.test(cleaned)) {
      candidates.push(cleaned);
    }
  }
  const symbol = input.symbol?.trim() ?? "";
  if (symbol.length >= 3 && SYMBOL.test(symbol)) candidates.push(symbol);

  return [...new Set(candidates)].sort((a, b) => b.length - a.length).slice(0, MAX_NEEDLES);
}

/**
 * Corrects a line number that drifted, by searching a window around it for an
 * anchor that occurs exactly once. Deliberately conservative: exact textual
 * match, one candidate line, and every anchor that matches uniquely must agree
 * — otherwise the citation is left alone and the finding is dropped.
 */
export function fuzzyRelocate(request: RelocateRequest): Relocation | null {
  const { lines, needles, window, tabWidth } = request;
  if (lines.length === 0 || needles.length === 0) return null;

  // A line past EOF gives no anchor, so the window is centred on the last line.
  const centre = Math.min(Math.max(request.line, 1), lines.length);
  const first = Math.max(1, centre - window);
  const last = Math.min(lines.length, centre + window);

  let agreed: Relocation | null = null;
  for (const needle of needles) {
    let hit = -1;
    let hits = 0;
    for (let n = first; n <= last; n += 1) {
      if (expandTabs(lines[n - 1] ?? "", tabWidth).includes(needle)) {
        hits += 1;
        if (hits > 1) break;
        hit = n;
      }
    }
    if (hits !== 1 || hit < 0) continue;
    if (agreed === null) {
      agreed = { line: hit, needle };
    } else if (agreed.line !== hit) {
      // Two anchors point at different lines: refuse rather than guess.
      return null;
    }
  }
  return agreed;
}

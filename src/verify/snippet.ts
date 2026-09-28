import { expandTabs, leadingSpaces, truncate } from "./text.ts";

/** Everything `extractSnippet` needs; the lines always come from disk. */
export interface SnippetRequest {
  /** The file's lines, terminators already stripped. */
  readonly lines: readonly string[];
  /** 1-based line the finding cites. */
  readonly line: number;
  /** 1-based last line of the cited range, when the finding spans several lines. */
  readonly endLine?: number | undefined;
  /** Lines of context on each side. */
  readonly contextLines: number;
  /** Characters kept per line. */
  readonly maxLineWidth: number;
  /** Hard cap on how many lines the snippet may contain. */
  readonly maxSnippetLines: number;
  /** Columns a tab expands to. */
  readonly tabWidth: number;
}

/**
 * Renders the cited lines plus context as a gutter-numbered block, with the
 * cited range marked by `>`. Common indentation is stripped and over-wide lines
 * are truncated, so a deeply nested statement still reads in a PDF table.
 */
export function extractSnippet(request: SnippetRequest): string {
  const { lines, line, contextLines, maxLineWidth, maxSnippetLines, tabWidth } = request;
  if (lines.length === 0) return "";

  const citedEnd = Math.min(Math.max(line, request.endLine ?? line), lines.length);
  const first = Math.max(1, line - contextLines);
  const last = Math.min(
    lines.length,
    Math.min(citedEnd + contextLines, first + maxSnippetLines - 1),
  );

  const body: string[] = [];
  for (let n = first; n <= last; n += 1) {
    body.push(expandTabs(lines[n - 1] ?? "", tabWidth));
  }

  const indents = body.map(leadingSpaces).filter((value): value is number => value !== null);
  const dedent = indents.length === 0 ? 0 : Math.min(...indents);
  const gutter = String(last).length;

  return body
    .map((content, index) => {
      const n = first + index;
      const marker = n >= line && n <= citedEnd ? ">" : " ";
      const text = truncate(content.slice(dedent), maxLineWidth);
      return `${marker} ${String(n).padStart(gutter)} | ${text}`.trimEnd();
    })
    .join("\n");
}
